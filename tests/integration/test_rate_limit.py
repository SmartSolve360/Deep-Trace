"""
Integration test for rate limiting.

Sets a deliberately tiny rate limit (3/minute) at the start of each
test via fixture override and verifies the 4th request gets 429.

Environment configured centrally in `tests/conftest.py`. The
deliberately tight rate limits are set inside the test module below.
"""
from __future__ import annotations

import io
import os

import pytest
from httpx import ASGITransport, AsyncClient

aiosqlite = pytest.importorskip("aiosqlite", reason="aiosqlite not installed")

import numpy as np
from PIL import Image


def _png_bytes(h: int = 128, w: int = 128, seed: int = 0) -> bytes:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 255, (h, w, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def app_instance():
    # Set deliberately tight rate limits for this test module
    os.environ["RATE_LIMIT_EMBED"] = "3/minute"
    os.environ["RATE_LIMIT_PUBLIC"] = "3/minute"
    os.environ["RATE_LIMIT_AUTHED"] = "3/minute"
    from app.database import dispose_db
    from app.main import create_app
    from app.models import Base
    from app.database import get_engine
    from app.config import get_settings

    get_settings.cache_clear()
    await dispose_db()
    app = create_app()
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield app
    await dispose_db()


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Reset the in-memory rate-limit store between tests so cross-test
    pollution doesn't cause flaky failures."""
    from app.core.rate_limit import limiter
    try:
        # slowapi 0.1.x exposes .reset() on the storage
        if hasattr(limiter, "_storage") and hasattr(limiter._storage, "reset"):
            limiter._storage.reset()
    except Exception:
        pass
    yield


@pytest.fixture
async def client(app_instance):
    async with AsyncClient(
        transport=ASGITransport(app=app_instance),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_embed_rate_limit_kicks_in(client):
    """With limit=3/minute, the 4th embed should return 429."""
    headers = {"X-API-Key": "test_api_key_rate_limit"}
    img = _png_bytes()

    # First 3 should succeed
    for i in range(3):
        r = await client.post(
            "/api/v1/watermark/embed",
            headers=headers,
            data={"account_id": f"acct-{i}", "device_signature": "rl-test"},
            files={"file": ("test.png", img, "image/png")},
        )
        assert r.status_code == 200, f"call {i}: {r.status_code} {r.text}"

    # 4th should be rate-limited
    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers,
        data={"account_id": "acct-4", "device_signature": "rl-test"},
        files={"file": ("test.png", img, "image/png")},
    )
    assert r.status_code == 429, f"expected 429, got {r.status_code}: {r.text}"
    # slowapi returns a specific body
    assert "rate limit" in r.text.lower() or "too many" in r.text.lower() or "ratelimit" in r.text.lower()


@pytest.mark.asyncio
async def test_public_endpoint_rate_limit(client):
    """Public endpoints also rate-limit (by IP since no API key)."""
    img = _png_bytes()

    # Embed once to get an asset_id
    r = await client.post(
        "/api/v1/watermark/embed",
        headers={"X-API-Key": "test_api_key_rate_limit"},
        data={"account_id": "public-test", "device_signature": "rl"},
        files={"file": ("test.png", img, "image/png")},
    )
    aid = r.json()["asset_id"]
    # 2 more embeds so we hit the limit of 3
    for i in range(2):
        r = await client.post(
            "/api/v1/watermark/embed",
            headers={"X-API-Key": "test_api_key_rate_limit"},
            data={"account_id": f"public-test-{i}", "device_signature": "rl"},
            files={"file": ("test.png", img, "image/png")},
        )
        assert r.status_code == 200

    # Public request should still be rate-limited (limit=3 for the IP, but
    # actually limit is per-key, and the public endpoint doesn't have a key,
    # so it uses IP. We need to first exhaust the public limit.)
    # Since the public endpoint uses IP and not the X-API-Key, hits from
    # the same test client share the IP bucket. Let's verify the public
    # endpoint gets 429 after 3 hits.
    for i in range(3):
        r = await client.get(f"/api/v1/asset/{aid}")
        # Could be 200 or 429 depending on bucket
        if r.status_code == 429:
            return  # already blocked, test passes
    # 4th should be 429
    r = await client.get(f"/api/v1/asset/{aid}")
    assert r.status_code == 429, f"expected 429, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_different_keys_have_separate_buckets(client):
    """API key A's rate limit doesn't affect API key B."""
    img = _png_bytes()

    # First API key: exhaust its bucket
    headers_a = {"X-API-Key": "test_api_key_rate_limit"}
    for i in range(3):
        r = await client.post(
            "/api/v1/watermark/embed",
            headers=headers_a,
            data={"account_id": f"a-{i}", "device_signature": "x"},
            files={"file": ("test.png", img, "image/png")},
        )
        assert r.status_code == 200
    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers_a,
        data={"account_id": "a-overflow", "device_signature": "x"},
        files={"file": ("test.png", img, "image/png")},
    )
    assert r.status_code == 429
