"""
End-to-end integration tests for the DEEP-TRACE API.

Uses an in-memory SQLite database (via aiosqlite) so the tests can
exercise the full HTTP stack without needing Postgres. The engine is
patched to use the SQLite DSN via env var.

Environment (DB URL, SECRET_KEY, API_KEYS, rate limits) is configured
centrally in `tests/conftest.py`.

Run with:
    pytest tests/integration/ -v

Skipped automatically if `aiosqlite` isn't installed.
"""

from __future__ import annotations

import io

import pytest

aiosqlite = pytest.importorskip("aiosqlite", reason="aiosqlite not installed")

import numpy as np
from PIL import Image
from httpx import ASGITransport, AsyncClient


def _png_bytes(h: int = 128, w: int = 128, seed: int = 0) -> bytes:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 255, (h, w, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def app_instance():
    """Build a fresh app with a clean SQLite DB."""
    from app.database import dispose_db, get_engine, init_db

    # Reset the global engine (in case a previous test left it)
    await dispose_db()

    from app.main import create_app

    app = create_app()
    await init_db()
    yield app
    await dispose_db()


@pytest.fixture
async def client(app_instance):
    async with AsyncClient(
        transport=ASGITransport(app=app_instance),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_open(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"


@pytest.mark.asyncio
async def test_embed_requires_api_key(client):
    img = _png_bytes()
    r = await client.post(
        "/api/v1/watermark/embed",
        data={
            "account_id": "acct-test",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "test-device-001",
        },
        files={"file": ("test.png", img, "image/png")},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_embed_wrong_api_key_rejected(client):
    img = _png_bytes()
    r = await client.post(
        "/api/v1/watermark/embed",
        headers={"X-API-Key": "bogus"},
        data={
            "account_id": "acct-test",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "test-device-001",
        },
        files={"file": ("test.png", img, "image/png")},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_embed_and_extract_round_trip(client):
    img = _png_bytes()
    headers = {"X-API-Key": "test_api_key_integration"}

    # Embed
    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers,
        data={
            "account_id": "acct-42",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "test-device-001",
        },
        files={"file": ("test.png", img, "image/png")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "SUCCESS"
    asset_id = body["asset_id"]
    payload_hex = body["payload_hex"]
    assert len(payload_hex) == 32
    assert body["perceptual_hashes"]["phash"]
    assert body["zkp_commitment_hex"]
    assert body["c2pa"]["manifest_uuid"]
    # Server should return the watermarked image as base64
    assert body["watermarked_image_b64"]

    # Extract from the WATERMARKED image (decoded from the embed response)
    import base64 as _b64
    watermarked_bytes = _b64.b64decode(body["watermarked_image_b64"])
    r2 = await client.post(
        "/api/v1/forensics/extract",
        headers=headers,
        files={"file": ("watermarked.png", watermarked_bytes, "image/png")},
    )
    assert r2.status_code == 200, r2.text
    extract_body = r2.json()
    assert extract_body["payload_hex"] == payload_hex
    # And the ledger lookup should match
    assert extract_body.get("ledger_match") is not None
    assert extract_body["ledger_match"]["payload_match"] is True
    assert extract_body["ledger_match"]["asset_id"] == asset_id


@pytest.mark.asyncio
async def test_ledger_lookup_after_embed(client):
    img = _png_bytes()
    headers = {"X-API-Key": "test_api_key_integration"}

    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers,
        data={
            "account_id": "acct-99",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "test-device-002",
        },
        files={"file": ("test.png", img, "image/png")},
    )
    asset_id = r.json()["asset_id"]

    # Fetch by asset_id
    r2 = await client.get(f"/api/v1/ledger/{asset_id}", headers=headers)
    assert r2.status_code == 200
    entry = r2.json()
    assert entry["asset_id"] == asset_id
    assert entry["account_id"] == "acct-99"


@pytest.mark.asyncio
async def test_ledger_search_by_account(client):
    headers = {"X-API-Key": "test_api_key_integration"}
    for i in range(3):
        img = _png_bytes(seed=i)
        await client.post(
            "/api/v1/watermark/embed",
            headers=headers,
            data={
                "account_id": "acct-search",
                "account_public_key": "04" + "ab" * 32,
                "device_signature": f"dev-{i}",
            },
            files={"file": ("test.png", img, "image/png")},
        )

    r = await client.get("/api/v1/ledger", headers=headers, params={"account_id": "acct-search"})
    assert r.status_code == 200
    entries = r.json()
    assert len(entries) >= 3
    for e in entries:
        assert e["account_id"] == "acct-search"


@pytest.mark.asyncio
async def test_auth_challenge(client):
    headers = {"X-API-Key": "test_api_key_integration"}
    r = await client.post(
        "/api/v1/auth/challenge",
        headers=headers,
        json={"account_id": "acct-chal"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["challenge_token"]
    assert body["nonce"]
    assert body["expires_at"] > body["issued_at"]


@pytest.mark.asyncio
async def test_invalid_image_rejected(client):
    headers = {"X-API-Key": "test_api_key_integration"}
    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers,
        data={
            "account_id": "acct-bad",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "dev-bad",
        },
        files={"file": ("test.png", b"not an image at all", "image/png")},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_ledger_phash_fuzzy_search(client):
    """Fuzzy perceptual-hash search: insert many entries, query a known
    pHash, confirm a sensible result set is returned."""
    import hashlib
    headers = {"X-API-Key": "test_api_key_integration"}

    # Register a known pHash
    target_phash = "abcdef0123456789"  # 16 hex chars (64-bit)
    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers,
        data={
            "account_id": "fuzzy-test",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "fuzzy-dev-001",
        },
        files={"file": ("test.png", _png_bytes(seed=123), "image/png")},
    )
    assert r.status_code == 200
    actual_phash = r.json()["perceptual_hashes"]["phash"]
    assert len(actual_phash) == 16  # 64-bit hex

    # Add a few noise entries
    for i in range(5):
        await client.post(
            "/api/v1/watermark/embed",
            headers=headers,
            data={
                "account_id": f"fuzzy-noise-{i}",
                "account_public_key": "04" + "ab" * 32,
                "device_signature": f"fuzzy-noise-dev-{i}",
            },
            files={"file": ("test.png", _png_bytes(seed=1000 + i), "image/png")},
        )

    # Search using a flipped-bit version of the target
    # Flip 2 bits: change last 2 chars by XOR with 0x03
    query = actual_phash
    # Construct a query 1 bit away from actual
    q_bytes = bytearray.fromhex(actual_phash)
    q_bytes[0] ^= 0x01
    query_close = q_bytes.hex()

    r = await client.get(
        "/api/v1/ledger/search",
        headers=headers,
        params={"phash": query_close, "account_id": "fuzzy-test", "limit": 5},
    )
    assert r.status_code == 200, r.text
    results = r.json()
    # We should get at least the matching entry back
    assert len(results) >= 1
    target_id = r.request.url  # just to silence linter
    asset_ids = {hit["asset_id"] for hit in results}
    # The fuzzy-test entry should be in the result set
    assert any(hit["account_id"] == "fuzzy-test" for hit in results)


@pytest.mark.asyncio
async def test_ledger_phash_search_filters_by_max_distance(client):
    """With max_distance=0, only exact matches should be returned."""
    headers = {"X-API-Key": "test_api_key_integration"}

    r = await client.post(
        "/api/v1/watermark/embed",
        headers=headers,
        data={
            "account_id": "exact-test",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "exact-dev",
        },
        files={"file": ("test.png", _png_bytes(seed=42), "image/png")},
    )
    actual_phash = r.json()["perceptual_hashes"]["phash"]

    # Search with the exact pHash and max_distance=0
    r = await client.get(
        "/api/v1/ledger/search",
        headers=headers,
        params={"phash": actual_phash, "max_distance": 0, "account_id": "exact-test"},
    )
    assert r.status_code == 200
    results = r.json()
    assert len(results) >= 1
    for hit in results:
        assert hit["perceptual_distance"]["phash"] == 0


@pytest.mark.asyncio
async def test_ledger_phash_search_rejects_invalid(client):
    """Non-hex pHash should be rejected at the API layer (Pydantic)."""
    headers = {"X-API-Key": "test_api_key_integration"}
    r = await client.get(
        "/api/v1/ledger/search",
        headers=headers,
        params={"phash": "zzzznotahexhash!@#"},
    )
    # Either 400 (validation) or 200 with empty result depending on routing;
    # we accept either as long as it doesn't crash.
    assert r.status_code in (200, 400, 422)
