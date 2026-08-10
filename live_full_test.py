"""Comprehensive live HTTP smoke test — all endpoints including new public ones."""
import base64
import io
import sys
import time
from pathlib import Path

import httpx
import numpy as np
from PIL import Image

BASE = "http://127.0.0.1:8765"
API_KEY = "live_test_api_key_32_bytes_min!"
HDR = {"X-API-Key": API_KEY}

print("=" * 70)
print("DEEP-TRACE live HTTP smoke test (full surface)")
print("=" * 70)


def make_image(seed: int = 42, h: int = 256, w: int = 256) -> bytes:
    arr = np.random.default_rng(seed).integers(0, 255, (h, w, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


with httpx.Client(base_url=BASE, timeout=30.0) as client:
    # 1. Health
    r = client.get("/health")
    assert r.status_code == 200
    print(f"[1]  GET  /health  -> 200  (alive)")

    # 2. Ready
    r = client.get("/ready")
    assert r.status_code == 200
    print(f"[2]  GET  /ready   -> 200  (db: {r.json()['database']})")

    # 3. Issue challenge
    r = client.post("/api/v1/auth/challenge", headers=HDR, json={"account_id": "live"})
    assert r.status_code == 200
    challenge = r.json()
    print(f"[3]  POST /api/v1/auth/challenge -> 200  (nonce={challenge['nonce'][:8]}...)")

    # 4. Embed (NEW: no account_public_key, derived automatically)
    img = make_image()
    r = client.post(
        "/api/v1/watermark/embed",
        headers=HDR,
        data={"account_id": "live-test", "device_signature": "live-device-001"},
        files={"file": ("test.png", img, "image/png")},
    )
    assert r.status_code == 200, r.text
    embed = r.json()
    asset_id = embed["asset_id"]
    print(f"[4]  POST /api/v1/watermark/embed -> 200  (asset={asset_id[:8]}..., psnr={embed['psnr_db']:.2f})")

    # 5. Public metadata (NEW: no API key)
    r = client.get(f"/api/v1/asset/{asset_id}")
    assert r.status_code == 200, r.text
    meta = r.json()
    assert "perceptual_hashes" in meta
    assert "image_url" in meta
    print(f"[5]  GET  /api/v1/asset/{{id}} -> 200  (public, no auth)")

    # 6. Public image download (NEW: no API key, returns the actual PNG)
    r = client.get(f"/api/v1/asset/{asset_id}/image")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "image/png"
    assert r.content[:8] == b"\x89PNG\r\n\x1a\n"
    print(f"[6]  GET  /api/v1/asset/{{id}}/image -> 200  (PNG, {len(r.content)} bytes)")

    # 7. Public thumbnail (NEW: 128x128)
    r = client.get(f"/api/v1/asset/{asset_id}/thumb")
    assert r.status_code == 200, r.text
    img_obj = Image.open(io.BytesIO(r.content))
    assert img_obj.size == (128, 128)
    print(f"[7]  GET  /api/v1/asset/{{id}}/thumb -> 200  (128x128 PNG)")

    # 8. Rate limit headers on public endpoint (NEW)
    r = client.get(f"/api/v1/asset/{asset_id}")
    assert "x-ratelimit-limit" in {k.lower() for k in r.headers.keys()}
    print(f"[8]  Rate limit headers present: limit={r.headers.get('x-ratelimit-limit')}")

    # 9. Watermarked image round-trips
    from app.engine.watermark import DCTQIMWatermark
    import cv2
    arr = np.frombuffer(r.content if False else client.get(f"/api/v1/asset/{asset_id}/image").content, dtype=np.uint8)
    decoded = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    assert decoded is not None
    print(f"[9]  Downloaded image decodes to {decoded.shape}")

    # 10. Verify (challenge-protected). Issue a fresh challenge for the
    # account that the asset was created under.
    ch_resp = client.post(
        "/api/v1/auth/challenge",
        headers=HDR,
        json={"account_id": "live-test"},
    )
    ch = ch_resp.json()["challenge_token"]
    wm_bytes = client.get(f"/api/v1/asset/{asset_id}/image").content
    r = client.post(
        f"/api/v1/forensics/verify/{asset_id}",
        headers={**HDR, "X-Challenge": ch, "X-Account-Id": "live-test"},
        files={"file": ("wm.png", wm_bytes, "image/png")},
    )
    assert r.status_code == 200, r.text
    verify = r.json()
    assert verify["verified"] is True
    print(f"[10] POST /api/v1/forensics/verify/{{id}} -> verified={verify['verified']}")

    # 11. Verify without challenge -> 401
    r = client.post(
        f"/api/v1/forensics/verify/{asset_id}",
        headers={**HDR, "X-Account-Id": "live-test"},
        files={"file": ("wm.png", wm_bytes, "image/png")},
    )
    assert r.status_code == 401, f"expected 401, got {r.status_code}: {r.text}"
    print(f"[11] POST /api/v1/forensics/verify without challenge -> 401  (auth required)")

    # 12. Non-existent asset -> 404
    import uuid
    bogus = str(uuid.uuid4())
    r = client.get(f"/api/v1/asset/{bogus}")
    assert r.status_code == 404
    r = client.get(f"/api/v1/asset/{bogus}/image")
    assert r.status_code == 404
    print(f"[12] Non-existent asset -> 404  (proper error handling)")

    # 13. Invalid UUID -> 400
    r = client.get("/api/v1/asset/not-a-uuid")
    assert r.status_code == 400
    print(f"[13] Invalid UUID -> 400  (validation works)")

    # 14. CORS preflight (NEW)
    r = client.options(
        f"/api/v1/asset/{asset_id}/image",
        headers={
            "Origin": "https://yoursite.wixsite.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code in (200, 204)
    assert "access-control-allow-origin" in {k.lower() for k in r.headers.keys()}
    print(f"[14] CORS preflight -> 200/204  (allow-origin={r.headers.get('access-control-allow-origin')})")

    # 15. Ledger search with combined pHash + dHash (NEW)
    r = client.get(
        "/api/v1/ledger/search",
        headers=HDR,
        params={
            "phash": meta["perceptual_hashes"]["phash"],
            "dhash": meta["perceptual_hashes"]["dhash"],
        },
    )
    assert r.status_code == 200
    hits = r.json()
    assert len(hits) >= 1
    print(f"[15] Combined pHash+dHash search -> {len(hits)} hit(s)")

    # 16. Extract from watermarked image (uses public download)
    wm_bytes = client.get(f"/api/v1/asset/{asset_id}/image").content
    r = client.post(
        "/api/v1/forensics/extract",
        headers=HDR,
        files={"file": ("wm.png", wm_bytes, "image/png")},
    )
    assert r.status_code == 200
    extract = r.json()
    assert extract["payload_hex"] == embed["payload_hex"]
    assert extract["ledger_match"]["payload_match"] is True
    print(f"[16] Extract from public-download image -> MATCH_FOUND")

print()
print("=" * 70)
print(f"All 16 endpoint scenarios passed.")
print("=" * 70)
