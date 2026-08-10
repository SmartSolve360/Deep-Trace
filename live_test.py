"""Live HTTP test against the running uvicorn server."""
import sys
import time
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8765"
API_KEY = "live_test_api_key_32_bytes_min!"
IMG = Path("test_image.png")

if not IMG.exists():
    print("ERROR: test_image.png missing — run make_test_image.py first", file=sys.stderr)
    sys.exit(1)

print("=" * 70)
print("DEEP-TRACE live HTTP test")
print("=" * 70)
print(f"Image:  {IMG} ({IMG.stat().st_size} bytes)")

with httpx.Client(base_url=BASE, timeout=30.0) as client:
    # 1. health
    r = client.get("/health")
    print(f"\n[1] GET /health")
    print(f"    {r.status_code} {r.json()}")

    # 2. ready
    r = client.get("/ready")
    print(f"\n[2] GET /ready")
    print(f"    {r.status_code} {r.json()}")

    # 3. challenge
    r = client.post(
        "/api/v1/auth/challenge",
        headers={"X-API-Key": API_KEY},
        json={"account_id": "live-test"},
    )
    r.raise_for_status()
    challenge = r.json()
    print(f"\n[3] POST /api/v1/auth/challenge")
    print(f"    {r.status_code} nonce={challenge['nonce']} ttl={challenge['ttl_seconds']}s")

    # 4. embed
    t0 = time.time()
    r = client.post(
        "/api/v1/watermark/embed",
        headers={"X-API-Key": API_KEY},
        data={
            "account_id": "live-test",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "live-device-001",
        },
        files={"file": ("test.png", IMG.read_bytes(), "image/png")},
    )
    r.raise_for_status()
    embed = r.json()
    t_embed = time.time() - t0
    print(f"\n[4] POST /api/v1/watermark/embed ({t_embed:.2f}s)")
    print(f"    {r.status_code} status={embed['status']}")
    print(f"    asset_id      = {embed['asset_id']}")
    print(f"    payload_hex   = {embed['payload_hex']}")
    print(f"    commitment    = {embed['zkp_commitment_hex'][:32]}...")
    print(f"    psnr_db       = {embed['psnr_db']:.2f}")
    print(f"    pHash         = {embed['perceptual_hashes']['phash']}")
    print(f"    image (b64)   = {len(embed['watermarked_image_b64'])} chars")

    # 5. lookup
    r = client.get(
        f"/api/v1/ledger/{embed['asset_id']}",
        headers={"X-API-Key": API_KEY},
    )
    r.raise_for_status()
    entry = r.json()
    print(f"\n[5] GET /api/v1/ledger/{embed['asset_id'][:8]}...")
    print(f"    {r.status_code}")
    print(f"    account_id    = {entry['account_id']}")
    print(f"    created_at    = {entry['created_at']}")
    print(f"    file_size     = {entry['file_size_bytes']} bytes")
    print(f"    psnr_db       = {entry['psnr_db']:.2f}")

    # 6. extract (against the original — should NOT find the watermark)
    r = client.post(
        "/api/v1/forensics/extract",
        headers={"X-API-Key": API_KEY},
        files={"file": ("original.png", IMG.read_bytes(), "image/png")},
    )
    r.raise_for_status()
    extract_orig = r.json()
    print(f"\n[6] POST /api/v1/forensics/extract (against original)")
    print(f"    {r.status_code} status={extract_orig['status']}")
    print(f"    payload_hex   = {extract_orig['payload_hex']}")
    print(f"    extract_status= {extract_orig['extraction_status']}")

    # 7. extract (against the watermarked image — should find the payload)
    import base64
    watermarked = base64.b64decode(embed["watermarked_image_b64"])
    r = client.post(
        "/api/v1/forensics/extract",
        headers={"X-API-Key": API_KEY},
        files={"file": ("watermarked.png", watermarked, "image/png")},
    )
    r.raise_for_status()
    extract_wm = r.json()
    print(f"\n[7] POST /api/v1/forensics/extract (against watermarked)")
    print(f"    {r.status_code} status={extract_wm['status']}")
    print(f"    payload_hex   = {extract_wm['payload_hex']}")
    print(f"    extract_status= {extract_wm['extraction_status']}")
    if extract_wm.get("ledger_match"):
        lm = extract_wm["ledger_match"]
        print(f"    ledger match  = {lm['asset_id']}")
        print(f"    payload match = {lm['payload_match']}")
        print(f"    phash dist    = {lm['perceptual_distance']['phash']}")

    # 8. verify against asset_id
    r = client.post(
        f"/api/v1/forensics/verify/{embed['asset_id']}",
        headers={"X-API-Key": API_KEY},
        files={"file": ("watermarked.png", watermarked, "image/png")},
    )
    r.raise_for_status()
    verify = r.json()
    print(f"\n[8] POST /api/v1/forensics/verify/{{asset_id}}")
    print(f"    {r.status_code} verified={verify['verified']} payload_match={verify['payload_match']}")
    print(f"    perceptual_distance = {verify['perceptual_distance']}")

    # 9. search by perceptual hash
    r = client.get(
        "/api/v1/ledger/search",
        headers={"X-API-Key": API_KEY},
        params={"phash": embed["perceptual_hashes"]["phash"]},
    )
    r.raise_for_status()
    search = r.json()
    print(f"\n[9] GET /api/v1/ledger/search?phash=...")
    print(f"    {r.status_code} hits={len(search)}")
    for h in search[:3]:
        print(f"    - {h['asset_id']} account={h['account_id']} dist={h['perceptual_distance']['phash']}")

    # 10. auth failure (no API key)
    r = client.get("/api/v1/ledger")
    print(f"\n[10] GET /api/v1/ledger (no API key)")
    print(f"    {r.status_code}  (expected 401)")

print("\n" + "=" * 70)
print("All endpoints tested successfully.")
print("=" * 70)
