"""Live forensic robustness test — simulates social media recompression attack.

1. Embed a watermark in an image
2. Decode the watermarked image from the embed response
3. Recompress it to JPEG Q=80 (simulating Twitter/Facebook)
4. Re-decode the JPEG
5. Submit the JPEG to /forensics/extract
6. Confirm the watermark was recovered and matches the ledger
"""
import base64
import io
import sys
import time

import httpx
from PIL import Image

BASE = "http://127.0.0.1:8765"
API_KEY = "live_test_api_key_32_bytes_min!"

print("=" * 70)
print("DEEP-TRACE forensic robustness test (JPEG Q=80 recompression)")
print("=" * 70)

with httpx.Client(base_url=BASE, timeout=30.0) as client:
    # 1. Build test image
    import numpy as np
    arr = np.random.default_rng(99).integers(0, 255, (512, 512, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    original_bytes = buf.getvalue()
    print(f"\n[1] Built test image: 512x512 PNG ({len(original_bytes)} bytes)")

    # 2. Embed watermark
    t0 = time.time()
    r = client.post(
        "/api/v1/watermark/embed",
        headers={"X-API-Key": API_KEY},
        data={
            "account_id": "robustness-test",
            "account_public_key": "04" + "ab" * 32,
            "device_signature": "robustness-device",
        },
        files={"file": ("test.png", original_bytes, "image/png")},
    )
    r.raise_for_status()
    embed = r.json()
    print(f"\n[2] Embedded watermark in {time.time()-t0:.2f}s")
    print(f"    asset_id      = {embed['asset_id']}")
    print(f"    payload_hex   = {embed['payload_hex']}")
    print(f"    psnr_db       = {embed['psnr_db']:.2f}")

    # 3. Decode the watermarked image
    watermarked_bytes = base64.b64decode(embed["watermarked_image_b64"])
    wm_img = Image.open(io.BytesIO(watermarked_bytes))
    print(f"\n[3] Decoded watermarked image: {wm_img.size} ({len(watermarked_bytes)} bytes)")

    # 4. Recompress to JPEG Q=80
    buf2 = io.BytesIO()
    wm_img.convert("RGB").save(buf2, format="JPEG", quality=80)
    jpeg_bytes = buf2.getvalue()
    print(f"\n[4] Recompressed to JPEG Q=80: ({len(jpeg_bytes)} bytes)")

    # 5. Try to extract from the JPEG
    t0 = time.time()
    r = client.post(
        "/api/v1/forensics/extract",
        headers={"X-API-Key": API_KEY},
        files={"file": ("recompressed.jpg", jpeg_bytes, "image/jpeg")},
    )
    r.raise_for_status()
    extract = r.json()
    print(f"\n[5] Extracted from recompressed JPEG in {time.time()-t0:.2f}s")
    print(f"    status        = {extract['status']}")
    print(f"    payload_hex   = {extract['payload_hex']}")
    print(f"    extract_status= {extract['extraction_status']}")
    print(f"    errors_corrected = {extract['errors_corrected']}")

    if extract.get("ledger_match"):
        lm = extract["ledger_match"]
        print(f"    ledger match  = {lm['asset_id']}")
        print(f"    payload match = {lm['payload_match']}")
        print(f"    hamming dist  = {lm['perceptual_distance']}")

    # 6. Verify
    r = client.post(
        f"/api/v1/forensics/verify/{embed['asset_id']}",
        headers={"X-API-Key": API_KEY},
        files={"file": ("recompressed.jpg", jpeg_bytes, "image/jpeg")},
    )
    r.raise_for_status()
    verify = r.json()
    print(f"\n[6] Verified against ledger")
    print(f"    verified        = {verify['verified']}")
    print(f"    payload_match   = {verify['payload_match']}")
    print(f"    hamming dist    = {verify['perceptual_distance']}")

    # Verdict
    print()
    if extract.get("payload_hex") == embed["payload_hex"]:
        print(">> PASS: Watermark survived JPEG Q=80 recompression, payload matches.")
    else:
        print(">> FAIL: Watermark did not survive recompression.")
        sys.exit(1)

    if verify.get("verified"):
        print(">> PASS: Ledger verification succeeded against the recompressed image.")
    else:
        print(">> FAIL: Ledger verification failed.")
        sys.exit(1)
