"""
DEEP-TRACE API client — minimal example showing the full provenance loop.

Run after starting the service:
    pip install httpx
    python examples/client_demo.py path/to/your/image.jpg

This script:
    1. Issues an HMAC challenge for the account
    2. Embeds a watermark in the image
    3. Simulates a recompression attack
    4. Extracts the watermark from the recompressed image
    5. Verifies the asset against the ledger
"""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

import httpx


def main(api_base: str, api_key: str, image_path: str, account_id: str) -> int:
    img_bytes = Path(image_path).read_bytes()
    if not img_bytes:
        print(f"error: empty file {image_path}", file=sys.stderr)
        return 1

    headers = {"X-API-Key": api_key}

    with httpx.Client(base_url=api_base, timeout=30.0) as client:
        # ---- 1. Issue a challenge ----
        print("[1] issuing HMAC challenge…")
        r = client.post("/api/v1/auth/challenge", headers=headers, json={"account_id": account_id})
        r.raise_for_status()
        challenge = r.json()
        print(f"    nonce={challenge['nonce']} ttl={challenge['ttl_seconds']}s")

        # ---- 2. Embed watermark ----
        print("[2] embedding watermark…")
        r = client.post(
            "/api/v1/watermark/embed",
            headers=headers,
            data={
                "account_id": account_id,
                "account_public_key": "04" + "ab" * 32,
                "device_signature": f"demo-client-{os.getpid()}",
                "timestamp": time.time(),
            },
            files={"file": (Path(image_path).name, img_bytes, "image/jpeg")},
        )
        r.raise_for_status()
        embed = r.json()
        asset_id = embed["asset_id"]
        print(f"    asset_id      = {asset_id}")
        print(f"    payload_hex   = {embed['payload_hex']}")
        print(f"    commitment    = {embed['zkp_commitment_hex'][:32]}…")
        print(f"    psnr_db       = {embed['psnr_db']:.2f}")
        print(f"    pHash         = {embed['perceptual_hashes']['phash']}")

        # ---- 3. Simulate recompression attack ----
        # In a real scenario the asset would be uploaded to social media
        # and re-downloaded. Here we just round-trip through PNG→JPEG→PNG.
        print("[3] simulating recompression (PNG→JPEG Q=80→PNG)…")
        try:
            from PIL import Image
            import numpy as np

            pil = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            buf = io.BytesIO()
            pil.save(buf, format="JPEG", quality=80)
            buf.seek(0)
            attacked = buf.getvalue()
        except ImportError:
            print("    (PIL not installed, using original bytes)")
            attacked = img_bytes

        # ---- 4. Extract watermark from the attacked image ----
        print("[4] extracting watermark from attacked image…")
        r = client.post(
            "/api/v1/forensics/extract",
            headers=headers,
            files={"file": ("attacked.jpg", attacked, "image/jpeg")},
        )
        r.raise_for_status()
        extract = r.json()
        print(f"    status        = {extract['status']}")
        print(f"    payload_hex   = {extract['payload_hex']}")
        print(f"    extract status= {extract['extraction_status']}")
        if extract.get("ledger_match"):
            lm = extract["ledger_match"]
            print(f"    ledger match  = {lm['asset_id']}")
            print(f"    payload match = {lm['payload_match']}")
            print(f"    hamming dist  = phash={lm['perceptual_distance']['phash']}")

        # ---- 5. Verify against ledger by asset_id ----
        print("[5] verifying against ledger by asset_id…")
        r = client.post(
            f"/api/v1/forensics/verify/{asset_id}",
            headers=headers,
            files={"file": ("attacked.jpg", attacked, "image/jpeg")},
        )
        r.raise_for_status()
        verify = r.json()
        print(f"    verified      = {verify['verified']}")
        print(f"    payload_match = {verify['payload_match']}")
        print(f"    hamming dist  = {verify['perceptual_distance']}")

        # ---- 6. Look up ledger entry ----
        print("[6] looking up ledger entry…")
        r = client.get(f"/api/v1/ledger/{asset_id}", headers=headers)
        r.raise_for_status()
        entry = r.json()
        print(f"    account_id    = {entry['account_id']}")
        print(f"    created_at    = {entry['created_at']}")
        print(f"    file_size     = {entry['file_size_bytes']} bytes")
        print(f"    c2pa embedded = {entry['c2pa']['embedded']}")

    return 0 if extract["payload_hex"] == embed["payload_hex"] else 2


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(
            f"usage: {sys.argv[0]} <api_base> <api_key> <image_path> [account_id]",
            file=sys.stderr,
        )
        print("  api_base  e.g. http://localhost:8000", file=sys.stderr)
        print("  api_key   your X-API-Key", file=sys.stderr)
        print("  image_path local image to watermark", file=sys.stderr)
        print("  account_id (default: demo-account)", file=sys.stderr)
        sys.exit(1)
    api_base = sys.argv[1]
    api_key = sys.argv[2]
    image_path = sys.argv[3]
    account_id = sys.argv[4] if len(sys.argv) > 4 else "demo-account"
    raise SystemExit(main(api_base, api_key, image_path, account_id))
