"""
Verify DEEP-TRACE is correctly installed and all engines wire up.

Run after `pip install -e .` or inside the Docker container:
    python scripts/verify_installation.py
"""

from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path

# Ensure project root is importable when run as a script
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> int:
    import numpy as np

    from app.config import settings
    from app.engine.ecc import ReedSolomonCodec
    from app.engine.perceptual import PerceptualHasher
    from app.engine.watermark import DCTQIMWatermark
    from app.engine.zkp import PedersenCommitment
    from app.core.security import derive_subkey, issue_challenge, verify_challenge

    print("=" * 70)
    print("DEEP-TRACE installation verification")
    print("=" * 70)
    print(f"Project:        {settings.PROJECT_NAME} v{settings.PROJECT_VERSION}")
    print(f"Environment:    {settings.ENVIRONMENT}")
    print(f"Log level:      {settings.LOG_LEVEL}")
    print(f"Database URL:   {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
    print()

    failures: list[str] = []

    # Use a deterministic 32-byte test secret so the verify script
    # always works regardless of the deployment's SECRET_KEY value.
    test_master = b"verify_installation_test_secret!"  # 32 bytes

    # 1. Reed-Solomon round trip
    try:
        codec = ReedSolomonCodec()
        data = secrets.token_bytes(16)
        codeword = codec.encode(data)
        decoded, _ = codec.decode(codeword)
        assert decoded == data
        print("[OK]   Reed-Solomon encode/decode round trip")
    except Exception as exc:
        failures.append(f"Reed-Solomon: {exc}")
        print(f"[FAIL] Reed-Solomon: {exc}")

    # 2. Pedersen commitment
    try:
        pc = PedersenCommitment(master_key=test_master)
        C, opening = pc.commit(12345)
        assert pc.verify(C, opening)
        print(f"[OK]   Pedersen commitment (p={pc.params.p.bit_length()}-bit modulus, q={pc.params.q.bit_length()}-bit order)")
    except Exception as exc:
        failures.append(f"Pedersen: {exc}")
        print(f"[FAIL] Pedersen: {exc}")

    # 3. HMAC challenge
    try:
        ch = issue_challenge("test-account")
        verify_challenge("test-account", ch)
        print("[OK]   HMAC challenge issue/verify")
    except Exception as exc:
        failures.append(f"HMAC challenge: {exc}")
        print(f"[FAIL] HMAC challenge: {exc}")

    # 4. Sub-key derivation
    try:
        k1 = derive_subkey(settings.SECRET_KEY.encode("utf-8"), "test")
        k2 = derive_subkey(settings.SECRET_KEY.encode("utf-8"), "test")
        k3 = derive_subkey(settings.SECRET_KEY.encode("utf-8"), "different")
        assert k1 == k2
        assert k1 != k3
        print("[OK]   HKDF-style sub-key derivation")
    except Exception as exc:
        failures.append(f"Sub-key derivation: {exc}")
        print(f"[FAIL] Sub-key derivation: {exc}")

    # 5. Watermark embed/extract
    try:
        wm = DCTQIMWatermark(secret_key=settings.SECRET_KEY.encode("utf-8"))
        rng = np.random.default_rng(42)
        img = rng.integers(0, 255, (256, 256, 3), dtype=np.uint8)
        result = wm.embed_watermark(img, "test-acct", time.time(), "test-sig")
        extracted, status, errors = wm.extract_watermark(result.watermarked_bgr)
        if extracted == result.payload_hex:
            print(f"[OK]   Watermark round trip (PSNR={result.psnr_db:.2f} dB, ECC corrected {errors} bytes)")
        else:
            raise RuntimeError(f"payload mismatch: {status}")
    except Exception as exc:
        failures.append(f"Watermark: {exc}")
        print(f"[FAIL] Watermark: {exc}")

    # 6. Perceptual hashing
    try:
        import io
        from PIL import Image

        rng = np.random.default_rng(0)
        arr = rng.integers(0, 255, (128, 128, 3), dtype=np.uint8)
        buf = io.BytesIO()
        Image.fromarray(arr).save(buf, format="PNG")
        hashes = PerceptualHasher.compute_hashes(buf.getvalue())
        assert hashes.phash and hashes.dhash and hashes.ahash and hashes.whash
        print(f"[OK]   Perceptual hashing (pHash={hashes.phash}, dHash={hashes.dhash})")
    except Exception as exc:
        failures.append(f"Perceptual hash: {exc}")
        print(f"[FAIL] Perceptual hash: {exc}")

    print()
    if failures:
        print(f"[FAIL] {len(failures)} verification(s) FAILED")
        for f in failures:
            print(f"   - {f}")
        return 1
    print("[OK]   All engine components verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
