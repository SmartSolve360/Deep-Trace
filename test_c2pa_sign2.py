"""Try C2PA via load_settings + Builder with settings file."""
import io
import json
import tempfile
from pathlib import Path

import c2pa
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image

# Load the test cert + key
cert_pem = open("c2pa_keys/test_signer.cert", "rb").read()
key_pem = open("c2pa_keys/test_signer.key", "rb").read()
private_key = serialization.load_pem_private_key(key_pem, password=None)

# Test approach: write a settings JSON for c2pa, then build from it
settings = {
    "version": 1,
    "trust_config": {
        "local_dir": "c2pa_keys",
        "trust_anchors": ["test_signer.cert"],
    },
    "signer": {
        "local_dir": "c2pa_keys",
        "certificate": "test_signer.cert",
        "private_key": "test_signer.key",
        "algorithm": "ps256",
    },
}

# Try loading settings
try:
    c2pa.load_settings(json.dumps(settings), format="json")
    print("load_settings OK")
except Exception as e:
    print(f"load_settings FAILED: {e}")

# Build a manifest
manifest_json = {
    "claim_generator": "DEEP-TRACE/probe/1.0",
    "assertions": [
        {
            "label": "c2pa.probe",
            "data": {"probe": "test-manifest", "version": 1},
        }
    ],
}

# Build a tiny test image
arr = np.random.default_rng(0).integers(0, 255, (64, 64, 3), dtype=np.uint8)
buf = io.BytesIO()
Image.fromarray(arr).save(buf, format="PNG")
image_bytes = buf.getvalue()

# Try signing using just the format string (uses the loaded settings)
builder = c2pa.Builder(manifest_json)
try:
    signed_stream = builder.sign(
        "image/png",                             # format
        io.BytesIO(image_bytes),                 # source
        io.BytesIO(),                            # dest
    )
    signed_bytes = signed_stream.getvalue() if hasattr(signed_stream, "getvalue") else signed_stream
    print(f"SIGNED OK via settings! Output: {len(signed_bytes)} bytes")
    with open("probe_signed.png", "wb") as f:
        f.write(signed_bytes)
except Exception as exc:
    import traceback
    traceback.print_exc()
    print(f"SIGN FAILED: {type(exc).__name__}: {exc}")
