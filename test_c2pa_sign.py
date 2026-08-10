"""Probe: sign a small image with our test cert via c2pa-python."""
import io

import c2pa
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image

# Load the test cert + key
cert_pem = open("c2pa_keys/test_signer.cert", "rb").read()
key_pem = open("c2pa_keys/test_signer.key", "rb").read()
private_key = serialization.load_pem_private_key(key_pem, password=None)
print(f"Loaded RSA-{private_key.key_size} private key + {len(cert_pem)}-byte cert")

# Build a signing callback
def sign_callback(data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

# Create the c2pa Signer
signer = c2pa.Signer.from_callback(
    callback=sign_callback,
    alg=c2pa.C2paSigningAlg.PS256,
    certs=cert_pem.decode("ascii"),
)
print(f"Signer created: reserve_size={signer.reserve_size()} bytes")

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
print(f"Test image: {len(image_bytes)} bytes PNG")

# Sign it
builder = c2pa.Builder(manifest_json)
try:
    signed_stream = builder.sign(
        signer,                                  # signer
        "image/png",                             # format
        io.BytesIO(image_bytes),                 # source
        io.BytesIO(),                            # dest
    )
    if isinstance(signed_stream, bytes):
        signed_bytes = signed_stream
    else:
        signed_bytes = signed_stream.getvalue()
    print(f"SIGNED OK! Output: {len(signed_bytes)} bytes")
    with open("probe_signed.png", "wb") as f:
        f.write(signed_bytes)
    print("Wrote probe_signed.png")
except Exception as exc:
    import traceback
    traceback.print_exc()
    print(f"SIGN FAILED: {type(exc).__name__}: {exc}")
