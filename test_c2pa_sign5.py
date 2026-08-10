"""Sign a small image with self-signed EC P-256 cert + trust anchor config."""
import io
import json

import c2pa
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from PIL import Image

cert_pem = open("c2pa_keys/test_signer.cert", "rb").read().decode("ascii")
key_pem = open("c2pa_keys/test_signer.key", "rb").read()
private_key = serialization.load_pem_private_key(key_pem, password=None)


def sign_callback(data: bytes) -> bytes:
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


# Create Signer
signer = c2pa.Signer.from_callback(
    callback=sign_callback,
    alg=c2pa.C2paSigningAlg.ES256,
    certs=cert_pem,
)
print(f"Signer: reserve_size={signer.reserve_size()}")

# Configure Settings with our self-signed cert as a trust anchor
settings = c2pa.Settings()
# trust_anchors is a JSON array of PEM-encoded certs
trust_anchors_json = json.dumps([cert_pem])
settings.set("verify.trust_anchors", trust_anchors_json)
print("Configured trust anchor")

# Build Context with signer + settings
ctx_builder = c2pa.ContextBuilder()
ctx_builder.with_signer(signer)
ctx_builder.with_settings(settings)
ctx = ctx_builder.build()

# Build manifest
manifest_json = {
    "claim_generator": "DEEP-TRACE/probe/1.0",
    "assertions": [{"label": "c2pa.probe", "data": {"hello": "world"}}],
}

# Test image
arr = np.random.default_rng(0).integers(0, 255, (64, 64, 3), dtype=np.uint8)
buf = io.BytesIO()
Image.fromarray(arr).save(buf, format="PNG")
image_bytes = buf.getvalue()

# Sign with context
builder = c2pa.Builder(manifest_json, context=ctx)
try:
    signed_stream = builder.sign(
        "image/png",
        io.BytesIO(image_bytes),
        io.BytesIO(),
    )
    signed_bytes = signed_stream.getvalue() if hasattr(signed_stream, "getvalue") else signed_stream
    print(f"SIGNED OK! Output: {len(signed_bytes)} bytes")
    with open("probe_signed.png", "wb") as f:
        f.write(signed_bytes)
    print("Wrote probe_signed.png")

    # Verify it
    print()
    print("=== Verifying the signed image ===")
    reader = c2pa.Reader("image/png", io.BytesIO(signed_bytes))
    print(f"Validation status: {reader.validation_state}")
except Exception as exc:
    import traceback
    traceback.print_exc()
    print(f"FAILED: {type(exc).__name__}: {exc}")
