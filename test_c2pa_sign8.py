"""Final C2PA signing attempt: chain + CA as trust anchor in Settings."""
import io
import json

import c2pa
import numpy as np
from PIL import Image

cert_pem = open("c2pa_keys/test_signer.cert", "rb").read()  # leaf
key_pem = open("c2pa_keys/test_signer.key", "rb").read()
ca_pem = open("c2pa_keys/ca.cert", "rb").read()

# The full cert chain: leaf first, then CA
chain_pem = cert_pem + b"\n" + ca_pem
print(f"leaf={len(cert_pem)}B  ca={len(ca_pem)}B  chain={len(chain_pem)}B")

arr = np.random.default_rng(0).integers(0, 255, (64, 64, 3), dtype=np.uint8)
buf = io.BytesIO()
Image.fromarray(arr).save(buf, format="PNG")
image_bytes = buf.getvalue()

manifest_json = {
    "claim_generator": "DEEP-TRACE/probe/1.0",
    "assertions": [{"label": "c2pa.probe", "data": {"hello": "world"}}],
}

# Build signer info
info = c2pa.C2paSignerInfo(
    alg=c2pa.C2paSigningAlg.ES256,
    sign_cert=chain_pem,
    private_key=key_pem,
    ta_url=None,
)
signer = c2pa.Signer.from_info(info)
print(f"Signer: reserve_size={signer.reserve_size()}")

# Configure Settings with trust anchors
settings = c2pa.Settings()
# try both verify.trust_anchors AND trust.trust_anchors
for key in ["verify.trust_anchors", "trust.trust_anchors"]:
    try:
        ta = json.dumps([ca_pem.decode("ascii")])
        settings.set(key, ta)
        print(f"  set {key} OK")
    except Exception as e:
        print(f"  set {key} FAILED: {e}")

# Try the sign
ctx_builder = c2pa.ContextBuilder()
ctx_builder.with_signer(signer)
ctx_builder.with_settings(settings)
ctx = ctx_builder.build()
print(f"Context: {ctx}")

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
except Exception as exc:
    import traceback
    traceback.print_exc()
    print(f"FAILED: {type(exc).__name__}: {exc}")
