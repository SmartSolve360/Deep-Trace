"""Use C2paSignerInfo + from_info — pass the key directly, no callback."""
import io

import c2pa
import numpy as np
from PIL import Image

cert_pem = open("c2pa_keys/test_signer.cert", "rb").read()
key_pem = open("c2pa_keys/test_signer.key", "rb").read()
ca_pem = open("c2pa_keys/ca.cert", "rb").read()
print(f"cert={len(cert_pem)}B  key={len(key_pem)}B  ca={len(ca_pem)}B")

# Certs must include the full chain (leaf + CA)
chain_pem = cert_pem + ca_pem

# Build signer info with the key directly
info = c2pa.C2paSignerInfo(
    alg=c2pa.C2paSigningAlg.ES256,
    sign_cert=chain_pem,
    private_key=key_pem,
    ta_url=None,
)
print(f"C2paSignerInfo: alg={info.alg!r} cert_len={len(info.sign_cert or b'')} key_len={len(info.private_key or b'')}")

signer = c2pa.Signer.from_info(info)
print(f"Signer: reserve_size={signer.reserve_size()}")

# Test image
arr = np.random.default_rng(0).integers(0, 255, (64, 64, 3), dtype=np.uint8)
buf = io.BytesIO()
Image.fromarray(arr).save(buf, format="PNG")
image_bytes = buf.getvalue()

manifest_json = {
    "claim_generator": "DEEP-TRACE/probe/1.0",
    "assertions": [{"label": "c2pa.probe", "data": {"hello": "world"}}],
}

builder = c2pa.Builder(manifest_json)
try:
    signed_stream = builder.sign(
        signer,
        "image/png",
        io.BytesIO(image_bytes),
        io.BytesIO(),
    )
    signed_bytes = signed_stream.getvalue() if hasattr(signed_stream, "getvalue") else signed_stream
    print(f"SIGNED OK! Output: {len(signed_bytes)} bytes")
    with open("probe_signed.png", "wb") as f:
        f.write(signed_bytes)
    print("Wrote probe_signed.png")
except Exception as exc:
    import traceback
    traceback.print_exc()
    print(f"FAILED: {type(exc).__name__}: {exc}")
