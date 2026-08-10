"""Try DER format + various algs."""
import io

import c2pa
import numpy as np
from cryptography.hazmat.primitives import serialization
from PIL import Image

# Try DER format
cert_der = open("c2pa_keys/test_signer.cert", "rb").read()
key_der = open("c2pa_keys/test_signer.key", "rb").read()
print(f"cert_der={len(cert_der)}B  key_der={len(key_der)}B")

arr = np.random.default_rng(0).integers(0, 255, (64, 64, 3), dtype=np.uint8)
buf = io.BytesIO()
Image.fromarray(arr).save(buf, format="PNG")
image_bytes = buf.getvalue()

manifest_json = {
    "claim_generator": "DEEP-TRACE/probe/1.0",
    "assertions": [{"label": "c2pa.probe", "data": {"hello": "world"}}],
}

# Try ES256 with the key as the actual PEM bytes
for alg_name, alg in [
    ("ES256", c2pa.C2paSigningAlg.ES256),
    ("ES384", c2pa.C2paSigningAlg.ES384),
    ("PS256", c2pa.C2paSigningAlg.PS256),
]:
    print(f"\n=== Trying {alg_name} ===")
    info = c2pa.C2paSignerInfo(
        alg=alg,
        sign_cert=cert_der,
        private_key=key_der,
        ta_url=None,
    )
    try:
        signer = c2pa.Signer.from_info(info)
        print(f"  Signer OK: reserve_size={signer.reserve_size()}")
        builder = c2pa.Builder(manifest_json)
        signed_stream = builder.sign(
            signer,
            "image/png",
            io.BytesIO(image_bytes),
            io.BytesIO(),
        )
        signed_bytes = signed_stream.getvalue() if hasattr(signed_stream, "getvalue") else signed_stream
        print(f"  SIGNED! Output: {len(signed_bytes)} bytes")
        with open(f"probe_{alg_name}.png", "wb") as f:
            f.write(signed_bytes)
        break  # one success is enough
    except Exception as exc:
        print(f"  FAILED: {type(exc).__name__}: {exc}")
