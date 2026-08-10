"""Use c2pa.Reader to check what it thinks of our cert chain."""
import io

import c2pa

# Read the cert PEM as text
with open("c2pa_keys/test_signer.cert", "rb") as f:
    cert_pem = f.read().decode("ascii")
print(f"Cert PEM length: {len(cert_pem)} chars")
print(cert_pem[:200])
print("...")
print(cert_pem[-100:])

# Try parsing the cert as-is
print("\n=== Trying to read the cert as a manifest ===")
try:
    reader = c2pa.Reader.from_stream("image/jpeg", io.BytesIO(b"\x00" * 100))
    print(f"Reader: {reader}")
except Exception as e:
    print(f"Reader: {e}")

# Look at the trust anchor in Settings
print("\n=== Settings introspection ===")
s = c2pa.Settings()
print(f"Default settings: {s}")
# Try to enumerate what keys are accepted
for key in ["verify.trust_anchors", "trust.trust_anchors", "core.trust_anchors",
            "signer.cert", "builder.thumbnail.enabled", "verify.allowed_algorithms",
            "core.debug", "core.merkle_tree_size", "verify.ocsp_fetch"]:
    try:
        s.set(key, "true")
        print(f"  {key}: OK")
    except Exception as e:
        print(f"  {key}: FAILED ({e})")
