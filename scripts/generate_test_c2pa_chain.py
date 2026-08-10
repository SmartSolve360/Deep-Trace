"""Generate a CA + leaf cert chain for C2PA test signing.

c2pa-rs performs strict X.509 chain validation. Self-signed certs are
rejected with "the certificate is invalid". We work around this by
generating a self-signed CA, then issuing a leaf signing cert from it.

The CA is also added to the trust anchors in c2pa_keys/ so it can be
used for verification.

Outputs:
    c2pa_keys/ca.cert        self-signed CA cert
    c2pa_keys/test_signer.cert  leaf signing cert (issued by CA)
    c2pa_keys/test_signer.key   leaf private key
"""
from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def main() -> int:
    out_dir = Path("c2pa_keys")
    out_dir.mkdir(parents=True, exist_ok=True)
    ca_path = out_dir / "ca.cert"
    ca_key_path = out_dir / "ca.key"
    leaf_key_path = out_dir / "test_signer.key"
    leaf_cert_path = out_dir / "test_signer.cert"

    now = datetime.datetime.now(datetime.timezone.utc)

    # ---- 1. CA ----
    print("Generating EC P-256 CA keypair…")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "DEEP-TRACE Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DEEP-TRACE"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,  # CA can sign other certs
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"  CA cert: {ca_path} ({ca_path.stat().st_size} bytes)")

    # ---- 2. Leaf signing cert (issued by CA) ----
    print("Generating EC P-256 leaf keypair…")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "DEEP-TRACE Test Signer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DEEP-TRACE"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,  # not critical — some C2PA validators are strict
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    leaf_key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        leaf_key_path.chmod(0o600)
    except OSError:
        pass
    print(f"  leaf cert: {leaf_cert_path} ({leaf_cert_path.stat().st_size} bytes)")
    print(f"  leaf key:  {leaf_key_path} ({leaf_key_path.stat().st_size} bytes)")

    print()
    print("Cert chain built. Use this bundle in c2pa settings:")
    print(f"  C2PA_SIGNING_KEY_PATH={leaf_key_path}")
    print(f"  C2PA_SIGNING_CERT_PATH={leaf_cert_path}")
    print(f"  C2PA_TRUST_ANCHORS_PATH={ca_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
