"""
Generate a self-signed EC P-256 cert + private key for C2PA test signing.

EC P-256 + ES256 is the C2PA default signing algorithm and is more
forgiving of self-signed dev certs than RSA + PS256.

Outputs to ./c2pa_keys/test_signer.{key,cert}.

In production you would use a real CA-issued cert from a C2PA trust list
provider and a hardware-backed private key (HSM / KMS).
"""
from __future__ import annotations

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def main() -> int:
    out_dir = Path("c2pa_keys")
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "test_signer.key"
    cert_path = out_dir / "test_signer.cert"

    print("Generating EC P-256 keypair…")
    key = ec.generate_private_key(ec.SECP256R1())

    print("Building self-signed X.509 certificate…")
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "DEEP-TRACE Test Signer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DEEP-TRACE"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
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
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key (PEM, PKCS8, no encryption -- dev only)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    # Write cert (PEM)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"  private key: {key_path} ({key_path.stat().st_size} bytes)")
    print(f"  certificate: {cert_path} ({cert_path.stat().st_size} bytes)")
    print(f"  subject:     {cert.subject.rfc4514_string()}")
    print(f"  algorithm:   EC P-256 (ES256)")
    print(f"  valid:       {cert.not_valid_before_utc.isoformat()} to {cert.not_valid_after_utc.isoformat()}")
    print()
    print("Set these in your .env to use the test signer:")
    print("  C2PA_SIGNING_KEY_PATH=c2pa_keys/test_signer.key")
    print("  C2PA_SIGNING_CERT_PATH=c2pa_keys/test_signer.cert")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
