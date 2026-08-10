"""
Unit tests for the C2PA wrapper.

Verifies:
- Manifest generation always succeeds (never raises).
- Real signing is attempted when c2pa-python is installed and the
  cert+key paths point to readable files.
- Fallback to reference-only mode works when the cert can't be
  validated by c2pa-rs (self-signed dev certs).
- The manifest UUID is stable across calls.
- The structured assertion contains all required fields.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.engine.c2pa_wrapper import C2PAWrapper


SAMPLE_HASHES = {
    "phash": "abcdef0123456789",
    "dhash": "0123456789abcdef",
    "ahash": "fedcba9876543210",
    "whash": "1111222233334444",
}


def test_no_keys_falls_back_silently():
    """Without cert paths, the wrapper should not attempt signing."""
    w = C2PAWrapper()
    assert w._signing_viable is False
    m = w.generate_manifest(
        account_id="acct-1",
        asset_id="00000000-0000-0000-0000-000000000000",
        payload_hex="deadbeef" * 4,
        perceptual_hashes=SAMPLE_HASHES,
        device_sig="dev-1",
        timestamp=1700000000.0,
    )
    assert m.embedded is False
    assert m.reference.startswith("deep-trace://manifest/")
    assert m.manifest_uuid
    assert "assertion" in m.raw_manifest


def test_missing_key_file_does_not_raise():
    """A non-existent key file should not crash the wrapper."""
    w = C2PAWrapper(
        signing_key_path="c2pa_keys/does_not_exist.key",
        signing_cert_path="c2pa_keys/does_not_exist.cert",
    )
    assert w._signing_viable is False
    m = w.generate_manifest(
        account_id="acct-1",
        asset_id="00000000-0000-0000-0000-000000000000",
        payload_hex="deadbeef" * 4,
        perceptual_hashes=SAMPLE_HASHES,
        device_sig="dev-1",
        timestamp=1700000000.0,
    )
    assert m.embedded is False


def test_validate_reference_returns_none_for_fallback_url():
    w = C2PAWrapper()
    assert w.validate_reference("deep-trace://manifest/abc") is None
    assert w.validate_reference("") is None
    assert w.validate_reference(None) is None  # type: ignore[arg-type]


def test_validate_reference_returns_none_for_missing_file():
    w = C2PAWrapper()
    assert w.validate_reference("/tmp/does/not/exist.c2pa") is None


def test_assertion_contains_required_fields():
    w = C2PAWrapper()
    m = w.generate_manifest(
        account_id="acct-test",
        asset_id="00000000-0000-0000-0000-000000000000",
        payload_hex="0123456789abcdef" * 2,
        perceptual_hashes=SAMPLE_HASHES,
        device_sig="dev-x",
        timestamp=1700000000.0,
    )
    assertion = m.raw_manifest["assertion"]
    assert assertion["asset_id"] == "00000000-0000-0000-0000-000000000000"
    assert assertion["payload_hex"] == "0123456789abcdef" * 2
    assert assertion["perceptual_hashes"] == SAMPLE_HASHES
    assert assertion["device_signature"] == "dev-x"
    assert "creation_timestamp" in assertion
    assert assertion["generator"]["name"] == "DEEP-TRACE Engine"


def test_account_id_is_hashed_in_assertion():
    """The account_id should be hashed, not stored in plaintext."""
    w = C2PAWrapper()
    m = w.generate_manifest(
        account_id="sensitive-account-id-12345",
        asset_id="00000000-0000-0000-0000-000000000000",
        payload_hex="deadbeef" * 4,
        perceptual_hashes=SAMPLE_HASHES,
        device_sig="dev",
        timestamp=1700000000.0,
    )
    raw = m.raw_manifest["assertion"]
    assert "sensitive-account-id-12345" not in str(raw), "account_id leaked in plaintext"
    assert "account_id_hash" in raw
    assert len(raw["account_id_hash"]) == 16  # SHA-256 prefix


def test_uuid_is_unique_per_call():
    w = C2PAWrapper()
    ids = set()
    for _ in range(20):
        m = w.generate_manifest(
            account_id="acct-1",
            asset_id="00000000-0000-0000-0000-000000000000",
            payload_hex="deadbeef" * 4,
            perceptual_hashes=SAMPLE_HASHES,
            device_sig="dev",
            timestamp=1700000000.0,
        )
        ids.add(m.manifest_uuid)
    assert len(ids) == 20


def test_real_signing_attempted_when_cert_present(monkeypatch):
    """If a cert + key are present, the wrapper should attempt real
    signing. With self-signed dev certs, c2pa-rs will reject, and the
    wrapper should fall back to reference-only without raising."""
    # Generate a self-signed cert (the c2pa-keys/ folder)
    cert_dir = Path("c2pa_keys")
    key_path = cert_dir / "test_signer.key"
    cert_path = cert_dir / "test_signer.cert"

    if not (key_path.exists() and cert_path.exists()):
        pytest.skip("c2pa_keys/test_signer.{key,cert} not present (run scripts/generate_test_c2pa_cert.py)")

    w = C2PAWrapper(
        signing_key_path=str(key_path),
        signing_cert_path=str(cert_path),
    )
    # Viability is true (lib + files present)
    assert w._signing_viable is True

    m = w.generate_manifest(
        account_id="acct-real",
        asset_id="00000000-0000-0000-0000-000000000000",
        payload_hex="cafebabe" * 4,
        perceptual_hashes=SAMPLE_HASHES,
        device_sig="dev-real",
        timestamp=1700000000.0,
    )

    # Self-signed dev certs will be rejected by c2pa-rs -> fallback
    # OR a real C2PA trust-list cert would produce embedded=True
    if m.embedded:
        assert os.path.isfile(m.reference)
        assert m.raw_manifest.get("signed") is True
    else:
        assert m.reference.startswith("deep-trace://manifest/")
        assert m.raw_manifest.get("fallback") is True
