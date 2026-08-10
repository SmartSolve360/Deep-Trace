"""
Unit tests for security primitives (HMAC, key derivation, challenges).
"""

from __future__ import annotations

import time

import pytest

from app.core.exceptions import AuthError
from app.core.security import (
    Challenge,
    constant_time_compare,
    derive_subkey,
    hmac_sha256,
    is_valid_api_key,
    issue_challenge,
    verify_challenge,
    verify_hmac_sha256,
)


def test_derive_subkey_deterministic():
    a = derive_subkey(b"x" * 32, "test/purpose")
    b = derive_subkey(b"x" * 32, "test/purpose")
    assert a == b
    assert len(a) == 32


def test_derive_subkey_different_purposes():
    a = derive_subkey(b"x" * 32, "purpose/A")
    b = derive_subkey(b"x" * 32, "purpose/B")
    assert a != b


def test_derive_subkey_short_master_rejected():
    with pytest.raises(ValueError):
        derive_subkey(b"short", "test")


def test_derive_subkey_stretches():
    a = derive_subkey(b"x" * 32, "stretch", length=64)
    assert len(a) == 64


def test_hmac_round_trip():
    key = b"k" * 32
    data = b"hello world"
    tag = hmac_sha256(key, data)
    assert verify_hmac_sha256(key, data, tag)
    assert not verify_hmac_sha256(key, data + b"x", tag)


def test_constant_time_compare():
    assert constant_time_compare(b"abc", b"abc")
    assert not constant_time_compare(b"abc", b"abd")
    assert not constant_time_compare(b"abc", b"abcd")


def test_challenge_issue_and_verify():
    account = "acct-1"
    ch = issue_challenge(account)
    verify_challenge(account, ch)  # no exception


def test_challenge_wrong_account_rejected():
    ch = issue_challenge("acct-1")
    with pytest.raises(AuthError):
        verify_challenge("acct-2", ch)


def test_challenge_expired_rejected(monkeypatch):
    ch = issue_challenge("acct-1")
    # Advance the clock past expiry
    future = ch.expires_at + 10
    monkeypatch.setattr("app.core.security.time.time", lambda: future)
    with pytest.raises(AuthError):
        verify_challenge("acct-1", ch)


def test_challenge_token_round_trip():
    ch = issue_challenge("acct-1")
    token = ch.to_token()
    ch2 = Challenge.from_token(token)
    assert ch.nonce == ch2.nonce
    assert ch.issued_at == ch2.issued_at
    assert ch.mac == ch2.mac


def test_api_key_validation(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "API_KEYS", ["good_key_1", "good_key_2"])
    assert is_valid_api_key("good_key_1")
    assert is_valid_api_key("good_key_2")
    assert not is_valid_api_key("bad_key")
    assert not is_valid_api_key(None)
    assert not is_valid_api_key("")
