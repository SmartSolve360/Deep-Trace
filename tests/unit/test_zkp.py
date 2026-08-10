"""
Unit tests for the Pedersen commitment scheme.
"""

from __future__ import annotations

import secrets

import pytest

from app.engine.zkp import PedersenCommitment

# A 32-byte test secret. Same value across the test session so the
# derived generator `h` is stable.
_TEST_MASTER_KEY = b"unit_test_pedersen_secret_32b_!!"  # exactly 32 bytes


def _pc() -> PedersenCommitment:
    """Build a fresh PedersenCommitment with the test master key."""
    return PedersenCommitment(master_key=_TEST_MASTER_KEY)


def test_requires_minimum_master_key_length():
    with pytest.raises(ValueError):
        PedersenCommitment(master_key=b"short")


def test_commit_verify_round_trip():
    pc = _pc()
    v = 12345678901234567890
    r = secrets.randbelow(pc.params.q - 2) + 1
    C, (v2, r2) = pc.commit(v, randomness=r)
    assert v2 == v
    assert r2 == r
    assert pc.verify(C, (v2, r2))


def test_commit_verify_random_randomness():
    pc = _pc()
    v = 42
    C, opening = pc.commit(v)
    assert pc.verify(C, opening)


def test_commit_hash_round_trip():
    pc = _pc()
    msg = b"account_id:secret_user_id"
    C, opening = pc.commit_hash(msg)
    assert pc.verify(C, opening)


def test_tampered_value_fails_verify():
    pc = _pc()
    C, (v, r) = pc.commit(100)
    # Tamper with the value
    assert not pc.verify(C, (v + 1, r))


def test_tampered_randomness_fails_verify():
    pc = _pc()
    C, (v, r) = pc.commit(100)
    bad_r = (r + 1) % pc.params.q
    if bad_r == 0:
        bad_r = 1
    assert not pc.verify(C, (v, bad_r))


def test_hiding_property():
    """Same value with two different random nonces should produce different commitments."""
    pc = _pc()
    v = 999
    C1, _ = pc.commit(v)
    C2, _ = pc.commit(v)
    assert C1 != C2


def test_to_from_hex():
    pc = _pc()
    C, _ = pc.commit(42)
    h = pc.to_hex(C)
    assert len(h) > 0
    C2 = pc.from_hex(h)
    assert C2 == C


def test_value_out_of_range():
    pc = _pc()
    with pytest.raises(ValueError):
        pc.commit(-1)
    with pytest.raises(ValueError):
        pc.commit(pc.params.q + 1)


def test_homomorphic_addition():
    """C(a+b) should equal C(a) * C(b) mod p (homomorphic property)."""
    pc = _pc()
    a, b = 100, 200
    ra, rb = secrets.randbelow(pc.params.q - 2) + 1, secrets.randbelow(pc.params.q - 2) + 1
    Ca, _ = pc.commit(a, ra)
    Cb, _ = pc.commit(b, rb)

    rc = secrets.randbelow(pc.params.q - 2) + 1
    Csum, _ = pc.commit(a + b, rc)

    p = pc.params.p
    lhs = (Csum * pow(Ca, -1, p) % p) * pow(Cb, -1, p) % p
    expected = pow(pc.params.h, (rc - ra - rb) % pc.params.q, p)
    assert lhs == expected


def test_different_master_keys_yield_different_h():
    """A different master key must derive a different h — otherwise
    we can't tell deployments apart."""
    pc1 = PedersenCommitment(master_key=b"deployment_a_secret_value_32b___")
    pc2 = PedersenCommitment(master_key=b"deployment_b_secret_value_32b___")
    assert pc1.params.h != pc2.params.h
    # And a commitment to the same value is incompatible
    C1, _ = pc1.commit(42)
    _, opening2 = pc2.commit(42)
    assert not pc2.verify(C1, opening2)


def test_commitment_unique_per_value():
    """Distinct values must produce distinct commitments (same randomness)."""
    pc = _pc()
    r = 12345
    C1, _ = pc.commit(100, randomness=r)
    C2, _ = pc.commit(101, randomness=r)
    assert C1 != C2
