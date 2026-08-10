"""
Unit tests for the Reed-Solomon error correction wrapper.
"""

from __future__ import annotations

import os
import secrets

import pytest

from app.engine.ecc import ReedSolomonCodec


def test_encode_decode_round_trip():
    codec = ReedSolomonCodec(data_bytes=16, ecc_bytes=32)
    payload = secrets.token_bytes(16)
    codeword = codec.encode(payload)
    assert len(codeword) == 48
    decoded, n_errors = codec.decode(codeword)
    assert decoded == payload
    assert n_errors == 0


def test_corrects_byte_errors():
    """RS(48, 16) should correct up to 16 byte errors."""
    codec = ReedSolomonCodec(data_bytes=16, ecc_bytes=32)
    payload = secrets.token_bytes(16)
    codeword = bytearray(codec.encode(payload))
    # Introduce 8 byte errors (well within 16-byte correction capacity)
    for i in range(8):
        codeword[i] ^= 0xFF
    decoded, n_errors = codec.decode(bytes(codeword))
    assert decoded == payload
    assert n_errors >= 8


def test_wrong_payload_length_rejected():
    codec = ReedSolomonCodec(data_bytes=16, ecc_bytes=32)
    with pytest.raises(ValueError):
        codec.encode(b"too_short")


def test_bit_capacity():
    codec = ReedSolomonCodec(data_bytes=16, ecc_bytes=32)
    assert codec.bit_capacity == 48 * 8
    assert codec.codeword_size == 48
