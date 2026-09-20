from __future__ import annotations
from .sha256 import sha256

_BLOCK_SIZE = 64   # SHA-256 processes 64-byte blocks
_IPAD = 0x36
_OPAD = 0x5C


def hmac_sha256(key: bytes, message: bytes) -> bytes:

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("hmac key must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("hmac message must be bytes")

    key = bytes(key)
    message = bytes(message)

    # Step 1: reduce/pad the key to exactly one block (B = 64 bytes).
    if len(key) > _BLOCK_SIZE:
        # Long keys are hashed first (RFC 2104 Sec. 2).
        key = sha256(key)
    if len(key) < _BLOCK_SIZE:
        # Short keys are right-padded with zeros.
        key = key + b"\x00" * (_BLOCK_SIZE - len(key))
    # Now len(key) == 64.

    # Step 2: build the inner and outer padded keys.
    # XOR each byte of the block-sized key with the pad constant.
    inner_key = bytes(b ^ _IPAD for b in key)
    outer_key = bytes(b ^ _OPAD for b in key)

    # Step 3: two SHA-256 calls.
    inner_hash = sha256(inner_key + message)          # H( (K' XOR ipad) || m )
    return sha256(outer_key + inner_hash)             # H( (K' XOR opad) || inner_hash )


def verify(key: bytes, message: bytes, tag: bytes) -> bool:

    expected = hmac_sha256(key, message)
    return _consttime_equal(expected, tag)


def _consttime_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
