from __future__ import annotations
from .aes import AES
from .hmac import _consttime_equal

_BLOCK = 16
_NONCE_LEN = 12                    # bytes (96 bits) — the recommended size
_MAX_PT_LEN = (1 << 36) - 32       # SP 800-38D Sec. 5.2.1.1

_R = 0xE1 << 120   # top byte 0xE1, rest zero, as a 128-bit integer


def _gf128_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        # Bit (127 - i) of x — MSB first.
        if (x >> (127 - i)) & 1:
            z ^= v
        # If LSB of v is 1, shift right and XOR with R; else just shift.
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _bytes_to_int(b: bytes) -> int:
    """16-byte block -> 128-bit integer (big-endian)."""
    return int.from_bytes(b, "big")


def _int_to_bytes(x: int) -> bytes:
    """128-bit integer -> 16-byte block (big-endian)."""
    return x.to_bytes(16, "big")


# --- GHASH ---------------------------------------------------------------

def _ghash(h_bytes: bytes, data: bytes) -> bytes:
    assert len(data) % _BLOCK == 0, "GHASH input must be block-aligned"
    h = _bytes_to_int(h_bytes)
    y = 0
    for i in range(0, len(data), _BLOCK):
        x = _bytes_to_int(data[i : i + _BLOCK])
        y = _gf128_mul(y ^ x, h)
    return _int_to_bytes(y)


# --- CTR mode using AES --------------------------------------------------

def _inc32(block: bytes) -> bytes:
    prefix = block[:12]
    ctr = int.from_bytes(block[12:], "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")


def _gctr(cipher: AES, icb: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = icb
    for i in range(0, len(data), _BLOCK):
        keystream = cipher.encrypt_block(counter)
        chunk = data[i : i + _BLOCK]
        # XOR truncated to len(chunk).
        out.extend(a ^ b for a, b in zip(chunk, keystream))
        counter = _inc32(counter)
    return bytes(out)


# --- Public API ----------------------------------------------------------

def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    _validate(key, nonce)
    if len(plaintext) > _MAX_PT_LEN:
        raise ValueError(f"plaintext too long (max {_MAX_PT_LEN} bytes per key/nonce)")

    cipher = AES(key)
    h = cipher.encrypt_block(b"\x00" * _BLOCK)          # GHASH subkey
    j0 = nonce + b"\x00\x00\x00\x01"                    # 12-byte nonce case

    # Encrypt the plaintext using CTR starting at J0+1.
    ciphertext = _gctr(cipher, _inc32(j0), plaintext)

    # Build the input to GHASH:  A || 0-pad || C || 0-pad || len(A)_64 || len(C)_64
    ghash_input = (
        aad + _zero_pad(len(aad))
        + ciphertext + _zero_pad(len(ciphertext))
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )
    s = _ghash(h, ghash_input)

    # Final tag = S XOR AES(J0).
    tag = bytes(a ^ b for a, b in zip(s, cipher.encrypt_block(j0)))
    return ciphertext, tag


def decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes | None:
    _validate(key, nonce)
    if not isinstance(tag, (bytes, bytearray)) or len(tag) != 16:
        return None

    cipher = AES(key)
    h = cipher.encrypt_block(b"\x00" * _BLOCK)
    j0 = nonce + b"\x00\x00\x00\x01"

    # Recompute the expected tag from the ciphertext + AAD, WITHOUT decrypting.
    ghash_input = (
        aad + _zero_pad(len(aad))
        + ciphertext + _zero_pad(len(ciphertext))
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )
    s = _ghash(h, ghash_input)
    expected_tag = bytes(a ^ b for a, b in zip(s, cipher.encrypt_block(j0)))

    # Constant-time compare — from hmac.py.
    if not _consttime_equal(expected_tag, bytes(tag)):
        return None                          # ⊥: tag failed; do NOT decrypt.

    # Tag valid — safe to decrypt.
    return _gctr(cipher, _inc32(j0), ciphertext)


# --- Helpers -------------------------------------------------------------

def _zero_pad(n: int) -> bytes:
    """Return the zero-padding needed to round n up to the next 16."""
    r = n % _BLOCK
    return b"\x00" * ((_BLOCK - r) % _BLOCK)


def _validate(key: bytes, nonce: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("GCM key must be bytes")
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("GCM nonce must be bytes")
    if len(key) not in (16, 32):
        raise ValueError("GCM key must be 16 or 32 bytes")
    if len(nonce) != _NONCE_LEN:
        raise ValueError(f"GCM nonce must be exactly {_NONCE_LEN} bytes (per §7.2)")
