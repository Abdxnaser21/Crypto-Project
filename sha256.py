
from __future__ import annotations
_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

# Initial hash values H0..H7: first 32 bits of the fractional parts of the
# square roots of the first 8 primes (FIPS 180-4 Section 5.3.3).
_H_INIT = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

_MASK32 = 0xFFFFFFFF  # 32-bit truncation mask


# --- Bitwise helpers -------------------------------------------------------
# All arithmetic in SHA-256 is on unsigned 32-bit words.

def _rotr(x: int, n: int) -> int:
    """Rotate 32-bit x right by n bits (FIPS 180-4 Sec. 3.2)."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _shr(x: int, n: int) -> int:
    """Logical right shift on a 32-bit word."""
    return (x & _MASK32) >> n


# The six SHA-256 functions (FIPS 180-4 Sec. 4.1.2).
def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & _MASK32) & z


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _big_sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _small_sigma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _small_sigma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


# --- Padding (FIPS 180-4 Sec. 5.1.1) --------------------------------------

def _pad(message: bytes) -> bytes:
    """
    Append 0x80, then zero bytes until length ≡ 56 (mod 64), then the
    original bit-length as a 64-bit big-endian integer. Total length is
    a multiple of 64 bytes = 512 bits.
    """
    bit_len = len(message) * 8
    padded = message + b"\x80"
    # Append zeros until length mod 64 == 56.
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += bit_len.to_bytes(8, "big")
    return padded


# --- Core compression (FIPS 180-4 Sec. 6.2.2) -----------------------------

def _compress(block: bytes, h: list[int]) -> list[int]:
    """Process one 512-bit block and update the 8-word hash state h."""
    # Step 1: prepare the message schedule W[0..63].
    W = [0] * 64
    for t in range(16):
        # Each word is 4 big-endian bytes of the block.
        W[t] = int.from_bytes(block[t * 4 : t * 4 + 4], "big")
    for t in range(16, 64):
        W[t] = (
            _small_sigma1(W[t - 2])
            + W[t - 7]
            + _small_sigma0(W[t - 15])
            + W[t - 16]
        ) & _MASK32

    # Step 2: initialize working variables a..h from current hash state.
    a, b, c, d, e, f, g, hh = h

    # Step 3: 64 rounds.
    for t in range(64):
        T1 = (hh + _big_sigma1(e) + _ch(e, f, g) + _K[t] + W[t]) & _MASK32
        T2 = (_big_sigma0(a) + _maj(a, b, c)) & _MASK32
        hh = g
        g = f
        f = e
        e = (d + T1) & _MASK32
        d = c
        c = b
        b = a
        a = (T1 + T2) & _MASK32

    # Step 4: add compressed chunk to the current hash state.
    return [
        (h[0] + a) & _MASK32,
        (h[1] + b) & _MASK32,
        (h[2] + c) & _MASK32,
        (h[3] + d) & _MASK32,
        (h[4] + e) & _MASK32,
        (h[5] + f) & _MASK32,
        (h[6] + g) & _MASK32,
        (h[7] + hh) & _MASK32,
    ]


# --- One-shot public API --------------------------------------------------

def sha256(message: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of message."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("sha256 input must be bytes")
    padded = _pad(bytes(message))
    h = list(_H_INIT)
    for i in range(0, len(padded), 64):
        h = _compress(padded[i : i + 64], h)
    return b"".join(word.to_bytes(4, "big") for word in h)


# --- Incremental (streaming) API ------------------------------------------
# Useful for large files during upload without holding them fully in RAM.

class Sha256:

    def __init__(self) -> None:
        self._h = list(_H_INIT)
        self._buffer = b""
        self._length = 0  # total bytes fed so far
        self._finalized = False

    def update(self, data: bytes) -> "Sha256":
        if self._finalized:
            raise RuntimeError("Sha256: update() after digest()")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Sha256.update: bytes required")
        self._length += len(data)
        buf = self._buffer + bytes(data)
        # Consume as many complete 64-byte blocks as we can; keep the rest.
        n_full = len(buf) // 64
        for i in range(n_full):
            self._h = _compress(buf[i * 64 : i * 64 + 64], self._h)
        self._buffer = buf[n_full * 64 :]
        return self

    def digest(self) -> bytes:
        if self._finalized:
            raise RuntimeError("Sha256: digest() called twice")
        self._finalized = True
        # Pad the leftover buffer using the total length seen.
        bit_len = self._length * 8
        pad = self._buffer + b"\x80"
        while len(pad) % 64 != 56:
            pad += b"\x00"
        pad += bit_len.to_bytes(8, "big")
        h = self._h
        for i in range(0, len(pad), 64):
            h = _compress(pad[i : i + 64], h)
        return b"".join(word.to_bytes(4, "big") for word in h)

    def hexdigest(self) -> str:
        return self.digest().hex()