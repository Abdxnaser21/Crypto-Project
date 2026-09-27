from __future__ import annotations
import os

from .ec_p256 import (
    N, G,
    scalar_mul, scalar_mul_g, point_add,
    point_to_bytes, point_from_bytes,
    is_valid_private_key, is_on_curve,
)
from .sha256 import sha256
from .hmac import hmac_sha256


# --- Key generation -------------------------------------------------------

def generate_keypair() -> tuple[int, bytes]:
    while True:
        candidate = int.from_bytes(os.urandom(32), "big")
        if is_valid_private_key(candidate):
            break
    public_point = scalar_mul_g(candidate)
    assert public_point is not None
    return candidate, point_to_bytes(public_point)


# --- RFC 6979 deterministic k -------------------------------------------
# Section 3.2 pseudocode, adapted for P-256 (qlen = 256, hash = SHA-256).

def _bits2int(data: bytes, qlen: int) -> int:
    """RFC 6979 §2.3.2 — bits2int for qlen = 256 (32 bytes)."""
    v = int.from_bytes(data, "big")
    excess = len(data) * 8 - qlen
    if excess > 0:
        v >>= excess
    return v


def _int2octets(x: int, rlen_bytes: int) -> bytes:
    """RFC 6979 §2.3.3 — int2octets."""
    return x.to_bytes(rlen_bytes, "big")


def _bits2octets(data: bytes, q: int, qlen: int, rlen_bytes: int) -> bytes:
    """RFC 6979 §2.3.4 — bits2octets."""
    z1 = _bits2int(data, qlen)
    z2 = z1 % q
    return _int2octets(z2, rlen_bytes)


def _rfc6979_generate_k(private_scalar: int, message_hash: bytes) -> int:
    qlen = 256
    rlen_bytes = 32
    hlen = 32

    x_octets = _int2octets(private_scalar, rlen_bytes)
    h1_octets = _bits2octets(message_hash, N, qlen, rlen_bytes)

    # Step b: V = 0x01 0x01 ... 0x01 (hlen bytes)
    V = b"\x01" * hlen
    # Step c: K = 0x00 0x00 ... 0x00 (hlen bytes)
    K = b"\x00" * hlen
    # Step d: K = HMAC_K(V || 0x00 || x_octets || h1_octets)
    K = hmac_sha256(K, V + b"\x00" + x_octets + h1_octets)
    # Step e: V = HMAC_K(V)
    V = hmac_sha256(K, V)
    # Step f: K = HMAC_K(V || 0x01 || x_octets || h1_octets)
    K = hmac_sha256(K, V + b"\x01" + x_octets + h1_octets)
    # Step g: V = HMAC_K(V)
    V = hmac_sha256(K, V)

    # Step h: repeatedly try to build k until it's in [1, N-1]
    while True:
        T = b""
        while len(T) < rlen_bytes:
            V = hmac_sha256(K, V)
            T += V
        k_candidate = _bits2int(T, qlen)
        if 1 <= k_candidate <= N - 1:
            return k_candidate
        # Otherwise, reroll:
        K = hmac_sha256(K, V + b"\x00")
        V = hmac_sha256(K, V)


# --- Sign ----------------------------------------------------------------

def sign(private_scalar: int, message: bytes) -> tuple[int, int]:
    if not is_valid_private_key(private_scalar):
        raise ValueError("private scalar out of range [1, N-1]")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")

    z = _hash_to_scalar(message)

    # Deterministic k. Very small chance the first k gives r == 0 or s == 0;
    # in that case RFC 6979 says re-derive k by continuing the HMAC-DRBG,
    # but the probability is astronomically small on P-256. We loop just
    # in case, with a hard cap.
    for _ in range(1000):
        k = _rfc6979_generate_k(private_scalar, sha256(message))
        kG = scalar_mul(k, G)
        assert kG is not None
        r = kG.x % N
        if r == 0:
            continue
        k_inv = pow(k, -1, N)
        s = (k_inv * (z + r * private_scalar)) % N
        if s == 0:
            continue
        return r, s
    raise RuntimeError("ECDSA sign failed: no valid (r,s) after 1000 tries")


# --- Verify -------------------------------------------------------------

def verify(public_key_bytes: bytes, message: bytes, signature: tuple[int, int]) -> bool:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if not (isinstance(signature, tuple) and len(signature) == 2):
        return False
    r, s = signature
    if not (isinstance(r, int) and isinstance(s, int)):
        return False

    # Range checks — a valid signature has r, s in [1, N-1].
    if not (1 <= r <= N - 1 and 1 <= s <= N - 1):
        return False

    # Decode and validate the public key point.
    try:
        Q = point_from_bytes(public_key_bytes)
    except (ValueError, TypeError):
        return False
    if not is_on_curve(Q) or Q is None:
        return False

    z = _hash_to_scalar(message)
    # Standard ECDSA verify (FIPS 186-4 Sec. 6.4.2).
    try:
        w = pow(s, -1, N)
    except ValueError:
        return False
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = point_add(scalar_mul(u1, G), scalar_mul(u2, Q))
    if point is None:
        return False
    return (point.x % N) == r


# --- Encoding helpers ---------------------------------------------------

def signature_to_bytes(sig: tuple[int, int]) -> bytes:
    r, s = sig
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def signature_from_bytes(data: bytes) -> tuple[int, int]:
    """Decode a 64-byte fixed-length signature into (r, s)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) != 64:
        raise ValueError("signature must be exactly 64 bytes")
    return (int.from_bytes(data[:32], "big"),
            int.from_bytes(data[32:], "big"))


# --- Internal ------------------------------------------------------------

def _hash_to_scalar(message: bytes) -> int:
    h = sha256(bytes(message))
    return _bits2int(h, 256)
