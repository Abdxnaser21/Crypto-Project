from __future__ import annotations
import os

from .ec_p256 import (
    N, G, Point,
    scalar_mul, scalar_mul_g,
    point_to_bytes, point_from_bytes,
    is_valid_private_key, is_on_curve,
)
from .sha256 import sha256

_DOMAIN_LABEL = b"SecureVault-ECDH-v1"

# --- Keypair generation ---------------------------------------------------

def generate_keypair() -> tuple[int, bytes]:
    while True:
        candidate = int.from_bytes(os.urandom(32), "big")
        if is_valid_private_key(candidate):
            break
    public_point = scalar_mul_g(candidate)
    assert public_point is not None            # 1..N-1 -> never infinity
    return candidate, point_to_bytes(public_point)


# --- The ECDH primitive itself -------------------------------------------

def _raw_shared_x(private_scalar: int, peer_public_bytes: bytes) -> bytes:
    if not is_valid_private_key(private_scalar):
        raise ValueError("private scalar out of range [1, N-1]")

    peer_point = point_from_bytes(peer_public_bytes)   # validates on-curve
    # SEC 1 Sec. 3.3.1: also check the peer point is not the identity and
    # its order is N. On P-256 the whole group has prime order N, so any
    # on-curve non-identity point has order N — the on-curve + non-identity
    # check is enough.
    if not is_on_curve(peer_point) or peer_point is None:
        raise ValueError("peer public key invalid")

    shared_point = scalar_mul(private_scalar, peer_point)
    if shared_point is None:
        raise ValueError("ECDH produced the point at infinity")

    # Return the x-coordinate as 32 big-endian bytes (SEC 1 Sec. 3.3.1).
    return shared_point.x.to_bytes(32, "big")


def shared_key(
    private_scalar: int,
    peer_public_bytes: bytes,
    info: bytes = b"",
) -> bytes:
    raw_x = _raw_shared_x(private_scalar, peer_public_bytes)
    return sha256(_DOMAIN_LABEL + raw_x + info)
