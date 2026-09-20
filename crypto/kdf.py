from __future__ import annotations
from .hmac import hmac_sha256

_LABEL_AUTH = b"auth"
_LABEL_KEK  = b"kek"

def derive_auth_key(master: bytes) -> bytes:
    """Derive the 32-byte authentication key used at login."""
    return hmac_sha256(master, _LABEL_AUTH)


def derive_kek(master: bytes) -> bytes:
    """Derive the 32-byte key-encryption-key that unlocks private keys."""
    return hmac_sha256(master, _LABEL_KEK)


def derive_both(master: bytes) -> tuple[bytes, bytes]:
    """Convenience: return (auth_key, kek) in one call."""
    return derive_auth_key(master), derive_kek(master)
