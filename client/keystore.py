"""
Client-side keystore.

The user's identity keys (sig_priv, dh_priv) live on the client's disk
in a small file per user. Both keys are encrypted with `kek` — the key
derived from the password via Argon2id + HMAC (§7.1).

File layout:
    magic(4) | version(1) | nonce(12) | ciphertext(64) | tag(16)

Where the 64-byte ciphertext decrypts to:
    sig_priv (32-byte scalar) || dh_priv (32-byte scalar)

Losing the password means losing the file — this is by design (§7 limitations).
"""

from __future__ import annotations

import os

from crypto.gcm import encrypt as gcm_encrypt, decrypt as gcm_decrypt

MAGIC = b"SVKS"
VERSION = 1
NONCE_LEN = 12
PLAINTEXT_LEN = 64        # two 32-byte scalars
TAG_LEN = 16


class KeystoreError(Exception):
    """Raised when the keystore file is missing, corrupt, or the kek is wrong."""


def save_keys(path: str, sig_priv: int, dh_priv: int, kek: bytes) -> None:
    """Encrypt (sig_priv, dh_priv) with kek and write to `path`."""
    if len(kek) != 32:
        raise ValueError("kek must be 32 bytes")
    plaintext = _encode_scalars(sig_priv, dh_priv)
    nonce = os.urandom(NONCE_LEN)
    aad = MAGIC + bytes([VERSION])
    ciphertext, tag = gcm_encrypt(kek, nonce, plaintext, aad)

    blob = MAGIC + bytes([VERSION]) + nonce + ciphertext + tag
    _atomic_write(path, blob)


def load_keys(path: str, kek: bytes) -> tuple[int, int]:
    """Read `path`, decrypt with kek, return (sig_priv, dh_priv).

    Raises KeystoreError if the file is missing, malformed, or if kek is
    wrong (GCM tag verification fails)."""
    if len(kek) != 32:
        raise ValueError("kek must be 32 bytes")
    if not os.path.exists(path):
        raise KeystoreError(f"keystore not found: {path}")

    with open(path, "rb") as f:
        blob = f.read()

    expected_len = 4 + 1 + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN
    if len(blob) != expected_len:
        raise KeystoreError("keystore has wrong length")
    if blob[:4] != MAGIC:
        raise KeystoreError("bad magic — not a SecureVault keystore")
    if blob[4] != VERSION:
        raise KeystoreError(f"unsupported keystore version: {blob[4]}")

    nonce = blob[5 : 5 + NONCE_LEN]
    ciphertext = blob[5 + NONCE_LEN : 5 + NONCE_LEN + PLAINTEXT_LEN]
    tag = blob[5 + NONCE_LEN + PLAINTEXT_LEN :]
    aad = MAGIC + bytes([VERSION])

    plaintext = gcm_decrypt(kek, nonce, ciphertext, tag, aad)
    if plaintext is None:
        raise KeystoreError("wrong password or corrupt keystore")
    return _decode_scalars(plaintext)


def rewrap_keys(path: str, old_kek: bytes, new_kek: bytes) -> None:
    """Load with old_kek, re-encrypt with new_kek. Used by change_password
    so the same identity keys stay valid — old shares still open (§7.1)."""
    sig_priv, dh_priv = load_keys(path, old_kek)
    save_keys(path, sig_priv, dh_priv, new_kek)


# --- Internal ------------------------------------------------------------

def _encode_scalars(sig_priv: int, dh_priv: int) -> bytes:
    return sig_priv.to_bytes(32, "big") + dh_priv.to_bytes(32, "big")


def _decode_scalars(plaintext: bytes) -> tuple[int, int]:
    return (int.from_bytes(plaintext[:32], "big"),
            int.from_bytes(plaintext[32:], "big"))


def _atomic_write(path: str, data: bytes) -> None:
    """Write via a temp file + rename so a crash mid-write can't leave a
    truncated keystore that locks the user out."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
