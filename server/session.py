"""
Server-side session state.

Three responsibilities:
  1. Nonce set — every used request_nonce is remembered, rejecting replays.
  2. Login challenge cache — random challenges issued by the server,
     consumed on login response (one-shot).
  3. Request signature check — every sensitive action carries a signature
     by the caller's own signing key, over a canonical string like
     "upload:{owner}:{nonce}". This lets the server authenticate the
     request without holding any secret.
"""

from __future__ import annotations

import os
import threading
import time

from crypto.ecdsa import verify as ecdsa_verify, signature_from_bytes

CHALLENGE_TTL_SECONDS = 60
CHALLENGE_LEN = 32


class SessionState:
    """Thread-safe holder for nonces and pending login challenges."""

    def __init__(self, challenge_ttl_seconds: int = CHALLENGE_TTL_SECONDS) -> None:
        self._used_nonces: set[str] = set()
        self._challenges: dict[str, tuple[bytes, float]] = {}
        self._ttl = challenge_ttl_seconds
        self._lock = threading.Lock()

    # ---- Login challenges ---------------------------------------------

    def issue_challenge(self, username: str) -> bytes:
        """Generate a random challenge and remember it for `username`."""
        challenge = os.urandom(CHALLENGE_LEN)
        with self._lock:
            self._challenges[username] = (challenge, time.monotonic())
        return challenge

    def consume_challenge(self, username: str) -> bytes | None:
        """
        Pop the challenge for `username`. Returns None if there isn't one,
        or if it's older than the TTL (prevents stale-challenge replay).
        A challenge is single-use — after consume, a new issue is required.
        """
        with self._lock:
            entry = self._challenges.pop(username, None)
            if entry is None:
                return None
            challenge, issued_at = entry
            if time.monotonic() - issued_at > self._ttl:
                return None
            return challenge

    # ---- Request nonces (replay protection) ---------------------------

    def check_and_consume_nonce(self, nonce_b64: str) -> bool:
        """
        Return True iff this nonce has never been seen. On success the
        nonce is added to the set so a second attempt returns False.
        """
        if not nonce_b64 or not isinstance(nonce_b64, str):
            return False
        with self._lock:
            if nonce_b64 in self._used_nonces:
                return False
            self._used_nonces.add(nonce_b64)
            return True

    def nonce_count(self) -> int:
        with self._lock:
            return len(self._used_nonces)

    # ---- Request signature check --------------------------------------

    @staticmethod
    def verify_request_signature(
        pubkey_bytes: bytes,
        canonical_payload: str,
        signature_bytes: bytes,
    ) -> bool:
        """
        Verify an ECDSA signature over a canonical string like
        "upload:{owner}:{nonce}". Never raises: returns False on any
        malformed input.
        """
        if not (isinstance(pubkey_bytes, (bytes, bytearray))
                and isinstance(signature_bytes, (bytes, bytearray))
                and isinstance(canonical_payload, str)):
            return False
        try:
            sig_tuple = signature_from_bytes(bytes(signature_bytes))
        except ValueError:
            return False
        return ecdsa_verify(bytes(pubkey_bytes),
                            canonical_payload.encode("utf-8"),
                            sig_tuple)


# ---- Canonical payload strings --------------------------------------
# All actions build the payload the same way on both client and server.
# One typo here breaks every signature — that's why it's in one place.

def payload_upload(owner: str, nonce_b64: str) -> str:
    return f"upload:{owner}:{nonce_b64}"


def payload_share(sender: str, doc_id_hex: str, recipient: str, nonce_b64: str) -> str:
    return f"share:{sender}:{doc_id_hex}:{recipient}:{nonce_b64}"


def payload_download(user: str, doc_id_hex: str, nonce_b64: str) -> str:
    return f"download:{user}:{doc_id_hex}:{nonce_b64}"


def payload_change_password(username: str, nonce_b64: str) -> str:
    return f"change_password:{username}:{nonce_b64}"
