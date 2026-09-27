"""
Client-side trust store — TOFU with fingerprints (§7.4).

Every contact's public keys the client has ever received are stored here
with one of two statuses:

  UNVERIFIED — first time we saw this bundle. Usable, but the user
               hasn't compared the fingerprint out-of-band yet.
  VERIFIED   — user compared the fingerprint (in person or over a call)
               and marked it trusted.

If the server later hands out a DIFFERENT bundle for a name we already
know, this is a possible MITM key swap. We refuse the new bundle
outright. There is no "trust anyway" path — the spec's TOFU model does
not allow overriding a mismatch (§7.4).

Fingerprint = SHA-256(sig_pub || dh_pub), shown grouped in hex for
out-of-band reading. One SHA-256 covers BOTH keys so an attacker
can't swap just one half.

Storage: one JSON file per user, `{username}_trust.json`, mapping
contact name -> {"fingerprint": hex, "status": "UNVERIFIED"|"VERIFIED"}.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum

from crypto.sha256 import sha256


class TrustStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED   = "VERIFIED"


@dataclass(frozen=True)
class TrustEntry:
    fingerprint: str          # 64-char hex
    status:      TrustStatus


class KeyMismatchError(Exception):
    """Raised when a stored fingerprint differs from a newly-received one.
    This is a possible MITM key swap — never silently overridden."""

    def __init__(self, username: str, stored: TrustEntry, seen_fingerprint: str) -> None:
        self.username = username
        self.stored = stored
        self.seen_fingerprint = seen_fingerprint
        super().__init__(
            f"key changed for '{username}': "
            f"stored={stored.fingerprint} ({stored.status.value}), "
            f"seen={seen_fingerprint}"
        )


def compute_fingerprint(sig_pub: bytes, dh_pub: bytes) -> str:
    """SHA-256 over BOTH keys — swapping one half changes the fingerprint."""
    return sha256(sig_pub + dh_pub).hex()


def format_fingerprint(hex_fp: str) -> str:
    """Group into 4-char blocks, 8 per line — the layout used for
    out-of-band reading (also what gui.py's dialog displays)."""
    groups = [hex_fp[i:i + 4] for i in range(0, len(hex_fp), 4)]
    lines = [" ".join(groups[i:i + 8]) for i in range(0, len(groups), 8)]
    return "\n".join(lines)


class TrustStore:
    """
    File-backed key trust for one local user. `owner_username` is the
    user this store belongs to; entries inside are that user's contacts.
    """

    def __init__(self, owner_username: str, base_dir: str = ".") -> None:
        self.owner = owner_username
        self._path = os.path.join(base_dir, f"{owner_username}_trust.json")
        self._entries: dict[str, TrustEntry] = {}
        self._load()

    # ---- Public API ---------------------------------------------------

    def get(self, username: str) -> TrustEntry | None:
        return self._entries.get(username)

    def all_entries(self) -> dict[str, TrustEntry]:
        return dict(self._entries)

    def record_first_contact(self, username: str,
                             sig_pub: bytes, dh_pub: bytes) -> TrustEntry:
        """Store a bundle we've never seen before, as UNVERIFIED.
        Caller is responsible for having asked the user first."""
        if username in self._entries:
            raise ValueError(f"already have an entry for '{username}'")
        entry = TrustEntry(
            fingerprint=compute_fingerprint(sig_pub, dh_pub),
            status=TrustStatus.UNVERIFIED,
        )
        self._entries[username] = entry
        self._save()
        return entry

    def check(self, username: str, sig_pub: bytes, dh_pub: bytes) -> TrustEntry:
        """
        Compare a received bundle against what's stored.
        Returns the (unchanged) stored entry if it matches.
        Raises KeyMismatchError if the fingerprint has changed.
        Raises KeyError if there is no entry yet (caller must call
        record_first_contact after asking the user).
        """
        stored = self._entries.get(username)
        if stored is None:
            raise KeyError(username)
        seen = compute_fingerprint(sig_pub, dh_pub)
        if seen != stored.fingerprint:
            raise KeyMismatchError(username, stored, seen)
        return stored

    def mark_verified(self, username: str) -> TrustEntry:
        """Promote an UNVERIFIED entry to VERIFIED after out-of-band comparison."""
        stored = self._entries.get(username)
        if stored is None:
            raise KeyError(username)
        if stored.status == TrustStatus.VERIFIED:
            return stored
        entry = TrustEntry(fingerprint=stored.fingerprint,
                           status=TrustStatus.VERIFIED)
        self._entries[username] = entry
        self._save()
        return entry

    # ---- Persistence --------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for name, data in raw.items():
            try:
                self._entries[name] = TrustEntry(
                    fingerprint=str(data["fingerprint"]),
                    status=TrustStatus(data["status"]),
                )
            except (KeyError, ValueError):
                continue

    def _save(self) -> None:
        blob = {name: {"fingerprint": e.fingerprint, "status": e.status.value}
                for name, e in self._entries.items()}
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(blob, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._path)
