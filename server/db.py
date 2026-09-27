"""
SecureVault server database.

SQLite storage for three tables:

  users        — one row per registered account
  documents    — one row per uploaded encrypted document
  shares       — one row per (document, recipient) pair

Everything the server stores is either public or encrypted:
  - Public key material: auth_pub, sig_pub, dh_pub (raw bytes).
  - Ciphertexts: document ciphertext, wrapped file keys, GCM tags.
  - Metadata bound as AAD: owner name, version, timestamp. Server can
    read these but cannot change them without breaking every recipient's
    GCM tag verification.

The server never sees:
  - Passwords (only the Argon2id salt).
  - Any user's `master`, `auth_key`, or `kek` (derived client-side).
  - Any user's private keys (stored client-side, encrypted with kek).
  - Any document's file key FK (delivered via ECDH-wrapped share records).

sqlite3 is stdlib and is a "storage" library — permitted by the spec.

Author: SecureVault team, ENCS4320.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass


# --- Schema --------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username         TEXT PRIMARY KEY,
    salt             BLOB NOT NULL,      -- 16-byte Argon2id salt
    argon2_t         INTEGER NOT NULL,   -- time cost (iterations)
    argon2_m         INTEGER NOT NULL,   -- memory cost (KiB)
    argon2_p         INTEGER NOT NULL,   -- parallelism
    auth_pub         BLOB NOT NULL,      -- 65 bytes, for login challenge
    sig_pub          BLOB NOT NULL,      -- 65 bytes, for document signing
    dh_pub           BLOB NOT NULL       -- 65 bytes, for ECDH key wrapping
);

CREATE TABLE IF NOT EXISTS documents (
    doc_id           BLOB PRIMARY KEY,   -- 16 bytes
    owner            TEXT NOT NULL,      -- foreign key to users.username
    version          INTEGER NOT NULL,   -- monotonic, starts at 1
    created_ms       INTEGER NOT NULL,   -- ms since epoch
    blob             BLOB NOT NULL,      -- full SVD1 blob from formats.pack_document
    FOREIGN KEY (owner) REFERENCES users(username)
);

CREATE TABLE IF NOT EXISTS shares (
    doc_id           BLOB NOT NULL,      -- 16 bytes
    recipient        TEXT NOT NULL,      -- foreign key to users.username
    blob             BLOB NOT NULL,      -- full SVS1 blob from formats.pack_share
    issued_ms        INTEGER NOT NULL,   -- when this share was created
    PRIMARY KEY (doc_id, recipient),
    FOREIGN KEY (doc_id) REFERENCES documents(doc_id),
    FOREIGN KEY (recipient) REFERENCES users(username)
);

CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient);
CREATE INDEX IF NOT EXISTS idx_docs_owner        ON documents(owner);
"""


# --- Data classes returned by the DB -------------------------------------

@dataclass(frozen=True)
class UserRecord:
    """What the server knows about a user. All fields are non-secret."""
    username:  str
    salt:      bytes
    argon2_t:  int
    argon2_m:  int
    argon2_p:  int
    auth_pub:  bytes
    sig_pub:   bytes
    dh_pub:    bytes

    def argon2_params(self) -> dict:
        return {"t": self.argon2_t, "m": self.argon2_m, "p": self.argon2_p}


@dataclass(frozen=True)
class DocumentRecord:
    """Stored SVD1 blob plus indexed fields for lookup."""
    doc_id:      bytes
    owner:       str
    version:     int
    created_ms:  int
    blob:        bytes    # what pack_document produced


@dataclass(frozen=True)
class ShareRecord:
    """Stored SVS1 blob for one recipient of one document."""
    doc_id:      bytes
    recipient:   str
    blob:        bytes    # what pack_share produced
    issued_ms:   int


# --- The DB itself -------------------------------------------------------

class ServerDB:
    def __init__(self, path: str = ":memory:") -> None:
        # check_same_thread=False lets one connection be used by multiple
        # threads; we serialize with self._lock below.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- Users ---------------------------------------------------------

    def create_user(self, u: UserRecord) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (u.username, u.salt, u.argon2_t, u.argon2_m, u.argon2_p,
                     u.auth_pub, u.sig_pub, u.dh_pub),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as e:
                raise ValueError(f"user '{u.username}' already exists") from e

    def get_user(self, username: str) -> UserRecord | None:
        """Return the user record or None if unknown."""
        with self._lock:
            row = self._conn.execute(
                "SELECT username, salt, argon2_t, argon2_m, argon2_p, "
                "auth_pub, sig_pub, dh_pub FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return UserRecord(*row) if row else None

    def update_user_auth(self, username: str,
                         salt: bytes, argon2_t: int, argon2_m: int, argon2_p: int,
                         auth_pub: bytes) -> None:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET salt = ?, argon2_t = ?, argon2_m = ?, "
                "argon2_p = ?, auth_pub = ? WHERE username = ?",
                (salt, argon2_t, argon2_m, argon2_p, auth_pub, username),
            )
            self._conn.commit()
        if cur.rowcount == 0:
            raise ValueError(f"user '{username}' not found")

    # ---- Documents -----------------------------------------------------

    def create_document(self, d: DocumentRecord) -> None:
        if d.version != 1:
            raise ValueError("new document must start at version 1")
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO documents VALUES (?, ?, ?, ?, ?)",
                    (d.doc_id, d.owner, d.version, d.created_ms, d.blob),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as e:
                raise ValueError(f"doc_id already exists") from e

    def update_document(self, d: DocumentRecord) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT version FROM documents WHERE doc_id = ?",
                (d.doc_id,),
            ).fetchone()
            if row is None:
                raise ValueError("document not found")
            current_version = row[0]
            if d.version != current_version + 1:
                raise ValueError(
                    f"version must be exactly {current_version + 1}, "
                    f"got {d.version}"
                )
            self._conn.execute(
                "UPDATE documents SET version = ?, created_ms = ?, blob = ? "
                "WHERE doc_id = ?",
                (d.version, d.created_ms, d.blob, d.doc_id),
            )
            self._conn.commit()

    def get_document(self, doc_id: bytes) -> DocumentRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT doc_id, owner, version, created_ms, blob "
                "FROM documents WHERE doc_id = ?",
                (doc_id,),
            ).fetchone()
        return DocumentRecord(*row) if row else None

    def list_documents_owned_by(self, owner: str) -> list[DocumentRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT doc_id, owner, version, created_ms, blob "
                "FROM documents WHERE owner = ? ORDER BY created_ms",
                (owner,),
            ).fetchall()
        return [DocumentRecord(*r) for r in rows]

    # ---- Shares --------------------------------------------------------

    def create_or_replace_share(self, s: ShareRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO shares "
                "(doc_id, recipient, blob, issued_ms) VALUES (?, ?, ?, ?)",
                (s.doc_id, s.recipient, s.blob, s.issued_ms),
            )
            self._conn.commit()

    def get_share(self, doc_id: bytes, recipient: str) -> ShareRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT doc_id, recipient, blob, issued_ms "
                "FROM shares WHERE doc_id = ? AND recipient = ?",
                (doc_id, recipient),
            ).fetchone()
        return ShareRecord(*row) if row else None

    def list_shares_for(self, recipient: str) -> list[ShareRecord]:
        """Every share addressed to this user — for LIST_DOCS."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT doc_id, recipient, blob, issued_ms "
                "FROM shares WHERE recipient = ? ORDER BY issued_ms",
                (recipient,),
            ).fetchall()
        return [ShareRecord(*r) for r in rows]

    # ---- Debug ---------------------------------------------------------

    def dump_stats(self) -> dict:
        """Small helper for the `dump_doc.py` demo script."""
        with self._lock:
            n_users = self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            n_docs  = self._conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            n_shrs  = self._conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
        return {"users": n_users, "documents": n_docs, "shares": n_shrs}
