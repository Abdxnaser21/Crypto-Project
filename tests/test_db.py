"""
Server DB tests.

We check:
  1. CRUD ops on users, documents, shares work correctly.
  2. Duplicate usernames and duplicate doc_ids are rejected.
  3. Version freshness rule enforced: version must be exactly N+1.
  4. Share overwrite works (a re-share replaces the old share row).
  5. Basic thread safety — concurrent inserts don't corrupt the DB.
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from server.db import (                              # noqa: E402
    ServerDB, UserRecord, DocumentRecord, ShareRecord,
)


def _make_user(username: str = "layla") -> UserRecord:
    return UserRecord(
        username=username,
        salt=os.urandom(16),
        argon2_t=2, argon2_m=128 * 1024, argon2_p=1,
        auth_pub=b"\x04" + b"\x11" * 64,
        sig_pub=b"\x04" + b"\x22" * 64,
        dh_pub=b"\x04" + b"\x33" * 64,
    )


def _make_doc(owner: str = "layla",
              doc_id: bytes | None = None,
              version: int = 1) -> DocumentRecord:
    return DocumentRecord(
        doc_id=doc_id if doc_id is not None else os.urandom(16),
        owner=owner,
        version=version,
        created_ms=1_700_000_000_000 + version,
        blob=b"fake-svd1-blob-bytes-here-" + os.urandom(50),
    )


def _make_share(doc_id: bytes,
                recipient: str = "omar",
                issued_ms: int = 1_700_000_500_000) -> ShareRecord:
    return ShareRecord(
        doc_id=doc_id,
        recipient=recipient,
        blob=b"fake-svs1-blob-" + os.urandom(80),
        issued_ms=issued_ms,
    )


class TestUsers(unittest.TestCase):
    def setUp(self) -> None:
        self.db = ServerDB(":memory:")

    def test_create_and_get(self) -> None:
        u = _make_user()
        self.db.create_user(u)
        got = self.db.get_user("layla")
        self.assertEqual(got, u)

    def test_get_unknown_returns_none(self) -> None:
        self.assertIsNone(self.db.get_user("nobody"))

    def test_duplicate_user_rejected(self) -> None:
        self.db.create_user(_make_user("layla"))
        with self.assertRaises(ValueError):
            self.db.create_user(_make_user("layla"))

    def test_update_auth_preserves_identity_keys(self) -> None:
        u = _make_user()
        self.db.create_user(u)
        new_salt = os.urandom(16)
        new_auth = b"\x04" + b"\x99" * 64
        self.db.update_user_auth(
            "layla", new_salt, 3, 256 * 1024, 1, new_auth,
        )
        got = self.db.get_user("layla")
        assert got is not None
        self.assertEqual(got.salt, new_salt)
        self.assertEqual(got.auth_pub, new_auth)
        # Identity keys untouched — old shares still work.
        self.assertEqual(got.sig_pub, u.sig_pub)
        self.assertEqual(got.dh_pub, u.dh_pub)

    def test_update_unknown_user_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.db.update_user_auth("ghost", b"\x00" * 16, 1, 1024, 1, b"\x04" + b"\x00" * 64)


class TestDocuments(unittest.TestCase):
    def setUp(self) -> None:
        self.db = ServerDB(":memory:")
        self.db.create_user(_make_user("layla"))
        self.doc_id = os.urandom(16)

    def test_create_and_get(self) -> None:
        d = _make_doc(doc_id=self.doc_id)
        self.db.create_document(d)
        got = self.db.get_document(self.doc_id)
        self.assertEqual(got, d)

    def test_get_unknown_returns_none(self) -> None:
        self.assertIsNone(self.db.get_document(b"\x00" * 16))

    def test_new_doc_must_be_version_1(self) -> None:
        with self.assertRaises(ValueError):
            self.db.create_document(_make_doc(version=2))

    def test_duplicate_doc_id_rejected(self) -> None:
        self.db.create_document(_make_doc(doc_id=self.doc_id))
        with self.assertRaises(ValueError):
            self.db.create_document(_make_doc(doc_id=self.doc_id))

    def test_update_freshness_enforced(self) -> None:
        self.db.create_document(_make_doc(doc_id=self.doc_id, version=1))
        # v3 is a rollback attack — must fail (spec's freshness rule).
        with self.assertRaises(ValueError):
            self.db.update_document(_make_doc(doc_id=self.doc_id, version=3))
        # v1 again is a rollback too.
        with self.assertRaises(ValueError):
            self.db.update_document(_make_doc(doc_id=self.doc_id, version=1))
        # v2 is exactly current+1 — allowed.
        self.db.update_document(_make_doc(doc_id=self.doc_id, version=2))
        got = self.db.get_document(self.doc_id)
        assert got is not None
        self.assertEqual(got.version, 2)

    def test_update_missing_doc_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.db.update_document(_make_doc(version=2))

    def test_list_by_owner(self) -> None:
        for _ in range(3):
            self.db.create_document(_make_doc(owner="layla"))
        self.db.create_user(_make_user("omar"))
        self.db.create_document(_make_doc(owner="omar"))
        layla_docs = self.db.list_documents_owned_by("layla")
        omar_docs  = self.db.list_documents_owned_by("omar")
        self.assertEqual(len(layla_docs), 3)
        self.assertEqual(len(omar_docs), 1)


class TestShares(unittest.TestCase):
    def setUp(self) -> None:
        self.db = ServerDB(":memory:")
        self.db.create_user(_make_user("layla"))
        self.db.create_user(_make_user("omar"))
        self.doc_id = os.urandom(16)
        self.db.create_document(_make_doc(doc_id=self.doc_id))

    def test_create_and_get(self) -> None:
        s = _make_share(self.doc_id, recipient="omar")
        self.db.create_or_replace_share(s)
        got = self.db.get_share(self.doc_id, "omar")
        self.assertEqual(got, s)

    def test_re_share_replaces_previous(self) -> None:
        s1 = _make_share(self.doc_id, recipient="omar", issued_ms=1000)
        s2 = _make_share(self.doc_id, recipient="omar", issued_ms=2000)
        self.db.create_or_replace_share(s1)
        self.db.create_or_replace_share(s2)
        # Only s2 remains.
        got = self.db.get_share(self.doc_id, "omar")
        assert got is not None
        self.assertEqual(got.issued_ms, 2000)
        self.assertEqual(got.blob, s2.blob)

    def test_list_shares_for_recipient(self) -> None:
        d1, d2 = os.urandom(16), os.urandom(16)
        self.db.create_document(_make_doc(doc_id=d1))
        self.db.create_document(_make_doc(doc_id=d2))
        self.db.create_or_replace_share(_make_share(d1, "omar", 100))
        self.db.create_or_replace_share(_make_share(d2, "omar", 200))
        shares = self.db.list_shares_for("omar")
        self.assertEqual(len(shares), 2)
        # Ordered by issued_ms.
        self.assertEqual(shares[0].issued_ms, 100)
        self.assertEqual(shares[1].issued_ms, 200)


class TestThreadSafety(unittest.TestCase):
    """Sanity: many threads inserting concurrently don't corrupt anything."""

    def test_concurrent_user_creation(self) -> None:
        import uuid
        db = ServerDB(":memory:")
        errors = []

        def worker(n: int) -> None:
            for _ in range(n):
                # uuid4 is globally unique — no race on username collisions.
                try:
                    db.create_user(_make_user(f"user_{uuid.uuid4().hex}"))
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=worker, args=(20,)) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [])
        stats = db.dump_stats()
        self.assertEqual(stats["users"], 5 * 20)


class TestStats(unittest.TestCase):
    def test_dump_stats(self) -> None:
        db = ServerDB(":memory:")
        db.create_user(_make_user("layla"))
        db.create_user(_make_user("omar"))
        doc_id = os.urandom(16)
        db.create_document(_make_doc(doc_id=doc_id))
        db.create_or_replace_share(_make_share(doc_id, "omar"))
        self.assertEqual(db.dump_stats(),
                         {"users": 2, "documents": 1, "shares": 1})


if __name__ == "__main__":
    unittest.main(verbosity=2)
