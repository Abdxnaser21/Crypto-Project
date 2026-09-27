"""
Trust store tests.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from client.trust_store import (                                    # noqa: E402
    TrustStore, TrustStatus, KeyMismatchError,
    compute_fingerprint, format_fingerprint,
)


def _sig(): return b"\x04" + os.urandom(64)
def _dh():  return b"\x04" + os.urandom(64)


class TestFingerprint(unittest.TestCase):
    def test_deterministic(self) -> None:
        sig, dh = _sig(), _dh()
        self.assertEqual(compute_fingerprint(sig, dh),
                         compute_fingerprint(sig, dh))

    def test_swapped_half_changes_fingerprint(self) -> None:
        # If an attacker swaps just dh_pub, the fingerprint must change.
        sig, dh1, dh2 = _sig(), _dh(), _dh()
        self.assertNotEqual(compute_fingerprint(sig, dh1),
                            compute_fingerprint(sig, dh2))

    def test_64_hex_chars(self) -> None:
        fp = compute_fingerprint(_sig(), _dh())
        self.assertEqual(len(fp), 64)
        int(fp, 16)   # is valid hex

    def test_format_layout(self) -> None:
        fp = "a" * 64
        formatted = format_fingerprint(fp)
        # 8 groups of 4 per line, 2 lines total
        self.assertEqual(formatted.count("\n"), 1)
        self.assertEqual(formatted.count(" "), 14)   # 7 spaces per line, 2 lines


class TestTOFU(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.store = TrustStore("layla", base_dir=self.tmpdir)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_contact_records_unverified(self) -> None:
        sig, dh = _sig(), _dh()
        entry = self.store.record_first_contact("omar", sig, dh)
        self.assertEqual(entry.status, TrustStatus.UNVERIFIED)
        self.assertEqual(entry.fingerprint, compute_fingerprint(sig, dh))

    def test_duplicate_first_contact_rejected(self) -> None:
        sig, dh = _sig(), _dh()
        self.store.record_first_contact("omar", sig, dh)
        with self.assertRaises(ValueError):
            self.store.record_first_contact("omar", _sig(), _dh())

    def test_check_matches_stored_key(self) -> None:
        sig, dh = _sig(), _dh()
        self.store.record_first_contact("omar", sig, dh)
        entry = self.store.check("omar", sig, dh)
        self.assertEqual(entry.status, TrustStatus.UNVERIFIED)

    def test_check_unknown_raises_keyerror(self) -> None:
        with self.assertRaises(KeyError):
            self.store.check("ghost", _sig(), _dh())

    def test_key_swap_raises_mismatch(self) -> None:
        # This is the whole point of §7.4 — server hands out a different key,
        # client refuses it hard, no override.
        sig, dh = _sig(), _dh()
        self.store.record_first_contact("omar", sig, dh)
        with self.assertRaises(KeyMismatchError):
            self.store.check("omar", _sig(), _dh())     # attacker's keys

    def test_mark_verified_promotes(self) -> None:
        sig, dh = _sig(), _dh()
        self.store.record_first_contact("omar", sig, dh)
        entry = self.store.mark_verified("omar")
        self.assertEqual(entry.status, TrustStatus.VERIFIED)
        # Fingerprint unchanged, only status.
        self.assertEqual(entry.fingerprint, compute_fingerprint(sig, dh))

    def test_mark_verified_unknown_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.store.mark_verified("ghost")

    def test_mark_verified_idempotent(self) -> None:
        sig, dh = _sig(), _dh()
        self.store.record_first_contact("omar", sig, dh)
        self.store.mark_verified("omar")
        again = self.store.mark_verified("omar")
        self.assertEqual(again.status, TrustStatus.VERIFIED)

    def test_verified_key_still_blocks_swap(self) -> None:
        # After promoting to VERIFIED, a mismatch is still a mismatch.
        sig, dh = _sig(), _dh()
        self.store.record_first_contact("omar", sig, dh)
        self.store.mark_verified("omar")
        with self.assertRaises(KeyMismatchError):
            self.store.check("omar", _sig(), _dh())


class TestPersistence(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_reloads_across_instances(self) -> None:
        sig, dh = _sig(), _dh()
        s1 = TrustStore("layla", base_dir=self.tmpdir)
        s1.record_first_contact("omar", sig, dh)
        s1.mark_verified("omar")

        # New instance reads from disk.
        s2 = TrustStore("layla", base_dir=self.tmpdir)
        entry = s2.check("omar", sig, dh)
        self.assertEqual(entry.status, TrustStatus.VERIFIED)

    def test_two_users_have_separate_stores(self) -> None:
        sig, dh = _sig(), _dh()
        layla_store = TrustStore("layla", base_dir=self.tmpdir)
        omar_store = TrustStore("omar", base_dir=self.tmpdir)
        layla_store.record_first_contact("mahmoud", sig, dh)
        self.assertIsNone(omar_store.get("mahmoud"))

    def test_corrupt_file_ignored(self) -> None:
        # A garbage file must not crash; we just start with an empty store.
        path = os.path.join(self.tmpdir, "layla_trust.json")
        with open(path, "w") as f:
            f.write("not json at all }}}")
        store = TrustStore("layla", base_dir=self.tmpdir)
        self.assertEqual(store.all_entries(), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
