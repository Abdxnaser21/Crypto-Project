"""
Keystore tests.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from client.keystore import (                                       # noqa: E402
    save_keys, load_keys, rewrap_keys,
    KeystoreError, MAGIC, NONCE_LEN, PLAINTEXT_LEN, TAG_LEN,
)


class TestKeystore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        self.path = self.tmp.name
        self.kek = os.urandom(32)
        self.sig = int.from_bytes(os.urandom(32), "big")
        self.dh = int.from_bytes(os.urandom(32), "big")

    def tearDown(self) -> None:
        for p in (self.path, self.path + ".tmp"):
            if os.path.exists(p):
                os.remove(p)

    def test_save_and_load_roundtrip(self) -> None:
        save_keys(self.path, self.sig, self.dh, self.kek)
        sig, dh = load_keys(self.path, self.kek)
        self.assertEqual(sig, self.sig)
        self.assertEqual(dh, self.dh)

    def test_wrong_kek_rejected(self) -> None:
        save_keys(self.path, self.sig, self.dh, self.kek)
        with self.assertRaises(KeystoreError):
            load_keys(self.path, os.urandom(32))

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(KeystoreError):
            load_keys("/tmp/no-such-file-abcxyz", self.kek)

    def test_bad_magic_rejected(self) -> None:
        save_keys(self.path, self.sig, self.dh, self.kek)
        with open(self.path, "r+b") as f:
            f.write(b"XXXX")  # clobber magic
        with self.assertRaises(KeystoreError):
            load_keys(self.path, self.kek)

    def test_tampered_ciphertext_rejected(self) -> None:
        save_keys(self.path, self.sig, self.dh, self.kek)
        with open(self.path, "r+b") as f:
            f.seek(5 + NONCE_LEN)      # first byte of ciphertext
            byte = f.read(1)
            f.seek(5 + NONCE_LEN)
            f.write(bytes([byte[0] ^ 0x01]))
        with self.assertRaises(KeystoreError):
            load_keys(self.path, self.kek)

    def test_rewrap_preserves_keys(self) -> None:
        save_keys(self.path, self.sig, self.dh, self.kek)
        new_kek = os.urandom(32)
        rewrap_keys(self.path, self.kek, new_kek)

        # Old kek no longer works
        with self.assertRaises(KeystoreError):
            load_keys(self.path, self.kek)

        # New kek loads the same keys
        sig, dh = load_keys(self.path, new_kek)
        self.assertEqual(sig, self.sig)
        self.assertEqual(dh, self.dh)

    def test_bad_kek_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            save_keys(self.path, self.sig, self.dh, b"\x00" * 16)
        with self.assertRaises(ValueError):
            load_keys(self.path, b"\x00" * 16)

    def test_file_length_is_fixed(self) -> None:
        save_keys(self.path, self.sig, self.dh, self.kek)
        expected = 4 + 1 + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN
        self.assertEqual(os.path.getsize(self.path), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
