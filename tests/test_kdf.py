import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.hmac import hmac_sha256                                # noqa: E402
from crypto.kdf import derive_auth_key, derive_kek, derive_both    # noqa: E402


class TestKdf(unittest.TestCase):
    def setUp(self) -> None:
        # Fixed master so results are reproducible.
        self.master = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff"
        )

    def test_auth_label_is_exactly_ascii_auth(self) -> None:
        expected = hmac_sha256(self.master, b"auth")
        self.assertEqual(derive_auth_key(self.master), expected)

    def test_kek_label_is_exactly_ascii_kek(self) -> None:
        expected = hmac_sha256(self.master, b"kek")
        self.assertEqual(derive_kek(self.master), expected)

    def test_auth_and_kek_differ(self) -> None:
        # If the two labels ever collided, login key and file-encryption
        # key would be equal — a serious protocol flaw.
        self.assertNotEqual(derive_auth_key(self.master),
                            derive_kek(self.master))

    def test_derive_both_matches_individual(self) -> None:
        auth, kek = derive_both(self.master)
        self.assertEqual(auth, derive_auth_key(self.master))
        self.assertEqual(kek,  derive_kek(self.master))

    def test_outputs_are_32_bytes(self) -> None:
        self.assertEqual(len(derive_auth_key(self.master)), 32)
        self.assertEqual(len(derive_kek(self.master)),      32)

    def test_different_masters_give_different_keys(self) -> None:
        other = os.urandom(32)
        self.assertNotEqual(derive_auth_key(self.master),
                            derive_auth_key(other))


if __name__ == "__main__":
    unittest.main(verbosity=2)
