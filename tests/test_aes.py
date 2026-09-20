import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.aes import encrypt_block, AES  # noqa: E402


# --- FIPS 197 Appendix C vectors -----------------------------------------

FIPS_APPENDIX_C = [
    # AES-128 (Appendix C.1)
    dict(
        name="AES-128 FIPS 197 App C.1",
        key=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        plaintext=bytes.fromhex("00112233445566778899aabbccddeeff"),
        ciphertext=bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    ),
    # AES-256 (Appendix C.3)
    dict(
        name="AES-256 FIPS 197 App C.3",
        key=bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        ),
        plaintext=bytes.fromhex("00112233445566778899aabbccddeeff"),
        ciphertext=bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
    ),
]


class TestAesFips197(unittest.TestCase):
    def test_appendix_c_vectors(self) -> None:
        for v in FIPS_APPENDIX_C:
            with self.subTest(v["name"]):
                self.assertEqual(
                    encrypt_block(v["key"], v["plaintext"]),
                    v["ciphertext"],
                )

    def test_aes_class_matches_function(self) -> None:
        for v in FIPS_APPENDIX_C:
            with self.subTest(v["name"]):
                cipher = AES(v["key"])
                self.assertEqual(cipher.encrypt_block(v["plaintext"]),
                                 v["ciphertext"])



try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


def _ref_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Reference AES-ECB single-block encrypt via the `cryptography` lib."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography library not installed")
class TestAesRandomCrossCheck(unittest.TestCase):
    def test_random_aes128(self) -> None:
        for _ in range(50):
            key = os.urandom(16)
            pt = os.urandom(16)
            self.assertEqual(encrypt_block(key, pt),
                             _ref_encrypt_block(key, pt))

    def test_random_aes256(self) -> None:
        for _ in range(50):
            key = os.urandom(32)
            pt = os.urandom(16)
            self.assertEqual(encrypt_block(key, pt),
                             _ref_encrypt_block(key, pt))

    def test_many_blocks_same_key(self) -> None:
        """Same key, many different blocks — checks key schedule is stable."""
        key = os.urandom(32)
        cipher = AES(key)
        for _ in range(100):
            pt = os.urandom(16)
            self.assertEqual(cipher.encrypt_block(pt),
                             _ref_encrypt_block(key, pt))


# --- Input validation -----------------------------------------------------

class TestAesValidation(unittest.TestCase):
    def test_bad_key_size_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 24, b"\x00" * 16)  # AES-192 not supported
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 15, b"\x00" * 16)

    def test_bad_block_size_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 16, b"\x00" * 15)
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 16, b"\x00" * 17)

    def test_non_bytes_rejected(self) -> None:
        with self.assertRaises(TypeError):
            encrypt_block("not bytes", b"\x00" * 16)  # type: ignore[arg-type]


# --- AES-256 avalanche sanity --------------------------------------------

class TestAesAvalanche(unittest.TestCase):
    def test_one_bit_change_flips_many(self) -> None:
        """A one-bit change in the plaintext should flip roughly half the
        ciphertext bits (avalanche). Loose bound: at least 40 of 128."""
        key = os.urandom(32)
        pt1 = os.urandom(16)
        pt2 = bytes([pt1[0] ^ 1]) + pt1[1:]
        ct1 = encrypt_block(key, pt1)
        ct2 = encrypt_block(key, pt2)
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(ct1, ct2))
        self.assertGreaterEqual(diff_bits, 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
