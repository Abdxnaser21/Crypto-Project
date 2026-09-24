import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.gcm import encrypt, decrypt  # noqa: E402


NIST_VECTORS = [
    # Test Case 1 (AES-128, empty plaintext, empty AAD)
    dict(
        name="NIST TC1 (AES-128, empty)",
        key=bytes.fromhex("00000000000000000000000000000000"),
        nonce=bytes.fromhex("000000000000000000000000"),
        plaintext=b"",
        aad=b"",
        ciphertext=b"",
        tag=bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"),
    ),
    # Test Case 2 (AES-128, 16-byte zero plaintext, empty AAD)
    dict(
        name="NIST TC2 (AES-128, 16B zeros)",
        key=bytes.fromhex("00000000000000000000000000000000"),
        nonce=bytes.fromhex("000000000000000000000000"),
        plaintext=bytes.fromhex("00000000000000000000000000000000"),
        aad=b"",
        ciphertext=bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"),
        tag=bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf"),
    ),
    # Test Case 3 (AES-128, 64-byte plaintext, empty AAD)
    dict(
        name="NIST TC3 (AES-128, 64B)",
        key=bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        nonce=bytes.fromhex("cafebabefacedbaddecaf888"),
        plaintext=bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        aad=b"",
        ciphertext=bytes.fromhex(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985"
        ),
        tag=bytes.fromhex("4d5c2af327cd64a62cf35abd2ba6fab4"),
    ),
    # Test Case 4 (AES-128, 60-byte plaintext with AAD)
    dict(
        name="NIST TC4 (AES-128, 60B + AAD)",
        key=bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        nonce=bytes.fromhex("cafebabefacedbaddecaf888"),
        plaintext=bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        ),
        aad=bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        ciphertext=bytes.fromhex(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
        ),
        tag=bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47"),
    ),
    # Test Case 15 (AES-256, 64-byte plaintext, empty AAD)
    dict(
        name="NIST TC15 (AES-256, 64B)",
        key=bytes.fromhex(
            "feffe9928665731c6d6a8f9467308308"
            "feffe9928665731c6d6a8f9467308308"
        ),
        nonce=bytes.fromhex("cafebabefacedbaddecaf888"),
        plaintext=bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        aad=b"",
        ciphertext=bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662898015ad"
        ),
        tag=bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c"),
    ),
    # Test Case 16 (AES-256, 60-byte plaintext with AAD)
    dict(
        name="NIST TC16 (AES-256, 60B + AAD)",
        key=bytes.fromhex(
            "feffe9928665731c6d6a8f9467308308"
            "feffe9928665731c6d6a8f9467308308"
        ),
        nonce=bytes.fromhex("cafebabefacedbaddecaf888"),
        plaintext=bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        ),
        aad=bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        ciphertext=bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662"
        ),
        tag=bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b"),
    ),
]


class TestGcmNistVectors(unittest.TestCase):
    def test_encrypt_matches_vectors(self) -> None:
        for v in NIST_VECTORS:
            with self.subTest(v["name"]):
                ct, tag = encrypt(v["key"], v["nonce"], v["plaintext"], v["aad"])
                self.assertEqual(ct, v["ciphertext"], f"CT mismatch in {v['name']}")
                self.assertEqual(tag, v["tag"], f"tag mismatch in {v['name']}")

    def test_decrypt_matches_vectors(self) -> None:
        for v in NIST_VECTORS:
            with self.subTest(v["name"]):
                pt = decrypt(v["key"], v["nonce"], v["ciphertext"], v["tag"], v["aad"])
                self.assertEqual(pt, v["plaintext"])


# --- Tamper detection: the whole reason to use GCM -----------------------

class TestGcmTamper(unittest.TestCase):
    def setUp(self) -> None:
        self.key = os.urandom(32)
        self.nonce = b"\x00" * 12                # per §7.2: fresh key -> zero nonce
        self.pt = b"Hello Omar - this is thesis-draft.pdf contents."
        self.aad = b"doc_id=0123|owner=layla|version=1"
        self.ct, self.tag = encrypt(self.key, self.nonce, self.pt, self.aad)

    def test_honest_decrypt_roundtrip(self) -> None:
        pt = decrypt(self.key, self.nonce, self.ct, self.tag, self.aad)
        self.assertEqual(pt, self.pt)

    def test_flipped_ciphertext_byte_rejected(self) -> None:
        # The attacker in the scenario: "flips a single byte of the ciphertext"
        bad = bytearray(self.ct)
        bad[0] ^= 0x01
        self.assertIsNone(
            decrypt(self.key, self.nonce, bytes(bad), self.tag, self.aad)
        )

    def test_flipped_tag_byte_rejected(self) -> None:
        bad_tag = bytearray(self.tag)
        bad_tag[-1] ^= 0x80
        self.assertIsNone(
            decrypt(self.key, self.nonce, self.ct, bytes(bad_tag), self.aad)
        )

    def test_altered_aad_rejected(self) -> None:
        # The attacker in the scenario: "changes the recorded file name"
        bad_aad = self.aad.replace(b"owner=layla", b"owner=omar__")
        self.assertIsNone(
            decrypt(self.key, self.nonce, self.ct, self.tag, bad_aad)
        )

    def test_wrong_nonce_rejected(self) -> None:
        wrong_nonce = b"\x00" * 11 + b"\x01"
        self.assertIsNone(
            decrypt(self.key, wrong_nonce, self.ct, self.tag, self.aad)
        )

    def test_wrong_key_rejected(self) -> None:
        wrong_key = bytes(b ^ 1 for b in self.key)
        self.assertIsNone(
            decrypt(wrong_key, self.nonce, self.ct, self.tag, self.aad)
        )


# --- Cross-check against `cryptography` library --------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography library not installed")
class TestGcmCrossCheck(unittest.TestCase):
    def test_random_aes256(self) -> None:
        for _ in range(30):
            key = os.urandom(32)
            nonce = os.urandom(12)
            pt = os.urandom(int.from_bytes(os.urandom(2), "big") % 2000)
            aad = os.urandom(int.from_bytes(os.urandom(1), "big") % 50)

            # Reference: cryptography's AESGCM returns (ciphertext || tag).
            ref_out = AESGCM(key).encrypt(nonce, pt, aad)
            ref_ct, ref_tag = ref_out[:-16], ref_out[-16:]

            # Ours:
            our_ct, our_tag = encrypt(key, nonce, pt, aad)

            self.assertEqual(our_ct,  ref_ct)
            self.assertEqual(our_tag, ref_tag)

    def test_our_ct_decrypts_with_library(self) -> None:
        # Sanity: their decrypt accepts our ciphertexts.
        key = os.urandom(32)
        nonce = os.urandom(12)
        pt = b"round-trip through both implementations"
        aad = b"aad here"
        our_ct, our_tag = encrypt(key, nonce, pt, aad)
        recovered = AESGCM(key).decrypt(nonce, our_ct + our_tag, aad)
        self.assertEqual(recovered, pt)

    def test_library_ct_decrypts_with_ours(self) -> None:
        # And ours accepts theirs.
        key = os.urandom(32)
        nonce = os.urandom(12)
        pt = b"and back the other way"
        aad = b"same aad"
        blob = AESGCM(key).encrypt(nonce, pt, aad)
        ct, tag = blob[:-16], blob[-16:]
        self.assertEqual(decrypt(key, nonce, ct, tag, aad), pt)


# --- Input validation ----------------------------------------------------

class TestGcmValidation(unittest.TestCase):
    def test_wrong_nonce_len_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encrypt(b"\x00" * 32, b"\x00" * 11, b"", b"")
        with self.assertRaises(ValueError):
            encrypt(b"\x00" * 32, b"\x00" * 13, b"", b"")

    def test_wrong_key_len_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encrypt(b"\x00" * 24, b"\x00" * 12, b"", b"")   # AES-192

    def test_non_bytes_rejected(self) -> None:
        with self.assertRaises(TypeError):
            encrypt("not bytes", b"\x00" * 12, b"", b"")     # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main(verbosity=2)
