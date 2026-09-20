import hmac as stdlib_hmac
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.hmac import hmac_sha256, verify

RFC4231 = [
    # Case 1
    (1,
     "0b" * 20,
     b"Hi There".hex(),
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),

    # Case 2 -- key = "Jefe", message = "what do ya want for nothing?"
    (2,
     b"Jefe".hex(),
     b"what do ya want for nothing?".hex(),
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),

    # Case 3 -- 20-byte key of 0xaa, 50-byte message of 0xdd
    (3,
     "aa" * 20,
     "dd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),

    # Case 4 -- 25-byte key 0x01..0x19, 50-byte message of 0xcd
    (4,
     "".join(f"{i:02x}" for i in range(1, 26)),
     "cd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),

    # Case 5 -- truncation test; RFC gives a 128-bit truncated tag,
    # we compute the full one and check the prefix.
    # key = 0x0c * 20, message = "Test With Truncation"
    (5,
     "0c" * 20,
     b"Test With Truncation".hex(),
     None),  # handled specially below

    # Case 6 -- 131-byte key of 0xaa, message = "Test Using Larger Than
    # Block-Size Key - Hash Key First"
    (6,
     "aa" * 131,
     b"Test Using Larger Than Block-Size Key - Hash Key First".hex(),
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),

    # Case 7 -- 131-byte key of 0xaa, long message
    (7,
     "aa" * 131,
     (b"This is a test using a larger than block-size key and a larger "
      b"than block-size data. The key needs to be hashed before being "
      b"used by the HMAC algorithm.").hex(),
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]


class TestHmacRFC4231(unittest.TestCase):
    def test_case_1(self) -> None:
        self._run_case(1)

    def test_case_2(self) -> None:
        self._run_case(2)

    def test_case_3(self) -> None:
        self._run_case(3)

    def test_case_4(self) -> None:
        self._run_case(4)

    def test_case_5_truncated(self) -> None:
        # Case 5 in the RFC gives HMAC-SHA-256-128 (first 16 bytes).
        expected_128 = "a3b6167473100ee06e0c796c2955552b"
        key_hex, msg_hex, _ = self._lookup(5)
        tag = hmac_sha256(bytes.fromhex(key_hex), bytes.fromhex(msg_hex))
        self.assertEqual(tag[:16].hex(), expected_128)

    def test_case_6(self) -> None:
        self._run_case(6)

    def test_case_7(self) -> None:
        self._run_case(7)

    # helpers
    def _lookup(self, num):
        for n, k, m, t in RFC4231:
            if n == num:
                return k, m, t
        raise AssertionError(f"case {num} missing")

    def _run_case(self, num):
        key_hex, msg_hex, expected = self._lookup(num)
        tag = hmac_sha256(bytes.fromhex(key_hex), bytes.fromhex(msg_hex))
        self.assertEqual(tag.hex(), expected, f"RFC 4231 case {num} failed")


# --- Cross-check against stdlib hmac on random inputs ---------------------

class TestHmacRandom(unittest.TestCase):
    def test_random_batch(self) -> None:
        for _ in range(50):
            klen = int.from_bytes(os.urandom(1), "big") % 100 + 1
            mlen = int.from_bytes(os.urandom(2), "big") % 4000
            key = os.urandom(klen)
            msg = os.urandom(mlen)
            expected = stdlib_hmac.new(key, msg, hashlib.sha256).digest()
            self.assertEqual(hmac_sha256(key, msg), expected)

    def test_edge_key_lengths(self) -> None:
        # Around the block-size boundary of 64 bytes.
        for klen in [0, 1, 63, 64, 65, 128, 200]:
            with self.subTest(klen=klen):
                key = os.urandom(klen)
                msg = os.urandom(100)
                expected = stdlib_hmac.new(key, msg, hashlib.sha256).digest()
                self.assertEqual(hmac_sha256(key, msg), expected)

    def test_empty_message(self) -> None:
        key = os.urandom(32)
        expected = stdlib_hmac.new(key, b"", hashlib.sha256).digest()
        self.assertEqual(hmac_sha256(key, b""), expected)


# --- Constant-time verify ------------------------------------------------

class TestHmacVerify(unittest.TestCase):
    def test_verify_accepts_valid_tag(self) -> None:
        key, msg = b"secret", b"hello"
        self.assertTrue(verify(key, msg, hmac_sha256(key, msg)))

    def test_verify_rejects_wrong_tag(self) -> None:
        key, msg = b"secret", b"hello"
        bad = bytes([b ^ 1 for b in hmac_sha256(key, msg)])   # flip every bit
        self.assertFalse(verify(key, msg, bad))

    def test_verify_rejects_short_tag(self) -> None:
        self.assertFalse(verify(b"k", b"m", b"tooshort"))

    def test_verify_rejects_long_tag(self) -> None:
        good = hmac_sha256(b"k", b"m")
        self.assertFalse(verify(b"k", b"m", good + b"\x00"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
