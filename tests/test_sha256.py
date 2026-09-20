
import hashlib
import os
import sys
import unittest

# Make src/ importable without any packaging.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../..", "src"))

from crypto.sha256 import sha256, Sha256  # noqa: E402


# --- Known-answer tests (NIST + FIPS 180-4 examples) ----------------------

KAT = [
    # (message, expected hex digest)
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        b"abc",
        # FIPS 180-4 Appendix B.1
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        # FIPS 180-4 Appendix B.2
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        b"The quick brown fox jumps over the lazy dog",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    ),
    (
        b"The quick brown fox jumps over the lazy dog.",  # one-byte change
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
    ),
]


class TestSha256KAT(unittest.TestCase):
    def test_known_answers(self) -> None:
        for msg, expected in KAT:
            with self.subTest(msg=msg[:20]):
                self.assertEqual(sha256(msg).hex(), expected)

    def test_million_a(self) -> None:
        """FIPS 180-4 Appendix B.3: one million 'a' characters."""
        msg = b"a" * 1_000_000
        expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        self.assertEqual(sha256(msg).hex(), expected)


# --- Cross-check against hashlib on random inputs -------------------------

class TestSha256Random(unittest.TestCase):
    def test_random_lengths(self) -> None:
        # Cover every length class: less than one block, exactly one block,
        # crossing block boundaries, and just above the padding threshold.
        interesting = [0, 1, 55, 56, 63, 64, 65, 111, 112, 119, 127, 128, 129, 1000, 5000]
        for n in interesting:
            with self.subTest(n=n):
                data = os.urandom(n)
                self.assertEqual(sha256(data).hex(), hashlib.sha256(data).hexdigest())

    def test_random_batch(self) -> None:
        for _ in range(50):
            n = int.from_bytes(os.urandom(2), "big") % 8000
            data = os.urandom(n)
            self.assertEqual(sha256(data), hashlib.sha256(data).digest())


# --- Incremental API matches one-shot API and hashlib ---------------------

class TestSha256Incremental(unittest.TestCase):
    def test_streaming_matches_oneshot(self) -> None:
        data = os.urandom(10_000)
        h = Sha256()
        # Feed in awkward chunk sizes to exercise the buffer.
        for chunk in (data[:7], data[7:64], data[64:65], data[65:200], data[200:]):
            h.update(chunk)
        self.assertEqual(h.digest(), sha256(data))
        self.assertEqual(h.digest.__self__ is not None, True)  # sanity

    def test_streaming_matches_hashlib(self) -> None:
        data = os.urandom(3000)
        h = Sha256()
        h.update(data[:1500])
        h.update(data[1500:])
        self.assertEqual(h.hexdigest(), hashlib.sha256(data).hexdigest())

    def test_digest_twice_rejected(self) -> None:
        h = Sha256()
        h.update(b"hi")
        h.digest()
        with self.assertRaises(RuntimeError):
            h.digest()

    def test_update_after_digest_rejected(self) -> None:
        h = Sha256()
        h.digest()
        with self.assertRaises(RuntimeError):
            h.update(b"x")


# --- Input validation -----------------------------------------------------

class TestSha256Types(unittest.TestCase):
    def test_str_rejected(self) -> None:
        with self.assertRaises(TypeError):
            sha256("not bytes")  # type: ignore[arg-type]

    def test_bytearray_accepted(self) -> None:
        ba = bytearray(b"hello")
        self.assertEqual(sha256(ba), hashlib.sha256(b"hello").digest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
