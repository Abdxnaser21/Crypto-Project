import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.ec_p256 import scalar_mul_g, point_to_bytes, N  # noqa: E402
from crypto.ecdsa import (                                   # noqa: E402
    generate_keypair, sign, verify,
    signature_to_bytes, signature_from_bytes,
)


# --- RFC 6979 Appendix A.2.5 vectors -------------------------------------
# P-256 private key from A.2.5:
#     x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
# Public key Ux, Uy also given, but we can just recompute it from x*G.
#
# Format: (message_bytes, expected_r_hex, expected_s_hex)

RFC6979_D = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

RFC6979_VECTORS = [
    (
        b"sample",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ),
    (
        b"test",
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    ),
]


class TestRfc6979Vectors(unittest.TestCase):
    def test_sign_matches_rfc6979(self) -> None:
        for msg, exp_r, exp_s in RFC6979_VECTORS:
            with self.subTest(msg=msg):
                r, s = sign(RFC6979_D, msg)
                self.assertEqual(f"{r:064X}", exp_r,
                                 f"r mismatch for message {msg!r}")
                self.assertEqual(f"{s:064X}", exp_s,
                                 f"s mismatch for message {msg!r}")

    def test_deterministic_across_calls(self) -> None:
        # Signing the same message twice with the same key must give
        # the exact same (r, s). That's the whole point of RFC 6979.
        sig1 = sign(RFC6979_D, b"sample")
        sig2 = sign(RFC6979_D, b"sample")
        self.assertEqual(sig1, sig2)


# --- Round-trip: sign then verify ----------------------------------------

class TestRoundTrip(unittest.TestCase):
    def test_random_key_random_message(self) -> None:
        for _ in range(10):
            d, Q_bytes = generate_keypair()
            msg = os.urandom(200)
            sig = sign(d, msg)
            self.assertTrue(verify(Q_bytes, msg, sig))

    def test_empty_message_supported(self) -> None:
        d, Q_bytes = generate_keypair()
        sig = sign(d, b"")
        self.assertTrue(verify(Q_bytes, b"", sig))


# --- Tamper detection ---------------------------------------------------

class TestTamper(unittest.TestCase):
    def setUp(self) -> None:
        self.d, self.Q_bytes = generate_keypair()
        self.msg = b"transfer 1000 USD from Layla to Omar"
        self.sig = sign(self.d, self.msg)

    def test_altered_message_rejected(self) -> None:
        altered = self.msg.replace(b"1000", b"9999")
        self.assertFalse(verify(self.Q_bytes, altered, self.sig))

    def test_flipped_r_rejected(self) -> None:
        r, s = self.sig
        bad_r = r ^ 1
        self.assertFalse(verify(self.Q_bytes, self.msg, (bad_r, s)))

    def test_flipped_s_rejected(self) -> None:
        r, s = self.sig
        bad_s = s ^ 1
        self.assertFalse(verify(self.Q_bytes, self.msg, (r, bad_s)))

    def test_wrong_public_key_rejected(self) -> None:
        # Sign with one key, try to verify with another.
        _, other_pub = generate_keypair()
        self.assertFalse(verify(other_pub, self.msg, self.sig))

    def test_out_of_range_r_rejected(self) -> None:
        _, s = self.sig
        self.assertFalse(verify(self.Q_bytes, self.msg, (0, s)))
        self.assertFalse(verify(self.Q_bytes, self.msg, (N, s)))

    def test_out_of_range_s_rejected(self) -> None:
        r, _ = self.sig
        self.assertFalse(verify(self.Q_bytes, self.msg, (r, 0)))
        self.assertFalse(verify(self.Q_bytes, self.msg, (r, N)))

    def test_malformed_pubkey_rejected(self) -> None:
        self.assertFalse(verify(b"\x04" + b"\x00" * 64, self.msg, self.sig))
        self.assertFalse(verify(b"too short", self.msg, self.sig))


# --- Signature encoding round-trip --------------------------------------

class TestSignatureEncoding(unittest.TestCase):
    def test_roundtrip(self) -> None:
        d, _ = generate_keypair()
        sig = sign(d, b"anything")
        blob = signature_to_bytes(sig)
        self.assertEqual(len(blob), 64)              # matches §7.6 share_sig(64)
        self.assertEqual(signature_from_bytes(blob), sig)

    def test_wrong_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            signature_from_bytes(b"\x00" * 63)
        with self.assertRaises(ValueError):
            signature_from_bytes(b"\x00" * 65)


# --- Cross-check against `cryptography` library --------------------------

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature, decode_dss_signature,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography library not installed")
class TestCrossCheck(unittest.TestCase):
    def test_our_signature_verifies_with_library(self) -> None:
        for _ in range(5):
            d, Q_bytes = generate_keypair()
            msg = os.urandom(150)
            r, s = sign(d, msg)

            # Import our public key into the library's format
            pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), Q_bytes
            )
            der_sig = encode_dss_signature(r, s)
            # Should not raise
            pub_obj.verify(der_sig, msg, ec.ECDSA(hashes.SHA256()))

    def test_library_signature_verifies_with_ours(self) -> None:
        for _ in range(5):
            priv_obj = ec.generate_private_key(ec.SECP256R1())
            msg = os.urandom(150)
            der_sig = priv_obj.sign(msg, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der_sig)

            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat,
            )
            pub_bytes = priv_obj.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            self.assertTrue(verify(pub_bytes, msg, (r, s)))


# --- Input validation ---------------------------------------------------

class TestInvalidInputs(unittest.TestCase):
    def test_sign_bad_private_scalar_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sign(0, b"msg")
        with self.assertRaises(ValueError):
            sign(N, b"msg")

    def test_sign_non_bytes_message_rejected(self) -> None:
        d, _ = generate_keypair()
        with self.assertRaises(TypeError):
            sign(d, "not bytes")   # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main(verbosity=2)
