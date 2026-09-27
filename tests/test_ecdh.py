import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.ec_p256 import (                                       # noqa: E402
    N, G, scalar_mul_g, point_to_bytes,
)
from crypto.ecdh import (                                          # noqa: E402
    generate_keypair, shared_key, _raw_shared_x,
)


# --- RFC 5903 §8.1 P-256 ECDH known-answer vector ------------------------

RFC5903_VECTOR = dict(
    # Alice's private key
    i_a=0xC88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433,
    # Bob's private key
    i_b=0xC6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53,
    # Shared secret x-coordinate (the raw ECDH output before any KDF)
    z=0xD6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE,
)


class TestRfc5903(unittest.TestCase):
    def test_raw_shared_x_matches_rfc5903(self) -> None:
        v = RFC5903_VECTOR
        # Alice computes shared using her private + Bob's public
        bob_pub = point_to_bytes(scalar_mul_g(v["i_b"]))
        raw = _raw_shared_x(v["i_a"], bob_pub)
        self.assertEqual(int.from_bytes(raw, "big"), v["z"])

        # And Bob computes the same using his private + Alice's public
        alice_pub = point_to_bytes(scalar_mul_g(v["i_a"]))
        raw2 = _raw_shared_x(v["i_b"], alice_pub)
        self.assertEqual(raw, raw2)


# --- Symmetry: the whole reason ECDH works -------------------------------

class TestSymmetry(unittest.TestCase):
    def test_alice_and_bob_derive_same_key(self) -> None:
        for _ in range(10):
            a_priv, a_pub = generate_keypair()
            b_priv, b_pub = generate_keypair()
            k_ab = shared_key(a_priv, b_pub)
            k_ba = shared_key(b_priv, a_pub)
            self.assertEqual(k_ab, k_ba)

    def test_different_info_gives_different_keys(self) -> None:
        # Using an info string binds the key to a purpose; a different
        # info string must produce a different key.
        a_priv, _ = generate_keypair()
        b_priv, b_pub = generate_keypair()
        k1 = shared_key(a_priv, b_pub, info=b"purpose-A")
        k2 = shared_key(a_priv, b_pub, info=b"purpose-B")
        self.assertNotEqual(k1, k2)

    def test_shared_key_is_32_bytes(self) -> None:
        a_priv, _ = generate_keypair()
        _, b_pub = generate_keypair()
        self.assertEqual(len(shared_key(a_priv, b_pub)), 32)


# --- Cross-check against `cryptography` library --------------------------

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, load_der_public_key,
    )
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography library not installed")
class TestCrossCheck(unittest.TestCase):
    def test_random_shared_secret_matches_library(self) -> None:
        """Our raw x-coordinate must match the library's on random pairs."""
        for _ in range(10):
            # Our side
            our_priv, our_pub_bytes = generate_keypair()

            # Their side
            their_priv_obj = ec.generate_private_key(ec.SECP256R1())
            their_pub_obj = their_priv_obj.public_key()
            their_pub_bytes = their_pub_obj.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )

            # Us -> them: use our private + their public via our library
            our_raw = _raw_shared_x(our_priv, their_pub_bytes)

            # Them -> us: use their private + our public via their library
            # Reconstruct our public into their format
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicKey,
            )
            our_pub_for_them = EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), our_pub_bytes
            )
            their_raw = their_priv_obj.exchange(ec.ECDH(), our_pub_for_them)

            self.assertEqual(our_raw, their_raw)


# --- Input validation ----------------------------------------------------

class TestInvalidInputs(unittest.TestCase):
    def test_bad_private_scalar_rejected(self) -> None:
        _, some_pub = generate_keypair()
        with self.assertRaises(ValueError):
            _raw_shared_x(0, some_pub)                # 0 is not in [1, N-1]
        with self.assertRaises(ValueError):
            _raw_shared_x(N, some_pub)                # N is not in [1, N-1]

    def test_malformed_peer_public_rejected(self) -> None:
        priv, _ = generate_keypair()
        with self.assertRaises(ValueError):
            _raw_shared_x(priv, b"\x04" + b"\x00" * 64)      # off-curve
        with self.assertRaises(ValueError):
            _raw_shared_x(priv, b"too short")                # bad length
        with self.assertRaises(ValueError):
            _raw_shared_x(priv, b"\x02" + b"\x00" * 32)      # compressed unsupported


# --- Generated keypairs are well-formed ---------------------------------

class TestKeypair(unittest.TestCase):
    def test_public_is_valid_encoded_point(self) -> None:
        _, pub = generate_keypair()
        self.assertEqual(len(pub), 65)
        self.assertEqual(pub[0], 0x04)

    def test_two_calls_give_different_keys(self) -> None:
        a1, p1 = generate_keypair()
        a2, p2 = generate_keypair()
        self.assertNotEqual(a1, a2)
        self.assertNotEqual(p1, p2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
