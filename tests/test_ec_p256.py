import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.ec_p256 import (                                          # noqa: E402
    G, N, P, Point, INFINITY,
    is_on_curve, is_valid_private_key,
    point_add, point_double, scalar_mul, scalar_mul_g,
    point_to_bytes, point_from_bytes,
)


# --- Group law sanity ----------------------------------------------------

class TestGroupLaw(unittest.TestCase):
    def test_G_on_curve(self) -> None:
        self.assertTrue(is_on_curve(G))

    def test_identity_is_on_curve(self) -> None:
        self.assertTrue(is_on_curve(INFINITY))

    def test_G_plus_identity_is_G(self) -> None:
        self.assertEqual(point_add(G, INFINITY), G)
        self.assertEqual(point_add(INFINITY, G), G)

    def test_G_plus_negG_is_identity(self) -> None:
        negG = Point(G.x, (P - G.y) % P)
        self.assertIsNone(point_add(G, negG))

    def test_double_matches_add_self(self) -> None:
        self.assertEqual(point_double(G), point_add(G, G))

    def test_N_times_G_is_identity(self) -> None:
        """N*G = O — the defining property of the curve order."""
        self.assertIsNone(scalar_mul(N, G))

    def test_1_times_G_is_G(self) -> None:
        self.assertEqual(scalar_mul(1, G), G)

    def test_0_times_G_is_identity(self) -> None:
        self.assertIsNone(scalar_mul(0, G))

    def test_associativity_small(self) -> None:
        # (2*G) + G  ==  G + (2*G)  ==  3*G  (checked three ways)
        two_G = point_double(G)
        three_a = point_add(two_G, G)
        three_b = point_add(G, two_G)
        three_c = scalar_mul(3, G)
        self.assertEqual(three_a, three_b)
        self.assertEqual(three_a, three_c)


# --- NIST known-answer scalar multiplications ---------------------------
# Source: NIST "Mathematical routines for the NIST prime elliptic curves",
# Table (also in openssl and every EC library test suite).
# Format: k, expected k*G

NIST_KG = [
    # k = 1
    (
        1,
        0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296,
        0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5,
    ),
    # k = 2
    (
        2,
        0x7CF27B18_8D034F7E_8A523803_04B51AC3_C08969E2_77F21B35_A60B48FC_47669978,
        0x07775510_DB8ED040_293D9AC6_9F7430DB_BA7DADE6_3CE98229_9E04B79D_227873D1,
    ),
    # k = 3
    (
        3,
        0x5ECBE4D1_A6330A44_C8F7EF95_1D4BF165_E6C6B721_EFADA985_FB41661B_C6E7FD6C,
        0x8734640C_4998FF7E_374B06CE_1A64A2EC_D82AB036_384FB83D_9A79B127_A27D5032,
    ),
    # k = 4
    (
        4,
        0xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852,
        0xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6,
    ),
    # k = 5
    (
        5,
        0x51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED,
        0xE0C17DA8904A727D8AE1BF36BF8A79260D012F00D4D80888D1D0BB44FDA16DA4,
    ),
    # k = 10
    (
        10,
        0xCEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F,
        0x878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773,
    ),
    # k = N-1  (last valid scalar)
    (
        N - 1,
        0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296,
        (P - 0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5) % P,
    ),
]


class TestScalarMultKAT(unittest.TestCase):
    def test_known_scalar_multiples_of_G(self) -> None:
        for k, ex_x, ex_y in NIST_KG:
            with self.subTest(k=k):
                result = scalar_mul_g(k)
                self.assertIsNotNone(result)
                assert result is not None            # for type-checker
                self.assertEqual(result.x, ex_x)
                self.assertEqual(result.y, ex_y)


# --- ECDH self-consistency (foundation for ecdh.py) ---------------------
# a*(b*G) == b*(a*G) — the property that lets two parties agree.

class TestEcdhIdentity(unittest.TestCase):
    def test_diffie_hellman_symmetry_random(self) -> None:
        for _ in range(10):
            a = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
            b = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
            A = scalar_mul_g(a)
            B = scalar_mul_g(b)
            shared_ab = scalar_mul(a, B)
            shared_ba = scalar_mul(b, A)
            self.assertEqual(shared_ab, shared_ba)


# --- Encoding round-trip and validity -----------------------------------

class TestEncoding(unittest.TestCase):
    def test_G_encode_decode_roundtrip(self) -> None:
        blob = point_to_bytes(G)
        self.assertEqual(len(blob), 65)
        self.assertEqual(blob[0], 0x04)
        back = point_from_bytes(blob)
        self.assertEqual(back, G)

    def test_random_point_roundtrip(self) -> None:
        for _ in range(5):
            k = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
            Pt = scalar_mul_g(k)
            self.assertIsNotNone(Pt)
            blob = point_to_bytes(Pt)
            self.assertEqual(point_from_bytes(blob), Pt)

    def test_encoding_identity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            point_to_bytes(INFINITY)

    def test_bad_prefix_rejected(self) -> None:
        blob = bytearray(point_to_bytes(G))
        blob[0] = 0x02   # compressed form (not supported)
        with self.assertRaises(ValueError):
            point_from_bytes(bytes(blob))

    def test_wrong_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            point_from_bytes(b"\x04" + b"\x00" * 63)   # too short

    def test_off_curve_point_rejected(self) -> None:
        # Take valid G, corrupt one byte -> almost certainly off the curve.
        blob = bytearray(point_to_bytes(G))
        blob[1] ^= 0x01
        with self.assertRaises(ValueError):
            point_from_bytes(bytes(blob))


# --- Private-key range check --------------------------------------------

class TestPrivateKeyRange(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertTrue(is_valid_private_key(1))
        self.assertTrue(is_valid_private_key(N - 1))

    def test_invalid(self) -> None:
        self.assertFalse(is_valid_private_key(0))
        self.assertFalse(is_valid_private_key(N))
        self.assertFalse(is_valid_private_key(-1))
        self.assertFalse(is_valid_private_key("not int"))   # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main(verbosity=2)
