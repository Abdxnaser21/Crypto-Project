from __future__ import annotations

# --- P-256 domain parameters (FIPS 186-4, Appendix D.1.2.3) --------------
# Curve equation: y^2 = x^3 + a*x + b (mod p)

# Prime modulus of the underlying field GF(p).
P = 0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF

# Curve coefficients. a = -3 mod p is standard for NIST prime curves.
A = P - 3
B = 0x5AC635D8_AA3A93E7_B3EBBD55_769886BC_651D06B0_CC53B0F6_3BCE3C3E_27D2604B

# Order of the base point G (a prime).
N = 0xFFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_BCE6FAAD_A7179E84_F3B9CAC2_FC632551

# Base point G = (Gx, Gy). Its order is N; every valid public key is k*G
# for some scalar k in [1, N-1].
GX = 0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296
GY = 0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5


# --- The point at infinity (identity element) ----------------------------
# Represented as None; every function treats None as "0" of the group.

class Point:

    __slots__ = ("x", "y")

    def __init__(self, x: int, y: int) -> None:
        self.x = x
        self.y = y

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        return hash((self.x, self.y))

    def __repr__(self) -> str:
        return f"Point(x={hex(self.x)}, y={hex(self.y)})"


INFINITY: Point | None = None  # identity element of the group


# --- Field arithmetic mod p ----------------------------------------------

def _mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


# --- Point validity checks -----------------------------------------------

def is_on_curve(P_: Point | None) -> bool:
    if P_ is None:
        return True
    x, y = P_.x, P_.y
    if not (0 <= x < P and 0 <= y < P):
        return False
    lhs = (y * y) % P
    rhs = (x * x * x + A * x + B) % P
    return lhs == rhs


# --- Point operations (SEC 1, Sec. 2.2.1) --------------------------------

def point_add(P1: Point | None, P2: Point | None) -> Point | None:
    # Identity rules.
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1.x, P1.y
    x2, y2 = P2.x, P2.y

    if x1 == x2:
        if (y1 + y2) % P == 0:
            # P1 = -P2 -> sum is the identity.
            return INFINITY
        # P1 == P2 -> use doubling formula.
        return point_double(P1)

    # Standard addition: slope m = (y2 - y1)/(x2 - x1).
    m = ((y2 - y1) * _mod_inv((x2 - x1) % P, P)) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return Point(x3, y3)


def point_double(P1: Point | None) -> Point | None:
    if P1 is None:
        return INFINITY
    x1, y1 = P1.x, P1.y
    if y1 == 0:
        # Tangent is vertical -> result is the identity.
        return INFINITY
    # Slope m = (3*x1^2 + a) / (2*y1).
    m = ((3 * x1 * x1 + A) * _mod_inv((2 * y1) % P, P)) % P
    x3 = (m * m - 2 * x1) % P
    y3 = (m * (x1 - x3) - y1) % P
    return Point(x3, y3)


def scalar_mul(k: int, P_: Point | None) -> Point | None:
    if P_ is None or k % N == 0:
        return INFINITY
    if k < 0:
        # k*P = (-k)*(-P) with -P = (x, -y mod p)
        k = -k
        P_ = Point(P_.x, (P - P_.y) % P)

    result: Point | None = INFINITY
    addend: Point | None = P_
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result


# --- Convenience: G and k*G ----------------------------------------------

G = Point(GX, GY)


def scalar_mul_g(k: int) -> Point | None:
    return scalar_mul(k, G)


# --- Encoding: uncompressed SEC1 form (0x04 || X || Y) -------------------

def point_to_bytes(P_: Point | None) -> bytes:
    if P_ is None:
        raise ValueError("cannot encode the point at infinity")
    return b"\x04" + P_.x.to_bytes(32, "big") + P_.y.to_bytes(32, "big")


def point_from_bytes(data: bytes) -> Point:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("point_from_bytes expects bytes")
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("invalid SEC1 uncompressed point")
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    Pt = Point(x, y)
    if not is_on_curve(Pt):
        raise ValueError("decoded point is not on P-256")
    return Pt


# --- Scalar (private key) helpers ----------------------------------------

def is_valid_private_key(d: int) -> bool:
    return isinstance(d, int) and 1 <= d <= N - 1
