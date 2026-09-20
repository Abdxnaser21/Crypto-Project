from __future__ import annotations

# --- S-box (FIPS 197 Sec. 5.1.1, Figure 7) --------------------------------
# Precomputed table for SubBytes. Each byte b is replaced by SBOX[b].

SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

# Round constants Rcon (FIPS 197 Sec. 5.2). We only need entries 1..10
# for AES-256 (Nr+1=15 round keys, but Rcon is used every Nk=8 words,
# so max index is (Nr+1)*4/Nk = 60/8 = 7 for AES-256, 10 for AES-128).
RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
)


# --- GF(2^8) multiplication (FIPS 197 Sec. 4.2) ---------------------------

def _xtime(b: int) -> int:
    """Multiply by x (i.e. by 0x02) in GF(2^8) with the AES polynomial."""
    return ((b << 1) ^ 0x1B) & 0xFF if (b & 0x80) else (b << 1) & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8). Only used by MixColumns."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


# --- Key schedule (FIPS 197 Sec. 5.2) -------------------------------------

def _sub_word(word: bytes) -> bytes:
    """Apply S-box to each byte of a 4-byte word."""
    return bytes(SBOX[b] for b in word)


def _rot_word(word: bytes) -> bytes:
    """Cyclic left-shift by one byte: (a,b,c,d) -> (b,c,d,a)."""
    return word[1:] + word[:1]


def _key_expansion(key: bytes) -> list[bytes]:
    """
    Expand key into round keys. Returns Nr+1 round keys, each 16 bytes.
      AES-128: Nk=4, Nr=10 -> 11 round keys
      AES-256: Nk=8, Nr=14 -> 15 round keys
    """
    if len(key) == 16:
        nk, nr = 4, 10
    elif len(key) == 32:
        nk, nr = 8, 14
    else:
        raise ValueError("AES key must be 16 bytes (AES-128) or 32 bytes (AES-256)")

    total_words = 4 * (nr + 1)   # 44 for AES-128, 60 for AES-256
    words: list[bytes] = [key[i * 4 : i * 4 + 4] for i in range(nk)]

    for i in range(nk, total_words):
        temp = words[i - 1]
        if i % nk == 0:
            # RotWord -> SubWord -> XOR with Rcon (only top byte).
            temp = _sub_word(_rot_word(temp))
            temp = bytes([temp[0] ^ RCON[i // nk]]) + temp[1:]
        elif nk > 6 and i % nk == 4:
            # AES-256 only: extra SubWord step.
            temp = _sub_word(temp)
        prev = words[i - nk]
        words.append(bytes(a ^ b for a, b in zip(prev, temp)))

    # Group every 4 words into a 16-byte round key.
    round_keys = [b"".join(words[i * 4 : i * 4 + 4]) for i in range(nr + 1)]
    return round_keys


# --- Round transformations (FIPS 197 Sec. 5.1) ---------------------------
# State is a list of 16 bytes, indexed as state[row + 4*col].

def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    """
    Row 0: no shift.
    Row 1: left rotate by 1.
    Row 2: left rotate by 2.
    Row 3: left rotate by 3.
    """
    # Row r sits at indices r, r+4, r+8, r+12.
    # Row 1
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    # Row 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _mix_columns(state: list[int]) -> None:
    """Per FIPS 197 Sec. 5.1.3, multiply each column by the fixed matrix."""
    for c in range(4):
        col = state[c * 4 : c * 4 + 4]
        s0, s1, s2, s3 = col
        state[c * 4 + 0] = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2 ^ s3
        state[c * 4 + 1] = s0 ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
        state[c * 4 + 2] = s0 ^ s1 ^ _gmul(s2, 2) ^ _gmul(s3, 3)
        state[c * 4 + 3] = _gmul(s0, 3) ^ s1 ^ s2 ^ _gmul(s3, 2)


def _add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


# --- Public block encrypt -------------------------------------------------

def encrypt_block(key: bytes, block: bytes) -> bytes:
    """
    Encrypt one 16-byte block under `key` (16 or 32 bytes).
    Returns 16 bytes of ciphertext.

    Modes (CTR, GCM, CBC, ...) are built on top of this in other files.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")
    if not isinstance(block, (bytes, bytearray)):
        raise TypeError("AES block must be bytes")
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    round_keys = _key_expansion(bytes(key))
    nr = len(round_keys) - 1     # 10 for AES-128, 14 for AES-256

    state = list(block)

    # Initial round key addition.
    _add_round_key(state, round_keys[0])

    # Nr - 1 full rounds.
    for r in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])

    # Final round (no MixColumns).
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[nr])

    return bytes(state)


# --- Convenience class ----------------------------------------------------

class AES:
    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 32):
            raise ValueError("AES key must be 16 or 32 bytes")
        self._round_keys = _key_expansion(bytes(key))
        self._nr = len(self._round_keys) - 1

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be exactly 16 bytes")
        state = list(block)
        _add_round_key(state, self._round_keys[0])
        for r in range(1, self._nr):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self._round_keys[r])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self._round_keys[self._nr])
        return bytes(state)
