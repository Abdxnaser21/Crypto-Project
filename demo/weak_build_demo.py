"""
demo/weak_build_demo.py

Bonus §12.2: the same attack against a deliberately weakened build and
against the correct build.

The weakness: reusing a (key, nonce) pair in AES-GCM. GCM's confidentiality
comes from a keystream XORed with the plaintext:
    C1 = P1 XOR KS(key, nonce)
    C2 = P2 XOR KS(key, nonce)
    C1 XOR C2 = P1 XOR P2         <- key cancels out completely
so an attacker who knows or guesses one plaintext recovers the other
outright, without touching the key.

This is the risk our §7.2 flags. Client.py never reuses a (key, nonce)
because every GCM call gets a fresh key. This script proves what would
happen if it didn't.

Run:
    python -m demo.weak_build_demo
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.gcm import encrypt as gcm_encrypt                        # noqa: E402


KEY = b"\x11" * 32
DOC_A = b"Layla: transfer $500 to Omar for March invoice."
DOC_B = b"Layla: transfer $9000 to Trudy--tell nobody!!!!"
assert len(DOC_A) == len(DOC_B), "demo docs must be equal length"


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def weak_build_reused_nonce() -> None:
    print("=" * 72)
    print("  WEAK BUILD: same (key, nonce) reused for two uploads")
    print("=" * 72)
    nonce = b"\x00" * 12                              # bug: fixed nonce
    ct_a, _ = gcm_encrypt(KEY, nonce, DOC_A)
    ct_b, _ = gcm_encrypt(KEY, nonce, DOC_B)
    print(f"\n  Ciphertext A: {ct_a.hex()}")
    print(f"  Ciphertext B: {ct_b.hex()}")

    # Attacker computes C_A XOR C_B (key cancels), then XOR with known doc A.
    recovered = _xor(_xor(ct_a, ct_b), DOC_A)
    print("\n  Attacker computes C_A XOR C_B, then XORs with known doc A:")
    print(f"    Recovered doc B: {recovered!r}")
    print(f"    Actual    doc B: {DOC_B!r}")
    assert recovered == DOC_B
    print("\n  >>> ATTACK SUCCEEDED — nonce reuse leaked the entire second file"
          "\n      without the attacker ever touching the key.\n")


def correct_build_fresh_nonce() -> None:
    print("=" * 72)
    print("  CORRECT BUILD: fresh nonce per encryption (what Client.py does)")
    print("=" * 72)
    nonce_a, nonce_b = os.urandom(12), os.urandom(12)
    ct_a, _ = gcm_encrypt(KEY, nonce_a, DOC_A)
    ct_b, _ = gcm_encrypt(KEY, nonce_b, DOC_B)
    print(f"\n  Ciphertext A: {ct_a.hex()}")
    print(f"  Ciphertext B: {ct_b.hex()}")

    guess = _xor(_xor(ct_a, ct_b), DOC_A)
    print("\n  Same attack attempted — different nonces = different keystreams,")
    print("  so C_A XOR C_B is meaningless noise:")
    print(f"    'Recovered' doc B: {guess!r}")
    print(f"    Actual      doc B: {DOC_B!r}")
    assert guess != DOC_B
    print("\n  >>> ATTACK FAILED — the identical attack recovers nothing.\n")


def main() -> None:
    weak_build_reused_nonce()
    correct_build_fresh_nonce()
    print("=" * 72)
    print("  This is why §7.2 uses a fresh key per file (nonce reuse impossible)")
    print("  and every ECDH key-wrap generates a fresh ephemeral keypair.")
    print("=" * 72)


if __name__ == "__main__":
    main()
