"""
demo/benchmark_argon2.py

Timing benchmark for Argon2id, using the exact code path from
Client.py._derive_master (§7.1). Best-of-5 per setting.

Numbers are hardware-specific — run on the laptop cited in the report,
not wherever this script happens to be. The reference laptop in §7.1
measured 235 ms at t=2, m=128 MiB.

Run:
    python -m demo.benchmark_argon2
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from client.client import SecureVaultClient                          # noqa: E402


PASSWORD = "a-representative-test-password!"
RUNS = 5

# Rows from §7.1 table, plus the setting actually used.
SETTINGS = [
    (1, 128 * 1024, 1),
    (2,  64 * 1024, 1),
    (2, 128 * 1024, 1),        # ← the one Client.py uses
    (3, 128 * 1024, 1),
    (2, 256 * 1024, 1),
]


def best_of(t: int, m_kib: int, p: int, runs: int = RUNS) -> float:
    salt = os.urandom(16)
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        SecureVaultClient._derive_master(PASSWORD, salt, t=t, m=m_kib, p=p)
        times.append(time.perf_counter() - start)
    return min(times)


def main() -> None:
    print(f"Argon2id timing (best of {RUNS} per setting)")
    print(f"Reference §7.1 target: 100–500 ms")
    print()
    print(f"  {'t':>2} | {'m':>10} | {'p':>2} | best-of-{RUNS} (ms)")
    print(f"  " + "-" * 46)
    for t, m_kib, p in SETTINGS:
        ms = best_of(t, m_kib, p) * 1000
        m_label = f"{m_kib // 1024} MiB"
        marker = "  ← used" if (t, m_kib, p) == (2, 128 * 1024, 1) else ""
        print(f"  {t:>2} | {m_label:>10} | {p:>2} | {ms:8.1f}{marker}")
    print()
    print("Attack cost estimate (per §7.1 arithmetic):")
    print("  8-char password from [a-zA-Z0-9]:   62^8 ≈ 2.2 × 10^14 attempts")
    print("  Bare SHA-256 @ 10^10 h/s:            ~6 hours to exhaust")
    print("  Argon2id @ 4000 guesses/s (1000 CPU cores):")
    print("                                        ~1700 years per account")
    print("  Top-10,000 password list @ 4/s:      ~40 minutes per account")


if __name__ == "__main__":
    main()
