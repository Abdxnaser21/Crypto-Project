# SecureVault

End-to-end encrypted file storage and sharing system.
**ENCS4320 Applied Cryptography — Term 1253 — Birzeit University**

Two users (Layla, Omar) can exchange documents through a server that
never sees plaintext or keys. An active network attacker cannot read,
tamper with, or forge documents undetected.

---

## Team

| Name | ID |
|---|---|
| Abd-Alrahman Naser | 1230146 |
| Mohammad Zaid | 1221265 |
| Khalid Omari | 1192973 |

---

## Design at a glance

| Concern | Choice | Why |
|---|---|---|
| Password → keys | Argon2id (t=2, m=128 MiB, p=1) → HMAC-SHA256 split | §7.1 — memory-hard, ~235 ms per login |
| Document confidentiality + integrity | AES-256-GCM, fresh key per file | §7.2 — no nonce reuse possible |
| Key exchange | ECDH on P-256 with fresh ephemeral wrap | §7.3 — 128-bit security |
| Authentication of origin | ECDSA on P-256, RFC 6979 deterministic k | §7.5 — non-repudiation |
| Public-key trust | TOFU + SHA-256 fingerprint, out-of-band verify | §7.4 — no PKI needed |
| Freshness | server-enforced version+1 + per-request nonces | §7.6 — replay resistant |

All crypto primitives (SHA-256, HMAC, AES, GCM, P-256, ECDH, ECDSA) are
implemented from scratch in pure Python under `src/crypto/`. The **only**
external cryptographic library used in production code is
**`argon2-cffi`** — required for §7.1 because a pure-Python Argon2 with
128 MiB would be too slow.

---

## Repository layout

```
crypto_project/
├── src/
│   ├── crypto/          # SHA-256, HMAC, KDF, AES, GCM, P-256, ECDH, ECDSA
│   ├── common/          # formats.py (SVD1/SVS1 blobs), wire.py (TCP framing)
│   ├── server/          # db.py, session.py, server.py
│   ├── client/          # client.py, cli.py, gui.py, keystore.py, trust_store.py
│   └── attacker/        # attacker_proxy.py — MITM proxy for §8 demos
├── tests/               # 198 tests (unit + integration + end-to-end)
├── demo/                # server_view_demo, weak_build_demo, benchmark_argon2
├── report/              # design report (PDF)
└── slides/              # presentation slides (PDF)
```

---

## Setup

**Requirements:** Python 3.10+ and one library.

```
pip install argon2-cffi
```

That's the only dependency. Everything else is Python standard library.

---

## Running the tests

From the project root:

```
python -m unittest discover -s tests
```

Expected result:

```
Ran 198 tests in ~11s
OK
```

Individual test files:

```
python -m unittest tests.test_sha256 -v         # 10 tests, NIST vectors
python -m unittest tests.test_gcm -v            # 14 tests, NIST vectors + tamper tests
python -m unittest tests.test_ecdsa -v          # 17 tests, RFC 6979 vectors
python -m unittest tests.test_end_to_end -v     # 13 tests, real TCP scenarios
```

Every crypto module is tested against official NIST/RFC vectors.

---

## Running the system

You need **two terminals**: one for the server, one for the client.

### Terminal 1 — start the server

```
python -m server.server
```

You'll see: `[server] listening on 127.0.0.1:9999`

### Terminal 2 — start the CLI

```
python -m client.cli --storage-dir layla_data
```

Menu appears. Pick options to sign up, log in, upload, share, download.
For a second user, open a **third terminal**:

```
python -m client.cli --storage-dir omar_data
```

Each `--storage-dir` isolates that user's keystore and trust file.

### GUI (bonus, §12.1)

Same idea with a graphical window:

```
python -m client.gui --storage-dir layla_data
```

---

## The 5 minute demo (25 Sep presentation)

### Step 1 — honest path (2 minutes)

1. Terminal 1: `python -m server.server`
2. Terminal 2: `python -m client.gui --storage-dir layla_data` → signup, login, upload `secret.txt`, copy the doc_id
3. Terminal 3: `python -m client.gui --storage-dir omar_data` → signup, login
4. Back in Layla's GUI: share the doc with `omar`
5. In Omar's GUI: download → **TOFU dialog** → trust → **"verified from layla"** ✓

### Step 2 — show the server sees ciphertext only (§7.2)

```
python -m demo.server_view_demo
```

Prints a hex dump of what's actually stored, then searches the whole DB
for the plaintext string and confirms it's not there.

### Step 3 — attack demos (§8)

Kill the server, then run:

```
python -m server.server                                    # terminal 1
python -m attacker.attacker_proxy --mode flip_ciphertext   # terminal 2
python -m client.cli --port 9998 --storage-dir omar_data   # terminal 3
```

The client now connects to the **attacker's port (9998)**, which
forwards to the real server (9999) with tampering.

Have Omar try to download → **SECURITY ERROR** dialog appears.

Repeat with each mode:

| Mode | What breaks | What Omar sees |
|---|---|---|
| `flip_ciphertext` | one byte flipped | `doc_hash mismatch` |
| `flip_metadata` | owner tampered in AAD | `document GCM tag failed` |
| `swap_pubkey` | server hands out attacker's key | `key changed for 'layla'` |
| `replay` | old request resent | `server error` (nonce used) |

### Step 4 — bonus §12.2 (nonce reuse math proof)

```
python -m demo.weak_build_demo
```

Shows the same attack against a weakened build (nonce reused) recovering
the plaintext, and against the correct build recovering only noise.

---

## Security properties

| Guarantee | Mechanism |
|---|---|
| Confidentiality vs server | AES-256-GCM with keys never sent to server |
| Confidentiality vs network | Same, plus ECDH ephemeral wrapping |
| Integrity of documents | GCM tag over ciphertext + header AAD |
| Freshness of documents | server-enforced version+1 |
| Freshness of requests | per-request nonces, 60s challenge TTL |
| Auth of file origin | ECDSA signature over SHA-256(content) |
| Auth of share origin | ECDSA signature over sender‖recipient‖doc_id‖version‖timestamp |
| Public-key trust | TOFU + SHA-256 fingerprint, no override on mismatch |
| Password brute-force resistance | Argon2id, ~235 ms per attempt |
| At-rest client keys | AES-GCM under KDF-derived kek |

---

## Known limitations

- Common-password guessing is still possible: Argon2 makes it slow
  (~40 min per account for the top-10000 list) but not impossible.
- First-contact key swap succeeds if the user accepts without an
  out-of-band comparison. Fingerprint verification is a user
  responsibility.
- Forgetting the password means the data is unrecoverable — there is
  no key escrow by design.
- Server sees metadata: who uploaded what and when, who shared with
  whom, file sizes and timings.
- Python is not constant-time; a co-located attacker could in principle
  extract keys via micro-timing. Out of scope for this project.
- No forward secrecy for the recipient's long-term DH key.
- P-256 is not quantum-resistant.

---

## AI usage declaration

The use of AI tools in this project complies with the AI Usage Statement outlined in Section 14 of the project guidelines.


---

## Library declaration

| Where | Library | Purpose | Permitted by |
|---|---|---|---|
| `src/` production code | `argon2-cffi` | Argon2id password hashing | §7.1 |
| `src/` production code | `sqlite3` (stdlib) | Server-side storage | spec-approved |
| `src/client/gui.py` | `tkinter` (stdlib) | GUI | §12.1 bonus |
| `tests/` only | `cryptography` | Cross-check our GCM against a reference | testing only |
| `tests/` only | `hashlib` | Cross-check our SHA-256 | testing only |

No other cryptographic libraries are imported anywhere.
