# SecureVault – Section 7 Design Decisions

ENCS4320 Applied Cryptography – Final Project

We aim for 128-bit security everywhere. All timings are from one of our laptops (i7-1065G7, Python 3.13).
Slides are cited as [L06 s42] = lecture 06, slide 42.

| Decision | Our choice | Rejected |
|---|---|---|
| Passwords | Argon2id (t=2, m=128 MiB, p=1), 16-byte salt | bare SHA-256, PBKDF2, bcrypt |
| Documents | AES-256-GCM, new key per file | CBC + HMAC, CCM |
| Public key | ECDH + ECDSA on P-256 | RSA / DH over Z_p* |
| Key trust | TOFU + fingerprint check | CA run by the server |
| Architecture | Client/server over TCP + attacker proxy | Shared folder |

## 7.1 Passwords

A bare SHA-256 is too fast: a GPU does billions of hashes per second [L05 s43]. A slow hash alone isn't
enough either, because a GPU runs thousands of guesses in parallel. A memory-hard hash stops that, since
each GPU core has limited memory [L05 s45]. PBKDF2 isn't memory-hard, bcrypt isn't either, and Argon2id is
the recommended variant [L05 s46]. So we picked Argon2id.

Work factor: t=2, m=128 MiB takes 235 ms on our laptop, which is inside the 0.1–0.5 s range [L05 s45].
The parameters are stored in the user record so we can raise them later. We also tried a few other
settings with argon2-cffi (p=1, best of 5 runs):

| t | m | time |
|---|---|---|
| 1 | 128 MiB | 116 ms |
| 2 | 64 MiB | 97 ms |
| 2 | 128 MiB | 195 ms |
| 3 | 128 MiB | 269 ms |
| 2 | 256 MiB | 372 ms |

(t=2 / 128 MiB gave 235 ms the first time and 195 ms when we ran it again. We kept 235 ms for the math below.)

Attack estimate, done the same way as the exercise in [L05 s47–48]. 8 characters from a-z A-Z 0-9 gives
62^8 ≈ 2.2 × 10^14 passwords.
- Bare SHA-256, no salt, 10^10 hashes/s: 2.2 × 10^14 / 10^10 ≈ 22,000 s ≈ 6 hours, and that breaks all
  accounts at once.
- Our Argon2id: one core on our laptop does 1 / 0.235 ≈ 4 guesses/s. We don't have a GPU to test, so we
  just assumed an attacker with 1,000 cores as fast as ours (4,000 guesses/s):
  2.2 × 10^14 / 4,000 ≈ 5.5 × 10^10 s ≈ 1,700 years for one account. In practice it should be even
  slower, because every guess needs 128 MiB and a GPU core doesn't have that much memory [L05 s45].
- Common passwords are still a problem. A top-10,000 list takes 10,000 × 0.235 s ≈ 40 minutes per account on
  one core. The salt doesn't help with guessing, only with precomputation [L05 s48].

Salt: `os.urandom(16)`, 16 random bytes like [L05 s44], new at sign-up and at every password change. It is
stored in the clear. It isn't secret because its job is uniqueness: two users with the same password get
different records, and the attacker has to go after one account at a time [L05 s44].

Second use of the password: Argon2id runs on the client and gives `master`. From it we get two keys with
HMAC-SHA256 as F, the same idea as ke = F(k, 0), km = F(k, 1) [L06 s35]:
`auth_key = HMAC(master, "auth")` for login, and `kek = HMAC(master, "kek")` to unlock the private keys.
The server only keeps the salt and `auth_pub`. At login it sends a random challenge and the client signs it.
If the password changes, we re-encrypt the same private keys with the new `kek`. The identity keys don't
come from the password, so contacts and old shares still work.

Unknown users: if the server said "no such user" or didn't send a salt, anyone could check which accounts
exist. So for an unknown username it sends `HMAC(server_secret, username)` as the salt. The same name
always gets the same fake salt, so asking twice doesn't give it away. The reply is `LOGIN_FAILED` in both
cases.

## 7.2 Document contents

AES-256-GCM, written by us. GCM is CTR + GHASH in encrypt-then-MAC order, so a changed ciphertext is
rejected before anything is decrypted [L06 s40–41]. If the tag is wrong, decryption returns ⊥ and never
the plaintext [L06 s37].

- CBC + HMAC done by hand: if we decrypted before checking, we'd have a padding oracle [L06 s31–33]. If we
  did build it ourselves, the safe order is encrypt-then-MAC with two separate keys [L06 s34–35].
- CCM: the MAC is over the plaintext, so the receiver has to decrypt before checking [L06 s38–39]. There's
  no padding oracle in CCM since CTR has no padding [L06 s39]. We still went with GCM because it checks
  before decrypting and uses about one cipher call per block, not two [L06 s39–40].

Keys per document: one random file key `FK`, plus one wrapped copy of `FK` for each person with access,
the owner included.

Nonces: reusing a (key, nonce) pair in GCM leaks the XOR of the plaintexts and the GHASH key H [L06 s42].
So every GCM key in our system encrypts only one message: `FK` is new for every upload, the wrap key is new
for every share, and `kek` is new after every password change. The nonce is a counter starting at 0, as
[L06 s42] says. Each key is used once, so the counter can't repeat, and there's nothing saved that a crash
could reset. Files over 64 GiB are refused [L06 s42].

Header: doc_id, owner, version and time stay readable and go in the AAD. The server can read them but can't
change them, and neither can the network attacker [L06 s37].

## 7.3 Public-key crypto

With symmetric keys only, we'd need a key for every pair of users (n(n−1)/2) or a KDC, and our server can't
be trusted as a KDC [L07 s5]. DH lets two people who never met agree on a key [L07 s10], and that key goes
into AES-GCM [L07 s8]. So we use ECDH to send `FK` to another user, and ECDSA to prove who wrote a
file [L07 s16].

We picked elliptic curves over DH in Z_p*, because Z_p* has much faster special attacks and needs bigger
numbers [L07 s57]. On a curve the best attacks are square-root attacks, so a group of about 2^256 gives
2^128 security [L07 s55]. That's P-256, and we use the same curve for both jobs so we only write it once.

At 128-bit security, ECC needs 256 bits where RSA/DL needs about 3072 bits [L07 s17], so keys are about
12× smaller. For speed we ran `openssl speed -seconds 3 ecdhp256 ecdsap256 rsa3072 ffdh3072`
(OpenSSL 3.2.2) on our laptop:

| Operation | ops/s |
|---|---|
| ECDH P-256 | 12,847 |
| DH-3072 | 767 |
| ECDSA P-256 sign | 22,282 |
| RSA-3072 sign | 1,145 |

That's about 17× faster for key agreement and about 19× faster for signing. These numbers are from
OpenSSL's C code, not our Python code, but we only wanted the ratio between ECC and RSA/DH.

SHA-256 also gives 128-bit collision security [L05 s35], so all parts match. AES-256 doesn't make the
system 256-bit.

## 7.4 Trusting a public key

If the server gives Layla its own key instead of Omar's, it becomes Trudy in the middle [L07 s58–59].

We use trust on first use + fingerprints. The first time Layla gets Omar's key, her client saves it as
UNVERIFIED. They compare the fingerprint (SHA-256 of his key bundle) in person or on a call, and then she
marks it VERIFIED. If the server later sends a different key, the client blocks sharing until they
compare again.

No CA on the server: the server is the thing we don't trust, and one central authority is a single point
of failure [L07 s5]. Weak spot: if users never compare, a key swapped on the very first download isn't
noticed.

## 7.5 Signatures vs MACs

- MAC (GCM tag, HMAC): integrity between people who share the key.
- Signature (ECDSA): document content, shares and login.

Only a signature gives non-repudiation. With a MAC both sides have the same key, so a judge can't tell if
Layla or Omar made the tag [L06 s5, L07 s6]. Making the tag longer doesn't change this, because both of
them still have the key. Only Layla has her private key, so only she could have signed [L07 s18].

We sign the SHA-256 of the file itself. Then Omar can give a third party the file, the signature and
Layla's public key, and they can check it without any secret key.

## 7.6 Architecture and formats

Client and server talk over TCP. `attacker_proxy.py` sits in the middle to flip bytes, change metadata,
replay messages and swap keys. The server stores accounts, key bundles, encrypted keys, documents and
shares. It can't read files (no `FK`), forge anything (no user signing keys) or get passwords cheaply (it
only has the salt and `auth_pub`).

Integers are big-endian, and strings are `u16 length ‖ UTF-8`.

| Object | Fields |
|---|---|
| Document `SVD1` | header: magic(4), doc_id(16), owner(str), version u32, created_ms u64 · then nonce(12), ciphertext, tag(16). Header = AAD |
| Encrypted payload | filename(str), mime(str), content, content_sig(64) |
| Share `SVS1` | magic(4), doc_id(16), version u32, doc_hash(32), sender(str), recipient(str), issued_ms u64, eph_pub(65), nonce(12), wrapped_fk(32), tag(16), share_sig(64) |
| Message frame | u32 length ‖ u8 type ‖ body |

Replay: the server only accepts `version = current + 1`, and the client remembers the highest version it
has seen for each document, so a lower one is STALE. Login challenges work only once.

On failure: nothing is saved or shown, and nothing about the failure is sent back to the server. Tags are
checked before decryption and compared in constant time [L06 s15]. Same error text isn't enough on its
own, since the oracle can hide in the control flow [L06 s33]. We check the tag first, so that path isn't
there in our code.

## Library use

Everything is ours (SHA-256, HMAC, AES, GCM, P-256, ECDH, ECDSA) except Argon2id. A pure-Python Argon2
with 128 MiB would be far too slow, so we'd have to cut the memory and lose the reason we chose it.

## Limitations

- Common passwords still fall (about 40 min per account for a top-10,000 list).
- If users never compare fingerprints, the first key can be swapped.
- A forgotten password means the files are gone.
- The server sees who shares with whom, file sizes and times.
- The connection itself isn't encrypted.
- If Omar's private key is stolen later, all old shares to him can be opened.
- Python isn't constant-time.
- Quantum computers would break EC [L07 s17].
