"""
SecureVault client.

One class, `SecureVaultClient`, implements the six operations from §5:
  signup, login, upload, share, download, change_password.

Everything crypto lives in crypto/*; this file is the glue that:
  - talks to the server via wire.send/recv_message
  - packs and unpacks SVD1/SVS1 blobs via common/formats.py
  - stores identity keys via client/keystore.py
  - checks contacts via client/trust_store.py (TOFU, §7.4)

Three keypairs per user (§7.1):
  auth_*     — derived from password, signs the login challenge
  sig_*      — random, signs documents and request signatures
  dh_*       — random, ECDH partner for wrapping file keys

`auth_*` never touches disk (it's re-derived from the password every
login). `sig_*` and `dh_*` are stored encrypted with kek in the keystore.
"""

from __future__ import annotations

import base64
import os
import socket
import time
from typing import Callable

from argon2.low_level import hash_secret_raw, Type

from crypto.sha256 import sha256
from crypto.kdf import derive_both
from crypto.gcm import encrypt as gcm_encrypt, decrypt as gcm_decrypt
from crypto.ec_p256 import N as P256_N, point_to_bytes, point_from_bytes, scalar_mul_g
from crypto.ecdh import generate_keypair as ecdh_keypair, shared_key
from crypto.ecdsa import (
    generate_keypair as ecdsa_keypair,
    sign as ecdsa_sign,
    verify as ecdsa_verify,
    signature_to_bytes, signature_from_bytes,
)

from common.wire import MsgType, send_message, recv_message
from common.formats import (
    DocumentHeader, Share,
    pack_document_header, pack_document, unpack_document,
    pack_payload, unpack_payload,
    pack_share_body, pack_share, unpack_share,
    DOC_ID_LEN, NONCE_LEN, SIG_LEN,
)
from client.keystore import save_keys, load_keys, rewrap_keys, KeystoreError
from client.trust_store import TrustStore, KeyMismatchError, TrustStatus, compute_fingerprint

# Argon2id parameters (§7.1). Measured 235 ms on the reference laptop.
ARGON2_T = 2
ARGON2_M_KIB = 128 * 1024
ARGON2_P = 1


class ClientError(Exception):
    """Any operation-level failure the caller should see."""


class SecureVaultClient:
    """
    One instance per user session. Not thread-safe — use one per thread.
    """

    def __init__(self,
                 host: str = "127.0.0.1",
                 port: int = 9999,
                 storage_dir: str = ".",
                 tofu_prompt: Callable[[str, str], bool] | None = None):
        self.host = host
        self.port = port
        self.storage_dir = storage_dir

        self.username: str | None = None
        self.sig_priv: int | None = None
        self.sig_pub_bytes: bytes | None = None
        self.dh_priv: int | None = None
        self.dh_pub_bytes: bytes | None = None
        self.trust: TrustStore | None = None

        # Called on TOFU first contact: (username, fingerprint) -> bool.
        # Default CLI-friendly behaviour: accept, log the fingerprint.
        self._tofu_prompt = tofu_prompt or self._default_tofu_prompt

    # ---- Networking ---------------------------------------------------

    def _rpc(self, msg_type: MsgType, payload: dict) -> tuple[MsgType, dict]:
        """Send one request, receive one response, close. Raises ClientError."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            send_message(sock, msg_type, payload)
            reply = recv_message(sock)
            sock.close()
            return reply
        except (OSError, ConnectionError, ValueError) as e:
            raise ClientError(f"network error: {e}") from e

    def _expect(self, reply: tuple[MsgType, dict],
                expected: MsgType | tuple[MsgType, ...]) -> dict:
        """Assert the reply is one of the expected types; raise otherwise."""
        mt, payload = reply
        allowed = (expected,) if isinstance(expected, MsgType) else expected
        if mt not in allowed:
            msg = payload.get("message", "server error")
            raise ClientError(msg)
        return payload

    # ---- Password → keys (§7.1) ---------------------------------------

    @staticmethod
    def _derive_master(password: str, salt: bytes,
                       t: int = ARGON2_T, m: int = ARGON2_M_KIB, p: int = ARGON2_P) -> bytes:
        return hash_secret_raw(
            secret=password.encode("utf-8"), salt=salt,
            time_cost=t, memory_cost=m, parallelism=p,
            hash_len=32, type=Type.ID,
        )

    @staticmethod
    def _derive_auth_scalar(auth_key: bytes) -> int:
        """Turn the 32-byte auth_key into a valid P-256 scalar in [1, N-1]."""
        return (int.from_bytes(auth_key, "big") % (P256_N - 1)) + 1

    # ---- Signup / Login -----------------------------------------------

    def signup(self, username: str, password: str) -> None:
        salt = os.urandom(16)
        master = self._derive_master(password, salt)
        auth_key, kek = derive_both(master)

        auth_scalar = self._derive_auth_scalar(auth_key)
        auth_pub_pt = scalar_mul_g(auth_scalar)
        assert auth_pub_pt is not None
        auth_pub_bytes = point_to_bytes(auth_pub_pt)

        sig_priv, sig_pub_bytes = ecdsa_keypair()
        dh_priv, dh_pub_bytes = ecdh_keypair()

        # Save identity keys encrypted with kek BEFORE talking to the server —
        # if the write fails we don't want a server-side account we can't use.
        save_keys(self._keystore_path(username), sig_priv, dh_priv, kek)

        reply = self._rpc(MsgType.REGISTER, {
            "username": username,
            "salt": base64.b64encode(salt).decode(),
            "argon2_params": {"t": ARGON2_T, "m": ARGON2_M_KIB, "p": ARGON2_P},
            "auth_pub": base64.b64encode(auth_pub_bytes).decode(),
            "sig_pub":  base64.b64encode(sig_pub_bytes).decode(),
            "dh_pub":   base64.b64encode(dh_pub_bytes).decode(),
        })
        self._expect(reply, MsgType.OK)

    def login(self, username: str, password: str) -> None:
        chal = self._expect(
            self._rpc(MsgType.LOGIN_CHALLENGE_REQ, {"username": username}),
            MsgType.LOGIN_CHALLENGE,
        )
        salt = base64.b64decode(chal["salt"])
        params = chal["argon2_params"]
        challenge = base64.b64decode(chal["challenge"])

        master = self._derive_master(password, salt,
                                     params["t"], params["m"], params["p"])
        auth_key, kek = derive_both(master)
        auth_scalar = self._derive_auth_scalar(auth_key)

        sig_r_s = ecdsa_sign(auth_scalar, challenge)
        sig_bytes = signature_to_bytes(sig_r_s)

        self._expect(
            self._rpc(MsgType.LOGIN_RESPONSE, {
                "username": username,
                "challenge_signature": base64.b64encode(sig_bytes).decode(),
            }),
            MsgType.OK,
        )

        try:
            sig_priv, dh_priv = load_keys(self._keystore_path(username), kek)
        except KeystoreError as e:
            raise ClientError(f"invalid credentials: {e}") from e

        sig_pub_pt = scalar_mul_g(sig_priv)
        dh_pub_pt  = scalar_mul_g(dh_priv)
        assert sig_pub_pt is not None and dh_pub_pt is not None

        self.username = username
        self.sig_priv = sig_priv
        self.sig_pub_bytes = point_to_bytes(sig_pub_pt)
        self.dh_priv = dh_priv
        self.dh_pub_bytes = point_to_bytes(dh_pub_pt)
        self.trust = TrustStore(username, base_dir=self.storage_dir)

    def logout(self) -> None:
        self.username = None
        self.sig_priv = None
        self.sig_pub_bytes = None
        self.dh_priv = None
        self.dh_pub_bytes = None
        self.trust = None

    # ---- Change password ----------------------------------------------

    def change_password(self, old_password: str, new_password: str) -> None:
        self._require_login()
        username = self.username
        assert username is not None

        salt_reply = self._expect(
            self._rpc(MsgType.GET_SALT, {"username": username}),
            MsgType.OK,
        )
        old_salt = base64.b64decode(salt_reply["salt"])
        old_params = salt_reply["argon2_params"]

        old_master = self._derive_master(old_password, old_salt,
                                         old_params["t"], old_params["m"], old_params["p"])
        old_auth_key, old_kek = derive_both(old_master)
        old_auth_scalar = self._derive_auth_scalar(old_auth_key)

        # Verify the OLD password is correct by loading the keystore with old_kek.
        # If load_keys succeeds, they know the old password.
        try:
            load_keys(self._keystore_path(username), old_kek)
        except KeystoreError as e:
            raise ClientError("old password incorrect") from e

        new_salt = os.urandom(16)
        new_master = self._derive_master(new_password, new_salt)
        new_auth_key, new_kek = derive_both(new_master)
        new_auth_scalar = self._derive_auth_scalar(new_auth_key)
        new_auth_pub_pt = scalar_mul_g(new_auth_scalar)
        assert new_auth_pub_pt is not None
        new_auth_pub_bytes = point_to_bytes(new_auth_pub_pt)

        # Sign the change_password action with the OLD auth key — proves knowledge
        # of the old password to the server.
        nonce_b64 = base64.b64encode(os.urandom(16)).decode()
        canonical = f"change_password:{username}:{nonce_b64}"
        proof = signature_to_bytes(ecdsa_sign(old_auth_scalar, canonical.encode("utf-8")))

        # Rewrap the keystore under new_kek — same identity keys, so old shares
        # to this user still open (§7.1).
        rewrap_keys(self._keystore_path(username), old_kek, new_kek)

        self._expect(self._rpc(MsgType.CHANGE_PASSWORD, {
            "username": username,
            "request_nonce": nonce_b64,
            "old_auth_proof": base64.b64encode(proof).decode(),
            "new_salt": base64.b64encode(new_salt).decode(),
            "new_argon2_params": {"t": ARGON2_T, "m": ARGON2_M_KIB, "p": ARGON2_P},
            "new_auth_pub": base64.b64encode(new_auth_pub_bytes).decode(),
        }), MsgType.OK)

    # ---- Upload -------------------------------------------------------

    def upload(self, file_path: str) -> str:
        """Encrypt and upload a local file. Returns the doc_id (hex)."""
        self._require_login()
        assert self.username and self.sig_priv is not None and self.dh_pub_bytes is not None

        with open(file_path, "rb") as f:
            content = f.read()
        filename = os.path.basename(file_path)

        # Sign the file content itself (§7.5 non-repudiation).
        content_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, sha256(content)))
        payload_bytes = pack_payload(filename, "application/octet-stream",
                                     content, content_sig)

        # Encrypt with a fresh per-file key FK (§7.2). Fresh key => zero nonce is safe.
        FK = os.urandom(32)
        doc_id = os.urandom(DOC_ID_LEN)
        header = DocumentHeader(
            doc_id=doc_id, owner=self.username,
            version=1, created_ms=int(time.time() * 1000),
        )
        aad = pack_document_header(header)
        ct, tag = gcm_encrypt(FK, b"\x00" * NONCE_LEN, payload_bytes, aad)
        doc_blob = pack_document(header, b"\x00" * NONCE_LEN, ct, tag)

        nonce_b64 = base64.b64encode(os.urandom(16)).decode()
        canonical = f"upload:{self.username}:{nonce_b64}"
        req_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, canonical.encode()))

        reply = self._expect(self._rpc(MsgType.UPLOAD, {
            "owner": self.username,
            "document": base64.b64encode(doc_blob).decode(),
            "request_nonce": nonce_b64,
            "request_signature": base64.b64encode(req_sig).decode(),
        }), MsgType.OK)

        # Self-share so we can later download our own document. Must come
        # AFTER the upload succeeds — the server rejects shares for docs
        # that don't yet exist.
        self._store_self_share(doc_id, ct, FK, version=1)

        return reply["doc_id"]

    def _store_self_share(self, doc_id: bytes, ciphertext: bytes,
                          FK: bytes, version: int) -> None:
        """Send a self-share to the server so the uploader can later download."""
        assert self.username and self.sig_priv is not None and self.dh_pub_bytes is not None

        eph_priv, eph_pub = ecdh_keypair()
        info = b"wrap|" + doc_id + b"|to=" + self.username.encode() + b"|from=" + self.username.encode()
        wrap_key = shared_key(eph_priv, self.dh_pub_bytes, info=info)
        wrapped_fk, wrap_tag = gcm_encrypt(wrap_key, b"\x00" * NONCE_LEN, FK, aad=b"")

        share_body = Share(
            doc_id=doc_id, version=version,
            doc_hash=sha256(ciphertext),
            sender=self.username, recipient=self.username,
            issued_ms=int(time.time() * 1000),
            eph_pub=eph_pub,
            nonce=b"\x00" * NONCE_LEN,
            wrapped_fk=wrapped_fk, tag=wrap_tag,
            share_sig=b"\x00" * SIG_LEN,
        )
        share_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, pack_share_body(share_body)))
        finalized = Share(**{**share_body.__dict__, "share_sig": share_sig})
        share_blob = pack_share(finalized)

        nonce_b64 = base64.b64encode(os.urandom(16)).decode()
        canonical = f"share:{self.username}:{doc_id.hex()}:{self.username}:{nonce_b64}"
        req_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, canonical.encode()))

        self._expect(self._rpc(MsgType.SHARE, {
            "sender": self.username, "recipient": self.username,
            "doc_id": doc_id.hex(),
            "share_blob": base64.b64encode(share_blob).decode(),
            "request_nonce": nonce_b64,
            "request_signature": base64.b64encode(req_sig).decode(),
        }), MsgType.OK)

    # ---- Share --------------------------------------------------------

    def share(self, doc_id_hex: str, recipient: str) -> None:
        """Share an already-uploaded document with another user."""
        self._require_login()
        assert self.username and self.sig_priv is not None

        # Look up recipient's public keys (through TOFU).
        recipient_sig_pub, recipient_dh_pub = self._get_verified_pubkey(recipient)

        # Retrieve our own copy to recover FK.
        doc_blob, our_share_blob = self._fetch_doc(doc_id_hex)
        parsed_doc = unpack_document(doc_blob)
        our_share = unpack_share(our_share_blob)
        FK = self._unwrap_fk(our_share)

        # Sanity check: does the doc's ciphertext match the hash our stored share committed to?
        if sha256(parsed_doc.ciphertext) != our_share.doc_hash:
            raise ClientError("stored share is stale — doc_hash mismatch")

        # Wrap FK for the recipient.
        doc_id = bytes.fromhex(doc_id_hex)
        eph_priv, eph_pub = ecdh_keypair()
        info = b"wrap|" + doc_id + b"|to=" + recipient.encode() + b"|from=" + self.username.encode()
        wrap_key = shared_key(eph_priv, recipient_dh_pub, info=info)
        wrapped_fk, wrap_tag = gcm_encrypt(wrap_key, b"\x00" * NONCE_LEN, FK, aad=b"")

        share_body = Share(
            doc_id=doc_id, version=parsed_doc.header.version,
            doc_hash=sha256(parsed_doc.ciphertext),
            sender=self.username, recipient=recipient,
            issued_ms=int(time.time() * 1000),
            eph_pub=eph_pub,
            nonce=b"\x00" * NONCE_LEN,
            wrapped_fk=wrapped_fk, tag=wrap_tag,
            share_sig=b"\x00" * SIG_LEN,
        )
        share_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, pack_share_body(share_body)))
        finalized = Share(**{**share_body.__dict__, "share_sig": share_sig})
        share_blob = pack_share(finalized)

        nonce_b64 = base64.b64encode(os.urandom(16)).decode()
        canonical = f"share:{self.username}:{doc_id_hex}:{recipient}:{nonce_b64}"
        req_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, canonical.encode()))

        self._expect(self._rpc(MsgType.SHARE, {
            "sender": self.username, "recipient": recipient,
            "doc_id": doc_id_hex,
            "share_blob": base64.b64encode(share_blob).decode(),
            "request_nonce": nonce_b64,
            "request_signature": base64.b64encode(req_sig).decode(),
        }), MsgType.OK)

    # ---- Download & verify --------------------------------------------

    def download(self, doc_id_hex: str, save_path: str) -> str:
        """Retrieve a document, verify all signatures, save plaintext to disk.
        Returns the name of the verified sender."""
        self._require_login()
        assert self.username and self.dh_priv is not None

        doc_blob, share_blob = self._fetch_doc(doc_id_hex)
        parsed_doc = unpack_document(doc_blob)
        parsed_share = unpack_share(share_blob)

        # Freshness: doc_hash in share must match what the server delivered as the doc.
        if sha256(parsed_doc.ciphertext) != parsed_share.doc_hash:
            raise ClientError("doc_hash mismatch — server may have swapped the document")
        if parsed_share.recipient != self.username:
            raise ClientError("share is not addressed to us")

        # Verify the sender's share signature.
        sender_sig_pub, _ = self._get_verified_pubkey(parsed_share.sender)
        unsigned_share = Share(**{**parsed_share.__dict__, "share_sig": b"\x00" * SIG_LEN})
        if not ecdsa_verify(sender_sig_pub, pack_share_body(unsigned_share),
                            signature_from_bytes(parsed_share.share_sig)):
            raise ClientError("share signature invalid")

        # Unwrap FK, then GCM-decrypt the document (tag verified inside).
        FK = self._unwrap_fk(parsed_share)
        plaintext = gcm_decrypt(FK, parsed_doc.nonce, parsed_doc.ciphertext,
                                parsed_doc.tag, parsed_doc.header_aad)
        if plaintext is None:
            raise ClientError("document GCM tag failed — tampered ciphertext or metadata")

        payload = unpack_payload(plaintext)

        # Verify owner's content signature (§7.5 non-repudiation of authorship).
        owner_sig_pub, _ = self._get_verified_pubkey(parsed_doc.header.owner)
        if not ecdsa_verify(owner_sig_pub, sha256(payload.content),
                            signature_from_bytes(payload.content_sig)):
            raise ClientError("content signature invalid")

        with open(save_path, "wb") as f:
            f.write(payload.content)
        return parsed_doc.header.owner

    def _fetch_doc(self, doc_id_hex: str) -> tuple[bytes, bytes]:
        """GET_DOC round-trip. Returns (doc_blob, share_blob)."""
        assert self.username and self.sig_priv is not None
        nonce_b64 = base64.b64encode(os.urandom(16)).decode()
        canonical = f"download:{self.username}:{doc_id_hex}:{nonce_b64}"
        req_sig = signature_to_bytes(ecdsa_sign(self.sig_priv, canonical.encode()))
        reply = self._expect(self._rpc(MsgType.GET_DOC, {
            "user": self.username, "doc_id": doc_id_hex,
            "request_nonce": nonce_b64,
            "request_signature": base64.b64encode(req_sig).decode(),
        }), MsgType.DOC)
        doc_blob = base64.b64decode(reply["document"])
        share_b64 = reply.get("share")
        if share_b64 is None:
            raise ClientError("server did not include a share record for us")
        return doc_blob, base64.b64decode(share_b64)

    def _unwrap_fk(self, share: Share) -> bytes:
        """Recompute the wrap_key from our dh_priv + share.eph_pub, decrypt FK."""
        assert self.username and self.dh_priv is not None
        info = (b"wrap|" + share.doc_id + b"|to=" + share.recipient.encode()
                + b"|from=" + share.sender.encode())
        wrap_key = shared_key(self.dh_priv, share.eph_pub, info=info)
        FK = gcm_decrypt(wrap_key, share.nonce, share.wrapped_fk, share.tag, aad=b"")
        if FK is None:
            raise ClientError("wrapped file key GCM tag failed")
        return FK

    # ---- Contact keys through TOFU ------------------------------------

    def _get_verified_pubkey(self, username: str) -> tuple[bytes, bytes]:
        """
        Retrieve `username`'s (sig_pub, dh_pub), running them through TOFU.

        First contact: prompts the user (via self._tofu_prompt) and stores
        as UNVERIFIED if accepted.
        Repeat contact: checks the fingerprint against the store, hard-blocks
        on mismatch.
        """
        assert self.trust is not None
        if username == self.username:
            # Talking to ourselves — no TOFU needed, our own keys are trusted.
            assert self.sig_pub_bytes is not None and self.dh_pub_bytes is not None
            return self.sig_pub_bytes, self.dh_pub_bytes

        reply = self._expect(
            self._rpc(MsgType.GET_USER_PUBKEY, {"username": username}),
            MsgType.USER_PUBKEY,
        )
        sig_pub = base64.b64decode(reply["sig_pub"])
        dh_pub  = base64.b64decode(reply["dh_pub"])

        try:
            self.trust.check(username, sig_pub, dh_pub)
        except KeyError:
            fp = compute_fingerprint(sig_pub, dh_pub)
            if not self._tofu_prompt(username, fp):
                raise ClientError(f"user declined to trust '{username}'")
            self.trust.record_first_contact(username, sig_pub, dh_pub)
        except KeyMismatchError as e:
            raise ClientError(str(e)) from e

        return sig_pub, dh_pub

    def mark_contact_verified(self, username: str) -> None:
        """Promote UNVERIFIED → VERIFIED after out-of-band fingerprint check."""
        self._require_login()
        assert self.trust is not None
        self.trust.mark_verified(username)

    # ---- Small helpers ------------------------------------------------

    def _require_login(self) -> None:
        if self.username is None:
            raise ClientError("not logged in")

    def _keystore_path(self, username: str) -> str:
        return os.path.join(self.storage_dir, f"{username}_keys.svks")

    @staticmethod
    def _default_tofu_prompt(username: str, fingerprint: str) -> bool:
        """CLI default: accept, print the fingerprint so the user can compare later."""
        print(f"[!] First contact with '{username}'. Fingerprint: {fingerprint}")
        print("    Compare this out-of-band, then run mark_contact_verified().")
        return True
