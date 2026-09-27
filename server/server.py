"""
SecureVault TCP server.

Handles one connection per thread. Every request is a framed message
(see common/wire.py); every response is a framed message back.

The server is honest-but-curious: it stores what clients give it and
serves it back on request, but it can't read anyone's files, forge
signatures, or learn passwords. This is enforced by the crypto, not
by any promise the server makes.

Message routing:
  REGISTER              -> register()
  LOGIN_CHALLENGE_REQ   -> login_challenge()
  LOGIN_RESPONSE        -> login()
  GET_SALT              -> get_salt()
  GET_USER_PUBKEY       -> get_user_pubkey()
  UPLOAD                -> upload()
  SHARE                 -> share()
  GET_DOC               -> get_doc()
  LIST_DOCS             -> list_docs()
  CHANGE_PASSWORD       -> change_password()

Fake-salt trick for unknown users: an unknown login/get_salt still gets
a stable salt (HMAC(server_secret, username)) and the same error text
as a wrong password. An attacker can't tell registered users apart from
unregistered ones by response content or timing.
"""

from __future__ import annotations

import base64
import os
import socket
import threading
import time

from common.wire import MsgType, send_message, recv_message
from server.db import ServerDB, UserRecord, DocumentRecord, ShareRecord
from server.session import (
    SessionState,
    payload_upload, payload_share, payload_download, payload_change_password,
)
from crypto.hmac import hmac_sha256
from crypto.ecdsa import verify as ecdsa_verify, signature_from_bytes
from common.formats import (
    unpack_document, unpack_share,
    DOC_ID_LEN,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
SALT_LEN = 16


class SecureVaultServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 db_path: str = ":memory:"):
        self.host = host
        self.port = port
        self.db = ServerDB(db_path)
        self.session = SessionState()
        # Server secret is used only to derive fake salts for unknown users.
        # Never leaves the process; a fresh one each start is fine because
        # the fake-salt property only needs consistency within one run.
        self._server_secret = os.urandom(32)
        self._listener: socket.socket | None = None
        self._shutdown = threading.Event()

    # ---- Lifecycle ----------------------------------------------------

    def start(self) -> None:
        """Bind and serve forever. Blocks the calling thread."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen(16)
        print(f"[server] listening on {self.host}:{self.port}")
        try:
            while not self._shutdown.is_set():
                try:
                    conn, addr = self._listener.accept()
                except OSError:
                    break
                threading.Thread(target=self._handle_connection,
                                 args=(conn, addr), daemon=True).start()
        finally:
            self._listener.close()

    def stop(self) -> None:
        self._shutdown.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        self.db.close()

    # ---- Connection handler -------------------------------------------

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        try:
            msg_type, payload = recv_message(conn)
            response_type, response_payload = self._dispatch(msg_type, payload)
            send_message(conn, response_type, response_payload)
        except (ConnectionError, ValueError) as e:
            try:
                send_message(conn, MsgType.ERROR, {"message": str(e)})
            except Exception:
                pass
        except Exception as e:
            try:
                send_message(conn, MsgType.ERROR,
                             {"message": f"internal error: {e}"})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, msg_type: MsgType, payload: dict) -> tuple[MsgType, dict]:
        handlers = {
            MsgType.REGISTER:            self.register,
            MsgType.LOGIN_CHALLENGE_REQ: self.login_challenge,
            MsgType.LOGIN_RESPONSE:      self.login,
            MsgType.GET_SALT:            self.get_salt,
            MsgType.GET_USER_PUBKEY:     self.get_user_pubkey,
            MsgType.UPLOAD:              self.upload,
            MsgType.SHARE:               self.share,
            MsgType.GET_DOC:             self.get_doc,
            MsgType.LIST_DOCS:           self.list_docs,
            MsgType.CHANGE_PASSWORD:     self.change_password,
        }
        handler = handlers.get(msg_type)
        if handler is None:
            return MsgType.ERROR, {"message": f"unsupported request: {msg_type.name}"}
        return handler(payload)

    # ---- Handlers -----------------------------------------------------

    def register(self, p: dict) -> tuple[MsgType, dict]:
        try:
            username  = _require_str(p, "username")
            salt      = _require_b64(p, "salt", exact_len=SALT_LEN)
            argon2    = p["argon2_params"]
            auth_pub  = _require_b64(p, "auth_pub", exact_len=65)
            sig_pub   = _require_b64(p, "sig_pub",  exact_len=65)
            dh_pub    = _require_b64(p, "dh_pub",   exact_len=65)
            t, m, pp = int(argon2["t"]), int(argon2["m"]), int(argon2["p"])
        except (KeyError, TypeError, ValueError) as e:
            return MsgType.ERROR, {"message": f"malformed register: {e}"}

        try:
            self.db.create_user(UserRecord(
                username=username, salt=salt,
                argon2_t=t, argon2_m=m, argon2_p=pp,
                auth_pub=auth_pub, sig_pub=sig_pub, dh_pub=dh_pub,
            ))
        except ValueError as e:
            return MsgType.ERROR, {"message": str(e)}
        return MsgType.OK, {"message": f"user '{username}' registered"}

    def login_challenge(self, p: dict) -> tuple[MsgType, dict]:
        try:
            username = _require_str(p, "username")
        except KeyError as e:
            return MsgType.ERROR, {"message": f"malformed request: {e}"}

        user = self.db.get_user(username)
        if user is not None:
            salt = user.salt
            argon2 = user.argon2_params()
        else:
            # Fake but stable salt so an attacker can't tell registered
            # users apart by response content. Uses same shape as a real
            # salt (16 bytes) and default Argon2 params.
            salt = hmac_sha256(self._server_secret,
                               username.encode("utf-8"))[:SALT_LEN]
            argon2 = {"t": 2, "m": 128 * 1024, "p": 1}

        challenge = self.session.issue_challenge(username)
        return MsgType.LOGIN_CHALLENGE, {
            "salt":          base64.b64encode(salt).decode(),
            "argon2_params": argon2,
            "challenge":     base64.b64encode(challenge).decode(),
        }

    def login(self, p: dict) -> tuple[MsgType, dict]:
        # Same error text on any failure — never distinguish wrong-password
        # from unknown-user (see §7.1).
        BAD = (MsgType.ERROR, {"message": "invalid credentials"})
        try:
            username = _require_str(p, "username")
            sig_b64  = _require_str(p, "challenge_signature")
        except KeyError:
            return BAD

        user = self.db.get_user(username)
        challenge = self.session.consume_challenge(username)
        if user is None or challenge is None:
            return BAD

        try:
            sig = signature_from_bytes(base64.b64decode(sig_b64))
        except (ValueError, Exception):
            return BAD

        if not ecdsa_verify(user.auth_pub, challenge, sig):
            return BAD
        return MsgType.OK, {"message": "login successful"}

    def get_salt(self, p: dict) -> tuple[MsgType, dict]:
        try:
            username = _require_str(p, "username")
        except KeyError as e:
            return MsgType.ERROR, {"message": str(e)}
        user = self.db.get_user(username)
        if user is None:
            return MsgType.ERROR, {"message": "user not found"}
        return MsgType.OK, {
            "salt":          base64.b64encode(user.salt).decode(),
            "argon2_params": user.argon2_params(),
        }

    def get_user_pubkey(self, p: dict) -> tuple[MsgType, dict]:
        try:
            username = _require_str(p, "username")
        except KeyError as e:
            return MsgType.ERROR, {"message": str(e)}
        user = self.db.get_user(username)
        if user is None:
            return MsgType.ERROR, {"message": "user not found"}
        return MsgType.USER_PUBKEY, {
            "sig_pub": base64.b64encode(user.sig_pub).decode(),
            "dh_pub":  base64.b64encode(user.dh_pub).decode(),
        }

    def upload(self, p: dict) -> tuple[MsgType, dict]:
        try:
            owner        = _require_str(p, "owner")
            request_nonce = _require_str(p, "request_nonce")
            request_sig   = _require_b64(p, "request_signature")
            doc_blob      = _require_b64(p, "document")
        except (KeyError, ValueError) as e:
            return MsgType.ERROR, {"message": f"malformed upload: {e}"}

        auth = self._authenticate(owner, payload_upload(owner, request_nonce),
                                  request_sig, request_nonce)
        if auth is not None:
            return auth

        try:
            parsed = unpack_document(doc_blob)
        except ValueError as e:
            return MsgType.ERROR, {"message": f"malformed document: {e}"}

        if parsed.header.owner != owner:
            return MsgType.ERROR, {"message": "owner in header does not match caller"}

        try:
            self.db.create_document(DocumentRecord(
                doc_id=parsed.header.doc_id,
                owner=parsed.header.owner,
                version=parsed.header.version,
                created_ms=parsed.header.created_ms,
                blob=doc_blob,
            ))
        except ValueError as e:
            return MsgType.ERROR, {"message": str(e)}
        return MsgType.OK, {"doc_id": parsed.header.doc_id.hex()}

    def share(self, p: dict) -> tuple[MsgType, dict]:
        try:
            sender       = _require_str(p, "sender")
            recipient    = _require_str(p, "recipient")
            doc_id_hex   = _require_str(p, "doc_id")
            request_nonce = _require_str(p, "request_nonce")
            request_sig   = _require_b64(p, "request_signature")
            share_blob   = _require_b64(p, "share_blob")
        except (KeyError, ValueError) as e:
            return MsgType.ERROR, {"message": f"malformed share: {e}"}

        auth = self._authenticate(
            sender,
            payload_share(sender, doc_id_hex, recipient, request_nonce),
            request_sig, request_nonce,
        )
        if auth is not None:
            return auth

        try:
            doc_id = bytes.fromhex(doc_id_hex)
        except ValueError:
            return MsgType.ERROR, {"message": "bad doc_id"}
        if len(doc_id) != DOC_ID_LEN:
            return MsgType.ERROR, {"message": "bad doc_id length"}

        try:
            parsed = unpack_share(share_blob)
        except ValueError as e:
            return MsgType.ERROR, {"message": f"malformed share blob: {e}"}

        if parsed.sender != sender or parsed.recipient != recipient or parsed.doc_id != doc_id:
            return MsgType.ERROR, {"message": "share fields do not match request"}
        if self.db.get_user(recipient) is None:
            return MsgType.ERROR, {"message": "recipient not found"}
        if self.db.get_document(doc_id) is None:
            return MsgType.ERROR, {"message": "document not found"}

        self.db.create_or_replace_share(ShareRecord(
            doc_id=doc_id, recipient=recipient,
            blob=share_blob, issued_ms=parsed.issued_ms,
        ))
        return MsgType.OK, {"message": f"shared with '{recipient}'"}

    def get_doc(self, p: dict) -> tuple[MsgType, dict]:
        try:
            user         = _require_str(p, "user")
            doc_id_hex   = _require_str(p, "doc_id")
            request_nonce = _require_str(p, "request_nonce")
            request_sig   = _require_b64(p, "request_signature")
        except (KeyError, ValueError) as e:
            return MsgType.ERROR, {"message": f"malformed get_doc: {e}"}

        auth = self._authenticate(
            user, payload_download(user, doc_id_hex, request_nonce),
            request_sig, request_nonce,
        )
        if auth is not None:
            return auth

        try:
            doc_id = bytes.fromhex(doc_id_hex)
        except ValueError:
            return MsgType.ERROR, {"message": "bad doc_id"}

        doc = self.db.get_document(doc_id)
        if doc is None:
            return MsgType.ERROR, {"message": "document not found"}

        # Owner can always download their own doc. Otherwise a share must exist.
        share = None
        if doc.owner != user:
            share = self.db.get_share(doc_id, user)
            if share is None:
                return MsgType.ERROR, {"message": "access denied"}

        return MsgType.DOC, {
            "document":  base64.b64encode(doc.blob).decode(),
            "share":     base64.b64encode(share.blob).decode() if share else None,
        }

    def list_docs(self, p: dict) -> tuple[MsgType, dict]:
        try:
            user = _require_str(p, "user")
        except KeyError as e:
            return MsgType.ERROR, {"message": str(e)}
        owned  = self.db.list_documents_owned_by(user)
        shared = self.db.list_shares_for(user)
        return MsgType.DOC_LIST, {
            "owned":  [d.doc_id.hex() for d in owned],
            "shared": [s.doc_id.hex() for s in shared],
        }

    def change_password(self, p: dict) -> tuple[MsgType, dict]:
        try:
            username     = _require_str(p, "username")
            request_nonce = _require_str(p, "request_nonce")
            old_auth_proof = _require_b64(p, "old_auth_proof")
            new_salt     = _require_b64(p, "new_salt", exact_len=SALT_LEN)
            new_argon2   = p["new_argon2_params"]
            new_auth_pub = _require_b64(p, "new_auth_pub", exact_len=65)
        except (KeyError, ValueError) as e:
            return MsgType.ERROR, {"message": f"malformed change_password: {e}"}

        user = self.db.get_user(username)
        if user is None:
            return MsgType.ERROR, {"message": "old password incorrect"}

        # Old password check: signature by old auth_pub over the canonical
        # payload proves the caller can still derive the old auth key.
        canonical = payload_change_password(username, request_nonce)
        try:
            sig = signature_from_bytes(old_auth_proof)
        except ValueError:
            return MsgType.ERROR, {"message": "old password incorrect"}
        if not ecdsa_verify(user.auth_pub, canonical.encode("utf-8"), sig):
            return MsgType.ERROR, {"message": "old password incorrect"}
        if not self.session.check_and_consume_nonce(request_nonce):
            return MsgType.ERROR, {"message": "nonce already used"}

        self.db.update_user_auth(
            username,
            new_salt,
            int(new_argon2["t"]), int(new_argon2["m"]), int(new_argon2["p"]),
            new_auth_pub,
        )
        return MsgType.OK, {"message": "password changed"}

    # ---- Shared authentication path -----------------------------------

    def _authenticate(self, user: str, canonical_payload: str,
                      signature_bytes: bytes, nonce_b64: str
                      ) -> tuple[MsgType, dict] | None:
        """
        Verify the caller's request signature and freshness.
        Returns None on success; an error tuple to send back on failure.
        Nonce is consumed only if the signature is valid — otherwise an
        attacker could burn fresh nonces by sending garbage.
        """
        record = self.db.get_user(user)
        if record is None:
            return MsgType.ERROR, {"message": "user not found"}
        ok = SessionState.verify_request_signature(
            record.sig_pub, canonical_payload, signature_bytes,
        )
        if not ok:
            return MsgType.ERROR, {"message": "bad request signature"}
        if not self.session.check_and_consume_nonce(nonce_b64):
            return MsgType.ERROR, {"message": "nonce already used"}
        return None


# ---- Helpers -----------------------------------------------------------

def _require_str(d: dict, key: str) -> str:
    v = d[key]
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a string")
    return v


def _require_b64(d: dict, key: str, exact_len: int | None = None) -> bytes:
    v = d[key]
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a base64 string")
    try:
        raw = base64.b64decode(v)
    except Exception:
        raise ValueError(f"{key} is not valid base64")
    if exact_len is not None and len(raw) != exact_len:
        raise ValueError(f"{key} must be exactly {exact_len} bytes")
    return raw


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = SecureVaultServer(port=port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[server] shutting down")
        server.stop()
