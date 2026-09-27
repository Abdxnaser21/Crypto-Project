"""
Attacker-in-the-middle proxy for SecureVault demos (§8).

Sits between the client and the real server. In passthrough mode it just
forwards traffic. In an attack mode it modifies one specific field of
the response (or replays a captured request) — and the client's crypto
detects it and refuses to proceed.

Modes:
    passthrough       forward everything unchanged
    flip_ciphertext   flip 1 byte in a downloaded document's ciphertext
    flip_metadata     alter the owner name in the document header (AAD)
    swap_pubkey       hand out attacker-generated public keys instead
    replay            resend a captured request instead of the new one
"""

from __future__ import annotations

import argparse
import base64
import socket
import threading

from common.wire import MsgType, recv_message, send_message, encode
from common.formats import (
    unpack_document, pack_document, DocumentHeader,
    NONCE_LEN, DOC_ID_LEN,
)
from crypto.ecdh import generate_keypair as ecdh_keypair
from crypto.ecdsa import generate_keypair as ecdsa_keypair


DEFAULT_LISTEN = 9998
DEFAULT_UPSTREAM = 9999


class AttackerProxy:
    def __init__(self, mode: str,
                 listen_port: int = DEFAULT_LISTEN,
                 upstream_host: str = "127.0.0.1",
                 upstream_port: int = DEFAULT_UPSTREAM):
        self.mode = mode
        self.listen_port = listen_port
        self.upstream = (upstream_host, upstream_port)
        self._last_request: tuple[MsgType, dict] | None = None
        self._listener: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", self.listen_port))
        self._listener.listen(16)
        print(f"[attacker] listening on 127.0.0.1:{self.listen_port} → "
              f"upstream {self.upstream[0]}:{self.upstream[1]}, mode={self.mode}")
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = self._listener.accept()
                except OSError:
                    break
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        finally:
            self._listener.close()

    def stop(self) -> None:
        self._stop.set()
        if self._listener:
            try: self._listener.close()
            except OSError: pass

    # ---- Per-connection handler ---------------------------------------

    def _handle(self, client_conn: socket.socket) -> None:
        try:
            client_mt, client_payload = recv_message(client_conn)

            # In REPLAY mode: if we've seen a request before, resend the
            # captured one instead of the fresh one.
            if self.mode == "replay" and self._last_request is not None:
                print(f"[attacker] REPLAY: resending old {self._last_request[0].name} "
                      f"instead of new {client_mt.name}")
                upstream_mt, upstream_payload = self._last_request
            else:
                upstream_mt, upstream_payload = client_mt, client_payload
                self._last_request = (client_mt, client_payload)

            # Forward to real server, get response.
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_sock.connect(self.upstream)
            send_message(upstream_sock, upstream_mt, upstream_payload)
            server_mt, server_payload = recv_message(upstream_sock)
            upstream_sock.close()

            # Apply the attack, if any, to the response.
            server_mt, server_payload = self._attack_response(
                client_mt, server_mt, server_payload,
            )

            send_message(client_conn, server_mt, server_payload)
        except Exception as e:
            print(f"[attacker] error: {e}")
        finally:
            try: client_conn.close()
            except OSError: pass

    # ---- Attacks -------------------------------------------------------

    def _attack_response(self, client_mt: MsgType,
                         server_mt: MsgType, payload: dict
                         ) -> tuple[MsgType, dict]:
        """Return a possibly-modified (server_mt, payload)."""
        if self.mode == "flip_ciphertext" and server_mt == MsgType.DOC:
            return server_mt, self._attack_flip_ciphertext(payload)

        if self.mode == "flip_metadata" and server_mt == MsgType.DOC:
            return server_mt, self._attack_flip_metadata(payload)

        if self.mode == "swap_pubkey" and server_mt == MsgType.USER_PUBKEY:
            return server_mt, self._attack_swap_pubkey(payload)

        return server_mt, payload

    def _attack_flip_ciphertext(self, payload: dict) -> dict:
        """Unpack the document, flip a ciphertext byte, repack."""
        try:
            doc_blob = base64.b64decode(payload["document"])
            parsed = unpack_document(doc_blob)
            bad_ct = bytearray(parsed.ciphertext)
            if len(bad_ct) == 0:
                print("[attacker] empty ciphertext, nothing to flip")
                return payload
            bad_ct[0] ^= 0x01
            new_blob = pack_document(parsed.header, parsed.nonce,
                                     bytes(bad_ct), parsed.tag)
            payload = dict(payload)
            payload["document"] = base64.b64encode(new_blob).decode()
            print("[attacker] flipped byte 0 of ciphertext — GCM should reject")
            return payload
        except Exception as e:
            print(f"[attacker] flip_ciphertext failed: {e}")
            return payload

    def _attack_flip_metadata(self, payload: dict) -> dict:
        """Rewrite the document header's owner name (part of AAD)."""
        try:
            doc_blob = base64.b64decode(payload["document"])
            parsed = unpack_document(doc_blob)
            forged_header = DocumentHeader(
                doc_id=parsed.header.doc_id,
                owner=parsed.header.owner + "_TAMPERED",
                version=parsed.header.version,
                created_ms=parsed.header.created_ms,
            )
            new_blob = pack_document(forged_header, parsed.nonce,
                                     parsed.ciphertext, parsed.tag)
            payload = dict(payload)
            payload["document"] = base64.b64encode(new_blob).decode()
            print(f"[attacker] altered owner in header AAD "
                  f"('{parsed.header.owner}' → '{forged_header.owner}') "
                  f"— GCM should reject")
            return payload
        except Exception as e:
            print(f"[attacker] flip_metadata failed: {e}")
            return payload

    def _attack_swap_pubkey(self, payload: dict) -> dict:
        """Replace the returned public keys with attacker-generated ones."""
        try:
            _, fake_sig_pub = ecdsa_keypair()
            _, fake_dh_pub  = ecdh_keypair()
            payload = dict(payload)
            payload["sig_pub"] = base64.b64encode(fake_sig_pub).decode()
            payload["dh_pub"]  = base64.b64encode(fake_dh_pub).decode()
            print("[attacker] swapped both public keys with our own "
                  "— client TOFU should reject on repeat, or if user compares fingerprint")
            return payload
        except Exception as e:
            print(f"[attacker] swap_pubkey failed: {e}")
            return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", default="passthrough",
                        choices=["passthrough", "flip_ciphertext",
                                 "flip_metadata", "swap_pubkey", "replay"])
    parser.add_argument("--listen-port",   type=int, default=DEFAULT_LISTEN)
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    args = parser.parse_args()

    proxy = AttackerProxy(
        mode=args.mode,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
    )
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n[attacker] shutting down")
        proxy.stop()


if __name__ == "__main__":
    main()
