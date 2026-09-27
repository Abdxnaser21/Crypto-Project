from __future__ import annotations
import json
import socket
from enum import IntEnum

# Cap incoming messages so a malicious peer can't make us allocate GBs.
# 128 MiB is plenty for a whole encrypted file blob in one JSON payload.
MAX_MESSAGE_LEN = 128 * 1024 * 1024


class MsgType(IntEnum):
    # Requests (client -> server)
    REGISTER            = 0x01
    LOGIN_CHALLENGE_REQ = 0x02
    LOGIN_RESPONSE      = 0x03
    GET_USER_PUBKEY     = 0x04
    UPLOAD              = 0x05
    SHARE               = 0x06
    GET_DOC             = 0x07
    LIST_DOCS           = 0x08
    GET_SALT            = 0x09
    CHANGE_PASSWORD     = 0x0A

    # Responses (server -> client)
    OK                  = 0x80
    ERROR               = 0x81
    LOGIN_CHALLENGE     = 0x82
    DOC                 = 0x83
    USER_PUBKEY         = 0x84
    DOC_LIST            = 0x85


def encode(msg_type: MsgType, payload: dict) -> bytes:
    if not isinstance(msg_type, MsgType):
        raise TypeError(f"msg_type must be MsgType, got {type(msg_type).__name__}")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    frame_len = 1 + len(body)
    if frame_len > MAX_MESSAGE_LEN:
        raise ValueError(f"message too large ({frame_len} > {MAX_MESSAGE_LEN})")
    return frame_len.to_bytes(4, "big") + bytes([int(msg_type)]) + body


def decode(frame_body: bytes) -> tuple[MsgType, dict]:

    if len(frame_body) < 1:
        raise ValueError("empty frame")
    try:
        msg_type = MsgType(frame_body[0])
    except ValueError:
        raise ValueError(f"unknown message type: 0x{frame_body[0]:02X}")
    if len(frame_body) == 1:
        payload = {}
    else:
        try:
            payload = json.loads(frame_body[1:].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"malformed JSON payload: {e}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
    return msg_type, payload


def send_message(sock: socket.socket, msg_type: MsgType, payload: dict) -> None:
    """Convenience: encode and send one full frame on `sock`."""
    sock.sendall(encode(msg_type, payload))


def recv_message(sock: socket.socket) -> tuple[MsgType, dict]:
    length_bytes = _recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    if length < 1:
        raise ValueError("frame length must be >= 1")
    if length > MAX_MESSAGE_LEN:
        raise ValueError(f"frame length {length} exceeds cap {MAX_MESSAGE_LEN}")
    body = _recv_exact(sock, length)
    return decode(body)


# --- Internal ------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from sock or raise ConnectionError."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise ConnectionError(
                f"peer closed after {n - remaining} of {n} expected bytes"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
