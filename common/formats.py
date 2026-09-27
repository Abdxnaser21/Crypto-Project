from __future__ import annotations
from dataclasses import dataclass

# Magic bytes let the parser reject a file that doesn't belong to us
# before any crypto runs. Cheap sanity guard.
MAGIC_DOC   = b"SVD1"
MAGIC_SHARE = b"SVS1"

# Fixed sizes from §7.6.
DOC_ID_LEN     = 16
NONCE_LEN      = 12
TAG_LEN        = 16
DOC_HASH_LEN   = 32
EPH_PUB_LEN    = 65    # uncompressed SEC1 P-256 point
WRAPPED_FK_LEN = 32    # a 32-byte file key encrypted with GCM => 32-byte ct
SIG_LEN        = 64    # ECDSA fixed-length (r||s), see ecdsa.py

# Reasonable safety limits so a malicious server can't make us allocate
# gigabytes by claiming an absurd string length. Tune if your username
# policy differs — 128 chars is plenty for usernames and filenames.
MAX_STR_LEN     = 4096
MAX_CONTENT_LEN = (1 << 36) - 32   # matches GCM's 64 GiB cap


# --- Low-level primitives -------------------------------------------------

def _pack_u16(x: int) -> bytes:
    if not (0 <= x <= 0xFFFF):
        raise ValueError(f"u16 out of range: {x}")
    return x.to_bytes(2, "big")


def _pack_u32(x: int) -> bytes:
    if not (0 <= x <= 0xFFFFFFFF):
        raise ValueError(f"u32 out of range: {x}")
    return x.to_bytes(4, "big")


def _pack_u64(x: int) -> bytes:
    if not (0 <= x <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f"u64 out of range: {x}")
    return x.to_bytes(8, "big")


def _pack_str(s: str) -> bytes:
    """u16 length || UTF-8 bytes."""
    if not isinstance(s, str):
        raise TypeError("expected str")
    encoded = s.encode("utf-8")
    if len(encoded) > MAX_STR_LEN:
        raise ValueError(f"string too long: {len(encoded)} > {MAX_STR_LEN}")
    return _pack_u16(len(encoded)) + encoded


# --- Streaming reader ----------------------------------------------------
# Trying to parse everything with slice arithmetic is error-prone; a small
# cursor object is much cleaner and matches how real parsers are written.

class _Reader:
    """Bounded byte reader with clear error messages on underflow."""
    __slots__ = ("buf", "pos")

    def __init__(self, data: bytes) -> None:
        self.buf = memoryview(data)
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ValueError(f"format truncated at offset {self.pos} (wanted {n} bytes)")
        chunk = bytes(self.buf[self.pos : self.pos + n])
        self.pos += n
        return chunk

    def read_u16(self) -> int: return int.from_bytes(self.read(2), "big")
    def read_u32(self) -> int: return int.from_bytes(self.read(4), "big")
    def read_u64(self) -> int: return int.from_bytes(self.read(8), "big")

    def read_str(self) -> str:
        n = self.read_u16()
        if n > MAX_STR_LEN:
            raise ValueError(f"string length {n} exceeds cap {MAX_STR_LEN}")
        return self.read(n).decode("utf-8")

    def remaining(self) -> int:
        return len(self.buf) - self.pos

    def assert_done(self, what: str) -> None:
        if self.remaining() != 0:
            raise ValueError(f"trailing {self.remaining()} bytes after {what}")


# ==========================================================================
# Document (SVD1) — the encrypted file blob stored by the server
# ==========================================================================

@dataclass(frozen=True)
class DocumentHeader:
    """Server-readable part; goes into the GCM AAD."""
    doc_id:     bytes    # 16 bytes
    owner:      str
    version:    int
    created_ms: int

    def __post_init__(self) -> None:
        if len(self.doc_id) != DOC_ID_LEN:
            raise ValueError(f"doc_id must be exactly {DOC_ID_LEN} bytes")


def pack_document_header(hdr: DocumentHeader) -> bytes:
    """
    Build the AAD bytes that go into GCM. Client and server must agree
    on this exact byte string, so both sides compute it the same way.
    """
    return (
        MAGIC_DOC
        + hdr.doc_id
        + _pack_str(hdr.owner)
        + _pack_u32(hdr.version)
        + _pack_u64(hdr.created_ms)
    )


def pack_document(hdr: DocumentHeader,
                  nonce: bytes,
                  ciphertext: bytes,
                  tag: bytes) -> bytes:
    """
    Build the full SVD1 blob: header || nonce || ciphertext || tag.

    The caller has already run gcm.encrypt(FK, nonce, plaintext,
    aad=pack_document_header(hdr)) to get (ciphertext, tag).
    """
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    if len(tag) != TAG_LEN:
        raise ValueError(f"tag must be {TAG_LEN} bytes")
    return pack_document_header(hdr) + nonce + ciphertext + tag


@dataclass(frozen=True)
class ParsedDocument:
    header:     DocumentHeader
    header_aad: bytes           # exact bytes to feed as AAD when decrypting
    nonce:      bytes
    ciphertext: bytes
    tag:        bytes


def unpack_document(blob: bytes) -> ParsedDocument:
    r = _Reader(blob)
    start = r.pos
    magic = r.read(4)
    if magic != MAGIC_DOC:
        raise ValueError(f"not a SecureVault document (magic={magic!r})")
    doc_id     = r.read(DOC_ID_LEN)
    owner      = r.read_str()
    version    = r.read_u32()
    created_ms = r.read_u64()
    hdr_end = r.pos
    header_aad = bytes(r.buf[start:hdr_end])

    nonce = r.read(NONCE_LEN)
    remaining = r.remaining() - TAG_LEN
    if remaining < 0:
        raise ValueError("document truncated: missing ciphertext or tag")
    ciphertext = r.read(remaining)
    tag = r.read(TAG_LEN)
    r.assert_done("document")

    return ParsedDocument(
        header=DocumentHeader(doc_id=doc_id, owner=owner,
                              version=version, created_ms=created_ms),
        header_aad=header_aad,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )


# --- Inner encrypted payload ---------------------------------------------
# What sits INSIDE the ciphertext once decrypted:
#   filename(str) || mime(str) || content(u32-len + bytes) || content_sig(64)

def pack_payload(filename: str,
                 mime: str,
                 content: bytes,
                 content_sig: bytes) -> bytes:
    """Build the plaintext blob that goes through gcm.encrypt."""
    if len(content) > MAX_CONTENT_LEN:
        raise ValueError("content too large")
    if len(content_sig) != SIG_LEN:
        raise ValueError(f"content_sig must be {SIG_LEN} bytes")
    return (
        _pack_str(filename)
        + _pack_str(mime)
        + _pack_u32(len(content)) + content
        + content_sig
    )


@dataclass(frozen=True)
class ParsedPayload:
    filename:    str
    mime:        str
    content:     bytes
    content_sig: bytes


def unpack_payload(blob: bytes) -> ParsedPayload:
    r = _Reader(blob)
    filename = r.read_str()
    mime     = r.read_str()
    content_len = r.read_u32()
    if content_len > MAX_CONTENT_LEN:
        raise ValueError("content length cap exceeded")
    content = r.read(content_len)
    content_sig = r.read(SIG_LEN)
    r.assert_done("payload")
    return ParsedPayload(filename=filename, mime=mime,
                         content=content, content_sig=content_sig)


# ==========================================================================
# Share (SVS1) — sent from sender to recipient (via the server)
# ==========================================================================

@dataclass(frozen=True)
class Share:
    """A share record. The `share_sig` covers everything else in the record
    (via pack_share_body), giving non-repudiation of the whole transfer."""
    doc_id:      bytes    # 16 bytes
    version:     int
    doc_hash:    bytes    # SHA-256 of the document's ciphertext (32 bytes)
    sender:      str
    recipient:   str
    issued_ms:   int
    eph_pub:     bytes    # 65 bytes
    nonce:       bytes    # 12 bytes
    wrapped_fk:  bytes    # 32 bytes (GCM ciphertext of FK)
    tag:         bytes    # 16 bytes (GCM tag for wrapped_fk)
    share_sig:   bytes    # 64 bytes (ECDSA signature over everything above)


def pack_share_body(s: Share) -> bytes:
    if len(s.doc_id) != DOC_ID_LEN:
        raise ValueError("doc_id length")
    if len(s.doc_hash) != DOC_HASH_LEN:
        raise ValueError("doc_hash length")
    if len(s.eph_pub) != EPH_PUB_LEN:
        raise ValueError("eph_pub length")
    if len(s.nonce) != NONCE_LEN:
        raise ValueError("nonce length")
    if len(s.wrapped_fk) != WRAPPED_FK_LEN:
        raise ValueError("wrapped_fk length")
    if len(s.tag) != TAG_LEN:
        raise ValueError("tag length")
    return (
        MAGIC_SHARE
        + s.doc_id
        + _pack_u32(s.version)
        + s.doc_hash
        + _pack_str(s.sender)
        + _pack_str(s.recipient)
        + _pack_u64(s.issued_ms)
        + s.eph_pub
        + s.nonce
        + s.wrapped_fk
        + s.tag
    )


def pack_share(s: Share) -> bytes:
    """Full share: body || share_sig."""
    if len(s.share_sig) != SIG_LEN:
        raise ValueError(f"share_sig must be {SIG_LEN} bytes")
    return pack_share_body(s) + s.share_sig


def unpack_share(blob: bytes) -> Share:
    r = _Reader(blob)
    magic = r.read(4)
    if magic != MAGIC_SHARE:
        raise ValueError(f"not a SecureVault share (magic={magic!r})")
    doc_id      = r.read(DOC_ID_LEN)
    version     = r.read_u32()
    doc_hash    = r.read(DOC_HASH_LEN)
    sender      = r.read_str()
    recipient   = r.read_str()
    issued_ms   = r.read_u64()
    eph_pub     = r.read(EPH_PUB_LEN)
    nonce       = r.read(NONCE_LEN)
    wrapped_fk  = r.read(WRAPPED_FK_LEN)
    tag         = r.read(TAG_LEN)
    share_sig   = r.read(SIG_LEN)
    r.assert_done("share")
    return Share(
        doc_id=doc_id, version=version, doc_hash=doc_hash,
        sender=sender, recipient=recipient, issued_ms=issued_ms,
        eph_pub=eph_pub, nonce=nonce, wrapped_fk=wrapped_fk,
        tag=tag, share_sig=share_sig,
    )
