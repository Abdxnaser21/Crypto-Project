import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from common.formats import (                                             # noqa: E402
    DocumentHeader, Share,
    pack_document_header, pack_document, unpack_document,
    pack_payload, unpack_payload,
    pack_share_body, pack_share, unpack_share,
    MAGIC_DOC, MAGIC_SHARE,
    NONCE_LEN, TAG_LEN, DOC_ID_LEN, DOC_HASH_LEN,
    EPH_PUB_LEN, WRAPPED_FK_LEN, SIG_LEN, MAX_STR_LEN,
)
from crypto.gcm import encrypt, decrypt                                  # noqa: E402
from crypto.sha256 import sha256                                          # noqa: E402
from crypto.ecdh import generate_keypair as ecdh_keypair, shared_key      # noqa: E402
from crypto.ecdsa import generate_keypair as ecdsa_keypair, sign, verify, signature_to_bytes  # noqa: E402


# ---------- Document header + document ----------------------------------

class TestDocument(unittest.TestCase):
    def setUp(self) -> None:
        self.hdr = DocumentHeader(
            doc_id=b"\x11" * DOC_ID_LEN,
            owner="layla",
            version=1,
            created_ms=1_700_000_000_000,
        )

    def test_header_roundtrip_deterministic(self) -> None:
        # Same header -> same bytes, always. This matters because both
        # sender and receiver must compute the exact same AAD.
        self.assertEqual(pack_document_header(self.hdr),
                         pack_document_header(self.hdr))

    def test_document_roundtrip(self) -> None:
        nonce = b"\x00" * NONCE_LEN
        ct = b"encrypted-bytes-here"
        tag = b"\xAB" * TAG_LEN
        blob = pack_document(self.hdr, nonce, ct, tag)
        parsed = unpack_document(blob)
        self.assertEqual(parsed.header, self.hdr)
        self.assertEqual(parsed.nonce, nonce)
        self.assertEqual(parsed.ciphertext, ct)
        self.assertEqual(parsed.tag, tag)
        # The AAD returned by unpack must equal what pack produced.
        self.assertEqual(parsed.header_aad, pack_document_header(self.hdr))

    def test_wrong_magic_rejected(self) -> None:
        good = pack_document(self.hdr, b"\x00" * NONCE_LEN, b"x", b"\x00" * TAG_LEN)
        bad = b"XXXX" + good[4:]
        with self.assertRaises(ValueError):
            unpack_document(bad)

    def test_truncated_rejected(self) -> None:
        # Truncate to inside the header - the parser must refuse before
        # even reaching the ciphertext.
        good = pack_document(self.hdr, b"\x00" * NONCE_LEN, b"content", b"\x00" * TAG_LEN)
        with self.assertRaises(ValueError):
            unpack_document(good[:6])   # magic(4) + 2 bytes of doc_id, then stops

    def test_bad_doc_id_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DocumentHeader(doc_id=b"short", owner="x", version=1, created_ms=0)

    def test_string_length_cap_enforced(self) -> None:
        # Owner name longer than MAX_STR_LEN must be refused at pack time.
        too_long = "a" * (MAX_STR_LEN + 1)
        with self.assertRaises(ValueError):
            pack_document_header(DocumentHeader(
                doc_id=b"\x00" * DOC_ID_LEN, owner=too_long,
                version=1, created_ms=0,
            ))


# ---------- Inner encrypted payload ------------------------------------

class TestPayload(unittest.TestCase):
    def test_payload_roundtrip(self) -> None:
        blob = pack_payload("thesis.pdf", "application/pdf",
                            b"file contents", b"\x00" * SIG_LEN)
        p = unpack_payload(blob)
        self.assertEqual(p.filename, "thesis.pdf")
        self.assertEqual(p.mime, "application/pdf")
        self.assertEqual(p.content, b"file contents")
        self.assertEqual(p.content_sig, b"\x00" * SIG_LEN)

    def test_payload_wrong_sig_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            pack_payload("f", "m", b"x", b"\x00" * 10)


# ---------- Share ------------------------------------------------------

class TestShare(unittest.TestCase):
    def _fake_share(self, **overrides) -> Share:
        base = dict(
            doc_id=b"\x22" * DOC_ID_LEN,
            version=3,
            doc_hash=b"\x33" * DOC_HASH_LEN,
            sender="layla",
            recipient="omar",
            issued_ms=1_700_000_500_000,
            eph_pub=b"\x04" + b"\x44" * 64,   # 65 bytes
            nonce=b"\x55" * NONCE_LEN,
            wrapped_fk=b"\x66" * WRAPPED_FK_LEN,
            tag=b"\x77" * TAG_LEN,
            share_sig=b"\x88" * SIG_LEN,
        )
        base.update(overrides)
        return Share(**base)

    def test_share_roundtrip(self) -> None:
        s = self._fake_share()
        parsed = unpack_share(pack_share(s))
        self.assertEqual(parsed, s)

    def test_share_body_excludes_sig(self) -> None:
        s = self._fake_share()
        body = pack_share_body(s)
        full = pack_share(s)
        self.assertEqual(full, body + s.share_sig)

    def test_share_wrong_magic_rejected(self) -> None:
        blob = pack_share(self._fake_share())
        with self.assertRaises(ValueError):
            unpack_share(b"YYYY" + blob[4:])

    def test_share_wrong_field_length_rejected(self) -> None:
        # A doc_hash of wrong length is caught at pack time.
        with self.assertRaises(ValueError):
            pack_share_body(self._fake_share(doc_hash=b"tooshort"))


# ---------- Full flow: pack + encrypt + unpack + decrypt --------------

class TestFullFlow(unittest.TestCase):
    """
    This is the moneyshot: we pack a real document, encrypt it with GCM,
    unpack it, decrypt it, and check we get the exact plaintext back.
    Also verifies that ANY tamper (metadata OR ciphertext) is rejected.
    """

    def test_full_upload_download_roundtrip(self) -> None:
        # --- Sender side ---
        FK = os.urandom(32)
        content = b"Hello Omar, here is my thesis draft.\n" * 10
        author_priv, author_pub = ecdsa_keypair()

        # 1. Sign the file content (author proof, §7.5)
        content_sig = signature_to_bytes(sign(author_priv, sha256(content)))

        # 2. Build inner payload and encrypt with FK
        payload = pack_payload("thesis.txt", "text/plain", content, content_sig)
        hdr = DocumentHeader(
            doc_id=os.urandom(DOC_ID_LEN),
            owner="layla",
            version=1,
            created_ms=1_700_000_000_000,
        )
        aad = pack_document_header(hdr)
        ct, tag = encrypt(FK, b"\x00" * NONCE_LEN, payload, aad)

        # 3. Pack the SVD1 blob for storage
        blob = pack_document(hdr, b"\x00" * NONCE_LEN, ct, tag)

        # --- Recipient side ---
        # 4. Unpack
        p = unpack_document(blob)
        # 5. Decrypt with GCM (checks tag first per §7.2)
        pt = decrypt(FK, p.nonce, p.ciphertext, p.tag, p.header_aad)
        self.assertIsNotNone(pt)
        # 6. Parse inner payload
        inner = unpack_payload(pt)
        # 7. Verify author signature over the file content
        from crypto.ecdsa import signature_from_bytes
        self.assertTrue(verify(author_pub, sha256(inner.content),
                               signature_from_bytes(inner.content_sig)))
        # 8. Content matches
        self.assertEqual(inner.content, content)
        self.assertEqual(inner.filename, "thesis.txt")

    def test_metadata_tamper_rejected_by_gcm(self) -> None:
        """Server changes owner from 'layla' to 'omar__' -> GCM rejects."""
        FK = os.urandom(32)
        content = b"secret"
        hdr = DocumentHeader(doc_id=os.urandom(DOC_ID_LEN), owner="layla",
                             version=1, created_ms=0)
        aad = pack_document_header(hdr)
        ct, tag = encrypt(FK, b"\x00" * NONCE_LEN, content, aad)
        blob = pack_document(hdr, b"\x00" * NONCE_LEN, ct, tag)

        # Attacker (server) unpacks, changes the owner, repacks.
        p = unpack_document(blob)
        forged_hdr = DocumentHeader(
            doc_id=p.header.doc_id, owner="omar__",
            version=p.header.version, created_ms=p.header.created_ms,
        )
        forged_blob = pack_document(forged_hdr, p.nonce, p.ciphertext, p.tag)
        p2 = unpack_document(forged_blob)

        # Recipient tries to decrypt -> tag fails because AAD differs.
        self.assertIsNone(
            decrypt(FK, p2.nonce, p2.ciphertext, p2.tag, p2.header_aad)
        )

    def test_ciphertext_tamper_rejected_by_gcm(self) -> None:
        FK = os.urandom(32)
        hdr = DocumentHeader(doc_id=os.urandom(DOC_ID_LEN), owner="layla",
                             version=1, created_ms=0)
        aad = pack_document_header(hdr)
        ct, tag = encrypt(FK, b"\x00" * NONCE_LEN, b"real secret", aad)
        blob = pack_document(hdr, b"\x00" * NONCE_LEN, ct, tag)

        # Flip a single byte in the ciphertext region.
        bad = bytearray(blob)
        # ct sits after header + nonce, before tag.
        ct_offset = len(aad) + NONCE_LEN
        bad[ct_offset] ^= 0x01

        p = unpack_document(bytes(bad))
        self.assertIsNone(
            decrypt(FK, p.nonce, p.ciphertext, p.tag, p.header_aad)
        )


# ---------- Share end-to-end: two users, ECDH-wrap, sign, verify ------

class TestShareFullFlow(unittest.TestCase):
    def test_layla_shares_with_omar(self) -> None:
        # Setup: two users, each with one DH pair and one signing pair.
        _, layla_dh_pub  = ecdh_keypair()   # not used here — sender uses ephemeral
        omar_dh_priv, omar_dh_pub = ecdh_keypair()
        layla_sig_priv, layla_sig_pub = ecdsa_keypair()

        # Layla has already uploaded a document with file key FK.
        FK = os.urandom(32)
        doc_id = os.urandom(DOC_ID_LEN)
        doc_hash = sha256(b"ciphertext of the doc goes here")
        version = 7
        issued_ms = 1_700_000_999_000

        # Layla builds the share:
        # 1. Fresh ephemeral ECDH key
        eph_priv, eph_pub = ecdh_keypair()
        # 2. Bind wrap key to (doc_id, sender, recipient) via info string
        info = b"wrap|doc_id=" + doc_id + b"|to=omar|from=layla"
        wrap_key = shared_key(eph_priv, omar_dh_pub, info=info)
        # 3. Wrap FK with GCM (single-use key -> zero nonce, per §7.2)
        wrapped_fk, w_tag = encrypt(wrap_key, b"\x00" * NONCE_LEN, FK, aad=b"")
        # 4. Build unsigned share body and sign it
        unsigned = Share(
            doc_id=doc_id, version=version, doc_hash=doc_hash,
            sender="layla", recipient="omar", issued_ms=issued_ms,
            eph_pub=eph_pub, nonce=b"\x00" * NONCE_LEN,
            wrapped_fk=wrapped_fk, tag=w_tag,
            share_sig=b"\x00" * SIG_LEN,           # placeholder
        )
        body = pack_share_body(unsigned)
        share_sig = signature_to_bytes(sign(layla_sig_priv, body))
        # Replace with real signature
        final = Share(**{**unsigned.__dict__, "share_sig": share_sig})

        # Send over the wire (packed bytes)
        blob = pack_share(final)

        # ---- Omar receives ----
        received = unpack_share(blob)

        # a) Verify the signature over the body (non-repudiation)
        from crypto.ecdsa import signature_from_bytes
        body_recv = pack_share_body(Share(
            **{**received.__dict__, "share_sig": b"\x00" * SIG_LEN}
        ))
        self.assertTrue(verify(layla_sig_pub, body_recv,
                               signature_from_bytes(received.share_sig)))

        # b) Recompute the wrap key using his DH private and the ephemeral pub
        omar_wrap = shared_key(omar_dh_priv, received.eph_pub, info=info)
        # c) Decrypt to recover FK
        recovered_FK = decrypt(omar_wrap, received.nonce,
                               received.wrapped_fk, received.tag, aad=b"")
        self.assertEqual(recovered_FK, FK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
