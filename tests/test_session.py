"""
Session tests.
"""

import base64
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.ecdsa import generate_keypair, sign, signature_to_bytes           # noqa: E402
from server.session import (                                                    # noqa: E402
    SessionState,
    payload_upload, payload_share, payload_download, payload_change_password,
)


class TestChallenges(unittest.TestCase):
    def setUp(self) -> None:
        self.s = SessionState()

    def test_issue_and_consume(self) -> None:
        c = self.s.issue_challenge("layla")
        self.assertEqual(len(c), 32)
        got = self.s.consume_challenge("layla")
        self.assertEqual(got, c)

    def test_consume_is_one_shot(self) -> None:
        self.s.issue_challenge("layla")
        self.s.consume_challenge("layla")
        self.assertIsNone(self.s.consume_challenge("layla"))

    def test_no_challenge_for_user(self) -> None:
        self.assertIsNone(self.s.consume_challenge("ghost"))

    def test_expired_challenge_rejected(self) -> None:
        s = SessionState(challenge_ttl_seconds=0)  # instant expiry
        s.issue_challenge("layla")
        time.sleep(0.01)
        self.assertIsNone(s.consume_challenge("layla"))


class TestNonces(unittest.TestCase):
    def setUp(self) -> None:
        self.s = SessionState()

    def test_first_use_accepted(self) -> None:
        n = base64.b64encode(os.urandom(16)).decode()
        self.assertTrue(self.s.check_and_consume_nonce(n))

    def test_replay_rejected(self) -> None:
        n = base64.b64encode(os.urandom(16)).decode()
        self.assertTrue(self.s.check_and_consume_nonce(n))
        self.assertFalse(self.s.check_and_consume_nonce(n))

    def test_empty_or_bad_type_rejected(self) -> None:
        self.assertFalse(self.s.check_and_consume_nonce(""))
        self.assertFalse(self.s.check_and_consume_nonce(None))       # type: ignore[arg-type]
        self.assertFalse(self.s.check_and_consume_nonce(b"bytes"))   # type: ignore[arg-type]

    def test_count_grows(self) -> None:
        self.assertEqual(self.s.nonce_count(), 0)
        for _ in range(5):
            self.s.check_and_consume_nonce(base64.b64encode(os.urandom(16)).decode())
        self.assertEqual(self.s.nonce_count(), 5)


class TestRequestSignature(unittest.TestCase):
    def setUp(self) -> None:
        self.priv, self.pub = generate_keypair()
        self.nonce = base64.b64encode(os.urandom(16)).decode()

    def test_valid_upload_signature_accepted(self) -> None:
        payload = payload_upload("layla", self.nonce)
        sig = signature_to_bytes(sign(self.priv, payload.encode()))
        self.assertTrue(SessionState.verify_request_signature(self.pub, payload, sig))

    def test_tampered_payload_rejected(self) -> None:
        payload = payload_upload("layla", self.nonce)
        sig = signature_to_bytes(sign(self.priv, payload.encode()))
        tampered = payload_upload("omar", self.nonce)  # different owner
        self.assertFalse(SessionState.verify_request_signature(self.pub, tampered, sig))

    def test_wrong_pubkey_rejected(self) -> None:
        _, wrong_pub = generate_keypair()
        payload = payload_download("layla", "abc123", self.nonce)
        sig = signature_to_bytes(sign(self.priv, payload.encode()))
        self.assertFalse(SessionState.verify_request_signature(wrong_pub, payload, sig))

    def test_malformed_signature_rejected(self) -> None:
        payload = payload_upload("layla", self.nonce)
        self.assertFalse(SessionState.verify_request_signature(self.pub, payload, b"short"))
        self.assertFalse(SessionState.verify_request_signature(self.pub, payload, b""))


class TestCanonicalPayloads(unittest.TestCase):
    def test_upload_format(self) -> None:
        self.assertEqual(payload_upload("layla", "N1"), "upload:layla:N1")

    def test_share_format(self) -> None:
        self.assertEqual(payload_share("layla", "abc", "omar", "N1"),
                         "share:layla:abc:omar:N1")

    def test_download_format(self) -> None:
        self.assertEqual(payload_download("layla", "abc", "N1"),
                         "download:layla:abc:N1")

    def test_change_password_format(self) -> None:
        self.assertEqual(payload_change_password("layla", "N1"),
                         "change_password:layla:N1")

    def test_payloads_are_distinct_across_actions(self) -> None:
        n = "SAME_NONCE"
        p1 = payload_upload("layla", n)
        p2 = payload_download("layla", "abc", n)
        self.assertNotEqual(p1, p2)  # cross-action replay must not verify


if __name__ == "__main__":
    unittest.main(verbosity=2)
