"""
End-to-end tests.

Spins up the real server on a random port and drives it with real
clients over real TCP sockets. This is the integration test that
proves the whole stack works together — from crypto primitives all
the way up to user-facing operations.

Each test uses a fresh temp directory for keystores and trust files,
and a fresh :memory: SQLite database, so tests don't interfere.
"""

import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from server.server import SecureVaultServer                          # noqa: E402
from client.client import SecureVaultClient, ClientError             # noqa: E402


def _start_server() -> tuple[SecureVaultServer, int]:
    """Bind on a random free port and start accepting in a background thread."""
    srv = SecureVaultServer(port=0, db_path=":memory:")
    srv._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv._listener.bind(("127.0.0.1", 0))
    srv.port = srv._listener.getsockname()[1]
    srv._listener.listen(16)

    def serve() -> None:
        while True:
            try:
                conn, _ = srv._listener.accept()
            except OSError:
                return
            threading.Thread(target=srv._handle_connection,
                             args=(conn, None), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)   # small warmup
    return srv, srv.port


class TestEndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self.srv, self.port = _start_server()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self) -> None:
        self.srv.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _client(self) -> SecureVaultClient:
        # tofu_prompt returns True → auto-accept first contact, like the
        # real CLI default. Real users would compare fingerprints.
        return SecureVaultClient(port=self.port, storage_dir=self.tmp,
                                 tofu_prompt=lambda name, fp: True)

    # ------------- Happy paths -------------

    def test_full_layla_to_omar_flow(self) -> None:
        """The demo scenario: register 2 users, upload, share, download, verify."""
        # Layla
        layla = self._client()
        layla.signup("layla", "layla-strong-password")
        layla.login("layla", "layla-strong-password")

        # Upload
        src = os.path.join(self.tmp, "thesis.txt")
        with open(src, "wb") as f:
            f.write(b"The launch codes are 0000. Do not share.")
        doc_id = layla.upload(src)
        self.assertEqual(len(doc_id), 32)  # 16 bytes hex

        # Omar
        omar = self._client()
        omar.signup("omar", "omar-other-password")
        omar.login("omar", "omar-other-password")

        # Share
        layla.share(doc_id, "omar")

        # Omar downloads and verifies
        out = os.path.join(self.tmp, "omar_copy.txt")
        sender = omar.download(doc_id, out)
        self.assertEqual(sender, "layla")
        with open(out, "rb") as f:
            self.assertEqual(f.read(),
                             b"The launch codes are 0000. Do not share.")

    def test_owner_can_download_own_document(self) -> None:
        """Owner should be able to fetch their own file back after upload."""
        layla = self._client()
        layla.signup("layla", "pw"); layla.login("layla", "pw")
        src = os.path.join(self.tmp, "mine.txt")
        with open(src, "wb") as f:
            f.write(b"private notes")
        doc_id = layla.upload(src)

        out = os.path.join(self.tmp, "mine_back.txt")
        sender = layla.download(doc_id, out)
        self.assertEqual(sender, "layla")
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"private notes")

    def test_login_survives_relogin(self) -> None:
        """Log out, log back in, still have working keys."""
        c = self._client()
        c.signup("mahmoud", "pw"); c.login("mahmoud", "pw")
        c.logout()
        c.login("mahmoud", "pw")
        self.assertEqual(c.username, "mahmoud")

    def test_change_password_then_login_with_new(self) -> None:
        c = self._client()
        c.signup("layla", "old-pw"); c.login("layla", "old-pw")
        c.change_password("old-pw", "new-pw")
        c.logout()
        # Old password must not work anymore
        with self.assertRaises(ClientError):
            c.login("layla", "old-pw")
        # New password does
        c.login("layla", "new-pw")

    def test_change_password_preserves_access_to_old_shares(self) -> None:
        """The identity keys are the same after password change, so
        pre-existing shares to this user still open."""
        layla = self._client()
        layla.signup("layla", "pw"); layla.login("layla", "pw")
        src = os.path.join(self.tmp, "s.txt")
        with open(src, "wb") as f:
            f.write(b"shared before password change")
        doc_id = layla.upload(src)

        omar = self._client()
        omar.signup("omar", "pw2"); omar.login("omar", "pw2")
        layla.share(doc_id, "omar")

        # Omar changes his password
        omar.change_password("pw2", "pw2-new")
        omar.logout()
        omar.login("omar", "pw2-new")

        # Old share still works
        out = os.path.join(self.tmp, "omar_out.txt")
        sender = omar.download(doc_id, out)
        self.assertEqual(sender, "layla")

    def test_share_with_multiple_recipients(self) -> None:
        layla = self._client()
        layla.signup("layla", "pw"); layla.login("layla", "pw")
        src = os.path.join(self.tmp, "team.txt")
        with open(src, "wb") as f:
            f.write(b"team announcement")
        doc_id = layla.upload(src)

        for name in ("omar", "mahmoud", "priya"):
            u = self._client()
            u.signup(name, f"{name}-pw"); u.login(name, f"{name}-pw")

        for name in ("omar", "mahmoud", "priya"):
            layla.share(doc_id, name)

        # Each recipient can download
        for name in ("omar", "mahmoud", "priya"):
            u = self._client()
            u.login(name, f"{name}-pw")
            out = os.path.join(self.tmp, f"{name}_out.txt")
            sender = u.download(doc_id, out)
            self.assertEqual(sender, "layla")

    # ------------- Rejection paths -------------

    def test_wrong_password_rejected(self) -> None:
        c = self._client()
        c.signup("layla", "right-pw")
        with self.assertRaises(ClientError):
            c.login("layla", "wrong-pw")

    def test_unknown_user_login_rejected(self) -> None:
        c = self._client()
        with self.assertRaises(ClientError):
            c.login("nobody", "anything")

    def test_duplicate_signup_rejected(self) -> None:
        c1 = self._client()
        c1.signup("layla", "pw")
        c2 = self._client()
        with self.assertRaises(ClientError):
            c2.signup("layla", "different-pw")

    def test_download_unauthorized_document_rejected(self) -> None:
        """Omar shouldn't be able to download a file Layla never shared with him."""
        layla = self._client()
        layla.signup("layla", "pw"); layla.login("layla", "pw")
        src = os.path.join(self.tmp, "private.txt")
        with open(src, "wb") as f:
            f.write(b"secret from omar")
        doc_id = layla.upload(src)

        omar = self._client()
        omar.signup("omar", "pw"); omar.login("omar", "pw")
        with self.assertRaises(ClientError):
            omar.download(doc_id, os.path.join(self.tmp, "wont_happen.txt"))

    def test_download_nonexistent_document_rejected(self) -> None:
        c = self._client()
        c.signup("layla", "pw"); c.login("layla", "pw")
        with self.assertRaises(ClientError):
            c.download("00" * 16, os.path.join(self.tmp, "nope.txt"))

    def test_share_to_unknown_recipient_rejected(self) -> None:
        c = self._client()
        c.signup("layla", "pw"); c.login("layla", "pw")
        src = os.path.join(self.tmp, "s.txt")
        with open(src, "wb") as f:
            f.write(b"x")
        doc_id = c.upload(src)
        with self.assertRaises(ClientError):
            c.share(doc_id, "ghost")

    def test_operations_before_login_rejected(self) -> None:
        c = self._client()
        with self.assertRaises(ClientError):
            c.upload("/tmp/whatever")
        with self.assertRaises(ClientError):
            c.share("00" * 16, "anyone")
        with self.assertRaises(ClientError):
            c.download("00" * 16, "/tmp/whatever")


if __name__ == "__main__":
    unittest.main(verbosity=2)
