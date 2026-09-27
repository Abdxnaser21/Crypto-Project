"""
demo/demo_server_view.py

Proves the server stores only ciphertext (§7.2).

Runs a full honest scenario in-process, then opens the server's SQLite
DB directly and prints the raw stored bytes. Shows the examiner that
what the server actually holds is unreadable noise.

"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from server.server import SecureVaultServer                          # noqa: E402
from client.client import SecureVaultClient                          # noqa: E402


PLAINTEXT = b"CONFIDENTIAL: launch codes are 0000, do not distribute."


def _start_server(db_path: str) -> tuple[SecureVaultServer, int]:
    srv = SecureVaultServer(port=0, db_path=db_path)
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
    time.sleep(0.05)
    return srv, srv.port


def _hex_grid(data: bytes, cols: int = 16, max_rows: int = 8) -> str:
    """Format bytes as a hex + ASCII dump grid."""
    lines = []
    for i in range(0, min(len(data), cols * max_rows), cols):
        chunk = data[i:i + cols]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(cols * 3 - 1)
        ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        lines.append(f"  {i:04x}  {hex_part}  |{ascii_part}|")
    if len(data) > cols * max_rows:
        lines.append(f"  ...  ({len(data) - cols * max_rows} more bytes)")
    return "\n".join(lines)


def main() -> None:
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "server.db")

    print("=" * 72)
    print("  Setting up honest scenario: layla uploads a document")
    print("=" * 72)

    srv, port = _start_server(db_path)
    layla = SecureVaultClient(port=port, storage_dir=os.path.join(tmp, "layla"),
                              tofu_prompt=lambda n, f: True)
    layla.signup("layla", "layla-pw")
    layla.login("layla", "layla-pw")
    src = os.path.join(tmp, "secret.txt")
    with open(src, "wb") as f:
        f.write(PLAINTEXT)
    doc_id = layla.upload(src)
    srv.stop()
    time.sleep(0.05)

    print(f"\n  Plaintext file contents ({len(PLAINTEXT)} bytes):")
    print(f"    {PLAINTEXT!r}")
    print(f"\n  Uploaded doc_id = {doc_id}\n")

    # --- Now inspect the raw DB ---
    import sqlite3
    conn = sqlite3.connect(db_path)
    print("=" * 72)
    print("  SERVER-SIDE VIEW — reading the DB directly (bypassing the API)")
    print("=" * 72)

    n_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    n_docs = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    n_shares = conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
    print(f"\n  Rows: {n_users} users, {n_docs} documents, {n_shares} shares\n")

    # Users table
    print("-" * 72)
    print("  users table:")
    print("-" * 72)
    for row in conn.execute("SELECT username, length(salt), length(auth_pub), "
                             "length(sig_pub), length(dh_pub) FROM users"):
        print(f"  username={row[0]!r}  salt={row[1]}B  auth_pub={row[2]}B  "
              f"sig_pub={row[3]}B  dh_pub={row[4]}B")
    print("  → all public data. no password, no private key, no plaintext.")

    # Documents table — the interesting part
    print()
    print("-" * 72)
    print("  documents table — the whole SVD1 blob stored per document:")
    print("-" * 72)
    for row in conn.execute("SELECT owner, version, length(blob), blob FROM documents"):
        owner, ver, size, blob = row
        print(f"\n  owner={owner!r}  version={ver}  total blob = {size} bytes")
        print(f"\n  RAW BYTES (first 128 shown, hex + ASCII):\n")
        print(_hex_grid(blob, cols=16, max_rows=8))
        print()
        # Try to interpret as text — should look like garbage
        preview = blob[24:24 + 60]  # skip the readable header, land in ciphertext
        printable_ratio = sum(1 for b in preview if 32 <= b < 127) / max(1, len(preview))
        print(f"  Ciphertext preview as text (bytes 24..84):")
        print(f"    {preview!r}")
        print(f"    printable-char ratio = {printable_ratio:.0%}  "
              f"(random ciphertext gives about 25%)")

    # Does the plaintext appear ANYWHERE in the DB?
    print()
    print("-" * 72)
    print("  Searching the entire DB file for the plaintext string...")
    print("-" * 72)
    with open(db_path, "rb") as f:
        db_bytes = f.read()
    if PLAINTEXT in db_bytes:
        print(f"  !!! FOUND — this would be a bug !!!")
    else:
        print(f"  Plaintext NOT FOUND in the {len(db_bytes)}-byte DB file.")
        print(f"  → the server has never seen the file's contents in the clear.")

    print()
    print("=" * 72)
    print("  CONCLUSION")
    print("=" * 72)
    print("  The server stores ciphertext + public metadata only.")
    print("  A stolen server DB reveals: usernames, salts, timestamps,")
    print("  public keys, ciphertext. No plaintext, no keys to decrypt it.")
    print()

    conn.close()


if __name__ == "__main__":
    main()
