"""
SecureVault interactive CLI.

Menu-driven front end for demos. Same operations as the class in
client.py, wired up to input()/print(). Every action prints the
outcome and any relevant identifiers (doc_id, fingerprint, etc.).

"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from client.client import SecureVaultClient, ClientError
from client.trust_store import format_fingerprint


def _tofu_prompt(username: str, fingerprint: str) -> bool:
    """First-contact prompt: show fingerprint, ask user to accept."""
    print()
    print(f"  ┌─ FIRST CONTACT with '{username}' " + "─" * (40 - len(username)))
    print(f"  │ Compare this fingerprint out-of-band (call, in person):")
    print(f"  │")
    for line in format_fingerprint(fingerprint).split("\n"):
        print(f"  │    {line}")
    print(f"  └─" + "─" * 60)
    answer = input("  Trust this key? [y/N]: ").strip().lower()
    return answer == "y"


def _prompt_password(label: str = "Password") -> str:
    """getpass hides the input; falls back to visible input on failure."""
    try:
        return getpass.getpass(f"{label}: ")
    except Exception:
        return input(f"{label} (visible): ")


def _op_signup(client: SecureVaultClient) -> None:
    username = input("Choose username: ").strip()
    password = _prompt_password("Choose password")
    try:
        print("[*] Deriving keys with Argon2id (this takes ~0.2s)...")
        client.signup(username, password)
        print(f"[+] Account '{username}' created.")
    except ClientError as e:
        print(f"[-] Signup failed: {e}")


def _op_login(client: SecureVaultClient) -> None:
    username = input("Username: ").strip()
    password = _prompt_password()
    try:
        print("[*] Deriving keys with Argon2id...")
        client.login(username, password)
        print(f"[+] Logged in as '{username}'.")
    except ClientError as e:
        print(f"[-] Login failed: {e}")


def _op_logout(client: SecureVaultClient) -> None:
    if client.username is None:
        print("[-] Not logged in.")
        return
    who = client.username
    client.logout()
    print(f"[+] Logged out '{who}'.")


def _op_upload(client: SecureVaultClient) -> None:
    if client.username is None:
        print("[-] Please login first.")
        return
    path = input("File path to upload: ").strip()
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        return
    try:
        doc_id = client.upload(path)
        print(f"[+] Uploaded. doc_id = {doc_id}")
        print("    (share or download using this id, not the filename)")
    except ClientError as e:
        print(f"[-] Upload failed: {e}")


def _op_share(client: SecureVaultClient) -> None:
    if client.username is None:
        print("[-] Please login first.")
        return
    doc_id = input("Document ID: ").strip()
    recipient = input("Recipient username: ").strip()
    try:
        client.share(doc_id, recipient)
        print(f"[+] Shared with '{recipient}'.")
    except ClientError as e:
        print(f"[-] Share failed: {e}")


def _op_download(client: SecureVaultClient) -> None:
    if client.username is None:
        print("[-] Please login first.")
        return
    doc_id = input("Document ID: ").strip()
    save_path = input("Save to (path): ").strip()
    try:
        sender = client.download(doc_id, save_path)
        print(f"[+] Downloaded and verified. Sender = '{sender}'.")
        print(f"    Saved to {save_path}")
    except ClientError as e:
        print(f"[-] Download failed: {e}")


def _op_change_password(client: SecureVaultClient) -> None:
    if client.username is None:
        print("[-] Please login first.")
        return
    old_pw = _prompt_password("Current password")
    new_pw = _prompt_password("New password")
    confirm = _prompt_password("Confirm new password")
    if new_pw != confirm:
        print("[-] New passwords don't match.")
        return
    try:
        client.change_password(old_pw, new_pw)
        print("[+] Password changed.")
    except ClientError as e:
        print(f"[-] Change failed: {e}")


def _op_verify_contact(client: SecureVaultClient) -> None:
    if client.username is None or client.trust is None:
        print("[-] Please login first.")
        return
    entries = client.trust.all_entries()
    if not entries:
        print("[-] No contacts yet — download or share something first.")
        return
    print()
    print("  Known contacts:")
    for name, entry in entries.items():
        fp_short = entry.fingerprint[:16]
        print(f"    - {name:<20} [{entry.status.value:<10}] {fp_short}...")
    print()
    name = input("Contact to mark VERIFIED (after out-of-band check): ").strip()
    if name not in entries:
        print(f"[-] No such contact: {name}")
        return
    try:
        client.mark_contact_verified(name)
        print(f"[+] '{name}' marked VERIFIED.")
    except Exception as e:
        print(f"[-] {e}")


def _op_list_contacts(client: SecureVaultClient) -> None:
    if client.username is None or client.trust is None:
        print("[-] Please login first.")
        return
    entries = client.trust.all_entries()
    if not entries:
        print("[-] No contacts yet.")
        return
    print()
    print(f"  Contacts of {client.username}:")
    for name, entry in entries.items():
        print(f"    - {name:<20} [{entry.status.value}]")
        print(f"      fingerprint: {entry.fingerprint}")


MENU = [
    ("Register (Sign Up)",       _op_signup),
    ("Login",                     _op_login),
    ("Logout",                    _op_logout),
    ("Upload Document",           _op_upload),
    ("Share Document",            _op_share),
    ("Download & Verify",         _op_download),
    ("Change Password",           _op_change_password),
    ("Verify a Contact's Key",    _op_verify_contact),
    ("List Contacts",             _op_list_contacts),
]


def _print_menu(client: SecureVaultClient) -> None:
    print()
    print("=" * 40)
    who = client.username if client.username else "not logged in"
    print(f"  SecureVault CLI  ─  [{who}]")
    print("=" * 40)
    for i, (label, _) in enumerate(MENU, start=1):
        print(f"  {i}. {label}")
    print(f"  0. Exit")


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureVault interactive CLI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--storage-dir", default=".",
                        help="where keystores and trust files go")
    args = parser.parse_args()

    client = SecureVaultClient(host=args.host, port=args.port,
                               storage_dir=args.storage_dir,
                               tofu_prompt=_tofu_prompt)

    print(f"[*] Connecting to {args.host}:{args.port}")
    while True:
        _print_menu(client)
        choice = input("Choose: ").strip()
        if choice == "0" or choice.lower() in ("q", "quit", "exit"):
            print("Goodbye.")
            return 0
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(MENU)):
                raise ValueError
        except ValueError:
            print("[-] Invalid choice.")
            continue
        _, handler = MENU[idx]
        try:
            handler(client)
        except KeyboardInterrupt:
            print("\n[-] Cancelled.")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")


if __name__ == "__main__":
    sys.exit(main())
