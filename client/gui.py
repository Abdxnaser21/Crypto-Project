"""
SecureVault graphical client.

Tkinter front end over client.SecureVaultClient. No crypto or protocol
logic here — this file is presentation only, so a bug in the UI can't
weaken security.

Three interactions get special treatment because they carry security weight:

  1. TOFU first contact (§7.4) — a modal dialog that BLOCKS the app,
     fingerprint shown in large monospace text made for reading aloud
     over a call. Two explicit buttons instead of an ambiguous "OK".

  2. Security failure — messagebox.showerror steals focus, needs an
     explicit click, and offers NO "proceed anyway" path.

  3. Actions the UI simply won't let you do — no "trust anyway" once a
     key mismatch is detected, no way to save a file that failed to
     verify (the write happens after every check passes), and every
     action tab is unreachable before login.
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from client.client import SecureVaultClient, ClientError
from client.trust_store import format_fingerprint


class SecureVaultGUI(tk.Tk):
    def __init__(self, host: str = "127.0.0.1", port: int = 9999,
                 storage_dir: str = "."):
        super().__init__()
        self.title("SecureVault")
        self.geometry("780x620")
        self.minsize(700, 540)

        self.client = SecureVaultClient(
            host=host, port=port, storage_dir=storage_dir,
            tofu_prompt=self._ask_trust_fingerprint,
        )

        self.login_frame = ttk.Frame(self, padding=24)
        self.main_frame = ttk.Frame(self, padding=14)
        self._build_login()
        self._build_main()
        self._show_login()

    # -------------------- Login screen --------------------

    def _build_login(self) -> None:
        f = self.login_frame
        ttk.Label(f, text="SecureVault",
                  font=("Segoe UI", 22, "bold")).pack(pady=(10, 24))

        form = ttk.Frame(f); form.pack()
        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky="e", pady=6, padx=6)
        self.login_user = ttk.Entry(form, width=32)
        self.login_user.grid(row=0, column=1, pady=6)
        ttk.Label(form, text="Password:").grid(row=1, column=0, sticky="e", pady=6, padx=6)
        self.login_pass = ttk.Entry(form, width=32, show="*")
        self.login_pass.grid(row=1, column=1, pady=6)

        btns = ttk.Frame(f); btns.pack(pady=18)
        ttk.Button(btns, text="Login", command=self._do_login
                   ).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Sign Up", command=self._do_signup
                   ).grid(row=0, column=1, padx=6)

        self.login_status = ttk.Label(
            f, text="", foreground="#b00020",
            wraplength=440, justify="center",
        )
        self.login_status.pack(pady=6)

    # -------------------- Main screen --------------------

    def _build_main(self) -> None:
        f = self.main_frame

        top = ttk.Frame(f); top.pack(fill="x")
        self.welcome_label = ttk.Label(top, text="", font=("Segoe UI", 13, "bold"))
        self.welcome_label.pack(side="left")
        ttk.Button(top, text="Logout", command=self._do_logout).pack(side="right")

        nb = ttk.Notebook(f); nb.pack(fill="both", expand=True, pady=10)

        # --- Upload tab ---
        upload = ttk.Frame(nb, padding=14); nb.add(upload, text="Upload")
        ttk.Button(upload, text="Choose file & upload...",
                   command=self._do_upload).pack(pady=8)
        row = ttk.Frame(upload); row.pack(fill="x", pady=6)
        ttk.Label(row, text="Last uploaded doc ID:").pack(side="left")
        self.last_doc_id_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.last_doc_id_var,
                  state="readonly", width=40).pack(side="left", padx=6)
        ttk.Button(row, text="Copy",
                   command=lambda: self._copy(self.last_doc_id_var.get())
                   ).pack(side="left")

        # --- Share tab ---
        share = ttk.Frame(nb, padding=14); nb.add(share, text="Share")
        ttk.Label(share, text="Document ID:").grid(row=0, column=0, sticky="e", pady=6)
        self.share_doc_id = ttk.Entry(share, width=44)
        self.share_doc_id.grid(row=0, column=1, pady=6)
        ttk.Label(share, text="Recipient username:").grid(row=1, column=0, sticky="e", pady=6)
        self.share_recipient = ttk.Entry(share, width=44)
        self.share_recipient.grid(row=1, column=1, pady=6)
        ttk.Button(share, text="Share", command=self._do_share
                   ).grid(row=2, column=0, columnspan=2, pady=12)

        # --- Download tab ---
        dl = ttk.Frame(nb, padding=14); nb.add(dl, text="Download")
        ttk.Label(dl, text="Document ID:").grid(row=0, column=0, sticky="e", pady=6)
        self.dl_doc_id = ttk.Entry(dl, width=44)
        self.dl_doc_id.grid(row=0, column=1, pady=6)
        ttk.Button(dl, text="Download && Verify...", command=self._do_download
                   ).grid(row=1, column=0, columnspan=2, pady=12)

        # --- Contacts tab ---
        contacts = ttk.Frame(nb, padding=14); nb.add(contacts, text="Trusted Contacts")
        self.contacts_list = tk.Listbox(contacts, width=80, height=10, font=("Consolas", 10))
        self.contacts_list.pack(fill="both", expand=True, pady=6)
        cbtns = ttk.Frame(contacts); cbtns.pack(fill="x")
        ttk.Button(cbtns, text="Refresh", command=self._refresh_contacts
                   ).pack(side="left")
        ttk.Button(cbtns, text="Mark Selected as VERIFIED",
                   command=self._verify_selected_contact
                   ).pack(side="left", padx=6)

        # --- Change password tab ---
        pw = ttk.Frame(nb, padding=14); nb.add(pw, text="Change Password")
        ttk.Label(pw, text="Current password:").grid(row=0, column=0, sticky="e", pady=6)
        self.pw_old = ttk.Entry(pw, width=34, show="*"); self.pw_old.grid(row=0, column=1, pady=6)
        ttk.Label(pw, text="New password:").grid(row=1, column=0, sticky="e", pady=6)
        self.pw_new = ttk.Entry(pw, width=34, show="*"); self.pw_new.grid(row=1, column=1, pady=6)
        ttk.Label(pw, text="Confirm new password:").grid(row=2, column=0, sticky="e", pady=6)
        self.pw_confirm = ttk.Entry(pw, width=34, show="*"); self.pw_confirm.grid(row=2, column=1, pady=6)
        ttk.Button(pw, text="Change Password", command=self._do_change_password
                   ).grid(row=3, column=0, columnspan=2, pady=12)

        ttk.Label(f, text="Activity log:").pack(anchor="w")
        self.log_text = tk.Text(f, height=9, state="disabled", wrap="word",
                                font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=False)

    # -------------------- Screen switching --------------------

    def _show_login(self) -> None:
        self.main_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def _show_main(self) -> None:
        self.login_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self.welcome_label.config(text=f"Logged in as: {self.client.username}")
        self._refresh_contacts()

    # -------------------- Log --------------------

    def _log(self, text: str) -> None:
        self.log_text.config(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    # -------------------- TOFU dialog --------------------

    def _ask_trust_fingerprint(self, username: str, fingerprint: str) -> bool:
        """Blocking modal — nothing else in the app can happen until this
        is explicitly resolved."""
        result = {"trust": False}
        dlg = tk.Toplevel(self)
        dlg.title("New Contact — Verify Identity")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        ttk.Label(dlg, text=f"First contact with '{username}'",
                  font=("Segoe UI", 12, "bold")).pack(padx=24, pady=(18, 6))
        ttk.Label(
            dlg, justify="center", wraplength=400,
            text=(f"You have never received a key for '{username}' before. "
                  "Call or meet them and read this fingerprint aloud together. "
                  "Do NOT trust it just because it looks plausible."),
        ).pack(padx=24, pady=4)

        fp_frame = tk.Frame(dlg, bg="#1e1e1e")
        fp_frame.pack(padx=24, pady=14, fill="x")
        tk.Label(fp_frame, text=format_fingerprint(fingerprint),
                 font=("Consolas", 13, "bold"),
                 fg="#00e08a", bg="#1e1e1e", justify="center"
                 ).pack(padx=16, pady=16)

        btns = ttk.Frame(dlg); btns.pack(pady=(4, 20))

        def accept(): result["trust"] = True;  dlg.destroy()
        def cancel(): result["trust"] = False; dlg.destroy()

        ttk.Button(btns, text="It matches — Trust & Continue",
                   command=accept).grid(row=0, column=0, padx=8)
        ttk.Button(btns, text="Cancel", command=cancel).grid(row=0, column=1, padx=8)
        dlg.protocol("WM_DELETE_WINDOW", cancel)  # X = cancel, never silent trust

        self.wait_window(dlg)
        return result["trust"]

    # -------------------- Security failure dialog --------------------

    def _show_security_failure(self, title: str, text: str) -> None:
        """Blocking OS error dialog — no dismiss-by-reflex path."""
        messagebox.showerror(title, text)

    # -------------------- Button handlers --------------------

    def _do_login(self) -> None:
        u, p = self.login_user.get().strip(), self.login_pass.get()
        if not u or not p:
            self.login_status.config(text="Enter a username and password.")
            return
        self.login_status.config(text="Logging in — Argon2id takes ~0.2s...")
        self.update_idletasks()
        try:
            self.client.login(u, p)
            self.login_pass.delete(0, "end")
            self.login_status.config(text="")
            self._log(f"[+] Logged in as '{u}'.")
            self._show_main()
        except ClientError as e:
            self.login_status.config(text=f"Login failed: {e}")

    def _do_signup(self) -> None:
        u, p = self.login_user.get().strip(), self.login_pass.get()
        if not u or not p:
            self.login_status.config(text="Enter a username and password.")
            return
        self.login_status.config(text="Creating account — Argon2id takes ~0.2s...")
        self.update_idletasks()
        try:
            self.client.signup(u, p)
            self.login_status.config(text="Account created — you can log in now.",
                                      foreground="#0a7a2e")
        except ClientError as e:
            self.login_status.config(text=f"Signup failed: {e}",
                                      foreground="#b00020")

    def _do_logout(self) -> None:
        who = self.client.username
        self.client.logout()
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        self.login_status.config(text="", foreground="#b00020")
        self._show_login()

    def _do_upload(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file to upload")
        if not path:
            return
        try:
            doc_id = self.client.upload(path)
            self.last_doc_id_var.set(doc_id)
            self._log(f"[+] Uploaded '{os.path.basename(path)}' — doc_id={doc_id}")
        except ClientError as e:
            self._show_security_failure("Upload Failed", str(e))
            self._log(f"[-] Upload failed: {e}")

    def _do_share(self) -> None:
        doc_id = self.share_doc_id.get().strip()
        recipient = self.share_recipient.get().strip()
        if not doc_id or not recipient:
            messagebox.showwarning("Missing info", "Enter both a document ID and a recipient.")
            return
        try:
            self.client.share(doc_id, recipient)
            self._log(f"[+] Shared {doc_id[:16]}... with '{recipient}'.")
            self._refresh_contacts()
        except ClientError as e:
            self._show_security_failure("Share Failed", str(e))
            self._log(f"[-] Share failed: {e}")

    def _do_download(self) -> None:
        doc_id = self.dl_doc_id.get().strip()
        if not doc_id:
            messagebox.showwarning("Missing info", "Enter a document ID.")
            return
        save_path = filedialog.asksaveasfilename(title="Save decrypted file as...")
        if not save_path:
            return
        try:
            sender = self.client.download(doc_id, save_path)
            self._log(f"[+] Downloaded and verified — signed by '{sender}' — saved to {save_path}")
            self._refresh_contacts()
        except ClientError as e:
            # The whole point of §7.4/7.5: verification failure MUST NOT
            # save a file. Our client.download() raises before writing.
            self._show_security_failure("SECURITY FAILURE — Download Rejected", str(e))
            self._log(f"[✗] Download REJECTED: {e}")

    def _do_change_password(self) -> None:
        old, new, conf = self.pw_old.get(), self.pw_new.get(), self.pw_confirm.get()
        if not old or not new:
            messagebox.showwarning("Missing info", "Enter both the current and new password.")
            return
        if new != conf:
            messagebox.showwarning("Mismatch", "New passwords don't match.")
            return
        try:
            self.client.change_password(old, new)
            self.pw_old.delete(0, "end")
            self.pw_new.delete(0, "end")
            self.pw_confirm.delete(0, "end")
            self._log("[+] Password changed.")
        except ClientError as e:
            self._show_security_failure("Change Password Failed", str(e))
            self._log(f"[-] Change failed: {e}")

    def _refresh_contacts(self) -> None:
        self.contacts_list.delete(0, "end")
        if self.client.trust is None:
            return
        for name, entry in self.client.trust.all_entries().items():
            fp_short = entry.fingerprint[:24]
            self.contacts_list.insert(
                "end",
                f"{name:<20} [{entry.status.value:<10}] {fp_short}...",
            )

    def _verify_selected_contact(self) -> None:
        sel = self.contacts_list.curselection()
        if not sel:
            return
        name = self.contacts_list.get(sel[0]).split()[0]
        try:
            self.client.mark_contact_verified(name)
            self._log(f"[+] '{name}' marked VERIFIED.")
            self._refresh_contacts()
        except Exception as e:
            messagebox.showerror("Verify Failed", str(e))

    def _copy(self, text: str) -> None:
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="SecureVault GUI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--storage-dir", default=".")
    args = parser.parse_args()
    app = SecureVaultGUI(host=args.host, port=args.port,
                         storage_dir=args.storage_dir)
    app.mainloop()


if __name__ == "__main__":
    main()
