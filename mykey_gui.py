# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Desktop GUI (Apache 2.0 interface layer).

A shell over the proprietary engine (mykey.py): it renders, prompts
and forwards — it contains no cryptography of its own. All brand
strings come from brand.py.

Phase 1 additions over the original GUI:
* manual add — type an existing password of your own and save it
  (previously the GUI could only generate),
* a searchable vault list with edit / delete,
* username / URL / notes / TOTP fields on every entry,
* CSV import (browsers + other managers) with a preview,
* recovery-phrase setup from the menu.
"""

import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import pyperclip

import brand
from mykey import MyKey, make_entry


class MyKeyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{brand.PRODUCT_NAME} - {brand.PRODUCT_TAGLINE}")
        self.root.geometry("520x640")
        secret = simpledialog.askstring(
            f"{brand.PRODUCT_NAME}", "Enter Master Password:", show="*"
        )
        if not secret:
            self.root.destroy()
            return
        try:
            self.app = MyKey(secret)
            self.app.unlock()
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            self.root.destroy()
            return
        self.current_pw_value = ""
        self.is_masked = True
        self.create_widgets()
        self.refresh_list()

    # -- layout ---------------------------------------------------------
    def create_widgets(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        vault_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Vault", menu=vault_menu)
        vault_menu.add_command(label="Import passwords…", command=self.do_import)
        vault_menu.add_command(label="Export CSV…", command=self.do_export)
        vault_menu.add_command(label="Set up recovery phrase…",
                               command=self.do_recovery_setup)
        sync_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Sync & Backup", menu=sync_menu)
        sync_menu.add_command(label="Sync status…", command=self.do_sync_status)
        sync_menu.add_command(label="Sync push", command=self.do_sync_push)
        sync_menu.add_command(label="Sync pull", command=self.do_sync_pull)
        sync_menu.add_command(label="Export backup package…",
                              command=self.do_backup_export)
        sync_menu.add_command(label="Import backup package…",
                              command=self.do_backup_import)
        about_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="About", menu=about_menu)
        about_menu.add_command(label="Project Details", command=self.show_about)

        main = ttk.Frame(self.root, padding="14")
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="SEARCH", font=("Arial", 8, "bold")).pack(anchor=tk.W)
        self.search_entry = tk.Entry(main, font=("Arial", 11))
        self.search_entry.pack(fill=tk.X, pady=(0, 6))
        self.search_entry.bind("<KeyRelease>", lambda _e: self.refresh_list())

        self.listbox = tk.Listbox(main, height=8, font=("Arial", 10))
        self.listbox.pack(fill=tk.X, pady=(0, 12))
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        self.fields = {}
        for label, key in (("SERVICE NAME", "service"), ("USERNAME", "username"),
                           ("PASSWORD", "password"), ("URL", "url"),
                           ("NOTES", "notes"), ("TOTP SECRET", "totp_secret")):
            ttk.Label(main, text=label, font=("Arial", 8, "bold")).pack(anchor=tk.W)
            entry = tk.Entry(main, font=("Arial", 11),
                             show="*" if key == "password" else "")
            entry.pack(fill=tk.X, pady=(0, 6))
            self.fields[key] = entry

        row = ttk.Frame(main)
        row.pack(fill=tk.X, pady=4)
        self.toggle_btn = ttk.Button(row, text="👁 Show", command=self.toggle_pw)
        self.toggle_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(row, text="📋 Copy", command=self.copy_pw).pack(
            side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=12)
        ttk.Button(main, text="SAVE MY PASSWORD",
                   command=self.do_save_typed).pack(fill=tk.X, pady=2)
        ttk.Button(main, text="GENERATE & SAVE",
                   command=self.do_generate).pack(fill=tk.X, pady=2)
        ttk.Button(main, text="DELETE ENTRY",
                   command=self.do_delete).pack(fill=tk.X, pady=2)

        ttk.Label(main, text=f"Secured by {brand.PRODUCT_NAME} | {brand.DOMAIN}",
                  font=("Arial", 8)).pack(side=tk.BOTTOM, pady=8)

    # -- helpers ----------------------------------------------------------
    def _form(self):
        return {k: e.get().strip() for k, e in self.fields.items()}

    def refresh_list(self):
        query = self.search_entry.get().strip() if hasattr(self, "search_entry") else ""
        entries = (self.app.search_entries(query) if query
                   else self.app.list_entries())
        self._listed = entries
        self.listbox.delete(0, tk.END)
        for e in entries:
            label = e["service"] + (f" ({e['username']})" if e["username"] else "")
            self.listbox.insert(tk.END, label)

    def on_select(self, _event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        entry = self._listed[sel[0]]
        for key, widget in self.fields.items():
            widget.delete(0, tk.END)
            widget.insert(0, entry.get(key, "") or "")
        self.current_pw_value = entry["password"]

    def toggle_pw(self):
        self.is_masked = not self.is_masked
        self.fields["password"].config(show="*" if self.is_masked else "")
        self.toggle_btn.config(text="👁 Show" if self.is_masked else "🔒 Hide")

    def copy_pw(self):
        value = self.fields["password"].get() or self.current_pw_value
        if value:
            self.current_pw_value = value
            pyperclip.copy(value)
            threading.Thread(target=self._wipe, args=(value,), daemon=True).start()

    def _wipe(self, value):
        time.sleep(60)
        try:
            if pyperclip.paste() == value:  # only clear what we put there
                pyperclip.copy("")
        except Exception:
            pass

    # -- actions ------------------------------------------------------------
    def do_save_typed(self):
        """Manual add/update: store the password the user typed."""
        form = self._form()
        if not form["service"] or not form["password"]:
            messagebox.showwarning(brand.PRODUCT_NAME,
                                   "Service and password are both required.")
            return
        try:
            existing = None
            try:
                existing = self.app.get_entry(form["service"], form["username"] or None)
            except KeyError:
                pass
            if existing:
                self.app.update_entry(form["service"], form["username"] or None,
                                      password=form["password"], url=form["url"],
                                      notes=form["notes"],
                                      totp_secret=form["totp_secret"])
            else:
                self.app.add_entry(make_entry(**form))
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        self.refresh_list()

    def do_generate(self):
        form = self._form()
        if not form["service"]:
            messagebox.showwarning(brand.PRODUCT_NAME, "Service is required.")
            return
        try:
            new_pw = self.app.generate_password()
            self.app.save_password(form["service"], new_pw,
                                   username=form["username"], url=form["url"],
                                   notes=form["notes"])
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        self.fields["password"].delete(0, tk.END)
        self.fields["password"].insert(0, new_pw)
        self.current_pw_value = new_pw
        self.refresh_list()

    def do_delete(self):
        form = self._form()
        if not form["service"]:
            return
        if not messagebox.askyesno(brand.PRODUCT_NAME,
                                   f"Delete {form['service']}?"):
            return
        try:
            self.app.delete_entry(form["service"], form["username"] or None)
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        self.refresh_list()

    def do_import(self):
        path = filedialog.askopenfilename(
            title="Choose an exported passwords file",
            filetypes=[("Password exports", "*.csv *.json *.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        from importers import parse_import, preview_import
        try:
            text = open(path, encoding="utf-8").read()
            fmt, records = parse_import(text)
            preview = preview_import(records, self.app.list_entries())
            proceed = messagebox.askyesno(
                brand.PRODUCT_NAME,
                f"Format: {fmt}\nNew: {len(preview['new'])}  "
                f"Duplicates: {len(preview['duplicates'])}  "
                f"Conflicts: {len(preview['conflicts'])}\n\n"
                "Import the new entries? (duplicates and conflicts are skipped)",
            )
            if not proceed:
                return
            stats = self.app.import_entries(records, on_conflict="skip")
            messagebox.showinfo(brand.PRODUCT_NAME, f"Imported: {stats}")
            messagebox.showwarning(
                brand.PRODUCT_NAME,
                "Delete the plaintext export file now — it is unencrypted.",
            )
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        self.refresh_list()

    def do_export(self):
        path = filedialog.asksaveasfilename(
            title="Export vault to CSV", defaultextension=".csv")
        if not path:
            return
        ok, msg = self.app.export_vault_to_csv(path)
        messagebox.showinfo(brand.PRODUCT_NAME, msg)
        if ok:
            messagebox.showwarning(
                brand.PRODUCT_NAME,
                "The export is plaintext CSV. Guard it and delete it when done.",
            )

    def do_recovery_setup(self):
        try:
            phrase = self.app.setup_recovery()
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        check = simpledialog.askstring(
            brand.PRODUCT_NAME,
            "YOUR RECOVERY PHRASE — write it down, keep it in a safe:\n\n"
            f"{phrase}\n\nNow type it back to verify:",
        )
        if (check or "").strip() != phrase:
            messagebox.showwarning(
                brand.PRODUCT_NAME,
                "That did not match. The phrase is active — make sure the "
                "phrase shown is written down exactly, in order.",
            )
        else:
            messagebox.showinfo(brand.PRODUCT_NAME, "Recovery phrase verified.")

    # -- Phase 3A: sync & backup (ciphertext file operations; the
    # sync actions never decrypt the vault) -------------------------
    def _sync_engine(self):
        import vaultsync

        return vaultsync.VaultSync(self.app.vault_file)

    def _identity_or_warn(self):
        import devices

        try:
            return devices.DeviceIdentity.load()
        except Exception:
            messagebox.showwarning(
                brand.PRODUCT_NAME,
                "No device identity yet. Create one from the command "
                "line first (device-init), then enroll this device.",
            )
            return None

    def do_sync_status(self):
        try:
            status = self._sync_engine().status()
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        lines = "\n".join(f"{k}: {v}" for k, v in status.items())
        messagebox.showinfo(brand.PRODUCT_NAME, f"Sync status\n\n{lines}")

    def do_sync_push(self):
        identity = self._identity_or_warn()
        if identity is None:
            return
        try:
            result = self._sync_engine().push(identity)
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        messagebox.showinfo(brand.PRODUCT_NAME, f"Sync push: {result}")

    def do_sync_pull(self):
        try:
            result = self._sync_engine().pull()
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        messagebox.showinfo(
            brand.PRODUCT_NAME,
            f"Sync pull: {result}\n\nThe vault changed on disk — "
            "restart the app to use the pulled copy.",
        )

    def do_backup_export(self):
        identity = self._identity_or_warn()
        if identity is None:
            return
        path = filedialog.asksaveasfilename(
            title="Export encrypted backup package",
            defaultextension=".mykeybak")
        if not path:
            return
        from backup_pkg import export_package

        try:
            package, code = export_package(self.app, identity,
                                           out_path=path)
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        messagebox.showinfo(
            brand.PRODUCT_NAME,
            f"Backup package written with {len(package['recipients'])} "
            "recipients. It is ciphertext — store or send it like a "
            "vault copy.",
        )
        if code:
            messagebox.showinfo(
                brand.PRODUCT_NAME,
                "YOUR BACKUP CODE — shown once, not stored anywhere:\n\n"
                f"{code}\n\n"
                "Opening this backup outside the app needs BOTH your "
                "recovery phrase AND this code. Write the code down "
                "and keep it somewhere different from the phrase.",
            )

    def do_backup_import(self):
        identity = self._identity_or_warn()
        if identity is None:
            return
        path = filedialog.askopenfilename(
            title="Import encrypted backup package",
            filetypes=[("MyKey backup package", "*.mykeybak"),
                       ("All files", "*.*")])
        if not path:
            return
        from backup_pkg import BackupRefused, import_package

        try:
            result = import_package(
                path, self.app.vault_file, identity=identity,
                registry=self.app._devices,
                pairing_registry=self.app._pairings)
        except BackupRefused:
            # This device cannot open it — offer the outside-app
            # recovery path: phrase, plus the backup code for
            # two-factor (v2) packages.
            phrase = simpledialog.askstring(
                brand.PRODUCT_NAME,
                "This device cannot open that package directly.\n"
                "Recovery phrase:", show="*", parent=self.root)
            if not phrase:
                return
            code = simpledialog.askstring(
                brand.PRODUCT_NAME,
                "Backup code (8 words — needed for newer backups; "
                "leave empty for older ones):", parent=self.root)
            try:
                result = import_package(
                    path, self.app.vault_file, identity=identity,
                    recovery_phrase=phrase,
                    backup_code=(code or None),
                    registry=self.app._devices,
                    pairing_registry=self.app._pairings)
            except Exception as exc:
                messagebox.showerror(brand.PRODUCT_NAME, str(exc))
                return
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        messagebox.showinfo(
            brand.PRODUCT_NAME,
            f"Backup imported (via {result['via']}). The vault on "
            "disk has been replaced — restart the app to use the "
            "restored vault.",
        )

    def show_about(self):
        messagebox.showinfo(
            f"About {brand.PRODUCT_NAME}",
            f"{brand.PRODUCT_NAME} — {brand.PRODUCT_TAGLINE}\n"
            f"Built in Canada · {brand.DOMAIN}\n"
            f"Support: {brand.SUPPORT_EMAIL}\n\n{brand.ATTRIBUTION}",
        )


if __name__ == "__main__":
    root = tk.Tk()
    MyKeyGUI(root)
    root.mainloop()
