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

import os
import re
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, simpledialog, ttk

import brand
from clipboard_guard import (
    ClipboardGuard,
    load_clipboard_clear_seconds,
    save_clipboard_clear_seconds,
)
from mykey import MyKey, make_entry, rotation_line, rotation_status


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
        # Copied secrets clear themselves (clipboard_guard.py holds
        # the rule and its hard bounds); closing the window is this
        # app's lock, so it clears a pending copied secret at once.
        self.clipboard = ClipboardGuard(
            clear_seconds=load_clipboard_clear_seconds())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.create_widgets()
        self.refresh_list()

    def _on_close(self):
        self.clipboard.clear_now()
        self.root.destroy()

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
        vault_menu.add_command(label="Password rotation…",
                               command=self.do_rotation_report)
        vault_menu.add_command(label="Set rotation default…",
                               command=self.do_rotation_default)
        sync_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Sync & Backup", menu=sync_menu)
        sync_menu.add_command(label="Sync status…", command=self.do_sync_status)
        sync_menu.add_command(label="Sync push", command=self.do_sync_push)
        sync_menu.add_command(label="Sync pull", command=self.do_sync_pull)
        sync_menu.add_command(label="Export backup package…",
                              command=self.do_backup_export)
        sync_menu.add_command(label="Import backup package…",
                              command=self.do_backup_import)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Clipboard clear delay…",
                                  command=self.do_clipboard_delay)
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="How MyKey works…",
                              command=lambda: self.show_help_doc(
                                  "HELP.md", f"How {brand.PRODUCT_NAME} works"))
        help_menu.add_command(label="Common questions…",
                              command=lambda: self.show_help_doc(
                                  "FAQ.md", "Common questions"))
        about_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="About", menu=about_menu)
        about_menu.add_command(label=f"About {brand.PRODUCT_NAME}",
                               command=self.show_about)

        main = ttk.Frame(self.root, padding="14")
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="SEARCH", font=("Arial", 8, "bold")).pack(anchor=tk.W)
        self.search_entry = tk.Entry(main, font=("Arial", 11))
        self.search_entry.pack(fill=tk.X, pady=(0, 6))
        self.search_entry.bind("<KeyRelease>", lambda _e: self.refresh_list())

        self.listbox = tk.Listbox(main, height=8, font=("Arial", 10))
        self.listbox.pack(fill=tk.X, pady=(0, 2))
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        self.rotation_count_label = ttk.Label(
            main, text="", font=("Arial", 9, "bold"))
        self.rotation_count_label.pack(anchor=tk.W, pady=(0, 10))

        self.fields = {}
        for label, key in (("SERVICE NAME", "service"), ("USERNAME", "username"),
                           ("PASSWORD", "password"), ("URL", "url"),
                           ("NOTES", "notes"), ("TOTP SECRET", "totp_secret")):
            ttk.Label(main, text=label, font=("Arial", 8, "bold")).pack(anchor=tk.W)
            entry = tk.Entry(main, font=("Arial", 11),
                             show="*" if key == "password" else "")
            entry.pack(fill=tk.X, pady=(0, 6))
            self.fields[key] = entry

        self.rotation_label = ttk.Label(main, text="", font=("Arial", 9))
        self.rotation_label.pack(anchor=tk.W, pady=(2, 0))

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
        ttk.Button(main, text="MARK AS CHANGED TODAY",
                   command=self.do_mark_changed).pack(fill=tk.X, pady=2)
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
        default = self.app.vault_settings()["default_rotate_days"]
        self.listbox.delete(0, tk.END)
        for e in entries:
            label = e["service"] + (f" ({e['username']})" if e["username"] else "")
            state = rotation_status(e, default)["state"]
            if state == "overdue":
                label += "  ⚠️ change overdue"
            elif state == "due_soon":
                label += "  ⏰ change due"
            self.listbox.insert(tk.END, label)
        due = self.app.rotation_due_count()
        self.rotation_count_label.config(
            text=(f"{due} password(s) due for a change — "
                  "see Vault → Password rotation" if due else ""))

    def on_select(self, _event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        entry = self._listed[sel[0]]
        for key, widget in self.fields.items():
            widget.delete(0, tk.END)
            widget.insert(0, entry.get(key, "") or "")
        self.current_pw_value = entry["password"]
        default = self.app.vault_settings()["default_rotate_days"]
        self.rotation_label.config(text=rotation_line(entry, default))

    def toggle_pw(self):
        self.is_masked = not self.is_masked
        self.fields["password"].config(show="*" if self.is_masked else "")
        self.toggle_btn.config(text="👁 Show" if self.is_masked else "🔒 Hide")

    def copy_pw(self):
        value = self.fields["password"].get() or self.current_pw_value
        if value:
            self.current_pw_value = value
            try:
                self.clipboard.copy(value)
            except Exception as exc:
                messagebox.showerror(brand.PRODUCT_NAME,
                                     f"Copy failed: {exc}")

    def do_clipboard_delay(self):
        """Settings: how long a copied password stays on the clipboard.

        Bounded by the product rule (60–300 seconds) — the dialog
        restricts the range and clipboard_guard clamps on save.
        """
        seconds = simpledialog.askinteger(
            "Clipboard clear delay",
            "Clear copied passwords after how many seconds?\n"
            "(Shortest 60, longest 300. Default is 60.)",
            initialvalue=self.clipboard.clear_seconds,
            minvalue=60, maxvalue=300, parent=self.root)
        if seconds is None:
            return
        self.clipboard.set_clear_seconds(seconds)
        save_clipboard_clear_seconds(self.clipboard.clear_seconds)

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

    def do_mark_changed(self):
        """The password was changed on the website itself: move only
        the age clock, the stored value is untouched."""
        form = self._form()
        if not form["service"]:
            return
        try:
            entry = self.app.mark_password_changed(
                form["service"], form["username"] or None)
        except Exception as exc:
            messagebox.showerror(brand.PRODUCT_NAME, str(exc))
            return
        default = self.app.vault_settings()["default_rotate_days"]
        self.rotation_label.config(text=rotation_line(entry, default))
        self.refresh_list()

    def do_rotation_report(self):
        default = self.app.vault_settings()["default_rotate_days"]
        header = ("Default: no rotation by default" if not default
                  else f"Default: change every {default} days")
        rows = [r for r in self.app.rotation_report()
                if r["state"] in ("overdue", "due_soon", "unknown")]
        if not rows:
            body = "Nothing needs changing right now."
        else:
            lines = []
            for r in rows:
                line = rotation_line(
                    {"password_set_at": r["password_set_at"],
                     "rotate_days": r["rotate_days"]}, None)
                suffix = {"overdue": " — overdue",
                          "due_soon": " — due soon"}.get(r["state"], "")
                lines.append(f"{r['service']}: {line}{suffix}")
            body = "\n".join(lines)
        messagebox.showinfo(brand.PRODUCT_NAME,
                            f"Password rotation\n\n{header}\n\n{body}")

    def do_rotation_default(self):
        answer = simpledialog.askstring(
            brand.PRODUCT_NAME,
            "Change every password after how many days?\n"
            "Type a number (the standard is 180), or 'never'.",
        )
        if answer is None:
            return
        answer = answer.strip().lower()
        try:
            value = 0 if answer in ("never", "off", "0") else int(answer)
            if value < 0:
                raise ValueError
            self.app.set_default_rotate_days(value)
        except (ValueError, TypeError):
            messagebox.showwarning(
                brand.PRODUCT_NAME,
                "Please type a whole number of days, or 'never'.")
            return
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

    # -- Help & About (in-app, fully offline: the text ships with
    # the app as HELP.md / FAQ.md beside this file — the same files
    # the repo carries as docs, mirrored byte-for-byte in the
    # phone / web app) --------------------------------------------

    def _app_dir(self):
        return os.path.dirname(os.path.abspath(__file__))

    def _app_version(self):
        try:
            from importlib.metadata import version

            return version("mykey")
        except Exception:
            pass
        try:
            with open(os.path.join(self._app_dir(), "pyproject.toml"),
                      encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("version"):
                        return line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        return "unknown"

    @staticmethod
    def _markdown_to_text(markdown):
        """Render the small markdown subset HELP.md/FAQ.md use
        (headings, bullets, **bold**) as readable plain text."""
        text = re.sub(r"<!--.*?-->", "", markdown, flags=re.DOTALL)
        out = []
        for raw in text.splitlines():
            line = raw.rstrip()
            stripped = line.strip()
            if stripped.startswith("### "):
                out += ["", stripped[4:], ""]
            elif stripped.startswith("## "):
                out += ["", stripped[3:], ""]
            elif stripped.startswith("# "):
                out += [stripped[2:], ""]
            elif stripped.startswith("- "):
                out.append("• " + stripped[2:])
            else:
                out.append(stripped)
        return "\n".join(out).replace("**", "").strip() + "\n"

    def _text_dialog(self, title, width=580, height=660):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry(f"{width}x{height}")
        frame = ttk.Frame(win, padding="12")
        frame.pack(fill=tk.BOTH, expand=True)
        text = tk.Text(frame, wrap=tk.WORD, font=("Arial", 11))
        scroll = ttk.Scrollbar(frame, orient="vertical",
                               command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(win, text="Close",
                   command=win.destroy).pack(pady=(0, 10))
        return win, text

    def show_help_doc(self, filename, title):
        path = os.path.join(self._app_dir(), filename)
        try:
            with open(path, encoding="utf-8") as fh:
                body = self._markdown_to_text(fh.read())
        except OSError:
            messagebox.showerror(
                brand.PRODUCT_NAME,
                f"The help file {filename} is missing from this "
                "install. It ships with the app — reinstalling "
                "restores it.",
            )
            return
        _win, text = self._text_dialog(title)
        text.insert("1.0", body)
        text.configure(state=tk.DISABLED)

    def _about_licence_block(self, text):
        """Licence / tip-jar block for the About dialog.

        FREE-TIER SLOT: intentionally empty until the owner rules
        on the free-tier + tip question. When it lands, the block
        renders here — nothing else in About needs to change.
        """
        return None

    def show_about(self):
        win, text = self._text_dialog(
            f"About {brand.PRODUCT_NAME}", width=520, height=560)
        text.tag_configure("link", foreground="#0b5cad", underline=True)
        for label, url in (("owner-link", "https://nrupalakolkar.com"),
                           ("muse-link", "https://muse.ai/join")):
            text.tag_bind(label, "<Button-1>",
                          lambda _e, u=url: webbrowser.open(u))
            text.tag_bind(label, "<Enter>",
                          lambda _e: win.configure(cursor="hand2"))
            text.tag_bind(label, "<Leave>",
                          lambda _e: win.configure(cursor=""))

        text.insert("1.0", f"{brand.PRODUCT_NAME} — {brand.PRODUCT_TAGLINE}\n"
                           f"Version {self._app_version()}\n\n"
                           f"Sold by {brand.VENDOR_NAME} · {brand.DOMAIN}\n"
                           f"Support: {brand.SUPPORT_EMAIL}\n\n")
        text.insert(tk.END, "Owned by ")
        text.insert(tk.END, "Nrupal Akolkar", "owner-link")
        text.insert(tk.END, " · Built with ")
        text.insert(tk.END, "Muse by Meta", "muse-link")
        text.insert(tk.END,
                    " — join Muse, then redeem code 101EEK in Settings "
                    "within 48 hours of joining and we both earn tokens.\n\n"
                    "Licence: the MyKey core is proprietary software of "
                    f"{brand.VENDOR_NAME}; the interface layer is "
                    "Apache 2.0. The full licence map is LICENSING.md "
                    "in the app folder.\n\n"
                    "What is in this version: see CHANGELOG.md in the "
                    "app folder.\n")
        self._about_licence_block(text)
        text.configure(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    MyKeyGUI(root)
    root.mainloop()
