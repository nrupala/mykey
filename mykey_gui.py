import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import pyperclip, threading, time
from mykey import MyKey

class MyKeyGUI:
    
    def __init__(self, root):
        self.root = root
        self.root.title("mykey - Zero Trust Vault")
        self.root.geometry("420x600")
        
        # 1. Theme Definitions
        self.themes = {
            "Light": {"bg": "#ffffff", "fg": "#202124", "btn": "#f1f3f4", "accent": "#1a73e8"},
            "Dark":  {"bg": "#202124", "fg": "#e8eaed", "btn": "#3c4043", "accent": "#8ab4f8"},
            "Sepia": {"bg": "#f4ecd8", "fg": "#5b4636", "btn": "#e6dec7", "accent": "#8f6d4d"}
        }
        self.current_theme = "Light"

        # 2. Initial Auth
        secret = simpledialog.askstring("Auth", "Master Password:", show='*')
        if not secret:
            self.root.destroy()
            return
            
        self.app = MyKey(secret)
        self.current_pw_value = ""
        self.is_masked = True
        
        self.create_widgets()
        self.apply_theme("Light") # Default start

    def apply_theme(self, theme_name):
        self.current_theme = theme_name
        colors = self.themes[theme_name]
        
        self.root.configure(bg=colors["bg"])
        self.main_container.configure(style="TFrame")
        
        # Configure TTK Styles
        style = ttk.Style()
        style.configure("TFrame", background=colors["bg"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["fg"])
        style.configure("TButton", padding=5)
        
        # Update specific non-TTK widgets
        self.service_entry.configure(bg=colors["btn"], fg=colors["fg"], insertbackground=colors["fg"])
        self.pw_entry.configure(bg=colors["btn"], fg=colors["fg"], insertbackground=colors["fg"])
        
        # Update status label
        # self.status_label.config(text="🛡️ Secured by mykey | Built in 🇨🇦 ")

    def create_widgets(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Add "Help" or "About" Tab
        about_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="About", menu=about_menu)
        about_menu.add_command(label="Project Details", command=self.show_about)   
       
        # Theme Selector Row
        theme_frame = tk.Frame(self.root, bg="#333") # Dark header for contrast
        theme_frame.pack(fill=tk.X)
        for t in self.themes.keys():
            tk.Button(theme_frame, text=t, command=lambda name=t: self.apply_theme(name),
                      bg="#444", fg="white", relief="flat", padx=10).pack(side=tk.LEFT)

        self.main_container = ttk.Frame(self.root, padding="20")
        self.main_container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.main_container, text="SERVICE NAME", font=('Arial', 8, 'bold')).pack(anchor=tk.W)
        self.service_entry = tk.Entry(self.main_container, font=("Arial", 11), relief="flat")
        self.service_entry.pack(pady=(0, 15), fill=tk.X, ipady=5)

        ttk.Label(self.main_container, text="PASSWORD", font=('Arial', 8, 'bold')).pack(anchor=tk.W)
        self.pw_entry = tk.Entry(self.main_container, show="*", font=("Courier New", 12), relief="flat")
        self.pw_entry.pack(pady=(0, 10), fill=tk.X, ipady=5)

        # Canadian Branded Status Bar
        
        try:
            status_text = "🛡️ Secured by mykey | Built in 🇨🇦 Canada"
            # Test if the current environment can handle the flag
            status_text.encode('ascii') 
            # If the line above doesn't fail, it means no emojis are present
            # so we manually set it to a safe version.
            safe_status = "🛡️ Secured by mykey | Built in [CAN] Canada"
        except UnicodeEncodeError:
        
            safe_status = "🛡️ Secured by mykey | Built in 🇨🇦 Canada"

        self.status_label = tk.Label(
            self.main_container, 
            text=safe_status, 
            font=("Segoe UI Symbol", 8) # Segoe UI Symbol is best for flags on Windows
        )
        self.status_label.pack(side=tk.BOTTOM, pady=10)  
      
        # Action Row
        ctrl_frame = ttk.Frame(self.main_container)
        ctrl_frame.pack(fill=tk.X, pady=5)
        self.toggle_btn = ttk.Button(ctrl_frame, text="👁 Show", command=self.toggle_pw)
        self.toggle_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(ctrl_frame, text="📋 Copy", command=self.copy_pw).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        ttk.Separator(self.main_container, orient='horizontal').pack(fill='x', pady=20)

        # Primary Buttons
        ttk.Button(self.main_container, text="GENERATE & SAVE", command=self.do_save).pack(fill=tk.X, pady=2)
        ttk.Button(self.main_container, text="RETRIEVE VAULT", command=self.do_get).pack(fill=tk.X, pady=2)
        ttk.Button(self.main_container, text="EXPORT CSV", command=self.do_export).pack(fill=tk.X, pady=2)

        self.status_label = tk.Label(self.main_container, text="Vault Encrypted", font=("Arial", 8))
        self.status_label.pack(side=tk.BOTTOM, pady=10)

    # ... Logic (do_save, do_get, toggle_pw, copy_pw) remains same as previous working logic ...
    def toggle_pw(self):
        self.is_masked = not self.is_masked
        self.pw_entry.config(show="*" if self.is_masked else "")
        self.toggle_btn.config(text="👁 Show" if self.is_masked else "🔒 Hide")

    def update_ui(self, val):
        self.current_pw_value = val
        self.pw_entry.delete(0, tk.END)
        self.pw_entry.insert(0, val)

    def do_save(self):
        svc = self.service_entry.get()
        if not svc: return
        new_pw = self.app.generate_password()
        self.app.save_password(svc, new_pw)
        self.update_ui(new_pw)

    def do_get(self):
        svc = self.service_entry.get()
        self.update_ui(self.app.get_password(svc))

    def copy_pw(self):
        if self.current_pw_value:
            pyperclip.copy(self.current_pw_value)
            threading.Thread(target=self.wipe, daemon=True).start()

    def wipe(self):
        time.sleep(60); pyperclip.copy("")

    def do_export(self):
        res, msg = self.app.export_vault_to_csv()
        messagebox.showinfo("Export", msg)

    def show_about(self):
        """Displays a themed Canadian About window with project details."""
        about_win = tk.Toplevel(self.root)
        about_win.title("About mykey")
        about_win.geometry("450x550")
        
        # Pull current theme colors
        colors = self.themes[self.current_theme]
        about_win.configure(bg=colors["bg"])

        content = ttk.Frame(about_win, padding="20", style="TFrame")
        content.pack(fill=tk.BOTH, expand=True)

        # Canada Branding Header
        header = f"🗝️ mykey | Built in 🇨🇦 Canada"
        ttk.Label(content, text=header, font=('Arial', 14, 'bold')).pack(pady=(0, 10))

        # Inspiration & Power of Thinking
        insp_text = (
            "💡 Inspiration: Protecting digital sovereignty.\n"
            "🧠 Privacy is a human right, not a privilege."
        )
        ttk.Label(content, text=insp_text, wraplength=380, justify="center").pack(pady=10)

        # Contributors List
        ttk.Label(content, text="CONTRIBUTORS", font=('Arial', 9, 'bold')).pack(pady=(15, 5))
        contrib_list = (
            "• Developer: Nrupal Akolkar/ X: @nrupal_akolkar Github: @nrupala\n"
        )
        #"• Security Architect: Nrupal Akolkar\n"
        #"• Documentation: Nrupal Akolkar\n"
        ttk.Label(content, text=contrib_list, justify="left").pack()

        # Contact & Donation
        ttk.Label(content, text="CONTACT & SUPPORT", font=('Arial', 9, 'bold')).pack(pady=(15, 5))
        contact_info = "📧 Contact: nrupalakolkar@gmail.com\n🌐 Web: www.GitHub.com/nrupala"
        ttk.Label(content, text=contact_info).pack()

        # Donation Button (using the link you'll insert)
        donate_btn = ttk.Button(content, text="☕ Support with a Coffee", 
        command=lambda: pyperclip.copy("https://buymeacoffee.com/nrupalakolt"))
        donate_btn.pack(pady=20)
        ttk.Label(content, text="(Clicking copies link to clipboard)", font=('Arial', 7)).pack()

        ttk.Button(content, text="Close", command=about_win.destroy).pack(side="bottom", pady=10)
    
if __name__ == "__main__":
    root = tk.Tk()
    MyKeyGUI(root)
    root.mainloop()
