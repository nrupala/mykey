import tkinter as tk
from tkinter import messagebox

def show_welcome():
    root = tk.Tk()
    root.withdraw() # Hide the main window
    
    welcome_text = (
        "Welcome to mykey! 🗝️\n\n"
        "This is a Zero-Trust vault. That means:\n"
        "1. We NEVER store your Master Password.\n"
        "2. If you lose it, we cannot reset it.\n"
        "3. Your data is encrypted locally on THIS device.\n\n"
        "Ready to secure your digital life?"
    )
    
    if messagebox.askyesno("First Run", welcome_text):
        messagebox.showinfo("Pro Tip", "Generate a Recovery Phrase next and write it down!")
    
    root.destroy()

if __name__ == "__main__":
    show_welcome()
