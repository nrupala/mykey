# MIT License
#
# Copyright (c) 2026 Nrupal Akolkar
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

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
