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

import tkinter as tk
from tkinter import messagebox

import brand


def show_welcome():
    root = tk.Tk()
    root.withdraw()

    welcome_text = (
        f"Welcome to {brand.PRODUCT_NAME}!\n\n"
        "This is a Zero-Trust vault. That means:\n"
        "1. We NEVER store your Master Password.\n"
        "2. If you lose it and your recovery phrase, we cannot reset it.\n"
        "3. Your data is encrypted locally on THIS device.\n\n"
        "Ready to secure your digital life?"
    )

    if messagebox.askyesno("First Run", welcome_text):
        messagebox.showinfo("Pro Tip", "Generate a Recovery Phrase next and write it down!")

    root.destroy()


if __name__ == "__main__":
    show_welcome()
