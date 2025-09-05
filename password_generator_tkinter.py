#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import string, secrets, random

def generate_password(length):
    if length < 4:
        return None
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    symbol = secrets.choice(string.punctuation)
    remaining = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length - 4))
    pw_list = list(upper + lower + digit + symbol + remaining)
    random.SystemRandom().shuffle(pw_list)
    return ''.join(pw_list)

def on_generate():
    try:
        length = int(length_var.get())
    except ValueError:
        messagebox.showerror("Invalid input", "Please enter a valid number for length.")
        return
    if length < 4:
        messagebox.showerror("Too short", "Password length must be at least 4.")
        return
    pwd = generate_password(length)
    result_entry.configure(state='normal')
    result_entry.delete(0, tk.END)
    result_entry.insert(0, pwd)
    result_entry.configure(state='readonly')
    result_var.set(pwd)
    copy_btn.config(state='normal')

def on_copy():
    pwd = result_var.get()
    if not pwd:
        return
    root.clipboard_clear()
    root.clipboard_append(pwd)
    messagebox.showinfo("Copied", "Password copied to clipboard.")

root = tk.Tk()
root.title("Secure Password Generator")
root.resizable(False, False)

mainframe = ttk.Frame(root, padding=12)
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(mainframe, text="Secure Password Generator", font=("Helvetica", 14, "bold")).grid(column=0,row=0, columnspan=3, pady=(0,10))

ttk.Label(mainframe, text="Password length:").grid(column=0,row=1, sticky=tk.W)
length_var = tk.StringVar(value='12')
length_spin = ttk.Spinbox(mainframe, from_=4, to=64, textvariable=length_var, width=5)
length_spin.grid(column=1, row=1, sticky=tk.W)

generate_btn = ttk.Button(mainframe, text="Generate", command=on_generate)
generate_btn.grid(column=0, row=2, pady=(10,0), sticky=tk.W)

result_var = tk.StringVar()
result_entry = ttk.Entry(mainframe, textvariable=result_var, width=40, state='readonly')
result_entry.grid(column=0, row=3, columnspan=2, pady=(10,0))

copy_btn = ttk.Button(mainframe, text="Copy", command=on_copy, state='disabled')
copy_btn.grid(column=2, row=3, padx=(5,0))

ttk.Label(mainframe, text="Tip: length 12+ is recommended").grid(column=0,row=4, columnspan=3, pady=(8,0), sticky=tk.W)

for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

root.mainloop()
