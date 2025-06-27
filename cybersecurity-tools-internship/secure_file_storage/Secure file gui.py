import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib
import os
import time

# ---------- Core Logic (Reused) ----------
def generate_key():
    key = Fernet.generate_key()
    with open("filekey.key", "wb") as key_file:
        key_file.write(key)
    display_message("✅ Key generated and saved as filekey.key")

def load_key():
    try:
        return open("filekey.key", "rb").read()
    except FileNotFoundError:
        display_message("❌ Key file not found. Generate it first.")
        return None

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def encrypt_file():
    key = load_key()
    if not key:
        return
    path = filedialog.askopenfilename(title="Select file to encrypt")
    if not path:
        return

    with open(path, "rb") as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    dir_name = os.path.dirname(path)
    base_name = os.path.basename(path)
    enc_file = os.path.join(dir_name, base_name + ".enc")

    with open(enc_file, "wb") as ef:
        ef.write(encrypted)

    file_hash = get_file_hash(path)
    metadata = f"Original File: {path}\nTime: {time.ctime()}\nSHA256: {file_hash}\n"
    with open(enc_file + ".meta", "w") as mf:
        mf.write(metadata)

    display_message(f"✅ File encrypted: {enc_file}\n📝 Metadata saved: {enc_file}.meta")

def decrypt_file():
    key = load_key()
    if not key:
        return
    enc_path = filedialog.askopenfilename(title="Select .enc file to decrypt", filetypes=[("Encrypted Files", "*.enc")])
    if not enc_path:
        return

    with open(enc_path, "rb") as ef:
        encrypted_data = ef.read()
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_data)
    except:
        display_message("❌ Decryption failed. Wrong key or corrupted file.")
        return

    output_path = enc_path.replace(".enc", "_decrypted")
    with open(output_path, "wb") as df:
        df.write(decrypted)

    integrity_msg = "⚠️ Metadata not found. Skipping integrity check."
    meta_path = enc_path + ".meta"
    if os.path.exists(meta_path):
        with open(meta_path, "r") as mf:
            lines = mf.readlines()
        for line in lines:
            if line.startswith("SHA256"):
                saved_hash = line.split(": ")[1].strip()
                current_hash = get_file_hash(output_path)
                if saved_hash == current_hash:
                    integrity_msg = "✅ Integrity Verified: File matches original."
                else:
                    integrity_msg = "❌ Integrity Failed: File may be tampered."

    display_message(f"🔓 File decrypted: {output_path}\n{integrity_msg}")

# ---------- GUI Setup ----------
def display_message(msg):
    output_text.config(state="normal")
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, msg)
    output_text.config(state="disabled")

app = tk.Tk()
app.title("🔐 Secure File Storage System")
app.geometry("600x400")
app.resizable(False, False)

tk.Label(app, text="Secure File Storage GUI", font=("Arial", 16, "bold")).pack(pady=10)

tk.Button(app, text="🔑 Generate Key", command=generate_key, width=30, bg="#4CAF50", fg="white").pack(pady=5)
tk.Button(app, text="🔐 Encrypt File", command=encrypt_file, width=30, bg="#2196F3", fg="white").pack(pady=5)
tk.Button(app, text="🔓 Decrypt File", command=decrypt_file, width=30, bg="#FF5722", fg="white").pack(pady=5)

tk.Label(app, text="Output:", font=("Arial", 12)).pack(pady=10)
output_text = tk.Text(app, height=10, width=70, state="disabled", bg="#f0f0f0")
output_text.pack()

app.mainloop()
