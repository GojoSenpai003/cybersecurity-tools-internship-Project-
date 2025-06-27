from cryptography.fernet import Fernet
import os
import hashlib
import time

# 🔑 Generate and save key
def generate_key():
    key = Fernet.generate_key()
    with open("filekey.key", "wb") as key_file:
        key_file.write(key)
    print("✅ Key saved as filekey.key")

# 🔓 Load existing key
def load_key():
    try:
        return open("filekey.key", "rb").read()
    except FileNotFoundError:
        print("❌ Key file not found. Generate it first.")
        return None

# 🧮 Calculate SHA-256 hash of file
def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# 🔐 Encrypt file
def encrypt_file(file_path):
    key = load_key()
    if not key:
        return

    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        original = file.read()

    # SAFELY CREATE ENCRYPTED FILE PATH
    dir_name = os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    enc_file = os.path.join(dir_name, base_name + ".enc")

    with open(enc_file, "wb") as encrypted_file:
        encrypted_file.write(fernet.encrypt(original))

    # Generate metadata
    file_hash = get_file_hash(file_path)
    metadata = (
        f"Original File: {file_path}\n"
        f"Time: {time.ctime()}\n"
        f"SHA256: {file_hash}\n"
    )
    meta_file_path = enc_file + ".meta"
    with open(meta_file_path, "w") as meta_file:
        meta_file.write(metadata)

    print(f"✅ File encrypted: {enc_file}")
    print(f"📝 Metadata saved: {meta_file_path}")

# 🔓 Decrypt file and verify integrity
def decrypt_file(enc_path):
    key = load_key()
    if not key:
        return

    fernet = Fernet(key)

    with open(enc_path, "rb") as enc_file:
        encrypted_data = enc_file.read()

    decrypted = fernet.decrypt(encrypted_data)

    original_path = enc_path.replace(".enc", "_decrypted")
    with open(original_path, "wb") as dec_file:
        dec_file.write(decrypted)

    print(f"🔓 File decrypted and saved as: {original_path}")

    # ✅ Integrity Check
    meta_path = enc_path + ".meta"
    if os.path.exists(meta_path):
        with open(meta_path, "r") as meta_file:
            meta_data = meta_file.read()

        hash_line = [line for line in meta_data.splitlines() if "SHA256" in line]
        if hash_line:
            saved_hash = hash_line[0].split(": ")[-1].strip()
            current_hash = get_file_hash(original_path)
            if saved_hash == current_hash:
                print("✅ Integrity Verified: File is authentic.")
            else:
                print("❌ Integrity Check Failed: File may be corrupted or tampered.")
    else:
        print("⚠️ No metadata found. Skipping integrity verification.")

# 🧭 Main menu
def main():
    print("🔐 Secure File Storage System")
    print("1. Generate Encryption Key")
    print("2. Encrypt File")
    print("3. Decrypt File with Integrity Check")
    print("4. Exit")

    while True:
        choice = input("\nChoose an option (1-4): ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            file_path = input("Enter path of file to encrypt: ").strip()
            if os.path.exists(file_path):
                encrypt_file(file_path)
            else:
                print("❌ File does not exist.")
        elif choice == "3":
            enc_path = input("Enter path of .enc file to decrypt: ").strip()
            if os.path.exists(enc_path):
                decrypt_file(enc_path)
            else:
                print("❌ File does not exist.")
        elif choice == "4":
            print("👋 Exiting. Stay secure!")
            break
        else:
            print("❗ Invalid choice. Enter a number from 1 to 4.")

if __name__ == "__main__":
    main()
3
