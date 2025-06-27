This project focuses on secure file handling using encryption and integrity checks. It is implemented both as a command-line interface (CLI) and a graphical interface (GUI).

**Key Features:**
- Uses the `cryptography` library (Fernet) to encrypt and decrypt files with AES
- Generates a unique encryption key which is securely stored
- Produces encrypted files with `.enc` extension and separate `.meta` files containing metadata such as original filename, SHA-256 hash, and timestamp
- On decryption, verifies the integrity of the file using the stored hash value
- Offers both a CLI version for direct usage and a Tkinter GUI for usability

This project demonstrates file-level encryption, metadata handling, secure key usage, and SHA-based file verification.