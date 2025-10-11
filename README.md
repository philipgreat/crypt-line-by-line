
# crypt-line-by-line

`crypt-line-by-line` is a command-line utility written in Rust, designed for **line-by-line** AES-256 encryption and decryption of text data via pipes or files. It is particularly useful for securing database exports (like `mysqldump` output), log files, or any text stream where per-line confidentiality is required.

## ✨ Key Features

* **Line-Based Processing:** Encrypts and decrypts each line of the input data independently.
* **Secure Encryption:** Uses the robust **AES-256-GCM** (Galois/Counter Mode) for authenticated encryption.
* **Base64 Encoding:** The resulting binary ciphertext is Base64 encoded, making it safe to store and transmit in text-based formats.
* **Flexible I/O:** Supports reading from standard input (pipes) and direct file paths.
* **CLI Interface:** Clear command-line arguments for mode switching (`--enc`/`--dec`) and password specification.

## ⚠️ Security Warning: Key Derivation

**CRITICAL WARNING:**

For the sake of code simplicity in this example, the project uses a basic **SHA-256** hash of the user password to derive the AES key. **This is highly insecure for production environments** as it is vulnerable to brute-force and dictionary attacks.

**For any real-world application, you MUST modify the code to use a robust Key Derivation Function (KDF) like Argon2 or PBKDF2 to securely generate the encryption key from the user-provided password.**

## 🚀 Installation

### 1. Build from Source

You will need the [Rust programming language and its toolchain](https://www.rust-lang.org/tools/install) installed.

```bash
# Clone the repository
git clone [https://github.com/YourUsername/crypt-line-by-line.git](https://github.com/YourUsername/crypt-line-by-line.git)
cd crypt-line-by-line

# Compile and build the optimized executable
cargo build --release

# The executable is located at target/release/
# (e.g., target/release/crypt-line-by-line)
