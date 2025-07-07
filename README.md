# 🛡️ Secure File Encryption System
A powerful command-line application built in Rust that allows you to securely encrypt files, set a self-destruct timer, and decrypt them only with the correct password. It features strong encryption (AES-256), secure file deletion, and a password retry mechanism — all wrapped in a user-friendly terminal interface.
<hr/>

## 📦 Setup Instructions
### ✅ Prerequisites
- Rust installed (via rustup)
- Git (for cloning the repository)

##  ⚙️ Steps to Run the Project
1. Clone the project
   ```
   git clone https://github.com/davidakpele/rust_file_encryption.git
   cd rust_file_encryption
   ```
2. Build the project
   ```
   cargo build --release
   ```
3. Run the application
   ```
   cargo run
   ```
## 🔐 How It Works
### 🧠 Overview
This system allows users to:
- Encrypt any file on their system.
- Set a time-based self-destruction deadline (in seconds, minutes, hours, or days).
- Decrypt the file only if they know the correct password before the timer expires.
- Securely erase the encrypted file if time runs out (data overwritten before deletion).


## 💼 Application Flow
### 🚀 On Launch
- A stylized ASCII UI is displayed (e.g., banners, icons).
- User is presented with 3 options:
   1. Encrypt a file
   2. Decrypt a file
   3. Exit.

## 🔒 Option 1: Encrypt a File
1. User provides the path to the file they want to encrypt.
2. Then, they enter the self-destruct deadline:
     - Accepts time formats like 30s, 5m, 2h, 1d (for seconds, minutes, hours, days).
3. User sets a password for the file.
4. The system:
     - Derives a secure key from the password using Argon2.
     - Encrypts the file with AES-256 in CBC mode.
     - Stores the encrypted file inside a folder called files/ as filename.enc.
     - Starts a countdown timer in the background.
5. The user is prompted to re-enter the password to cancel the destruction timer.
     - If correct, destruction is canceled.
     - If wrong or skipped, destruction continues.

## 🔓 Option 2: Decrypt a File
1. User enters the name of the encrypted file they wish to decrypt (e.g., secret.txt.enc).
2. The system checks if the file exists inside the files/ folder:
     - If not found, it displays a "file not found" error with ASCII art.
3. If found, the user is prompted to enter the password.
4. The password is verified:
     - If correct: file is decrypted and saved as files/secret.txt.dec.
     - If incorrect: user is allowed to retry without exiting, until the self-destruct timer expires.
5. If the timer expires before correct password is entered:
     - The encrypted file is securely erased (multiple overwrites + deletion).

## 🔐 Security Features 
  - Argon2 key derivation for strong password security.
  - AES-256-CBC encryption with random IV and salt.
  - Secure erase logic (overwrites file with random data 3 times before deleting).
  - Atomic flags and background thread ensure file destruction is safe and concurrent.

## 🖼 User Interface (Terminal-Based)
 - ASCII art banners and symbols are shown for:
    - Startup
    - Python branding (🐍)
    - Corrupted files (💀)
    - Successful actions (✅)
 - Clean, beginner-friendly CLI interaction.

## ❗ Usage Guidelines
 - Never forget your password. There's no recovery mechanism.
 - Decrypted files are saved with .dec suffix.
 - Don’t modify encrypted files manually — it will cause decryption failure.