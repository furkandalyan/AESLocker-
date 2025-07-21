AESLocker
AESLocker is a modern, user-friendly file and folder encryption tool with advanced security features and a beautiful graphical interface. It allows you to securely encrypt and decrypt files or entire folders using AES encryption, password protection, and optional RSA hybrid encryption. The tool is designed for both everyday users and power users who need robust data protection.
Features
AES-256 Encryption for files and folders
Password-protected key files (.keyinfo) with customizable names
Hybrid encryption: Optionally encrypt AES keys with RSA public keys
Key expiration: Set how long a key is valid (minutes, hours, days)
Key embedding: Optionally embed the .keyinfo inside the encrypted file (.aesf)
Modern GUI: Drag-and-drop, large fonts, and multi-language support (Turkish/English)
RSA key generation: Generate RSA key pairs directly from the GUI
Detailed logging: All operations are logged for audit and recovery
Custom encrypted file format: .aesf with a unique header and optional embedded key info
Smart folder extraction: When decrypting folders, restores the original folder structure
How to Use
Run the application
Double-click main.py or run it with Python 3:
Apply to main.py
Select Language
Choose Turkish or English at startup.
Encrypt a File or Folder
Click “Select File or Folder” and choose your target.
Click “Encrypt”.
Enter a password and set key expiration.
Choose a name for your .keyinfo file.
Optionally, embed the key info into the encrypted file.
For folders, specify which file types to encrypt.
Decrypt a File or Folder
Select the .aesf file.
Select the corresponding .keyinfo file (or use embedded key info).
Enter your password (and RSA private key if required).
The decrypted file/folder will be restored.
Generate RSA Keys
Click “RSA Anahtar Üret” to create a new RSA key pair for hybrid encryption.
Requirements
Python 3.7+
Dependencies:
cryptography
pycryptodome
tkinterdnd2
Install dependencies with:
Apply to main.py
Security Notes
Your encryption keys are never sent anywhere; everything is local.
For maximum security, use strong passwords and keep your .keyinfo and RSA private keys safe.
License
MIT License
