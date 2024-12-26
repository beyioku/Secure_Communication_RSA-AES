# Secure_Communication_RSA-AES
This repository implements a secure communication mechanism using RSA for key exchange and AES in CBC mode for encryption, coupled with HMAC for message integrity verification. The system demonstrates key generation, encryption, decryption, and message authentication using Python's cryptography library.

## Features
- **RSA Key Exchange**: Generates RSA key pairs for secure AES key exchange between users.
- **AES Encryption**: Utilizes AES in CBC mode for data confidentiality.
- **HMAC Authentication**: Ensures message integrity and authenticity with HMAC using SHA-256.
- **Padding**: Implements PKCS#7 padding for AES encryption compatibility.
- **Cryptographic Best Practices**: Follows modern cryptographic standards using the `cryptography` library.

## Getting Started.
1. Install the required library:
   ```bash
   pip install cryptography
