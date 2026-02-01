Siap 👍
Untuk repo **ECDH + AES-256-GCM demo** seperti punyamu, isi `README.md` sebaiknya **ringkas, akademis, dan enak dibaca dosen/reviewer**. Aku kasih **template siap pakai** (tinggal copy-paste).

---

## Contoh `README.md` (Recommended)

````md
# ECDH + AES-256-GCM Secure Communication Demo

This repository demonstrates a **secure communication channel** using  
**Elliptic Curve Diffie–Hellman (ECDH)** for key exchange and  
**AES-256-GCM** for authenticated encryption, implemented in **C++ (OpenSSL)**.

The demo simulates two parties — **Moniq** and **Resya** — establishing a shared secret,
deriving a symmetric key, and securely exchanging an encrypted message.

---

## 🔐 Cryptographic Overview

- **Key Exchange**: ECDH (NIST P-256 / secp256r1)
- **Key Derivation**: HKDF with SHA-256
- **Symmetric Encryption**: AES-256-GCM (AEAD)
- **Randomness Source**: OpenSSL `RAND_bytes`
- **Library**: OpenSSL 3.x

---

## 🧩 Protocol Flow

1. Moniq generates an ephemeral ECDH key pair  
2. Resya generates an ephemeral ECDH key pair  
3. Public keys are exchanged  
4. Both parties derive the same shared secret  
5. Shared secret is expanded using HKDF-SHA-256  
6. AES-256-GCM is used to encrypt and authenticate messages  

---

## 🛠️ Build & Run

### Requirements
- C++17 compatible compiler
- OpenSSL 3.x
- MinGW / MSYS2 (Windows) or GCC/Clang (Linux)

### Compile (Windows – MSYS2 MinGW64)
```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 ecdh_demo.cpp -o ecdh_demo -lcrypto
````

### Run

```bash
./ecdh_demo
```

---

## 📌 Example Output

```text
[1/4] Generating ECDH key pairs (P-256)...
[2/4] Exchanging public keys...
   Moniq public key: 65 bytes
   Resya public key: 65 bytes
[3/4] Deriving shared secret and AES key...
   Shared secret: 32 bytes
   AES-256 key:    32 bytes
[4/4] Encrypting and decrypting message...
   Decrypted message : "Hello Resya, this channel is secure."

[OK] ECDH + AES-GCM completed successfully.
```

---

## 🧠 Security Properties

* **Forward Secrecy** (ephemeral ECDH keys)
* **Confidentiality** (AES-256)
* **Integrity & Authenticity** (GCM authentication tag)
* **Key Separation & Domain Separation** via HKDF
* **Constant-time primitives** handled by OpenSSL

---

## ⚠️ Notes

* This demo performs **unauthenticated ECDH**
* It is vulnerable to Man-in-the-Middle (MITM) attacks without authentication
* See the report for TLS-like authentication extensions (ECDSA + certificates)

---

## 📚 Educational Purpose

This project is intended for:

* Cryptography coursework
* Secure protocol demonstrations
* Learning OpenSSL EVP APIs
* Understanding ECDH + AEAD design patterns

---

## 👤 Author

**Gabrielle Briliant Lintong**
Information Technology – Cyber Security
President University

---

## 📄 License

This project is provided for **educational purposes only**.

```
