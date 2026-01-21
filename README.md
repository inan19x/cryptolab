# 🧪 Crypto Lab (RSA‑2048 & AES‑256)

> This repository demonstrates **how cryptography works**.
Encrypt & Decrypt (RSA / AES),
Digital sign (RSA),
Signature verification (RSA)

---

# 🧪 Toy Crypto Lab (RSA‑10 & AES‑4)

> **Educational cryptography only — intentionally insecure**.
> This repository demonstrates **how cryptography could breaks** when parameters are too small.

---

## 📌 Overview

This repository contains **toy implementations** of:

* 🔐 **RSA with ~10‑bit modulus** (encryption + digital signatures)
* 🔑 **AES‑like symmetric cipher with 4‑bit key**

The goal is **education**, not security.

By intentionally weakening cryptographic parameters, learners can:

* Observe encryption and decryption step‑by‑step
* Understand **why key size matters**
* See **real cryptographic attacks** in action (+ BONUS : with Shor Algorithm / Quantum attack)
* Safely experiment without risking real systems :-)

---

## ⚠️ IMPORTANT WARNING

🚫 **DO NOT USE THIS CODE FOR REAL SECURITY**

* Keys are trivially breakable
* Attacks are expected to succeed
* This code violates all modern cryptographic standards

✅ This code **is safe for learning and demonstrations**

---

## 📁 Repository Structure

```
cryptolab/
│
├── RSA-10/
│   ├── RSA10_keygen.py
│   ├── RSA10_encrypt.py
│   ├── RSA10_decrypt.py
│   ├── RSA10_sign.py
│   ├── RSA10_verify.py
│   ├── RSA10_crack.py
│   └── RSA10_quantum_crack.py
│
├── AES-4/
│   ├── AES4_keygen.py
│   ├── AES4_encrypt.py
│   ├── AES4_decrypt.py
│   └── AES4_crack.py
│
├── RSA-2048/
│   ├── RSA2048_keygen.py
│   ├── RSA2048_encrypt.py
│   ├── RSA2048_decrypt.py
│   ├── RSA2048_sign.py
│   ├── RSA2048_verify.py
│
├── AES-256/
│   ├── AES256_keygen.py
│   ├── AES256_encrypt.py
│   ├── AES256_decrypt.py
│
└── README.md
```

---

## 🆚 RSA vs AES — Side‑by‑Side

| Feature       | RSA‑10                  | AES‑4         |
| ------------- | ----------------------- | ------------- |
| Crypto type   | Asymmetric              | Symmetric     |
| Key sharing   | Public / Private        | Shared secret |
| Used for      | Encryption & Signatures | Encryption    |
| Attack method | Factoring `n`           | Brute force   |
| Key space     | Tiny                    | Tiny          |
| Outcome       | Broken                  | Broken        |

---

## 🎓 Educational Goals

This project helps learners:

* Understand cryptographic primitives
* See **real attacks**, not just theory
* Learn *why* modern crypto enforces limits
* Build intuition before using real libraries
* Distinguish encryption from authentication

---

## ❓ Why Toy Crypto?

Real cryptography:

* Uses massive key sizes
* Is impossible to break in a classroom
* Hides attack mechanics

Toy cryptography:

* Is transparent
* Is interactive
* Makes attacks observable and intuitive

---

