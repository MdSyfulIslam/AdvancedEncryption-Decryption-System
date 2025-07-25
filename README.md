# 🔐 Advanced Encryption-Decryption System (Web-Based)

A browser-based encryption and decryption tool that implements **AES**, **RSA**, and **Caesar Cipher** algorithms. Designed for educational and demonstration purposes, this project helps users explore both modern and classical encryption techniques via a simple, responsive web interface. This project was developed as part of the Computer and Cyber Security (CSE 323) course at Green University of Bangladesh.

---

## 📋 Table of Contents

- [🔍 Project Overview](#-project-overview)
- [🎯 Features](#-features)
- [⚙️ Tools & Technologies](#️-tools--technologies)
- [🧠 Algorithms Used](#-algorithms-used)
- [📊 Testing & Results](#-testing--results)
- [🧪 Limitations](#-limitations)
- [📈 Future Improvements](#-future-improvements)
- [👨‍💻 Authors](#-authors)
- [📎 References](#-references)

---

## 🔍 Project Overview

This **Advanced Encryption-Decryption System** is a **web-based application** that allows users to securely encrypt and decrypt messages using:

- 🔐 AES (Advanced Encryption Standard)  
- 🔐 RSA (Rivest–Shamir–Adleman)  
- 🔐 Caesar Cipher  

The tool helps students and security enthusiasts explore encryption logic with real-time feedback using a user-friendly interface.

---

## 🎯 Features

- 🔑 Encrypt and decrypt messages using AES, RSA, or Caesar Cipher  
- 🔐 Auto-generated keys for RSA; user-provided keys for AES and Caesar  
- 🧪 Real-time encryption-decryption via client-side JavaScript  
- 📥 Auto-fill encrypted output for decryption testing  
- 📦 Minimal, responsive single-page web design  
- 📚 Educational comparison of algorithm strengths and performance  

---

## ⚙️ Tools & Technologies

- **HTML5** – Page structure  
- **CSS3** – Styling and layout  
- **JavaScript (Vanilla)** – Encryption logic and interactivity  
- **CryptoJS Library** – AES implementation  
- **Browser Environment** – Runs locally on modern web browsers (Chrome, Firefox, etc.)

---

## 🧠 Algorithms Used

### 🔐 AES (Advanced Encryption Standard)
- Symmetric encryption with a user-defined password
- 256-bit key generation using CryptoJS
- Strong security but depends on password strength

### 🔐 RSA (Rivest–Shamir–Adleman)
- Asymmetric encryption using public/private keys
- Small primes used for demo purposes (p=61, q=53)
- Public key `(e, n)` and private key `(d, n)`
- Slower but more secure than symmetric ciphers

### 🔐 Caesar Cipher
- Historical substitution cipher
- Shifts characters by a fixed number (1–25)
- Low security, used only for demonstration

---

## 📊 Testing & Results

### ⏱️ Performance Benchmarks

| Algorithm       | 100 Chars | 1000 Chars | Notes                            |
|----------------|------------|-------------|----------------------------------|
| AES            | ~5ms       | ~12ms       | Fast, strong encryption          |
| RSA            | ~10ms      | ~25-30ms    | Slower, suitable for small data  |
| Caesar Cipher  | <1ms       | <1ms        | Fastest but least secure         |

### 🛡️ Security Observations

- **AES** offers high security but is vulnerable to weak passwords  
- **RSA** is secure in concept but demo uses small primes (not production safe)  
- **Caesar** is easy to crack and only useful for learning  

---

## 🧪 Limitations

- ❌ RSA implementation uses small primes (not safe for real encryption)
- ❌ Entirely client-side: keys exposed in browser memory
- ❌ No file or message persistence
- ❌ Caesar Cipher included for learning only
- ❌ No authentication or access control

---

## 📈 Future Improvements

- 🔐 Use larger primes and secure key generation for RSA  
- ☁️ Move sensitive processing to a backend server (e.g., Flask, Node.js)  
- 💾 Add encrypted message storage or file export  
- 📱 Build a mobile-friendly version or standalone desktop app  
- 🧪 Add message integrity checks and validation messages  
- 🔐 Add password strength indicators and encryption analytics  

---

## 👨‍💻 Authors
**Md Syful Islam**  Student ID : 222002111
**Tasdid Rahman Khan**  Student ID : 222002029
**Sazzad Hossain**  Student ID : 221002464

📚 B.Sc. in CSE (Day), Green University of Bangladesh  
🧑‍🏫 **Course:** Computer and Cyber Security  
👨‍🏫 **Instructor:** Md. Sabbir Hosen Mamun  
📚 **Section:** 222-D4  
📅 **Submitted on:** 01 May 2025  

---

## 📎 References

1. [RSA Algorithm – GeeksForGeeks](https://www.geeksforgeeks.org/rsa-algorithm-cryptography/)  
2. [Advanced Encryption Standard – TutorialsPoint](https://www.tutorialspoint.com/cryptography/advanced-encryption-standard.htm)  
3. [Crypto Basics – TechTarget](https://www.techtarget.com/searchsecurity/definition/cipher)  

