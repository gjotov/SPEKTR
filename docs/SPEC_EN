# SPEKTR-26 Cryptosystem Technical Specification

## 1. Overview
**SPEKTR-26** is a modular, high-security symmetric cryptosystem implemented in Rust. It specializes in **steganographic data encapsulation** and **plausible deniability**. The system is designed to provide secure data storage that is invisible to forensic analysis and resilient against physical coercion.

## 2. Key Derivation Hierarchy
### 2.1 Hardware Entanglement (Silicon DNA)
The system binds the encryption process to the specific hardware of the host machine. 
- **Source:** Machine UUID (Motherboard/CPU serials).
- **Transformation:** `Hardware_DNA = SHA-256(Machine_UID)`.
This prevents unauthorized decryption on any device other than the one used for encryption.

### 2.2 Key Derivation Function (KDF)
To mitigate brute-force and dictionary attacks, SPEKTR-26 uses **Argon2id**.
- **Input:** User Password + Hardware DNA.
- **Output:** 512-bit raw key material, split into:
  - `Cipher_Key` (256-bit)
  - `MAC_Key` (256-bit)
- **Parameters:** $m=64MB, t=3, p=1$.

## 3. Cryptographic Core
### 3.1 Deterministic Chaos Engine
A fixed-point (Q32) **Logistic Map** generates the internal entropy:
$$x_{n+1} = 4.0 \cdot x_n \cdot (1 - x_n)$$
This ensures mathematical chaos remains identical across different CPU architectures without floating-point drift.

### 3.2 Substitution-Permutation Network (SPN)
- **Dynamic S-Box:** Generated via a chaos-driven Fisher-Yates shuffle. No static tables are used.
- **Constant-Time Substitution:** Lookups are performed via bit-masking to prevent cache-timing side-channel attacks.
- **Polyphase Diffusion (P-Box):** A 128-bit permutation layer using ARX (Add-Rotate-Xor) operations to ensure the **Strict Avalanche Criterion (SAC)**.

## 4. Encapsulation & Steganography
### 4.1 WAV Carrier
The system hides the ciphertext within a valid **8-bit Mono LPCM WAV** file. 
- **Stealth:** The encrypted payload replaces the audio data, appearing as low-level radio interference or white noise.
- **Zero Metadata:** No internal headers, magic numbers, or length markers exist within the encrypted stream.

### 4.2 AEAD (Authenticated Encryption)
SPEKTR-26 follows the **Encrypt-then-MAC** paradigm:
1. **Encryption:** Chunked CTR (Counter) mode with 128-bit blocks.
2. **Authentication:** HMAC-SHA256 tag computed over the Nonce and Ciphertext.

## 5. Defense Protocols
### 5.1 Plausible Deniability
The container supports a **Double-Bottom** architecture:
- **Decoy Slot:** Revealed by the decoy password.
- **Real Slot:** Hidden within the high-entropy noise. Its presence cannot be proven without the master key.

### 5.2 Panic Protocol (Scorched Earth)
If the **Panic Key** is triggered, the system:
1. Returns the decoy data to the user.
2. Initiates a background **multi-threaded shredding** process.
3. Overwrites the container with random noise and unlinks the file from the filesystem.

---
**Status:** Miri-verified | Memory-safe (Rust) | Production-ready PoC.