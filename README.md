# GoCrypt - Fast and Secure File Encryption

This is a high-performance file encryption tool written in Go. It encrypts files in parallel using AES-GCM, derives keys with Argon2id, and authenticates everything with a final HMAC-SHA256 tag for full-file integrity.

---

## How It Works

1. **Header** – Contains salt, nonce base, chunk size.
2. **Key Derivation** – Password is expanded into a 256-bit key using Argon2id.
3. **Encryption** – File is split into chunks, each encrypted with AES-GCM:

   - Nonce = `NonceBase || chunk_index`
   - AAD = `SHA256(headerRaw) || chunk_index`
   - Framing: `4-byte little-endian length || ciphertext`

4. **Authentication** – An HMAC-SHA256 is computed over: `headerRaw || (len || ciphertext)` for every chunk
5. **Trailer** – Final 32-byte HMAC tag appended at EOF.

---

## Tech Stack

- **Language**: Go (Golang)
- **Crypto**: AES-GCM, Argon2id, HMAC-SHA256
- **Concurrency**: Goroutines, worker pools

---

## Security Guarantees

- AES-GCM provides confidentiality and per-chunk authenticity
- Final HMAC provides whole-file integrity against truncation, reordering, splicing.
- Argon2id (t=3, m=64 MiB, p=4) adds strong resistance against GPU/ASIC password cracking — **effective only with a high-entropy passphrase**.
- Nonce wrapping is detected and prevented

---

## Example Encryption/Decryption

![Log Screenshot](docs/logs.png)

## Post-Quantum Note

- **AES-256** and **HMAC-SHA-256** remain robust under Grover’s algorithm (≈128-bit effective security).
- Argon2id remains memory-hard; **strong passphrase** is needed regardless.
