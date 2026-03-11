# Cryptography Lab

## Overview

This lab introduces applied cryptography using C and OpenSSL. You will work with three standalone programs, each targeting a different class of cryptographic operation. All three programs share `common.c` and `common.h`, which provide reusable wrappers around the raw OpenSSL EVP API. You are not expected to implement those wrappers; your job is to use them correctly inside each task file.

By the end of the lab you will have:

- Encrypted and decrypted text files using a symmetric key (AES-128-CBC with HMAC-SHA256)
- Encrypted BMP images column-by-column and observed the visual difference between ECB and CBC modes
- Hashed file data with SHA-256, encrypted the digest with RSA-OAEP, and produced and verified an RSA-PSS signature

  --

## Prerequisites

You need GCC and OpenSSL development headers installed.

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install gcc libssl-dev
```

**macOS (Homebrew):**

```bash
brew install openssl
```

The Makefile on macOS automatically picks up the Homebrew OpenSSL prefix via `brew --prefix openssl`, so no manual flag editing is needed.

## Repository Structure

```
.
├── Makefile
├── common.h              # Shared declarations — read this carefully
├── common.c              # Shared implementation — do not modify
├── 1_encrypt_text.c      # Part 1: symmetric encryption
├── 2_encrypt_image.c     # Part 2: block cipher modes
├── 3_sign_digest.c       # Part 3: hashing, RSA encryption, RSA signing
├── original_files/       # Input files provided to you
│   ├── shorttext.txt
│   ├── longtext.txt
│   ├── SUTD.bmp
│   └── triangle.bmp
└── output/               # Created automatically when you run each program
```

## Building

To compile all three programs at once:

```bash
make
```

To compile a single program:

```bash
make 1_encrypt_text
make 2_encrypt_image
make 3_sign_digest
```

To remove all compiled binaries and the `output/` directory:

```bash
make clean
```

## Part 1: Symmetric Text Encryption (`1_encrypt_text.c`)

### What this program does

The program generates a random 32-byte session key, then encrypts two text files and decrypts them back. Encrypted output is written as Base64 text so it is printable. The decrypted files should be byte-for-byte identical to the originals.

### What to observe

After implementing and running `./1_encrypt_text` you should see output like:

```
Original byte length: 47
Encrypted byte length: 95
```

Note that the encrypted length is always larger than the plaintext. Account for the 16-byte IV, PKCS7 padding on the ciphertext, and the 32-byte HMAC appended at the end.

Verify that `output/dec_shorttext.txt` and `output/dec_longtext.txt` are identical to their originals. Any mismatch in the key or the token layout will cause HMAC verification to fail and `session_decrypt()` will return NULL.

### Questions to test your understanding

- Why does encrypting the same file twice (with the same key) produce a different `enc_shorttext.txt` each time?
- What is the minimum possible encrypted length for a 0-byte input?
- What happens if you corrupt one byte of the Base64 ciphertext and then attempt decryption?

## Part 2: Image Encryption (`2_encrypt_image.c`)

### What this program does

The program encrypts a 24-bit BMP image **column by column** using 3DES in either ECB or CBC mode. The key and IV are hardcoded. It produces eight output images: two source images, two traversal orders (top-down and bottom-up), two cipher modes (4 combinations each).

### Understanding the column-by-column approach

Each column is extracted as a byte array (3 bytes per pixel, height pixels), padded to an 8-byte boundary with PKCS7, then encrypted with 3DES. The encrypted bytes are written back into the output image in place of the original pixel data.

This is intentional. By operating on columns rather than the full image at once, you can see clearly how ECB and CBC handle repeating data patterns.

### What to observe

After completing the tasks and running the compiled output, open the output images in any image viewer.

**ECB outputs** (`enc_*_ecb_*.bmp`): The image structure is still partially visible. Regions of the image that have uniform or repeating pixel columns produce identical ciphertext columns, so edges and solid areas remain recognisable. This is the classic ECB weakness.

**CBC outputs** (`enc_*_cbc_*.bmp`): The image looks like random noise. Because each column's ciphertext feeds into the XOR of the next column's encryption, identical input columns produce completely different output.

**Bottom-up vs top-down**: These differ in which end of the column is processed first. With CBC, this changes which column feeds the IV into the chain, so the two directions produce visually different noise even though the same key is used.

### Questions to test your understanding

- Explain why ECB leaks image structure but CBC does not.
- If you encrypt the same BMP twice with CBC and the same key and IV, do you get the same output? Why or why not?
- Why does the PKCS7 padding always add at least one byte, even when the data is already aligned to the block size?

## Part 3: Signed Digests (`3_sign_digest.c`)

### What this program does

The program generates a fresh RSA-1024 key pair in memory, then performs two separate exercises on each of the two text files:

1. `enc_digest`: computes SHA-256 of the file, encrypts the 32-byte digest with the RSA public key (OAEP padding), decrypts it back with the private key, and checks the round-trip
2. `sign_digest`: signs the raw file data with the RSA private key (PSS padding, SHA-256), then verifies the signature with the public key

### What to observe

After competing the tasks here, run `./3_sign_digest` several times. Notice:

- The SHA-256 digest of each file is the same every run (deterministic).
- The RSA-OAEP encrypted digest is different every run (randomised padding).
- The PSS signature is different every run (randomised salt).
- Decryption and verification still succeed every run despite the randomness.

### Questions to test your understanding

- The digest of `longtext.txt` is the same length as the digest of `shorttext.txt`. Why?
- OAEP encryption of the 32-byte digest produces 128 bytes. What accounts for the 96 bytes of overhead?
- PSS signing produces a different 128-byte signature each time. How does verification recover the correct result without knowing the salt in advance?
- Why would it be a mistake to use the same key pair to encrypt data (CP1 in PA2) and also sign data (AP in PA2)?

## Running All Three Programs

```bash
make
./1_encrypt_text
./2_encrypt_image
./3_sign_digest
```

All output is written to the `output/` directory. The directory is created automatically if it does not exist.

## Connecting to PA2

This lab directly prepares you for Programming Assignment 2. The relationship is as follows:

| Lab                                           | PA2 Counterpart                                                                                  |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Part 1: `session_encrypt` / `session_decrypt` | CP2 file transfer (symmetric encryption after key exchange)                                      |
| Part 2: ECB vs CBC visual analysis            | Background for understanding why CBC is used in CP2                                              |
| Part 3: RSA sign + verify                     | Authentication Protocol (AP)                                                                     |
| Part 3: RSA encrypt + decrypt                 | CP1 file transfer (RSA encrypts file chunks) and CP2 key exchange (RSA encrypts the session key) |

In PA2, `common.c` is compiled alongside your client and server source files unchanged. The same functions you call in this lab (`session_encrypt`, `rsa_encrypt_block`, `sign_message_pss`, `verify_message_pss`, `load_cert_bytes`, `verify_server_cert`) are the ones you will call in your network code.
