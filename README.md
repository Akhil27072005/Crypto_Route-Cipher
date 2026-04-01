# Route cipher + hash (assignment README)

## Brief theory

**Cipher (route / transposition).** Plaintext is combined with a short tag, written into a rectangular grid in row-major order (padding if needed), then read off along a fixed **clockwise spiral** from the outside inward. Decryption reverses that: ciphertext refills the grid along the same spiral, the grid is read row-wise, padding is stripped, and the tag is recovered. Security is limited: it is classical transposition with a public route and no secret key, so it illustrates routing permutations rather than modern confidentiality.

**Hash.** All steps use **32-bit unsigned** arithmetic: every `+`, `^`, `<<`, `>>`, and `*` wraps modulo **2^32** (same as `uint32_t` in C++).

**Symbols**

| Symbol | Meaning |
|--------|---------|
| `n` | Length of the input string (number of bytes). |
| `v[i]` | Numeric value of byte `i`, range 0…255 (as in `(unsigned char)input[i]`). |
| `h` | Running 32-bit hash state. |
| `^` | Bitwise XOR (same as ⊕ in math notation). |
| `<<`, `>>` | Bitwise shifts on 32-bit values. |

**Algorithm**

1. **Initialize:** `h ← 2654435769` (hex `0x9E3779B9`).

2. **Mix in each byte** for `i = 0` … `n − 1`:

   ```
   m = (h << 5) + (h >> 2) + v[i] + i
   h = h ^ m
   ```

   `(h << 5) + (h >> 2)` spreads bits of the current state. Adding `v[i]` injects the message byte; adding `i` makes the same byte value affect the state differently at different positions.

3. **Finalize** (avalanche):

   ```
   h = h ^ (h >> 16)
   h = (h * 0x45D9F3B) & 0xFFFFFFFF    // K = 0x45D9F3B = 73244475 decimal
   h = h ^ (h >> 16)
   ```

   The two `^ (h >> 16)` steps fold the upper and lower 16 bits. Multiplying by the odd constant `K` spreads bit differences across the word before the last fold.

4. **Output:** write `h` as **8 uppercase hex digits** (leading zeros kept). That string is appended to the plaintext before the route cipher; decryption recomputes `h` from the recovered plaintext and compares. This is a small **integrity tag** for the lab, not a collision-resistant cryptographic hash (e.g. SHA-256).

## How to run

From this folder, with **no extra arguments** so you get the menu (encrypt, decrypt, etc.):

```bash
g++ -std=c++17 -O2 route_cipher.cpp -o route_cipher.exe
./route_cipher.exe
```

---

## Worked example 1

| Field | Value |
|--------|--------|
| **Plaintext** | `Hello` |
| **Key** | None — route is fixed (clockwise spiral from top-left); grid size follows the length of plaintext + 8-hex hash. |
| **Ciphertext** | `Hell29XXXDFo7E71` |
| **Hash (8 hex)** | `7E2F179D` |

```
=== ENCRYPT (step-by-step) ===
Plaintext: [Hello]
Step 1) Hash (8 hex chars): 7E2F179D
Step 2) Combined (plaintext+hash): [Hello7E2F179D]
        Combined length: 13
Step 3) Grid dimensions: rows=4, cols=4
Step 4) Fill grid row-wise (pad with 'X'):
Grid (4x4):
  H e l l
  o 7 E 2
  F 1 7 9
  D X X X
Step 5) Read grid in clockwise spiral => Ciphertext:
Hell29XXXDFo7E71

=== DECRYPT (step-by-step) ===
Ciphertext: [Hell29XXXDFo7E71]
Ciphertext length: 16
Step 1) Grid dimensions from ciphertext length: rows=4, cols=4
Step 2) Fill grid in clockwise spiral:
Grid (4x4):
  H e l l
  o 7 E 2
  F 1 7 9
  D X X X
Step 3) Read grid row-wise => Combined (with padding): [Hello7E2F179DXXX]
Step 4) Trim trailing padding 'X': trimmed=3
        Combined (trimmed): [Hello7E2F179D]
Step 5) Extract last 8 chars as hash:
        Plaintext: [Hello]
        Extracted hash: 7E2F179D
Step 6) Recompute hash(plaintext): 7E2F179D
Step 7) DECRYPT: compare recomputed vs extracted => VALID
```

---

## Worked example 2

| Field | Value |
|--------|--------|
| **Plaintext** | `This is sample sentence to be encrypted` |
| **Key** | None — same fixed spiral route; grid size from plaintext + 8-hex hash length. |
| **Ciphertext** | `This isenby6XX1218Cpec  sample r5Fdet esentocne t` |
| **Hash (8 hex)** | `F56C8121` |

```
=== ENCRYPT (step-by-step) ===
Plaintext: [This is sample sentence to be encrypted]
Step 1) Hash (8 hex chars): F56C8121
Step 2) Combined (plaintext+hash): [This is sample sentence to be encryptedF56C8121]
        Combined length: 47
Step 3) Grid dimensions: rows=7, cols=7
Step 4) Fill grid row-wise (pad with 'X'):
Grid (7x7):
  T h i s   i s
    s a m p l e
    s e n t e n
  c e   t o   b
  e   e n c r y
  p t e d F 5 6
  C 8 1 2 1 X X
Step 5) Read grid in clockwise spiral => Ciphertext:
This isenby6XX1218Cpec  sample r5Fdet esentocne t

=== DECRYPT (step-by-step) ===
Ciphertext: [This isenby6XX1218Cpec  sample r5Fdet esentocne t]
Ciphertext length: 49
Step 1) Grid dimensions from ciphertext length: rows=7, cols=7
Step 2) Fill grid in clockwise spiral:
Grid (7x7):
  T h i s   i s
    s a m p l e
    s e n t e n
  c e   t o   b
  e   e n c r y
  p t e d F 5 6
  C 8 1 2 1 X X
Step 3) Read grid row-wise => Combined (with padding): [This is sample sentence to be encryptedF56C8121XX]
Step 4) Trim trailing padding 'X': trimmed=2
        Combined (trimmed): [This is sample sentence to be encryptedF56C8121]
Step 5) Extract last 8 chars as hash:
        Plaintext: [This is sample sentence to be encrypted]
        Extracted hash: F56C8121
Step 6) Recompute hash(plaintext): F56C8121
Step 7) DECRYPT: compare recomputed vs extracted => VALID
```
