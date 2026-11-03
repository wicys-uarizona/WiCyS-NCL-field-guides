# Cryptography CTF Cheat Sheet

**Author:** Alec Teran ([@astolica](https://github.com/astolica))
**Last updated:** November 2026
**License:** Free to share and use. Credit appreciated.

A field reference for crypto challenges in CTFs: how to recognize what you're looking at, which attack applies, and the code to run it.

---

## Table of Contents

1. [Triage Workflow](#1-triage-workflow)
2. [Encodings and Bytes](#2-encodings-and-bytes)
3. [Classical Ciphers](#3-classical-ciphers)
4. [XOR](#4-xor)
5. [RSA](#5-rsa)
6. [Block Ciphers and Modes (AES)](#6-block-ciphers-and-modes-aes)
7. [Stream Ciphers and PRNGs](#7-stream-ciphers-and-prngs)
8. [Hashes and MACs](#8-hashes-and-macs)
9. [Discrete Log, Diffie-Hellman, ECC](#9-discrete-log-diffie-hellman-ecc)
10. [Math Toolbox](#10-math-toolbox)
11. [Tools and Resources](#11-tools-and-resources)

---

## 1. Triage Workflow

1. **Read the source.** If the challenge ships a script, the bug is almost always in it. Look for reused nonces, small parameters, custom "improvements," and oracles.
2. **Identify the data.** Character set and length tell you a lot (see table below).
3. **Strip layers.** Chained encodings (hex, then Base64, then ROT13) are common. Decode until it stops changing.
4. **Know the flag format.** `flag{`, `picoCTF{`, `CTF{` give you known plaintext for XOR, stream ciphers, and crib dragging.
5. **Search the weirdness.** A strange constant, exponent, or curve parameter is usually the vulnerability.

### Recognize the data

| Looks like | Probably |
|---|---|
| `0-9a-f`, even length | Hex |
| `A-Za-z0-9+/`, ends in `=` or `==`, length % 4 == 0 | Base64 |
| `A-Za-z0-9-_` | URL-safe Base64 |
| `A-Z2-7`, padded with `=` | Base32 |
| `1-9A-HJ-NP-Za-km-z` (no `0OIl`) | Base58 |
| Only `0` and `1`, groups of 8 | Binary ASCII |
| `.` `-` and spaces or `/` | Morse |
| Letters only, word spacing kept | Caesar, Vigenere, or substitution |
| `<~ ... ~>` | Ascii85 / Base85 |
| `++++[>+++<-]` | Brainfuck (esolang, not crypto, but it shows up) |
| 32 hex chars | MD5 / 128-bit value / one AES block |
| 40 hex chars | SHA-1 |
| 64 hex chars | SHA-256 |
| `$2a$`, `$2b$` | bcrypt |
| `$1$`, `$5$`, `$6$` | md5crypt, sha256crypt, sha512crypt |
| Huge decimal ints labeled `n`, `e`, `c` | RSA |
| Length a multiple of 16 bytes | AES (block cipher) |

---

## 2. Encodings and Bytes

### Python one-liners

```python
import base64, binascii, codecs

bytes.fromhex("666c6167")            # b'flag'
b"flag".hex()                        # '666c6167'
base64.b64decode("ZmxhZw==")         # b'flag'
base64.b64encode(b"flag")            # b'ZmxhZw=='
base64.b32decode("MZWGCZY=")         # b'flag'
base64.a85decode(data)               # Ascii85
codecs.decode("synt", "rot_13")      # 'flag'

int.from_bytes(b"flag", "big")       # 1718378855
(1718378855).to_bytes(4, "big")      # b'flag'

ord("A"), chr(65)                    # 65, 'A'
```

### PyCryptodome helpers (most common in CTF source)

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
long_to_bytes(m)      # int  -> bytes (use for RSA plaintexts)
bytes_to_long(b"hi")  # bytes -> int
```

### ASCII facts worth memorizing

| Range | Values |
|---|---|
| `0-9` | 48-57 (`0x30-0x39`) |
| `A-Z` | 65-90 (`0x41-0x5A`) |
| `a-z` | 97-122 (`0x61-0x7A`) |
| Space | 32 (`0x20`) |
| Printable | 32-126 |

- Upper and lowercase differ by exactly **`0x20` (bit 5)**. `ord('a') ^ ord('A') == 0x20`.
- XOR output that is readable but has **flipped case** means `0x20` is part of the key.
- Letter XOR space flips case: `'a' ^ ' ' == 'A'`. Useful for crib dragging.

### Endianness

```python
import struct
struct.unpack("<I", b"\x01\x00\x00\x00")[0]   # 1  (little-endian)
struct.unpack(">I", b"\x00\x00\x00\x01")[0]   # 1  (big-endian)
int.from_bytes(data, "little")
```

---

## 3. Classical Ciphers

| Cipher | Tell | Attack |
|---|---|---|
| Caesar / ROT-N | Letter frequencies shifted | Try all 26 shifts |
| ROT13 | Caesar with 13 | `codecs.decode(s, "rot_13")` |
| ROT47 | Mangled printable ASCII (`!` to `~`) | Rotate within 33-126 |
| Atbash | A<->Z, B<->Y | Reverse alphabet |
| Affine | `E(x) = (a*x + b) mod 26` | Brute force 12 x 26 keys |
| Monoalphabetic substitution | Natural frequency profile, scrambled letters | Frequency analysis, quipqiup |
| Vigenere | Flattened frequency, repeating patterns | Kasiski / Index of Coincidence, then per-column Caesar |
| Rail fence | All plaintext letters present, scrambled order | Try rail counts 2 to ~10 |
| Columnar transposition | Same as above, block-shaped | Anagram columns, try key lengths |
| Bacon | Only two symbols (A/B, case, fonts) in groups of 5 | Map to binary |
| Playfair | Even length, no double letters in pairs, no J | Known 5x5 key or hill climbing |
| Polybius / Tap code | Digits 1-5 in pairs | Grid lookup |

### Caesar brute force

```python
def caesar(s, k):
    out = []
    for c in s:
        if c.isupper():   out.append(chr((ord(c) - 65 + k) % 26 + 65))
        elif c.islower(): out.append(chr((ord(c) - 97 + k) % 26 + 97))
        else:             out.append(c)
    return "".join(out)

for k in range(26):
    print(k, caesar(ct, k))
```

### Vigenere decrypt (known key)

```python
def vig_dec(ct, key):
    out, i = [], 0
    for c in ct:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = ord(key[i % len(key)].lower()) - 97
            out.append(chr((ord(c) - base - k) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)
```

### Index of Coincidence

- English text: **~0.066**. Random / polyalphabetic: **~0.038**.
- For Vigenere, split ciphertext into `n` columns for each candidate key length; the right `n` gives columns with IoC near 0.066.

English letter frequency (most to least): `ETAOINSHRDLCUMWFGYPBVKJXQZ`

---

## 4. XOR

### Properties

```
a ^ a = 0        a ^ 0 = a        a ^ b = b ^ a
(a ^ b) ^ b = a  -> if you know any two of (pt, key, ct), you get the third
```

### Repeating-key XOR

```python
from itertools import cycle
def xor(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))
```

### Single-byte XOR brute force with scoring

```python
FREQ = "etaoin shrdlu"
def score(b):
    return sum(ch in FREQ for ch in b.decode("latin-1").lower())

best = max(range(256), key=lambda k: score(bytes(c ^ k for c in ct)))
print(best, bytes(c ^ best for c in ct))
```

### Known-plaintext key recovery (the flag-format trick)

```python
known = b"flag{"
partial_key = xor(ct[:len(known)], known)
print(partial_key)   # often reveals the whole repeating key or its pattern
```

### Repeating-key XOR with unknown key length

1. For each keysize 2-40, compute normalized **Hamming distance** between adjacent blocks. Smallest few are likely key lengths.
2. Transpose: column `i` = every `keysize`-th byte starting at `i`.
3. Solve each column as single-byte XOR.

```python
def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
```

### Many-time pad (reused key / nonce)

- `c1 ^ c2 == p1 ^ p2`. The key disappears.
- **Crib drag:** XOR a guessed word (`" the "`, `"flag{"`) across every offset of `c1 ^ c2` and look for readable output.
- With many ciphertexts, treat column-wise like single-byte XOR; spaces flip letter case, which leaks key bytes.

### Tools

- `xortool -l <len> -c 20 file` (guesses key length and key assuming space is most common char)
- CyberChef "XOR Brute Force"

---

## 5. RSA

### Core

```
n = p * q            phi = (p-1)(q-1)
d = e^-1 mod phi     c = m^e mod n       m = c^d mod n
```

```python
from Crypto.Util.number import long_to_bytes
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)            # Python 3.8+
m = pow(c, d, n)
print(long_to_bytes(m))
```

### Attack decision table

| Symptom | Attack |
|---|---|
| `n` is small (< ~256 bits) or in factordb | Factor it: factordb.com, `sympy.factorint`, yafu, cado-nfs |
| `e` is small (3) and `m^e < n` | **Cube root:** `m = iroot(c, e)` |
| Same `m` sent with small `e` to `e` different moduli | **Hastad broadcast:** CRT, then e-th root |
| Same `n`, two different `e`, same `m` | **Common modulus:** `gcd(e1,e2)=1`, Bezout |
| Several `n` values | **Common factor:** `gcd(n1, n2)` |
| `p` and `q` very close together | **Fermat factorization** |
| `e` is huge (close to `n`) | **Wiener** (small `d`) or Boneh-Durfee |
| `p - 1` is smooth | **Pollard p-1** |
| `n` is prime, or `n = p^k` | `phi = n-1` or `phi = p^(k-1)(p-1)` |
| Multi-prime `n = p*q*r...` | `phi = product(pi - 1)` |
| `gcd(e, phi) != 1` | Take roots mod each prime (e.g. `nthroot_mod`, AMM), combine with CRT |
| Leaked `dp`/`dq` | `p = gcd(pow(2, e*dp, n) - 2, n)` or brute `k` in `e*dp = 1 + k(p-1)` |
| Partial bits of `p` known | **Coppersmith** (SageMath `small_roots`) |
| Known prefix of message, small `e` | Coppersmith stereotyped message |
| Decryption oracle (won't decrypt `c` directly) | **Blinding:** send `c * 2^e mod n`, divide result by 2 |
| Oracle leaks parity / LSB | **LSB oracle** binary search |
| PKCS#1 v1.5 padding-valid oracle | **Bleichenbacher** |
| `.pem` / `.pub` file given | `openssl rsa -pubin -in key.pub -text -noout` or `RSA.import_key` |

### Snippets

```python
# Integer k-th root (gmpy2 is fastest)
import gmpy2
m, exact = gmpy2.iroot(c, 3)

# Common factor across many moduli
from math import gcd
p = gcd(n1, n2)

# Common modulus (same n, same m, coprime e1, e2)
g, a, b = gmpy2.gcdext(e1, e2)          # a*e1 + b*e2 = 1
m = (pow(c1, a, n) * pow(c2, b, n)) % n # Python 3.8+ handles negative exponents

# Hastad broadcast (e = 3)
from sympy.ntheory.modular import crt
M, _ = crt([n1, n2, n3], [c1, c2, c3])
m, _ = gmpy2.iroot(int(M), 3)

# Fermat factorization (p, q close)
def fermat(n):
    a = gmpy2.isqrt(n)
    if a * a < n: a += 1
    while True:
        b2 = a * a - n
        b, exact = gmpy2.iroot(b2, 2)
        if exact:
            return int(a - b), int(a + b)
        a += 1

# Pollard p-1
def pollard_p1(n, B=2**20):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
```

### Go-to tool

[RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) runs most of the above automatically:

```bash
python3 RsaCtfTool.py -n <n> -e <e> --decrypt <c>
python3 RsaCtfTool.py --publickey key.pub --private
```

---

## 6. Block Ciphers and Modes (AES)

AES block size is **16 bytes**. Keys are 16, 24, or 32 bytes.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)
```

### Mode cheat sheet

| Mode | Weakness to look for | Attack |
|---|---|---|
| **ECB** | Identical plaintext blocks give identical ciphertext blocks | Spot repeats ("ECB penguin"); **byte-at-a-time** oracle; cut-and-paste blocks |
| **CBC** | Attacker controls IV or previous ciphertext block | **Bit flipping**; **padding oracle**; IV = key reuse |
| **CTR / OFB / GCM** | Nonce reuse turns it into a many-time pad | XOR ciphertexts (see Section 4) |
| **GCM** | Nonce reuse also leaks auth key `H` | Forbidden attack (forge tags) |
| Any | Key derived from time, small space, or weak hash | Brute force the key |

### Detect ECB

```python
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
is_ecb = len(blocks) != len(set(blocks))
```

### ECB byte-at-a-time (oracle encrypts `input || secret`)

1. Find block size by growing input until ciphertext length jumps.
2. Send `"A" * 15`. The first block is `AAAAAAAAAAAAAAA + secret[0]`.
3. Build a dict of `AAAAAAAAAAAAAAA + x` for all 256 `x`, match the block, and recover `secret[0]`.
4. Shrink padding by one and repeat for each byte.

### CBC bit flipping

Decryption: `P[i] = D(C[i]) ^ C[i-1]`. Flipping a bit in `C[i-1]` flips the same bit in `P[i]` (and garbles `P[i-1]`).

```python
# Turn "role=user" into "role=admin" style edits at position pos in block i
delta = bytes(a ^ b for a, b in zip(known_pt, target_pt))
c = bytearray(ct)
for j, d in enumerate(delta):
    c[(i - 1) * 16 + pos + j] ^= d
```

For block 0, flip bytes in the **IV** instead.

### CBC padding oracle

Server reveals whether padding is valid. For each byte, from last to first:

1. Brute force the byte of a crafted previous block `C'` until padding is valid.
2. Intermediate `I = guess ^ pad_value`; plaintext `P = I ^ C[i-1]`.
3. Recovers full plaintext in at most `256 * 16` queries per block. Tools: `padbuster`, `paddingoracle` Python lib.

### PKCS#7 padding

Pad value = number of pad bytes. `b"YELLOW SUBMARINE"` (16 bytes) gets a whole extra block of `\x10`.

---

## 7. Stream Ciphers and PRNGs

| Target | Weakness | Attack |
|---|---|---|
| Python `random` / MT19937 | Fully determined by 624 32-bit outputs | `randcrack`, `mersenne-twister-predictor`; untemper and clone |
| `random.seed(time.time())` or small seed | Tiny seed space | Brute force timestamps around challenge time |
| LCG `x' = (a*x + c) mod m` | Linear | Recover `m` via gcd of determinants, then `a`, `c` |
| LFSR | Linear over GF(2) | **Berlekamp-Massey** from `2L` output bits |
| RC4 | Biased early bytes, key reuse | Statistical biases, reuse becomes XOR |

### Cloning MT19937

```python
from randcrack import RandCrack
rc = RandCrack()
for _ in range(624):
    rc.submit(observed_32bit_output())
rc.predict_getrandbits(32)
```

### Recovering LCG parameters

```python
# Given consecutive outputs s0..s6, unknown a, c, m
from math import gcd
from functools import reduce
t = [s[i+1] - s[i] for i in range(len(s) - 1)]
u = [abs(t[i+2]*t[i] - t[i+1]**2) for i in range(len(t) - 2)]
m = reduce(gcd, u)
a = (s[2] - s[1]) * pow(s[1] - s[0], -1, m) % m
c = (s[1] - s[0] * a) % m
```

---

## 8. Hashes and MACs

| Situation | Attack |
|---|---|
| Unsalted hash of a password | Lookup (crackstation.net), `hashcat`, `john` with `rockyou.txt` |
| Hash of short/limited input (PIN, single word) | Brute force locally |
| `MAC = H(secret || msg)` with MD5/SHA-1/SHA-256 | **Length extension** (`hashpump`, `hash_extender`) |
| PHP `==` with `0e...` hashes | **Magic hashes** compare equal as `0` (`md5("240610708")`) |
| Need two inputs with same MD5 | Known collisions / `fastcoll`, `hashclash` |
| CRC32 "integrity" | CRC is linear and forgeable, not cryptographic |
| Truncated hash compared | Birthday attack: ~`2^(bits/2)` tries |

### Hashcat modes

| Mode | Hash |
|---|---|
| 0 | MD5 |
| 100 | SHA-1 |
| 1400 | SHA-256 |
| 1700 | SHA-512 |
| 3200 | bcrypt |
| 1000 | NTLM |
| 1800 | sha512crypt |

```bash
hashcat -m 0 -a 0 hash.txt rockyou.txt
hashcat -m 0 -a 3 hash.txt '?d?d?d?d?d?d'    # mask: 6 digits
john --wordlist=rockyou.txt hash.txt
hashid '<hash>'                               # identify hash type
```

### Length extension

```bash
hash_extender --data 'user=guest' --secret 16 --append '&admin=1' \
              --signature <hex_mac> --format sha256
```

Brute force `--secret` length if unknown.

---

## 9. Discrete Log, Diffie-Hellman, ECC

### Discrete log `g^x = h (mod p)`

| Condition | Attack |
|---|---|
| `p - 1` is smooth | **Pohlig-Hellman** |
| Small `x` or small group | **Baby-step giant-step**, Pollard rho |
| General | `sympy.discrete_log(p, h, g)` or SageMath `discrete_log` |

```python
from sympy.ntheory import discrete_log
x = discrete_log(p, h, g)
```

### Diffie-Hellman

- Shared secret `s = g^(ab) mod p`. Need `a` or `b`, so this reduces to discrete log.
- Weak if `p` is small, `p - 1` is smooth, or `g` generates a tiny subgroup.
- If you are man-in-the-middle, you can swap public keys and hold both sessions.

### Elliptic curves (use SageMath)

```python
# Sage
E = EllipticCurve(GF(p), [a, b])
G = E(gx, gy); Q = E(qx, qy)
print(G.order().factor())        # smooth order -> Pohlig-Hellman
k = G.discrete_log(Q)
```

| Curve smell | Attack |
|---|---|
| Group order is smooth | Pohlig-Hellman |
| `E.order() == p` (anomalous) | **Smart's attack** |
| Small embedding degree | **MOV attack** (reduce to finite field DLP) |
| Singular curve (discriminant 0) | Map to additive or multiplicative group |
| Server doesn't validate points | **Invalid curve attack** |
| ECDSA with reused nonce `k` | Two signatures recover `k`, then private key |
| ECDSA with biased / short nonces | Lattice attack (Hidden Number Problem) |

### ECDSA nonce reuse

```python
# Same r in two signatures (r, s1) on z1 and (r, s2) on z2, curve order n
k = (z1 - z2) * pow(s1 - s2, -1, n) % n
d = (s1 * k - z1) * pow(r, -1, n) % n
```

---

## 10. Math Toolbox

```python
from math import gcd, isqrt
pow(a, -1, m)            # modular inverse (Python 3.8+)
pow(a, b, m)             # fast modular exponent

import gmpy2
gmpy2.iroot(x, k)        # (root, is_exact)
gmpy2.is_prime(p)
gmpy2.next_prime(p)

from sympy import factorint, totient, isprime
from sympy.ntheory.modular import crt
from sympy.ntheory.residue_ntheory import nthroot_mod, sqrt_mod
```

### Extended Euclid

```python
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y
```

### Key theorems

- **Fermat:** `a^(p-1) = 1 mod p` for prime `p` not dividing `a`.
- **Euler:** `a^phi(n) = 1 mod n` when `gcd(a, n) = 1`.
- **CRT:** Solutions mod coprime moduli combine into one solution mod their product.
- **Bezout:** `a*x + b*y = gcd(a, b)` always has integer solutions.
- **Lattices / LLL:** If a secret is "small" relative to a modulus, try building a lattice (Sage `Matrix(ZZ, ...).LLL()`). Covers knapsack, HNP, truncated LCG, Coppersmith.

---

## 11. Tools and Resources

### Install

```bash
pip install pycryptodome gmpy2 sympy pwntools randcrack xortool
```

### Toolkit

| Tool | Use |
|---|---|
| [CyberChef](https://gchq.github.io/CyberChef/) | Encoding chains, "Magic" auto-detect |
| [dCode.fr](https://www.dcode.fr/) | Huge catalog of classical ciphers with identifier |
| [quipqiup](https://quipqiup.com/) | Substitution cipher solver |
| [factordb](http://factordb.com/) | Lookup known factorizations |
| [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) | Automated RSA attacks |
| [SageMath](https://www.sagemath.org/) | ECC, lattices, Coppersmith, finite fields |
| [hashcat](https://hashcat.net/) / John the Ripper | Hash cracking |
| [hash_extender](https://github.com/iagox86/hash_extender) | Length extension |
| pwntools | Talking to remote oracles (`remote(host, port)`) |
| `openssl` | Inspect keys and certs |

### Oracle interaction template (pwntools)

```python
from pwn import remote
io = remote("host", 1337)
io.recvuntil(b"> ")
io.sendline(payload.hex().encode())
resp = io.recvline().strip()
```

### Practice

- [CryptoHack](https://cryptohack.org/) (best structured crypto practice)
- [Cryptopals](https://cryptopals.com/) (classic sets; covers most attacks here)
- [picoCTF](https://picoctf.org/) (beginner friendly)
- [CTFtime](https://ctftime.org/) (writeups for past challenges)

---

> **Rule of thumb:** CTF crypto is rarely about breaking the algorithm itself. It is about finding the one place the challenge author used it wrong.

*Compiled by Alec Teran. Good luck and happy hacking.*
