---
name: cipher-engine
description: Detects and solves text ciphers including Base64, Hex, Binary, Caesar, Vigenere, ROT13, Atbash, Morse, and URL encoding. Supports auto-detection, brute-force key search, and recursive chain decoding.
---

# Cipher Engine Skill

## Overview
Detects and solves a wide range of classical and modern text ciphers. Supports automatic detection when the cipher type is unknown, and brute-force key-space search for ciphers with small key spaces.

## Supported Ciphers

| Cipher        | Detect | Decode | Encode | Notes                                      |
|---------------|--------|--------|--------|--------------------------------------------|
| Base64        | ✅     | ✅     | ✅     | Standard and URL-safe variants             |
| Hex           | ✅     | ✅     | ✅     | Uppercase and lowercase                    |
| Binary        | ✅     | ✅     | ✅     | Space-delimited 8-bit groups               |
| ROT13         | ✅     | ✅     | ✅     | Symmetric; encode == decode                |
| Caesar        | ✅     | ✅     | ✅     | Brute-forces all 25 shifts, scores with IC |
| Vigenere      | ✅     | ✅     | ✅     | Key length detection via Kasiski/IC        |
| Atbash        | ✅     | ✅     | ✅     | Reverse-alphabet substitution              |
| Morse Code    | ✅     | ✅     | ✅     | Dots/dashes with space delimiters          |
| URL Encoding  | ✅     | ✅     | ✅     | %XX percent-encoding                       |
| Base32        | ✅     | ✅     | ✅     | RFC 4648                                   |

## Usage

```bash
# Auto-detect and solve all applicable ciphers
python cipher_tool.py --input "SGVsbG8gV29ybGQ="

# Force a specific cipher
python cipher_tool.py --input "Khoor Zruog" --cipher caesar

# Encode with a cipher
python cipher_tool.py --input "Hello World" --cipher base64 --mode encode

# Vigenere with known key
python cipher_tool.py --input "RIJVS" --cipher vigenere --key "KEY"

# Read input from file
python cipher_tool.py --file puzzles/encoded.txt

# Output results to file
python cipher_tool.py --input "..." --output puzzles/decoded.txt

# Stack multiple ciphers (auto-chain until plaintext)
python cipher_tool.py --input "..." --chain
```

## Arguments

| Argument    | Description                                              |
|-------------|----------------------------------------------------------|
| `--input`   | Encoded string (inline)                                  |
| `--file`    | Path to file containing encoded content                  |
| `--cipher`  | Force specific cipher (base64/hex/binary/caesar/vigenere/rot13/atbash/morse/url/base32) |
| `--mode`    | `decode` (default) or `encode`                           |
| `--key`     | Cipher key for Vigenere; shift amount for Caesar         |
| `--chain`   | Auto-apply detected ciphers recursively until no further decoding possible |
| `--output`  | Write results to file                                    |
| `--verbose` | Show scoring, detection confidence, and intermediate steps |

## Detection Heuristics

- **Base64**: Matches `[A-Za-z0-9+/=]` pattern with length divisible by 4
- **Hex**: All characters in `[0-9a-fA-F]` with even length
- **Binary**: Only `0`, `1`, and spaces with 8-bit group pattern
- **ROT13**: Letter-only, passes IC threshold for English
- **Caesar**: Best-shift selected by Index of Coincidence scoring
- **Vigenere**: Kasiski test + IC analysis determines likely key length
- **Morse**: Contains only `.`, `-`, `/`, and spaces

## Output

Results print to stdout in structured format:
```
=== Cipher Engine Results ===
Input: SGVsbG8gV29ybGQ=
Detected: Base64 (confidence: HIGH)
Decoded:  Hello World

[Chain Step 2 - if --chain enabled]
Input: Hello World
Detected: Plaintext (no further decoding needed)
```
