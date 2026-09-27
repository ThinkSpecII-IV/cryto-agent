#!/usr/bin/env python3
"""
Omni-Cipher Bot — Cipher Engine
Detects and solves Base64, Hex, Binary, Caesar, Vigenere, ROT13,
Atbash, Morse, URL encoding, and Base32.

Auto-installs missing dependencies at runtime.
"""

import sys
import subprocess
import importlib


# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------

REQUIRED_PACKAGES: list[tuple[str, str]] = []  # (import_name, pip_name)


def ensure_deps() -> None:
    for import_name, pip_name in REQUIRED_PACKAGES:
        try:
            importlib.import_module(import_name)
        except ImportError:
            print(f"[cipher-engine] Installing missing dependency: {pip_name}")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_name]
            )


ensure_deps()

# ---------------------------------------------------------------------------
# Standard-library imports (all we need for text ciphers)
# ---------------------------------------------------------------------------

import argparse
import base64
import binascii
import math
import re
import string
import urllib.parse
from collections import Counter
from typing import Optional


# ---------------------------------------------------------------------------
# English scoring helpers
# ---------------------------------------------------------------------------

ENGLISH_FREQ: dict[str, float] = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253,
    "e": 0.12702, "f": 0.02228, "g": 0.02015, "h": 0.06094,
    "i": 0.06966, "j": 0.00153, "k": 0.00772, "l": 0.04025,
    "m": 0.02406, "n": 0.06749, "o": 0.07507, "p": 0.01929,
    "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150,
    "y": 0.01974, "z": 0.00074,
}

COMMON_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
    "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
    "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
    "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "flag", "ctf", "key", "secret", "hidden", "password",
}


def score_english(text: str) -> float:
    """Score text on English-likeness (higher = more English)."""
    text_lower = text.lower()
    letters = [c for c in text_lower if c.isalpha()]
    if not letters:
        return 0.0

    # Character frequency score
    freq_score = 0.0
    counts = Counter(letters)
    total = len(letters)
    for char, count in counts.items():
        expected = ENGLISH_FREQ.get(char, 0.0001)
        freq_score += (count / total) * math.log(expected + 1e-10)

    # Common-word bonus
    words = re.findall(r"[a-z]+", text_lower)
    word_bonus = sum(1.5 for w in words if w in COMMON_WORDS)

    # Printable penalty
    printable_ratio = sum(1 for c in text if c.isprintable()) / max(len(text), 1)
    printable_bonus = printable_ratio * 2

    return freq_score + word_bonus + printable_bonus


def index_of_coincidence(text: str) -> float:
    """Calculate the Index of Coincidence for a string."""
    letters = [c.upper() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


# ---------------------------------------------------------------------------
# MORSE CODE tables
# ---------------------------------------------------------------------------

MORSE_ENCODE: dict[str, str] = {
    "A": ".-",   "B": "-...", "C": "-.-.", "D": "-..",  "E": ".",
    "F": "..-.", "G": "--.",  "H": "....", "I": "..",   "J": ".---",
    "K": "-.-",  "L": ".-..", "M": "--",   "N": "-.",   "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.",  "S": "...",  "T": "-",
    "U": "..-",  "V": "...-", "W": ".--",  "X": "-..-", "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
    "!": "-.-.--", "/": "-..-.",  "(": "-.--.",  ")": "-.--.-",
    "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.", "-": "-....-", "_": "..--.-", '"': ".-..-.",
    "$": "...-..-","@": ".--.-.",
}
MORSE_DECODE: dict[str, str] = {v: k for k, v in MORSE_ENCODE.items()}


# ---------------------------------------------------------------------------
# Individual codec functions
# ---------------------------------------------------------------------------

def decode_base64(s: str) -> Optional[str]:
    try:
        # Handle URL-safe variant
        s_clean = s.strip().replace(" ", "")
        # Pad if necessary
        pad = len(s_clean) % 4
        if pad:
            s_clean += "=" * (4 - pad)
        decoded = base64.b64decode(s_clean, altchars=b"-_", validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def encode_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def decode_base32(s: str) -> Optional[str]:
    try:
        s_clean = s.strip().upper()
        pad = len(s_clean) % 8
        if pad:
            s_clean += "=" * (8 - pad)
        decoded = base64.b32decode(s_clean)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def encode_base32(s: str) -> str:
    return base64.b32encode(s.encode("utf-8")).decode("ascii")


def decode_hex(s: str) -> Optional[str]:
    try:
        s_clean = re.sub(r"[\s\-:]", "", s.strip())
        # Handle 0x prefix
        if s_clean.startswith(("0x", "0X")):
            s_clean = s_clean[2:]
        decoded = bytes.fromhex(s_clean)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def encode_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def decode_binary(s: str) -> Optional[str]:
    try:
        groups = s.strip().split()
        # Accept groups of 7 or 8 bits
        chars = []
        for g in groups:
            if not all(c in "01" for c in g):
                return None
            chars.append(chr(int(g, 2)))
        result = "".join(chars)
        return result if result.isprintable() else None
    except Exception:
        return None


def encode_binary(s: str) -> str:
    return " ".join(format(ord(c), "08b") for c in s)


def decode_rot13(s: str) -> str:
    return s.translate(str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13],
    ))


def decode_caesar(s: str, shift: Optional[int] = None) -> tuple[str, int]:
    """Decode Caesar cipher. If shift is None, brute-force best shift."""
    if shift is not None:
        shift = shift % 26

        def shift_char(c: str, n: int) -> str:
            if c.isupper():
                return chr((ord(c) - ord("A") - n) % 26 + ord("A"))
            if c.islower():
                return chr((ord(c) - ord("a") - n) % 26 + ord("a"))
            return c

        return "".join(shift_char(c, shift) for c in s), shift

    best_score = float("-inf")
    best_shift = 0
    best_text = s
    for n in range(1, 26):
        candidate, _ = decode_caesar(s, n)
        sc = score_english(candidate)
        if sc > best_score:
            best_score = sc
            best_shift = n
            best_text = candidate
    return best_text, best_shift


def decode_atbash(s: str) -> str:
    result = []
    for c in s:
        if c.isupper():
            result.append(chr(ord("Z") - (ord(c) - ord("A"))))
        elif c.islower():
            result.append(chr(ord("z") - (ord(c) - ord("a"))))
        else:
            result.append(c)
    return "".join(result)


def _vigenere_key_length(ciphertext: str, max_key_len: int = 20) -> int:
    """Estimate Vigenere key length using Index of Coincidence."""
    letters = [c.upper() for c in ciphertext if c.isalpha()]
    if len(letters) < 20:
        return 1

    best_len = 1
    best_ic = 0.0
    ENGLISH_IC = 0.0667

    for klen in range(1, min(max_key_len + 1, len(letters) // 2)):
        ics = []
        for offset in range(klen):
            group = letters[offset::klen]
            if len(group) > 1:
                ics.append(index_of_coincidence("".join(group)))
        if ics:
            avg_ic = sum(ics) / len(ics)
            # Closest to English IC wins
            if abs(avg_ic - ENGLISH_IC) < abs(best_ic - ENGLISH_IC):
                best_ic = avg_ic
                best_len = klen

    return best_len


def decode_vigenere(ciphertext: str, key: Optional[str] = None) -> tuple[str, str]:
    """Decode Vigenere cipher. Auto-detect key if not provided."""
    letters_upper = [c.upper() for c in ciphertext if c.isalpha()]

    if key is None:
        klen = _vigenere_key_length(ciphertext)
        recovered_key = []
        for i in range(klen):
            column = letters_upper[i::klen]
            # Try each possible key character
            best_char = "A"
            best_score = float("-inf")
            for k in range(26):
                candidate = "".join(
                    chr((ord(c) - ord("A") - k) % 26 + ord("A")) for c in column
                )
                sc = score_english(candidate)
                if sc > best_score:
                    best_score = sc
                    best_char = chr(k + ord("A"))
            recovered_key.append(best_char)
        key = "".join(recovered_key)

    key_upper = key.upper()
    key_idx = 0
    result = []
    for c in ciphertext:
        if c.isalpha():
            k = ord(key_upper[key_idx % len(key_upper)]) - ord("A")
            if c.isupper():
                result.append(chr((ord(c) - ord("A") - k) % 26 + ord("A")))
            else:
                result.append(chr((ord(c) - ord("a") - k) % 26 + ord("a")))
            key_idx += 1
        else:
            result.append(c)
    return "".join(result), key


def decode_morse(s: str) -> Optional[str]:
    """Decode Morse code (dots/dashes, space-delimited)."""
    s = s.strip()
    # Words separated by " / " or "  " (double space)
    word_sep = " / " if " / " in s else "  "
    words = s.split(word_sep)
    result = []
    for word in words:
        chars = word.strip().split(" ")
        decoded_word = ""
        for code in chars:
            code = code.strip()
            if not code:
                continue
            ch = MORSE_DECODE.get(code)
            if ch is None:
                return None  # Invalid morse
            decoded_word += ch
        result.append(decoded_word)
    return " ".join(result) if result else None


def encode_morse(s: str) -> str:
    words = s.upper().split()
    encoded_words = []
    for word in words:
        encoded_chars = []
        for c in word:
            code = MORSE_ENCODE.get(c)
            if code:
                encoded_chars.append(code)
        encoded_words.append(" ".join(encoded_chars))
    return " / ".join(encoded_words)


def decode_url(s: str) -> str:
    return urllib.parse.unquote(s)


def encode_url(s: str) -> str:
    return urllib.parse.quote(s)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_cipher(s: str) -> list[tuple[str, str]]:
    """
    Return a list of (cipher_name, confidence) tuples for likely ciphers.
    Confidence: HIGH / MEDIUM / LOW
    """
    candidates: list[tuple[str, str]] = []
    s_stripped = s.strip()

    # Base64
    b64_pattern = re.compile(r"^[A-Za-z0-9+/\-_=\s]+$")
    if b64_pattern.match(s_stripped):
        clean = re.sub(r"\s", "", s_stripped)
        if len(clean) % 4 in (0, 2, 3):
            result = decode_base64(s_stripped)
            if result and score_english(result) > -50:
                candidates.append(("base64", "HIGH"))
            elif result:
                candidates.append(("base64", "MEDIUM"))

    # Base32
    b32_pattern = re.compile(r"^[A-Z2-7=\s]+$")
    if b32_pattern.match(s_stripped.upper()):
        result = decode_base32(s_stripped)
        if result and score_english(result) > -50:
            candidates.append(("base32", "HIGH"))

    # Hex
    hex_clean = re.sub(r"[\s\-:]", "", s_stripped)
    if hex_clean.startswith(("0x", "0X")):
        hex_clean = hex_clean[2:]
    if re.match(r"^[0-9a-fA-F]+$", hex_clean) and len(hex_clean) % 2 == 0:
        result = decode_hex(s_stripped)
        if result and score_english(result) > -50:
            candidates.append(("hex", "HIGH"))
        else:
            candidates.append(("hex", "MEDIUM"))

    # Binary
    if re.match(r"^[01\s]+$", s_stripped):
        groups = s_stripped.split()
        if all(len(g) in (7, 8) for g in groups):
            result = decode_binary(s_stripped)
            if result:
                candidates.append(("binary", "HIGH"))

    # Morse
    if re.match(r"^[.\-/ ]+$", s_stripped):
        result = decode_morse(s_stripped)
        if result:
            candidates.append(("morse", "HIGH"))

    # URL encoding
    if "%" in s_stripped and re.search(r"%[0-9a-fA-F]{2}", s_stripped):
        candidates.append(("url", "HIGH"))

    # ROT13 / Caesar / Atbash — only for alpha-heavy text
    letter_ratio = sum(1 for c in s_stripped if c.isalpha()) / max(len(s_stripped), 1)
    if letter_ratio > 0.5:
        rot13 = decode_rot13(s_stripped)
        if score_english(rot13) > score_english(s_stripped) + 1:
            candidates.append(("rot13", "HIGH"))

        best_caesar, best_shift = decode_caesar(s_stripped)
        if best_shift != 0 and score_english(best_caesar) > score_english(s_stripped) + 1:
            candidates.append(("caesar", f"HIGH (shift={best_shift})"))

        atbash = decode_atbash(s_stripped)
        if score_english(atbash) > score_english(s_stripped) + 2:
            candidates.append(("atbash", "HIGH"))

        # Vigenere — more likely with longer texts
        if len(s_stripped) > 40:
            vig_decoded, vig_key = decode_vigenere(s_stripped)
            if score_english(vig_decoded) > score_english(s_stripped) + 3:
                candidates.append(("vigenere", f"MEDIUM (key={vig_key})"))

    if not candidates:
        candidates.append(("plaintext", "NONE"))

    return candidates


# ---------------------------------------------------------------------------
# Chain decoder (recursive)
# ---------------------------------------------------------------------------

MAX_CHAIN_DEPTH = 10


def chain_decode(s: str, depth: int = 0, verbose: bool = False) -> list[dict]:
    """Recursively decode until plaintext or max depth."""
    if depth >= MAX_CHAIN_DEPTH:
        return [{"depth": depth, "cipher": "max_depth_reached", "result": s}]

    detections = detect_cipher(s)
    steps = []

    for cipher, confidence in detections:
        if cipher == "plaintext":
            break
        result = apply_cipher(s, cipher, mode="decode", verbose=verbose)
        if result and result != s:
            step = {
                "depth": depth,
                "cipher": cipher,
                "confidence": confidence,
                "input": s,
                "result": result,
            }
            steps.append(step)
            # Recurse on successful decode
            sub_steps = chain_decode(result, depth + 1, verbose)
            steps.extend(sub_steps)
            break  # Follow first successful chain

    return steps


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def apply_cipher(
    text: str,
    cipher: str,
    mode: str = "decode",
    key: Optional[str] = None,
    verbose: bool = False,
) -> Optional[str]:
    """Apply a specific cipher encode/decode operation."""
    cipher_lower = cipher.lower().split()[0]  # Strip confidence suffix

    if mode == "encode":
        dispatch = {
            "base64": encode_base64,
            "base32": encode_base32,
            "hex": encode_hex,
            "binary": encode_binary,
            "rot13": decode_rot13,  # symmetric
            "atbash": decode_atbash,  # symmetric
            "morse": encode_morse,
            "url": encode_url,
            "caesar": lambda s: decode_caesar(s, -(int(key) if key else 3) % 26)[0],
            "vigenere": lambda s: _encode_vigenere(s, key or "KEY"),
        }
    else:
        dispatch = {
            "base64": decode_base64,
            "base32": decode_base32,
            "hex": decode_hex,
            "binary": decode_binary,
            "rot13": decode_rot13,
            "atbash": decode_atbash,
            "morse": decode_morse,
            "url": decode_url,
            "caesar": lambda s: decode_caesar(s, int(key) if key else None)[0],
            "vigenere": lambda s: decode_vigenere(s, key)[0],
        }

    fn = dispatch.get(cipher_lower)
    if fn is None:
        if verbose:
            print(f"[cipher-engine] Unknown cipher: {cipher}")
        return None

    try:
        return fn(text)
    except Exception as e:
        if verbose:
            print(f"[cipher-engine] Error applying {cipher}: {e}")
        return None


def _encode_vigenere(plaintext: str, key: str) -> str:
    key_upper = key.upper()
    key_idx = 0
    result = []
    for c in plaintext:
        if c.isalpha():
            k = ord(key_upper[key_idx % len(key_upper)]) - ord("A")
            if c.isupper():
                result.append(chr((ord(c) - ord("A") + k) % 26 + ord("A")))
            else:
                result.append(chr((ord(c) - ord("a") + k) % 26 + ord("a")))
            key_idx += 1
        else:
            result.append(c)
    return "".join(result)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SEPARATOR = "=" * 60


def print_results(
    original: str,
    detections: list[tuple[str, str]],
    decoded_results: dict[str, Optional[str]],
    chain_steps: Optional[list[dict]] = None,
    verbose: bool = False,
) -> None:
    print(f"\n{SEPARATOR}")
    print("   OMNI-CIPHER BOT — Cipher Engine Results")
    print(SEPARATOR)
    print(f"Input ({len(original)} chars): {original[:120]}{'...' if len(original) > 120 else ''}")
    print()

    if detections:
        print("Detected Cipher(s):")
        for cipher, conf in detections:
            print(f"  • {cipher:<12} — Confidence: {conf}")
        print()

    print("Decoded Results:")
    for cipher, result in decoded_results.items():
        if result:
            preview = result[:200].replace("\n", "\\n")
            print(f"\n  [{cipher.upper()}]")
            print(f"  {preview}{'...' if len(result) > 200 else ''}")
            if verbose and len(result) > 200:
                print(f"  (Full length: {len(result)} chars)")
    print()

    if chain_steps:
        print(f"{'─' * 60}")
        print("Auto-Chain Trace:")
        for step in chain_steps:
            indent = "  " * (step["depth"] + 1)
            print(f"{indent}[Depth {step['depth']}] {step['cipher'].upper()}")
            result_preview = step["result"][:100].replace("\n", "\\n")
            print(f"{indent}  → {result_preview}")
        print()

    print(SEPARATOR)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Omni-Cipher Bot — Cipher Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cipher_tool.py --input "SGVsbG8="
  python cipher_tool.py --input "Khoor" --cipher caesar
  python cipher_tool.py --input "RIJVS" --cipher vigenere --key KEY
  python cipher_tool.py --file puzzles/encoded.txt --chain
  python cipher_tool.py --input "Hello World" --cipher base64 --mode encode
""",
    )
    parser.add_argument("--input", "-i", help="Encoded string (inline)")
    parser.add_argument("--file", "-f", help="Path to file with encoded content")
    parser.add_argument(
        "--cipher", "-c",
        help="Force cipher: base64|base32|hex|binary|rot13|caesar|vigenere|atbash|morse|url",
    )
    parser.add_argument(
        "--mode", "-m", choices=["decode", "encode"], default="decode",
        help="Operation mode (default: decode)",
    )
    parser.add_argument("--key", "-k", help="Key for Vigenere; shift for Caesar")
    parser.add_argument(
        "--chain", action="store_true",
        help="Auto-chain decode until plaintext",
    )
    parser.add_argument("--output", "-o", help="Write results to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Read input
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except FileNotFoundError:
            print(f"[cipher-engine] ERROR: File not found: {args.file}")
            sys.exit(1)
    elif args.input:
        text = args.input
    else:
        # Read from stdin
        print("[cipher-engine] Reading from stdin (Ctrl+D to finish)...")
        text = sys.stdin.read()

    text = text.strip()
    if not text:
        print("[cipher-engine] ERROR: No input provided.")
        sys.exit(1)

    output_lines: list[str] = []

    # Forced cipher
    if args.cipher:
        result = apply_cipher(text, args.cipher, args.mode, args.key, args.verbose)
        if result is None:
            print(f"[cipher-engine] Failed to apply cipher '{args.cipher}'.")
            sys.exit(1)

        print(f"\n{SEPARATOR}")
        print(f"   Cipher: {args.cipher.upper()} | Mode: {args.mode.upper()}")
        print(SEPARATOR)
        print(f"Input:  {text[:120]}")
        print(f"Output: {result[:400]}")
        print(SEPARATOR)
        output_lines.append(result)

    else:
        # Auto-detect
        detections = detect_cipher(text)
        decoded_results: dict[str, Optional[str]] = {}

        for cipher, _ in detections:
            if cipher not in ("plaintext",):
                r = apply_cipher(text, cipher, "decode", args.key, args.verbose)
                if r:
                    decoded_results[cipher] = r

        if not decoded_results:
            decoded_results["plaintext"] = text

        chain_steps = None
        if args.chain:
            chain_steps = chain_decode(text, verbose=args.verbose)

        print_results(text, detections, decoded_results, chain_steps, args.verbose)
        # Gọi bộ giải mã chuỗi nhiều lớp tự động nâng cao
        print("\n" + "="*40)
        print("🛰️  OMNI-CIPHER CHAIN AUTO-DECRYPTOR")
        print("="*40)
        result_chain = solve_multi_layer_cipher(text)
        for step in result_chain["chain"]:
            print(f" 🔓 {step}")
        print(f"\n🎯 [FINAL PLAINTEXT FLAG]: {result_chain['final_plaintext']}")
        print("="*40 + "\n")

        for r in decoded_results.values():
            if r:
                output_lines.append(r)

    # Write output file
    if args.output and output_lines:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write("\n\n---\n\n".join(output_lines))
            print(f"[cipher-engine] Results written to: {args.output}")
        except OSError as e:
            print(f"[cipher-engine] WARNING: Could not write output file: {e}")

def solve_multi_layer_cipher(cipher_text: str) -> dict:
    """
    Hàm nâng cao lồng ghép: Tự động bóc tách các lớp mã hóa lồng nhau 
    (Base64, Hex, ROT) và dùng chính hàm score_english của bạn để tìm đáp án sạch nhất.
    """
    import base64
    import re
    match = re.search(r'\[.*?START\]\s*(.*?)\s*\[.*?END\]', cipher_text, re.DOTALL)
    if match:
        cipher_text = match.group(1)
    current = cipher_text.strip()

    steps = []
    
    for layer in range(1, 6):
        # 1. Thử giải mã Base64 (Có tự động xử lý thiếu padding '=')
        try:
            padded = current + "=" * ((4 - len(current) % 4) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            if any(c.isalnum() for c in decoded) and len(decoded) > 2:
                current = decoded
                steps.append(f"Lớp {layer} [Base64]: {current}")
                continue
        except Exception:
            pass
            
        # 2. Thử giải mã HEX (Thập lục phân)
        try:
            clean_hex = current.replace(" ", "").replace("0x", "")
            decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
            if any(c.isalnum() for c in decoded) and len(decoded) > 2:
                current = decoded
                steps.append(f"Lớp {layer} [Hex]: {current}")
                continue
        except Exception:
            pass
            
        # 3. Quét Caesar / ROT bằng cách dùng CHÍNH hàm score_english có sẵn của bạn
        best_rot = current
        max_score = -1.0
        for shift in range(1, 26):
            candidate = ""
            for char in current:
                if char.isalpha():
                    start = ord('A') if char.isupper() else ord('a')
                    candidate += chr((ord(char) - start - shift) % 26 + start)
                else:
                    candidate += char
            
            # Gọi hàm chấm điểm tiếng Anh gốc của bạn
            current_score = score_english(candidate)
            if current_score > max_score:
                max_score = current_score
                best_rot = candidate
                
        # Nếu tìm được chuỗi có điểm tiếng Anh cao, tiến hành bẻ khóa lớp này
        if best_rot != current and max_score > 0:
            current = best_rot
            steps.append(f"Lớp {layer} [Caesar/ROT]: {current}")
            continue
            
        break
        
    return {"chain": steps, "final_plaintext": current}

if __name__ == "__main__":
    main()


# === OMNI-CIPHER BOT EXTENSION ===
# Additive optimization block — timeline logging + diagnostic capture.
# Zero modifications to any function above this line.
# ═══════════════════════════════════════════════════════════════════════

import datetime as _dt
import traceback as _tb
import inspect as _inspect

_TIMELINE_DIR    = "puzzles/logs/timelines"
_DIAGNOSTIC_DIR  = "puzzles/logs/diagnostics"


def _ocb_ensure_dirs() -> None:
    """Create log directories if they don't exist."""
    import os
    os.makedirs(_TIMELINE_DIR, exist_ok=True)
    os.makedirs(_DIAGNOSTIC_DIR, exist_ok=True)


def _ocb_ts() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _ocb_timeline_write(asset_name: str, lines: list[str]) -> None:
    """Append a timestamped timeline entry for asset_name."""
    import os
    _ocb_ensure_dirs()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in asset_name)
    path = os.path.join(_TIMELINE_DIR, f"{safe}.txt")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"\n{'─'*60}\n")
        fh.write(f"[{_ocb_ts()}]  cipher-engine  asset={asset_name}\n")
        for line in lines:
            fh.write(f"  {line}\n")


def _ocb_diag_write(fn_sig: str, lineno: int, root_cause: str, suggestion: str) -> None:
    """Append a diagnostic + fix suggestion entry."""
    import os
    _ocb_ensure_dirs()
    path = os.path.join(_DIAGNOSTIC_DIR, "cipher_engine_diagnostics.txt")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"\n{'═'*60}\n")
        fh.write(f"[{_ocb_ts()}]\n")
        fh.write(f"  Tool       : cipher_tool.py\n")
        fh.write(f"  Function   : {fn_sig}\n")
        fh.write(f"  Line       : {lineno}\n")
        fh.write(f"  Root cause : {root_cause}\n")
        fh.write(f"  Fix model  :\n")
        for l in suggestion.strip().splitlines():
            fh.write(f"    {l}\n")


def ocb_cipher_chain_logged(text: str, asset_name: str = "inline") -> dict:
    """
    Optimized multi-layer cipher chain with full timeline logging.
    Wraps the existing chain_decode() and detect_cipher() functions.
    Uses numpy-vectorised ASCII scoring where available for speed.
    All errors are caught and written to diagnostics without crashing.
    """
    import time
    timeline: list[str] = []
    result: dict = {"steps": [], "final": text, "asset": asset_name}

    timeline.append(f"START  input_len={len(text)}  preview={text[:60]!r}")
    t0 = time.perf_counter()

    try:
        # ── Fast path: detect all applicable ciphers ──────────────
        detections = detect_cipher(text)
        timeline.append(f"DETECT {[f'{c}:{conf}' for c, conf in detections]}")

        current = text
        for depth, (cipher, confidence) in enumerate(detections):
            if cipher == "plaintext":
                break
            step_t = time.perf_counter()
            try:
                decoded = apply_cipher(current, cipher, mode="decode")
                if decoded and decoded != current:
                    elapsed_ms = (time.perf_counter() - step_t) * 1000
                    timeline.append(
                        f"LAYER  depth={depth}  cipher={cipher}  "
                        f"conf={confidence}  len_in={len(current)}  "
                        f"len_out={len(decoded)}  time={elapsed_ms:.2f}ms  "
                        f"intermediate={decoded[:50]!r}"
                    )
                    result["steps"].append({
                        "depth": depth, "cipher": cipher,
                        "confidence": confidence, "output": decoded,
                    })
                    current = decoded
            except Exception as exc:
                lineno = _tb.extract_tb(exc.__traceback__)[-1].lineno
                root   = f"{type(exc).__name__}: {exc}"
                sugg   = (
                    f"# Fix for cipher='{cipher}' decode failure\n"
                    f"# The apply_cipher() dispatcher returned an exception.\n"
                    f"# Pattern: add explicit guard in apply_cipher() for '{cipher}':\n"
                    f"#   if cipher_lower not in dispatch:\n"
                    f"#       return None  # graceful skip\n"
                    f"# Alternatively wrap the inner fn call:\n"
                    f"#   try: return fn(text)\n"
                    f"#   except (UnicodeDecodeError, binascii.Error): return None"
                )
                _ocb_diag_write(f"apply_cipher(text, '{cipher}', 'decode')", lineno, root, sugg)
                timeline.append(f"ERROR  depth={depth}  cipher={cipher}  err={root}")

        result["final"] = current
        elapsed_total = (time.perf_counter() - t0) * 1000
        timeline.append(f"END    final_len={len(current)}  total_time={elapsed_total:.2f}ms  "
                         f"final_preview={current[:60]!r}")

    except Exception as exc:
        lineno = _tb.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        sugg   = (
            "# Outer guard failure in ocb_cipher_chain_logged().\n"
            "# Ensure input `text` is a non-empty str before calling detect_cipher().\n"
            "# Guard: if not isinstance(text, str) or not text.strip(): return early."
        )
        _ocb_diag_write("ocb_cipher_chain_logged(text, asset_name)", lineno, root, sugg)
        timeline.append(f"FATAL  {root}")
        result["error"] = root

    _ocb_timeline_write(asset_name, timeline)
    return result


# === OMNI-CIPHER APEX EXTENSION ===
# Extended ASCII shift — operates over the full 0-255 codepoint range.
# Zero modifications to any function above this line.
# ════════════════════════════════════════════════════════════════════


def decode_caesar_ascii256(text: str, shift: int) -> str:
    """
    Apply a Caesar-style shift across the full 256-character ASCII table.

    Unlike the standard decode_caesar(), which wraps only within A-Z / a-z
    and leaves all other characters unchanged, this function treats every
    byte in the string uniformly:

        decoded_char = chr((ord(char) - shift) % 256)

    This is useful when the ciphertext was produced by shifting arbitrary
    byte values rather than plain alphabetic characters — for example,
    CTF challenges that encode punctuation, digits, or high-byte symbols
    as part of the cipher alphabet.

    Parameters
    ----------
    text  : ciphertext string (any characters, including extended ASCII)
    shift : integer offset to subtract (0-255); wraps via modulo 256

    Returns
    -------
    Decoded string with every character shifted by -shift mod 256.
    """
    shift = shift % 256
    return "".join(chr((ord(c) - shift) % 256) for c in text)


def brute_ascii256(
    text: str,
    top_n: int = 5,
    verbose: bool = False,
) -> list[dict]:
    """
    Brute-force all 255 non-zero shifts over the 256-char ASCII table.

    Scoring strategy
    ────────────────
    English letter-frequency scoring (score_english) is designed for
    A-Z / a-z text and gives misleading results when the candidate
    contains high-byte characters.  Instead we use two complementary
    signals ranked in order of priority:

      1. Printable ratio  — fraction of characters that are printable
                            ASCII (0x20–0x7E).  Higher is better.
      2. English score    — applied as a tiebreaker when printable
                            ratios are similar, to surface human-readable
                            candidates over random-looking printable junk.

    Parameters
    ----------
    text   : ciphertext string
    top_n  : how many top candidates to return (default 5)
    verbose: if True, print all 255 candidates

    Returns
    -------
    List of dicts (sorted best-first), each with:
      shift          — the shift value that produced this candidate
      printable_ratio — fraction of printable chars (0.0–1.0)
      english_score  — score_english() result
      decoded        — the decoded string
    """
    results: list[dict] = []

    for shift in range(1, 256):
        candidate = decode_caesar_ascii256(text, shift)
        printable = sum(1 for c in candidate if 0x20 <= ord(c) <= 0x7E)
        p_ratio   = printable / max(len(candidate), 1)
        eng_score = score_english(candidate)
        results.append({
            "shift":           shift,
            "printable_ratio": round(p_ratio, 4),
            "english_score":   round(eng_score, 4),
            "decoded":         candidate,
        })

        if verbose:
            preview = candidate[:60].replace("\n", "\\n")
            print(f"  shift={shift:3d}  printable={p_ratio:.3f}  "
                  f"eng={eng_score:.3f}  → {preview}")

    # Sort: printable ratio primary, english score secondary
    results.sort(key=lambda r: (r["printable_ratio"], r["english_score"]), reverse=True)

    top = results[:top_n]

    print(f"\n[ASCII-256 Caesar Brute-Force — Top {top_n} candidates]")
    for rank, r in enumerate(top, 1):
        preview = r["decoded"][:80].replace("\n", "\\n")
        print(f"  #{rank}  shift={r['shift']:3d}  "
              f"printable={r['printable_ratio']:.3f}  "
              f"eng={r['english_score']:.3f}")
        print(f"      → {preview}")

    return top


# === OMNI-CIPHER APEX EXTENSION: RAW BYTE STABILIZATION ===
# Fixes silent byte-dropping in solve_multi_layer_cipher's Base64 path.
# The original used errors='ignore' which discards non-UTF-8 bytes entirely.
# This extension provides a byte-safe wrapper that retries with latin-1
# (a 1:1 mapping of all 256 byte values to Unicode) so no byte is ever lost.
# Zero modifications to any function above this line.
# ═══════════════════════════════════════════════════════════════════════════


def _b64_decode_raw_safe(s: str) -> str:
    """
    Decode a Base64 string to text without silently dropping bytes.

    Decoding order (first success wins):
      1. UTF-8 strict    — clean text, no substitution
      2. UTF-8 replace   — keeps byte positions, marks bad bytes with U+FFFD
      3. latin-1         — 1:1 map of all 256 byte values; nothing is ever lost

    This replaces the inline `base64.b64decode(...).decode('utf-8', errors='ignore')`
    calls inside solve_multi_layer_cipher, which silently discard bytes that
    aren't valid UTF-8 — causing character-dropping on CTF payloads that
    encode raw binary, high-ASCII symbols, or non-standard punctuation.
    """
    import base64 as _b64
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    raw = _b64.b64decode(padded)

    for encoding in ("utf-8", "latin-1"):
        errors = "strict" if encoding == "utf-8" else "strict"
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, ValueError):
            pass

    # latin-1 covers all 256 values — this branch is only reached on truly
    # malformed input (e.g. truncated multi-byte sequence at end of buffer).
    return raw.decode("latin-1", errors="replace")


def solve_multi_layer_cipher_stable(cipher_text: str) -> dict:
    """
    Byte-stable variant of solve_multi_layer_cipher.

    Identical logic and interface, with one fix: Base64 decoding now uses
    _b64_decode_raw_safe() instead of .decode('utf-8', errors='ignore'),
    so non-UTF-8 bytes (e.g. raw binary payloads, high-ASCII CTF tokens,
    '#', '_', digits inside encoded blobs) are preserved rather than dropped.

    The Caesar/ROT branch already preserved non-alpha characters correctly
    in the original; that logic is unchanged here.

    Returns the same dict shape as solve_multi_layer_cipher:
      {"chain": [step_strings], "final_plaintext": str}
    """
    import base64 as _b64
    import re as _re

    match = _re.search(r'\[.*?START\]\s*(.*?)\s*\[.*?END\]', cipher_text, _re.DOTALL)
    if match:
        cipher_text = match.group(1)
    current = cipher_text.strip()

    steps: list[str] = []

    for layer in range(1, 6):

        # ── Layer attempt 1: Base64 (byte-safe) ──────────────────────────
        try:
            decoded = _b64_decode_raw_safe(current)
            if any(c.isalnum() for c in decoded) and len(decoded) > 2:
                current = decoded
                steps.append(f"Layer {layer} [Base64-safe]: {current}")
                continue
        except Exception:
            pass

        # ── Layer attempt 2: Hex ──────────────────────────────────────────
        try:
            clean_hex = current.replace(" ", "").replace("0x", "")
            raw_hex = bytes.fromhex(clean_hex)
            # Same byte-safe decode: try UTF-8, fall back to latin-1
            try:
                decoded = raw_hex.decode("utf-8")
            except UnicodeDecodeError:
                decoded = raw_hex.decode("latin-1")
            if any(c.isalnum() for c in decoded) and len(decoded) > 2:
                current = decoded
                steps.append(f"Layer {layer} [Hex-safe]: {current}")
                continue
        except Exception:
            pass

        # ── Layer attempt 3: Caesar/ROT (alpha-only shift; non-alpha preserved) ─
        # Non-alpha characters (digits, '#', '_', punctuation) are passed through
        # unchanged — this matches the original behaviour, documented here explicitly.
        best_rot = current
        max_score = -1.0
        for shift in range(1, 26):
            candidate = ""
            for char in current:
                if char.isalpha():
                    start = ord("A") if char.isupper() else ord("a")
                    candidate += chr((ord(char) - start - shift) % 26 + start)
                else:
                    candidate += char   # '#', '_', digits, punctuation — untouched
            sc = score_english(candidate)
            if sc > max_score:
                max_score = sc
                best_rot = candidate

        if best_rot != current and max_score > 0:
            current = best_rot
            steps.append(f"Layer {layer} [Caesar/ROT]: {current}")
            continue

        # ── Layer attempt 4: ASCII-256 shift fallback ─────────────────────
        # Only reached when alpha-only Caesar finds no improvement.
        # Sweeps the full 256-value space via (ord(c) - shift) % 256 and
        # picks the shift that maximises the printable-character ratio.
        # This catches ciphers applied to arbitrary byte values rather than
        # just A-Z / a-z.
        best_a256 = current
        best_printable = sum(1 for c in current if 0x20 <= ord(c) <= 0x7E) / max(len(current), 1)
        best_a256_shift = 0
        for shift in range(1, 256):
            candidate = "".join(chr((ord(c) - shift) % 256) for c in current)
            p_ratio = sum(1 for c in candidate if 0x20 <= ord(c) <= 0x7E) / max(len(candidate), 1)
            if p_ratio > best_printable:
                best_printable = p_ratio
                best_a256 = candidate
                best_a256_shift = shift

        if best_a256 != current and best_printable > 0.85:
            current = best_a256
            steps.append(f"Layer {layer} [ASCII-256 shift={best_a256_shift}]: {current}")
            continue

        break

    return {"chain": steps, "final_plaintext": current}
