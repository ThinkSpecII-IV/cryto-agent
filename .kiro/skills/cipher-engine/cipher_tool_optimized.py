#!/usr/bin/env python3
"""High-performance Omni-Cipher engine.

The implementation is standard-library only.  Translation tables are cached
for the hot substitution paths, and raw decoded bytes are never discarded.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _dt
import fcntl
import hashlib
import json
import math
import mmap
import os
import re
import string
import sys
import time
import urllib.parse
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Optional


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
	letters = [char for char in text.lower() if char.isalpha()]
	if not letters:
		return 0.0
	counts = Counter(letters)
	total = len(letters)
	frequency_score = sum(
		(count / total) * math.log(ENGLISH_FREQ.get(char, 0.0001) + 1e-10)
		for char, count in counts.items()
	)
	words = re.findall(r"[a-z]+", text.lower())
	word_bonus = sum(1.5 for word in words if word in COMMON_WORDS)
	printable_ratio = sum(char.isprintable() for char in text) / max(len(text), 1)
	return frequency_score + word_bonus + printable_ratio * 2


def index_of_coincidence(text: str) -> float:
	letters = [char.upper() for char in text if char.isalpha()]
	length = len(letters)
	if length < 2:
		return 0.0
	counts = Counter(letters)
	return sum(value * (value - 1) for value in counts.values()) / (length * (length - 1))


MORSE_ENCODE: dict[str, str] = {
	"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
	"F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
	"K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
	"P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
	"U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
	"Z": "--..", "0": "-----", "1": ".----", "2": "..---",
	"3": "...--", "4": "....-", "5": ".....", "6": "-....",
	"7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-",
	",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
	"/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...",
	":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.",
	"-": "-....-", "_": "..--.-", '"': ".-..-.", "$": "...-..-",
	"@": ".--.-.",
}
MORSE_DECODE = {value: key for key, value in MORSE_ENCODE.items()}


def decode_base64(value: str) -> Optional[str]:
	try:
		clean = re.sub(r"\s+", "", value.strip())
		clean += "=" * ((4 - len(clean) % 4) % 4)
		raw = base64.b64decode(clean, altchars=b"-_", validate=False)
		return _decode_raw_text(raw)
	except (binascii.Error, ValueError, UnicodeError):
		return None


def _decode_raw_text(raw: bytes) -> str:
	"""Decode every raw byte losslessly using the Latin-1 mapping."""
	return raw.decode("latin-1", errors="strict")


def _b64_decode_raw_safe(value: str) -> str:
	clean = re.sub(r"\s+", "", value.strip())
	clean += "=" * ((4 - len(clean) % 4) % 4)
	return _decode_raw_text(base64.b64decode(clean, altchars=b"-_", validate=False))


def encode_base64(value: str) -> str:
	return base64.b64encode(value.encode("utf-8")).decode("ascii")


def decode_base32(value: str) -> Optional[str]:
	try:
		clean = value.strip().upper()
		clean += "=" * ((8 - len(clean) % 8) % 8)
		return _decode_raw_text(base64.b32decode(clean))
	except (binascii.Error, ValueError, UnicodeError):
		return None


def encode_base32(value: str) -> str:
	return base64.b32encode(value.encode("utf-8")).decode("ascii")


# === OMNI-CIPHER APEX CORE UPDATE: DUAL INTERFACE ===
def decode_base85(value: str) -> Optional[str]:
	try:
		clean = re.sub(r"\s+", "", value.strip())
		return _decode_raw_text(base64.b85decode(clean.encode("ascii")))
	except (binascii.Error, ValueError, UnicodeError):
		return None


def encode_base85(value: str) -> str:
	return base64.b85encode(value.encode("utf-8")).decode("ascii")


_ZERO_WIDTH_ZERO = "\u200c"
_ZERO_WIDTH_ONE = "\u200d"


def extract_zero_width(value: str) -> dict[str, object]:
	"""Extract U+200C/U+200D tokens and decode complete MSB-first bytes."""
	bits = "".join(
		"1" if character == _ZERO_WIDTH_ONE else "0"
		for character in value
		if character in (_ZERO_WIDTH_ZERO, _ZERO_WIDTH_ONE)
	)
	complete_bits = len(bits) - len(bits) % 8
	raw = bytes(
		int(bits[offset:offset + 8], 2)
		for offset in range(0, complete_bits, 8)
	)
	return {
		"token_count": len(bits),
		"bits": bits,
		"trailing_bits": len(bits) - complete_bits,
		"raw_bytes": raw,
		"text": _decode_raw_text(raw),
	}


def decode_zero_width(value: str) -> Optional[str]:
	extraction = extract_zero_width(value)
	return extraction["text"] if extraction["token_count"] >= 8 else None


def encode_zero_width(value: str) -> str:
	raw = value.encode("latin-1", errors="strict")
	return "".join(
		_ZERO_WIDTH_ONE if byte & (1 << bit) else _ZERO_WIDTH_ZERO
		for byte in raw
		for bit in range(7, -1, -1)
	)


def decode_hex(value: str) -> Optional[str]:
	try:
		clean = re.sub(r"[\s\-:]", "", value.strip())
		if clean.startswith(("0x", "0X")):
			clean = clean[2:]
		return _decode_raw_text(bytes.fromhex(clean))
	except (ValueError, UnicodeError):
		return None


def encode_hex(value: str) -> str:
	return value.encode("utf-8").hex()


def decode_binary(value: str) -> Optional[str]:
	try:
		groups = value.strip().split()
		if not groups or any(not group or any(bit not in "01" for bit in group) for group in groups):
			return None
		result = "".join(chr(int(group, 2)) for group in groups)
		return result if result.isprintable() else None
	except (ValueError, OverflowError):
		return None


def encode_binary(value: str) -> str:
	return " ".join(format(ord(char), "08b") for char in value)


_ALPHABET_UPPER = string.ascii_uppercase
_ALPHABET_LOWER = string.ascii_lowercase
_ROT13_TABLE = str.maketrans(
	_ALPHABET_UPPER + _ALPHABET_LOWER,
	_ALPHABET_UPPER[13:] + _ALPHABET_UPPER[:13] + _ALPHABET_LOWER[13:] + _ALPHABET_LOWER[:13],
)
_ATBASH_TABLE = str.maketrans(
	_ALPHABET_UPPER + _ALPHABET_LOWER,
	_ALPHABET_UPPER[::-1] + _ALPHABET_LOWER[::-1],
)


def decode_rot13(value: str) -> str:
	return value.translate(_ROT13_TABLE)


def decode_atbash(value: str) -> str:
	return value.translate(_ATBASH_TABLE)


@lru_cache(maxsize=26)
def _caesar_table(shift: int) -> dict[int, int]:
	shift %= 26
	table: dict[int, int] = {}
	for index, char in enumerate(_ALPHABET_UPPER):
		table[ord(char)] = ord(_ALPHABET_UPPER[(index - shift) % 26])
	for index, char in enumerate(_ALPHABET_LOWER):
		table[ord(char)] = ord(_ALPHABET_LOWER[(index - shift) % 26])
	return table


def decode_caesar(value: str, shift: Optional[int] = None) -> tuple[str, int]:
	if shift is not None:
		normalized = shift % 26
		return value.translate(_caesar_table(normalized)), normalized
	best_text, best_shift, best_score = value, 0, float("-inf")
	for candidate_shift in range(1, 26):
		candidate = value.translate(_caesar_table(candidate_shift))
		candidate_score = score_english(candidate)
		if candidate_score > best_score:
			best_text, best_shift, best_score = candidate, candidate_shift, candidate_score
	return best_text, best_shift


def _vigenere_key_length(ciphertext: str, max_key_len: int = 20) -> int:
	letters = [char.upper() for char in ciphertext if char.isalpha()]
	if len(letters) < 20:
		return 1
	best_length, best_distance = 1, float("inf")
	for key_length in range(1, min(max_key_len + 1, len(letters) // 2)):
		values = [index_of_coincidence("".join(letters[offset::key_length]))
				  for offset in range(key_length) if len(letters[offset::key_length]) > 1]
		if values:
			distance = abs(sum(values) / len(values) - 0.0667)
			if distance < best_distance:
				best_length, best_distance = key_length, distance
	return best_length


def decode_vigenere(ciphertext: str, key: Optional[str] = None) -> tuple[str, str]:
	letters = [char.upper() for char in ciphertext if char.isalpha()]
	if key is None:
		key_chars: list[str] = []
		key_length = _vigenere_key_length(ciphertext)
		for index in range(key_length):
			column = letters[index::key_length]
			candidates = []
			for shift in range(26):
				candidate = "".join(chr((ord(char) - 65 - shift) % 26 + 65) for char in column)
				candidates.append((score_english(candidate), chr(65 + shift)))
			key_chars.append(max(candidates)[1])
		key = "".join(key_chars)
	if not key or not any(char.isalpha() for char in key):
		raise ValueError("Vigenere key must contain at least one letter")
	shifts = [ord(char.upper()) - 65 for char in key if char.isalpha()]
	result: list[str] = []
	key_index = 0
	for char in ciphertext:
		if char.isalpha() and char.isascii():
			shift = shifts[key_index % len(shifts)]
			base = 65 if char.isupper() else 97
			result.append(chr((ord(char) - base - shift) % 26 + base))
			key_index += 1
		else:
			result.append(char)
	return "".join(result), key


def decode_morse(value: str) -> Optional[str]:
	value = value.strip()
	separator = " / " if " / " in value else "  "
	words: list[str] = []
	for word in value.split(separator):
		decoded = []
		for code in word.strip().split():
			if code not in MORSE_DECODE:
				return None
			decoded.append(MORSE_DECODE[code])
		words.append("".join(decoded))
	return " ".join(words) if words else None


def encode_morse(value: str) -> str:
	return " / ".join(" ".join(MORSE_ENCODE.get(char, "") for char in word)
					   for word in value.upper().split())


def decode_url(value: str) -> str:
	return urllib.parse.unquote(value)


def encode_url(value: str) -> str:
	return urllib.parse.quote(value)


def detect_cipher(value: str) -> list[tuple[str, str]]:
	candidates: list[tuple[str, str]] = []
	stripped = value.strip()
	zero_width = extract_zero_width(value)
	if zero_width["token_count"] >= 8:
		confidence = "HIGH" if zero_width["trailing_bits"] == 0 else "MEDIUM"
		candidates.append(("zero-width", confidence))
	if re.fullmatch(r"[A-Za-z0-9+/\-_=\s]+", stripped):
		clean = re.sub(r"\s", "", stripped)
		if len(clean) % 4 in (0, 2, 3):
			decoded = decode_base64(stripped)
			if decoded:
				candidates.append(("base64", "HIGH" if score_english(decoded) > -50 else "MEDIUM"))
	if re.fullmatch(r"[A-Z2-7=\s]+", stripped.upper()):
		decoded = decode_base32(stripped)
		if decoded:
			candidates.append(("base32", "HIGH"))
	if re.fullmatch(r"[!-~]+", re.sub(r"\s+", "", stripped)):
		decoded = decode_base85(stripped)
		if decoded:
			confidence = "HIGH" if score_english(decoded) > -50 else "LOW"
			candidates.append(("base85", confidence))
	clean_hex = re.sub(r"[\s\-:]", "", stripped)
	if clean_hex.startswith(("0x", "0X")):
		clean_hex = clean_hex[2:]
	if re.fullmatch(r"[0-9a-fA-F]+", clean_hex or "") and len(clean_hex) % 2 == 0:
		decoded = decode_hex(stripped)
		if decoded:
			candidates.append(("hex", "HIGH" if score_english(decoded) > -50 else "MEDIUM"))
	if re.fullmatch(r"[01\s]+", stripped):
		groups = stripped.split()
		if groups and all(len(group) in (7, 8) for group in groups) and decode_binary(stripped):
			candidates.append(("binary", "HIGH"))
	if re.fullmatch(r"[.\-/ ]+", stripped) and (decoded := decode_morse(stripped)):
		candidates.append(("morse", "HIGH"))
	if "%" in stripped and re.search(r"%[0-9a-fA-F]{2}", stripped):
		candidates.append(("url", "HIGH"))
	if sum(char.isalpha() for char in stripped) / max(len(stripped), 1) > 0.5:
		original_score = score_english(stripped)
		rot13 = decode_rot13(stripped)
		if score_english(rot13) > original_score + 1:
			candidates.append(("rot13", "HIGH"))
		caesar, shift = decode_caesar(stripped)
		if shift and score_english(caesar) > original_score + 1:
			candidates.append(("caesar", f"HIGH (shift={shift})"))
		atbash = decode_atbash(stripped)
		if score_english(atbash) > original_score + 2:
			candidates.append(("atbash", "HIGH"))
		if len(stripped) > 40:
			vigenere, key = decode_vigenere(stripped)
			if score_english(vigenere) > original_score + 3:
				candidates.append(("vigenere", f"MEDIUM (key={key})"))
	return candidates or [("plaintext", "NONE")]


def _encode_vigenere(plaintext: str, key: str) -> str:
	shifts = [ord(char.upper()) - 65 for char in key if char.isalpha()]
	if not shifts:
		raise ValueError("Vigenere key must contain at least one letter")
	result: list[str] = []
	key_index = 0
	for char in plaintext:
		if char.isalpha() and char.isascii():
			base = 65 if char.isupper() else 97
			result.append(chr((ord(char) - base + shifts[key_index % len(shifts)]) % 26 + base))
			key_index += 1
		else:
			result.append(char)
	return "".join(result)


def apply_cipher(text: str, cipher: str, mode: str = "decode", key: Optional[str] = None,
				 verbose: bool = False) -> Optional[str]:
	cipher_name = cipher.lower().split()[0]
	if mode == "encode":
		dispatch = {
			"base64": encode_base64, "base32": encode_base32, "base85": encode_base85, "hex": encode_hex,
			"binary": encode_binary, "rot13": decode_rot13, "atbash": decode_atbash,
			"morse": encode_morse, "url": encode_url,
			"caesar": lambda value: decode_caesar(value, -(int(key) if key else 3) % 26)[0],
			"vigenere": lambda value: _encode_vigenere(value, key or "KEY"),
			"zero-width": encode_zero_width, "zerowidth": encode_zero_width,
			"ascii256": lambda value: decode_caesar_ascii256(value, -int(key or 1)),
		}
	else:
		dispatch = {
			"base64": decode_base64, "base32": decode_base32, "base85": decode_base85, "hex": decode_hex,
			"binary": decode_binary, "rot13": decode_rot13, "atbash": decode_atbash,
			"morse": decode_morse, "url": decode_url,
			"caesar": lambda value: decode_caesar(value, int(key) if key else None)[0],
			"vigenere": lambda value: decode_vigenere(value, key)[0],
			"zero-width": decode_zero_width, "zerowidth": decode_zero_width,
			"ascii256": lambda value: decode_caesar_ascii256(value, int(key or 1)),
		}
	function = dispatch.get(cipher_name)
	if function is None:
		if verbose:
			print(f"[cipher-engine] Unknown cipher: {cipher}")
		return None
	try:
		return function(text)
	except (ValueError, TypeError, IndexError, binascii.Error) as error:
		if verbose:
			print(f"[cipher-engine] Error applying {cipher}: {error}")
		return None


MAX_CHAIN_DEPTH = 10


def chain_decode(text: str, depth: int = 0, verbose: bool = False) -> list[dict]:
	if depth >= MAX_CHAIN_DEPTH:
		return [{"depth": depth, "cipher": "max_depth_reached", "result": text}]
	steps: list[dict] = []
	for cipher, confidence in detect_cipher(text):
		if cipher == "plaintext":
			break
		result = apply_cipher(text, cipher, verbose=verbose)
		if result and result != text:
			steps.append({"depth": depth, "cipher": cipher, "confidence": confidence,
						  "input": text, "result": result})
			steps.extend(chain_decode(result, depth + 1, verbose))
			break
	return steps


@lru_cache(maxsize=256)
def _ascii256_table(shift: int) -> dict[int, int]:
	normalized = shift % 256
	return {value: (value - normalized) % 256 for value in range(256)}


def decode_caesar_ascii256(text: str, shift: int) -> str:
	return text.translate(_ascii256_table(shift))


def brute_ascii256(text: str, top_n: int = 5, verbose: bool = False) -> list[dict]:
	results = []
	length = max(len(text), 1)
	for shift in range(1, 256):
		candidate = decode_caesar_ascii256(text, shift)
		printable_ratio = sum(0x20 <= ord(char) <= 0x7E for char in candidate) / length
		entry = {"shift": shift, "printable_ratio": round(printable_ratio, 4),
				 "english_score": round(score_english(candidate), 4), "decoded": candidate}
		results.append(entry)
		if verbose:
			print(f"  shift={shift:3d} printable={printable_ratio:.3f} "
				  f"eng={entry['english_score']:.3f} -> {candidate[:60]!r}")
	results.sort(key=lambda entry: (entry["printable_ratio"], entry["english_score"]), reverse=True)
	selected = results[:top_n]
	print(f"\n[ASCII-256 Caesar Brute-Force - Top {top_n} candidates]")
	for rank, entry in enumerate(selected, 1):
		print(f"  #{rank} shift={entry['shift']:3d} printable={entry['printable_ratio']:.3f} "
			  f"eng={entry['english_score']:.3f}\n      -> {entry['decoded'][:80]!r}")
	return selected


def solve_multi_layer_cipher(cipher_text: str) -> dict:
	match = re.search(r"\[.*?START\]\s*(.*?)\s*\[.*?END\]", cipher_text, re.DOTALL)
	current = (match.group(1) if match else cipher_text).strip()
	steps: list[str] = []
	for layer in range(1, 6):
		zero_width_text = decode_zero_width(current)
		if zero_width_text and zero_width_text != current:
			current = zero_width_text
			steps.append(f"Layer {layer} [Zero-width]: {current}")
			continue
		try:
			decoded = _b64_decode_raw_safe(current)
			if len(decoded) > 2 and any(char.isalnum() for char in decoded):
				current = decoded
				steps.append(f"Layer {layer} [Base64-safe]: {current}")
				continue
		except (binascii.Error, ValueError, UnicodeError):
			pass
		decoded_base32 = decode_base32(current)
		if decoded_base32 and decoded_base32 != current:
			current = decoded_base32
			steps.append(f"Layer {layer} [Base32]: {current}")
			continue
		decoded_base85 = decode_base85(current)
		if decoded_base85 and decoded_base85 != current:
			current = decoded_base85
			steps.append(f"Layer {layer} [Base85]: {current}")
			continue
		try:
			clean_hex = current.replace(" ", "").replace("0x", "")
			decoded = _decode_raw_text(bytes.fromhex(clean_hex))
			if len(decoded) > 2 and any(char.isalnum() for char in decoded):
				current = decoded
				steps.append(f"Layer {layer} [Hex-safe]: {current}")
				continue
		except (ValueError, UnicodeError):
			pass
		best_text, best_score, best_shift = current, float("-inf"), 0
		for shift in range(1, 26):
			candidate = current.translate(_caesar_table(shift))
			candidate_score = score_english(candidate)
			if candidate_score > best_score:
				best_text, best_score, best_shift = candidate, candidate_score, shift
		if best_text != current and best_score > 0:
			current = best_text
			steps.append(f"Layer {layer} [Caesar/ROT shift={best_shift}]: {current}")
			continue
		best_text, best_ratio, best_shift = current, 0.0, 0
		for shift in range(1, 256):
			candidate = decode_caesar_ascii256(current, shift)
			printable_ratio = sum(0x20 <= ord(char) <= 0x7E for char in candidate) / max(len(candidate), 1)
			if printable_ratio > best_ratio:
				best_text, best_ratio, best_shift = candidate, printable_ratio, shift
		if best_text != current and best_ratio > 0.85:
			current = best_text
			steps.append(f"Layer {layer} [ASCII-256 shift={best_shift}]: {current}")
			continue
		break
	return {"chain": steps, "final_plaintext": current}


SEPARATOR = "=" * 60


def print_results(original: str, detections: list[tuple[str, str]],
				  decoded_results: dict[str, Optional[str]], chain_steps: Optional[list[dict]] = None,
				  verbose: bool = False) -> None:
	print(f"\n{SEPARATOR}\n   OMNI-CIPHER BOT - Cipher Engine Results\n{SEPARATOR}")
	print(f"Input ({len(original)} chars): {original[:120]}{'...' if len(original) > 120 else ''}\n")
	print("Detected Cipher(s):")
	for cipher, confidence in detections:
		print(f"  {cipher:<12} - Confidence: {confidence}")
	print("\nDecoded Results:")
	for cipher, result in decoded_results.items():
		if result:
			print(f"\n  [{cipher.upper()}]\n  {result[:200].replace(chr(10), chr(92) + 'n')}"
				  f"{'...' if len(result) > 200 else ''}")
			if verbose and len(result) > 200:
				print(f"  (Full length: {len(result)} chars)")
	if chain_steps:
		print(f"\n{'-' * 60}\nAuto-Chain Trace:")
		for step in chain_steps:
			indent = "  " * (step["depth"] + 1)
			print(f"{indent}[Depth {step['depth']}] {step['cipher'].upper()}\n"
				  f"{indent}  -> {step['result'][:100].replace(chr(10), chr(92) + 'n')}")
	print(f"\n{SEPARATOR}")


_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_TIMELINE_DIR = os.path.join(_REPO_ROOT, "puzzles", "logs", "timelines")
_DIAGNOSTIC_DIR = os.path.join(_REPO_ROOT, "puzzles", "logs", "diagnostics")


def _ocb_ensure_dirs() -> None:
	os.makedirs(_TIMELINE_DIR, exist_ok=True)
	os.makedirs(_DIAGNOSTIC_DIR, exist_ok=True)


def _ocb_ts() -> str:
	return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _ocb_locked_append(path: str, content: str) -> None:
	with open(path, "a", encoding="utf-8") as handle:
		fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
		try:
			handle.write(content)
			handle.flush()
			os.fsync(handle.fileno())
		finally:
			fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _ocb_timeline_write(asset_name: str, lines: list[str]) -> dict[str, str]:
	_ocb_ensure_dirs()
	safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in asset_name)
	digest = hashlib.sha256(asset_name.encode("utf-8")).hexdigest()[:12]
	path = os.path.join(_TIMELINE_DIR, f"cipher_{safe_name}_{digest}.txt")
	content = f"\n{'-' * 60}\n[{_ocb_ts()}] cipher-engine asset={asset_name}\n"
	content += "".join(f"  {line}\n" for line in lines)
	_ocb_locked_append(path, content)
	return {"timeline_path": path, "diagnostic_path": os.path.join(_DIAGNOSTIC_DIR, "cipher_engine_diagnostics.txt")}


def _ocb_diag_write(fn_sig: str, lineno: int, root_cause: str, suggestion: str) -> None:
	_ocb_ensure_dirs()
	path = os.path.join(_DIAGNOSTIC_DIR, "cipher_engine_diagnostics.txt")
	content = (f"\n{'=' * 60}\n[{_ocb_ts()}]\n  Tool: cipher_tool_optimized.py\n"
			   f"  Function: {fn_sig}\n  Line: {lineno}\n  Root cause: {root_cause}\n  Fix model:\n")
	content += "".join(f"    {line}\n" for line in suggestion.strip().splitlines())
	_ocb_locked_append(path, content)


def ocb_cipher_chain_logged(text: str, asset_name: str = "inline") -> dict:
	timeline = [f"START input_len={len(text)} preview={text[:60]!r}"]
	result: dict = {"contract": "ocb.v1", "tool": "cipher-engine", "asset": asset_name,
					"findings": {}, "steps": [], "final": text}
	started = time.perf_counter()
	try:
		current = text
		for depth, (cipher, confidence) in enumerate(detect_cipher(text)):
			if cipher == "plaintext":
				break
			step_started = time.perf_counter()
			decoded = apply_cipher(current, cipher)
			if decoded and decoded != current:
				timeline.append(f"LAYER depth={depth} cipher={cipher} conf={confidence} "
								f"len_in={len(current)} len_out={len(decoded)} "
								f"time={(time.perf_counter() - step_started) * 1000:.2f}ms")
				result["steps"].append({"depth": depth, "cipher": cipher,
										"confidence": confidence, "output": decoded})
				current = decoded
		result["final"] = current
		timeline.append(f"END final_len={len(current)} total_time="
						f"{(time.perf_counter() - started) * 1000:.2f}ms")
	except Exception as error:
		result["error"] = f"{type(error).__name__}: {error}"
		timeline.append(f"FATAL {result['error']}")
		_ocb_diag_write("ocb_cipher_chain_logged(text, asset_name)", 0, result["error"],
						"Validate that text is a non-empty string before decoding.")
	result["findings"]["chain"] = result["steps"]
	result["telemetry"] = {
		"contract": "ocb.v1", "tool": "cipher-engine", "asset": asset_name,
		**_ocb_timeline_write(asset_name, timeline), "events": timeline,
	}
	return result


def _cipher_main() -> None:
	parser = argparse.ArgumentParser(description="Omni-Cipher Bot - Cipher Engine")
	parser.add_argument("--input", "-i", help="Encoded string (inline)")
	parser.add_argument("--file", "-f", help="Path to file with encoded content")
	parser.add_argument("--cipher", "-c", help="Force a cipher")
	parser.add_argument("--mode", "-m", choices=["decode", "encode"], default="decode")
	parser.add_argument("--key", "-k", help="Key for Vigenere; shift for Caesar")
	parser.add_argument("--chain", action="store_true", help="Auto-chain decode until plaintext")
	parser.add_argument("--output", "-o", help="Write results to file")
	parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
	args = parser.parse_args()
	if args.key or args.cipher:
		record_resource_insufficiency(
			"cipher-engine",
			Path(__file__),
			"manually overridden cipher decoding",
			"Automatic cipher detection or key estimation was bypassed for this invocation.",
			[
				"Expand key-length scoring and language models for the detected cipher family.",
				"Add confidence reporting and preserve punctuation during candidate scoring.",
			],
		)

	if args.file:
		try:
			with open(args.file, "rb") as handle:
				size = os.fstat(handle.fileno()).st_size
				if size == 0:
					text = ""
				else:
					with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
						text = "".join(
							_decode_raw_text(mapped[offset:offset + 1024 * 1024])
							for offset in range(0, size, 1024 * 1024)
						)
		except FileNotFoundError:
			print(f"[cipher-engine] ERROR: File not found: {args.file}")
			raise SystemExit(1)
	elif args.input is not None:
		text = args.input
	else:
		print("[cipher-engine] Reading from stdin (Ctrl+D to finish)...")
		text = sys.stdin.read()
	text = text.strip()
	if not text:
		print("[cipher-engine] ERROR: No input provided.")
		raise SystemExit(1)
	asset_name = os.path.basename(args.file) if args.file else ("inline" if args.input is not None else "stdin")
	telemetry = ocb_cipher_chain_logged(text, asset_name)
	print(f"[cipher-engine] Telemetry: {telemetry['telemetry']['timeline_path']}")

	output_lines: list[str] = []
	if args.cipher:
		result = apply_cipher(text, args.cipher, args.mode, args.key, args.verbose)
		if result is None:
			print(f"[cipher-engine] Failed to apply cipher '{args.cipher}'.")
			raise SystemExit(1)
		append_record(
			"ALGORITHM_OPERATION",
			tool="cipher-engine",
			source=Path(__file__),
			state="COMPLETED",
			details={"algorithm": args.cipher.lower(), "mode": args.mode,
					 "input_characters": len(text), "output_characters": len(result)},
		)
		print(f"\n{SEPARATOR}\n   Cipher: {args.cipher.upper()} | Mode: {args.mode.upper()}\n{SEPARATOR}")
		print(f"Input:  {text[:120]}\nOutput: {result[:400]}\n{SEPARATOR}")
		output_lines.append(result)
	else:
		detections = detect_cipher(text)
		decoded_results: dict[str, Optional[str]] = {
			cipher: result for cipher, _ in detections if cipher != "plaintext"
			if (result := apply_cipher(text, cipher, "decode", args.key, args.verbose))
		}
		append_record(
			"ALGORITHM_OPERATION",
			tool="cipher-engine",
			source=Path(__file__),
			state="COMPLETED",
			details={"algorithms_detected": [name for name, _ in detections],
					 "algorithms_applied": list(decoded_results), "mode": "decode"},
		)
		if not decoded_results:
			decoded_results["plaintext"] = text
		print_results(text, detections, decoded_results,
					  chain_decode(text, verbose=args.verbose) if args.chain else None,
					  args.verbose)
		result_chain = solve_multi_layer_cipher(text)
		print("\n" + "=" * 40 + "\nOMNI-CIPHER CHAIN AUTO-DECRYPTOR\n" + "=" * 40)
		for step in result_chain["chain"]:
			print(f"  {step}")
		print(f"\n[FINAL PLAINTEXT FLAG]: {result_chain['final_plaintext']}\n{'=' * 40}\n")
		output_lines.extend(result for result in decoded_results.values() if result)

	if args.output and output_lines:
		try:
			with open(args.output, "w", encoding="utf-8") as handle:
				handle.write("\n\n---\n\n".join(output_lines))
			print(f"[cipher-engine] Results written to: {args.output}")
		except OSError as error:
			print(f"[cipher-engine] WARNING: Could not write output file: {error}")


# === OMNI-CIPHER APEX CORE UNION ===
_APEX_TIMELINE_DIR = os.path.join(_REPO_ROOT, "puzzles", "logs", "timelines")
_APEX_DIAGNOSTIC_DIR = os.path.join(_REPO_ROOT, "puzzles", "logs", "diagnostics")


def _apex_emit_transaction(state: str, detail: str) -> None:
	"""Best-effort synchronized execution record; telemetry must not stop the CLI."""
	record = json.dumps({
		"contract": "ocb.apex.v1",
		"tool": "cipher-engine",
		"state": state,
		"timestamp": _dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
		"detail": detail,
	}, ensure_ascii=False, sort_keys=True) + "\n"
	for directory in (_APEX_TIMELINE_DIR, _APEX_DIAGNOSTIC_DIR):
		try:
			os.makedirs(directory, exist_ok=True)
			path = os.path.join(directory, "apex_transactions.jsonl")
			with open(path, "a", encoding="utf-8") as handle:
				fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
				try:
					handle.write(record)
					handle.flush()
					os.fsync(handle.fileno())
				finally:
					fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
		except Exception as error:
			print(f"[cipher-engine] Telemetry write failed: {type(error).__name__}: {error}", file=sys.stderr)


_LIFECYCLE_IMPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _LIFECYCLE_IMPORT_DIR not in sys.path:
	sys.path.insert(0, _LIFECYCLE_IMPORT_DIR)
from apex_lifecycle import append_record, record_resource_insufficiency, run_cli


# === OMNI-CIPHER APEX LIFECYCLE AGENT ===
def main() -> None:
	run_cli("cipher-engine", __file__, _cipher_main, _apex_emit_transaction)


if __name__ == "__main__":
	main()
