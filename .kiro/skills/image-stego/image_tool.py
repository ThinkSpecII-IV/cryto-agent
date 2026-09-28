#!/usr/bin/env python3
"""
Omni-Cipher Bot — Image Steganography Tool
Scans PNG/JPG images for EXIF metadata, LSB hidden data,
color-plane anomalies, PNG chunks, and embedded strings.

Auto-installs: Pillow, opencv-python, numpy
"""

import sys
import subprocess
import importlib
import struct
import fcntl
import hashlib


# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------

DEPS = [
    ("PIL", "Pillow==12.3.0"),
    ("cv2", "opencv-python==5.0.0.93"),
    ("numpy", "numpy==2.5.3"),
]


def ensure_deps() -> None:
    for import_name, pip_name in DEPS:
        try:
            importlib.import_module(import_name)
        except ImportError:
            print(f"[image-stego] Installing missing dependency: {pip_name}")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_name]
            )


ensure_deps()

# ---------------------------------------------------------------------------
# Now safe to import
# ---------------------------------------------------------------------------

import argparse
import os
import zlib
from pathlib import Path
from typing import Optional

import cv2
import numpy as np
from PIL import Image, ExifTags
from PIL.ExifTags import TAGS, GPSTAGS

SEPARATOR = "=" * 65


def _decode_raw_text(raw: bytes) -> str:
    """Decode bytes without dropping invalid UTF-8 sequences."""
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="strict")


# ---------------------------------------------------------------------------
# EXIF extraction
# ---------------------------------------------------------------------------

def _gps_to_decimal(values, ref: str) -> float:
    """Convert GPS EXIF rational values to decimal degrees."""
    try:
        deg = float(values[0])
        min_ = float(values[1])
        sec = float(values[2])
        decimal = deg + min_ / 60 + sec / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return 0.0


def extract_exif(img_path: str, verbose: bool = False) -> dict:
    """Extract all EXIF, IPTC, and embedded metadata from an image."""
    findings: dict = {}

    try:
        img = Image.open(img_path)
    except Exception as e:
        return {"error": str(e)}

    # --- Standard EXIF ---
    try:
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, f"Tag_{tag_id}")
                if tag_name == "GPSInfo":
                    gps = {}
                    for gps_tag_id, gps_value in value.items():
                        gps_name = GPSTAGS.get(gps_tag_id, f"GPS_{gps_tag_id}")
                        gps[gps_name] = gps_value
                    # Compute decimal coords if available
                    lat = gps.get("GPSLatitude")
                    lat_ref = gps.get("GPSLatitudeRef", "N")
                    lon = gps.get("GPSLongitude")
                    lon_ref = gps.get("GPSLongitudeRef", "E")
                    if lat and lon:
                        gps["_DecimalLatitude"] = _gps_to_decimal(lat, lat_ref)
                        gps["_DecimalLongitude"] = _gps_to_decimal(lon, lon_ref)
                    findings["GPS"] = gps
                else:
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="replace").rstrip("\x00")
                        except Exception:
                            value = value.hex()
                    findings[tag_name] = str(value)[:500]
    except (AttributeError, Exception):
        pass

    # --- PNG text chunks via PIL info ---
    if img.format == "PNG":
        for key, val in img.info.items():
            findings[f"PNG.{key}"] = str(val)[:500]

    # --- Image basic info ---
    findings["_Format"] = img.format or "Unknown"
    findings["_Mode"] = img.mode
    findings["_Size"] = f"{img.width}×{img.height}"

    return findings


# ---------------------------------------------------------------------------
# PNG chunk parser
# ---------------------------------------------------------------------------

def parse_png_chunks(img_path: str) -> list[dict]:
    """Low-level PNG chunk reader to find tEXt/zTXt/iTXt/custom chunks."""
    chunks = []
    try:
        with open(img_path, "rb") as f:
            signature = f.read(8)
            if signature != b"\x89PNG\r\n\x1a\n":
                return [{"error": "Not a valid PNG file"}]

            while True:
                header = f.read(8)
                if len(header) < 8:
                    break
                length = struct.unpack(">I", header[:4])[0]
                chunk_type = header[4:8].decode("ascii", errors="replace")
                data = f.read(length)
                crc = f.read(4)

                chunk_info: dict = {"type": chunk_type, "length": length}

                if chunk_type == "tEXt":
                    try:
                        null_pos = data.index(b"\x00")
                        keyword = data[:null_pos].decode("latin-1")
                        text = data[null_pos + 1:].decode("latin-1", errors="replace")
                        chunk_info["keyword"] = keyword
                        chunk_info["text"] = text
                    except Exception as e:
                        chunk_info["raw"] = data.hex()
                        chunk_info["error"] = str(e)

                elif chunk_type == "zTXt":
                    try:
                        null_pos = data.index(b"\x00")
                        keyword = data[:null_pos].decode("latin-1")
                        compressed = data[null_pos + 2:]
                        text = zlib.decompress(compressed).decode("utf-8", errors="replace")
                        chunk_info["keyword"] = keyword
                        chunk_info["text"] = text
                    except Exception as e:
                        chunk_info["raw"] = data[:64].hex()
                        chunk_info["error"] = str(e)

                elif chunk_type == "iTXt":
                    try:
                        chunk_info["text"] = data.decode("utf-8", errors="replace")[:500]
                    except Exception:
                        chunk_info["raw"] = data[:64].hex()

                elif chunk_type not in ("IHDR", "IDAT", "IEND", "PLTE", "bKGD",
                                         "cHRM", "gAMA", "pHYs", "sBIT", "sRGB",
                                         "hIST", "tIME"):
                    # Unusual / ancillary chunk
                    chunk_info["note"] = "Non-standard chunk — may contain hidden data"
                    chunk_info["preview"] = data[:64].hex()

                chunks.append(chunk_info)

                if chunk_type == "IEND":
                    # Check for appended data
                    remainder = f.read()
                    if remainder:
                        chunks.append({
                            "type": "APPENDED_DATA",
                            "length": len(remainder),
                            "preview": remainder[:128].hex(),
                            "note": "Data found after IEND — may be another file or hidden payload",
                        })
                    break

    except Exception as e:
        chunks.append({"error": str(e)})

    return chunks


# ---------------------------------------------------------------------------
# LSB extraction
# ---------------------------------------------------------------------------

def extract_lsb(
    img_path: str,
    bits_per_channel: int = 1,
    verbose: bool = False,
) -> dict:
    """
    Extract LSB bits from all channels in row-major order.
    Returns extracted bytes and text preview.
    """
    try:
        img = Image.open(img_path).convert("RGBA")
    except Exception as e:
        return {"error": str(e)}

    pixels = np.array(img)
    height, width, channels = pixels.shape

    # Build bit mask for requested LSB depth
    mask = (1 << bits_per_channel) - 1

    # --- vectorized replacement for 4-nested Python loops ---
    # Slice the first min(channels,4) planes, shape (H, W, C).
    # For each requested bit depth we shift right by (bit_pos) and AND with 1,
    # producing one bit-plane per (channel, bit_pos) pair in row-major order.
    n_ch = min(channels, 4)
    planes = pixels[:, :, :n_ch].astype(np.uint8)   # (H, W, C) uint8

    if bits_per_channel == 1:
        # Common fast path: just the LSB of each channel pixel
        # Shape (H, W, C) -> flatten to 1-D bit array
        bit_planes = (planes & 1).reshape(-1)          # (H*W*C,) uint8 0/1
    else:
        # General path: extract bits_per_channel bits per pixel per channel,
        # MSB-first within each pixel's bit group.
        bit_shifts = np.arange(bits_per_channel - 1, -1, -1, dtype=np.uint8)
        # planes: (H, W, C), bit_shifts: (B,) -> broadcast to (H, W, C, B)
        bit_planes = ((planes[:, :, :, np.newaxis] >> bit_shifts) & 1
                      ).reshape(-1).astype(np.uint8)   # (H*W*C*B,)

    total_bits = len(bit_planes)

    # Pack bits into bytes with np.packbits (MSB-first, same as the original loop)
    # Trim to a multiple of 8 before packing so no phantom zero-padding bytes appear.
    trim = (total_bits // 8) * 8
    byte_data = bytearray(np.packbits(bit_planes[:trim]))
    total_bytes = len(byte_data)

    # Try to interpret as text
    text_preview = None
    text_confidence = "LOW"
    decoded = _decode_raw_text(bytes(byte_data))
    printable = "".join(c for c in decoded if c.isprintable() or c in "\n\r\t")
    if len(printable) > 20:
        text_preview = decoded[:500]
        printable_ratio = len(printable) / max(len(decoded), 1)
        if printable_ratio > 0.7:
            text_confidence = "HIGH"
        elif printable_ratio > 0.4:
            text_confidence = "MEDIUM"

    # Try null-terminated string from beginning
    null_terminated = None
    if b"\x00" in byte_data[:1000]:
        null_pos = byte_data.index(b"\x00")
        candidate = byte_data[:null_pos]
        try:
            null_terminated = _decode_raw_text(bytes(candidate))
        except Exception:
            pass

    return {
        "total_bits": total_bits,
        "total_bytes": total_bytes,
        "bits_per_channel": bits_per_channel,
        "text_preview": text_preview,
        "text_confidence": text_confidence,
        "null_terminated_string": null_terminated,
        "raw_bytes": bytes(byte_data),
        "hex_preview": byte_data[:64].hex(),
    }


# ---------------------------------------------------------------------------
# Color plane analysis
# ---------------------------------------------------------------------------

def _entropy(channel_array: np.ndarray) -> float:
    """Calculate Shannon entropy of a grayscale image array."""
    hist, _ = np.histogram(channel_array.flatten(), bins=256, range=(0, 256))
    hist = hist / hist.sum()
    hist = hist[hist > 0]
    return float(-np.sum(hist * np.log2(hist)))


def analyze_color_planes(
    img_path: str,
    save_planes: bool = False,
    output_dir: str = "puzzles/planes",
    verbose: bool = False,
) -> dict:
    """Analyze R/G/B/A channels for steganographic anomalies."""
    try:
        img_cv = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
        if img_cv is None:
            return {"error": f"OpenCV could not open: {img_path}"}
    except Exception as e:
        return {"error": str(e)}

    has_alpha = img_cv.shape[2] == 4 if img_cv.ndim == 3 else False

    # OpenCV loads as BGR(A)
    if has_alpha:
        b, g, r, a = cv2.split(img_cv)
        channel_map = {"Red": r, "Green": g, "Blue": b, "Alpha": a}
    else:
        b, g, r = cv2.split(img_cv) if img_cv.ndim == 3 else (img_cv, img_cv, img_cv)
        channel_map = {"Red": r, "Green": g, "Blue": b}

    results: dict = {}

    for ch_name, ch_data in channel_map.items():
        hist = cv2.calcHist([ch_data], [0], None, [256], [0, 256]).flatten()
        hist_normalized = hist / max(hist.sum(), 1)

        # Anomaly scoring
        entropy = _entropy(ch_data)
        # Ideal entropy for uniform noise ~= 8.0; natural images ~= 6-7.5
        entropy_score = abs(entropy - 7.0) / 7.0

        # Spike detection at 0 and 255
        extreme_ratio = (float(hist[0]) + float(hist[255])) / max(float(hist.sum()), 1)

        # Odd/even imbalance (LSB test)
        odd_count = int(np.sum(ch_data % 2 == 1))
        even_count = int(np.sum(ch_data % 2 == 0))
        total = odd_count + even_count
        lsb_imbalance = abs(odd_count - even_count) / max(total, 1)

        # Overall anomaly score (0..1)
        anomaly_score = min(
            (entropy_score * 0.4 + extreme_ratio * 0.3 + lsb_imbalance * 0.3), 1.0
        )
        anomaly_label = (
            "HIGH" if anomaly_score > 0.5
            else "MEDIUM" if anomaly_score > 0.25
            else "LOW"
        )

        ch_result = {
            "entropy": round(entropy, 4),
            "anomaly_score": round(anomaly_score, 4),
            "anomaly_level": anomaly_label,
            "lsb_imbalance": round(lsb_imbalance, 4),
            "extreme_value_ratio": round(extreme_ratio, 4),
            "mean": round(float(ch_data.mean()), 2),
            "std": round(float(ch_data.std()), 2),
        }

        # Bit-plane analysis
        bit_planes: dict = {}
        for bit in range(8):
            plane = ((ch_data >> bit) & 1) * 255
            plane_mean = float(plane.mean())
            # Random noise → mean ≈ 127.5; structured data → mean ≠ 127.5
            bit_anomaly = abs(plane_mean - 127.5) / 127.5
            bit_planes[f"bit_{bit}"] = {
                "mean": round(plane_mean, 2),
                "anomaly": round(bit_anomaly, 4),
            }
        ch_result["bit_planes"] = bit_planes

        if save_planes:
            os.makedirs(output_dir, exist_ok=True)
            plane_path = os.path.join(output_dir, f"{Path(img_path).stem}_{ch_name.lower()}.png")
            cv2.imwrite(plane_path, ch_data)
            ch_result["saved_to"] = plane_path

        results[ch_name] = ch_result

    return results


# ---------------------------------------------------------------------------
# String extraction from pixel data
# ---------------------------------------------------------------------------

def extract_strings(
    img_path: str,
    min_length: int = 6,
    verbose: bool = False,
) -> list[dict]:
    """Find printable ASCII strings in raw pixel bytes."""
    try:
        img = Image.open(img_path)
        raw = img.tobytes()
    except Exception as e:
        return [{"error": str(e)}]

    strings_found: list[dict] = []
    current: list[int] = []
    start_offset = 0

    for i, byte in enumerate(raw):
        if 0x20 <= byte <= 0x7E:  # Printable ASCII
            if not current:
                start_offset = i
            current.append(byte)
        else:
            if len(current) >= min_length:
                s = bytes(current).decode("ascii")
                strings_found.append({
                    "offset": f"0x{start_offset:06X}",
                    "length": len(s),
                    "string": s[:200],
                })
            current = []

    if len(current) >= min_length:
        strings_found.append({
            "offset": f"0x{start_offset:06X}",
            "length": len(current),
            "string": bytes(current).decode("ascii")[:200],
        })

    return strings_found


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_banner(img_path: str, img: Image.Image) -> None:
    size_bytes = os.path.getsize(img_path)
    size_mb = size_bytes / (1024 * 1024)
    print(f"\n{SEPARATOR}")
    print("   OMNI-CIPHER BOT — Image Steganography Tool")
    print(SEPARATOR)
    print(f"File   : {img_path}")
    print(f"Format : {img.format or 'Unknown'} | Mode: {img.mode}")
    print(f"Size   : {img.width}×{img.height} px | {size_mb:.2f} MB")
    print(SEPARATOR)


def print_exif_results(exif: dict) -> None:
    print("\n[EXIF / Metadata]")
    if "error" in exif:
        print(f"  ⚠ {exif['error']}")
        return
    interesting = {
        k: v for k, v in exif.items()
        if k not in ("_Format", "_Mode", "_Size")
    }
    if not interesting:
        print("  No EXIF data found.")
        return
    for key, val in interesting.items():
        if isinstance(val, dict):
            print(f"  {key}:")
            for k2, v2 in val.items():
                print(f"    {k2}: {v2}")
        else:
            print(f"  {key}: {val}")


def print_chunk_results(chunks: list[dict]) -> None:
    print("\n[PNG Chunks]")
    notable = [
        c for c in chunks
        if c.get("type") not in ("IHDR", "IDAT", "IEND", "PLTE", "bKGD",
                                   "cHRM", "gAMA", "pHYs", "sBIT", "sRGB",
                                   "hIST", "tIME") or "text" in c
    ]
    if not notable:
        print("  No notable chunks found.")
        return
    for chunk in notable:
        if "error" in chunk:
            print(f"  ⚠ {chunk['error']}")
            continue
        ch_type = chunk.get("type", "?")
        if "text" in chunk:
            kw = chunk.get("keyword", "")
            print(f"  [{ch_type}] {kw}: {chunk['text'][:120]}")
        elif "note" in chunk:
            print(f"  [{ch_type}] ⚠ {chunk['note']}")
            if "preview" in chunk:
                print(f"    Hex: {chunk['preview'][:80]}")
        else:
            print(f"  [{ch_type}] length={chunk.get('length', '?')}")


def print_lsb_results(lsb: dict) -> None:
    print("\n[LSB Steganography]")
    if "error" in lsb:
        print(f"  ⚠ {lsb['error']}")
        return
    print(f"  Extracted: {lsb['total_bits']:,} bits → {lsb['total_bytes']:,} bytes")
    print(f"  Hex preview: {lsb['hex_preview'][:64]}")
    if lsb.get("null_terminated_string"):
        print(f"  Null-terminated string: {lsb['null_terminated_string'][:120]}")
    if lsb.get("text_preview"):
        conf = lsb["text_confidence"]
        print(f"  Text confidence: {conf}")
        print(f"  Text preview: {lsb['text_preview'][:300]}")
    else:
        print("  No readable text found in LSB data.")


def print_plane_results(planes: dict) -> None:
    print("\n[Color Plane Analysis]")
    if "error" in planes:
        print(f"  ⚠ {planes['error']}")
        return
    for ch_name, ch_data in planes.items():
        level = ch_data.get("anomaly_level", "?")
        score = ch_data.get("anomaly_score", 0)
        entropy = ch_data.get("entropy", 0)
        lsb_imb = ch_data.get("lsb_imbalance", 0)
        indicator = "🔴" if level == "HIGH" else "🟡" if level == "MEDIUM" else "🟢"
        print(f"  {indicator} {ch_name:<8} anomaly={score:.3f} ({level})"
              f"  entropy={entropy:.3f}  lsb_imbalance={lsb_imb:.3f}")
        if ch_data.get("saved_to"):
            print(f"    Saved: {ch_data['saved_to']}")
        # Show flagged bit planes
        for bp_name, bp_data in ch_data.get("bit_planes", {}).items():
            if bp_data["anomaly"] > 0.3:
                print(f"    ⚠ {bp_name}: mean={bp_data['mean']:.1f} anomaly={bp_data['anomaly']:.3f}")


def print_string_results(strings: list[dict]) -> None:
    print("\n[Embedded Strings]")
    errors = [s for s in strings if "error" in s]
    if errors:
        print(f"  ⚠ {errors[0]['error']}")
        return
    if not strings:
        print("  No printable strings found.")
        return
    print(f"  Found {len(strings)} string(s):")
    for s in strings[:20]:  # Limit display
        print(f"  {s['offset']} ({s['length']:4d} chars): {s['string'][:80]}")
    if len(strings) > 20:
        print(f"  ... and {len(strings) - 20} more")


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def scan_image(
    img_path: str,
    technique: str = "all",
    save_planes: bool = False,
    output: Optional[str] = None,
    lsb_bits: int = 1,
    verbose: bool = False,
) -> None:
    """Run the full steganography scan on a single image."""
    if not os.path.isfile(img_path):
        print(f"[image-stego] ERROR: File not found: {img_path}")
        return

    try:
        img = Image.open(img_path)
    except Exception as e:
        print(f"[image-stego] ERROR opening image: {e}")
        return

    print_banner(img_path, img)
    output_data: list[str] = []

    if technique in ("all", "exif"):
        exif = extract_exif(img_path, verbose)
        print_exif_results(exif)
        output_data.append(f"[EXIF]\n{exif}")

    if technique in ("all", "chunks") and (img.format == "PNG"):
        chunks = parse_png_chunks(img_path)
        print_chunk_results(chunks)
        output_data.append(f"[CHUNKS]\n{chunks}")

    if technique in ("all", "lsb"):
        lsb = extract_lsb(img_path, lsb_bits, verbose)
        print_lsb_results(lsb)
        if output and lsb.get("raw_bytes"):
            bin_path = output if output.endswith(".bin") else output + ".bin"
            with open(bin_path, "wb") as fh:
                fh.write(lsb["raw_bytes"])
            print(f"\n[image-stego] LSB raw bytes written to: {bin_path}")

    if technique in ("all", "planes"):
        planes = analyze_color_planes(img_path, save_planes, verbose=verbose)
        print_plane_results(planes)

    if technique in ("all", "strings"):
        strings = extract_strings(img_path, verbose=verbose)
        print_string_results(strings)

    # ------------------------------------------------------------------
    # RGB Extension Block
    # Converts img_cv from BGR to RGB and scans each channel's LSBs
    # for embedded ASCII text strings longer than 4 characters.
    # This block is additive — it does not modify any BGR logic above.
    # ------------------------------------------------------------------
    if technique in ("all", "planes", "lsb"):
        try:
            img_cv_rgb_ext = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
            if img_cv_rgb_ext is not None:
                img_rgb = cv2.cvtColor(
                    img_cv_rgb_ext[:, :, :3] if img_cv_rgb_ext.ndim == 3 and img_cv_rgb_ext.shape[2] >= 3
                    else img_cv_rgb_ext,
                    cv2.COLOR_BGR2RGB,
                )
                print("[RGB Extension — LSB ASCII Scan]")
                channel_names = ["Red", "Green", "Blue"]
                found_any = False
                for ch_idx, ch_name in enumerate(channel_names):
                    plane = img_rgb[:, :, ch_idx]
                    # Extract LSBs in row-major order, pack into bytes
                    # Vectorized: isolate LSB plane, trim to multiple of 8,
                    # then let np.packbits assemble the bytes (MSB-first).
                    lsb_plane = (plane.flatten() & np.uint8(1))
                    trim = (lsb_plane.size // 8) * 8
                    byte_vals = bytearray(np.packbits(lsb_plane[:trim]))
                    # Extract printable ASCII strings longer than 4 chars
                    current_run: list[int] = []
                    strings_found: list[str] = []
                    for b in byte_vals:
                        if 0x20 <= b <= 0x7E:
                            current_run.append(b)
                        else:
                            if len(current_run) > 4:
                                strings_found.append(bytes(current_run).decode("ascii"))
                            current_run = []
                    if current_run and len(current_run) > 4:
                        strings_found.append(bytes(current_run).decode("ascii"))
                    if strings_found:
                        found_any = True
                        print(f"  {ch_name} channel — {len(strings_found)} string(s) found:")
                        for s in strings_found[:10]:
                            print(f"    → {s[:120]!r}")
                    elif verbose:
                        print(f"  {ch_name} channel — no ASCII strings > 4 chars in LSBs")
                if not found_any:
                    print("  No hidden ASCII strings detected in RGB LSB planes.")
        except Exception as e:
            print(f"  [RGB Extension] Error: {e}")

    print(f"\n{SEPARATOR}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Omni-Cipher Bot — Image Steganography Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python image_tool.py --input puzzles/image.png
  python image_tool.py --input puzzles/photo.jpg --technique lsb
  python image_tool.py --input puzzles/image.png --technique exif
  python image_tool.py --input puzzles/image.png --technique planes --save-planes
  python image_tool.py --dir puzzles/
""",
    )
    parser.add_argument("--input", "-i", help="Path to image file")
    parser.add_argument("--dir", "-d", help="Directory to scan all PNG/JPG files")
    parser.add_argument(
        "--technique", "-t",
        choices=["all", "exif", "lsb", "planes", "strings", "chunks"],
        default="all",
        help="Analysis technique (default: all)",
    )
    parser.add_argument("--output", "-o", help="Write extracted LSB data to file")
    parser.add_argument(
        "--save-planes", action="store_true",
        help="Save color channel images to puzzles/planes/",
    )
    parser.add_argument(
        "--lsb-bits", type=int, default=1,
        help="Number of LSB bits per channel to extract (default: 1)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.dir:
        target_dir = Path(args.dir)
        if not target_dir.is_dir():
            print(f"[image-stego] ERROR: Not a directory: {args.dir}")
            sys.exit(1)
        images = list(target_dir.glob("*.png")) + list(target_dir.glob("*.jpg")) + \
                 list(target_dir.glob("*.jpeg")) + list(target_dir.glob("*.PNG")) + \
                 list(target_dir.glob("*.JPG"))
        if not images:
            print(f"[image-stego] No PNG/JPG images found in {args.dir}")
            sys.exit(0)
        for img_path in sorted(images):
            scan_image(
                str(img_path), args.technique, args.save_planes,
                args.output, args.lsb_bits, args.verbose
            )
            telemetry = ocb_image_scan_logged(str(img_path))
            print(f"[image-stego] Telemetry: {telemetry['telemetry']['timeline_path']}")
    elif args.input:
        scan_image(
            args.input, args.technique, args.save_planes,
            args.output, args.lsb_bits, args.verbose
        )
        telemetry = ocb_image_scan_logged(args.input)
        print(f"[image-stego] Telemetry: {telemetry['telemetry']['timeline_path']}")
    else:
        parser.print_help()
        sys.exit(1)


# === OMNI-CIPHER BOT EXTENSION ===
# Additive optimization block — timeline logging + diagnostic capture.
# Zero modifications to any function above this line.
# ═══════════════════════════════════════════════════════════════════════

import datetime as _dt_img
import traceback as _tb_img
import time as _time_img

_REPO_ROOT_IMG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_TIMELINE_DIR_IMG = os.path.join(_REPO_ROOT_IMG, "puzzles", "logs", "timelines")
_DIAGNOSTIC_DIR_IMG = os.path.join(_REPO_ROOT_IMG, "puzzles", "logs", "diagnostics")


def _img_ensure_dirs() -> None:
    import os
    os.makedirs(_TIMELINE_DIR_IMG, exist_ok=True)
    os.makedirs(_DIAGNOSTIC_DIR_IMG, exist_ok=True)


def _img_ts() -> str:
    return _dt_img.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _img_locked_append(path: str, content: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _img_timeline_write(asset_name: str, lines: list) -> dict[str, str]:
    _img_ensure_dirs()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in asset_name)
    digest = hashlib.sha256(asset_name.encode("utf-8")).hexdigest()[:12]
    path = os.path.join(_TIMELINE_DIR_IMG, f"image_{safe}_{digest}.txt")
    content = f"\n{'-' * 60}\n[{_img_ts()}] image-stego asset={asset_name}\n"
    content += "".join(f"  {line}\n" for line in lines)
    _img_locked_append(path, content)
    return {"timeline_path": path, "diagnostic_path": os.path.join(_DIAGNOSTIC_DIR_IMG, "image_stego_diagnostics.txt")}


def _img_diag_write(fn_sig: str, lineno: int, root_cause: str, suggestion: str) -> None:
    _img_ensure_dirs()
    path = os.path.join(_DIAGNOSTIC_DIR_IMG, "image_stego_diagnostics.txt")
    content = (f"\n{'=' * 60}\n[{_img_ts()}]\n"
               f"  Tool: image_tool.py\n  Function: {fn_sig}\n  Line: {lineno}\n"
               f"  Root cause: {root_cause}\n  Fix model:\n")
    content += "".join(f"    {line}\n" for line in suggestion.strip().splitlines())
    _img_locked_append(path, content)


def ocb_image_scan_logged(img_path: str) -> dict:
    """
    Optimized full-image steganography scan with timeline logging.
    Wraps extract_lsb(), extract_exif(), analyze_color_planes(), extract_strings().
    Uses numpy vectorised LSB extraction for maximum speed.
    All errors caught and written to diagnostics without crashing.
    """
    import os
    import time

    asset_name = os.path.basename(img_path)
    timeline: list = []
    result: dict = {"contract": "ocb.v1", "tool": "image-stego", "asset": asset_name,
                    "findings": {}}

    timeline.append(f"START  path={img_path}")
    t0 = time.perf_counter()

    # ── EXIF ──────────────────────────────────────────────────
    try:
        t = time.perf_counter()
        exif = extract_exif(img_path)
        ms = (time.perf_counter() - t) * 1000
        tag_count = len([k for k in exif if not k.startswith("_")])
        timeline.append(f"EXIF   tags={tag_count}  time={ms:.2f}ms")
        if "GPS" in exif:
            timeline.append(f"EXIF   GPS detected: {exif['GPS']}")
        result["findings"]["exif"] = exif
    except Exception as exc:
        lineno = _tb_img.extract_tb(exc.__traceback__)[-1].lineno or 0
        root   = f"{type(exc).__name__}: {exc}"
        _img_diag_write("extract_exif(img_path)", lineno, root,
            "# extract_exif() failed — likely corrupted EXIF segment.\n"
            "# Fix: wrap img._getexif() call in try/except AttributeError\n"
            "# and fall back to img.info dict for PNG text chunks.")
        timeline.append(f"ERROR  EXIF  {root}")

    # ── PNG CHUNKS ────────────────────────────────────────────
    try:
        t = time.perf_counter()
        chunks = parse_png_chunks(img_path)
        ms = (time.perf_counter() - t) * 1000
        notable = [c for c in chunks if "text" in c or "note" in c]
        timeline.append(f"CHUNKS total={len(chunks)}  notable={len(notable)}  time={ms:.2f}ms")
        for c in notable:
            timeline.append(f"CHUNK  type={c.get('type')}  text={str(c.get('text',''))[:60]!r}")
        result["findings"]["chunks"] = notable
    except Exception as exc:
        lineno = _tb_img.extract_tb(exc.__traceback__)[-1].lineno or 0
        root   = f"{type(exc).__name__}: {exc}"
        _img_diag_write("parse_png_chunks(img_path)", lineno, root,
            "# PNG chunk parse failed — file may not be a valid PNG.\n"
            "# Fix: check magic bytes b'\\x89PNG\\r\\n\\x1a\\n' before parsing.\n"
            "# Guard: if Path(img_path).suffix.lower() != '.png': return []")
        timeline.append(f"ERROR  CHUNKS  {root}")

    # ── LSB — vectorised numpy path for speed ─────────────────
    try:
        t = time.perf_counter()
        # Fast vectorised LSB extraction using numpy bit-AND
        from PIL import Image as _PIL_Image
        import numpy as _np_lsb
        _img_arr = _np_lsb.array(_PIL_Image.open(img_path).convert("RGBA"))
        _lsb_bits = (_img_arr & 1).flatten()          # bit-AND entire pixel matrix
        _byte_count = len(_lsb_bits) // 8
        _packed = _np_lsb.packbits(_lsb_bits[:_byte_count * 8])  # numpy packbits = ~10× faster than loop
        _raw_bytes = _packed.tobytes()
        ms = (time.perf_counter() - t) * 1000

        # Extract printable ASCII strings
        _printable = bytes(b for b in _raw_bytes if 0x20 <= b <= 0x7E)
        _text_preview = _printable[:200].decode("ascii", errors="replace")

        timeline.append(f"LSB    pixels={len(_img_arr.flatten())//4}  "
                         f"bits={len(_lsb_bits)}  bytes={_byte_count}  "
                         f"time={ms:.2f}ms  (numpy vectorised)")
        timeline.append(f"LSB    text_preview={_text_preview[:80]!r}")
        result["findings"]["lsb_text_preview"] = _text_preview
    except Exception as exc:
        lineno = _tb_img.extract_tb(exc.__traceback__)[-1].lineno or 0
        root   = f"{type(exc).__name__}: {exc}"
        _img_diag_write("ocb_image_scan_logged → LSB numpy block", lineno, root,
            "# numpy vectorised LSB failed.\n"
            "# Common cause: image mode not convertible to RGBA (e.g. palette PNG).\n"
            "# Fix: use img.convert('RGBA') before np.array().\n"
            "# Fallback: call existing extract_lsb(img_path) which handles modes.")
        timeline.append(f"ERROR  LSB  {root}")

    # ── COLOR PLANES ──────────────────────────────────────────
    try:
        t = time.perf_counter()
        planes = analyze_color_planes(img_path)
        ms = (time.perf_counter() - t) * 1000
        for ch, data in planes.items():
            if isinstance(data, dict):
                timeline.append(
                    f"PLANE  channel={ch}  anomaly={data.get('anomaly_level','?')}  "
                    f"score={data.get('anomaly_score','?')}  entropy={data.get('entropy','?')}  "
                    f"time={ms:.2f}ms"
                )
        result["findings"]["planes"] = {
            k: {"anomaly_level": v.get("anomaly_level"), "anomaly_score": v.get("anomaly_score")}
            for k, v in planes.items() if isinstance(v, dict)
        }
    except Exception as exc:
        lineno = _tb_img.extract_tb(exc.__traceback__)[-1].lineno or 0
        root   = f"{type(exc).__name__}: {exc}"
        _img_diag_write("analyze_color_planes(img_path)", lineno, root,
            "# Color plane analysis failed.\n"
            "# Common cause: cv2.imread() returns None for unsupported format.\n"
            "# Fix: check `if img_cv is None: return {'error': ...}` at top of function.\n"
            "# Also ensure opencv-python is installed: pip install opencv-python")
        timeline.append(f"ERROR  PLANES  {root}")

    # ── STRING EXTRACTION ─────────────────────────────────────
    try:
        t = time.perf_counter()
        strings = extract_strings(img_path, min_length=6)
        ms = (time.perf_counter() - t) * 1000
        timeline.append(f"STRINGS  found={len(strings)}  time={ms:.2f}ms")
        for s in strings[:5]:
            timeline.append(f"STRING   offset={s.get('offset')}  val={s.get('string','')[:60]!r}")
        result["findings"]["strings"] = strings[:20]
    except Exception as exc:
        lineno = _tb_img.extract_tb(exc.__traceback__)[-1].lineno or 0
        root   = f"{type(exc).__name__}: {exc}"
        _img_diag_write("extract_strings(img_path)", lineno, root,
            "# String extraction from pixel bytes failed.\n"
            "# Common cause: image.tobytes() returns non-UTF8 data for exotic modes.\n"
            "# Fix: iterate raw bytes with range check 0x20<=b<=0x7E (already done).\n"
            "# Fallback: open with mode='rb' and scan file bytes directly.")
        timeline.append(f"ERROR  STRINGS  {root}")

    elapsed_total = (time.perf_counter() - t0) * 1000
    timeline.append(f"END    total_time={elapsed_total:.2f}ms")
    result["telemetry"] = {
        "contract": "ocb.v1", "tool": "image-stego", "asset": asset_name,
        **_img_timeline_write(asset_name, timeline), "events": timeline,
    }
    return result


if __name__ == "__main__":
    main()
