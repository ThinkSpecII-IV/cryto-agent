---
name: image-stego
description: Scans PNG and JPG images for hidden data using EXIF metadata extraction, LSB steganography, color-plane anomaly detection, bit-plane analysis, PNG chunk inspection, and embedded string extraction.
---

# Image Steganography Skill

## Overview
Scans PNG and JPG/JPEG images for hidden information using multiple steganographic techniques: EXIF metadata extraction, LSB (Least Significant Bit) analysis, color-plane anomaly detection, and alpha-channel inspection.

## Supported Techniques

| Technique              | PNG | JPG | Description                                              |
|------------------------|-----|-----|----------------------------------------------------------|
| EXIF Metadata          | ✅  | ✅  | Extract all EXIF/IPTC/XMP tags including GPS, comments  |
| LSB Steganography      | ✅  | ⚠️  | Extract bits from pixel LSBs (best on lossless PNG)     |
| Color Plane Extraction | ✅  | ✅  | Isolate R, G, B, Alpha channels for visual anomalies    |
| Bit-Plane Analysis     | ✅  | ✅  | Show each of the 8 bit-planes per channel               |
| Histogram Analysis     | ✅  | ✅  | Detect unusual value distributions suggesting stego     |
| String Extraction      | ✅  | ✅  | Find printable ASCII strings embedded in pixel data     |
| Chunk Analysis         | ✅  | ❌  | Parse PNG ancillary chunks (tEXt, zTXt, iTXt, etc.)    |
| Alpha Channel          | ✅  | ❌  | Inspect alpha channel for data hiding                   |

## Dependencies
- `Pillow` (PIL) — Image loading, metadata, pixel access
- `opencv-python` — Color plane manipulation, histogram
- `numpy` — Bit-plane arithmetic and array operations

Auto-installed at runtime if missing.

## Usage

```bash
# Full scan (all techniques)
python image_tool.py --input puzzles/image.png

# Specific technique
python image_tool.py --input puzzles/image.png --technique lsb
python image_tool.py --input puzzles/image.png --technique exif
python image_tool.py --input puzzles/image.png --technique planes
python image_tool.py --input puzzles/image.png --technique strings

# Extract raw LSB bits to file
python image_tool.py --input puzzles/image.png --technique lsb --output puzzles/lsb_data.bin

# Scan all images in a directory
python image_tool.py --dir puzzles/

# Save color plane images for visual inspection
python image_tool.py --input puzzles/image.png --technique planes --save-planes
```

## Arguments

| Argument        | Description                                                   |
|-----------------|---------------------------------------------------------------|
| `--input`       | Path to image file (PNG or JPG)                               |
| `--dir`         | Directory to scan all PNG/JPG files                           |
| `--technique`   | Force technique: `all` / `exif` / `lsb` / `planes` / `strings` / `chunks` |
| `--output`      | Write extracted data to file                                  |
| `--save-planes` | Save isolated channel images to `puzzles/planes/`             |
| `--lsb-bits`    | Number of LSB bits to extract per channel (default: 1)        |
| `--verbose`     | Show raw pixel samples and scoring details                    |

## LSB Extraction Method

By default, extracts the least significant bit of every pixel's RGB channels in row-major order:

```
pixel(0,0).R[bit0], pixel(0,0).G[bit0], pixel(0,0).B[bit0],
pixel(0,1).R[bit0], ...
```

Bits are assembled into bytes (MSB-first) and tested as UTF-8 text. Non-printable bytes are reported as hex.

## Output

```
=== Image Steganography Results ===
File: puzzles/image.png (1024×768, RGBA, 2.1MB)

[EXIF]
  Make: Canon
  Model: EOS 5D Mark IV
  Comment: FLAG{hidden_in_metadata}
  GPS: 37.7749° N, 122.4194° W

[LSB — 1 bit per channel]
  Extracted 294912 bits → 36864 bytes
  Printable ASCII detected!
  Preview: "This is a hidden message..."

[PNG Chunks]
  tEXt chunk: Author = "ARG_Master"
  iTXt chunk: Description = "Look at the red channel bit-plane 0"

[Color Planes — Anomaly Score]
  Red channel:   0.87 (HIGH — unusual histogram spike at value 128)
  Green channel: 0.12 (LOW)
  Blue channel:  0.09 (LOW)
  Alpha channel: 0.55 (MEDIUM — non-uniform transparency)

[String Extraction]
  Found 3 printable strings (length ≥ 8):
    offset 0x1A3F: "password1"
    offset 0x2B10: "CTF{stego_master}"
```
