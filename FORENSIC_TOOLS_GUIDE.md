# OMNI-CIPHER FORENSIC EXTENSIONS — User Guide

## Overview
Three transparent, user-controlled educational forensic tools have been added to the workspace with **zero background automation** or hidden execution chains.

---

## 1. Shannon Entropy Analysis (CLI)

Calculate image randomness to detect possible encryption or compression.

### Usage
```bash
python .kiro/skills/image-stego/image_tool.py --input <image_file> --entropy
```

### Example
```bash
python .kiro/skills/image-stego/image_tool.py --input puzzles/stego_challenge.png --entropy
```

### Output
```
[Entropy Analysis — Shannon Information Content]
  File          : puzzles/stego_challenge.png
  Entropy score : 0.0129 bits/byte
  Max possible  : 8.0 bits/byte
  Interpretation: Very low — mostly uniform/blank areas
  Pixels        : 120,000
```

### Interpretation
- **< 1.0 bits**: Very low — mostly uniform/blank areas
- **1.0–3.0 bits**: Low — significant patterns or compression
- **3.0–6.0 bits**: Moderate — typical natural image
- **6.0–7.5 bits**: High — possible encryption or random data
- **> 7.5 bits**: Very high — likely random/encrypted payload

---

## 2. Forensic Tool Suggestions (CLI)

Print informational suggestions for external tools. **No execution — manual only.**

### Usage
```bash
python .kiro/skills/image-stego/image_tool.py --input <image_file> --suggest-tools
```

### Example
```bash
python .kiro/skills/image-stego/image_tool.py --input puzzles/stego_challenge.png --suggest-tools
```

### Output
```
[Optional Forensic Tools — Manual Execution Only]
  If you want to investigate puzzles/stego_challenge.png further:

  exiftool     (✗ not found)
    → exiftool <file>        # Extract EXIF metadata
  binwalk      (✗ not found)
    → binwalk -e <file>      # Extract embedded files
  foremost     (✗ not found)
    → foremost -i <file> -o <dir>  # Carve file fragments

  To use any tool, copy the command above and run it manually in your terminal.
  No automatic execution will occur.
```

**If a tool is installed (✓), you can manually copy and run the suggested command in your terminal.**

---

## 3. Interactive Color-Channel Visualization UI

Open `puzzles/omni_hud.html` in a web browser for interactive image analysis.

### Opening the UI
```bash
# macOS
open puzzles/omni_hud.html

# Or in any browser: File → Open → puzzles/omni_hud.html
```

### Features

#### Channel Isolation
- **Full RGB**: Display all color channels
- **Red Only**: Isolate red channel (set G=0, B=0)
- **Green Only**: Isolate green channel (set R=0, B=0)
- **Blue Only**: Isolate blue channel (set R=0, G=0)
- **Alpha Channel**: Display transparency layer

#### Pixel Transformations
- **Invert Colors**: Invert RGB values (255 - value)
- **LSB (Red)**: Extract least-significant bit from red channel
- **LSB (Green)**: Extract least-significant bit from green channel
- **LSB (Blue)**: Extract least-significant bit from blue channel

#### Bit Plane Extraction
Extract individual bit planes (0–7) from all RGB channels combined:
- **Bit 0 (LSB)**: Least significant bit
- **Bit 1–6**: Middle bit planes
- **Bit 7 (MSB)**: Most significant bit

### Workflow
1. Click "Load Image" and select a PNG or JPG
2. Use buttons to toggle between different channel views
3. Watch the canvas update in real-time
4. Check the "Image Information" panel for image metadata

---

## Design Principles

All three tools follow strict transparency rules:

✓ **User Control**: All operations triggered by explicit user action (CLI flag or button click)  
✓ **No Automation**: Zero background execution or conditional triggers  
✓ **Educational**: Designed for learning, not for penetration testing  
✓ **Transparent**: All code is readable and auditable  
✓ **Latin-1 Safe**: Full character preservation for complex passwords (-, @, !, #)  

---

## Technical Notes

### Entropy Calculation
- Uses NumPy histogram on pixel byte values (0–255)
- Computes Shannon entropy: H = -Σ(p_i * log₂(p_i))
- Pure mathematical operation, no external dependencies

### Tool Suggestions
- Checks system PATH using `shutil.which()`
- Reports availability without executing anything
- Provides exact command syntax for manual use

### Canvas Rendering
- Client-side JavaScript (no server required)
- HTML5 Canvas API for real-time pixel manipulation
- Supports PNG, JPG, and all common image formats

---

## Troubleshooting

**Q: The entropy value seems wrong?**  
A: Very low entropy (< 1.0) is expected for mostly-uniform images like blank areas or flat colors.

**Q: How do I use the suggested tools?**  
A: If a tool shows as "✓ installed", install it via your package manager (e.g., `brew install exiftool`), then copy the suggested command and run it manually in your terminal.

**Q: Can I edit or extend these tools?**  
A: Yes! All code is in `.kiro/skills/image-stego/image_tool.py` and `puzzles/omni_hud.html`. The extension is labeled with `# === OMNI-CIPHER APEX EXTENSION: FORENSIC MATRIX ===`.

