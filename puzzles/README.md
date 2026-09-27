# Puzzles — Drop Zone

Drop your ARG/CTF puzzle assets here. The Puzzle Solver agent will inventory and analyze this directory automatically.

## Supported File Types

| Extension          | Tool                                  |
|--------------------|---------------------------------------|
| `.txt`, `.bin`     | cipher-engine (cipher_tool.py)        |
| `.png`, `.jpg`     | image-stego (image_tool.py)           |
| `.mp4`, `.mkv`     | media-analyzer (media_tool.py)        |
| `.wav`, `.mp3`     | media-analyzer (media_tool.py)        |

## Quick Start

```bash
# Analyze all text/encoded files
python .kiro/skills/cipher-engine/cipher_tool.py --file puzzles/encoded.txt --chain

# Scan an image for steganography
python .kiro/skills/image-stego/image_tool.py --input puzzles/image.png

# Analyze video for hidden frames + audio morse code
python .kiro/skills/media-analyzer/media_tool.py --input puzzles/clip.mp4

# Run full puzzle-solver agent on this directory
# (Use the puzzle-solver agent defined in .kiro/agents/puzzle-solver.md)
```

## Session Logs

Analysis session logs will be saved here as `session_<timestamp>.log`.
