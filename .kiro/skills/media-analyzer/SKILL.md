---
name: media-analyzer
description: Extracts hidden visual frames from video files and parses audio frequency spectrograms for Morse code or hidden text peaks using scipy, numpy, and ffmpeg.
---

# Media Analyzer Skill

## Overview
Analyzes video and audio files for hidden data. Extracts unusual/hidden frames from video files, generates and analyzes audio spectrograms for Morse code or steganographic frequency peaks, and performs temporal and statistical anomaly detection.

## Supported Formats

| Type  | Format(s)           | Techniques                                                    |
|-------|---------------------|---------------------------------------------------------------|
| Video | .mp4, .mkv, .avi    | Frame extraction, duplicate detection, hidden frame finder    |
| Audio | .wav, .mp3, .flac   | Spectrogram, Morse decoding, LSB audio stego, frequency peaks |

## Dependencies
- `numpy` — Numerical array operations
- `scipy` — Spectrogram generation, signal processing
- `opencv-python` — Frame extraction from video
- `Pillow` — Frame image processing
- `ffmpeg` (system) — MP3/MKV demuxing, audio conversion

Auto-installed at runtime if missing. `ffmpeg` must be available in `$PATH`.

## Usage

```bash
# Full analysis of a video file
python media_tool.py --input puzzles/clip.mp4

# Full analysis of an audio file
python media_tool.py --input puzzles/audio.wav

# Extract all frames from video (saves to puzzles/frames/)
python media_tool.py --input puzzles/clip.mp4 --mode frames

# Spectrogram only
python media_tool.py --input puzzles/audio.wav --mode spectrogram

# Morse code extraction from audio
python media_tool.py --input puzzles/audio.wav --mode morse

# Hidden frame detection (frames that differ significantly from neighbors)
python media_tool.py --input puzzles/clip.mp4 --mode hidden-frames

# Save spectrogram image
python media_tool.py --input puzzles/audio.wav --save-spectrogram

# Pipe decoded output to cipher engine
python media_tool.py --input puzzles/audio.wav --mode morse | python .kiro/skills/cipher-engine/cipher_tool.py --input -
```

## Arguments

| Argument             | Description                                                        |
|----------------------|--------------------------------------------------------------------|
| `--input`            | Path to video or audio file                                        |
| `--mode`             | `all` / `frames` / `hidden-frames` / `spectrogram` / `morse` / `lsb-audio` |
| `--output`           | Output directory for extracted frames/spectrogram                  |
| `--save-spectrogram` | Save spectrogram PNG to output directory                           |
| `--frame-interval`   | Extract every Nth frame (default: 1 = all frames)                 |
| `--diff-threshold`   | Frame difference score to flag as "hidden" (default: 30.0)        |
| `--verbose`          | Show per-frame scores and FFT bin details                          |

## Video Analysis — Hidden Frame Detection

Computes per-frame mean absolute difference (MAD) against the running average. Frames exceeding `--diff-threshold` standard deviations from the mean are flagged as anomalous and saved to `output/hidden_frames/`.

## Audio Analysis — Spectrogram & Morse

1. Loads audio as mono PCM via `scipy.io.wavfile` or `ffmpeg` pipe.
2. Computes Short-Time Fourier Transform (STFT) to generate a spectrogram.
3. Detects dominant frequency bands and their temporal on/off patterns.
4. Compares on/off durations to Morse code timing ratios (1:3:7 dot:dash:word-gap).
5. Reports decoded Morse text and saves the spectrogram image.

## Output

```
=== Media Analyzer Results ===
File: puzzles/clip.mp4
Type: Video | Duration: 00:02:34 | Frames: 3708 | FPS: 24.0

[Frame Analysis]
  Total frames analyzed: 3708
  Flagged as anomalous:  3
  
  ⚠ Frame 1204 — diff_score=87.3 (threshold=30.0) → saved: output/hidden_frames/frame_1204.png
  ⚠ Frame 2891 — diff_score=94.1 → saved: output/hidden_frames/frame_2891.png
  ⚠ Frame 3700 — diff_score=112.4 → contains text overlay: "THE KEY IS: DELTA"

[Audio Spectrogram — puzzles/audio.wav]
  Sample rate: 44100 Hz | Duration: 45.2s | Channels: 1
  Dominant frequency: 1000 Hz
  Morse-like pattern detected! Timing ratio: 1.0:3.1:7.2 (dot:dash:gap)
  Decoded Morse: "CTF{hidden_in_frequency}"

[LSB Audio Analysis]
  Extracted 88200 samples → checking LSBs...
  Text detected: "secret_key_delta_7"
```
