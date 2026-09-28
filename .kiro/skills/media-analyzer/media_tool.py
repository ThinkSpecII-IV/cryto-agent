#!/usr/bin/env python3
"""
Omni-Cipher Bot — Media Analyzer
Analyzes video (.mp4, .mkv, .avi) and audio (.wav, .mp3, .flac) files
for hidden frames, spectrogram anomalies, and Morse code.

Auto-installs: numpy, scipy, opencv-python, Pillow
Requires: ffmpeg in $PATH for mp3/mkv support
"""

import sys
import subprocess
import importlib
import shutil


# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------

DEPS = [
    ("numpy", "numpy"),
    ("scipy", "scipy"),
    ("cv2", "opencv-python"),
    ("PIL", "Pillow"),
]


def ensure_deps() -> None:
    for import_name, pip_name in DEPS:
        try:
            importlib.import_module(import_name)
        except ImportError:
            print(f"[media-analyzer] Installing missing dependency: {pip_name}")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_name]
            )


ensure_deps()

# ---------------------------------------------------------------------------
# Imports after bootstrap
# ---------------------------------------------------------------------------

import argparse
import os
import io
import struct
import wave
import tempfile
from pathlib import Path
from typing import Optional, Union

import cv2
import numpy as np
from PIL import Image

SEPARATOR = "=" * 65

# Lazy scipy imports (used only when needed)
_scipy_signal = None
_scipy_wavfile = None


def _get_scipy_signal():
    global _scipy_signal
    if _scipy_signal is None:
        from scipy import signal as _sig
        _scipy_signal = _sig
    return _scipy_signal


def _get_scipy_wavfile():
    global _scipy_wavfile
    if _scipy_wavfile is None:
        from scipy.io import wavfile as _wf
        _scipy_wavfile = _wf
    return _scipy_wavfile


# ---------------------------------------------------------------------------
# Morse code tables
# ---------------------------------------------------------------------------

MORSE_DECODE: dict[str, str] = {
    ".-": "A",   "-...": "B", "-.-.": "C", "-..": "D",  ".": "E",
    "..-.": "F", "--.": "G",  "....": "H", "..": "I",   ".---": "J",
    "-.-": "K",  ".-..": "L", "--": "M",   "-.": "N",   "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R",  "...": "S",  "-": "T",
    "..-": "U",  "...-": "V", ".--": "W",  "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0","----." : "9","---..": "8","--...": "7",
    "-....": "6",".....: ": "5","....-": "4","...--": "3","..---": "2",
    ".----": "1",
}


# ---------------------------------------------------------------------------
# ffmpeg helpers
# ---------------------------------------------------------------------------

def ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


def convert_audio_to_wav(input_path: str, output_path: str) -> bool:
    """Use ffmpeg to convert any audio format to mono 44100Hz WAV."""
    if not ffmpeg_available():
        print("[media-analyzer] WARNING: ffmpeg not found in PATH — cannot convert audio")
        return False
    try:
        result = subprocess.run(
            [
                "ffmpeg", "-y", "-i", input_path,
                "-ac", "1",         # mono
                "-ar", "44100",     # 44.1 kHz
                "-f", "wav",
                output_path,
            ],
            capture_output=True,
            timeout=120,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[media-analyzer] ffmpeg error: {e}")
        return False


def get_video_info(cap: cv2.VideoCapture) -> dict:
    """Extract basic video metadata from an OpenCV capture object."""
    fps = cap.get(cv2.CAP_PROP_FPS) or 0
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    duration_s = frame_count / fps if fps > 0 else 0
    minutes = int(duration_s // 60)
    seconds = int(duration_s % 60)
    return {
        "fps": fps,
        "frame_count": frame_count,
        "width": width,
        "height": height,
        "duration": f"{minutes:02d}:{seconds:02d}",
        "duration_s": duration_s,
    }


# ---------------------------------------------------------------------------
# Video: hidden frame detection
# ---------------------------------------------------------------------------

def analyze_video_frames(
    video_path: str,
    mode: str = "hidden-frames",
    output_dir: Optional[str] = None,
    frame_interval: int = 1,
    diff_threshold: float = 30.0,
    verbose: bool = False,
) -> dict:
    """
    Analyze video frames for anomalies.
    mode='all' or mode='frames': extract every frame_interval-th frame.
    mode='hidden-frames': flag frames that differ strongly from neighbors.
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {"error": f"Cannot open video: {video_path}"}

    info = get_video_info(cap)
    out_dir = output_dir or str(Path(video_path).parent / "frames")
    hidden_dir = str(Path(out_dir) / "hidden_frames")

    if mode in ("all", "frames"):
        os.makedirs(out_dir, exist_ok=True)
    if mode in ("all", "hidden-frames"):
        os.makedirs(hidden_dir, exist_ok=True)

    frame_diffs: list[float] = []
    flagged_frames: list[dict] = []
    prev_gray: Optional[np.ndarray] = None
    frame_idx = 0
    extracted_count = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if frame_idx % frame_interval == 0:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(float)

            if prev_gray is not None:
                diff = float(np.mean(np.abs(gray - prev_gray)))
                frame_diffs.append(diff)
            else:
                frame_diffs.append(0.0)

            if mode in ("all", "frames"):
                frame_path = os.path.join(out_dir, f"frame_{frame_idx:06d}.png")
                cv2.imwrite(frame_path, frame)
                extracted_count += 1

            prev_gray = gray

        frame_idx += 1

    cap.release()

    # Statistical anomaly detection
    if len(frame_diffs) >= 3:
        arr = np.array(frame_diffs)
        mean_diff = float(arr.mean())
        std_diff = float(arr.std())
        threshold = mean_diff + diff_threshold

        if verbose:
            print(f"[media-analyzer] Frame diff stats: mean={mean_diff:.2f} std={std_diff:.2f} threshold={threshold:.2f}")

        # Re-scan for flagged frames
        cap2 = cv2.VideoCapture(video_path)
        diff_frame_idx = 0
        scan_idx = 0

        while True:
            ret, frame = cap2.read()
            if not ret:
                break
            if diff_frame_idx % frame_interval == 0:
                if scan_idx < len(frame_diffs) and frame_diffs[scan_idx] > threshold:
                    frame_path = os.path.join(hidden_dir, f"frame_{diff_frame_idx:06d}.png")
                    cv2.imwrite(frame_path, frame)

                    # Try OCR-lite: look for high-contrast text regions
                    text_hint = _detect_text_overlay(frame)

                    flagged_frames.append({
                        "frame_index": diff_frame_idx,
                        "diff_score": round(frame_diffs[scan_idx], 2),
                        "threshold": round(threshold, 2),
                        "saved_to": frame_path,
                        "text_hint": text_hint,
                    })

                scan_idx += 1
            diff_frame_idx += 1

        cap2.release()

    return {
        "video_info": info,
        "frames_analyzed": len(frame_diffs),
        "frames_extracted": extracted_count,
        "flagged_count": len(flagged_frames),
        "flagged_frames": flagged_frames,
        "mean_diff": round(float(np.mean(frame_diffs)) if frame_diffs else 0, 2),
        "output_dir": out_dir,
    }


def _detect_text_overlay(frame: np.ndarray) -> Optional[str]:
    """
    Simple text region heuristic: look for high-contrast rectangular regions
    that suggest title cards or text overlays. Returns a hint string or None.
    """
    try:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        # Threshold to find high-contrast areas
        _, binary = cv2.threshold(gray, 200, 255, cv2.THRESH_BINARY)
        white_ratio = float(binary.mean()) / 255.0
        if white_ratio > 0.1:
            return f"High-contrast region detected (white_ratio={white_ratio:.2f}) — may contain text"
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Audio: load PCM samples
# ---------------------------------------------------------------------------

def load_audio_samples(audio_path: str) -> tuple[Optional[np.ndarray], int]:
    """
    Load audio as mono float32 numpy array.
    Tries scipy wavfile first, falls back to ffmpeg conversion.
    Returns (samples, sample_rate) or (None, 0) on failure.
    """
    ext = Path(audio_path).suffix.lower()

    # Direct WAV loading
    if ext == ".wav":
        try:
            wavfile = _get_scipy_wavfile()
            rate, data = wavfile.read(audio_path)
            if data.ndim > 1:
                data = data.mean(axis=1)
            samples = data.astype(np.float32)
            if samples.max() > 1.0:
                samples = samples / 32768.0
            return samples, rate
        except Exception as e:
            print(f"[media-analyzer] scipy.io.wavfile error: {e} — trying ffmpeg")

    # Fallback: ffmpeg → temp WAV
    if ffmpeg_available():
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            if convert_audio_to_wav(audio_path, tmp_path):
                wavfile = _get_scipy_wavfile()
                rate, data = wavfile.read(tmp_path)
                if data.ndim > 1:
                    data = data.mean(axis=1)
                samples = data.astype(np.float32)
                if samples.max() > 1.0:
                    samples = samples / 32768.0
                return samples, rate
        except Exception as e:
            print(f"[media-analyzer] Failed to load audio via ffmpeg: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    else:
        print("[media-analyzer] WARNING: ffmpeg not available. Only WAV files supported.")

    return None, 0


# ---------------------------------------------------------------------------
# Audio: spectrogram analysis
# ---------------------------------------------------------------------------

def analyze_spectrogram(
    samples: np.ndarray,
    sample_rate: int,
    save_path: Optional[str] = None,
    verbose: bool = False,
) -> dict:
    """
    Generate STFT spectrogram, detect dominant frequencies, and identify peaks.
    """
    signal = _get_scipy_signal()

    # STFT parameters
    nperseg = min(1024, len(samples) // 4)
    if nperseg < 64:
        return {"error": "Audio too short for spectrogram analysis"}

    freqs, times, Sxx = signal.spectrogram(
        samples, fs=sample_rate, nperseg=nperseg,
        noverlap=nperseg // 2, scaling="density"
    )

    Sxx_db = 10 * np.log10(Sxx + 1e-10)

    # Dominant frequency over time
    dominant_freq_indices = np.argmax(Sxx, axis=0)
    dominant_freqs = freqs[dominant_freq_indices]
    mean_dominant = float(dominant_freqs.mean())
    modal_dominant = float(freqs[np.bincount(dominant_freq_indices).argmax()])

    # Frequency peaks (significant concentrations)
    avg_power_per_freq = np.mean(Sxx_db, axis=1)
    peak_indices, _ = signal.find_peaks(
        avg_power_per_freq, height=np.mean(avg_power_per_freq) + 5, distance=5
    )
    peak_freqs = [(float(freqs[i]), round(float(avg_power_per_freq[i]), 2)) for i in peak_indices]

    result = {
        "sample_rate": sample_rate,
        "duration_s": round(len(samples) / sample_rate, 2),
        "num_frames": len(times),
        "freq_resolution": round(float(freqs[1] - freqs[0]), 2) if len(freqs) > 1 else 0,
        "mean_dominant_freq_hz": round(mean_dominant, 1),
        "modal_dominant_freq_hz": round(modal_dominant, 1),
        "significant_peaks": peak_freqs[:20],  # Top 20 peaks
        "spectrogram_shape": Sxx.shape,
        "time_array": times,
        "freq_array": freqs,
        "spectrogram_db": Sxx_db,
    }

    # Save spectrogram image
    if save_path:
        _save_spectrogram_image(Sxx_db, freqs, times, sample_rate, save_path)
        result["spectrogram_saved"] = save_path

    return result


def _save_spectrogram_image(
    Sxx_db: np.ndarray,
    freqs: np.ndarray,
    times: np.ndarray,
    sample_rate: int,
    save_path: str,
) -> None:
    """Save spectrogram as a color-mapped PNG without matplotlib dependency."""
    try:
        # Normalize to 0-255
        vmin = np.percentile(Sxx_db, 5)
        vmax = np.percentile(Sxx_db, 99)
        normalized = np.clip((Sxx_db - vmin) / max(vmax - vmin, 1e-6), 0, 1)
        img_data = (normalized * 255).astype(np.uint8)

        # Flip for conventional spectrogram orientation (low freq at bottom)
        img_data = np.flipud(img_data)

        # Apply a simple colormap (viridis-like: black→blue→green→yellow)
        height, width = img_data.shape
        rgb = np.zeros((height, width, 3), dtype=np.uint8)
        v = img_data.astype(np.float32) / 255.0
        rgb[:, :, 0] = (np.clip(v * 2 - 0.5, 0, 1) * 255).astype(np.uint8)   # R
        rgb[:, :, 1] = (np.clip(v * 1.5, 0, 1) * 255).astype(np.uint8)        # G
        rgb[:, :, 2] = (np.clip(1 - v * 1.2, 0, 1) * 255).astype(np.uint8)   # B

        img = Image.fromarray(rgb)
        os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
        img.save(save_path)
    except Exception as e:
        print(f"[media-analyzer] Could not save spectrogram image: {e}")


# ---------------------------------------------------------------------------
# Audio: Morse code detection
# ---------------------------------------------------------------------------

def detect_morse_from_audio(
    samples: np.ndarray,
    sample_rate: int,
    target_freq: Optional[float] = None,
    verbose: bool = False,
) -> dict:
    """
    Detect Morse code patterns in audio by analyzing amplitude envelope
    at the dominant tone frequency.
    """
    signal = _get_scipy_signal()

    # Find dominant frequency if not specified
    if target_freq is None:
        spec_result = analyze_spectrogram(samples, sample_rate, verbose=verbose)
        target_freq = spec_result.get("modal_dominant_freq_hz", 1000.0)

    if verbose:
        print(f"[media-analyzer] Morse detection targeting freq: {target_freq:.1f} Hz")

    # Bandpass filter around target frequency
    nyquist = sample_rate / 2
    if target_freq > 0 and target_freq < nyquist * 0.9:
        low = max(target_freq - 100, 50) / nyquist
        high = min(target_freq + 100, nyquist * 0.99) / nyquist
        if low < high:
            try:
                b, a = signal.butter(4, [low, high], btype="band")
                filtered = signal.lfilter(b, a, samples)
            except Exception:
                filtered = samples
        else:
            filtered = samples
    else:
        filtered = samples

    # Amplitude envelope via Hilbert transform
    try:
        analytic = signal.hilbert(filtered)
        envelope = np.abs(analytic)
    except Exception:
        envelope = np.abs(filtered)

    # Smooth envelope
    window = max(1, int(sample_rate * 0.01))  # 10ms window
    kernel = np.ones(window) / window
    smoothed = np.convolve(envelope, kernel, mode="same")

    # Threshold: detect on/off states
    threshold = float(np.mean(smoothed) + np.std(smoothed) * 0.5)
    on_off = (smoothed > threshold).astype(int)

    # Find run lengths (on/off durations in samples)
    runs: list[tuple[int, int]] = []  # (value, duration_samples)
    if len(on_off) > 0:
        current_val = on_off[0]
        current_len = 1
        for i in range(1, len(on_off)):
            if on_off[i] == current_val:
                current_len += 1
            else:
                runs.append((int(current_val), current_len))
                current_val = on_off[i]
                current_len = 1
        runs.append((int(current_val), current_len))

    # Filter out very short runs (< 20ms) as noise
    min_samples = int(sample_rate * 0.02)
    runs = [(v, d) for v, d in runs if d >= min_samples]

    if not runs:
        return {"error": "No significant on/off patterns detected"}

    # Estimate dot duration (shortest 'on' run)
    on_runs = [d for v, d in runs if v == 1]
    if not on_runs:
        return {"error": "No active tone detected"}

    on_runs_sorted = sorted(on_runs)
    # Use 25th percentile as dot estimate
    dot_est = on_runs_sorted[max(0, len(on_runs_sorted) // 4)]

    dot_s = dot_est / sample_rate
    dash_threshold = dot_est * 2.0

    if verbose:
        print(f"[media-analyzer] Estimated dot duration: {dot_s*1000:.1f}ms")

    # Decode runs to Morse symbols
    morse_chars: list[str] = []
    morse_sequence: str = ""

    for v, d in runs:
        if v == 1:  # tone on
            morse_chars.append("." if d < dash_threshold else "-")
        else:  # tone off
            gap_ratio = d / dot_est
            if gap_ratio < 2.5:
                pass  # inter-symbol gap, ignore
            elif gap_ratio < 5.0:
                morse_sequence += "".join(morse_chars) + " "
                morse_chars = []
            else:
                # Word gap
                if morse_chars:
                    morse_sequence += "".join(morse_chars)
                    morse_chars = []
                morse_sequence += " / "

    if morse_chars:
        morse_sequence += "".join(morse_chars)

    morse_sequence = morse_sequence.strip()

    # Decode Morse to text
    decoded_text = _decode_morse_string(morse_sequence)

    # Timing ratio analysis
    off_runs = sorted([d for v, d in runs if v == 0])
    timing_info = {}
    if on_runs and off_runs:
        avg_dot = float(np.mean(on_runs_sorted[:max(1, len(on_runs_sorted) // 3)]))
        avg_dash = float(np.mean(on_runs_sorted[len(on_runs_sorted) // 2:])) if len(on_runs_sorted) > 2 else avg_dot * 3
        timing_info = {
            "dot_ms": round(avg_dot / sample_rate * 1000, 1),
            "dash_ms": round(avg_dash / sample_rate * 1000, 1),
            "ratio_dot_dash": round(avg_dash / max(avg_dot, 1), 2),
        }

    return {
        "target_frequency_hz": round(target_freq, 1),
        "dot_duration_ms": round(dot_s * 1000, 1),
        "morse_sequence": morse_sequence[:500],
        "decoded_text": decoded_text,
        "timing": timing_info,
        "total_symbols": len(morse_chars) + len(morse_sequence.replace(" / ", "").replace(" ", "")),
    }


def _decode_morse_string(morse: str) -> str:
    """Decode a morse string like '.- -... / .-..' to text."""
    words = morse.split(" / ")
    result = []
    for word in words:
        chars = word.strip().split(" ")
        decoded_word = ""
        for code in chars:
            code = code.strip()
            if code:
                decoded_word += MORSE_DECODE.get(code, f"[{code}]")
        result.append(decoded_word)
    return " ".join(result)


# ---------------------------------------------------------------------------
# Audio: LSB steganography
# ---------------------------------------------------------------------------

def extract_audio_lsb(samples: np.ndarray, sample_rate: int) -> dict:
    """Extract LSB bits from audio PCM samples."""
    # Convert float samples to int16
    if samples.dtype != np.int16:
        int_samples = (samples * 32767).astype(np.int16)
    else:
        int_samples = samples

    # Extract LSBs — vectorized: isolate bit-0 of every int16 sample,
    # then np.packbits assembles groups of 8 bits into bytes (MSB-first).
    lsb_plane = (int_samples.view(np.uint16) & np.uint16(1)).astype(np.uint8)
    trim = (lsb_plane.size // 8) * 8
    byte_data = bytearray(np.packbits(lsb_plane[:trim]))

    # Try to interpret as text
    text_preview = None
    try:
        # Find null-terminated or printable region
        decoded = bytes(byte_data).decode("utf-8", errors="ignore")
        printable = "".join(c for c in decoded if c.isprintable() or c in "\n\r\t")
        if len(printable) > 10:
            text_preview = printable[:400]
    except Exception:
        pass

    return {
        "total_samples": len(int_samples),
        "total_lsb_bits": len(lsb_plane),
        "total_bytes": len(byte_data),
        "hex_preview": byte_data[:64].hex(),
        "text_preview": text_preview,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_banner(file_path: str, file_type: str, extra_info: str = "") -> None:
    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"\n{SEPARATOR}")
    print("   OMNI-CIPHER BOT — Media Analyzer")
    print(SEPARATOR)
    print(f"File : {file_path}")
    print(f"Type : {file_type} | Size: {size_mb:.2f} MB {extra_info}")
    print(SEPARATOR)


def print_video_results(results: dict) -> None:
    if "error" in results:
        print(f"  ⚠ {results['error']}")
        return

    info = results.get("video_info", {})
    print(f"\n[Video Info]")
    print(f"  Duration  : {info.get('duration', '?')}")
    print(f"  Dimensions: {info.get('width')}×{info.get('height')}")
    print(f"  FPS       : {info.get('fps', '?'):.1f}")
    print(f"  Frames    : {info.get('frame_count', '?')}")

    print(f"\n[Frame Analysis]")
    print(f"  Frames analyzed : {results.get('frames_analyzed', 0)}")
    print(f"  Frames extracted: {results.get('frames_extracted', 0)}")
    print(f"  Mean diff score : {results.get('mean_diff', 0):.2f}")
    print(f"  Flagged frames  : {results.get('flagged_count', 0)}")

    flagged = results.get("flagged_frames", [])
    if flagged:
        print()
        for f in flagged:
            print(f"  ⚠ Frame {f['frame_index']:6d} — diff={f['diff_score']:.1f} (thresh={f['threshold']:.1f})")
            print(f"    Saved: {f['saved_to']}")
            if f.get("text_hint"):
                print(f"    Hint: {f['text_hint']}")
    else:
        print("  No anomalous frames detected.")


def print_spectrogram_results(spec: dict) -> None:
    print(f"\n[Spectrogram Analysis]")
    if "error" in spec:
        print(f"  ⚠ {spec['error']}")
        return

    print(f"  Sample rate          : {spec.get('sample_rate', '?')} Hz")
    print(f"  Duration             : {spec.get('duration_s', '?')} s")
    print(f"  Dominant frequency   : {spec.get('modal_dominant_freq_hz', '?')} Hz")
    print(f"  Mean dominant freq   : {spec.get('mean_dominant_freq_hz', '?')} Hz")

    peaks = spec.get("significant_peaks", [])
    if peaks:
        print(f"  Significant peaks ({len(peaks)}):")
        for freq, power in peaks[:10]:
            print(f"    {freq:8.1f} Hz  power={power:.1f} dB")

    if spec.get("spectrogram_saved"):
        print(f"  Spectrogram image saved: {spec['spectrogram_saved']}")


def print_morse_results(morse: dict) -> None:
    print(f"\n[Morse Code Detection]")
    if "error" in morse:
        print(f"  ⚠ {morse['error']}")
        return

    print(f"  Target frequency : {morse.get('target_frequency_hz', '?')} Hz")
    print(f"  Dot duration     : {morse.get('dot_duration_ms', '?')} ms")

    timing = morse.get("timing", {})
    if timing:
        print(f"  Dash duration    : {timing.get('dash_ms', '?')} ms")
        print(f"  Dot:Dash ratio   : 1:{timing.get('ratio_dot_dash', '?')}")

    seq = morse.get("morse_sequence", "")
    if seq:
        print(f"\n  Morse sequence: {seq[:120]}")
        decoded = morse.get("decoded_text", "")
        if decoded:
            print(f"  Decoded text  : {decoded}")
        else:
            print("  Could not decode Morse sequence to text.")
    else:
        print("  No Morse pattern detected.")


def print_lsb_audio_results(lsb: dict) -> None:
    print(f"\n[LSB Audio Analysis]")
    if "error" in lsb:
        print(f"  ⚠ {lsb['error']}")
        return

    print(f"  Samples  : {lsb.get('total_samples', 0):,}")
    print(f"  LSB bits : {lsb.get('total_lsb_bits', 0):,}")
    print(f"  Bytes    : {lsb.get('total_bytes', 0):,}")
    print(f"  Hex prev : {lsb.get('hex_preview', '')[:64]}")

    if lsb.get("text_preview"):
        print(f"  Text found: {lsb['text_preview'][:200]}")
    else:
        print("  No readable text in LSB data.")


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def analyze_file(
    file_path: str,
    mode: str = "all",
    output_dir: Optional[str] = None,
    save_spectrogram: bool = False,
    frame_interval: int = 1,
    diff_threshold: float = 30.0,
    verbose: bool = False,
) -> None:
    ext = Path(file_path).suffix.lower()
    is_video = ext in (".mp4", ".mkv", ".avi", ".mov", ".webm")
    is_audio = ext in (".wav", ".mp3", ".flac", ".aac", ".ogg", ".m4a")

    if not os.path.isfile(file_path):
        print(f"[media-analyzer] ERROR: File not found: {file_path}")
        return

    if is_video:
        print_banner(file_path, "Video")

        if mode in ("all", "frames", "hidden-frames"):
            video_results = analyze_video_frames(
                file_path, mode=mode, output_dir=output_dir,
                frame_interval=frame_interval, diff_threshold=diff_threshold,
                verbose=verbose,
            )
            print_video_results(video_results)

        # Flash-Frame Scanner — additive absdiff cut detector
        if mode in ("all", "frames", "hidden-frames"):
            flash_frame_scanner(
                file_path,
                frame_interval=frame_interval,
                diff_threshold=diff_threshold,
                verbose=verbose,
            )

        # Also extract audio from video for spectrogram analysis
        if mode in ("all", "spectrogram", "morse") and ffmpeg_available():
            print(f"\n[Extracting audio track from video...]")
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                if convert_audio_to_wav(file_path, tmp_path):
                    samples, sample_rate = load_audio_samples(tmp_path)
                    if samples is not None:
                        _analyze_audio_content(
                            samples, sample_rate, mode, output_dir or str(Path(file_path).parent),
                            save_spectrogram, verbose, file_path
                        )
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    elif is_audio:
        samples, sample_rate = load_audio_samples(file_path)
        if samples is None:
            print(f"[media-analyzer] ERROR: Could not load audio from {file_path}")
            return

        duration_s = len(samples) / sample_rate if sample_rate > 0 else 0
        print_banner(file_path, "Audio", f"| {duration_s:.1f}s | {sample_rate}Hz")
        _analyze_audio_content(
            samples, sample_rate, mode,
            output_dir or str(Path(file_path).parent),
            save_spectrogram, verbose, file_path
        )
    else:
        print(f"[media-analyzer] Unsupported file format: {ext}")
        print("Supported: .mp4 .mkv .avi .wav .mp3 .flac")

    print(f"\n{SEPARATOR}\n")


def _analyze_audio_content(
    samples: np.ndarray,
    sample_rate: int,
    mode: str,
    output_dir: str,
    save_spectrogram: bool,
    verbose: bool,
    source_path: str,
) -> None:
    """Common audio analysis logic."""
    spec_save_path = None
    if save_spectrogram:
        stem = Path(source_path).stem
        spec_save_path = os.path.join(output_dir, f"{stem}_spectrogram.png")

    if mode in ("all", "spectrogram"):
        spec = analyze_spectrogram(samples, sample_rate, spec_save_path, verbose)
        print_spectrogram_results(spec)

    if mode in ("all", "morse"):
        morse = detect_morse_from_audio(samples, sample_rate, verbose=verbose)
        print_morse_results(morse)

    if mode in ("all", "lsb-audio"):
        lsb = extract_audio_lsb(samples, sample_rate)
        print_lsb_audio_results(lsb)

    # FFT Enhancement — runs alongside existing spectrogram/morse analysis
    if mode in ("all", "spectrogram", "morse"):
        fft_sweep_audio(samples, sample_rate, top_n=8, verbose=verbose)

    # Spectrogram edge-scan — Canny geometry detection on magnitude matrix
    if mode in ("all", "spectrogram"):
        scan_spectrogram_edges(samples, sample_rate, verbose=verbose)


# ---------------------------------------------------------------------------
# Audio FFT Enhancement — in-memory sweep with Morse carrier detection
# ---------------------------------------------------------------------------

def fft_sweep_audio(
    samples: np.ndarray,
    sample_rate: int,
    top_n: int = 8,
    verbose: bool = False,
) -> dict:
    """
    Perform an in-memory FFT sweep on PCM samples.
    Extracts the top N dominant amplitude peaks and checks whether any
    fall inside the standard telegraphy Morse carrier band (400–800 Hz).

    Returns a dict with peak list and morse_carrier_detected flag.
    """
    print(f"\n[FFT Sweep — Dominant Frequency Analysis]")

    if len(samples) < 64:
        print(f"  ⚠ Audio too short for FFT analysis ({len(samples)} samples)")
        return {"error": "too short", "peaks": [], "morse_carrier_detected": False}

    # Compute absolute amplitude spectrum (single-sided)
    fft_raw = np.fft.rfft(samples.astype(np.float64))
    fft_mag = np.abs(fft_raw)
    freqs   = np.fft.rfftfreq(len(samples), d=1.0 / sample_rate)

    # Extract top_n peaks by amplitude
    top_indices = np.argsort(fft_mag)[-top_n:][::-1]  # descending
    peaks: list[tuple[float, float]] = []
    for idx in top_indices:
        freq_hz  = float(freqs[idx])
        amp      = float(fft_mag[idx])
        if freq_hz > 0:
            peaks.append((round(freq_hz, 2), round(amp, 4)))

    print(f"  Sample rate    : {sample_rate} Hz")
    print(f"  Total samples  : {len(samples):,}")
    print(f"  FFT bins       : {len(fft_mag):,}")
    print(f"\n  Top {top_n} dominant frequency peaks:")
    for rank, (freq_hz, amp) in enumerate(peaks, 1):
        band_tag = " ← telegraphy band" if 400 <= freq_hz <= 800 else ""
        print(f"    #{rank:2d}  {freq_hz:9.2f} Hz   amplitude={amp:.4f}{band_tag}")

    # Morse carrier check: any persistent peak in 400–800 Hz?
    carrier_peaks = [f for f, _ in peaks if 400 <= f <= 800]
    morse_carrier_detected = len(carrier_peaks) > 0

    if morse_carrier_detected:
        print(f"\n  🔓 [MORSE AUDIO CARRIER DETECTED]")
        print(f"     Persistent sinusoidal peak(s) isolated in telegraphy band: {carrier_peaks} Hz")
    else:
        if verbose:
            print(f"\n  No Morse carrier peaks detected in 400–800 Hz band.")

    return {
        "peaks": peaks,
        "carrier_peaks_hz": carrier_peaks,
        "morse_carrier_detected": morse_carrier_detected,
        "fft_bins": len(fft_mag),
    }


# ---------------------------------------------------------------------------
# Video Flash-Frame Scanner — cv2.absdiff edge-variance jump detector
# ---------------------------------------------------------------------------

def flash_frame_scanner(
    video_path: str,
    frame_interval: int = 1,
    diff_threshold: float = 30.0,
    verbose: bool = False,
) -> dict:
    """
    Sequential gray-frame cv2.absdiff scan for hidden flash-frame cuts.
    Checks every frame_interval-th frame pair. When the mean pixel
    difference between consecutive frames exceeds diff_threshold, the
    frame index is flagged as an anomalous flash-frame cut.

    Returns a dict with anomalous_frames list and summary stats.
    """
    print(f"\n[Flash-Frame Scanner — cv2.absdiff Variance Check]")

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print(f"  ⚠ Cannot open video: {video_path}")
        return {"error": f"Cannot open: {video_path}", "anomalous_frames": []}

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps          = cap.get(cv2.CAP_PROP_FPS) or 0
    print(f"  File           : {os.path.basename(video_path)}")
    print(f"  Total frames   : {total_frames}")
    print(f"  FPS            : {fps:.2f}")
    print(f"  Frame interval : {frame_interval}")
    print(f"  Diff threshold : {diff_threshold}")

    prev_gray: Optional[np.ndarray] = None
    anomalous_frames: list[dict] = []
    frame_idx   = 0
    scanned     = 0
    diff_scores: list[float] = []

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if frame_idx % frame_interval == 0:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            if prev_gray is not None:
                diff_map  = cv2.absdiff(gray, prev_gray)
                mean_diff = float(np.mean(diff_map))
                diff_scores.append(mean_diff)

                if mean_diff > diff_threshold:
                    anomalous_frames.append({
                        "frame_index": frame_idx,
                        "mean_diff":   round(mean_diff, 3),
                        "threshold":   diff_threshold,
                    })
                    if verbose:
                        print(f"  ⚠ Frame {frame_idx:6d} mean_diff={mean_diff:.3f}")
            else:
                diff_scores.append(0.0)

            prev_gray = gray
            scanned  += 1

        frame_idx += 1

    cap.release()

    global_mean = float(np.mean(diff_scores)) if diff_scores else 0.0
    global_max  = float(np.max(diff_scores))  if diff_scores else 0.0

    print(f"\n  Frames scanned : {scanned}")
    print(f"  Mean diff      : {global_mean:.3f}")
    print(f"  Peak diff      : {global_max:.3f}")
    print(f"  Anomalous cuts : {len(anomalous_frames)}")

    if anomalous_frames:
        print(f"\n  🔓 [FLASH FRAME VARIANCE ALERT]")
        for entry in anomalous_frames:
            print(f"     Frame index {entry['frame_index']:6d} — "
                  f"mean_diff={entry['mean_diff']:.3f} "
                  f"(threshold={entry['threshold']})")
    else:
        print("  No flash-frame cuts detected above threshold.")

    return {
        "scanned_frames":   scanned,
        "anomalous_frames": anomalous_frames,
        "anomalous_count":  len(anomalous_frames),
        "global_mean_diff": round(global_mean, 3),
        "global_peak_diff": round(global_max, 3),
    }



# ---------------------------------------------------------------------------
# Spectrogram edge scan — Canny geometry detection on magnitude matrix
# ---------------------------------------------------------------------------

def scan_spectrogram_edges(
    samples: "np.ndarray",
    sample_rate: int,
    canny_low: int = 50,
    canny_high: int = 150,
    min_contour_area: float = 20.0,
    verbose: bool = False,
) -> dict:
    """
    Run Canny edge detection over a spectrogram magnitude matrix to look for
    geometric structures or visually embedded text patterns.

    How it works
    ────────────
    1. Build a standard STFT spectrogram via scipy.signal.spectrogram.
    2. Normalise the dB-scaled magnitude matrix to a uint8 grayscale image
       (frequency axis → rows, time axis → columns).
    3. Apply cv2.Canny() to extract sharp magnitude-gradient edges.
    4. Find contours in the edge map with cv2.findContours().
    5. Report bounding-box geometry and aspect ratios of the largest contours.

    Limitations
    ───────────
    Spectrograms encode energy density, not typography.  This function can
    detect *structured, repetitive, or rectangular* anomalies in frequency
    space (e.g. SSTV frames, tonal grids, deliberate text painted in audio),
    but it will NOT read arbitrary text from normal speech or music.  Treat
    any "structured geometry detected" result as a lead to investigate
    further, not a confirmed flag.

    Returns
    ───────
    dict with keys:
      spectrogram_shape   — (freq_bins, time_bins)
      edge_pixel_ratio    — fraction of pixels that are edges (0.0–1.0)
      contour_count       — number of contours above min_contour_area
      top_contours        — list of dicts with x, y, w, h, area, aspect_ratio
      structured_geometry_detected — bool: True when layout looks non-random
    """
    signal_mod = _get_scipy_signal()

    # ── 1. Build spectrogram ──────────────────────────────────────────────
    nperseg = min(1024, len(samples) // 4)
    if nperseg < 64:
        msg = "Audio too short for spectrogram edge scan"
        if verbose:
            print(f"[spectrogram-edge] ⚠ {msg}")
        return {"error": msg, "structured_geometry_detected": False}

    freqs, times, Sxx = signal_mod.spectrogram(
        samples, fs=sample_rate, nperseg=nperseg,
        noverlap=nperseg // 2, scaling="density",
    )
    Sxx_db = 10.0 * np.log10(Sxx + 1e-10)

    # ── 2. Normalise to uint8 ─────────────────────────────────────────────
    vmin = np.percentile(Sxx_db, 5)
    vmax = np.percentile(Sxx_db, 99)
    norm = np.clip((Sxx_db - vmin) / max(vmax - vmin, 1e-6), 0.0, 1.0)
    gray_img = (norm * 255).astype(np.uint8)

    # Flip so low frequencies sit at the bottom (conventional orientation)
    gray_img = np.flipud(gray_img)

    # ── 3. Canny edge detection ───────────────────────────────────────────
    edges = cv2.Canny(gray_img, threshold1=canny_low, threshold2=canny_high)

    edge_pixel_ratio = float(np.count_nonzero(edges)) / max(edges.size, 1)

    # ── 4. Find contours ──────────────────────────────────────────────────
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    significant: list[dict] = []
    for cnt in contours:
        area = float(cv2.contourArea(cnt))
        if area < min_contour_area:
            continue
        x, y, w, h = cv2.boundingRect(cnt)
        aspect = round(w / max(h, 1), 3)
        significant.append({"x": x, "y": y, "w": w, "h": h,
                             "area": round(area, 1), "aspect_ratio": aspect})

    # Sort by area descending; keep top 10 for the report
    significant.sort(key=lambda d: d["area"], reverse=True)
    top_contours = significant[:10]

    # ── 5. Heuristic: is the geometry structured / non-random? ────────────
    # Thresholds are intentionally conservative to limit false positives.
    structured = False
    reasons: list[str] = []

    #  a) Many sizeable contours → repeated pattern
    if len(significant) > 30:
        structured = True
        reasons.append(f"{len(significant)} contours above area threshold")

    #  b) Several tall, narrow contours → possible vertical stripe / text column
    tall_narrow = [c for c in top_contours if c["aspect_ratio"] < 0.4 and c["h"] > 10]
    if len(tall_narrow) >= 4:
        structured = True
        reasons.append(f"{len(tall_narrow)} tall-narrow contours (possible text columns)")

    #  c) Several wide, short contours → possible horizontal band / text row
    wide_short = [c for c in top_contours if c["aspect_ratio"] > 2.5 and c["w"] > 10]
    if len(wide_short) >= 4:
        structured = True
        reasons.append(f"{len(wide_short)} wide-short contours (possible text rows)")

    #  d) Edge density is notably higher than random noise baseline
    if edge_pixel_ratio > 0.08:
        structured = True
        reasons.append(f"high edge density ({edge_pixel_ratio:.3f})")

    # ── Print report ──────────────────────────────────────────────────────
    print(f"\n[Spectrogram Edge Scan — Canny Geometry Detection]")
    print(f"  Spectrogram shape  : {Sxx_db.shape[0]} freq bins × {Sxx_db.shape[1]} time bins")
    print(f"  Edge pixel ratio   : {edge_pixel_ratio:.4f}")
    print(f"  Contours found     : {len(contours)} total, {len(significant)} above area threshold")

    if top_contours:
        print(f"  Top contours (by area):")
        for c in top_contours[:5]:
            print(f"    x={c['x']:4d} y={c['y']:4d}  {c['w']}×{c['h']}px  "
                  f"area={c['area']:.0f}  aspect={c['aspect_ratio']}")

    if structured:
        print(f"\n  🔓 [AUDIO VISUAL SPECTROGRAM FLAG UNMASKED]")
        for r in reasons:
            print(f"     ↳ {r}")
    else:
        print(f"  No structured geometry detected (likely normal audio content).")

    if verbose:
        print(f"  Canny thresholds   : low={canny_low}  high={canny_high}")
        print(f"  Min contour area   : {min_contour_area} px²")
        print(f"  Note: edge detection on spectrograms detects frequency-space")
        print(f"        geometry, not typography. Results are investigative leads.")

    return {
        "spectrogram_shape": Sxx_db.shape,
        "edge_pixel_ratio": round(edge_pixel_ratio, 4),
        "contour_count": len(significant),
        "top_contours": top_contours,
        "structured_geometry_detected": structured,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Omni-Cipher Bot — Media Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python media_tool.py --input puzzles/clip.mp4
  python media_tool.py --input puzzles/audio.wav --mode morse
  python media_tool.py --input puzzles/audio.wav --save-spectrogram
  python media_tool.py --input puzzles/clip.mp4 --mode hidden-frames --diff-threshold 50
""",
    )
    parser.add_argument("--input", "-i", required=True, help="Path to video or audio file")
    parser.add_argument(
        "--mode", "-m",
        choices=["all", "frames", "hidden-frames", "spectrogram", "morse", "lsb-audio"],
        default="all",
        help="Analysis mode (default: all)",
    )
    parser.add_argument("--output", "-o", help="Output directory for frames/spectrogram")
    parser.add_argument(
        "--save-spectrogram", action="store_true",
        help="Save spectrogram as PNG image",
    )
    parser.add_argument(
        "--frame-interval", type=int, default=1,
        help="Extract every Nth frame (default: 1 = all)",
    )
    parser.add_argument(
        "--diff-threshold", type=float, default=30.0,
        help="Frame difference threshold for anomaly detection (default: 30.0)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    analyze_file(
        file_path=args.input,
        mode=args.mode,
        output_dir=args.output,
        save_spectrogram=args.save_spectrogram,
        frame_interval=args.frame_interval,
        diff_threshold=args.diff_threshold,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()


# === OMNI-CIPHER BOT EXTENSION ===
# Additive optimization block — timeline logging + diagnostic capture.
# Zero modifications to any function above this line.
# ═══════════════════════════════════════════════════════════════════════

import datetime as _dt_med
import traceback as _tb_med
import time as _time_med

_TIMELINE_DIR_MED   = "puzzles/logs/timelines"
_DIAGNOSTIC_DIR_MED = "puzzles/logs/diagnostics"


def _med_ensure_dirs() -> None:
    import os
    os.makedirs(_TIMELINE_DIR_MED, exist_ok=True)
    os.makedirs(_DIAGNOSTIC_DIR_MED, exist_ok=True)


def _med_ts() -> str:
    return _dt_med.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _med_timeline_write(asset_name: str, lines: list) -> None:
    import os
    _med_ensure_dirs()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in asset_name)
    path = os.path.join(_TIMELINE_DIR_MED, f"{safe}.txt")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"\n{'─'*60}\n")
        fh.write(f"[{_med_ts()}]  media-analyzer  asset={asset_name}\n")
        for line in lines:
            fh.write(f"  {line}\n")


def _med_diag_write(fn_sig: str, lineno: int, root_cause: str, suggestion: str) -> None:
    import os
    _med_ensure_dirs()
    path = os.path.join(_DIAGNOSTIC_DIR_MED, "media_analyzer_diagnostics.txt")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"\n{'═'*60}\n")
        fh.write(f"[{_med_ts()}]\n")
        fh.write(f"  Tool       : media_tool.py\n")
        fh.write(f"  Function   : {fn_sig}\n")
        fh.write(f"  Line       : {lineno}\n")
        fh.write(f"  Root cause : {root_cause}\n")
        fh.write(f"  Fix model  :\n")
        for l in suggestion.strip().splitlines():
            fh.write(f"    {l}\n")


def ocb_audio_analyze_logged(audio_path: str) -> dict:
    """
    Optimized audio analysis pipeline with full timeline logging.
    Wraps load_audio_samples(), fft_sweep_audio(), detect_morse_from_audio(),
    and extract_audio_lsb() with per-step timing and defensive error capture.
    Uses numpy rfft for in-memory FFT (no temp file I/O overhead).
    """
    import os, time

    asset_name = os.path.basename(audio_path)
    timeline: list = []
    result: dict = {"asset": asset_name, "findings": {}}
    timeline.append(f"START  path={audio_path}")
    t0 = time.perf_counter()

    # ── Load audio samples ────────────────────────────────────
    samples = None
    sample_rate = 0
    try:
        t = time.perf_counter()
        samples, sample_rate = load_audio_samples(audio_path)
        ms = (time.perf_counter() - t) * 1000
        if samples is not None:
            timeline.append(f"LOAD   sample_rate={sample_rate}Hz  "
                             f"samples={len(samples):,}  dtype={samples.dtype}  "
                             f"duration={len(samples)/max(sample_rate,1):.2f}s  "
                             f"time={ms:.2f}ms")
        else:
            timeline.append(f"LOAD   FAILED — samples is None")
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("load_audio_samples(audio_path)", lineno, root,
            "# Audio load failed — likely unsupported codec or corrupt file.\n"
            "# Common cause: raw MP3 stream passed to scipy.io.wavfile directly.\n"
            "# Fix: check file extension before calling wavfile.read():\n"
            "#   if ext != '.wav': use ffmpeg convert_audio_to_wav() first.\n"
            "# For MP3: subprocess ffmpeg -i input.mp3 -ar 44100 -ac 1 output.wav\n"
            "# Then reload with wavfile.read(output.wav).")
        timeline.append(f"ERROR  LOAD  {root}")
        _med_timeline_write(asset_name, timeline)
        return result

    if samples is None:
        _med_timeline_write(asset_name, timeline)
        return result

    # ── FFT sweep ─────────────────────────────────────────────
    try:
        t = time.perf_counter()
        fft_result = fft_sweep_audio(samples, sample_rate, top_n=8)
        ms = (time.perf_counter() - t) * 1000
        timeline.append(f"FFT    bins={fft_result.get('fft_bins',0):,}  "
                         f"top_peaks={fft_result.get('peaks',[])[:3]}  "
                         f"morse_carrier={fft_result.get('morse_carrier_detected')}  "
                         f"time={ms:.2f}ms")
        if fft_result.get("morse_carrier_detected"):
            timeline.append(f"FFT    🔓 MORSE AUDIO CARRIER DETECTED  "
                             f"carrier_hz={fft_result.get('carrier_peaks_hz')}")
        result["findings"]["fft"] = fft_result
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("fft_sweep_audio(samples, sample_rate)", lineno, root,
            "# FFT sweep failed.\n"
            "# Common cause: samples array is empty or all-zero (silent audio).\n"
            "# Fix: guard with `if len(samples) < 64 or np.max(np.abs(samples)) < 1e-9: return early`\n"
            "# Also ensure samples is float64: samples.astype(np.float64) before np.fft.rfft().")
        timeline.append(f"ERROR  FFT  {root}")

    # ── Spectrogram ───────────────────────────────────────────
    try:
        t = time.perf_counter()
        spec = analyze_spectrogram(samples, sample_rate)
        ms = (time.perf_counter() - t) * 1000
        timeline.append(f"SPEC   dominant_hz={spec.get('modal_dominant_freq_hz')}  "
                         f"peaks={len(spec.get('significant_peaks',[]))}  "
                         f"duration={spec.get('duration_s')}s  time={ms:.2f}ms")
        for freq_hz, power in spec.get("significant_peaks", [])[:5]:
            timeline.append(f"PEAK   {freq_hz:.1f}Hz  power={power:.1f}dB")
        result["findings"]["spectrogram"] = {
            "dominant_hz": spec.get("modal_dominant_freq_hz"),
            "peaks": spec.get("significant_peaks", [])[:8],
        }
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("analyze_spectrogram(samples, sample_rate)", lineno, root,
            "# Spectrogram failed — likely nperseg too large for short audio.\n"
            "# Fix: nperseg = min(1024, len(samples) // 4)\n"
            "# Guard: if nperseg < 64: return {'error': 'too short'}")
        timeline.append(f"ERROR  SPEC  {root}")

    # ── Morse detection ───────────────────────────────────────
    try:
        t = time.perf_counter()
        morse = detect_morse_from_audio(samples, sample_rate)
        ms = (time.perf_counter() - t) * 1000
        seq = morse.get("morse_sequence", "")
        decoded = morse.get("decoded_text", "")
        timeline.append(f"MORSE  target_hz={morse.get('target_frequency_hz')}  "
                         f"dot_ms={morse.get('dot_duration_ms')}  "
                         f"sequence_len={len(seq)}  decoded={decoded[:60]!r}  "
                         f"time={ms:.2f}ms")
        result["findings"]["morse"] = {"decoded": decoded, "sequence": seq[:120]}
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("detect_morse_from_audio(samples, sample_rate)", lineno, root,
            "# Morse detection failed.\n"
            "# Common cause: Hilbert transform on very short or constant signal.\n"
            "# Fix: guard `if len(samples) < sample_rate * 0.1: return {'error': ...}`\n"
            "# Also catch scipy.signal.lfilter ValueError for degenerate bandpass coefficients:\n"
            "#   if low >= high: skip bandpass, use samples directly.")
        timeline.append(f"ERROR  MORSE  {root}")

    # ── LSB audio ─────────────────────────────────────────────
    try:
        t = time.perf_counter()
        lsb = extract_audio_lsb(samples, sample_rate)
        ms = (time.perf_counter() - t) * 1000
        timeline.append(f"LSB    samples={lsb.get('total_samples',0):,}  "
                         f"bytes={lsb.get('total_bytes',0):,}  "
                         f"text_found={bool(lsb.get('text_preview'))}  "
                         f"time={ms:.2f}ms")
        if lsb.get("text_preview"):
            timeline.append(f"LSB    text_preview={lsb['text_preview'][:80]!r}")
        result["findings"]["lsb"] = {
            "bytes": lsb.get("total_bytes"),
            "text_preview": lsb.get("text_preview"),
        }
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("extract_audio_lsb(samples, sample_rate)", lineno, root,
            "# Audio LSB extraction failed.\n"
            "# Common cause: samples are float32 and conversion to int16 overflows.\n"
            "# Fix: clip before cast: np.clip(samples * 32767, -32768, 32767).astype(np.int16)\n"
            "# Also use np.unpackbits() for vectorised LSB extraction instead of Python loop:\n"
            "#   int16_arr = samples_int16.view(np.uint8)\n"
            "#   bits = np.unpackbits(int16_arr) — then slice LSBs at positions [7::8]")
        timeline.append(f"ERROR  LSB  {root}")

    elapsed_total = (time.perf_counter() - t0) * 1000
    timeline.append(f"END    total_time={elapsed_total:.2f}ms")
    _med_timeline_write(asset_name, timeline)
    return result


def ocb_video_analyze_logged(
    video_path: str,
    frame_interval: int = 1,
    diff_threshold: float = 30.0,
) -> dict:
    """
    Optimized video analysis pipeline with full timeline logging.
    Wraps analyze_video_frames() and flash_frame_scanner() with per-step
    timing, cv2.absdiff vectorised frame comparison, and diagnostic capture.
    """
    import os, time

    asset_name = os.path.basename(video_path)
    timeline: list = []
    result: dict = {"asset": asset_name, "findings": {}}
    timeline.append(f"START  path={video_path}  interval={frame_interval}  threshold={diff_threshold}")
    t0 = time.perf_counter()

    # ── Video frame analysis ──────────────────────────────────
    try:
        t = time.perf_counter()
        video_result = analyze_video_frames(
            video_path, mode="hidden-frames",
            frame_interval=frame_interval,
            diff_threshold=diff_threshold,
        )
        ms = (time.perf_counter() - t) * 1000
        info = video_result.get("video_info", {})
        timeline.append(
            f"VIDEO  fps={info.get('fps',0):.2f}  frames={info.get('frame_count',0)}  "
            f"duration={info.get('duration','?')}  "
            f"size={info.get('width')}x{info.get('height')}  time={ms:.2f}ms"
        )
        timeline.append(
            f"DIFF   mean={video_result.get('mean_diff',0):.3f}  "
            f"flagged={video_result.get('flagged_count',0)}"
        )
        for f in video_result.get("flagged_frames", []):
            timeline.append(f"FLAG   frame={f['frame_index']}  "
                             f"diff={f['diff_score']}  threshold={f['threshold']}")
        result["findings"]["video"] = video_result
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("analyze_video_frames(video_path, ...)", lineno, root,
            "# Video frame analysis failed.\n"
            "# Common cause: cv2.VideoCapture can't open file (codec not supported).\n"
            "# Fix: check cap.isOpened() immediately after VideoCapture(path).\n"
            "# For MKV/H265: ensure opencv was built with ffmpeg support.\n"
            "# Fallback: use ffmpeg to remux: ffmpeg -i input.mkv -c copy output.mp4")
        timeline.append(f"ERROR  VIDEO  {root}")

    # ── Flash frame scanner ───────────────────────────────────
    try:
        t = time.perf_counter()
        flash_result = flash_frame_scanner(
            video_path,
            frame_interval=frame_interval,
            diff_threshold=diff_threshold,
        )
        ms = (time.perf_counter() - t) * 1000
        timeline.append(
            f"FLASH  scanned={flash_result.get('scanned_frames',0)}  "
            f"anomalous={flash_result.get('anomalous_count',0)}  "
            f"peak_diff={flash_result.get('global_peak_diff',0):.3f}  "
            f"time={ms:.2f}ms"
        )
        for entry in flash_result.get("anomalous_frames", []):
            timeline.append(f"CUT    frame={entry['frame_index']}  "
                             f"mean_diff={entry['mean_diff']}")
            if flash_result.get("anomalous_count", 0) > 0:
                timeline.append(f"FLASH  🔓 [FLASH FRAME VARIANCE ALERT]  "
                                 f"frames={[e['frame_index'] for e in flash_result.get('anomalous_frames',[])]}")
        result["findings"]["flash"] = flash_result
    except Exception as exc:
        lineno = _tb_med.extract_tb(exc.__traceback__)[-1].lineno
        root   = f"{type(exc).__name__}: {exc}"
        _med_diag_write("flash_frame_scanner(video_path, ...)", lineno, root,
            "# Flash frame scanner failed.\n"
            "# Common cause: cv2.absdiff() dtype mismatch (uint8 vs float).\n"
            "# Fix: ensure both frames are uint8 before absdiff:\n"
            "#   gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)  # already uint8\n"
            "# Also guard: if prev_gray.shape != gray.shape: resize or skip.")
        timeline.append(f"ERROR  FLASH  {root}")

    elapsed_total = (time.perf_counter() - t0) * 1000
    timeline.append(f"END    total_time={elapsed_total:.2f}ms")
    _med_timeline_write(asset_name, timeline)
    return result
