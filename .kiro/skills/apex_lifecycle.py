#!/usr/bin/env python3
"""Shared, report-only lifecycle checks for the Omni-Cipher tools."""

from __future__ import annotations

import argparse
import ast
import datetime
import fcntl
import hashlib
import json
import py_compile
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Callable, Optional


ROOT = Path(__file__).resolve().parents[2]
CORE_TOOLS = (
    ROOT / ".kiro/skills/cipher-engine/cipher_tool_optimized.py",
    ROOT / ".kiro/skills/image-stego/image_tool.py",
    ROOT / ".kiro/skills/media-analyzer/media_tool.py",
)
PATCH_LOG = ROOT / "puzzles/logs/diagnostics/workspace_patches.log"
LIFECYCLE_HEADER = "# === OMNI-CIPHER APEX LIFECYCLE AGENT ==="
SKILL_ROOT = ROOT / ".kiro/skills"


def _timestamp() -> str:
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def _active_blocks(path: Path) -> list[str]:
    try:
        return [
            line.strip()[2:].strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("# ===")
        ]
    except (OSError, UnicodeError):
        return []


def _snapshot(path: Path) -> dict:
    try:
        stat = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return {
            "exists": True,
            "size_bytes": stat.st_size,
            "modified_ns": stat.st_mtime_ns,
            "sha256": digest.hexdigest(),
        }
    except OSError as error:
        return {"exists": False, "error": f"{type(error).__name__}: {error}"}


def _previous_hash(source_name: str) -> Optional[str]:
    try:
        with PATCH_LOG.open("r", encoding="utf-8") as log:
            for line in reversed(log.readlines()):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("source_file") == source_name:
                    file_state = record.get("file_state", {})
                    return file_state.get("sha256")
    except OSError:
        pass
    return None


def append_record(
    event: str,
    *,
    tool: str,
    source: Path,
    state: str,
    details: Optional[dict] = None,
    patched_blocks: Optional[list[str]] = None,
) -> None:
    """Append one JSON record; logging failures never interrupt tool use."""
    source_name = _relative(source)
    file_state = _snapshot(source)
    previous = _previous_hash(source_name)
    current = file_state.get("sha256")
    changed = previous is not None and current is not None and previous != current
    blocks = _active_blocks(source)
    record = {
        "timestamp": _timestamp(),
        "event": event,
        "tool": tool,
        "source_file": source_name,
        "state": state,
        "file_state": file_state,
        "recent_structural_updates_added": changed if previous is not None else None,
        "active_blocks": blocks,
        "active_blocks_patched": patched_blocks if patched_blocks is not None else (blocks if changed else []),
        "details": details or {},
    }
    try:
        PATCH_LOG.parent.mkdir(parents=True, exist_ok=True)
        with PATCH_LOG.open("a", encoding="utf-8") as log:
            fcntl.flock(log.fileno(), fcntl.LOCK_EX)
            try:
                log.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                log.flush()
            finally:
                fcntl.flock(log.fileno(), fcntl.LOCK_UN)
    except Exception as error:
        print(f"[apex-lifecycle] Telemetry write failed: {type(error).__name__}: {error}", file=sys.stderr)


def _decode_check(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    decoder = next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_decode_raw_text"
    )
    namespace: dict = {}
    module = ast.Module(body=[decoder], type_ignores=[])
    exec(compile(module, str(path), "exec"), namespace)
    sample = b"-@!#\x00\xff"
    decoded = namespace["_decode_raw_text"](sample)
    if decoded != sample.decode("latin-1") or decoded.encode("latin-1") != sample:
        raise AssertionError(f"Latin-1 round trip failed in {_relative(path)}")


def _compile_files(files: list[Path]) -> list[dict]:
    errors = []
    with tempfile.TemporaryDirectory(prefix="omni-apex-compile-") as temp_dir:
        temp_root = Path(temp_dir)
        for index, source in enumerate(files):
            try:
                py_compile.compile(
                    str(source),
                    cfile=str(temp_root / f"module_{index}.pyc"),
                    doraise=True,
                )
            except Exception as error:
                errors.append({
                    "file": _relative(source),
                    "error_type": type(error).__name__,
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                })
    return errors


def run_preflight(tool: str, source: Path) -> dict:
    """Compile all core scripts and verify lossless raw-byte decoding."""
    errors = _compile_files(list(CORE_TOOLS))
    if not errors:
        for path in CORE_TOOLS:
            try:
                _decode_check(path)
            except Exception as error:
                errors.append({
                    "file": _relative(path),
                    "error_type": type(error).__name__,
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                })
    report = {
        "interpreter": sys.executable,
        "compiled_files": [_relative(path) for path in CORE_TOOLS],
        "exceptions": errors,
        "ok": not errors,
    }
    append_record(
        "PREFLIGHT",
        tool=tool,
        source=source,
        state="PASS" if report["ok"] else "FAIL",
        details=report,
    )
    if errors:
        append_record(
            "FLAWS_INCIDENT_REPORT",
            tool=tool,
            source=source,
            state="OPEN",
            details={
                "summary": "Core preflight found compilation or Latin-1 invariant failures.",
                "exceptions": errors,
                "recommendations": [
                    "Repair the reported source location and rerun the core preflight.",
                    "Preserve the strict Latin-1 decoder and punctuation round-trip assertion.",
                ],
            },
        )
    return report


def record_resource_insufficiency(
    tool: str,
    source: Path,
    puzzle_class: str,
    structural_gap: str,
    recommendations: list[str],
) -> None:
    append_record(
        "RESOURCE INSUFFICIENCY FAULT",
        tool=tool,
        source=source,
        state="RECOMMENDATION_REQUIRED",
        details={
            "puzzle_class": puzzle_class,
            "structural_gap": structural_gap,
            "recommended_patches": recommendations,
        },
    )


def run_cli(
    tool: str,
    source: str,
    entrypoint: Callable[[], None],
    transaction_logger: Callable[[str, str], None],
) -> None:
    """Run one CLI after preflight and synchronize both telemetry contracts."""
    source_path = Path(source).resolve()
    append_record("ACCESS", tool=tool, source=source_path, state="STARTED")
    report = run_preflight(tool, source_path)
    if not report["ok"]:
        transaction_logger("FAILED", "lifecycle preflight failed")
        append_record("EXECUTION_RESULT", tool=tool, source=source_path, state="BLOCKED")
        raise SystemExit(1)

    try:
        entrypoint()
    except SystemExit as error:
        state = "COMPLETED" if error.code in (None, 0) else "FAILED"
        transaction_logger(state, f"cli_exit={error.code!r}")
        append_record("EXECUTION_RESULT", tool=tool, source=source_path, state=state,
                      details={"exit_code": error.code})
        raise
    except Exception as error:
        details = {
            "error_type": type(error).__name__,
            "message": str(error),
            "traceback": traceback.format_exc(),
            "recommendations": [
                "Inspect the reported call path and reproduce with the failing asset.",
                "Keep raw-byte decoding and symbol-preservation invariants intact.",
            ],
        }
        append_record("FLAWS_INCIDENT_REPORT", tool=tool, source=source_path,
                      state="OPEN", details=details)
        transaction_logger("ERROR", f"{type(error).__name__}: {error}")
        append_record("EXECUTION_RESULT", tool=tool, source=source_path, state="ERROR",
                      details={"error_type": type(error).__name__})
        print(f"[{tool}] ERROR: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
    else:
        transaction_logger("COMPLETED", "cli_exit=0")
        append_record("EXECUTION_RESULT", tool=tool, source=source_path, state="COMPLETED")


def run_integration_suite() -> dict:
    """Compile repository Python sources and enforce shared core invariants."""
    excluded = {".git", ".venv", "venv", "__pycache__", "node_modules", ".tox"}
    python_files = [
        path for path in ROOT.rglob("*.py")
        if not any(part in excluded for part in path.parts)
    ]
    errors = _compile_files(python_files)
    if not errors:
        for path in CORE_TOOLS:
            try:
                _decode_check(path)
            except Exception as error:
                errors.append({
                    "file": _relative(path),
                    "error_type": type(error).__name__,
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                })
    punctuation = "-@!#"
    logging_round_trip = json.loads(json.dumps(punctuation, ensure_ascii=False)) == punctuation
    if not logging_round_trip:
        errors.append({"file": "telemetry", "error_type": "AssertionError",
                       "message": "JSON logging changed punctuation tokens"})
    return {"ok": not errors, "python_files_checked": len(python_files), "exceptions": errors,
            "punctuation_logging_round_trip": logging_round_trip}


def _skill_snapshot() -> dict[str, tuple[int, int, str]]:
    result = {}
    for path in SKILL_ROOT.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        try:
            stat = path.stat()
            result[_relative(path)] = (stat.st_mtime_ns, stat.st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        except OSError:
            continue
    return result


def watch(interval: float, debounce: float) -> None:
    """Poll .kiro/skills and run the repository integration gate after edits."""
    previous = _skill_snapshot()
    pending: list[str] = []
    last_change = 0.0
    print(f"[apex-lifecycle] Watching {SKILL_ROOT}; Ctrl+C stops the watcher.")
    try:
        while True:
            time.sleep(interval)
            current = _skill_snapshot()
            changed = sorted(
                name for name in set(previous) | set(current)
                if previous.get(name) != current.get(name)
            )
            if changed:
                pending.extend(name for name in changed if name not in pending)
                last_change = time.monotonic()
                for name in changed:
                    source = ROOT / name
                    append_record(
                        "MODIFIED",
                        tool="workspace-watcher",
                        source=source,
                        state="DETECTED",
                        details={"path": name},
                        patched_blocks=_active_blocks(source),
                    )
                previous = current

            if pending and time.monotonic() - last_change >= debounce:
                report = run_integration_suite()
                source = ROOT / pending[-1]
                append_record(
                    "FULL_INTEGRATION_SUITE",
                    tool="workspace-watcher",
                    source=source,
                    state="PASS" if report["ok"] else "FAIL",
                    details={"changed_files": pending, **report},
                )
                if not report["ok"]:
                    append_record(
                        "FLAWS_INCIDENT_REPORT",
                        tool="workspace-watcher",
                        source=source,
                        state="OPEN",
                        details={
                            "summary": "Post-update repository integration gate failed.",
                            "exceptions": report["exceptions"],
                            "recommendations": [
                                "Repair each reported syntax or invariant failure.",
                                "Re-run the integration suite after the patch is complete.",
                            ],
                        },
                    )
                else:
                    print(f"[apex-lifecycle] Integration PASS ({report['python_files_checked']} Python files)")
                pending.clear()
    except KeyboardInterrupt:
        print("\n[apex-lifecycle] Watcher stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Omni-Cipher lifecycle checks and source watcher")
    parser.add_argument("--watch", action="store_true", help="Watch .kiro/skills and test after changes")
    parser.add_argument("--once", action="store_true", help="Run one repository-wide integration check")
    parser.add_argument("--interval", type=float, default=1.0, help="Watcher polling interval in seconds")
    parser.add_argument("--debounce", type=float, default=1.5, help="Quiet time before running integration checks")
    args = parser.parse_args()
    if args.watch:
        watch(max(args.interval, 0.2), max(args.debounce, 0.2))
    elif args.once:
        report = run_integration_suite()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        raise SystemExit(0 if report["ok"] else 1)
    else:
        parser.print_help()


# === OMNI-CIPHER APEX LIFECYCLE AGENT ===
if __name__ == "__main__":
    main()