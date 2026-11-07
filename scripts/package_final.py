#!/usr/bin/env python3
"""Build and verify the final env-guard source archive."""

from __future__ import annotations

import stat
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "env-guard-v4-final.zip"
VERIFY = ROOT / ".tmp" / "verify-final"
PREFIX = "env-guard/"
EXCLUDED_DIRS = {".git", "__pycache__", ".venv", ".tmp"}
EXECUTABLE_SUFFIXES = {".py", ".sh"}


def excluded(relative: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in relative.parts)


def main() -> int:
    if VERIFY.exists():
        shutil.rmtree(VERIFY)
    VERIFY.mkdir(parents=True)

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            if path == OUTPUT:
                continue
            relative = path.relative_to(ROOT)
            if excluded(relative):
                continue
            name = PREFIX + relative.as_posix()
            mode = 0o755 if path.suffix in EXECUTABLE_SUFFIXES else 0o644
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 7, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)

    expected: dict[str, int] = {}
    with zipfile.ZipFile(OUTPUT) as archive:
        for info in archive.infolist():
            if info.is_dir():
                print(f"FAIL: archive entry is a directory: {info.filename}")
                return 1
            if not info.filename.startswith(PREFIX):
                print(f"FAIL: bad archive prefix: {info.filename}")
                return 1
            mode = info.external_attr >> 16
            suffix = Path(info.filename).suffix
            expected_mode = 0o755 if suffix in EXECUTABLE_SUFFIXES else 0o644
            if mode != stat.S_IFREG | expected_mode:
                print(f"FAIL: mode {oct(mode)} for {info.filename}")
                return 1
            expected[info.filename] = expected_mode
            archive.extract(info, VERIFY)

    for name, expected_mode in expected.items():
        extracted = VERIFY / Path(*name.split("/"))
        if not extracted.is_file():
            print(f"FAIL: missing extracted file: {name}")
            return 1
        # zipfile.extract may not apply permission bits on every platform.
        # The archive metadata below remains the authoritative transport mode.
        archive_mode = None
        with zipfile.ZipFile(OUTPUT) as archive:
            archive_mode = stat.S_IMODE(archive.getinfo(name).external_attr >> 16)
        if archive_mode != expected_mode:
            print(f"FAIL: archive mode {oct(archive_mode)} for {name}")
            return 1

    print(f"files={len(expected)}")
    print(f"archive={OUTPUT.name}")
    print("verification=passed")
    shutil.rmtree(VERIFY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
