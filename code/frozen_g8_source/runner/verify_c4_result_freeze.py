#!/usr/bin/env python3
"""Re-enumerate and authenticate the frozen C4 evidence before completion."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat

import freeze_c4_results


def require_digest(value: str, label: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError(f"invalid {label} SHA-256")
    return value


def read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is not a regular non-symlink file: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"{label} changed during open: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, freeze_c4_results.CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise RuntimeError(f"{label} changed during read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_manifest(root: Path, raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("C4 result manifest is not ASCII") from exc
    if not text or not text.endswith("\n"):
        raise RuntimeError("C4 result manifest is empty or lacks a final newline")
    rows: dict[str, str] = {}
    for line in text.splitlines():
        digest, separator, relative = line.partition("  ")
        require_digest(digest, "manifest entry")
        path = Path(relative)
        if (
            separator != "  "
            or not relative
            or path.is_absolute()
            or path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in path.parts)
            or relative in rows
        ):
            raise RuntimeError(f"malformed or duplicate result-manifest line: {line!r}")
        candidate = (root / path).absolute()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"result-manifest path escapes root: {relative}") from exc
        rows[relative] = digest
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-analysis-json-sha256", required=True)
    parser.add_argument("--expected-analysis-tex-sha256", required=True)
    args = parser.parse_args(argv)
    expected_manifest = require_digest(
        args.expected_manifest_sha256, "result manifest"
    )
    expected_json = require_digest(args.expected_analysis_json_sha256, "analysis JSON")
    expected_tex = require_digest(args.expected_analysis_tex_sha256, "analysis TEX")
    root = args.root.absolute()
    freeze_c4_results.require_regular_directory(root, "C4 result root")
    manifest_path = root / freeze_c4_results.RESULT_MANIFEST
    manifest_raw = read_regular(manifest_path, "C4 result manifest")
    if hashlib.sha256(manifest_raw).hexdigest() != expected_manifest:
        raise RuntimeError("C4 result manifest changed after creation")
    declared = parse_manifest(root, manifest_raw)
    selected = freeze_c4_results.evidence_files(root)
    actual_names = {path.relative_to(root).as_posix() for path in selected}
    if set(declared) != actual_names:
        raise RuntimeError("C4 result inventory changed after manifest creation")
    for relative, expected in sorted(declared.items()):
        observed = hashlib.sha256(
            read_regular(root / relative, f"C4 result {relative}")
        ).hexdigest()
        if observed != expected:
            raise RuntimeError(f"C4 result changed after manifest creation: {relative}")
    if declared.get("analysis/c4_primary.json") != expected_json:
        raise RuntimeError("result manifest does not bind captured analysis JSON")
    if declared.get("analysis/c4_primary.tex") != expected_tex:
        raise RuntimeError("result manifest does not bind captured analysis TEX")
    print(expected_manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
