#!/usr/bin/env python3
"""Create a durable, create-only checksum inventory of all C4 result evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat


CHUNK = 1024 * 1024
RESULT_MANIFEST = "C4_RESULT_SHA256SUMS"
REQUIRED_FILES = (
    "MATRIX_ACTIVE",
    "C4_EXECUTION_ACTIVE",
    "C4_POLICY_PREFLIGHT_PROVENANCE.json",
    "C4_POLICY_SET.json",
    "C4_POLICY_PREFLIGHT_SEAL.json",
    "analysis/c4_primary.json",
    "analysis/c4_primary.tex",
)
EVIDENCE_DIRECTORIES = (
    "analysis",
    "journals",
    "logs",
    "policy_preflight",
    "receipts",
    "traces",
    "wrapper_cleanup_attestations",
    "wrapper_completions",
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            value.update(chunk)
    return value.hexdigest()


def require_regular_file(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} is not a regular non-symlink file: {path}")


def require_regular_directory(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label} is not a regular non-symlink directory: {path}")


def evidence_files(root: Path) -> list[Path]:
    selected: set[Path] = set()
    for relative in REQUIRED_FILES:
        path = root / relative
        require_regular_file(path, f"required C4 result {relative}")
        selected.add(path)
    for relative in EVIDENCE_DIRECTORIES:
        directory = root / relative
        require_regular_directory(directory, f"C4 result directory {relative}")
        for path in directory.rglob("*"):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError(f"symlink in C4 result evidence: {path}")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"non-regular C4 result evidence: {path}")
            selected.add(path)
    return sorted(selected, key=lambda path: path.relative_to(root).as_posix())


def fsync_evidence(root: Path, files: list[Path]) -> None:
    """Force evidence bytes and directory entries durable before hashing."""
    directories = {root}
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = path.parent
        while parent != root:
            directories.add(parent)
            parent = parent.parent
    for directory in sorted(
        directories, key=lambda path: len(path.relative_to(root).parts), reverse=True
    ):
        require_regular_directory(directory, "C4 evidence directory")
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    root = args.root
    require_regular_directory(root, "C4 run root")
    output = root / RESULT_MANIFEST
    if os.path.lexists(output):
        raise SystemExit(f"refusing to overwrite frozen result manifest: {output}")

    files = evidence_files(root)
    if not files:
        raise SystemExit("no C4 result evidence found")
    fsync_evidence(root, files)
    payload = "".join(
        f"{digest(path)}  {path.relative_to(root).as_posix()}\n" for path in files
    ).encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise RuntimeError("short write while freezing C4 results")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(root, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)

    require_regular_file(output, "C4 result manifest")
    print(digest(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
