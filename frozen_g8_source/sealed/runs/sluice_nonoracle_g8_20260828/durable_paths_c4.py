#!/usr/bin/env python3
"""Durably create C4 evidence directories and create-only phase markers."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat


def _under_root(root: Path, raw: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.absolute()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"path escapes C4 root: {raw}") from exc
    return candidate


def _open_directory(path: Path) -> int:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"not a regular non-symlink directory: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(descriptor)
        raise RuntimeError(f"directory changed during open: {path}")
    return descriptor


def _fsync_directory(path: Path) -> None:
    descriptor = _open_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_directory(root: Path, destination: Path) -> None:
    relative = destination.relative_to(root)
    current = root
    _fsync_directory(current)
    for part in relative.parts:
        parent = current
        current = parent / part
        try:
            os.mkdir(current, 0o700)
            created = True
        except FileExistsError:
            created = False
        _fsync_directory(current)
        if created:
            # Persist the new directory's own metadata, then the parent entry
            # that names it, before a child process can place evidence inside.
            _fsync_directory(parent)


def create_lines(root: Path, destination: Path, lines: list[str]) -> None:
    if destination.parent == destination:
        raise RuntimeError("marker has no parent")
    ensure_directory(root, destination.parent)
    if not lines or any("\n" in line or "\r" in line for line in lines):
        raise RuntimeError("marker lines must be non-empty single lines")
    payload = ("\n".join(lines) + "\n").encode("ascii")
    descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise RuntimeError(f"short marker write: {destination}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(destination.parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    ensure = subparsers.add_parser("ensure")
    ensure.add_argument("paths", nargs="+")
    marker = subparsers.add_parser("create-lines")
    marker.add_argument("path")
    marker.add_argument("lines", nargs="+")
    args = parser.parse_args(argv)

    root = args.root.absolute()
    _fsync_directory(root)
    if args.operation == "ensure":
        for raw in args.paths:
            ensure_directory(root, _under_root(root, raw))
    else:
        create_lines(root, _under_root(root, args.path), list(args.lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
