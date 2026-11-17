#!/usr/bin/env python3
"""Create and durably verify one immutable C4 vLLM server-log archive."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys


CHUNK = 1024 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: SOURCE DESTINATION")
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])

    source_info = source.lstat()
    if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
        raise SystemExit("source server log is not a regular non-symlink file")
    parent_info = destination.parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise SystemExit("destination parent is not a regular non-symlink directory")
    if os.path.lexists(destination):
        raise SystemExit("destination server log already exists")

    temporary = destination.with_name(f".{destination.name}.tmp.{os.getpid()}")
    if os.path.lexists(temporary):
        raise SystemExit("server-log staging path already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK), b""):
                offset = 0
                while offset < len(chunk):
                    written = os.write(descriptor, chunk[offset:])
                    if written <= 0:
                        raise RuntimeError("short write while archiving server log")
                    offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    # A hard link publishes the fully fsync'd inode atomically and refuses to
    # replace any concurrently created final path.  Both names are on the same
    # evidence filesystem, including NFS deployments.
    os.link(temporary, destination, follow_symlinks=False)
    parent_descriptor = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)

    destination_info = destination.lstat()
    if (
        stat.S_ISLNK(destination_info.st_mode)
        or not stat.S_ISREG(destination_info.st_mode)
        or destination_info.st_size != source_info.st_size
        or digest(destination) != digest(source)
    ):
        raise SystemExit("durable server-log archive verification failed")
    temporary.unlink()
    parent_descriptor = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
