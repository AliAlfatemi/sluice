#!/usr/bin/env python3
"""Data-driven checkout materialization for Git-omitted tree state.

Problem this closes
-------------------
Git (and dulwich) record only two file modes -- 0644 and 0755 -- plus symlinks
and gitlinks, and they do not record directories at all.  A tree that is sealed
read-only on disk (0444 files, 0555 directories) and that contains a
deliberately empty directory therefore CANNOT be reproduced by any checkout:

  * every 0444 file comes back 0644,
  * every 0555 directory comes back 0755,
  * every empty directory is simply absent.

The C10..C15 launch attempts each hit this, and each responded by hand-pinning
one more table of per-capsule constants (``files=``, ``directories=``,
``digest=``) into the next generation's checkout helper.  Because every attempt
must re-verify every previous attempt's capsule, that table grows as
1+2+...+n -- measured at 2 (C12), 6 (C13), 10 (C14) and 15 (C15) sealed roots.
Each entry had to be hand-computed correctly before a single experimental arm
could run, so the probability of a clean launch fell as the cost of achieving
one rose.  Six consecutive generations produced zero arms.

The fix here is to stop hand-writing that state and start deriving it.  A seal
is *scanned* out of a tree, stored beside it as ordinary committed data, and
replayed after checkout.  Adding an Nth sealed tree needs no new code and no
new constants, so the quadratic term disappears.

Operations
----------
  seal <root>...        derive TREE_SEAL.json for each root by scanning it
  materialize <root>... restore modes + empty directories from the seal
  verify <root>...      report whether a root currently matches its seal

``materialize`` is idempotent and is safe to run on an already-correct tree.
It never weakens a verifier: it makes a checkout physically equal to what the
verifiers already, correctly, demand.

Exit codes: 0 success, 1 mismatch/failure, 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath

SEAL_BASENAME = "TREE_SEAL.json"
SEAL_SCHEMA = "sluice_tree_seal/1"

# Modes a plain Git checkout can actually reproduce.  Anything else in a tree
# is, by definition, state that must be replayed from the seal.
GIT_REPRODUCIBLE_FILE_MODES = frozenset({0o644, 0o755})


def _safe_relative(value: str) -> str:
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or parsed.as_posix() != value:
        raise ValueError(f"unsafe relative path in seal: {value!r}")
    return parsed.as_posix()


def scan_tree(root: Path) -> dict:
    """Derive the complete mode/empty-directory state of ``root``."""
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"not a directory: {root}")
    files: dict[str, int] = {}
    directories: dict[str, int] = {}
    symlinks: list[str] = []
    empty_directories: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        if rel_dir:
            directories[rel_dir] = stat.S_IMODE(here.lstat().st_mode)
        if not dirnames and not filenames and rel_dir:
            empty_directories.append(rel_dir)
        for name in filenames:
            path = here / name
            if path.name == SEAL_BASENAME and rel_dir == "":
                continue
            rel = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                symlinks.append(rel)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise SystemExit(f"refusing: non-regular, non-symlink entry: {path}")
            files[rel] = stat.S_IMODE(info.st_mode)

    root_mode = stat.S_IMODE(root.lstat().st_mode)
    value = {
        "schema": SEAL_SCHEMA,
        "root_mode": root_mode,
        "files": dict(sorted(files.items())),
        "directories": dict(sorted(directories.items())),
        "symlinks": sorted(symlinks),
        "empty_directories": sorted(empty_directories),
    }
    value["digest"] = seal_digest(value)
    return value


def seal_digest(value: dict) -> str:
    """Stable digest over exactly the state a checkout cannot reproduce."""
    material = {
        "root_mode": value["root_mode"],
        "files": value["files"],
        "directories": value["directories"],
        "symlinks": value["symlinks"],
        "empty_directories": value["empty_directories"],
    }
    payload = json.dumps(
        material, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(b"sluice-tree-seal-v1\0" + payload).hexdigest()


def load_seal(root: Path) -> dict:
    path = root / SEAL_BASENAME
    if not path.is_file():
        raise SystemExit(f"missing seal: {path}")
    value = json.loads(path.read_text(encoding="ascii"))
    if value.get("schema") != SEAL_SCHEMA:
        raise SystemExit(f"unexpected seal schema in {path}")
    for key in ("files", "directories"):
        for rel in value.get(key, {}):
            _safe_relative(rel)
    for rel in value.get("empty_directories", []):
        _safe_relative(rel)
    if value.get("digest") != seal_digest(value):
        raise SystemExit(f"seal is internally inconsistent: {path}")
    return value


def op_seal(root: Path) -> int:
    value = scan_tree(root)
    payload = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         sort_keys=True, indent=1).encode("ascii") + b"\n"
    target = root / SEAL_BASENAME
    # The tree may itself be read-only; open the parent explicitly.
    previous = stat.S_IMODE(root.lstat().st_mode)
    os.chmod(root, previous | 0o700)
    try:
        if target.exists():
            os.chmod(target, 0o644)
        target.write_bytes(payload)
        os.chmod(target, 0o444)
    finally:
        os.chmod(root, previous)
    print(f"sealed {root} files={len(value['files'])} "
          f"dirs={len(value['directories'])} "
          f"empty={len(value['empty_directories'])} digest={value['digest'][:16]}")
    return 0


def op_materialize(root: Path) -> int:
    """Restore empty directories and exact modes after a checkout."""
    root = root.resolve()
    value = load_seal(root)

    # Make the whole subtree writable/traversable first, so a partially
    # materialized (already read-only) tree can still be corrected.
    for dirpath, dirnames, _ in os.walk(root):
        dirnames.sort()
        try:
            os.chmod(dirpath, stat.S_IMODE(Path(dirpath).lstat().st_mode) | 0o700)
        except FileNotFoundError:
            pass

    created = 0
    for rel in value["empty_directories"]:
        path = root / rel
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created += 1

    # Directories that exist only to hold the empty ones must exist too.
    for rel in value["directories"]:
        path = root / rel
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created += 1

    missing = [rel for rel in value["files"] if not (root / rel).is_file()]
    if missing:
        raise SystemExit(
            f"refusing: {len(missing)} sealed file(s) absent from checkout, "
            f"first={missing[0]}"
        )

    for rel, mode in value["files"].items():
        os.chmod(root / rel, mode)

    # Directories last, deepest first, so tightening 0555 cannot block a
    # subsequent write inside that directory.
    for rel in sorted(value["directories"], key=lambda p: p.count("/"), reverse=True):
        os.chmod(root / rel, value["directories"][rel])
    os.chmod(root, value["root_mode"])

    print(f"materialized {root} created_dirs={created} "
          f"files={len(value['files'])} dirs={len(value['directories'])}")
    return 0


def op_verify(root: Path) -> int:
    root = root.resolve()
    value = load_seal(root)
    problems: list[str] = []

    for rel, mode in value["files"].items():
        path = root / rel
        if not path.is_file():
            problems.append(f"missing file: {rel}")
            continue
        actual = stat.S_IMODE(path.lstat().st_mode)
        if actual != mode:
            problems.append(f"mode {oct(actual)} != {oct(mode)}: {rel}")
    for rel, mode in value["directories"].items():
        path = root / rel
        if not path.is_dir():
            problems.append(f"missing directory: {rel}")
            continue
        actual = stat.S_IMODE(path.lstat().st_mode)
        if actual != mode:
            problems.append(f"dir mode {oct(actual)} != {oct(mode)}: {rel}")
    for rel in value["empty_directories"]:
        path = root / rel
        if not path.is_dir():
            problems.append(f"missing empty directory: {rel}")
        elif any(path.iterdir()):
            problems.append(f"declared-empty directory is not empty: {rel}")
    actual_root = stat.S_IMODE(root.lstat().st_mode)
    if actual_root != value["root_mode"]:
        problems.append(f"root mode {oct(actual_root)} != {oct(value['root_mode'])}")

    if problems:
        print(f"MISMATCH {root} ({len(problems)} problem(s))")
        for line in problems[:20]:
            print(f"  {line}")
        return 1
    print(f"OK {root} digest={value['digest'][:16]}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("seal", "materialize", "verify"))
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args(argv[1:])
    handler = {"seal": op_seal, "materialize": op_materialize, "verify": op_verify}[
        args.operation
    ]
    status = 0
    for root in args.roots:
        status |= handler(root)
    return status


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main(sys.argv))
