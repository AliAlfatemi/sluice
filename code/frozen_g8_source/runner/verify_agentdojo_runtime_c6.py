#!/usr/bin/env python3
"""Authenticate C6's minimal official AgentDojo v0.1.35 runtime closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct


RUNTIME_RELATIVE = "external/agentdojo-v0.1.35"
MANIFEST_NAME = "AGENTDOJO_RUNTIME_SHA256SUMS"
EXPECTED_FILE_COUNT = 115
EXPECTED_DIRECTORY_COUNT_BELOW_ROOT = 41
EXPECTED_PYTHON_FILE_COUNT = 99
EXPECTED_PYTHON_TREE_SHA256 = "1d277192874c252ca21ece753b4ab10217958a1f41511b1f7175e919d9c01114"
EXPECTED_LOADED_ASSET_FILE_COUNT = 112
EXPECTED_LOADED_ASSET_TREE_SHA256 = "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
EXPECTED_OPENAI_LLM_SHA256 = "7f91178cb0bb354b89427650d7b8725d6aff8fe18d43fc85bf4b4fdc1ddf9574"
KEY_FILES = {
    "LICENSE": "4285a071f2d382338e52b4fb0a186d952984a34d43a33d8872e1a1d8cb43401e",
    "pyproject.toml": "f69dde819258d5dc2c6dca13ecbb116e54904374879a5c921332db36474e0a3b",
    "uv.lock": "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330",
}
PROVENANCE = {
    "manifests/AGENTDOJO_SOURCE.json": "fef6394ff1236e09351fd4930ac185b2265ad48e54de82f59209bb6c5664abe6",
    "runs/acquisition/agentdojo_v0.1.35/upstream_checkout_file_sha256.txt": "6bc6d63cfa362d1fb7efdb46ff7b011b8d2960d49b3ae43fee5ae70305abfba3",
    "runs/acquisition/agentdojo_v0.1.35/SHA256SUMS": "98c226d276ac0a759703292e7b411ae70e22c9b772845196af8171bb95db32d1",
}
LOADED_SUFFIXES = {".py", ".yaml", ".yml", ".txt"}
HEX64 = re.compile(r"[0-9a-f]{64}")


def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def stable_read(path: Path, label: str) -> tuple[bytes, tuple[int, int, int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SystemExit(f"cannot securely open {label}: {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SystemExit(f"not a regular file {label}: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if identity(opened) != identity(after_read) or len(raw) != opened.st_size:
        raise SystemExit(f"{label} changed or was short-read: {path}")
    try:
        after_close = path.lstat()
    except OSError as exc:
        raise SystemExit(f"{label} disappeared after read: {path}: {exc}") from exc
    if identity(after_close) != identity(opened) or stat.S_ISLNK(after_close.st_mode):
        raise SystemExit(f"{label} raced during read: {path}")
    return raw, identity(opened)


def digest(path: Path, label: str = "input") -> str:
    return hashlib.sha256(stable_read(path, label)[0]).hexdigest()


def regular(path: Path, label: str) -> Path:
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise SystemExit(f"not a regular non-symlink {label}: {path}")
    return path


def parse_manifest(run_root: Path) -> tuple[dict[str, str], bytes]:
    path = regular(run_root / MANIFEST_NAME, "runtime manifest")
    rows: dict[str, str] = {}
    raw, _identity = stable_read(path, "runtime manifest")
    try:
        payload = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("AgentDojo runtime manifest is not ASCII") from exc
    if not payload.endswith("\n"):
        raise SystemExit("partial AgentDojo runtime manifest")
    for line in payload.splitlines():
        fields = line.split("  ", 1)
        if len(fields) != 2 or HEX64.fullmatch(fields[0]) is None:
            raise SystemExit("malformed AgentDojo runtime manifest row")
        name = fields[1]
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != name or name in rows:
            raise SystemExit(f"unsafe or duplicate AgentDojo runtime path: {name!r}")
        rows[name] = fields[0]
    if list(rows) != sorted(rows) or len(rows) != EXPECTED_FILE_COUNT:
        raise SystemExit("AgentDojo runtime manifest count/order mismatch")
    return rows, raw


def canonical_tree(paths: list[Path], source_root: Path, blobs: dict[Path, bytes]) -> str:
    value = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(source_root).as_posix().encode("utf-8")
        content = blobs[path]
        value.update(struct.pack(">Q", len(relative)))
        value.update(relative)
        value.update(struct.pack(">Q", len(content)))
        value.update(content)
    return value.hexdigest()


def parse_official_full_manifest(raw: bytes) -> dict[str, str]:
    prefix = "/external/agentdojo-v0.1.35/"
    result: dict[str, str] = {}
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("official AgentDojo full-tree manifest is not ASCII") from exc
    for line in text.splitlines():
        fields = line.split("  ", 1)
        if len(fields) != 2 or HEX64.fullmatch(fields[0]) is None:
            raise SystemExit("malformed official AgentDojo full-tree manifest")
        absolute = fields[1]
        if prefix not in absolute:
            raise SystemExit("official AgentDojo full-tree path has wrong root")
        suffix = absolute.split(prefix, 1)[1]
        if suffix in result:
            raise SystemExit("duplicate official AgentDojo full-tree path")
        result[suffix] = fields[0]
    if len(result) != 36860:
        raise SystemExit("official AgentDojo full-tree manifest count mismatch")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--repo", type=Path)
    args = parser.parse_args()
    run_root = args.run_root.resolve()
    repo = args.repo.resolve() if args.repo else run_root.parents[1]
    runtime = repo / RUNTIME_RELATIVE
    runtime_info = runtime.lstat()
    if stat.S_ISLNK(runtime_info.st_mode) or not stat.S_ISDIR(runtime_info.st_mode):
        raise SystemExit("AgentDojo runtime root is missing or a symlink")
    source_root = runtime / "src/agentdojo"
    source_info = source_root.lstat()
    if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISDIR(source_info.st_mode):
        raise SystemExit("AgentDojo source root is missing or a symlink")

    files: list[Path] = []
    directories: list[Path] = []
    file_blobs: dict[Path, bytes] = {}
    entry_identities: dict[str, tuple[int, int, int, int, int, int]] = {}
    for path in sorted(runtime.rglob("*"), key=lambda item: item.relative_to(runtime).as_posix()):
        info = path.lstat()
        mode = info.st_mode
        relative_runtime = path.relative_to(runtime).as_posix()
        if stat.S_ISLNK(mode):
            raise SystemExit(f"symlink in AgentDojo runtime closure: {path}")
        if stat.S_ISDIR(mode):
            if path.name == "__pycache__":
                raise SystemExit("__pycache__ in AgentDojo runtime closure")
            directories.append(path)
            entry_identities[relative_runtime] = identity(info)
        elif stat.S_ISREG(mode):
            if path.suffix in {".pyc", ".pyo"}:
                raise SystemExit("bytecode in AgentDojo runtime closure")
            raw, opened_identity = stable_read(path, "AgentDojo runtime input")
            if opened_identity != identity(info):
                raise SystemExit(f"AgentDojo runtime entry raced before read: {path}")
            files.append(path)
            file_blobs[path] = raw
            entry_identities[relative_runtime] = opened_identity
        else:
            raise SystemExit(f"special file in AgentDojo runtime closure: {path}")
    if len(files) != EXPECTED_FILE_COUNT or len(directories) != EXPECTED_DIRECTORY_COUNT_BELOW_ROOT:
        raise SystemExit("AgentDojo runtime closure inventory mismatch")
    expected_top = {"LICENSE", "pyproject.toml", "uv.lock", "src"}
    if {PurePosixPath(name).parts[0] for name in entry_identities} != expected_top:
        raise SystemExit("AgentDojo runtime closure has an unexpected top-level entry")

    rows, runtime_manifest_raw = parse_manifest(run_root)
    actual_names = {path.relative_to(repo).as_posix() for path in files}
    if set(rows) != actual_names:
        raise SystemExit("AgentDojo runtime manifest path coverage mismatch")
    for name, expected in rows.items():
        if hashlib.sha256(file_blobs[repo / name]).hexdigest() != expected:
            raise SystemExit(f"AgentDojo runtime digest mismatch: {name}")

    source_files = sorted(
        (path for path in files if source_root in path.parents),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    if any(path.suffix not in LOADED_SUFFIXES for path in source_files):
        raise SystemExit("unauthenticated file type in AgentDojo source closure")
    python_files = [path for path in source_files if path.suffix == ".py"]
    if len(python_files) != EXPECTED_PYTHON_FILE_COUNT or canonical_tree(python_files, source_root, file_blobs) != EXPECTED_PYTHON_TREE_SHA256:
        raise SystemExit("AgentDojo Python-tree identity mismatch")
    if len(source_files) != EXPECTED_LOADED_ASSET_FILE_COUNT or canonical_tree(source_files, source_root, file_blobs) != EXPECTED_LOADED_ASSET_TREE_SHA256:
        raise SystemExit("AgentDojo loaded-asset identity mismatch")
    for name, expected in KEY_FILES.items():
        if hashlib.sha256(file_blobs[runtime / name]).hexdigest() != expected:
            raise SystemExit(f"AgentDojo key-file identity mismatch: {name}")
    openai = runtime / "src/agentdojo/agent_pipeline/llms/openai_llm.py"
    if hashlib.sha256(file_blobs[openai]).hexdigest() != EXPECTED_OPENAI_LLM_SHA256:
        raise SystemExit("AgentDojo provider-source identity mismatch")

    provenance_blobs: dict[str, bytes] = {}
    for name, expected in PROVENANCE.items():
        raw, _input_identity = stable_read(repo / name, "AgentDojo provenance input")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise SystemExit(f"AgentDojo provenance digest mismatch: {name}")
        provenance_blobs[name] = raw
    full = parse_official_full_manifest(
        provenance_blobs[
            "runs/acquisition/agentdojo_v0.1.35/upstream_checkout_file_sha256.txt"
        ]
    )
    for name, expected in rows.items():
        suffix = name.removeprefix(RUNTIME_RELATIVE + "/")
        if full.get(suffix) != expected:
            raise SystemExit(f"runtime file is not byte-identical to official source: {suffix}")

    try:
        source_record = json.loads(
            provenance_blobs["manifests/AGENTDOJO_SOURCE.json"].decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("invalid AgentDojo source provenance JSON") from exc
    release = source_record.get("official_release", {})
    checkout = source_record.get("clean_checkout", {})
    if (
        source_record.get("benchmark", {}).get("version") != "0.1.35"
        or release.get("commit_sha1") != "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
        or release.get("git_tree_sha1") != "3c74b60f2bad4ff321d864e0c0483f256cc8f8d2"
        or checkout.get("python_source_tree_sha256") != EXPECTED_PYTHON_TREE_SHA256
    ):
        raise SystemExit("AgentDojo official acquisition identity mismatch")

    # Re-enumerate the closure and re-read every file.  Any swap, extra entry,
    # or content change between authentication and return is fail-closed.
    final_identities: dict[str, tuple[int, int, int, int, int, int]] = {}
    for path in sorted(runtime.rglob("*"), key=lambda item: item.relative_to(runtime).as_posix()):
        info = path.lstat()
        relative_runtime = path.relative_to(runtime).as_posix()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise SystemExit("AgentDojo runtime closure changed type during verification")
        final_identities[relative_runtime] = identity(info)
        if stat.S_ISREG(info.st_mode):
            final_raw, final_identity = stable_read(path, "final AgentDojo runtime input")
            if final_identity != identity(info) or final_raw != file_blobs.get(path):
                raise SystemExit(f"AgentDojo runtime content changed during verification: {path}")
    if final_identities != entry_identities:
        raise SystemExit("AgentDojo runtime inventory changed during verification")
    if identity(runtime.lstat()) != identity(runtime_info) or identity(source_root.lstat()) != identity(source_info):
        raise SystemExit("AgentDojo runtime root changed during verification")
    for name, raw in provenance_blobs.items():
        if stable_read(repo / name, "final AgentDojo provenance input")[0] != raw:
            raise SystemExit(f"AgentDojo provenance changed during verification: {name}")
    if stable_read(run_root / MANIFEST_NAME, "final runtime manifest")[0] != runtime_manifest_raw:
        raise SystemExit("AgentDojo runtime manifest changed during verification")

    result = {
        "directory_count_below_root": len(directories),
        "file_count": len(files),
        "loaded_asset_file_count": len(source_files),
        "loaded_asset_tree_sha256": EXPECTED_LOADED_ASSET_TREE_SHA256,
        "manifest_sha256": hashlib.sha256(runtime_manifest_raw).hexdigest(),
        "official_commit": release["commit_sha1"],
        "official_git_tree": release["git_tree_sha1"],
        "python_file_count": len(python_files),
        "python_tree_sha256": EXPECTED_PYTHON_TREE_SHA256,
        "schema": "sluice_agentdojo_c6_runtime_verification/1",
        "status": "PASS",
        "version": "0.1.35",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
