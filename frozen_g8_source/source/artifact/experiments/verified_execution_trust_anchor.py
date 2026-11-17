#!/usr/bin/env python3
"""Independent, hard-coded verifier for the verified execution trust anchor.

This post-run verifier deliberately does not import the loader builder, the
bootstrap, or any Sluice module.  Its constants bind the reviewed literal
``python -c`` bytes and the exact authenticated project closure at HEAD
19a3810.  The stdlib interpreter and this verifier remain explicit TCB.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


EXPECTED_SOURCE_COMMIT = "19a381085675f957eab5f877dac0e734656e1949"
EXPECTED_BOOTSTRAP_SHA256 = "0e3948c3f6a7a7979f67f37479a970e22a4425912356f6e3f6989e554f235bb0"
EXPECTED_INLINE_LOADER_SHA256 = "6f395735aff438816323cf8eb1365a0ce2b6d880f28c09c9a2cbf649a616100f"
EXPECTED_INLINE_LOADER_BYTES = 4128
EXPECTED_MODULES = {
    "sluice_v2.rocky_gpu_isolation": (
        "sluice_v2/rocky_gpu_isolation.py",
        "77afdfcef30fd5df4ae97c5d1a16ce9411468cdc719af56679a810e24cb0266b",
    ),
    "sluice_v2.runtime_staging": (
        "sluice_v2/runtime_staging.py",
        "fde69df7afb04a75fad01e5cabfd984733f6de24aa935c0b499e91d2a4a36cfd",
    ),
    "experiments.stage_authenticated_runtime": (
        "experiments/stage_authenticated_runtime.py",
        "860923dca956da9338bf29f06e4d3b1f0d4d8167cb1c05646d4eb3606773ef95",
    ),
    "experiments.diagnose_rocky_cuda_isolation": (
        "experiments/diagnose_rocky_cuda_isolation.py",
        "a657d7d7e38f266611fd4e34a2c5f0ac222781b17ea12b2e606f5d8a1565f441",
    ),
}
ENTRY_CLOSURES = {
    "experiments.stage_authenticated_runtime": (
        "sluice_v2.rocky_gpu_isolation",
        "sluice_v2.runtime_staging",
        "experiments.stage_authenticated_runtime",
    ),
    "experiments.diagnose_rocky_cuda_isolation": (
        "sluice_v2.rocky_gpu_isolation",
        "sluice_v2.runtime_staging",
        "experiments.stage_authenticated_runtime",
        "experiments.diagnose_rocky_cuda_isolation",
    ),
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[a-z0-9][a-z0-9_-]{7,127}\Z")
_RECORD_KEYS = frozenset(
    {
        "bootstrap",
        "closure",
        "closure_manifest",
        "inline_loader_sha256",
        "interpreter",
        "pycache",
        "run_id",
        "source_commit",
    }
)
_FILE_KEYS = frozenset({"device", "gid", "inode", "mode", "nlink", "size", "uid"})
_DIRECTORY_KEYS = frozenset({"device", "gid", "inode", "mode", "uid"})
_PROCFS_MOUNT_KEYS = frozenset(
    {
        "filesystem",
        "mount_id",
        "mount_options",
        "mountpoint",
        "root",
        "source",
        "super_options",
    }
)


class TrustAnchorError(RuntimeError):
    """The independently frozen execution contract failed closed."""


def _exact_json_equal(observed: object, expected: object) -> bool:
    """Compare JSON-shaped values without Python's bool/numeric aliases."""

    if type(observed) is not type(expected):
        return False
    if type(expected) is dict:
        return set(observed) == set(expected) and all(
            _exact_json_equal(observed[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(observed) == len(expected) and all(
            _exact_json_equal(left, right)
            for left, right in zip(observed, expected, strict=True)
        )
    if type(expected) not in (str, int, float, bool, type(None)):
        return False
    return observed == expected


def _canonical_absolute(value: object, name: str) -> Path:
    if type(value) is not str:
        raise TrustAnchorError(f"{name} is not an absolute path string")
    path = Path(value)
    if (
        not path.is_absolute()
        or value.startswith("//")
        or ".." in path.parts
        or "\x00" in value
        or os.fspath(path) != value
    ):
        raise TrustAnchorError(f"{name} is not a canonical absolute path")
    return path


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    return flags | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)


def _file_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    return flags | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)


def _directory_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISDIR(status.st_mode):
        raise TrustAnchorError("trust-anchor path component is not a directory")
    return (
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
    )


def _open_file(path: Path) -> tuple[int, tuple[tuple[int, int, int, int, int], ...]]:
    descriptor = os.open("/", _directory_flags())
    binding = [_directory_identity(os.fstat(descriptor))]
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            binding.append(_directory_identity(os.fstat(child)))
            os.close(descriptor)
            descriptor = child
        leaf = os.open(path.name, _file_flags(), dir_fd=descriptor)
    finally:
        os.close(descriptor)
    return leaf, tuple(binding)


def _read_bound(path: Path) -> tuple[bytes, str]:
    descriptor, binding = _open_file(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TrustAnchorError("trust-anchor file is not single-link regular")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            chunks.append(block)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if len(payload) != before.st_size or identity != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise TrustAnchorError("trust-anchor file changed during same-FD read")
        rebound, rebound_binding = _open_file(path)
        try:
            rebound_status = os.fstat(rebound)
            if rebound_binding != binding or (rebound_status.st_dev, rebound_status.st_ino) != (before.st_dev, before.st_ino):
                raise TrustAnchorError("trust-anchor path identity changed")
        finally:
            os.close(rebound)
        return payload, hashlib.sha256(payload).hexdigest()
    finally:
        os.close(descriptor)


def _identity(value: object, keys: frozenset[str], name: str) -> None:
    if type(value) is not dict or set(value) != keys:
        raise TrustAnchorError(f"{name} identity schema is invalid")
    for key in keys:
        if type(value[key]) is not int or value[key] < 0:
            raise TrustAnchorError(f"{name} identity value is invalid")
    if value["inode"] == 0 or value["mode"] > 0o7777:
        raise TrustAnchorError(f"{name} identity is outside its range")
    if "nlink" in keys and value["nlink"] != 1:
        raise TrustAnchorError(f"{name} is not single-link")


def _procfs_mount(value: object) -> None:
    if type(value) is not dict or set(value) != _PROCFS_MOUNT_KEYS:
        raise TrustAnchorError("interpreter procfs mount schema is invalid")
    if (
        value["filesystem"] != "proc"
        or value["mountpoint"] != "/proc"
        or value["root"] != "/"
        or value["source"] != "proc"
        or type(value["mount_id"]) is not int
        or value["mount_id"] <= 0
    ):
        raise TrustAnchorError("interpreter procfs mount identity is invalid")
    for key in ("mount_options", "super_options"):
        options = value[key]
        if (
            type(options) is not list
            or any(type(option) is not str or not option for option in options)
            or options != sorted(set(options))
        ):
            raise TrustAnchorError("interpreter procfs mount options are invalid")


def verify_frozen_anchor(artifact_root: Path) -> dict[str, object]:
    root = _canonical_absolute(os.fspath(Path(artifact_root)), "artifact root")
    bootstrap = root / "experiments" / "verified_execution_bootstrap.py"
    loader = root / "experiments" / "verified_inline_loader_v1.txt"
    bootstrap_bytes, bootstrap_sha256 = _read_bound(bootstrap)
    loader_bytes, loader_sha256 = _read_bound(loader)
    if (
        bootstrap_sha256 != EXPECTED_BOOTSTRAP_SHA256
        or loader_sha256 != EXPECTED_INLINE_LOADER_SHA256
        or len(loader_bytes) != EXPECTED_INLINE_LOADER_BYTES
        or not bootstrap_bytes
    ):
        raise TrustAnchorError("reviewed bootstrap/inline-loader bytes differ")
    for relative, expected_sha256 in EXPECTED_MODULES.values():
        _payload, observed = _read_bound(root / relative)
        if observed != expected_sha256:
            raise TrustAnchorError(f"reviewed closure source differs: {relative}")
    return {
        "bootstrap_sha256": bootstrap_sha256,
        "inline_loader_bytes": len(loader_bytes),
        "inline_loader_sha256": loader_sha256,
        "source_commit": EXPECTED_SOURCE_COMMIT,
    }


def verify_execution_record(
    value: object,
    *,
    artifact_root: Path,
    entry_module: str,
    run_id: str,
) -> dict[str, object]:
    verify_frozen_anchor(artifact_root)
    if entry_module not in ENTRY_CLOSURES or _RUN_ID.fullmatch(run_id) is None:
        raise TrustAnchorError("requested entry/run binding is invalid")
    if type(value) is not dict or set(value) != {"end", "equal", "start"}:
        raise TrustAnchorError("verified execution envelope schema is invalid")
    if value["equal"] is not True or not _exact_json_equal(
        value["start"], value["end"]
    ):
        raise TrustAnchorError("verified execution start/end drifted")
    record = value["start"]
    if type(record) is not dict or set(record) != _RECORD_KEYS:
        raise TrustAnchorError("verified execution record schema is invalid")
    if (
        record["source_commit"] != EXPECTED_SOURCE_COMMIT
        or record["run_id"] != run_id
        or record["inline_loader_sha256"] != EXPECTED_INLINE_LOADER_SHA256
    ):
        raise TrustAnchorError("verified execution trust-anchor binding differs")
    root = Path(artifact_root)
    bootstrap = record["bootstrap"]
    if type(bootstrap) is not dict or set(bootstrap) != {"identity", "path", "sha256"}:
        raise TrustAnchorError("verified bootstrap record schema is invalid")
    _identity(bootstrap["identity"], _FILE_KEYS, "bootstrap")
    if (
        _canonical_absolute(bootstrap["path"], "bootstrap")
        != root / "experiments" / "verified_execution_bootstrap.py"
        or bootstrap["sha256"] != EXPECTED_BOOTSTRAP_SHA256
    ):
        raise TrustAnchorError("verified bootstrap record differs")
    closure = record["closure"]
    expected_names = ENTRY_CLOSURES[entry_module]
    if type(closure) is not list or len(closure) != len(expected_names):
        raise TrustAnchorError("verified closure size differs")
    for item, module in zip(closure, expected_names, strict=True):
        if type(item) is not dict or set(item) != {"identity", "module", "path", "sha256"}:
            raise TrustAnchorError("verified closure item schema is invalid")
        _identity(item["identity"], _FILE_KEYS, f"closure {module}")
        relative, expected_sha256 = EXPECTED_MODULES[module]
        if (
            item["module"] != module
            or _canonical_absolute(item["path"], f"closure {module}") != root / relative
            or item["sha256"] != expected_sha256
        ):
            raise TrustAnchorError(f"verified closure binding differs: {module}")
    for key in ("closure_manifest",):
        item = record[key]
        if type(item) is not dict or set(item) != {"identity", "path", "sha256"}:
            raise TrustAnchorError(f"verified {key} record schema is invalid")
        _identity(item["identity"], _FILE_KEYS, key)
        _canonical_absolute(item["path"], key)
        if type(item["sha256"]) is not str or _SHA256.fullmatch(item["sha256"]) is None:
            raise TrustAnchorError(f"verified {key} digest is invalid")
    interpreter = record["interpreter"]
    if type(interpreter) is not dict or set(interpreter) != {
        "identity",
        "path",
        "procfs_mount",
        "sha256",
    }:
        raise TrustAnchorError("verified interpreter record schema is invalid")
    _identity(interpreter["identity"], _FILE_KEYS, "interpreter")
    _canonical_absolute(interpreter["path"], "interpreter")
    if (
        type(interpreter["sha256"]) is not str
        or _SHA256.fullmatch(interpreter["sha256"]) is None
    ):
        raise TrustAnchorError("verified interpreter digest is invalid")
    _procfs_mount(interpreter["procfs_mount"])
    pycache = record["pycache"]
    if type(pycache) is not dict or set(pycache) != {"empty", "identity", "path"} or pycache["empty"] is not True:
        raise TrustAnchorError("verified pycache record schema is invalid")
    _identity(pycache["identity"], _DIRECTORY_KEYS, "pycache")
    pycache_path = _canonical_absolute(pycache["path"], "pycache")
    if pycache_path == root or root in pycache_path.parents or pycache_path in root.parents:
        raise TrustAnchorError("verified pycache is not external to the artifact")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--entry-module", required=True, choices=tuple(ENTRY_CLOSURES))
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    arguments = parser.parse_args()
    payload, _digest = _read_bound(_canonical_absolute(os.fspath(arguments.record), "record"))
    try:
        container = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustAnchorError("post-run record is not ASCII JSON") from exc
    canonical = (json.dumps(container, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    if canonical != payload or type(container) is not dict or "verified_execution" not in container:
        raise TrustAnchorError("post-run record is not canonical verified evidence")
    verified = verify_execution_record(
        container["verified_execution"],
        artifact_root=arguments.artifact_root,
        entry_module=arguments.entry_module,
        run_id=arguments.run_id,
    )
    print(json.dumps({"entry_module": arguments.entry_module, "run_id": arguments.run_id, "status": "verified", "verified_execution_sha256": hashlib.sha256((json.dumps(verified, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")).hexdigest()}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
