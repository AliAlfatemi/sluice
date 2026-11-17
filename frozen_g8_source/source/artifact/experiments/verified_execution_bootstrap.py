#!/usr/bin/env python3
"""Stdlib-only loader for an externally authenticated project closure.

This file must only be executed from the frozen inline ``python -c`` loader.
That loader reads these bytes from a pinned descriptor, checks the externally
frozen SHA-256, and injects ``VERIFIED_INLINE_LOADER`` before ``exec``.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types
from typing import Callable


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_RUN_ID = re.compile(r"[a-z0-9][a-z0-9_-]{7,127}\Z")
_MODULE = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+\Z")
_INLINE_KEYS = frozenset(
    {
        "bootstrap_binding",
        "bootstrap_fd",
        "bootstrap_path",
        "bootstrap_sha256",
        "closure_manifest_path",
        "closure_manifest_sha256",
        "inline_loader_sha256",
        "pycache_binding",
        "pycache_fd",
        "pycache_identity",
        "run_id",
        "source_commit",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "artifact_root",
        "entry_module",
        "inline_loader_sha256",
        "modules",
        "run_id",
        "schema_version",
        "source_commit",
    }
)
_MODULE_KEYS = frozenset({"module", "path", "sha256"})
_ENTRY_CLOSURES = {
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
_PROC_SELF_EXE = "/proc/self/exe"


class VerifiedBootstrapError(RuntimeError):
    """The pre-import authenticated execution boundary failed closed."""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _directory_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISDIR(status.st_mode):
        raise VerifiedBootstrapError("verified path component is not a directory")
    return (
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
    )


def _file_identity(status: os.stat_result) -> dict[str, int]:
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise VerifiedBootstrapError("verified source is not a single-link regular file")
    return {
        "device": status.st_dev,
        "gid": status.st_gid,
        "inode": status.st_ino,
        "mode": stat.S_IMODE(status.st_mode),
        "nlink": status.st_nlink,
        "size": status.st_size,
        "uid": status.st_uid,
    }


def _canonical_absolute(path: object, name: str) -> Path:
    if type(path) is not str:
        raise VerifiedBootstrapError(f"{name} must be an absolute path string")
    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or os.fspath(candidate) != path
        or "\x00" in path
    ):
        raise VerifiedBootstrapError(f"{name} must be a canonical absolute path")
    return candidate


def _open_chain_file(
    path: Path, name: str
) -> tuple[int, tuple[tuple[int, int, int, int, int], ...]]:
    candidate = _canonical_absolute(os.fspath(path), name)
    descriptor = os.open("/", _directory_flags())
    binding = [_directory_identity(os.fstat(descriptor))]
    try:
        for component in candidate.parts[1:-1]:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            binding.append(_directory_identity(os.fstat(child)))
            os.close(descriptor)
            descriptor = child
        leaf = candidate.name
        if not leaf or leaf in {".", ".."} or "/" in leaf:
            raise VerifiedBootstrapError(f"{name} must name a regular file")
        file_descriptor = os.open(leaf, _file_flags(), dir_fd=descriptor)
    finally:
        os.close(descriptor)
    _file_identity(os.fstat(file_descriptor))
    return file_descriptor, tuple(binding)


def _open_chain_directory(
    path: Path, name: str
) -> tuple[int, tuple[tuple[int, int, int, int, int], ...]]:
    candidate = _canonical_absolute(os.fspath(path), name)
    descriptor = os.open("/", _directory_flags())
    binding = [_directory_identity(os.fstat(descriptor))]
    try:
        for component in candidate.parts[1:]:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            binding.append(_directory_identity(os.fstat(child)))
            os.close(descriptor)
            descriptor = child
        return descriptor, tuple(binding)
    except BaseException:
        os.close(descriptor)
        raise


def _rebound_chain(
    path: Path,
    binding: tuple[tuple[int, int, int, int, int], ...],
    identity: dict[str, int],
    name: str,
) -> None:
    descriptor, observed = _open_chain_file(path, name)
    try:
        if observed != binding or _file_identity(os.fstat(descriptor)) != identity:
            raise VerifiedBootstrapError(f"{name} path identity changed")
    finally:
        os.close(descriptor)


def _rebound_directory_chain(
    path: Path,
    binding: tuple[tuple[int, int, int, int, int], ...],
    identity: tuple[int, int, int, int, int],
    name: str,
) -> None:
    descriptor, observed = _open_chain_directory(path, name)
    try:
        if observed != binding or _directory_identity(os.fstat(descriptor)) != identity:
            raise VerifiedBootstrapError(f"{name} path identity changed")
    finally:
        os.close(descriptor)


def _read_stable(descriptor: int, maximum: int, name: str) -> tuple[bytes, dict[str, int]]:
    before = os.fstat(descriptor)
    identity = _file_identity(before)
    if before.st_size < 0 or before.st_size > maximum:
        raise VerifiedBootstrapError(f"{name} exceeds the verified size limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(descriptor, min(1 << 20, maximum + 1 - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > maximum:
            raise VerifiedBootstrapError(f"{name} exceeds the verified size limit")
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    if len(payload) != before.st_size or _file_identity(after) != identity:
        raise VerifiedBootstrapError(f"{name} changed during same-FD read")
    return payload, identity


def _hash_regular_descriptor(descriptor: int, name: str) -> tuple[str, dict[str, int]]:
    payload, identity = _read_stable(descriptor, 1 << 30, name)
    return hashlib.sha256(payload).hexdigest(), identity


def _read_proc_generated(descriptor: int, maximum: int, name: str) -> bytes:
    """Read a procfs generated file twice from one retained descriptor."""

    def metadata() -> tuple[int, int, int, int, int, int]:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise VerifiedBootstrapError(f"{name} is not a procfs regular file")
        return (
            status.st_dev,
            status.st_ino,
            status.st_uid,
            status.st_gid,
            status.st_mode,
            status.st_nlink,
        )

    def once() -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1 << 16, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise VerifiedBootstrapError(f"{name} exceeds its size limit")
        return b"".join(chunks)

    before = metadata()
    first = once()
    middle = metadata()
    second = once()
    after = metadata()
    if not first or first != second or before != middle or middle != after:
        raise VerifiedBootstrapError(f"{name} changed during same-FD read")
    return first


def _mount_unescape(value: str) -> str:
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


def _procfs_mount_identity() -> dict[str, object]:
    """Bind the exact procfs mount containing the sole magic-link exception."""

    proc_path = Path("/proc")
    proc_fd, proc_binding = _open_chain_directory(proc_path, "procfs root")
    pid_fd = -1
    mountinfo_fd = -1
    fdinfo_directory_fd = -1
    fdinfo_fd = -1
    try:
        proc_status = os.fstat(proc_fd)
        proc_identity = _directory_identity(proc_status)
        if proc_status.st_uid != 0 or stat.S_IMODE(proc_status.st_mode) != 0o555:
            raise VerifiedBootstrapError("procfs root ownership/mode is invalid")
        pid_fd = os.open(str(os.getpid()), _directory_flags(), dir_fd=proc_fd)
        _directory_identity(os.fstat(pid_fd))
        mountinfo_fd = os.open("mountinfo", _file_flags(), dir_fd=pid_fd)
        mountinfo = _read_proc_generated(
            mountinfo_fd, 4 << 20, "procfs mountinfo"
        )
        fdinfo_directory_fd = os.open("fdinfo", _directory_flags(), dir_fd=pid_fd)
        fdinfo_fd = os.open(str(proc_fd), _file_flags(), dir_fd=fdinfo_directory_fd)
        fdinfo = _read_proc_generated(fdinfo_fd, 1 << 20, "procfs fdinfo")
    finally:
        for descriptor in (
            fdinfo_fd,
            fdinfo_directory_fd,
            mountinfo_fd,
            pid_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        os.close(proc_fd)
    _rebound_directory_chain(
        proc_path,
        proc_binding,
        proc_identity,
        "procfs root",
    )
    try:
        fdinfo_lines = fdinfo.decode("ascii").splitlines()
        mountinfo_lines = mountinfo.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise VerifiedBootstrapError("procfs identity is not ASCII") from exc
    mount_ids = [
        line.split(":", 1)[1].strip()
        for line in fdinfo_lines
        if line.startswith("mnt_id:")
    ]
    if (
        len(mount_ids) != 1
        or re.fullmatch(r"[1-9][0-9]*", mount_ids[0]) is None
    ):
        raise VerifiedBootstrapError("procfs fdinfo has no exact mount ID")
    mount_id = int(mount_ids[0])
    matches: list[dict[str, object]] = []
    for line in mountinfo_lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            raise VerifiedBootstrapError("procfs mountinfo record is malformed")
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 6 or len(right_fields) < 3:
            raise VerifiedBootstrapError("procfs mountinfo record is short")
        if left_fields[0] != str(mount_id):
            continue
        matches.append(
            {
                "filesystem": right_fields[0],
                "mount_id": mount_id,
                "mount_options": sorted(left_fields[5].split(",")),
                "mountpoint": _mount_unescape(left_fields[4]),
                "root": _mount_unescape(left_fields[3]),
                "source": _mount_unescape(right_fields[1]),
                "super_options": sorted(right_fields[2].split(",")),
            }
        )
    if len(matches) != 1:
        raise VerifiedBootstrapError("procfs mount ID has no unique mountinfo record")
    identity = matches[0]
    if (
        identity["filesystem"] != "proc"
        or identity["mountpoint"] != "/proc"
        or identity["root"] != "/"
        or identity["source"] != "proc"
    ):
        raise VerifiedBootstrapError("/proc is not the exact expected procfs mount")
    return identity


def _interpreter_identity(status: os.stat_result) -> dict[str, int]:
    identity = _file_identity(status)
    if (
        status.st_uid != os.geteuid()
        or status.st_gid != os.getegid()
        or stat.S_IMODE(status.st_mode) != 0o755
        or status.st_size <= 0
    ):
        raise VerifiedBootstrapError("verified interpreter ownership/mode is invalid")
    return identity


def _interpreter_magic_link_state(
    descriptor: int,
) -> tuple[dict[str, int], str]:
    """Validate the dedicated /proc/self/exe magic-link exception."""

    identity = _interpreter_identity(os.fstat(descriptor))
    fd_magic = f"/proc/self/fd/{descriptor}"
    exe_realpath = os.path.realpath(_PROC_SELF_EXE)
    fd_realpath = os.path.realpath(fd_magic)
    if (
        not exe_realpath.startswith("/")
        or "\x00" in exe_realpath
        or exe_realpath != fd_realpath
    ):
        raise VerifiedBootstrapError("interpreter procfs realpath binding differs")
    for magic_path in (_PROC_SELF_EXE, fd_magic):
        observed = _interpreter_identity(os.stat(magic_path))
        if observed != identity:
            raise VerifiedBootstrapError("interpreter procfs inode binding differs")
    return identity, exe_realpath


def _open_verified_interpreter(
) -> tuple[int, dict[str, int], str, dict[str, object]]:
    procfs_mount = _procfs_mount_identity()
    # O_NOFOLLOW is intentionally omitted only for this literal kernel magic link.
    descriptor = os.open(_PROC_SELF_EXE, os.O_RDONLY | os.O_CLOEXEC)
    try:
        identity, realpath = _interpreter_magic_link_state(descriptor)
        return descriptor, identity, realpath, procfs_mount
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_verified_interpreter(
    descriptor: int,
    expected_identity: dict[str, int],
    expected_realpath: str,
    expected_procfs_mount: dict[str, object],
) -> None:
    if _procfs_mount_identity() != expected_procfs_mount:
        raise VerifiedBootstrapError("interpreter procfs mount identity drifted")
    observed_identity, observed_realpath = _interpreter_magic_link_state(descriptor)
    if (
        observed_identity != expected_identity
        or observed_realpath != expected_realpath
    ):
        raise VerifiedBootstrapError("verified interpreter path identity drifted")


def _validate_inline_context(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _INLINE_KEYS:
        raise VerifiedBootstrapError("inline-loader context schema is invalid")
    for key in (
        "bootstrap_sha256",
        "closure_manifest_sha256",
        "inline_loader_sha256",
    ):
        if type(value[key]) is not str or _SHA256.fullmatch(value[key]) is None:
            raise VerifiedBootstrapError(f"inline-loader {key} is invalid")
    if type(value["source_commit"]) is not str or _COMMIT.fullmatch(value["source_commit"]) is None:
        raise VerifiedBootstrapError("inline-loader source_commit is invalid")
    if type(value["run_id"]) is not str or _RUN_ID.fullmatch(value["run_id"]) is None:
        raise VerifiedBootstrapError("inline-loader run_id is invalid")
    if type(value["bootstrap_fd"]) is not int or value["bootstrap_fd"] < 3:
        raise VerifiedBootstrapError("inline-loader bootstrap descriptor is invalid")
    if type(value["pycache_fd"]) is not int or value["pycache_fd"] < 3:
        raise VerifiedBootstrapError("inline-loader pycache descriptor is invalid")
    _canonical_absolute(value["bootstrap_path"], "bootstrap path")
    _canonical_absolute(value["closure_manifest_path"], "closure manifest path")
    if type(value["bootstrap_binding"]) is not list:
        raise VerifiedBootstrapError("inline-loader bootstrap binding is invalid")
    if type(value["pycache_binding"]) is not list:
        raise VerifiedBootstrapError("inline-loader pycache binding is invalid")
    if type(value["pycache_identity"]) is not list:
        raise VerifiedBootstrapError("inline-loader pycache identity is invalid")
    return value


def _pycache_identity(
    artifact_root: Path, inline: dict[str, object]
) -> tuple[
    Path,
    int,
    dict[str, int],
    tuple[tuple[int, int, int, int, int], ...],
]:
    if sys.dont_write_bytecode is not True:
        raise VerifiedBootstrapError("verified execution requires Python -B")
    prefix_text = sys.pycache_prefix
    prefix = _canonical_absolute(prefix_text, "Python pycache prefix")
    if prefix == artifact_root or artifact_root in prefix.parents or prefix in artifact_root.parents:
        raise VerifiedBootstrapError("Python pycache prefix must be external to the artifact")
    descriptor = inline["pycache_fd"]
    injected_binding = tuple(tuple(item) for item in inline["pycache_binding"])
    injected_identity = tuple(inline["pycache_identity"])
    status = os.fstat(descriptor)
    if (
        _directory_identity(status) != injected_identity
        or not injected_binding
        or injected_binding[-1] != injected_identity
    ):
        raise VerifiedBootstrapError("Python pycache descriptor identity changed")
    _rebound_directory_chain(
        prefix, injected_binding, injected_identity, "Python pycache prefix"
    )
    if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) != 0o700:
        raise VerifiedBootstrapError("Python pycache prefix must be private and owned")
    if os.listdir(descriptor):
        raise VerifiedBootstrapError("Python pycache prefix must start empty")
    identity = {
        "device": status.st_dev,
        "gid": status.st_gid,
        "inode": status.st_ino,
        "mode": stat.S_IMODE(status.st_mode),
        "uid": status.st_uid,
    }
    return prefix, descriptor, identity, injected_binding


def _install_package(name: str) -> None:
    if name in sys.modules:
        existing = sys.modules[name]
        if getattr(existing, "__verified_sluice_package__", False) is not True:
            raise VerifiedBootstrapError("project package was imported before verification")
        return
    package = types.ModuleType(name)
    package.__package__ = name
    package.__path__ = []
    package.__verified_sluice_package__ = True
    sys.modules[name] = package


def main() -> int:
    inline = _validate_inline_context(globals().get("VERIFIED_INLINE_LOADER"))
    entry_argv = globals().get("VERIFIED_ENTRY_ARGV")
    if type(entry_argv) is not list or any(type(value) is not str for value in entry_argv):
        raise VerifiedBootstrapError("verified entry argv schema is invalid")
    bootstrap_path = _canonical_absolute(inline["bootstrap_path"], "bootstrap path")
    bootstrap_fd = inline["bootstrap_fd"]
    bootstrap_bytes, bootstrap_identity = _read_stable(
        bootstrap_fd, 4 << 20, "verified bootstrap"
    )
    if hashlib.sha256(bootstrap_bytes).hexdigest() != inline["bootstrap_sha256"]:
        raise VerifiedBootstrapError("verified bootstrap digest mismatch")
    injected_binding = tuple(tuple(item) for item in inline["bootstrap_binding"])
    _rebound_chain(
        bootstrap_path,
        injected_binding,
        bootstrap_identity,
        "verified bootstrap",
    )

    manifest_path = _canonical_absolute(
        inline["closure_manifest_path"], "closure manifest path"
    )
    manifest_fd, manifest_binding = _open_chain_file(
        manifest_path, "closure manifest"
    )
    retained: list[int] = [manifest_fd]
    try:
        manifest_bytes, manifest_identity = _read_stable(
            manifest_fd, 1 << 20, "closure manifest"
        )
        if hashlib.sha256(manifest_bytes).hexdigest() != inline["closure_manifest_sha256"]:
            raise VerifiedBootstrapError("closure manifest digest mismatch")
        try:
            manifest = json.loads(manifest_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerifiedBootstrapError("closure manifest is not ASCII JSON") from exc
        if manifest_bytes != _canonical_json(manifest):
            raise VerifiedBootstrapError("closure manifest is not canonical JSON")
        if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
            raise VerifiedBootstrapError("closure manifest schema is invalid")
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["source_commit"] != inline["source_commit"]
            or manifest["run_id"] != inline["run_id"]
            or manifest["inline_loader_sha256"] != inline["inline_loader_sha256"]
        ):
            raise VerifiedBootstrapError("closure manifest invocation binding is invalid")
        artifact_root = _canonical_absolute(manifest["artifact_root"], "artifact root")
        entry_module = manifest["entry_module"]
        if type(entry_module) is not str or entry_module not in _ENTRY_CLOSURES:
            raise VerifiedBootstrapError("closure entry module is invalid")
        modules = manifest["modules"]
        if type(modules) is not list or len(modules) != len(_ENTRY_CLOSURES[entry_module]):
            raise VerifiedBootstrapError("closure module list is invalid")

        (
            pycache_prefix,
            pycache_fd,
            pycache_identity,
            pycache_binding,
        ) = _pycache_identity(artifact_root, inline)
        (
            interpreter_fd,
            interpreter_identity,
            interpreter_realpath,
            interpreter_procfs_mount,
        ) = _open_verified_interpreter()
        retained.append(interpreter_fd)
        interpreter_sha256, hashed_interpreter_identity = _hash_regular_descriptor(
            interpreter_fd, "verified interpreter"
        )
        if hashed_interpreter_identity != interpreter_identity:
            raise VerifiedBootstrapError("verified interpreter changed before hashing")
        _revalidate_verified_interpreter(
            interpreter_fd,
            interpreter_identity,
            interpreter_realpath,
            interpreter_procfs_mount,
        )
        closure: list[dict[str, object]] = []
        sources: list[tuple[str, Path, int, bytes, tuple[tuple[int, int, int, int, int], ...], dict[str, int]]] = []
        seen: set[str] = set()
        for index, item in enumerate(modules):
            if type(item) is not dict or set(item) != _MODULE_KEYS:
                raise VerifiedBootstrapError("closure module record schema is invalid")
            module_name = item["module"]
            relative_text = item["path"]
            digest = item["sha256"]
            if (
                type(module_name) is not str
                or _MODULE.fullmatch(module_name) is None
                or module_name != _ENTRY_CLOSURES[entry_module][index]
                or module_name in seen
            ):
                raise VerifiedBootstrapError("closure module order/name is invalid")
            seen.add(module_name)
            if type(relative_text) is not str:
                raise VerifiedBootstrapError("closure module path is invalid")
            relative = PurePosixPath(relative_text)
            if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != relative_text:
                raise VerifiedBootstrapError("closure module path is not canonical relative")
            if type(digest) is not str or _SHA256.fullmatch(digest) is None:
                raise VerifiedBootstrapError("closure module digest is invalid")
            path = artifact_root.joinpath(*relative.parts)
            descriptor, binding = _open_chain_file(path, f"closure module {module_name}")
            retained.append(descriptor)
            payload, identity = _read_stable(
                descriptor, 16 << 20, f"closure module {module_name}"
            )
            if hashlib.sha256(payload).hexdigest() != digest:
                raise VerifiedBootstrapError("closure module digest mismatch")
            sources.append((module_name, path, descriptor, payload, binding, identity))
            closure.append(
                {
                    "identity": identity,
                    "module": module_name,
                    "path": os.fspath(path),
                    "sha256": digest,
                }
            )

        artifact_text = os.fspath(artifact_root)
        sys.path[:] = [
            entry
            for entry in sys.path
            if not entry
            or not (
                os.path.abspath(entry) == artifact_text
                or os.path.abspath(entry).startswith(artifact_text + os.sep)
            )
        ]
        _install_package("sluice_v2")
        _install_package("experiments")
        finalized = False

        start_wire = {
            "bootstrap": {
                "identity": bootstrap_identity,
                "path": os.fspath(bootstrap_path),
                "sha256": inline["bootstrap_sha256"],
            },
            "closure": closure,
            "closure_manifest": {
                "identity": manifest_identity,
                "path": os.fspath(manifest_path),
                "sha256": inline["closure_manifest_sha256"],
            },
            "inline_loader_sha256": inline["inline_loader_sha256"],
            "interpreter": {
                "identity": interpreter_identity,
                "path": interpreter_realpath,
                "procfs_mount": interpreter_procfs_mount,
                "sha256": interpreter_sha256,
            },
            "pycache": {
                "empty": True,
                "identity": pycache_identity,
                "path": os.fspath(pycache_prefix),
            },
            "run_id": inline["run_id"],
            "source_commit": inline["source_commit"],
        }

        def finalize() -> dict[str, object]:
            nonlocal finalized
            if finalized:
                raise VerifiedBootstrapError("verified bootstrap finalized twice")
            finalized = True
            end_closure: list[dict[str, object]] = []
            for module_name, path, descriptor, payload, binding, identity in sources:
                observed, observed_identity = _read_stable(
                    descriptor, 16 << 20, f"closure module {module_name}"
                )
                if observed != payload or observed_identity != identity:
                    raise VerifiedBootstrapError("executing closure descriptor changed")
                _rebound_chain(path, binding, identity, f"closure module {module_name}")
                end_closure.append(
                    {
                        "identity": identity,
                        "module": module_name,
                        "path": os.fspath(path),
                        "sha256": hashlib.sha256(observed).hexdigest(),
                    }
                )
            _rebound_chain(
                manifest_path,
                manifest_binding,
                manifest_identity,
                "closure manifest",
            )
            _rebound_chain(
                bootstrap_path,
                injected_binding,
                bootstrap_identity,
                "verified bootstrap",
            )
            end_bootstrap, end_bootstrap_identity = _read_stable(
                bootstrap_fd, 4 << 20, "verified bootstrap"
            )
            end_interpreter_sha256, end_interpreter_identity = (
                _hash_regular_descriptor(interpreter_fd, "verified interpreter")
            )
            _revalidate_verified_interpreter(
                interpreter_fd,
                interpreter_identity,
                interpreter_realpath,
                interpreter_procfs_mount,
            )
            pycache_status = os.fstat(pycache_fd)
            _rebound_directory_chain(
                pycache_prefix,
                pycache_binding,
                _directory_identity(pycache_status),
                "Python pycache prefix",
            )
            if (
                end_bootstrap != bootstrap_bytes
                or end_bootstrap_identity != bootstrap_identity
                or end_interpreter_sha256 != interpreter_sha256
                or end_interpreter_identity != interpreter_identity
                or _directory_identity(pycache_status)
                != (
                    pycache_identity["device"],
                    pycache_identity["inode"],
                    pycache_identity["uid"],
                    pycache_identity["gid"],
                    pycache_identity["mode"],
                )
                or os.listdir(pycache_fd)
            ):
                raise VerifiedBootstrapError("verified execution identity drifted")
            end_wire = dict(start_wire)
            end_wire["closure"] = end_closure
            return {
                "end": end_wire,
                "equal": end_wire == start_wire,
                "start": start_wire,
            }

        for module_name, path, _descriptor, payload, _binding, _identity in sources:
            module = types.ModuleType(module_name)
            module.__file__ = os.fspath(path)
            module.__package__ = module_name.rpartition(".")[0]
            module.__loader__ = None
            if module_name == entry_module:
                module.__dict__["VERIFIED_BOOTSTRAP_START"] = start_wire
                module.__dict__["VERIFIED_BOOTSTRAP_FINALIZE"] = finalize
            sys.modules[module_name] = module
            code = compile(payload, os.fspath(path), "exec", dont_inherit=True)
            exec(code, module.__dict__)

        entry = sys.modules[entry_module]
        entry_main = getattr(entry, "main", None)
        if not callable(entry_main):
            raise VerifiedBootstrapError("verified entry module has no callable main")
        sys.argv = [os.fspath(sources[-1][1]), *entry_argv]
        result = entry_main()
        if type(result) is not int:
            raise VerifiedBootstrapError("verified entry main returned a non-integer")
        if not finalized:
            raise VerifiedBootstrapError("verified entry did not finalize provenance")
        return result
    finally:
        for descriptor in reversed(retained):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
