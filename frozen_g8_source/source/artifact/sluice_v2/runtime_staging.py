"""Create-only authenticated staging of a runtime tree onto node-local XFS.

The protocol treats the source tree as read-only, copies only directories,
regular files, and safe relative symbolic links, fsyncs the completed copy,
and publishes it with Linux ``renameat2(RENAME_NOREPLACE)``. Every mutable
path traversal is pinned to directory descriptors. A success is reported only
after the complete lexical path is reopened and rebound to the same identity.

This module never deletes or overwrites a path. An interrupted or rejected
copy remains under its unique ``.staging-*`` name for diagnosis.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import struct
import time
from typing import Any, Iterable


SCHEMA_VERSION = 1
PROTOCOL_ID = "sluice-authenticated-local-runtime-v1"
_LABEL = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RENAME_NOREPLACE = 1
_MAX_AUTHENTICATED_JSON_BYTES = 16 << 20
_LIBC = ctypes.CDLL(None, use_errno=True)
_AT_SYMLINK_NOFOLLOW = 0x100
_AT_STATX_FORCE_SYNC = 0x2000
_STATX_REQUIRED = 0x0000031F  # type, mode, nlink, uid, gid, inode, and size
_NFS_SUPER_MAGIC = "00006969"
_XFS_SUPER_MAGIC = "58465342"


class _StatxTimestamp(ctypes.Structure):
    _fields_ = (
        ("seconds", ctypes.c_int64),
        ("nanoseconds", ctypes.c_uint32),
        ("reserved", ctypes.c_int32),
    )


class _Statx(ctypes.Structure):
    # Linux statx is a fixed 256-byte ABI.  Only basic-stat fields are read.
    _fields_ = (
        ("mask", ctypes.c_uint32),
        ("block_size", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64),
        ("nlink", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("spare0", ctypes.c_uint16),
        ("inode", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64),
        ("attributes_mask", ctypes.c_uint64),
        ("atime", _StatxTimestamp),
        ("btime", _StatxTimestamp),
        ("ctime", _StatxTimestamp),
        ("mtime", _StatxTimestamp),
        ("rdev_major", ctypes.c_uint32),
        ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32),
        ("dev_minor", ctypes.c_uint32),
        ("remaining", ctypes.c_ubyte * 112),
    )


class _Statfs(ctypes.Structure):
    # Linux x86-64 statfs ABI (120 bytes).
    _fields_ = (
        ("filesystem_type", ctypes.c_long),
        ("block_size", ctypes.c_long),
        ("blocks", ctypes.c_ulong),
        ("blocks_free", ctypes.c_ulong),
        ("blocks_available", ctypes.c_ulong),
        ("files", ctypes.c_ulong),
        ("files_free", ctypes.c_ulong),
        ("fsid", ctypes.c_int32 * 2),
        ("name_length", ctypes.c_long),
        ("fragment_size", ctypes.c_long),
        ("mount_flags", ctypes.c_long),
        ("spare", ctypes.c_long * 4),
    )


class RuntimeStagingError(RuntimeError):
    """The runtime staging contract failed closed."""


@dataclass(frozen=True)
class MountIdentity:
    filesystem: str
    mountpoint: str
    source: str
    mount_options: tuple[str, ...]
    super_options: tuple[str, ...]
    mount_id: int

    def __post_init__(self) -> None:
        if type(self.mount_id) is not int or self.mount_id <= 0:
            raise ValueError("mount identity requires a positive kernel mount ID")

    def to_wire(self) -> dict[str, object]:
        return {
            "filesystem": self.filesystem,
            "mount_options": list(self.mount_options),
            "mount_id": self.mount_id,
            "mountpoint": self.mountpoint,
            "source": self.source,
            "super_options": list(self.super_options),
        }


@dataclass(frozen=True)
class DescriptorFilesystemIdentity:
    filesystem_magic: str
    fsid: tuple[int, int]
    mount_id: int
    statvfs_fsid: int

    def to_wire(self) -> dict[str, object]:
        return {
            "filesystem_magic": self.filesystem_magic,
            "fsid": list(self.fsid),
            "mount_id": self.mount_id,
            "statvfs_fsid": self.statvfs_fsid,
        }


def _descriptor_mount_id(descriptor: int, role: str) -> int:
    """Read the kernel mount ID associated with one still-open descriptor."""

    before = os.fstat(descriptor)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fdinfo = os.open(f"/proc/self/fdinfo/{descriptor}", flags)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fdinfo, 4096)
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > 65536:
                raise RuntimeStagingError(f"{role} descriptor fdinfo is oversized")
    finally:
        os.close(fdinfo)
    after = os.fstat(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
    ):
        raise RuntimeStagingError(f"{role} descriptor changed during mount-ID read")
    try:
        lines = b"".join(chunks).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeStagingError(f"{role} descriptor fdinfo is non-ASCII") from exc
    values = [line.split(":", 1)[1].strip() for line in lines if line.startswith("mnt_id:")]
    if len(values) != 1 or re.fullmatch(r"[1-9][0-9]*", values[0]) is None:
        raise RuntimeStagingError(f"{role} descriptor fdinfo omitted a valid mount ID")
    return int(values[0])


def _descriptor_filesystem(
    descriptor: int, role: str
) -> DescriptorFilesystemIdentity:
    """Return filesystem identity from an already-pinned Linux descriptor."""

    if os.uname().sysname != "Linux":
        raise RuntimeStagingError(f"{role} descriptor filesystem requires Linux")
    if ctypes.sizeof(_Statfs) != 120:
        raise RuntimeStagingError("unexpected Linux x86-64 statfs ABI size")
    fstatfs = getattr(_LIBC, "fstatfs", None)
    if fstatfs is None:
        raise RuntimeStagingError("libc fstatfs is unavailable")
    fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_Statfs))
    fstatfs.restype = ctypes.c_int
    observed = _Statfs()
    ctypes.set_errno(0)
    if fstatfs(descriptor, ctypes.byref(observed)) != 0:
        value = ctypes.get_errno()
        raise OSError(value, f"fstatfs failed for {role} descriptor")
    statvfs = os.fstatvfs(descriptor)
    statvfs_fsid = getattr(statvfs, "f_fsid", None)
    if type(statvfs_fsid) is not int:
        raise RuntimeStagingError(f"{role} descriptor statvfs omitted f_fsid")
    return DescriptorFilesystemIdentity(
        filesystem_magic=f"{int(observed.filesystem_type) & 0xffffffff:08x}",
        fsid=(int(observed.fsid[0]), int(observed.fsid[1])),
        mount_id=_descriptor_mount_id(descriptor, role),
        statvfs_fsid=statvfs_fsid,
    )


def _require_descriptor_filesystem(
    observed: DescriptorFilesystemIdentity, expected_magic: str, role: str
) -> None:
    if observed.filesystem_magic != expected_magic:
        raise RuntimeStagingError(
            f"{role} descriptor filesystem magic {observed.filesystem_magic!r} "
            f"does not match {expected_magic!r}"
        )


def _assert_descriptor_filesystem_rebound(
    path: Path,
    expected: DescriptorFilesystemIdentity,
    expected_mount: MountIdentity,
    role: str,
) -> None:
    descriptor, _ = _open_directory_chain(path, role)
    try:
        observed = _descriptor_filesystem(descriptor, role)
        mount = mount_for_path(path)
        if (
            observed != expected
            or mount != expected_mount
            or observed.mount_id != mount.mount_id
        ):
            raise RuntimeStagingError(f"{role} descriptor filesystem changed")
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class _TreeAudit:
    execution_sha256: str
    inventory: dict[str, object]
    sha256: str
    timestamp_sha256: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _mount_unescape(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def mount_for_path(path: Path) -> MountIdentity:
    """Resolve the longest matching mountpoint from Linux mountinfo."""

    candidate = _lexical_absolute(path, "mount path")
    candidates: list[tuple[int, MountIdentity]] = []
    with Path("/proc/self/mountinfo").open("r", encoding="ascii") as stream:
        for raw_line in stream:
            left, separator, right = raw_line.rstrip("\n").partition(" - ")
            if not separator:
                raise RuntimeStagingError("malformed /proc/self/mountinfo record")
            left_fields = left.split()
            right_fields = right.split()
            if len(left_fields) < 6 or len(right_fields) < 3:
                raise RuntimeStagingError("short /proc/self/mountinfo record")
            mountpoint = Path(_mount_unescape(left_fields[4]))
            try:
                candidate.relative_to(mountpoint)
            except ValueError:
                continue
            identity = MountIdentity(
                filesystem=right_fields[0],
                mount_id=int(left_fields[0]),
                mountpoint=os.fspath(mountpoint),
                source=_mount_unescape(right_fields[1]),
                mount_options=tuple(sorted(left_fields[5].split(","))),
                super_options=tuple(sorted(right_fields[2].split(","))),
            )
            candidates.append((len(mountpoint.parts), identity))
    if not candidates:
        raise RuntimeStagingError(f"no mount identity for {candidate}")
    return max(candidates, key=lambda item: item[0])[1]


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _lexical_absolute(path: Path, name: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts or "\x00" in os.fspath(candidate):
        raise ValueError(f"{name} must be a canonical absolute path")
    return candidate


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _regular_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _directory_key(status: os.stat_result) -> tuple[int, int, int, int]:
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("path-chain component must be a directory")
    return (status.st_dev, status.st_ino, status.st_uid, stat.S_IMODE(status.st_mode))


def _leaf_key(status: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        status.st_mode,
        status.st_nlink,
        status.st_size,
    )


def _regular_identity_wire(status: os.stat_result) -> dict[str, int]:
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeStagingError("authenticated JSON identity is not regular")
    return {
        "device": status.st_dev,
        "gid": status.st_gid,
        "inode": status.st_ino,
        "mode": stat.S_IMODE(status.st_mode),
        "nlink": status.st_nlink,
        "size": status.st_size,
        "uid": status.st_uid,
    }


def _open_directory_chain(
    path: Path, name: str
) -> tuple[int, tuple[tuple[int, int, int, int], ...]]:
    """Open every lexical component without symlink following and pin the leaf."""

    candidate = _lexical_absolute(path, name)
    descriptor = os.open("/", _directory_flags())
    identities = [_directory_key(os.fstat(descriptor))]
    try:
        for component in candidate.parts[1:]:
            if not component or component in {".", ".."} or "/" in component:
                raise ValueError(f"{name} has an invalid path component")
            try:
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(f"{name} path chain must not contain symbolic links") from exc
                raise
            try:
                identities.append(_directory_key(os.fstat(child)))
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor, tuple(identities)
    except BaseException:
        os.close(descriptor)
        raise


def _assert_directory_rebound(
    path: Path,
    expected: tuple[tuple[int, int, int, int], ...],
    name: str,
) -> None:
    try:
        descriptor, observed = _open_directory_chain(path, name)
    except (OSError, ValueError) as exc:
        raise RuntimeStagingError(f"{name} path identity changed") from exc
    try:
        if observed != expected:
            raise RuntimeStagingError(f"{name} path identity changed")
    finally:
        os.close(descriptor)


def _split_leaf(path: Path, name: str) -> tuple[Path, str]:
    candidate = _lexical_absolute(path, name)
    leaf = candidate.name
    if not leaf or leaf in {".", ".."} or "/" in leaf or "\x00" in leaf:
        raise ValueError(f"{name} must name a leaf")
    return candidate.parent, leaf


def _stat_or_none(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _same_stat(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _record(hasher: Any, *values: object) -> None:
    encoded = json.dumps(
        list(values), allow_nan=False, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    hasher.update(struct.pack(">Q", len(encoded)))
    hasher.update(encoded)


def _mode_key(kind: str, mode: int) -> str:
    return f"{kind}:{stat.S_IMODE(mode):04o}"


def _hash_regular_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    *,
    require_single_link: bool,
) -> str:
    descriptor = os.open(name, _regular_flags(), dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_stat(expected, before)
            or (require_single_link and before.st_nlink != 1)
        ):
            raise RuntimeStagingError("regular-file identity changed before hashing")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if not _same_stat(before, after):
            raise RuntimeStagingError("regular file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _validate_relative_links(
    entry_types: dict[tuple[str, ...], str],
    links: dict[tuple[str, ...], str],
) -> None:
    """Resolve the scanned symlink graph lexically, rejecting escapes/cycles/breakage."""

    for link_path, initial_target in links.items():
        resolved = list(link_path[:-1])
        pending = list(PurePosixPath(initial_target).parts)
        seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
        while pending:
            state = (tuple(resolved), tuple(pending))
            if state in seen:
                raise ValueError("runtime tree has a cyclic symlink")
            seen.add(state)
            component = pending.pop(0)
            if component in {"", "."}:
                continue
            if component == "..":
                if not resolved:
                    raise ValueError("runtime tree symlink escapes its root")
                resolved.pop()
                continue
            resolved.append(component)
            current = tuple(resolved)
            kind = entry_types.get(current)
            if kind is None:
                raise ValueError("runtime tree has a broken symlink")
            if kind == "L":
                resolved.pop()
                pending = list(PurePosixPath(links[current]).parts) + pending
            elif pending and kind != "D":
                raise ValueError("runtime tree symlink traverses a nondirectory")
        if tuple(resolved) not in entry_types:
            raise ValueError("runtime tree has a broken symlink")


def _audit_tree_fd(root_fd: int, *, require_single_link_files: bool) -> _TreeAudit:
    counts = {"directories": 0, "regular_files": 0, "symlinks": 0}
    regular_bytes = 0
    modes: dict[str, int] = {}
    inventory_hash = hashlib.sha256(b"sluice-runtime-inventory-v1\0")
    tree_hash = hashlib.sha256(b"sluice-authenticated-tree-v1\0")
    timestamp_hash = hashlib.sha256(b"sluice-runtime-timestamps-v1\0")
    entry_types: dict[tuple[str, ...], str] = {(): "D"}
    links: dict[tuple[str, ...], str] = {}

    def visit(directory_fd: int, relative: PurePosixPath) -> None:
        nonlocal regular_bytes
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise RuntimeStagingError("runtime directory changed type")
        counts["directories"] += 1
        mode_key = _mode_key("D", before.st_mode)
        modes[mode_key] = modes.get(mode_key, 0) + 1
        names_before = tuple(sorted(os.listdir(directory_fd), key=lambda value: value.encode("utf-8")))
        _record(inventory_hash, "D", relative.as_posix(), stat.S_IMODE(before.st_mode))
        _record(tree_hash, "D", relative.as_posix(), stat.S_IMODE(before.st_mode))
        _record(timestamp_hash, "D", relative.as_posix(), before.st_mtime_ns)
        for entry_name in names_before:
            if not entry_name or entry_name in {".", ".."} or "/" in entry_name or "\x00" in entry_name:
                raise ValueError("runtime entry has an invalid name")
            status = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
            child_relative = relative / entry_name
            child_parts = tuple(child_relative.parts)
            if stat.S_ISDIR(status.st_mode):
                entry_types[child_parts] = "D"
                child_fd = os.open(entry_name, _directory_flags(), dir_fd=directory_fd)
                try:
                    if not _same_stat(status, os.fstat(child_fd)):
                        raise RuntimeStagingError("runtime directory identity changed before recursion")
                    visit(child_fd, child_relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(status.st_mode):
                entry_types[child_parts] = "F"
                content = _hash_regular_at(
                    directory_fd,
                    entry_name,
                    status,
                    require_single_link=require_single_link_files,
                )
                counts["regular_files"] += 1
                regular_bytes += status.st_size
                mode_key = _mode_key("F", status.st_mode)
                modes[mode_key] = modes.get(mode_key, 0) + 1
                _record(inventory_hash, "F", child_relative.as_posix(), stat.S_IMODE(status.st_mode), status.st_size)
                _record(tree_hash, "F", child_relative.as_posix(), stat.S_IMODE(status.st_mode), status.st_size, content)
                _record(timestamp_hash, "F", child_relative.as_posix(), status.st_mtime_ns)
            elif stat.S_ISLNK(status.st_mode):
                target = os.readlink(entry_name, dir_fd=directory_fd)
                if PurePosixPath(target).is_absolute():
                    raise ValueError("runtime symlink target must be relative")
                after_link = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
                if not _same_stat(status, after_link):
                    raise RuntimeStagingError("runtime symlink changed while reading")
                entry_types[child_parts] = "L"
                links[child_parts] = target
                counts["symlinks"] += 1
                _record(inventory_hash, "L", child_relative.as_posix(), target)
                _record(tree_hash, "L", child_relative.as_posix(), target)
                _record(timestamp_hash, "L", child_relative.as_posix(), status.st_mtime_ns)
            else:
                raise ValueError("runtime tree contains a special file")
        names_after = tuple(sorted(os.listdir(directory_fd), key=lambda value: value.encode("utf-8")))
        after = os.fstat(directory_fd)
        if names_before != names_after or not _same_stat(before, after):
            raise RuntimeStagingError("runtime tree changed during authentication")

    visit(root_fd, PurePosixPath("."))
    _validate_relative_links(entry_types, links)
    inventory = {
        **counts,
        "inventory_sha256": inventory_hash.hexdigest(),
        "mode_counts": dict(sorted(modes.items())),
        "regular_bytes": regular_bytes,
    }
    tree_sha256 = tree_hash.hexdigest()
    timestamp_sha256 = timestamp_hash.hexdigest()
    execution_hash = hashlib.sha256(b"sluice-runtime-execution-semantics-v1\0")
    _record(
        execution_hash,
        tree_sha256,
        timestamp_sha256,
        inventory,
    )
    return _TreeAudit(
        execution_sha256=execution_hash.hexdigest(),
        inventory=inventory,
        sha256=tree_sha256,
        timestamp_sha256=timestamp_sha256,
    )


def _safe_canonical_directory(path: Path, name: str) -> Path:
    candidate = _lexical_absolute(path, name)
    descriptor, binding = _open_directory_chain(candidate, name)
    os.close(descriptor)
    _assert_directory_rebound(candidate, binding, name)
    return candidate


def inspect_runtime_tree(root: Path) -> dict[str, object]:
    """Validate entry types/symlinks and return a stable aggregate inventory."""

    candidate = _lexical_absolute(root, "runtime tree")
    descriptor, binding = _open_directory_chain(candidate, "runtime tree")
    try:
        audit = _audit_tree_fd(descriptor, require_single_link_files=False)
        root_key = _directory_key(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    _assert_directory_rebound(candidate, binding, "runtime tree")
    rebound_fd, _ = _open_directory_chain(candidate, "runtime tree")
    try:
        if _directory_key(os.fstat(rebound_fd)) != root_key:
            raise RuntimeStagingError("runtime tree root identity changed")
    finally:
        os.close(rebound_fd)
    return audit.inventory


def audit_runtime_execution(
    root: Path, *, require_single_link_files: bool = True
) -> dict[str, object]:
    """Authenticate one tree's content and timestamp-sensitive semantics."""

    if type(require_single_link_files) is not bool:
        raise TypeError("require_single_link_files must be Boolean")
    candidate = _lexical_absolute(root, "runtime execution tree")
    descriptor, binding = _open_directory_chain(candidate, "runtime execution tree")
    try:
        audit = _audit_tree_fd(
            descriptor, require_single_link_files=require_single_link_files
        )
        identity = _root_identity_fd(descriptor)
    finally:
        os.close(descriptor)
    _assert_directory_rebound(candidate, binding, "runtime execution tree")
    return {
        "execution_sha256": audit.execution_sha256,
        "inventory": audit.inventory,
        "root_identity": identity,
        "timestamp_sha256": audit.timestamp_sha256,
        "tree_sha256": audit.sha256,
    }


def runtime_timestamps_match(source: Path, staged: Path) -> bool:
    """Compare modification times for every corresponding tree entry."""

    left_path = _lexical_absolute(source, "timestamp source")
    right_path = _lexical_absolute(staged, "timestamp staged tree")
    left_fd, left_binding = _open_directory_chain(left_path, "timestamp source")
    right_fd, right_binding = _open_directory_chain(right_path, "timestamp staged tree")
    try:
        left = _audit_tree_fd(left_fd, require_single_link_files=False)
        right = _audit_tree_fd(right_fd, require_single_link_files=False)
    finally:
        os.close(left_fd)
        os.close(right_fd)
    _assert_directory_rebound(left_path, left_binding, "timestamp source")
    _assert_directory_rebound(right_path, right_binding, "timestamp staged tree")
    return left.timestamp_sha256 == right.timestamp_sha256


def _open_or_create_base(path: Path) -> tuple[int, tuple[tuple[int, int, int, int], ...], Path]:
    candidate = _lexical_absolute(path, "destination base")
    parent, leaf = _split_leaf(candidate, "destination base")
    parent_fd, parent_binding = _open_directory_chain(parent, "destination base parent")
    try:
        if _stat_or_none(parent_fd, leaf) is None:
            os.mkdir(leaf, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        try:
            base_fd = os.open(leaf, _directory_flags(), dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError(
                    "destination base must not be a symbolic link"
                ) from exc
            raise
        try:
            status = os.fstat(base_fd)
            if not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) != 0o700:
                raise PermissionError("destination base must be owned by the effective user with mode 0700")
            binding = parent_binding + (_directory_key(status),)
        except BaseException:
            os.close(base_fd)
            raise
    finally:
        os.close(parent_fd)
    try:
        _assert_directory_rebound(candidate, binding, "destination base")
    except BaseException:
        os.close(base_fd)
        raise
    return base_fd, binding, candidate


def _copy_regular(source_fd: int, destination_fd: int, name: str, expected: os.stat_result) -> int:
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    reader = os.open(name, _regular_flags(), dir_fd=source_fd)
    writer = -1
    try:
        before = os.fstat(reader)
        if not stat.S_ISREG(before.st_mode) or not _same_stat(expected, before):
            raise RuntimeStagingError("source regular file identity changed before copy")
        writer = os.open(name, destination_flags, 0o600, dir_fd=destination_fd)
        copied = 0
        while True:
            block = os.read(reader, 1 << 20)
            if not block:
                break
            _write_all(writer, block)
            copied += len(block)
        after = os.fstat(reader)
        if not _same_stat(before, after) or copied != before.st_size:
            raise RuntimeStagingError("source regular file changed during copy")
        os.fchmod(writer, stat.S_IMODE(before.st_mode))
        os.utime(writer, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.fsync(writer)
        staged = os.fstat(writer)
        if not stat.S_ISREG(staged.st_mode) or staged.st_nlink != 1 or staged.st_size != before.st_size or stat.S_IMODE(staged.st_mode) != stat.S_IMODE(before.st_mode) or staged.st_mtime_ns != before.st_mtime_ns:
            raise RuntimeStagingError("staged regular file metadata mismatch")
        return copied
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)


def _copy_directory(source_fd: int, destination_fd: int, *, relative: PurePosixPath) -> dict[str, int]:
    before = os.fstat(source_fd)
    if not stat.S_ISDIR(before.st_mode):
        raise RuntimeStagingError("source directory changed type before copy")
    names_before = tuple(sorted(os.listdir(source_fd), key=lambda name: name.encode("utf-8")))
    counts = {"directories": 1, "regular_bytes": 0, "regular_files": 0, "symlinks": 0}
    for name in names_before:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ValueError("runtime entry has an invalid name")
        source_status = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        child_relative = relative / name
        if stat.S_ISDIR(source_status.st_mode):
            os.mkdir(name, 0o700, dir_fd=destination_fd)
            child_source_fd = os.open(name, _directory_flags(), dir_fd=source_fd)
            child_destination_fd = os.open(name, _directory_flags(), dir_fd=destination_fd)
            try:
                if not _same_stat(source_status, os.fstat(child_source_fd)):
                    raise RuntimeStagingError("source directory identity changed before recursion")
                child_counts = _copy_directory(child_source_fd, child_destination_fd, relative=child_relative)
                os.fchmod(child_destination_fd, stat.S_IMODE(source_status.st_mode))
                os.utime(child_destination_fd, ns=(source_status.st_atime_ns, source_status.st_mtime_ns))
                os.fsync(child_destination_fd)
                if os.fstat(child_destination_fd).st_mtime_ns != source_status.st_mtime_ns:
                    raise RuntimeStagingError("staged directory timestamp mismatch")
            finally:
                os.close(child_source_fd)
                os.close(child_destination_fd)
            for key, value in child_counts.items():
                counts[key] += value
        elif stat.S_ISREG(source_status.st_mode):
            copied = _copy_regular(source_fd, destination_fd, name, source_status)
            counts["regular_files"] += 1
            counts["regular_bytes"] += copied
        elif stat.S_ISLNK(source_status.st_mode):
            target = os.readlink(name, dir_fd=source_fd)
            if PurePosixPath(target).is_absolute():
                raise ValueError("runtime symlink target must be relative")
            if not _same_stat(source_status, os.stat(name, dir_fd=source_fd, follow_symlinks=False)):
                raise RuntimeStagingError("source symlink changed before copy")
            os.symlink(target, name, dir_fd=destination_fd)
            os.utime(name, ns=(source_status.st_atime_ns, source_status.st_mtime_ns), dir_fd=destination_fd, follow_symlinks=False)
            if os.readlink(name, dir_fd=destination_fd) != target:
                raise RuntimeStagingError("staged symlink target mismatch")
            if os.stat(name, dir_fd=destination_fd, follow_symlinks=False).st_mtime_ns != source_status.st_mtime_ns:
                raise RuntimeStagingError("staged symlink timestamp mismatch")
            counts["symlinks"] += 1
        else:
            raise ValueError("runtime tree contains a special file")
    names_after = tuple(sorted(os.listdir(source_fd), key=lambda name: name.encode("utf-8")))
    if names_before != names_after or not _same_stat(before, os.fstat(source_fd)):
        raise RuntimeStagingError("source directory changed during copy")
    return counts


def _rename_noreplace_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str) -> None:
    renameat2 = getattr(_LIBC, "renameat2", None)
    if renameat2 is None:
        raise RuntimeStagingError("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(source_fd, os.fsencode(source_name), destination_fd, os.fsencode(destination_name), _RENAME_NOREPLACE)
    if result != 0:
        value = ctypes.get_errno()
        if value == errno.EEXIST:
            raise FileExistsError(destination_name)
        raise OSError(value, "renameat2(RENAME_NOREPLACE) failed")


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short create-only write")
        offset += written


def _publish_regular_noreplace_at(parent_fd: int, temporary: str, destination: str) -> bool:
    """Publish one fsynced regular file and report use of the NFS link fallback.

    The fallback deliberately leaves the temporary hard link in place.  Its
    caller still holds the authenticated temporary descriptor and must close
    that descriptor before unlinking the temporary name.  This ordering avoids
    NFS silly-rename semantics, which otherwise retain a hidden second link
    until the open descriptor is closed.
    """

    try:
        _rename_noreplace_at(parent_fd, temporary, parent_fd, destination)
        return False
    except RuntimeStagingError:
        pass
    except OSError as exc:
        if exc.errno not in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
            raise
    if _stat_or_none(parent_fd, destination) is not None:
        raise FileExistsError(destination)
    before = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeStagingError("JSON fallback source is not a private regular file")
    try:
        os.link(temporary, destination, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
    except FileExistsError:
        raise FileExistsError(destination) from None
    published = os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
    linked = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(published.st_mode) or (published.st_dev, published.st_ino) != (linked.st_dev, linked.st_ino) or published.st_nlink != 2 or linked.st_nlink != 2:
        raise RuntimeStagingError("JSON hard-link publication identity check failed")
    return True


def _read_regular_fd(descriptor: int, *, expected_mode: int, expected_nlink: int, maximum_bytes: int) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != expected_mode or before.st_nlink != expected_nlink or before.st_size < 0 or before.st_size > maximum_bytes:
        raise RuntimeStagingError("authenticated JSON file metadata is invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(descriptor, min(1 << 20, maximum_bytes + 1 - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > maximum_bytes:
            raise RuntimeStagingError("authenticated JSON file exceeds the size limit")
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    if len(payload) != before.st_size or not _same_stat(before, after):
        raise RuntimeStagingError("authenticated JSON file changed while reading")
    return payload, after


def _forced_link_count(
    parent_fd: int, name: str, expected: os.stat_result
) -> int | None:
    """Return the server-synchronous link count, or None when statx cannot.

    Every identity field except the link count is verified fail-closed here, so
    a caller polling for hard-link cleanup can never converge on a different
    object.  The link count is returned rather than asserted because the
    bounded cleanup poll in ``_write_json_at`` is exactly the code that must
    observe a still-lagging count without failing the publication outright.
    """

    statx = getattr(_LIBC, "statx", None)
    if statx is None:
        return None
    statx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_Statx),
    )
    statx.restype = ctypes.c_int
    observed = _Statx()
    ctypes.set_errno(0)
    result = statx(
        parent_fd,
        os.fsencode(name),
        _AT_SYMLINK_NOFOLLOW | _AT_STATX_FORCE_SYNC,
        _STATX_REQUIRED,
        ctypes.byref(observed),
    )
    if result != 0:
        value = ctypes.get_errno()
        if value in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
            return None
        raise OSError(value, "statx(AT_STATX_FORCE_SYNC) failed")
    if observed.mask & _STATX_REQUIRED != _STATX_REQUIRED:
        raise RuntimeStagingError("forced statx omitted required JSON identity fields")
    observed_device = os.makedev(observed.dev_major, observed.dev_minor)
    if (
        not stat.S_ISREG(observed.mode)
        or stat.S_IMODE(observed.mode) != 0o600
        or observed.inode != expected.st_ino
        or observed.size != expected.st_size
        or observed.uid != expected.st_uid
        or observed.gid != expected.st_gid
        or observed_device != expected.st_dev
    ):
        raise RuntimeStagingError("forced JSON identity check failed after hard-link cleanup")
    return int(observed.nlink)


def _force_sync_regular_leaf(
    parent_fd: int, name: str, expected: os.stat_result
) -> bool:
    """Force server-synchronous basic attributes with Linux statx when available."""

    observed_nlink = _forced_link_count(parent_fd, name, expected)
    if observed_nlink is None:
        return False
    if observed_nlink != 1:
        raise RuntimeStagingError("forced JSON identity check failed after hard-link cleanup")
    return True


def _force_sync_absent_leaf(parent_fd: int, name: str) -> bool:
    """Require server-synchronous absence with Linux statx when available."""

    statx = getattr(_LIBC, "statx", None)
    if statx is None:
        return False
    statx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_Statx),
    )
    statx.restype = ctypes.c_int
    observed = _Statx()
    ctypes.set_errno(0)
    result = statx(
        parent_fd,
        os.fsencode(name),
        _AT_SYMLINK_NOFOLLOW | _AT_STATX_FORCE_SYNC,
        _STATX_REQUIRED,
        ctypes.byref(observed),
    )
    if result == 0:
        raise RuntimeStagingError("authenticated absent path exists")
    value = ctypes.get_errno()
    if value == errno.ENOENT:
        return True
    if value in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
        return False
    raise OSError(value, "statx(AT_STATX_FORCE_SYNC) absence check failed")


def _json_post_publish_test_hook(parent_fd: int, destination: str) -> None:
    """No-op fault-injection hook used only by deterministic unit tests."""
    del parent_fd, destination


def _json_post_read_test_hook(parent_fd: int, destination: str) -> None:
    """No-op fault-injection hook used only by deterministic unit tests."""
    del parent_fd, destination


def _runtime_pre_publish_test_hook(base_fd: int, stage: str, destination: str) -> None:
    """No-op fault-injection hook used only by deterministic unit tests."""
    del base_fd, stage, destination


def _runtime_post_publish_test_hook(base_fd: int, destination: str) -> None:
    """No-op fault-injection hook used only by deterministic unit tests."""
    del base_fd, destination


def _write_json_at(parent_fd: int, destination: str, payload: bytes, *, run_hook: bool) -> str:
    if _stat_or_none(parent_fd, destination) is not None:
        raise FileExistsError(destination)
    temporary = f".sluice-json-{os.getpid()}-{secrets.token_hex(16)}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        initial_payload, initial_status = _read_regular_fd(descriptor, expected_mode=0o600, expected_nlink=1, maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES)
        if initial_payload != payload:
            raise RuntimeStagingError("temporary JSON failed same-descriptor authentication")
        link_fallback = _publish_regular_noreplace_at(
            parent_fd, temporary, destination
        )
        os.fsync(parent_fd)
        published_fd = os.open(destination, _regular_flags(), dir_fd=parent_fd)
        try:
            published_before = os.fstat(published_fd)
            if (published_before.st_dev, published_before.st_ino) != (initial_status.st_dev, initial_status.st_ino):
                raise RuntimeStagingError("published JSON identity differs from its temporary file")
            pre_cleanup_payload, _ = _read_regular_fd(
                published_fd,
                expected_mode=0o600,
                expected_nlink=2 if link_fallback else 1,
                maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES,
            )
            if pre_cleanup_payload != payload:
                raise RuntimeStagingError(
                    "published JSON differs before temporary-name cleanup"
                )
            if link_fallback:
                os.close(descriptor)
                descriptor = -1
                os.close(published_fd)
                published_fd = -1
                os.unlink(temporary, dir_fd=parent_fd)
                os.fsync(parent_fd)
                # The temporary name is gone from this client's view, but the
                # second link can still be observable: an NFS server that
                # silly-renamed the entry, or any other holder of a second
                # link, keeps the count at two until it is released.  Poll
                # server-synchronous attributes -- which also refresh this
                # client's cached attributes for the descriptor read below --
                # inside the bounded deadline instead of asserting convergence
                # before the poll has had any chance to run.
                deadline = time.monotonic() + 10.0
                while True:
                    forced_nlink = _forced_link_count(
                        parent_fd, destination, initial_status
                    )
                    candidate_fd = os.open(
                        destination, _regular_flags(), dir_fd=parent_fd
                    )
                    candidate_status = os.fstat(candidate_fd)
                    if (candidate_status.st_dev, candidate_status.st_ino) != (
                        initial_status.st_dev,
                        initial_status.st_ino,
                    ):
                        os.close(candidate_fd)
                        raise RuntimeStagingError(
                            "JSON hard-link cleanup changed published identity"
                        )
                    if forced_nlink in (None, 1) and candidate_status.st_nlink == 1:
                        published_fd = candidate_fd
                        break
                    os.close(candidate_fd)
                    unexpected = candidate_status.st_nlink not in (1, 2) or (
                        forced_nlink is not None and forced_nlink not in (1, 2)
                    )
                    if unexpected or time.monotonic() >= deadline:
                        raise RuntimeStagingError(
                            "JSON hard-link cleanup link count did not converge"
                        )
                    time.sleep(0.05)
                _force_sync_regular_leaf(parent_fd, destination, initial_status)
                cleaned_payload, cleaned_status = _read_regular_fd(
                    published_fd,
                    expected_mode=0o600,
                    expected_nlink=1,
                    maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES,
                )
                if (
                    cleaned_payload != payload
                    or (cleaned_status.st_dev, cleaned_status.st_ino)
                    != (initial_status.st_dev, initial_status.st_ino)
                ):
                    raise RuntimeStagingError(
                        "JSON hard-link temporary-name cleanup failed"
                    )
            if run_hook:
                _json_post_publish_test_hook(parent_fd, destination)
            published_payload, published_status = _read_regular_fd(published_fd, expected_mode=0o600, expected_nlink=1, maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES)
            if published_payload != payload:
                raise RuntimeStagingError("published JSON content differs from its fsynced payload")
            _force_sync_regular_leaf(parent_fd, destination, published_status)
            rebound = os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
            if _leaf_key(rebound) != _leaf_key(published_status):
                raise RuntimeStagingError("published JSON leaf identity changed")
        finally:
            if published_fd >= 0:
                os.close(published_fd)
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return hashlib.sha256(payload).hexdigest()


def write_json_create_only(path: Path, wire: dict[str, object]) -> str:
    """Durably publish canonical JSON without replacing an existing path."""

    destination = _lexical_absolute(path, "evidence path")
    parent, leaf = _split_leaf(destination, "evidence path")
    payload = (json.dumps(wire, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    if len(payload) > _MAX_AUTHENTICATED_JSON_BYTES:
        raise ValueError("evidence JSON exceeds the authenticated size limit")
    parent_fd, parent_binding = _open_directory_chain(parent, "evidence parent")
    published_status: os.stat_result | None = None
    try:
        digest = _write_json_at(parent_fd, leaf, payload, run_hook=True)
        published_fd = os.open(leaf, _regular_flags(), dir_fd=parent_fd)
        try:
            rebound_payload, published_status = _read_regular_fd(published_fd, expected_mode=0o600, expected_nlink=1, maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES)
            if rebound_payload != payload:
                raise RuntimeStagingError("published JSON changed before path rebound")
        finally:
            os.close(published_fd)
    finally:
        os.close(parent_fd)
    _assert_directory_rebound(parent, parent_binding, "evidence parent")
    rebound_parent_fd, _ = _open_directory_chain(parent, "evidence parent")
    try:
        rebound = os.stat(leaf, dir_fd=rebound_parent_fd, follow_symlinks=False)
        if published_status is None or _leaf_key(rebound) != _leaf_key(published_status):
            raise RuntimeStagingError("published JSON path failed complete rebound")
    finally:
        os.close(rebound_parent_fd)
    return digest


def read_json_authenticated_with_identity(
    path: Path,
) -> tuple[dict[str, object], str, dict[str, int]]:
    """Read/hash private canonical JSON and return its same-FD identity."""

    candidate = _lexical_absolute(path, "authenticated JSON path")
    parent, leaf = _split_leaf(candidate, "authenticated JSON path")
    parent_fd, parent_binding = _open_directory_chain(parent, "authenticated JSON parent")
    descriptor = -1
    try:
        try:
            descriptor = os.open(leaf, _regular_flags(), dir_fd=parent_fd)
            first, first_status = _read_regular_fd(descriptor, expected_mode=0o600, expected_nlink=1, maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES)
            _force_sync_regular_leaf(parent_fd, leaf, first_status)
            _json_post_read_test_hook(parent_fd, leaf)
        finally:
            os.close(parent_fd)
        _assert_directory_rebound(
            parent, parent_binding, "authenticated JSON parent"
        )
        rebound_parent_fd, _ = _open_directory_chain(
            parent, "authenticated JSON parent"
        )
        try:
            rebound = os.stat(leaf, dir_fd=rebound_parent_fd, follow_symlinks=False)
            if _leaf_key(rebound) != _leaf_key(first_status):
                raise RuntimeStagingError("authenticated JSON path identity changed")
        finally:
            os.close(rebound_parent_fd)
        second, second_status = _read_regular_fd(descriptor, expected_mode=0o600, expected_nlink=1, maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES)
        if first != second or _leaf_key(first_status) != _leaf_key(second_status):
            raise RuntimeStagingError("authenticated JSON changed across path rebound")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("authenticated JSON contains a duplicate object key")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> object:
        raise ValueError(f"authenticated JSON contains nonfinite number {value}")

    try:
        wire = json.loads(
            first.decode("ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("authenticated JSON is not canonical ASCII JSON") from exc
    if type(wire) is not dict:
        raise ValueError("authenticated JSON must contain an object")
    canonical = (
        json.dumps(
            wire,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    if first != canonical:
        raise ValueError("authenticated JSON bytes are not canonical")
    return (
        wire,
        hashlib.sha256(first).hexdigest(),
        _regular_identity_wire(second_status),
    )


def read_json_authenticated(path: Path) -> tuple[dict[str, object], str]:
    """Read and hash one private JSON object from one pinned descriptor."""

    wire, digest, _ = read_json_authenticated_with_identity(path)
    return wire, digest


def read_regular_authenticated_with_identity(
    path: Path,
) -> tuple[str, dict[str, int]]:
    """Hash one bounded regular leaf from the same pinned FD, even if invalid JSON."""

    candidate = _lexical_absolute(path, "authenticated regular path")
    parent, leaf = _split_leaf(candidate, "authenticated regular path")
    parent_fd, parent_binding = _open_directory_chain(parent, "authenticated regular parent")
    descriptor = -1
    try:
        descriptor = os.open(leaf, _regular_flags(), dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or before.st_size < 0
            or before.st_size > _MAX_AUTHENTICATED_JSON_BYTES
        ):
            raise RuntimeStagingError("authenticated regular leaf metadata is invalid")
        first, first_status = _read_regular_fd(
            descriptor,
            expected_mode=stat.S_IMODE(before.st_mode),
            expected_nlink=before.st_nlink,
            maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES,
        )
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        raise
    finally:
        os.close(parent_fd)
    _assert_directory_rebound(parent, parent_binding, "authenticated regular parent")
    rebound_parent_fd, _ = _open_directory_chain(parent, "authenticated regular parent")
    try:
        rebound = os.stat(leaf, dir_fd=rebound_parent_fd, follow_symlinks=False)
        if _leaf_key(rebound) != _leaf_key(first_status):
            raise RuntimeStagingError("authenticated regular path identity changed")
    finally:
        os.close(rebound_parent_fd)
    try:
        second, second_status = _read_regular_fd(
            descriptor,
            expected_mode=stat.S_IMODE(before.st_mode),
            expected_nlink=before.st_nlink,
            maximum_bytes=_MAX_AUTHENTICATED_JSON_BYTES,
        )
        if first != second or _leaf_key(first_status) != _leaf_key(second_status):
            raise RuntimeStagingError("authenticated regular leaf changed across rebound")
        return hashlib.sha256(first).hexdigest(), _regular_identity_wire(second_status)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def assert_path_absent_authenticated(path: Path) -> None:
    """Require one lexical leaf to be absent across a pinned-parent rebound."""

    candidate = _lexical_absolute(path, "absent path")
    parent, leaf = _split_leaf(candidate, "absent path")
    parent_fd, parent_binding = _open_directory_chain(parent, "absent path parent")
    try:
        if (
            not _force_sync_absent_leaf(parent_fd, leaf)
            and _stat_or_none(parent_fd, leaf) is not None
        ):
            raise RuntimeStagingError("authenticated absent path exists")
    finally:
        os.close(parent_fd)
    _assert_directory_rebound(parent, parent_binding, "absent path parent")
    rebound_fd, _ = _open_directory_chain(parent, "absent path parent")
    try:
        if (
            not _force_sync_absent_leaf(rebound_fd, leaf)
            and _stat_or_none(rebound_fd, leaf) is not None
        ):
            raise RuntimeStagingError("authenticated absent path appeared")
    finally:
        os.close(rebound_fd)


def _root_identity_fd(descriptor: int) -> dict[str, int]:
    status = os.fstat(descriptor)
    if not stat.S_ISDIR(status.st_mode):
        raise RuntimeStagingError("runtime root identity is not a directory")
    return {"device": status.st_dev, "gid": status.st_gid, "inode": status.st_ino, "mode": stat.S_IMODE(status.st_mode), "uid": status.st_uid}


def _counts_match(copied: dict[str, int], inventory: dict[str, object]) -> bool:
    return all(copied[key] == inventory[key] for key in ("directories", "regular_files", "symlinks", "regular_bytes"))


def _copy_counts_from_inventory(inventory: dict[str, object]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in ("directories", "regular_bytes", "regular_files", "symlinks"):
        value = inventory[key]
        if type(value) is not int or value < 0:
            raise RuntimeStagingError("authenticated inventory count is invalid")
        result[key] = value
    return result


def _validate_base_descriptor(base_fd: int, expected_key: tuple[int, int, int, int]) -> None:
    status = os.fstat(base_fd)
    if _directory_key(status) != expected_key or status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) != 0o700:
        raise RuntimeStagingError("destination base descriptor identity changed")


def stage_authenticated_runtime(
    *,
    source: Path,
    destination_base: Path,
    label: str,
    source_commit: str,
    expected_source_filesystems: Iterable[str] = ("nfs", "nfs4"),
    expected_destination_filesystem: str = "xfs",
) -> dict[str, object]:
    """Copy and atomically publish one digest-addressed runtime tree."""

    if type(label) is not str or _LABEL.fullmatch(label) is None:
        raise ValueError("runtime label is invalid")
    if type(source_commit) is not str or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("source_commit must be exactly 40 lowercase hexadecimal characters")
    expected_sources = frozenset(expected_source_filesystems)
    if not expected_sources or any(type(value) is not str or not value for value in expected_sources):
        raise ValueError("expected source filesystems must be nonempty strings")
    if type(expected_destination_filesystem) is not str or not expected_destination_filesystem:
        raise ValueError("expected destination filesystem is invalid")

    started = _utc_now()
    source_root = _lexical_absolute(source, "runtime source")
    source_fd, source_binding = _open_directory_chain(source_root, "runtime source")
    base_fd = -1
    try:
        base_fd, base_binding, base = _open_or_create_base(destination_base)
        base_key = _directory_key(os.fstat(base_fd))
        if _under(source_root, base) or _under(base, source_root):
            raise ValueError("source and destination trees must be disjoint")
        source_mount_before = mount_for_path(source_root)
        destination_mount_before = mount_for_path(base)
        _assert_directory_rebound(source_root, source_binding, "runtime source")
        _assert_directory_rebound(base, base_binding, "destination base")
        _validate_base_descriptor(base_fd, base_key)
        if source_mount_before.filesystem not in expected_sources:
            raise RuntimeStagingError(f"source filesystem {source_mount_before.filesystem!r} is outside the frozen NFS allowlist")
        if destination_mount_before.filesystem != expected_destination_filesystem:
            raise RuntimeStagingError(f"destination filesystem {destination_mount_before.filesystem!r} is not XFS")

        source_descriptor_filesystem_before = _descriptor_filesystem(
            source_fd, "runtime source"
        )
        destination_descriptor_filesystem_before = _descriptor_filesystem(
            base_fd, "destination base"
        )
        _require_descriptor_filesystem(
            source_descriptor_filesystem_before,
            _NFS_SUPER_MAGIC,
            "runtime source",
        )
        _require_descriptor_filesystem(
            destination_descriptor_filesystem_before,
            _XFS_SUPER_MAGIC,
            "destination base",
        )
        if (
            source_descriptor_filesystem_before.mount_id
            != source_mount_before.mount_id
            or destination_descriptor_filesystem_before.mount_id
            != destination_mount_before.mount_id
        ):
            raise RuntimeStagingError(
                "descriptor mount ID does not match the selected mountinfo record"
            )

        source_identity_before = _root_identity_fd(source_fd)
        source_audit_before = _audit_tree_fd(source_fd, require_single_link_files=False)
        source_sha256_before = source_audit_before.sha256
        if _SHA256.fullmatch(source_sha256_before) is None:
            raise RuntimeStagingError("source tree digest is invalid")
        final_name = f"{label}-sha256-{source_sha256_before}"
        final_path = base / final_name
        existing = _stat_or_none(base_fd, final_name)
        if existing is not None:
            if not stat.S_ISDIR(existing.st_mode):
                raise FileExistsError("digest destination exists with the wrong type")
            final_fd = os.open(final_name, _directory_flags(), dir_fd=base_fd)
            try:
                if not _same_stat(existing, os.fstat(final_fd)):
                    raise RuntimeStagingError("existing digest destination identity changed")
                final_audit = _audit_tree_fd(final_fd, require_single_link_files=True)
                published_identity = _root_identity_fd(final_fd)
                published_descriptor_filesystem = _descriptor_filesystem(
                    final_fd, "published runtime"
                )
                final_binding = base_binding + (_directory_key(os.fstat(final_fd)),)
            finally:
                os.close(final_fd)
            _assert_directory_rebound(base, base_binding, "destination base")
            source_audit_after = _audit_tree_fd(source_fd, require_single_link_files=False)
            source_identity_after = _root_identity_fd(source_fd)
            if source_audit_after != source_audit_before or source_identity_after != source_identity_before:
                raise RuntimeStagingError("source runtime changed during reuse authentication")
            if final_audit.sha256 != source_sha256_before or final_audit.inventory != source_audit_before.inventory or final_audit.timestamp_sha256 != source_audit_before.timestamp_sha256 or final_audit.execution_sha256 != source_audit_before.execution_sha256:
                raise FileExistsError("digest destination exists but fails authentication")
            source_descriptor_filesystem_after = _descriptor_filesystem(
                source_fd, "runtime source"
            )
            destination_descriptor_filesystem_after = _descriptor_filesystem(
                base_fd, "destination base"
            )
            source_mount_after = mount_for_path(source_root)
            destination_mount_after = mount_for_path(final_path)
            if (
                source_descriptor_filesystem_after
                != source_descriptor_filesystem_before
                or destination_descriptor_filesystem_after
                != destination_descriptor_filesystem_before
                or published_descriptor_filesystem
                != destination_descriptor_filesystem_before
                or source_mount_after != source_mount_before
                or destination_mount_after != destination_mount_before
                or source_descriptor_filesystem_after.mount_id
                != source_mount_after.mount_id
                or destination_descriptor_filesystem_after.mount_id
                != destination_mount_after.mount_id
            ):
                raise RuntimeStagingError(
                    "descriptor filesystem identity changed during reuse authentication"
                )
            _assert_directory_rebound(final_path, final_binding, "published runtime")
            _assert_directory_rebound(source_root, source_binding, "runtime source")
            _assert_descriptor_filesystem_rebound(
                source_root,
                source_descriptor_filesystem_before,
                source_mount_before,
                "runtime source",
            )
            _assert_descriptor_filesystem_rebound(
                final_path,
                destination_descriptor_filesystem_before,
                destination_mount_before,
                "published runtime",
            )
            return {
                "atomic_rename_noreplace": True,
                "copy_counts": _copy_counts_from_inventory(final_audit.inventory),
                "destination_base": os.fspath(base),
                "destination_descriptor_filesystem_after": destination_descriptor_filesystem_after.to_wire(),
                "destination_descriptor_filesystem_before": destination_descriptor_filesystem_before.to_wire(),
                "destination_mount_after": destination_mount_after.to_wire(),
                "destination_mount_before": destination_mount_before.to_wire(),
                "finished_utc": _utc_now(),
                "hostname": os.uname().nodename,
                "label": label,
                "protocol_id": PROTOCOL_ID,
                "published_identity": published_identity,
                "published_path": os.fspath(final_path),
                "reused_existing": True,
                "schema_version": SCHEMA_VERSION,
                "source_commit": source_commit,
                "source_descriptor_filesystem_after": source_descriptor_filesystem_after.to_wire(),
                "source_descriptor_filesystem_before": source_descriptor_filesystem_before.to_wire(),
                "source_execution_sha256": source_audit_before.execution_sha256,
                "source_identity_after": source_identity_after,
                "source_identity_before": source_identity_before,
                "source_inventory": source_audit_before.inventory,
                "source_mount_after": source_mount_after.to_wire(),
                "source_mount_before": source_mount_before.to_wire(),
                "source_path": os.fspath(source_root),
                "source_sha256": source_sha256_before,
                "source_timestamp_sha256": source_audit_before.timestamp_sha256,
                "source_treated_read_only": True,
                "source_timestamps_preserved": True,
                "started_utc": started,
            }

        stage_name = f".staging-{label}-{os.getpid()}-{secrets.token_hex(16)}"
        os.mkdir(stage_name, 0o700, dir_fd=base_fd)
        os.fsync(base_fd)
        stage_fd = os.open(stage_name, _directory_flags(), dir_fd=base_fd)
        published = False
        try:
            stage_status = os.fstat(stage_fd)
            if not stat.S_ISDIR(stage_status.st_mode) or stage_status.st_uid != os.geteuid() or stat.S_IMODE(stage_status.st_mode) != 0o700:
                raise RuntimeStagingError("unique staging directory identity is invalid")
            source_root_status = os.fstat(source_fd)
            copied = _copy_directory(source_fd, stage_fd, relative=PurePosixPath("."))
            os.fchmod(stage_fd, stat.S_IMODE(source_root_status.st_mode))
            os.utime(stage_fd, ns=(source_root_status.st_atime_ns, source_root_status.st_mtime_ns))
            os.fsync(stage_fd)

            source_audit_after = _audit_tree_fd(source_fd, require_single_link_files=False)
            source_identity_after = _root_identity_fd(source_fd)
            staged_audit = _audit_tree_fd(stage_fd, require_single_link_files=True)
            if source_audit_after != source_audit_before or source_identity_after != source_identity_before:
                raise RuntimeStagingError("source runtime changed across staging")
            if staged_audit.sha256 != source_sha256_before or staged_audit.inventory != source_audit_before.inventory or staged_audit.timestamp_sha256 != source_audit_before.timestamp_sha256 or staged_audit.execution_sha256 != source_audit_before.execution_sha256 or not _counts_match(copied, source_audit_before.inventory):
                raise RuntimeStagingError("staged runtime differs from authenticated source")

            stage_identity = _root_identity_fd(stage_fd)
            _runtime_pre_publish_test_hook(base_fd, stage_name, final_name)
            _validate_base_descriptor(base_fd, base_key)
            stage_rebound = os.stat(stage_name, dir_fd=base_fd, follow_symlinks=False)
            if _root_identity_fd(stage_fd) != stage_identity or (stage_rebound.st_dev, stage_rebound.st_ino) != (stage_identity["device"], stage_identity["inode"]):
                raise RuntimeStagingError("staging directory identity changed before publication")
            _rename_noreplace_at(base_fd, stage_name, base_fd, final_name)
            published = True
            os.fsync(base_fd)
            if _stat_or_none(base_fd, stage_name) is not None:
                raise RuntimeStagingError("staging name remained after atomic publication")
            final_fd = os.open(final_name, _directory_flags(), dir_fd=base_fd)
            try:
                final_status = os.fstat(final_fd)
                if (final_status.st_dev, final_status.st_ino) != (stage_identity["device"], stage_identity["inode"]):
                    raise RuntimeStagingError("published runtime identity differs from staging")
                _runtime_post_publish_test_hook(base_fd, final_name)
                published_audit = _audit_tree_fd(final_fd, require_single_link_files=True)
                published_identity = _root_identity_fd(final_fd)
                published_descriptor_filesystem = _descriptor_filesystem(
                    final_fd, "published runtime"
                )
                final_binding = base_binding + (_directory_key(os.fstat(final_fd)),)
            finally:
                os.close(final_fd)
            _assert_directory_rebound(base, base_binding, "destination base")
            if published_audit.sha256 != source_sha256_before or published_audit.inventory != source_audit_before.inventory or published_audit.timestamp_sha256 != source_audit_before.timestamp_sha256 or published_audit.execution_sha256 != source_audit_before.execution_sha256:
                raise RuntimeStagingError("published runtime failed post-rename authentication")
            source_descriptor_filesystem_after = _descriptor_filesystem(
                source_fd, "runtime source"
            )
            destination_descriptor_filesystem_after = _descriptor_filesystem(
                base_fd, "destination base"
            )
            source_mount_after = mount_for_path(source_root)
            destination_mount_after = mount_for_path(final_path)
            if (
                source_descriptor_filesystem_after
                != source_descriptor_filesystem_before
                or destination_descriptor_filesystem_after
                != destination_descriptor_filesystem_before
                or published_descriptor_filesystem
                != destination_descriptor_filesystem_before
                or source_mount_after != source_mount_before
                or destination_mount_after != destination_mount_before
                or source_descriptor_filesystem_after.mount_id
                != source_mount_after.mount_id
                or destination_descriptor_filesystem_after.mount_id
                != destination_mount_after.mount_id
            ):
                raise RuntimeStagingError(
                    "descriptor filesystem identity changed across staging"
                )
            _validate_base_descriptor(base_fd, base_key)
            _assert_directory_rebound(final_path, final_binding, "published runtime")
            _assert_directory_rebound(source_root, source_binding, "runtime source")
            _assert_descriptor_filesystem_rebound(
                source_root,
                source_descriptor_filesystem_before,
                source_mount_before,
                "runtime source",
            )
            _assert_descriptor_filesystem_rebound(
                final_path,
                destination_descriptor_filesystem_before,
                destination_mount_before,
                "published runtime",
            )
        except BaseException as exc:
            failure = {
                "error": type(exc).__name__,
                "failed_utc": _utc_now(),
                "protocol_id": PROTOCOL_ID,
                "published_before_failure": published,
                "source_sha256_before": source_sha256_before,
                "stage_name": stage_name,
                "status": "failed_closed",
            }
            try:
                payload = (json.dumps(failure, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
                _write_json_at(base_fd, f"{stage_name}.failure.json", payload, run_hook=False)
            except BaseException:
                pass
            raise
        finally:
            os.close(stage_fd)

        return {
            "atomic_rename_noreplace": True,
            "copy_counts": copied,
            "destination_base": os.fspath(base),
            "destination_descriptor_filesystem_after": destination_descriptor_filesystem_after.to_wire(),
            "destination_descriptor_filesystem_before": destination_descriptor_filesystem_before.to_wire(),
            "destination_mount_after": destination_mount_after.to_wire(),
            "destination_mount_before": destination_mount_before.to_wire(),
            "finished_utc": _utc_now(),
            "hostname": os.uname().nodename,
            "label": label,
            "protocol_id": PROTOCOL_ID,
            "published_identity": published_identity,
            "published_path": os.fspath(final_path),
            "reused_existing": False,
            "schema_version": SCHEMA_VERSION,
            "source_commit": source_commit,
            "source_descriptor_filesystem_after": source_descriptor_filesystem_after.to_wire(),
            "source_descriptor_filesystem_before": source_descriptor_filesystem_before.to_wire(),
            "source_execution_sha256": source_audit_before.execution_sha256,
            "source_identity_after": source_identity_after,
            "source_identity_before": source_identity_before,
            "source_inventory": source_audit_before.inventory,
            "source_mount_after": source_mount_after.to_wire(),
            "source_mount_before": source_mount_before.to_wire(),
            "source_path": os.fspath(source_root),
            "source_sha256": source_sha256_before,
            "source_timestamp_sha256": source_audit_before.timestamp_sha256,
            "source_treated_read_only": True,
            "source_timestamps_preserved": True,
            "started_utc": started,
        }
    finally:
        os.close(source_fd)
        if base_fd >= 0:
            os.close(base_fd)
