"""Fail-closed rootless isolation for Rocky-8 GPU workers.

Rocky Linux 8's 4.18 kernel does not provide the Landlock ABI required by
``linux_isolation``.  This additive backend establishes an equivalent bounded
filesystem boundary without pretending Landlock is present:

* the worker is ``execve`` separated with a fixed bootstrap environment;
* fresh user, mount, network, IPC, and PID namespaces are mandatory;
* a dedicated namespace PID 1 reaps descendants and forwards termination;
* a private tmpfs becomes the process root with ``chroot``;
* authenticated inputs are individually bind-mounted read-only at synthetic
  ``/opt/sluice`` targets;
* only explicitly enumerated NVIDIA character devices are mounted;
* every inherited descriptor except one private AF_UNIX ``SOCK_SEQPACKET``
  channel (and null standard descriptors) is closed;
* capabilities are emptied, no-new-privileges and a syscall filter are set,
  and active denial probes are required before an attestation is emitted.

This is a small experiment worker, not a general container runtime.  The
trusted launcher must provide frozen content digests for every bind.  A run is
not final until the child re-hashes every mounted input at shutdown.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping


SCHEMA_VERSION = 2
BACKEND_ID = "rocky8-rootless-chroot-pid-ipc-v2"
MAX_PACKET_BYTES = 1 << 20

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MODULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}\Z")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_GPU_NAME = re.compile(r"nvidia(?:[0-9]+|ctl|-uvm|-uvm-tools)\Z")
_PROC_SELF_EXE = "/proc/self/exe"
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
_INTERPRETER_PIN_KEYS = frozenset(
    {"identity", "path", "procfs_mount", "sha256"}
)
_REGULAR_FILE_IDENTITY_KEYS = frozenset(
    {"device", "gid", "inode", "mode", "nlink", "size", "uid"}
)

_CATEGORIES = frozenset({"runtime", "model_source", "model_cache", "support"})
_CATEGORY_TARGETS = {
    "runtime": PurePosixPath("/opt/sluice/runtime"),
    "model_source": PurePosixPath("/opt/sluice/model_source"),
    "model_cache": PurePosixPath("/opt/sluice/model_cache"),
    "support": PurePosixPath("/opt/sluice/support"),
}
_REQUIRED_CATEGORIES = frozenset({"runtime", "model_source", "model_cache"})
_FORBIDDEN_TARGET_ROOTS = tuple(
    PurePosixPath(value) for value in ("/dev", "/etc", "/home", "/proc", "/root", "/sys", "/u")
)
_SAFE_ENVIRONMENT_NAMES = frozenset(
    {
        "CUDA_VISIBLE_DEVICES",
        "HF_HUB_OFFLINE",
        "HOME",
        "LANG",
        "LC_ALL",
        "MKL_NUM_THREADS",
        "NCCL_P2P_DISABLE",
        "OMP_NUM_THREADS",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "PYTHONPYCACHEPREFIX",
        "TOKENIZERS_PARALLELISM",
        "TRANSFORMERS_OFFLINE",
    }
)
_REQUIRED_ENVIRONMENT = {
    "HF_HUB_OFFLINE": "1",
    "HOME": "/nonexistent",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TOKENIZERS_PARALLELISM": "false",
    "TRANSFORMERS_OFFLINE": "1",
}
_BOOTSTRAP_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
}

_CLONE_NEWNS = 0x00020000
_CLONE_NEWIPC = 0x08000000
_CLONE_NEWUSER = 0x10000000
_CLONE_NEWPID = 0x20000000
_CLONE_NEWNET = 0x40000000
_MS_RDONLY = 1
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_NOEXEC = 8
_MS_REMOUNT = 32
_MS_BIND = 4096
_MS_REC = 16384
_MS_PRIVATE = 1 << 18

_PR_SET_PDEATHSIG = 1
_PR_GET_PDEATHSIG = 2
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_CAPBSET_READ = 23
_PR_CAPBSET_DROP = 24
_PR_SET_SECUREBITS = 28
_PR_GET_SECUREBITS = 27
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_PR_GET_SECCOMP = 21
_PR_SET_SECCOMP = 22
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_IS_SET = 1
_PR_CAP_AMBIENT_CLEAR_ALL = 4

_NAMESPACE_NAMES = ("user", "mnt", "net", "ipc", "pid")
_WATCHDOG_SIGNAL = signal.SIGUSR1
_TERMINATION_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)

_SECBIT_LOCKED_NO_ROOT = 0x0F
_SECCOMP_MODE_FILTER = 2
_AUDIT_ARCH_X86_64 = 0xC000003E
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_LINUX_CAPABILITY_VERSION_3 = 0x20080522

# Linux x86-64 syscall numbers.  The backend refuses every other architecture.
_DENIED_SYSCALLS = {
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "bind": 49,
    "listen": 50,
    "socketpair": 53,
    "ptrace": 101,
    "capset": 126,
    "pivot_root": 155,
    "chroot": 161,
    "mount": 165,
    "umount2": 166,
    "init_module": 175,
    "delete_module": 176,
    "kexec_load": 246,
    "add_key": 248,
    "request_key": 249,
    "keyctl": 250,
    "unshare": 272,
    "accept4": 288,
    "perf_event_open": 298,
    "name_to_handle_at": 303,
    "open_by_handle_at": 304,
    "setns": 308,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "finit_module": 313,
    "seccomp": 317,
    "bpf": 321,
    "userfaultfd": 323,
    "pidfd_send_signal": 424,
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "clone3": 435,
    "pidfd_open": 434,
    "pidfd_getfd": 438,
    "process_madvise": 440,
    "mount_setattr": 442,
    "io_uring_setup": 425,
    "kcmp": 312,
}
_PRCTL_SYSCALL = 157
_ALLOWED_PRCTL_OPTIONS = (
    _PR_GET_PDEATHSIG,
    _PR_GET_DUMPABLE,
    _PR_GET_SECCOMP,
    _PR_CAPBSET_READ,
    _PR_GET_SECUREBITS,
    _PR_GET_NO_NEW_PRIVS,
    _PR_CAP_AMBIENT,
)

_LIBC = ctypes.CDLL(None, use_errno=True)

_WORKER_INLINE_PLACEHOLDER = "@WORKER_SHA256@"
_INTERPRETER_INLINE_PLACEHOLDER = "@INTERPRETER_SHA256@"
_WORKER_INLINE_TEMPLATE = r'''import posix as os,sys
EXPECTED="@WORKER_SHA256@"
EXPECTED_INTERPRETER="@INTERPRETER_SHA256@"
if sys.flags.isolated!=1 or sys.flags.no_site!=1 or sys.dont_write_bytecode is not True: raise RuntimeError("worker inline interpreter flags are incomplete")
prefix=sys.pycache_prefix
if not isinstance(prefix,str) or not prefix.startswith("/"): raise RuntimeError("worker inline pycache prefix is invalid")
prefix_fd=os.open(prefix,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|(os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0))
try:
 prefix_status=os.fstat(prefix_fd)
 if prefix_status.st_mode&0o170000!=0o040000 or prefix_status.st_uid!=os.geteuid() or prefix_status.st_mode&0o7777!=0o700 or os.listdir(prefix_fd): raise RuntimeError("worker inline pycache prefix is not fresh/private/empty")
finally: os.close(prefix_fd)
import hashlib
if len(sys.argv)!=6: raise RuntimeError("worker inline argv schema is invalid")
fd=int(sys.argv[1]); interpreter_fd=int(sys.argv[2]); ipc=sys.argv[3]; parent=sys.argv[4]; path=sys.argv[5]
before=os.fstat(fd)
if before.st_mode&0o170000!=0o100000 or before.st_nlink!=1: raise RuntimeError("worker source descriptor is invalid")
identity=[before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode&0o7777,before.st_nlink,before.st_size]
os.lseek(fd,0,0); chunks=[]
while True:
 block=os.read(fd,1048576)
 if not block: break
 chunks.append(block)
payload=b"".join(chunks); after=os.fstat(fd)
if [after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode&0o7777,after.st_nlink,after.st_size]!=identity or len(payload)!=before.st_size: raise RuntimeError("worker source changed during same-FD read")
if hashlib.sha256(payload).hexdigest()!=EXPECTED: raise RuntimeError("worker source digest mismatch")
interpreter_before=os.fstat(interpreter_fd)
if interpreter_before.st_mode&0o170000!=0o100000 or interpreter_before.st_nlink!=1: raise RuntimeError("worker interpreter descriptor is invalid")
interpreter_identity=[interpreter_before.st_dev,interpreter_before.st_ino,interpreter_before.st_uid,interpreter_before.st_gid,interpreter_before.st_mode&0o7777,interpreter_before.st_nlink,interpreter_before.st_size]
os.lseek(interpreter_fd,0,0); interpreter_digest=hashlib.sha256()
while True:
 block=os.read(interpreter_fd,1048576)
 if not block: break
 interpreter_digest.update(block)
interpreter_after=os.fstat(interpreter_fd)
if [interpreter_after.st_dev,interpreter_after.st_ino,interpreter_after.st_uid,interpreter_after.st_gid,interpreter_after.st_mode&0o7777,interpreter_after.st_nlink,interpreter_after.st_size]!=interpreter_identity: raise RuntimeError("worker interpreter changed during same-FD read")
if interpreter_digest.hexdigest()!=EXPECTED_INTERPRETER: raise RuntimeError("worker interpreter digest mismatch")
sys.argv=[path,"--worker",ipc,parent]
namespace={"__builtins__":__builtins__,"__file__":path,"__name__":"__main__","VERIFIED_INTERPRETER_EXPECTED_SHA256":EXPECTED_INTERPRETER,"VERIFIED_INTERPRETER_SOURCE_FD":interpreter_fd,"VERIFIED_INTERPRETER_SOURCE_IDENTITY":interpreter_identity,"VERIFIED_WORKER_EXPECTED_SHA256":EXPECTED,"VERIFIED_WORKER_SOURCE_FD":fd,"VERIFIED_WORKER_SOURCE_IDENTITY":identity}
exec(compile(payload,path,"exec",dont_inherit=True),namespace)
'''


def _worker_inline_source(
    expected_sha256: str, expected_interpreter_sha256: str
) -> str:
    _valid_sha256(expected_sha256, "worker inline expected SHA-256")
    _valid_sha256(
        expected_interpreter_sha256, "worker inline interpreter SHA-256"
    )
    if _WORKER_INLINE_TEMPLATE.count(_WORKER_INLINE_PLACEHOLDER) != 1:
        raise RockyIsolationError("worker inline loader placeholder is not unique")
    if _WORKER_INLINE_TEMPLATE.count(_INTERPRETER_INLINE_PLACEHOLDER) != 1:
        raise RockyIsolationError(
            "worker inline interpreter placeholder is not unique"
        )
    return _WORKER_INLINE_TEMPLATE.replace(
        _WORKER_INLINE_PLACEHOLDER, expected_sha256
    ).replace(_INTERPRETER_INLINE_PLACEHOLDER, expected_interpreter_sha256)


class RockyIsolationError(RuntimeError):
    """A strict Rocky isolation launch or attestation failed."""


class RockyIsolationUnavailable(RockyIsolationError):
    """The host lacks a control required by the strict fallback."""


class _CUDADiagnosticFailure(RockyIsolationError):
    """A safe, bounded phase label for allocation-only diagnostic failure."""

    def __init__(self, stage: str, cause: BaseException) -> None:
        super().__init__(f"CUDA diagnostic stage {stage} failed")
        self.stage = stage
        self.cause_type = type(cause).__name__
        self.cause_errno = int(cause.errno or 0) if isinstance(cause, OSError) else 0


def _raise_errno(operation: str) -> None:
    value = ctypes.get_errno()
    raise OSError(value, f"{operation} failed")


def _prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
    ctypes.set_errno(0)
    result = _LIBC.prctl(option, arg2, arg3, arg4, arg5)
    if result < 0:
        _raise_errno("prctl")
    return int(result)


def _valid_sha256(value: str, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


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


def _canonical_existing(path: Path, name: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"{name} must not be a symbolic link")
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{name} must exist") from exc
    return canonical


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _source_open_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _canonical_lexical_absolute(path: Path, name: str) -> Path:
    candidate = Path(path)
    text = os.fspath(candidate)
    if (
        not candidate.is_absolute()
        or text.startswith("//")
        or ".." in candidate.parts
        or "\x00" in text
        or text != candidate.as_posix()
    ):
        raise ValueError(f"{name} must be a canonical absolute lexical path")
    return candidate


def _canonical_wire_absolute(value: object, name: str) -> Path:
    """Reject lexical aliases before a wire path is normalized by ``Path``."""

    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical absolute path string")
    candidate = Path(value)
    if (
        not candidate.is_absolute()
        or value.startswith("//")
        or ".." in candidate.parts
        or "\x00" in value
        or value != candidate.as_posix()
    ):
        raise ValueError(f"{name} must be a canonical absolute path string")
    return candidate


def _directory_identity(status: os.stat_result) -> dict[str, int]:
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("authenticated path component is not a directory")
    return {
        "device": status.st_dev,
        "gid": status.st_gid,
        "inode": status.st_ino,
        "mode": stat.S_IMODE(status.st_mode),
        "uid": status.st_uid,
    }


def _source_identity(status: os.stat_result) -> dict[str, object]:
    if stat.S_ISDIR(status.st_mode):
        kind = "directory"
    elif stat.S_ISREG(status.st_mode):
        kind = "regular"
    else:
        raise ValueError("bind source must be a regular file or directory")
    return {
        "device": status.st_dev,
        "gid": status.st_gid,
        "inode": status.st_ino,
        "kind": kind,
        "mode": stat.S_IMODE(status.st_mode),
        "uid": status.st_uid,
    }


def _open_source_chain(
    path: Path, name: str
) -> tuple[int, tuple[dict[str, int], ...], dict[str, object]]:
    """Pin a lexical source root without following any path-component symlink."""

    candidate = _canonical_lexical_absolute(path, name)
    descriptor = os.open("/", _directory_open_flags())
    chain: list[dict[str, int]] = [_directory_identity(os.fstat(descriptor))]
    try:
        for component in candidate.parts[1:-1]:
            if not component or component in {".", ".."} or "/" in component:
                raise ValueError(f"{name} has an invalid component")
            child = os.open(component, _directory_open_flags(), dir_fd=descriptor)
            try:
                chain.append(_directory_identity(os.fstat(child)))
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        leaf = candidate.name
        if not leaf or leaf in {".", ".."} or "/" in leaf:
            raise ValueError(f"{name} must identify one source object")
        source_fd = os.open(leaf, _source_open_flags(), dir_fd=descriptor)
        identity = _source_identity(os.fstat(source_fd))
        return source_fd, tuple(chain), identity
    except BaseException:
        raise
    finally:
        os.close(descriptor)


def _exact_identity_wire(value: object, *, source: bool) -> dict[str, object]:
    required = {"device", "gid", "inode", "mode", "uid"}
    if source:
        required.add("kind")
    if type(value) is not dict or set(value) != required:
        raise ValueError("authenticated source identity schema is invalid")
    for key in ("device", "gid", "inode", "mode", "uid"):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError("authenticated source identity value is invalid")
    if value["inode"] == 0 or value["mode"] > 0o7777:
        raise ValueError("authenticated source identity is outside its range")
    if source and value["kind"] not in {"directory", "regular"}:
        raise ValueError("authenticated source identity kind is invalid")
    return dict(value)


def _assert_source_rebound(
    path: Path,
    source_fd: int,
    expected_chain: tuple[dict[str, int], ...],
    expected_identity: dict[str, object],
) -> None:
    try:
        descriptor, chain, identity = _open_source_chain(path, "bind source")
    except (OSError, ValueError) as exc:
        raise RockyIsolationError("bind source lexical identity changed") from exc
    try:
        pinned = _source_identity(os.fstat(source_fd))
        if chain != expected_chain or identity != expected_identity or pinned != expected_identity:
            raise RockyIsolationError("bind source lexical identity changed")
        rebound = os.fstat(descriptor)
        original = os.fstat(source_fd)
        if (rebound.st_dev, rebound.st_ino) != (original.st_dev, original.st_ino):
            raise RockyIsolationError("bind source path no longer names the pinned object")
    finally:
        os.close(descriptor)


def _namespace_stable_source_identity_equal(
    expected: object,
    observed: object,
    *,
    source: bool,
) -> bool:
    """Compare identity fields whose representation survives a user namespace.

    Linux translates ``st_uid`` and ``st_gid`` through the active user-ID maps.
    The launcher and outer worker already require the complete identities before
    ``unshare``.  Once inside that namespace, the retained descriptor plus
    device, inode, mode, and kind remain the exact path/object binding.
    """

    expected_wire = _exact_identity_wire(expected, source=source)
    observed_wire = _exact_identity_wire(observed, source=source)
    keys = ("device", "inode", "mode") + (("kind",) if source else ())
    return all(expected_wire[key] == observed_wire[key] for key in keys)


def _assert_source_rebound_after_unshare(
    path: Path,
    source_fd: int,
    expected_chain: tuple[dict[str, int], ...],
    expected_identity: dict[str, object],
) -> None:
    """Rebind a retained source after user-namespace UID/GID translation."""

    try:
        descriptor, chain, identity = _open_source_chain(
            path, "namespaced bind source"
        )
    except (OSError, ValueError) as exc:
        raise RockyIsolationError("namespaced bind source identity changed") from exc
    try:
        pinned = _source_identity(os.fstat(source_fd))
        if (
            len(chain) != len(expected_chain)
            or any(
                not _namespace_stable_source_identity_equal(
                    expected_item, observed_item, source=False
                )
                for expected_item, observed_item in zip(
                    expected_chain, chain, strict=True
                )
            )
            or not _namespace_stable_source_identity_equal(
                expected_identity, identity, source=True
            )
            or not _namespace_stable_source_identity_equal(
                expected_identity, pinned, source=True
            )
        ):
            raise RockyIsolationError("namespaced bind source identity changed")
        rebound = os.fstat(descriptor)
        original = os.fstat(source_fd)
        if (rebound.st_dev, rebound.st_ino) != (
            original.st_dev,
            original.st_ino,
        ):
            raise RockyIsolationError(
                "namespaced bind path no longer names the pinned object"
            )
    finally:
        os.close(descriptor)


def _source_contains_any_inode(source: Path, identities: frozenset[tuple[int, int]]) -> bool:
    def matches(path: Path) -> bool:
        status = path.stat(follow_symlinks=False)
        return (status.st_dev, status.st_ino) in identities

    if matches(source):
        return True
    if not source.is_dir():
        return False
    for directory, names, files in os.walk(source, followlinks=False):
        base = Path(directory)
        for name in names + files:
            path = base / name
            if path.is_symlink():
                continue
            if matches(path):
                return True
    return False


def sha256_file(path: Path) -> str:
    """Hash one stable regular file without following a substituted symlink."""

    canonical = Path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(os.fspath(canonical), flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("authenticated file must be regular")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if not stable:
            raise RockyIsolationError("authenticated file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _record(hasher: Any, *values: object) -> None:
    encoded = json.dumps(
        list(values),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    hasher.update(struct.pack(">Q", len(encoded)))
    hasher.update(encoded)


def _stable_stat(before: os.stat_result, after: os.stat_result) -> bool:
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


def _sha256_regular_fd(descriptor: int) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("authenticated descriptor must be regular")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(descriptor, 1 << 20)
        if not block:
            break
        digest.update(block)
    if not _stable_stat(before, os.fstat(descriptor)):
        raise RockyIsolationError("authenticated file changed while hashing")
    return digest.hexdigest()


def _read_proc_generated(descriptor: int, maximum: int, name: str) -> bytes:
    """Read a generated procfs regular file twice from one pinned FD."""

    def metadata() -> tuple[int, int, int, int, int, int]:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise RockyIsolationError(f"{name} is not a procfs regular file")
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
                raise RockyIsolationError(f"{name} exceeds its size limit")
        return b"".join(chunks)

    before = metadata()
    first = once()
    middle = metadata()
    second = once()
    after = metadata()
    if not first or first != second or before != middle or middle != after:
        raise RockyIsolationError(f"{name} changed during same-FD read")
    return first


def _procfs_unescape(value: str) -> str:
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


def _procfs_mount_identity() -> dict[str, object]:
    """Bind the exact procfs mount used by the sole magic-link exception."""

    proc_path = Path("/proc")
    proc_fd, proc_chain, proc_identity = _open_source_chain(
        proc_path, "procfs root"
    )
    pid_fd = -1
    mountinfo_fd = -1
    fdinfo_directory_fd = -1
    fdinfo_fd = -1
    try:
        proc_status = os.fstat(proc_fd)
        if (
            proc_identity["kind"] != "directory"
            or proc_status.st_uid != 0
            or stat.S_IMODE(proc_status.st_mode) != 0o555
        ):
            raise RockyIsolationError("procfs root ownership/mode is invalid")
        pid_fd = os.open(str(os.getpid()), _directory_open_flags(), dir_fd=proc_fd)
        _directory_identity(os.fstat(pid_fd))
        mountinfo_fd = os.open("mountinfo", _source_open_flags(), dir_fd=pid_fd)
        mountinfo = _read_proc_generated(
            mountinfo_fd, 4 << 20, "procfs mountinfo"
        )
        fdinfo_directory_fd = os.open(
            "fdinfo", _directory_open_flags(), dir_fd=pid_fd
        )
        fdinfo_fd = os.open(
            str(proc_fd), _source_open_flags(), dir_fd=fdinfo_directory_fd
        )
        fdinfo = _read_proc_generated(fdinfo_fd, 1 << 20, "procfs fdinfo")
        _assert_source_rebound(
            proc_path,
            proc_fd,
            proc_chain,
            proc_identity,
        )
    finally:
        for descriptor in (
            fdinfo_fd,
            fdinfo_directory_fd,
            mountinfo_fd,
            pid_fd,
            proc_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
    try:
        fdinfo_lines = fdinfo.decode("ascii").splitlines()
        mountinfo_lines = mountinfo.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RockyIsolationError("procfs identity is not ASCII") from exc
    mount_ids = [
        line.split(":", 1)[1].strip()
        for line in fdinfo_lines
        if line.startswith("mnt_id:")
    ]
    if (
        len(mount_ids) != 1
        or re.fullmatch(r"[1-9][0-9]*", mount_ids[0]) is None
    ):
        raise RockyIsolationError("procfs fdinfo has no exact mount ID")
    mount_id = int(mount_ids[0])
    matches: list[dict[str, object]] = []
    for line in mountinfo_lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            raise RockyIsolationError("procfs mountinfo record is malformed")
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 6 or len(right_fields) < 3:
            raise RockyIsolationError("procfs mountinfo record is short")
        if left_fields[0] != str(mount_id):
            continue
        matches.append(
            {
                "filesystem": right_fields[0],
                "mount_id": mount_id,
                "mount_options": sorted(left_fields[5].split(",")),
                "mountpoint": _procfs_unescape(left_fields[4]),
                "root": _procfs_unescape(left_fields[3]),
                "source": _procfs_unescape(right_fields[1]),
                "super_options": sorted(right_fields[2].split(",")),
            }
        )
    if len(matches) != 1:
        raise RockyIsolationError("procfs mount ID has no unique mountinfo record")
    return _exact_procfs_mount_wire(matches[0])


def _exact_procfs_mount_wire(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _PROCFS_MOUNT_KEYS:
        raise ValueError("procfs mount identity schema is invalid")
    if (
        value["filesystem"] != "proc"
        or value["mountpoint"] != "/proc"
        or value["root"] != "/"
        or value["source"] != "proc"
        or type(value["mount_id"]) is not int
        or value["mount_id"] <= 0
    ):
        raise ValueError("procfs mount identity is invalid")
    for key in ("mount_options", "super_options"):
        options = value[key]
        if (
            type(options) is not list
            or any(type(option) is not str or not option for option in options)
            or options != sorted(set(options))
        ):
            raise ValueError("procfs mount options are invalid")
    return dict(value)


def _regular_file_identity(status: os.stat_result) -> dict[str, int]:
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise RockyIsolationError(
            "verified interpreter is not a single-link regular file"
        )
    return {
        "device": status.st_dev,
        "gid": status.st_gid,
        "inode": status.st_ino,
        "mode": stat.S_IMODE(status.st_mode),
        "nlink": status.st_nlink,
        "size": status.st_size,
        "uid": status.st_uid,
    }


def _interpreter_file_identity(status: os.stat_result) -> dict[str, int]:
    identity = _regular_file_identity(status)
    if (
        status.st_uid != os.geteuid()
        or status.st_gid != os.getegid()
        or stat.S_IMODE(status.st_mode) != 0o755
        or status.st_size <= 0
    ):
        raise RockyIsolationError("verified interpreter ownership/mode is invalid")
    return identity


def _exact_interpreter_pin_wire(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _INTERPRETER_PIN_KEYS:
        raise ValueError("verified interpreter pin schema is invalid")
    identity = value["identity"]
    if type(identity) is not dict or set(identity) != _REGULAR_FILE_IDENTITY_KEYS:
        raise ValueError("verified interpreter identity schema is invalid")
    for key in _REGULAR_FILE_IDENTITY_KEYS:
        if type(identity[key]) is not int or identity[key] < 0:
            raise ValueError("verified interpreter identity value is invalid")
    if (
        identity["inode"] == 0
        or identity["mode"] != 0o755
        or identity["nlink"] != 1
        or identity["size"] <= 0
    ):
        raise ValueError("verified interpreter identity is outside its range")
    path = _canonical_wire_absolute(value["path"], "interpreter realpath")
    digest = _valid_sha256(value["sha256"], "interpreter pin SHA-256")
    return {
        "identity": dict(identity),
        "path": os.fspath(path),
        "procfs_mount": _exact_procfs_mount_wire(value["procfs_mount"]),
        "sha256": digest,
    }


def _proc_self_exe_state(descriptor: int) -> tuple[dict[str, int], str]:
    identity = _interpreter_file_identity(os.fstat(descriptor))
    fd_magic = f"/proc/self/fd/{descriptor}"
    exe_realpath = os.path.realpath(_PROC_SELF_EXE)
    fd_realpath = os.path.realpath(fd_magic)
    if (
        not exe_realpath.startswith("/")
        or "\x00" in exe_realpath
        or exe_realpath != fd_realpath
    ):
        raise RockyIsolationError("interpreter procfs realpath binding differs")
    for magic_path in (_PROC_SELF_EXE, fd_magic):
        if _interpreter_file_identity(os.stat(magic_path)) != identity:
            raise RockyIsolationError("interpreter procfs inode binding differs")
    return identity, exe_realpath


def _pin_proc_self_exe(expected_sha256: str) -> tuple[int, dict[str, object]]:
    expected = _valid_sha256(expected_sha256, "interpreter pin SHA-256")
    procfs_mount = _procfs_mount_identity()
    # O_NOFOLLOW is intentionally omitted only for this literal kernel magic link.
    descriptor = os.open(_PROC_SELF_EXE, os.O_RDONLY | os.O_CLOEXEC)
    try:
        identity, realpath = _proc_self_exe_state(descriptor)
        observed = _sha256_regular_fd(descriptor)
        if observed != expected:
            raise RockyIsolationError(
                "interpreter authentication failed before launch"
            )
        wire = {
            "identity": identity,
            "path": realpath,
            "procfs_mount": procfs_mount,
            "sha256": observed,
        }
        _revalidate_proc_self_exe(descriptor, wire)
        return descriptor, wire
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_proc_self_exe(
    descriptor: int, expected_wire: object
) -> dict[str, object]:
    expected = _exact_interpreter_pin_wire(expected_wire)
    if _procfs_mount_identity() != expected["procfs_mount"]:
        raise RockyIsolationError("interpreter procfs mount identity drifted")
    identity, realpath = _proc_self_exe_state(descriptor)
    if (
        identity != expected["identity"]
        or realpath != expected["path"]
        or _sha256_regular_fd(descriptor) != expected["sha256"]
    ):
        raise RockyIsolationError("verified interpreter identity drifted")
    return expected


def _verified_execution_identity_equal(
    expected: list[int], observed: list[int], *, after_unshare: bool
) -> bool:
    if type(after_unshare) is not bool:
        raise TypeError("after_unshare must be Boolean")
    if not after_unshare:
        return observed == expected
    # UID/GID are translated by the active user namespace.  The full values
    # were checked before unshare; retain every namespace-stable field here.
    stable_indexes = (0, 1, 4, 5, 6)
    return all(observed[index] == expected[index] for index in stable_indexes)


def _executing_worker_source_sha256(*, after_unshare: bool = False) -> str:
    descriptor = globals().get("VERIFIED_WORKER_SOURCE_FD")
    expected = globals().get("VERIFIED_WORKER_EXPECTED_SHA256")
    expected_identity = globals().get("VERIFIED_WORKER_SOURCE_IDENTITY")
    if type(descriptor) is not int or descriptor < 3:
        raise RockyIsolationError("worker did not inherit its verified source descriptor")
    if type(expected_identity) is not list or len(expected_identity) != 7 or any(
        type(value) is not int or value < 0 for value in expected_identity
    ):
        raise RockyIsolationError("worker verified source identity is invalid")
    status = os.fstat(descriptor)
    observed_identity = [
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
        status.st_nlink,
        status.st_size,
    ]
    if not _verified_execution_identity_equal(
        expected_identity, observed_identity, after_unshare=after_unshare
    ):
        raise RockyIsolationError("worker verified source descriptor identity changed")
    digest = _sha256_regular_fd(descriptor)
    if digest != expected:
        raise RockyIsolationError("worker verified source descriptor digest changed")
    return digest


def _executing_interpreter_sha256(*, after_unshare: bool = False) -> str:
    descriptor = globals().get("VERIFIED_INTERPRETER_SOURCE_FD")
    expected = globals().get("VERIFIED_INTERPRETER_EXPECTED_SHA256")
    expected_identity = globals().get("VERIFIED_INTERPRETER_SOURCE_IDENTITY")
    if type(descriptor) is not int or descriptor < 3:
        raise RockyIsolationError(
            "worker did not inherit its verified interpreter descriptor"
        )
    if type(expected_identity) is not list or len(expected_identity) != 7 or any(
        type(value) is not int or value < 0 for value in expected_identity
    ):
        raise RockyIsolationError("worker verified interpreter identity is invalid")
    status = os.fstat(descriptor)
    observed_identity = [
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
        status.st_nlink,
        status.st_size,
    ]
    if not _verified_execution_identity_equal(
        expected_identity, observed_identity, after_unshare=after_unshare
    ):
        raise RockyIsolationError(
            "worker verified interpreter descriptor identity changed"
        )
    digest = _sha256_regular_fd(descriptor)
    if digest != expected:
        raise RockyIsolationError(
            "worker verified interpreter descriptor digest changed"
        )
    return digest


def _executing_identity_fds() -> frozenset[int]:
    descriptors = {
        globals().get("VERIFIED_WORKER_SOURCE_FD"),
        globals().get("VERIFIED_INTERPRETER_SOURCE_FD"),
    }
    if (
        len(descriptors) != 2
        or any(type(descriptor) is not int or descriptor < 3 for descriptor in descriptors)
    ):
        raise RockyIsolationError("verified execution descriptors are invalid")
    return frozenset(descriptors)


def _validate_tree_links(
    entry_types: dict[tuple[str, ...], str],
    links: dict[tuple[str, ...], str],
) -> None:
    for link_path, target in links.items():
        resolved = list(link_path[:-1])
        pending = list(PurePosixPath(target).parts)
        seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
        while pending:
            state = (tuple(resolved), tuple(pending))
            if state in seen:
                raise ValueError("authenticated tree has a cyclic symlink")
            seen.add(state)
            component = pending.pop(0)
            if component in {"", "."}:
                continue
            if component == "..":
                if not resolved:
                    raise ValueError("authenticated tree symlink escapes its root")
                resolved.pop()
                continue
            resolved.append(component)
            current = tuple(resolved)
            kind = entry_types.get(current)
            if kind is None:
                raise ValueError("authenticated tree has a broken symlink")
            if kind == "L":
                resolved.pop()
                pending = list(PurePosixPath(links[current]).parts) + pending
            elif pending and kind != "D":
                raise ValueError("authenticated tree symlink traverses a nondirectory")
        if tuple(resolved) not in entry_types:
            raise ValueError("authenticated tree has a broken symlink")


def _sha256_tree_fd(root_fd: int) -> str:
    """Hash a tree exclusively through one already-pinned root descriptor."""

    hasher = hashlib.sha256(b"sluice-authenticated-tree-v1\0")
    entry_types: dict[tuple[str, ...], str] = {(): "D"}
    links: dict[tuple[str, ...], str] = {}

    def visit(directory_fd: int, relative: PurePosixPath) -> None:
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("authenticated tree directory changed type")
        names_before = tuple(
            sorted(os.listdir(directory_fd), key=lambda value: value.encode("utf-8"))
        )
        _record(hasher, "D", relative.as_posix(), stat.S_IMODE(before.st_mode))
        for name in names_before:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError("authenticated tree entry name is invalid")
            status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            child_relative = relative / name
            parts = tuple(child_relative.parts)
            if stat.S_ISDIR(status.st_mode):
                entry_types[parts] = "D"
                child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
                try:
                    if not _stable_stat(status, os.fstat(child_fd)):
                        raise RockyIsolationError(
                            "authenticated directory changed before recursion"
                        )
                    visit(child_fd, child_relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(status.st_mode):
                entry_types[parts] = "F"
                child_fd = os.open(name, _source_open_flags(), dir_fd=directory_fd)
                try:
                    if not _stable_stat(status, os.fstat(child_fd)):
                        raise RockyIsolationError(
                            "authenticated regular file changed before hashing"
                        )
                    content = _sha256_regular_fd(child_fd)
                finally:
                    os.close(child_fd)
                _record(
                    hasher,
                    "F",
                    child_relative.as_posix(),
                    stat.S_IMODE(status.st_mode),
                    status.st_size,
                    content,
                )
            elif stat.S_ISLNK(status.st_mode):
                target = os.readlink(name, dir_fd=directory_fd)
                if PurePosixPath(target).is_absolute():
                    raise ValueError("authenticated tree symlink target must be relative")
                if not _stable_stat(
                    status,
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                ):
                    raise RockyIsolationError("authenticated symlink changed while reading")
                entry_types[parts] = "L"
                links[parts] = target
                _record(hasher, "L", child_relative.as_posix(), target)
            else:
                raise ValueError("authenticated tree contains a special file")
        names_after = tuple(
            sorted(os.listdir(directory_fd), key=lambda value: value.encode("utf-8"))
        )
        if names_before != names_after or not _stable_stat(before, os.fstat(directory_fd)):
            raise RockyIsolationError("authenticated tree changed while hashing")

    visit(root_fd, PurePosixPath("."))
    _validate_tree_links(entry_types, links)
    return hasher.hexdigest()


def sha256_tree(root: Path) -> str:
    """Return a deterministic, path/type/mode/content-bound tree digest.

    Symlinks are recorded as symlinks and may only resolve within the tree.
    Special files and concurrent directory mutation are rejected.
    """

    descriptor, chain, identity = _open_source_chain(Path(root), "authenticated tree")
    try:
        if identity["kind"] != "directory":
            raise ValueError("authenticated tree root must be a directory")
        digest = _sha256_tree_fd(descriptor)
        _assert_source_rebound(Path(root), descriptor, chain, identity)
        return digest
    finally:
        os.close(descriptor)


def _digest_source_fd(bind: "AuthenticatedBind") -> str:
    _assert_source_rebound(
        bind.source,
        bind.source_fd,
        bind.source_chain_identity,
        bind.source_identity,
    )
    if bind.source_identity["kind"] == "directory":
        return _sha256_tree_fd(bind.source_fd)
    return _sha256_regular_fd(bind.source_fd)


def _digest_source_fd_after_unshare(bind: "AuthenticatedBind") -> str:
    _assert_source_rebound_after_unshare(
        bind.source,
        bind.source_fd,
        bind.source_chain_identity,
        bind.source_identity,
    )
    if bind.source_identity["kind"] == "directory":
        return _sha256_tree_fd(bind.source_fd)
    return _sha256_regular_fd(bind.source_fd)


def _bind_source_fds(config: "RockyGPUIsolationConfig") -> tuple[int, ...]:
    descriptors = tuple(bind.source_fd for bind in config.binds)
    if (
        any(type(value) is not int or value < 3 for value in descriptors)
        or len(set(descriptors)) != len(descriptors)
    ):
        raise RockyIsolationError("authenticated bind descriptors are not exact and unique")
    return descriptors


def _close_bind_source_fds(config: "RockyGPUIsolationConfig") -> None:
    for descriptor in _bind_source_fds(config):
        try:
            os.close(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise


def _digest_path(path: Path) -> str:
    if path.is_dir():
        return sha256_tree(path)
    return sha256_file(path)


@dataclass(frozen=True)
class AuthenticatedBind:
    label: str
    category: str
    source: Path
    target: PurePosixPath | str
    expected_sha256: str
    probe_relative: PurePosixPath | str
    allow_exec: bool = False
    source_fd: int | None = None
    source_identity: Mapping[str, object] | None = None
    source_chain_identity: tuple[Mapping[str, object], ...] | list[Mapping[str, object]] = ()

    @property
    def source_is_directory(self) -> bool:
        return self.source_identity["kind"] == "directory"

    def __post_init__(self) -> None:
        if type(self.label) is not str or _LABEL.fullmatch(self.label) is None:
            raise ValueError("bind label is invalid")
        if self.category not in _CATEGORIES:
            raise ValueError("bind category is invalid")
        source = _canonical_lexical_absolute(Path(self.source), "bind source")
        opened_here = self.source_fd is None
        if opened_here:
            descriptor, observed_chain, observed_identity = _open_source_chain(
                source, "bind source"
            )
        else:
            if type(self.source_fd) is not int or self.source_fd < 3:
                raise ValueError("bind source descriptor is invalid")
            descriptor = self.source_fd
            if type(self.source_chain_identity) not in (tuple, list):
                raise ValueError("bind source-chain identity is invalid")
            observed_chain = tuple(
                _exact_identity_wire(item, source=False)
                for item in self.source_chain_identity
            )
            if not observed_chain:
                raise ValueError("bind source-chain identity is empty")
            observed_identity = _exact_identity_wire(
                self.source_identity, source=True
            )
            if _source_identity(os.fstat(descriptor)) != observed_identity:
                raise ValueError("bind source descriptor identity is invalid")
            _assert_source_rebound(
                source, descriptor, observed_chain, observed_identity
            )
        try:
            object.__setattr__(self, "source", source)
            object.__setattr__(self, "source_fd", descriptor)
            object.__setattr__(self, "source_identity", observed_identity)
            object.__setattr__(self, "source_chain_identity", observed_chain)
            target_text = str(self.target)
            target = PurePosixPath(target_text)
            if (
                not target.is_absolute()
                or ".." in target.parts
                or target_text != target.as_posix()
                or target == PurePosixPath("/")
            ):
                raise ValueError("bind target must be a canonical absolute path")
            category_root = _CATEGORY_TARGETS[self.category]
            if target != category_root and category_root not in target.parents:
                raise ValueError("bind target is outside its category target")
            if any(
                target == root or root in target.parents
                for root in _FORBIDDEN_TARGET_ROOTS
            ):
                raise ValueError("bind target enters a forbidden host namespace")
            object.__setattr__(self, "target", target)
            _valid_sha256(self.expected_sha256, "expected_sha256")
            probe_text = str(self.probe_relative)
            probe = PurePosixPath(probe_text)
            if observed_identity["kind"] == "regular":
                if probe_text != ".":
                    raise ValueError("a file bind probe_relative must be '.'")
            else:
                if (
                    probe.is_absolute()
                    or ".." in probe.parts
                    or probe_text != probe.as_posix()
                ):
                    raise ValueError(
                        "bind probe_relative must be canonical and relative"
                    )
                probe_source = source.joinpath(*probe.parts)
                try:
                    resolved_probe = probe_source.resolve(strict=True)
                except OSError as exc:
                    raise ValueError("bind read probe must exist") from exc
                if not _under(resolved_probe, source) or not resolved_probe.is_file():
                    raise ValueError(
                        "bind read probe must be a regular file within its source"
                    )
            object.__setattr__(self, "probe_relative", probe)
            if type(self.allow_exec) is not bool:
                raise TypeError("allow_exec must be Boolean")
            if self.allow_exec and self.category not in {"runtime", "support"}:
                raise ValueError(
                    "only authenticated runtime/support binds may execute"
                )
            _assert_source_rebound(source, descriptor, observed_chain, observed_identity)
        except BaseException:
            if opened_here:
                os.close(descriptor)
            raise

    def to_wire(self) -> dict[str, object]:
        return {
            "allow_exec": self.allow_exec,
            "category": self.category,
            "expected_sha256": self.expected_sha256,
            "label": self.label,
            "probe_relative": self.probe_relative.as_posix(),
            "source": os.fspath(self.source),
            "source_chain_identity": [dict(item) for item in self.source_chain_identity],
            "source_fd": self.source_fd,
            "source_identity": dict(self.source_identity),
            "target": self.target.as_posix(),
        }

    @classmethod
    def from_wire(cls, wire: Mapping[str, object]) -> "AuthenticatedBind":
        required = {
            "allow_exec",
            "category",
            "expected_sha256",
            "label",
            "probe_relative",
            "source",
            "source_chain_identity",
            "source_fd",
            "source_identity",
            "target",
        }
        if type(wire) is not dict or set(wire) != required:
            raise ValueError("bind wire schema is invalid")
        if any(
            type(wire[name]) is not str
            for name in (
                "category",
                "expected_sha256",
                "label",
                "probe_relative",
                "source",
                "target",
            )
        ):
            raise ValueError("bind wire string fields are invalid")
        source = _canonical_wire_absolute(wire["source"], "bind wire source")
        return cls(
            allow_exec=wire["allow_exec"],
            category=wire["category"],
            expected_sha256=wire["expected_sha256"],
            label=wire["label"],
            probe_relative=wire["probe_relative"],
            source=source,
            source_chain_identity=wire["source_chain_identity"],
            source_fd=wire["source_fd"],
            source_identity=wire["source_identity"],
            target=wire["target"],
        )


@dataclass(frozen=True)
class GPUDevice:
    source: Path
    target: PurePosixPath | str
    major: int
    minor: int

    def __post_init__(self) -> None:
        source = _canonical_existing(Path(self.source), "GPU device")
        status = source.stat(follow_symlinks=False)
        if not stat.S_ISCHR(status.st_mode):
            raise ValueError("GPU device source must be a character device")
        if _GPU_NAME.fullmatch(source.name) is None:
            raise ValueError("GPU device source is not an exact NVIDIA compute device")
        object.__setattr__(self, "source", source)
        target = PurePosixPath(str(self.target))
        if target != PurePosixPath("/dev") / source.name:
            raise ValueError("GPU device target must preserve its exact /dev basename")
        object.__setattr__(self, "target", target)
        for name in ("major", "minor"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise TypeError(f"GPU device {name} must be a nonnegative integer")
        if (self.major, self.minor) != (os.major(status.st_rdev), os.minor(status.st_rdev)):
            raise ValueError("GPU device major/minor do not match the live host device")

    @classmethod
    def from_host(cls, source: Path) -> "GPUDevice":
        path = _canonical_existing(Path(source), "GPU device")
        status = path.stat(follow_symlinks=False)
        return cls(
            source=path,
            target=PurePosixPath("/dev") / path.name,
            major=os.major(status.st_rdev),
            minor=os.minor(status.st_rdev),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "major": self.major,
            "minor": self.minor,
            "source": os.fspath(self.source),
            "target": self.target.as_posix(),
        }

    @classmethod
    def from_wire(cls, wire: Mapping[str, object]) -> "GPUDevice":
        if type(wire) is not dict or set(wire) != {"major", "minor", "source", "target"}:
            raise ValueError("GPU device wire schema is invalid")
        source = _canonical_wire_absolute(wire["source"], "GPU device wire source")
        target = _canonical_wire_absolute(wire["target"], "GPU device wire target")
        return cls(
            major=wire["major"],
            minor=wire["minor"],
            source=source,
            target=target,
        )


@dataclass(frozen=True)
class ProtectedHostPaths:
    shared_home: Path
    ledger: Path
    signing_key: Path
    tool_credential: Path
    raw_audit: Path

    def __post_init__(self) -> None:
        for name in ("shared_home", "ledger", "signing_key", "tool_credential", "raw_audit"):
            value = _canonical_existing(Path(getattr(self, name)), f"protected {name}")
            object.__setattr__(self, name, value)
        if len(set(self.as_mapping().values())) != 5:
            raise ValueError("protected host probes must be distinct")

    def as_mapping(self) -> dict[str, Path]:
        return {
            "ledger": self.ledger,
            "raw_audit": self.raw_audit,
            "shared_home": self.shared_home,
            "signing_key": self.signing_key,
            "tool_credential": self.tool_credential,
        }

    def to_wire(self) -> dict[str, str]:
        return {name: os.fspath(path) for name, path in self.as_mapping().items()}

    @classmethod
    def from_wire(cls, wire: Mapping[str, object]) -> "ProtectedHostPaths":
        required = {"shared_home", "ledger", "signing_key", "tool_credential", "raw_audit"}
        if type(wire) is not dict or set(wire) != required or any(
            type(value) is not str for value in wire.values()
        ):
            raise ValueError("protected paths wire schema is invalid")
        return cls(
            **{
                name: _canonical_wire_absolute(
                    wire[name], f"protected {name} wire path"
                )
                for name in required
            }
        )


def _validate_environment(environment: Mapping[str, str], devices: tuple[GPUDevice, ...]) -> dict[str, str]:
    if type(environment) is not dict or any(
        type(name) is not str or type(value) is not str
        for name, value in environment.items()
    ):
        raise TypeError("workload environment must be an exact string dictionary")
    if set(environment) - _SAFE_ENVIRONMENT_NAMES:
        raise ValueError("workload environment contains a loader or secret-capable name")
    for name, expected in _REQUIRED_ENVIRONMENT.items():
        if environment.get(name) != expected:
            raise ValueError(f"workload environment requires {name}={expected}")
    for name, value in environment.items():
        if _ENV_NAME.fullmatch(name) is None or not value.isascii() or "\x00" in value or "\n" in value:
            raise ValueError("workload environment contains an invalid value")
        if len(value) > 4096:
            raise ValueError("workload environment value is too long")
    if environment.get("LANG") not in {"C", "C.UTF-8"} or environment.get("LC_ALL") not in {
        "C",
        "C.UTF-8",
    }:
        raise ValueError("workload locale must be deterministic")
    if not environment.get("PYTHONHASHSEED", "").isdigit():
        raise ValueError("workload PYTHONHASHSEED must be numeric")
    pycache_prefix = environment.get("PYTHONPYCACHEPREFIX")
    if (
        pycache_prefix is None
        or re.fullmatch(r"/tmp/sluice-pycache-[a-z0-9][a-z0-9_-]{7,127}", pycache_prefix)
        is None
    ):
        raise ValueError("workload PYTHONPYCACHEPREFIX must be a unique canonical /tmp path")
    path_value = environment.get("PATH")
    if not path_value or any(
        not component.startswith("/opt/sluice/runtime") for component in path_value.split(":")
    ):
        raise ValueError("workload PATH must contain only the synthetic runtime")
    visible = environment.get("CUDA_VISIBLE_DEVICES")
    if visible is None or re.fullmatch(r"[0-9]+(?:,[0-9]+)*", visible) is None:
        raise ValueError("workload CUDA_VISIBLE_DEVICES must be an exact numeric list")
    if len(set(visible.split(","))) != len(visible.split(",")):
        raise ValueError("workload CUDA_VISIBLE_DEVICES must not contain duplicates")
    exposed = {
        device.target.name.removeprefix("nvidia")
        for device in devices
        if device.target.name.removeprefix("nvidia").isdigit()
    }
    if set(visible.split(",")) != exposed:
        raise ValueError("CUDA_VISIBLE_DEVICES must exactly match mounted GPU device nodes")
    return dict(sorted(environment.items()))


@dataclass(frozen=True)
class RockyGPUIsolationConfig:
    binds: tuple[AuthenticatedBind, ...]
    devices: tuple[GPUDevice, ...]
    protected_host_paths: ProtectedHostPaths
    worker_source_sha256: str
    interpreter_sha256: str
    workload_environment: Mapping[str, str]
    root_parent: Path
    root_tmpfs_bytes: int = 268435456
    startup_timeout_seconds: float = 180.0
    allow_cuda_diagnostic: bool = False
    cuda_preload_paths: tuple[PurePosixPath | str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.binds) is not tuple or not self.binds or any(
            type(bind) is not AuthenticatedBind for bind in self.binds
        ):
            raise TypeError("binds must be a nonempty tuple of AuthenticatedBind")
        if type(self.devices) is not tuple or any(
            type(device) is not GPUDevice for device in self.devices
        ):
            raise TypeError("devices must be a tuple of GPUDevice")
        if type(self.protected_host_paths) is not ProtectedHostPaths:
            raise TypeError("protected_host_paths must be ProtectedHostPaths")
        _valid_sha256(self.worker_source_sha256, "worker_source_sha256")
        _valid_sha256(self.interpreter_sha256, "interpreter_sha256")
        if len({bind.label for bind in self.binds}) != len(self.binds):
            raise ValueError("bind labels must be unique")
        if len({bind.target for bind in self.binds}) != len(self.binds):
            raise ValueError("bind targets must be unique")
        categories = {bind.category for bind in self.binds}
        if not _REQUIRED_CATEGORIES.issubset(categories):
            raise ValueError("strict GPU isolation requires runtime, model_source, and model_cache binds")
        for left in self.binds:
            for right in self.binds:
                if left is right:
                    continue
                if left.source_is_directory and left.target in right.target.parents:
                    raise ValueError("directory bind targets must not overlap")
        for protected in self.protected_host_paths.as_mapping().values():
            for bind in self.binds:
                if _under(protected, bind.source):
                    raise ValueError("an authenticated bind covers a protected host path")
        protected_inodes = frozenset(
            (status.st_dev, status.st_ino)
            for status in (
                path.stat(follow_symlinks=False)
                for path in self.protected_host_paths.as_mapping().values()
            )
        )
        for bind in self.binds:
            if _source_contains_any_inode(bind.source, protected_inodes):
                raise ValueError("an authenticated bind aliases a protected host inode")
        device_names = {device.target.name for device in self.devices}
        for required in ("nvidiactl", "nvidia-uvm"):
            if required not in device_names:
                raise ValueError(f"strict GPU isolation requires {required}")
        if not any(re.fullmatch(r"nvidia[0-9]+", name) for name in device_names):
            raise ValueError("strict GPU isolation requires nvidia0 or another exact GPU node")
        if len(device_names) != len(self.devices):
            raise ValueError("GPU device targets must be unique")
        environment = _validate_environment(self.workload_environment, self.devices)
        object.__setattr__(self, "workload_environment", environment)
        root_parent = _canonical_existing(Path(self.root_parent), "root_parent")
        if not root_parent.is_dir():
            raise ValueError("root_parent must be a directory")
        object.__setattr__(self, "root_parent", root_parent)
        if type(self.root_tmpfs_bytes) is not int or not 16 * 1024 * 1024 <= self.root_tmpfs_bytes <= 1024**3:
            raise ValueError("root_tmpfs_bytes must be in [16 MiB, 1 GiB]")
        if (
            type(self.startup_timeout_seconds) not in (int, float)
            or isinstance(self.startup_timeout_seconds, bool)
            or not 1 <= float(self.startup_timeout_seconds) <= 3600
        ):
            raise ValueError("startup_timeout_seconds must be in [1, 3600]")
        if type(self.allow_cuda_diagnostic) is not bool:
            raise TypeError("allow_cuda_diagnostic must be Boolean")
        if type(self.cuda_preload_paths) is not tuple:
            raise TypeError("cuda_preload_paths must be a tuple")
        preloads: list[PurePosixPath] = []
        for raw in self.cuda_preload_paths:
            text = str(raw)
            path = PurePosixPath(text)
            if not path.is_absolute() or ".." in path.parts or text != path.as_posix():
                raise ValueError("CUDA preload path must be canonical and absolute")
            if not any(path == bind.target or bind.target in path.parents for bind in self.binds):
                raise ValueError("CUDA preload path must be inside an authenticated bind")
            preloads.append(path)
        object.__setattr__(self, "cuda_preload_paths", tuple(preloads))
        if preloads and not self.allow_cuda_diagnostic:
            raise ValueError("CUDA preload paths require the diagnostic authorization bit")

    @classmethod
    def strict(cls, **kwargs: object) -> "RockyGPUIsolationConfig":
        return cls(**kwargs)

    def to_wire(self) -> dict[str, object]:
        return {
            "allow_cuda_diagnostic": self.allow_cuda_diagnostic,
            "binds": [bind.to_wire() for bind in self.binds],
            "cuda_preload_paths": [path.as_posix() for path in self.cuda_preload_paths],
            "devices": [device.to_wire() for device in self.devices],
            "interpreter_sha256": self.interpreter_sha256,
            "protected_host_paths": self.protected_host_paths.to_wire(),
            "root_parent": os.fspath(self.root_parent),
            "root_tmpfs_bytes": self.root_tmpfs_bytes,
            "schema_version": SCHEMA_VERSION,
            "startup_timeout_seconds": float(self.startup_timeout_seconds),
            "worker_source_sha256": self.worker_source_sha256,
            "workload_environment": dict(self.workload_environment),
        }

    @classmethod
    def from_wire(cls, wire: Mapping[str, object]) -> "RockyGPUIsolationConfig":
        required = {
            "allow_cuda_diagnostic",
            "binds",
            "cuda_preload_paths",
            "devices",
            "interpreter_sha256",
            "protected_host_paths",
            "root_parent",
            "root_tmpfs_bytes",
            "schema_version",
            "startup_timeout_seconds",
            "worker_source_sha256",
            "workload_environment",
        }
        if (
            type(wire) is not dict
            or set(wire) != required
            or type(wire["schema_version"]) is not int
            or wire["schema_version"] != SCHEMA_VERSION
        ):
            raise ValueError("Rocky config wire schema is invalid")
        if type(wire["binds"]) is not list or type(wire["devices"]) is not list:
            raise ValueError("Rocky config bind/device arrays are invalid")
        if type(wire["cuda_preload_paths"]) is not list:
            raise ValueError("Rocky config preload array is invalid")
        if any(type(value) is not str for value in wire["cuda_preload_paths"]):
            raise ValueError("Rocky config preload paths are invalid")
        root_parent = _canonical_wire_absolute(
            wire["root_parent"], "Rocky config root_parent"
        )
        cuda_preload_paths = tuple(
            _canonical_wire_absolute(value, "Rocky config CUDA preload path")
            for value in wire["cuda_preload_paths"]
        )
        return cls(
            allow_cuda_diagnostic=wire["allow_cuda_diagnostic"],
            binds=tuple(AuthenticatedBind.from_wire(item) for item in wire["binds"]),
            cuda_preload_paths=cuda_preload_paths,
            devices=tuple(GPUDevice.from_wire(item) for item in wire["devices"]),
            interpreter_sha256=wire["interpreter_sha256"],
            protected_host_paths=ProtectedHostPaths.from_wire(wire["protected_host_paths"]),
            root_parent=root_parent,
            root_tmpfs_bytes=wire["root_tmpfs_bytes"],
            startup_timeout_seconds=wire["startup_timeout_seconds"],
            worker_source_sha256=wire["worker_source_sha256"],
            workload_environment=wire["workload_environment"],
        )


def canonical_config_sha256(config: RockyGPUIsolationConfig) -> str:
    if type(config) is not RockyGPUIsolationConfig:
        raise TypeError("config must be RockyGPUIsolationConfig")
    encoded = json.dumps(
        config.to_wire(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def send_packet(channel: socket.socket, wire: Mapping[str, object]) -> None:
    """Send one bounded canonical JSON object over a packet-preserving channel."""

    if type(wire) is not dict or any(type(key) is not str for key in wire):
        raise ValueError("packet must be an object with string keys")
    try:
        encoded = json.dumps(
            wire,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ValueError("packet must be finite canonical JSON") from exc
    if not encoded or len(encoded) > MAX_PACKET_BYTES:
        raise ValueError("packet exceeds the bounded frame")
    written = channel.send(encoded)
    if written != len(encoded):
        raise RockyIsolationError("short private IPC write")


def _recv_packet_raw(channel: socket.socket) -> tuple[dict[str, Any], tuple[int, int, int] | None]:
    credential_size = struct.calcsize("3i")
    encoded, ancillary, flags, _address = channel.recvmsg(
        MAX_PACKET_BYTES + 1,
        socket.CMSG_SPACE(credential_size),
    )
    if not encoded:
        raise EOFError("private IPC channel closed")
    if flags & getattr(socket, "MSG_TRUNC", 0):
        raise ValueError("packet exceeds the bounded frame")
    if len(encoded) > MAX_PACKET_BYTES:
        raise ValueError("packet exceeds the bounded frame")
    try:
        wire = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("packet is not canonical ASCII JSON") from exc
    if type(wire) is not dict or any(type(key) is not str for key in wire):
        raise ValueError("packet must be an object with string keys")
    canonical = json.dumps(
        wire,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if canonical != encoded:
        raise ValueError("packet encoding is not canonical")
    credentials: list[tuple[int, int, int]] = []
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            if len(value) < credential_size:
                raise RockyIsolationError("malformed SCM_CREDENTIALS")
            credentials.append(struct.unpack("3i", value[:credential_size]))
    if len(credentials) > 1:
        raise RockyIsolationError("multiple SCM_CREDENTIALS records received")
    return wire, credentials[0] if credentials else None


def recv_packet(channel: socket.socket) -> dict[str, Any]:
    wire, _credentials = _recv_packet_raw(channel)
    return wire


def _recv_packet_with_credentials(channel: socket.socket) -> tuple[dict[str, Any], tuple[int, int, int]]:
    wire, credentials = _recv_packet_raw(channel)
    if credentials is None:
        raise RockyIsolationError("SCM_CREDENTIALS were not attached to the private packet")
    pid, uid, gid = credentials
    if pid <= 0 or uid < 0 or gid < 0:
        raise RockyIsolationError("invalid SCM_CREDENTIALS")
    return wire, credentials


@dataclass(frozen=True)
class RockyLiveCapabilityReport:
    linux: bool
    x86_64: bool
    user_namespace: bool
    mount_namespace: bool
    network_namespace: bool
    ipc_namespace: bool
    pid_namespace: bool
    namespace_pid_one: bool
    private_mount_propagation: bool
    tmpfs_root: bool
    chroot: bool
    no_new_privileges: bool
    capabilities_empty: bool
    seccomp_filter: bool
    unix_seqpacket: bool
    unix_peer_credentials: bool
    exact_gpu_devices: bool

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be Boolean")

    @property
    def supports_strict(self) -> bool:
        return all(getattr(self, name) for name in self.__dataclass_fields__)

    def to_wire(self) -> dict[str, bool]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_wire(cls, wire: Mapping[str, object]) -> "RockyLiveCapabilityReport":
        fields = set(cls.__dataclass_fields__)
        if type(wire) is not dict or set(wire) != fields:
            raise ValueError("capability report wire schema is invalid")
        return cls(**{name: wire[name] for name in fields})


def validate_live_capabilities(report: RockyLiveCapabilityReport) -> None:
    if type(report) is not RockyLiveCapabilityReport:
        raise TypeError("report must be RockyLiveCapabilityReport")
    missing = [name for name in report.__dataclass_fields__ if not getattr(report, name)]
    if missing:
        raise RockyIsolationUnavailable(
            "strict Rocky isolation controls unavailable: " + ", ".join(missing)
        )


@dataclass(frozen=True)
class RockyIsolationAttestation:
    capabilities: RockyLiveCapabilityReport
    _wire: Mapping[str, object]

    def to_wire(self) -> dict[str, object]:
        # A JSON round-trip provides a detached, mutation-safe public value.
        return json.loads(
            json.dumps(
                dict(self._wire),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )


def _peer_credentials(channel: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RockyIsolationUnavailable("unix_peer_credentials unavailable")
    size = struct.calcsize("3i")
    raw = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    if len(raw) != size:
        raise RockyIsolationError("malformed AF_UNIX peer credentials")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise RockyIsolationError("invalid AF_UNIX peer credentials")
    return pid, uid, gid


def _apply_resource_hardening() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    ceiling = 64
    new_hard = ceiling if hard == resource.RLIM_INFINITY else min(int(hard), ceiling)
    new_soft = new_hard if soft == resource.RLIM_INFINITY else min(int(soft), new_hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, new_hard))
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    new_hard = 64 if hard == resource.RLIM_INFINITY else min(int(hard), 64)
    new_soft = new_hard if soft == resource.RLIM_INFINITY else min(int(soft), new_hard)
    resource.setrlimit(resource.RLIMIT_NPROC, (new_soft, new_hard))
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    ceiling = 64 * 1024 * 1024
    new_hard = ceiling if hard == resource.RLIM_INFINITY else min(int(hard), ceiling)
    new_soft = new_hard if soft == resource.RLIM_INFINITY else min(int(soft), new_hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (new_soft, new_hard))


def _harden_early(expected_parent_pid: int) -> None:
    """Bind the outer supervisor to its launcher before parsing input."""

    if type(expected_parent_pid) is not int or expected_parent_pid <= 1:
        raise RockyIsolationError("invalid expected parent PID")
    _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != expected_parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(111)
    _apply_resource_hardening()


def _harden_namespace_init(liveness_fd: int) -> None:
    """Close the fork/PDEATHSIG race for namespace PID 1.

    A PID-namespace init cannot observe its parent from the ancestor namespace
    through ``getppid()`` (the value is zero).  The outer supervisor therefore
    holds the write side of a one-byte liveness pipe.  PID 1 arms PDEATHSIG,
    consumes the release byte, and then requires the pipe to remain open.  EOF
    means the supervisor died in the small interval before PDEATHSIG was armed.
    """

    if type(liveness_fd) is not int or liveness_fd < 3:
        raise RockyIsolationError("invalid namespace-init liveness descriptor")
    _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
    release = os.read(liveness_fd, 1)
    if release != b"G":
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(112)
    os.set_blocking(liveness_fd, False)
    try:
        state = os.read(liveness_fd, 1)
    except BlockingIOError:
        state = None
    if state is not None:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(113)
    os.close(liveness_fd)
    _apply_resource_hardening()


def _write_mapping(path: str, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        encoded = value.encode("ascii")
        if os.write(descriptor, encoded) != len(encoded):
            raise OSError(errno.EIO, "short namespace mapping write")
    finally:
        os.close(descriptor)


def _enter_namespaces() -> tuple[dict[str, str], dict[str, str]]:
    """Create all namespaces; the caller must fork to enter ``CLONE_NEWPID``."""

    before = {
        name: os.readlink(f"/proc/self/ns/{name}") for name in _NAMESPACE_NAMES
    }
    original_uid = os.getuid()
    original_gid = os.getgid()
    ctypes.set_errno(0)
    flags = _CLONE_NEWUSER | _CLONE_NEWNS | _CLONE_NEWNET | _CLONE_NEWIPC | _CLONE_NEWPID
    if _LIBC.unshare(flags) != 0:
        _raise_errno("unshare user/mount/network/IPC/PID namespaces")
    try:
        _write_mapping("/proc/self/setgroups", "deny")
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
    _write_mapping("/proc/self/uid_map", f"0 {original_uid} 1\n")
    _write_mapping("/proc/self/gid_map", f"0 {original_gid} 1\n")
    if _LIBC.setresgid(0, 0, 0) != 0:
        _raise_errno("setresgid in user namespace")
    if _LIBC.setresuid(0, 0, 0) != 0:
        _raise_errno("setresuid in user namespace")
    after = {
        name: os.readlink(f"/proc/self/ns/{name}")
        for name in ("user", "mnt", "net", "ipc")
    }
    # CLONE_NEWPID changes only children.  Rocky's 4.18 kernel temporarily
    # reports ENOENT for pid_for_children between unshare and the first fork,
    # so the host-visible supervisor resolves the actual child's nsfs link
    # immediately after that fork.
    after["pid"] = ""
    if any(before[name] == after[name] for name in ("user", "mnt", "net", "ipc")):
        raise RockyIsolationUnavailable("a requested namespace did not change")
    return before, after


def _namespace_pid_vector() -> list[int]:
    with open("/proc/self/status", "r", encoding="ascii") as handle:
        for line in handle:
            if line.startswith("NSpid:"):
                values = [int(value) for value in line.split()[1:]]
                if not values or any(value <= 0 for value in values):
                    break
                return values
    raise RockyIsolationError("kernel did not expose a valid NSpid mapping")


def _mount(
    source: str | None,
    target: str,
    filesystem: str | None,
    flags: int,
    data: str | None = None,
) -> None:
    def value(text: str | None) -> ctypes.c_char_p:
        return ctypes.c_char_p(text.encode("utf-8")) if text is not None else ctypes.c_char_p()

    ctypes.set_errno(0)
    result = _LIBC.mount(value(source), value(target), value(filesystem), flags, value(data))
    if result != 0:
        _raise_errno("mount")


def _decode_mount_path(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _mount_table() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    with open("/proc/self/mountinfo", "r", encoding="ascii") as handle:
        for line in handle:
            left, right = line.rstrip("\n").split(" - ", 1)
            fields = left.split(" ")
            right_fields = right.split(" ")
            entries.append(
                {
                    "mountpoint": _decode_mount_path(fields[4]),
                    "options": frozenset(fields[5].split(",")),
                    "optional": tuple(fields[6:]),
                    "filesystem": right_fields[0],
                }
            )
    return entries


def _mount_entry(path: Path) -> dict[str, object]:
    target = os.fspath(path)
    matches = [entry for entry in _mount_table() if entry["mountpoint"] == target]
    if not matches:
        raise RockyIsolationError("expected mountpoint is absent")
    return matches[-1]


def _source_has_nested_mount(bind: AuthenticatedBind) -> bool:
    if not bind.source_is_directory:
        return False
    for entry in _mount_table():
        mountpoint = Path(entry["mountpoint"])
        if mountpoint != bind.source and _under(mountpoint, bind.source):
            return True
    return False


def _inside(root: Path, target: PurePosixPath) -> Path:
    return root.joinpath(*target.parts[1:])


def _prepare_workload_pycache(root: Path, config: RockyGPUIsolationConfig) -> Path:
    prefix = PurePosixPath(config.workload_environment["PYTHONPYCACHEPREFIX"])
    target = _inside(root, prefix)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.mkdir(mode=0o700)
    status = target.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o700
        or any(target.iterdir())
    ):
        raise RockyIsolationError("workload pycache prefix is not fresh/private/empty")
    return target


def _prepare_mount_target(root: Path, bind: AuthenticatedBind) -> Path:
    target = _inside(root, bind.target)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if bind.source_is_directory:
        target.mkdir(mode=0o700)
    else:
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        os.close(descriptor)
    return target


def _assert_mounted_source_crossbound(
    target: Path, bind: AuthenticatedBind
) -> None:
    """Require a newly mounted object to be the retained authenticated source.

    Rocky 8's 4.18 kernel rejects a bind source expressed as
    ``/proc/self/fd/<directory-fd>`` from this rootless user namespace, even
    for a plain nonrecursive bind.  The compatibility path therefore resolves
    the already-rebound lexical source only for the mount syscall.  Before any
    mounted content is read or executed, this check binds the resulting mount
    back to the retained descriptor's device/inode/mode/kind and revalidates
    the complete lexical chain.  A rename/replacement during the mount window
    consequently fails closed even when the replacement has identical bytes.
    """

    try:
        mounted_identity = _source_identity(target.stat(follow_symlinks=False))
        pinned_identity = _source_identity(os.fstat(bind.source_fd))
    except (OSError, ValueError) as exc:
        raise RockyIsolationError(
            "mounted bind cannot be cross-bound to the retained source"
        ) from exc
    if (
        not _namespace_stable_source_identity_equal(
            bind.source_identity, pinned_identity, source=True
        )
        or not _namespace_stable_source_identity_equal(
            bind.source_identity, mounted_identity, source=True
        )
        or (mounted_identity["device"], mounted_identity["inode"])
        != (pinned_identity["device"], pinned_identity["inode"])
    ):
        raise RockyIsolationError(
            "mounted bind is not the retained authenticated source object"
        )
    _assert_source_rebound_after_unshare(
        bind.source,
        bind.source_fd,
        bind.source_chain_identity,
        bind.source_identity,
    )


def _mount_authenticated_source(root: Path, bind: AuthenticatedBind) -> Path:
    """Bind a lexical source and cross-bind it to the retained FD immediately."""

    target = _prepare_mount_target(root, bind)
    # Nested mounts are rejected before this call.  A nonrecursive bind is
    # deliberate: recursively copying a mount tree would introduce objects
    # outside the retained-FD content audit and is rejected by Rocky 4.18 for
    # the procfd compatibility source in any case.
    _mount(os.fspath(bind.source), os.fspath(target), None, _MS_BIND)
    _assert_mounted_source_crossbound(target, bind)
    return target


def _bind_readonly(root: Path, bind: AuthenticatedBind) -> dict[str, object]:
    _assert_source_rebound_after_unshare(
        bind.source,
        bind.source_fd,
        bind.source_chain_identity,
        bind.source_identity,
    )
    if _source_has_nested_mount(bind):
        raise RockyIsolationError("authenticated bind source contains a nested mount")
    source_digest = _digest_source_fd_after_unshare(bind)
    if source_digest != bind.expected_sha256:
        raise RockyIsolationError("pinned bind source digest mismatch")
    target = _mount_authenticated_source(root, bind)
    remount = _MS_BIND | _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV
    if not bind.allow_exec:
        remount |= _MS_NOEXEC
    _mount(None, os.fspath(target), None, remount)
    _assert_mounted_source_crossbound(target, bind)
    entry = _mount_entry(target)
    readonly = "ro" in entry["options"]
    if not readonly:
        raise RockyIsolationError("authenticated bind did not become read-only")
    mounted_digest = _digest_path(target)
    if mounted_digest != bind.expected_sha256:
        raise RockyIsolationError("mounted bind digest differs from authenticated source")
    _assert_source_rebound_after_unshare(
        bind.source,
        bind.source_fd,
        bind.source_chain_identity,
        bind.source_identity,
    )
    probe = target if not bind.source_is_directory else target.joinpath(*bind.probe_relative.parts)
    descriptor = os.open(probe, os.O_RDONLY | os.O_CLOEXEC)
    try:
        read_probe = bool(os.read(descriptor, 1))
    finally:
        os.close(descriptor)
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    except OSError as exc:
        write_denied = exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS)
    else:
        os.close(descriptor)
        write_denied = False
    if not (read_probe and write_denied):
        raise RockyIsolationError("authenticated bind active read/write probes failed")
    return {
        "allow_exec": bind.allow_exec,
        "category": bind.category,
        "label": bind.label,
        "read_probe": read_probe,
        "readonly": readonly and write_denied,
        "sha256": mounted_digest,
        "source": os.fspath(bind.source),
        "source_identity": dict(bind.source_identity),
        "source_strategy": "lexical-mount-immediate-retained-fd-cross-bind",
        "target": bind.target.as_posix(),
    }


def _bind_device(root: Path, device: GPUDevice) -> dict[str, object]:
    target = _inside(root, device.target)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    os.close(descriptor)
    _mount(os.fspath(device.source), os.fspath(target), None, _MS_BIND)
    status = target.stat(follow_symlinks=False)
    observed = (os.major(status.st_rdev), os.minor(status.st_rdev))
    if not stat.S_ISCHR(status.st_mode) or observed != (device.major, device.minor):
        raise RockyIsolationError("mounted GPU device identity mismatch")
    return {
        "major": observed[0],
        "minor": observed[1],
        "source": os.fspath(device.source),
        "target": device.target.as_posix(),
    }


def _network_connect_denied() -> bool:
    channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        channel.settimeout(0.25)
        return channel.connect_ex(("198.51.100.1", 9)) != 0
    finally:
        channel.close()


def _close_unneeded_fds(keep: frozenset[int]) -> None:
    if type(keep) is not frozenset or any(type(value) is not int or value < 3 for value in keep):
        raise ValueError("kept descriptors must be integers >= 3")
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if maximum == resource.RLIM_INFINITY:
        maximum = 1024
    for descriptor in range(3, int(maximum)):
        if descriptor in keep:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_descriptors(maximum: int = 64) -> frozenset[int]:
    live: set[int] = set()
    for descriptor in range(maximum):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            live.add(descriptor)
    return frozenset(live)


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _cap_last_cap() -> int:
    with open("/proc/sys/kernel/cap_last_cap", "r", encoding="ascii") as handle:
        value = int(handle.read().strip())
    if not 0 <= value <= 63:
        raise RockyIsolationError("unsupported kernel capability range")
    return value


def _drop_all_capabilities(last_cap: int) -> bool:
    _prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    for capability in range(last_cap + 1):
        _prctl(_PR_CAPBSET_DROP, capability)
    _prctl(_PR_SET_SECUREBITS, _SECBIT_LOCKED_NO_ROOT)
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    ctypes.set_errno(0)
    if _LIBC.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        _raise_errno("capset")
    observed = (_CapData * 2)()
    ctypes.set_errno(0)
    if _LIBC.capget(ctypes.byref(header), ctypes.byref(observed)) != 0:
        _raise_errno("capget")
    if any(
        (entry.effective or entry.permitted or entry.inheritable) for entry in observed
    ):
        return False
    if _prctl(_PR_GET_SECUREBITS) != _SECBIT_LOCKED_NO_ROOT:
        return False
    for capability in range(last_cap + 1):
        if _prctl(_PR_CAPBSET_READ, capability) != 0:
            return False
        if _prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_IS_SET, capability, 0, 0) != 0:
            return False
    return True


def _seccomp_filter_sha256() -> str:
    encoded = json.dumps(
        {
            "architecture": "x86_64",
            "audit_arch": _AUDIT_ARCH_X86_64,
            "default": "allow",
            "denied_errno": errno.EPERM,
            "prctl": {
                "allowed_options": list(_ALLOWED_PRCTL_OPTIONS),
                "other_options": "errno",
                "syscall": _PRCTL_SYSCALL,
            },
            "syscalls": dict(sorted(_DENIED_SYSCALLS.items())),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _install_seccomp_filter() -> str:
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RockyIsolationUnavailable("seccomp filter supports only audited Linux x86_64")
    instructions: list[_SockFilter] = [
        _SockFilter(0x20, 0, 0, 4),  # BPF_LD | BPF_W | BPF_ABS: seccomp_data.arch
        _SockFilter(0x15, 1, 0, _AUDIT_ARCH_X86_64),  # matching arch skips kill
        _SockFilter(0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SockFilter(0x20, 0, 0, 0),  # seccomp_data.nr
    ]
    allowed_prctl = tuple(sorted(_ALLOWED_PRCTL_OPTIONS))
    # prctl is argument-filtered: read-only attestation operations remain
    # available, while attempts to clear PDEATHSIG, restore dumpability, or
    # alter securebits/no_new_privs are denied.
    instructions.append(_SockFilter(0x15, 0, len(allowed_prctl) + 3, _PRCTL_SYSCALL))
    instructions.append(_SockFilter(0x20, 0, 0, 16))  # seccomp_data.args[0], low 32 bits
    for index, option in enumerate(allowed_prctl):
        instructions.append(
            _SockFilter(0x15, len(allowed_prctl) - index, 0, option)
        )
    instructions.append(_SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM))
    instructions.append(_SockFilter(0x06, 0, 0, _SECCOMP_RET_ALLOW))
    instructions.append(_SockFilter(0x20, 0, 0, 0))  # restore syscall nr
    for number in sorted(_DENIED_SYSCALLS.values()):
        instructions.append(_SockFilter(0x15, 0, 1, number))
        instructions.append(_SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM))
    instructions.append(_SockFilter(0x06, 0, 0, _SECCOMP_RET_ALLOW))
    array = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), array)
    _prctl(_PR_SET_NO_NEW_PRIVS, 1)
    ctypes.set_errno(0)
    result = _LIBC.prctl(
        _PR_SET_SECCOMP,
        _SECCOMP_MODE_FILTER,
        ctypes.byref(program),
        0,
        0,
    )
    if result != 0:
        _raise_errno("install seccomp filter")
    if _prctl(_PR_GET_SECCOMP) != _SECCOMP_MODE_FILTER:
        raise RockyIsolationError("seccomp filter mode was not retained")
    return _seccomp_filter_sha256()


def _pdeathsig_is_kill() -> bool:
    observed = ctypes.c_int(0)
    ctypes.set_errno(0)
    if _LIBC.prctl(_PR_GET_PDEATHSIG, ctypes.byref(observed), 0, 0, 0) != 0:
        _raise_errno("get parent death signal")
    return observed.value == signal.SIGKILL


def _protected_path_denials(paths: ProtectedHostPaths) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name, path in paths.as_mapping().items():
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        except OSError as exc:
            result[name] = exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR)
        else:
            os.close(descriptor)
            result[name] = False
    return result


def _rewrite_python_paths(config: RockyGPUIsolationConfig) -> None:
    mappings = [
        (os.fspath(bind.source), bind.target.as_posix())
        for bind in config.binds
        if bind.source_is_directory and bind.category in {"runtime", "model_source", "support"}
    ]
    rewritten: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        candidate = os.path.abspath(entry)
        for source, target in mappings:
            if candidate == source or candidate.startswith(source + os.sep):
                suffix = candidate[len(source) :].lstrip(os.sep)
                value = target if not suffix else target + "/" + suffix
                if value not in rewritten:
                    rewritten.append(value)
                break
    for bind in config.binds:
        if bind.source_is_directory and bind.category in {"runtime", "model_source", "support"}:
            value = bind.target.as_posix()
            if value not in rewritten:
                rewritten.append(value)
    sys.path[:] = rewritten
    runtime_roots = [bind.target.as_posix() for bind in config.binds if bind.category == "runtime"]
    if runtime_roots:
        sys.prefix = runtime_roots[0]
        sys.exec_prefix = runtime_roots[0]


class _CUDAUUID(ctypes.Structure):
    _fields_ = (("bytes", ctypes.c_ubyte * 16),)


def _cuda_check(result: int, operation: str) -> None:
    if result != 0:
        raise RockyIsolationError(f"{operation} failed with CUDA status {result}")


def _cuda_runtime_version_number(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)", value)
    if match is None:
        raise RockyIsolationError("Torch reported a noncanonical CUDA runtime version")
    return int(match.group(1)) * 1000 + int(match.group(2)) * 10


def _cuda_driver_device_metadata(config: RockyGPUIsolationConfig) -> dict[str, object]:
    candidates = tuple(
        path.as_posix() for path in config.cuda_preload_paths if path.name == "libcuda.so.1"
    )
    if len(candidates) != 1:
        raise RockyIsolationError("CUDA diagnostic requires one exact libcuda.so.1 preload")
    library = ctypes.CDLL(candidates[0], mode=ctypes.RTLD_GLOBAL)
    library.cuInit.argtypes = (ctypes.c_uint,)
    library.cuInit.restype = ctypes.c_int
    library.cuDriverGetVersion.argtypes = (ctypes.POINTER(ctypes.c_int),)
    library.cuDriverGetVersion.restype = ctypes.c_int
    library.cuDeviceGet.argtypes = (ctypes.POINTER(ctypes.c_int), ctypes.c_int)
    library.cuDeviceGet.restype = ctypes.c_int
    library.cuDeviceGetName.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_int, ctypes.c_int)
    library.cuDeviceGetName.restype = ctypes.c_int
    uuid_function = getattr(library, "cuDeviceGetUuid_v2", None)
    if uuid_function is None:
        uuid_function = getattr(library, "cuDeviceGetUuid", None)
    if uuid_function is None:
        raise RockyIsolationError("CUDA driver lacks a device UUID function")
    uuid_function.argtypes = (ctypes.POINTER(_CUDAUUID), ctypes.c_int)
    uuid_function.restype = ctypes.c_int
    total_memory_function = getattr(library, "cuDeviceTotalMem_v2", None)
    if total_memory_function is None:
        total_memory_function = getattr(library, "cuDeviceTotalMem", None)
    if total_memory_function is None:
        raise RockyIsolationError("CUDA driver lacks a total-memory function")
    total_memory_function.argtypes = (ctypes.POINTER(ctypes.c_size_t), ctypes.c_int)
    total_memory_function.restype = ctypes.c_int

    _cuda_check(library.cuInit(0), "cuInit")
    driver_version = ctypes.c_int()
    _cuda_check(library.cuDriverGetVersion(ctypes.byref(driver_version)), "cuDriverGetVersion")
    device = ctypes.c_int()
    _cuda_check(library.cuDeviceGet(ctypes.byref(device), 0), "cuDeviceGet")
    name_buffer = ctypes.create_string_buffer(256)
    _cuda_check(library.cuDeviceGetName(name_buffer, len(name_buffer), device.value), "cuDeviceGetName")
    uuid = _CUDAUUID()
    _cuda_check(uuid_function(ctypes.byref(uuid), device.value), "cuDeviceGetUuid")
    total_memory = ctypes.c_size_t()
    _cuda_check(
        total_memory_function(ctypes.byref(total_memory), device.value),
        "cuDeviceTotalMem",
    )
    raw_uuid = bytes(uuid.bytes).hex()
    formatted_uuid = "GPU-{}-{}-{}-{}-{}".format(
        raw_uuid[:8],
        raw_uuid[8:12],
        raw_uuid[12:16],
        raw_uuid[16:20],
        raw_uuid[20:],
    )
    try:
        name = name_buffer.value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RockyIsolationError("CUDA device name is not ASCII") from exc
    if not name or driver_version.value <= 0 or total_memory.value <= 0:
        raise RockyIsolationError("CUDA driver returned empty device metadata")
    return {
        "cuda_driver_api_version": int(driver_version.value),
        "device_name": name,
        "device_total_memory_bytes": int(total_memory.value),
        "device_uuid": formatted_uuid,
    }


def _cuda_allocation_diagnostic(config: RockyGPUIsolationConfig) -> dict[str, object]:
    if not config.allow_cuda_diagnostic:
        raise RockyIsolationError("CUDA diagnostic was not authorized in the frozen config")
    for path in config.cuda_preload_paths:
        try:
            ctypes.CDLL(path.as_posix(), mode=ctypes.RTLD_GLOBAL)
        except BaseException as exc:
            raise _CUDADiagnosticFailure(f"preload_{path.name}", exc) from exc
    import importlib

    forbidden = {"transformers", "vllm"}
    if forbidden.intersection(sys.modules):
        raise RockyIsolationError("a model-serving or tokenizer module was already loaded")
    try:
        torch = importlib.import_module("torch")
    except BaseException as exc:
        raise _CUDADiagnosticFailure("import_torch", exc) from exc
    if forbidden.intersection(sys.modules):
        raise RockyIsolationError("Torch import loaded a forbidden model-serving module")
    try:
        available = torch.cuda.is_available()
        device_count = torch.cuda.device_count()
    except BaseException as exc:
        raise _CUDADiagnosticFailure("torch_cuda_discovery", exc) from exc
    if not available or device_count != len(
        config.workload_environment["CUDA_VISIBLE_DEVICES"].split(",")
    ):
        raise RockyIsolationError("CUDA diagnostic observed the wrong visible device count")
    try:
        torch.cuda.set_device(0)
    except BaseException as exc:
        raise _CUDADiagnosticFailure("torch_set_device", exc) from exc
    try:
        driver = _cuda_driver_device_metadata(config)
    except BaseException as exc:
        if isinstance(exc, _CUDADiagnosticFailure):
            raise
        raise _CUDADiagnosticFailure("cuda_driver_metadata", exc) from exc
    cuda_runtime = str(torch.version.cuda)
    if driver["cuda_driver_api_version"] < _cuda_runtime_version_number(cuda_runtime):
        raise RockyIsolationError("CUDA driver API is older than the Torch CUDA runtime")
    try:
        properties = torch.cuda.get_device_properties(0)
    except BaseException as exc:
        raise _CUDADiagnosticFailure("torch_device_properties", exc) from exc
    if str(properties.name) != driver["device_name"]:
        raise RockyIsolationError("Torch and CUDA driver device names differ")
    if int(properties.total_memory) != driver["device_total_memory_bytes"]:
        raise RockyIsolationError("Torch and CUDA driver memory observations differ")
    try:
        allocated_before = int(torch.cuda.memory_allocated(0))
    except BaseException as exc:
        raise _CUDADiagnosticFailure("torch_memory_before", exc) from exc
    tensor = None
    try:
        tensor = torch.ones(1024, dtype=torch.float32, device="cuda")
        tensor_bytes = int(tensor.nelement() * tensor.element_size())
        checksum = float(tensor.sum().item())
        torch.cuda.synchronize()
        allocated_during = int(torch.cuda.memory_allocated(0))
    except BaseException as exc:
        raise _CUDADiagnosticFailure("torch_allocate_and_check", exc) from exc
    finally:
        del tensor
        try:
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
        except BaseException as exc:
            raise _CUDADiagnosticFailure("torch_release", exc) from exc
    try:
        allocated_after = int(torch.cuda.memory_allocated(0))
    except BaseException as exc:
        raise _CUDADiagnosticFailure("torch_memory_after", exc) from exc
    if checksum != 1024.0:
        raise RockyIsolationError("CUDA allocation diagnostic checksum mismatch")
    if allocated_during - allocated_before < 4096 or allocated_after != allocated_before:
        raise RockyIsolationError("CUDA allocation diagnostic did not allocate and free the tensor")
    return {
        "allocated_after_bytes": allocated_after,
        "allocated_before_bytes": allocated_before,
        "allocated_bytes": tensor_bytes,
        "allocated_during_bytes": allocated_during,
        "checksum": checksum,
        "cuda_driver_api_version": driver["cuda_driver_api_version"],
        "cuda_runtime": cuda_runtime,
        "device_count": int(torch.cuda.device_count()),
        "device_name": driver["device_name"],
        "device_total_memory_bytes": driver["device_total_memory_bytes"],
        "device_uuid": driver["device_uuid"],
        "diagnostic_only": True,
        "forbidden_modules_absent": True,
        "model_loaded": False,
        "tokenizer_loaded": False,
        "torch_version": str(torch.__version__),
        "vllm_imported": False,
    }


class _NamespaceTermination(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(f"namespace init received signal {signum}")
        self.signum = signum


def _signal_namespace_children(signum: int) -> None:
    """Signal only processes visible below namespace PID 1."""

    try:
        os.kill(-1, signum)
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise


def _force_kill_and_reap_namespace_children(timeout_seconds: float = 5.0) -> list[dict[str, int]]:
    """Kill and reap every remaining child visible to namespace PID 1."""

    _signal_namespace_children(signal.SIGKILL)
    reaped: list[dict[str, int]] = []
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if pid > 0:
            reaped.append({"pid": pid, "status": status})
            continue
        if time.monotonic() >= deadline:
            raise RockyIsolationError("namespace descendants did not terminate before cleanup deadline")
        time.sleep(0.01)


def _install_namespace_init_signal_handlers() -> dict[int, object]:
    previous: dict[int, object] = {}

    def terminate(signum: int, _frame: object) -> None:
        _signal_namespace_children(signum)
        raise _NamespaceTermination(signum)

    for signum in _TERMINATION_SIGNALS:
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, terminate)
    return previous


def _restore_signal_handlers(previous: Mapping[int, object]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _wait_for_namespace_init(init_host_pid: int) -> int:
    """Outer supervisor signal-forwarding and watchdog/reap loop."""

    if type(init_host_pid) is not int or init_host_pid <= 1:
        raise RockyIsolationError("invalid namespace-init host PID")
    previous: dict[int, object] = {}

    def forward(signum: int, _frame: object) -> None:
        target = signal.SIGKILL if signum == _WATCHDOG_SIGNAL else signum
        try:
            os.kill(init_host_pid, target)
        except OSError as exc:
            if exc.errno != errno.ESRCH:
                raise

    for signum in _TERMINATION_SIGNALS + (_WATCHDOG_SIGNAL,):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, forward)
    try:
        while True:
            try:
                waited_pid, status = os.waitpid(init_host_pid, 0)
            except InterruptedError:
                continue
            if waited_pid != init_host_pid:
                raise RockyIsolationError("outer supervisor reaped the wrong child")
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return 128 + os.WTERMSIG(status)
            raise RockyIsolationError("namespace init entered an unsupported wait state")
    finally:
        _restore_signal_handlers(previous)


def _fork_namespace_init_and_supervise(
    channel: socket.socket,
    *,
    challenge: str,
    config: RockyGPUIsolationConfig,
    config_sha256: str,
    root_path: Path,
    root_identity: list[int],
    interpreter_pin: dict[str, object],
    worker_source_sha256: str,
    interpreter_sha256: str,
    launcher_peer: tuple[int, int, int],
    namespace_before: dict[str, str],
    namespace_expected: dict[str, str],
    worker_bootstrap_flags: dict[str, bool],
    worker_inline_loader_sha256: str,
) -> int:
    """Fork the process that becomes PID 1, then remain its host-side reaper."""

    flags = os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0
    liveness_read, liveness_write = os.pipe2(flags)
    supervisor_host_pid = os.getpid()
    init_host_pid = os.fork()
    if init_host_pid == 0:
        os.close(liveness_write)
        try:
            return_code = _namespace_init_main(
                channel,
                challenge=challenge,
                config=config,
                config_sha256=config_sha256,
                root_path=root_path,
                root_identity=root_identity,
                interpreter_pin=interpreter_pin,
                worker_source_sha256=worker_source_sha256,
                interpreter_sha256=interpreter_sha256,
                launcher_peer=launcher_peer,
                namespace_before=namespace_before,
                namespace_expected=namespace_expected,
                supervisor_host_pid=supervisor_host_pid,
                liveness_fd=liveness_read,
                worker_inline_loader_sha256=worker_inline_loader_sha256,
                worker_bootstrap_flags=worker_bootstrap_flags,
            )
        except BaseException:
            return_code = 118
        finally:
            channel.close()
        os._exit(return_code)

    _close_bind_source_fds(config)
    os.close(liveness_read)
    try:
        namespace_expected = dict(namespace_expected)
        namespace_expected["pid"] = os.readlink(f"/proc/{init_host_pid}/ns/pid")
        if namespace_expected["pid"] == namespace_before["pid"]:
            raise RockyIsolationUnavailable("forked child did not enter the fresh PID namespace")
        send_packet(
            channel,
            {
                "init_host_pid": init_host_pid,
                "namespace_expected": namespace_expected,
                "supervisor_host_pid": supervisor_host_pid,
                "type": "namespace_supervisor",
            },
        )
        if os.write(liveness_write, b"G") != 1:
            raise RockyIsolationError("namespace-init release write was short")
        channel.close()
        return _wait_for_namespace_init(init_host_pid)
    except BaseException:
        try:
            os.kill(init_host_pid, signal.SIGKILL)
        except OSError as exc:
            if exc.errno != errno.ESRCH:
                raise
        try:
            os.waitpid(init_host_pid, 0)
        except ChildProcessError:
            pass
        raise
    finally:
        os.close(liveness_write)


def _worker_error(channel: socket.socket, phase: str, exc: BaseException) -> None:
    try:
        wire: dict[str, object] = {
            "errno": int(exc.errno) if isinstance(exc, OSError) and exc.errno else 0,
            "phase": phase,
            "reason": type(exc).__name__,
            "type": "error",
        }
        if isinstance(exc, _CUDADiagnosticFailure):
            wire.update(
                {
                    "cuda_cause": exc.cause_type,
                    "cuda_errno": exc.cause_errno,
                    "cuda_stage": exc.stage,
                }
            )
        send_packet(channel, wire)
    except BaseException:
        pass


def _host_process_ipc_isolation_probe(command: Mapping[str, object]) -> dict[str, object]:
    required = {"posix_shm_name", "sysv_shmid", "type", "victim_pid"}
    if type(command) is not dict or set(command) != required or command.get("type") != "host_isolation_probe":
        raise ValueError("host-isolation probe schema is invalid")
    victim_pid = command["victim_pid"]
    sysv_shmid = command["sysv_shmid"]
    posix_shm_name = command["posix_shm_name"]
    if type(victim_pid) is not int or victim_pid <= 1:
        raise ValueError("host-isolation victim PID is invalid")
    if type(sysv_shmid) is not int or sysv_shmid < 0:
        raise ValueError("host-isolation SysV identifier is invalid")
    if type(posix_shm_name) is not str or re.fullmatch(r"/sluice-[a-z0-9-]{8,96}", posix_shm_name) is None:
        raise ValueError("host-isolation POSIX name is invalid")

    try:
        os.kill(victim_pid, signal.SIGTERM)
    except OSError as exc:
        signal_errno = int(exc.errno or 0)
        signal_denied = exc.errno == errno.ESRCH
    else:
        signal_errno = 0
        signal_denied = False

    _LIBC.shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
    _LIBC.shmat.restype = ctypes.c_void_p
    _LIBC.shmdt.argtypes = (ctypes.c_void_p,)
    _LIBC.shmdt.restype = ctypes.c_int
    ctypes.set_errno(0)
    address = _LIBC.shmat(sysv_shmid, None, 0o10000)  # SHM_RDONLY
    shmat_failed = ctypes.c_void_p(-1).value
    if address == shmat_failed:
        sysv_errno = ctypes.get_errno()
        sysv_denied = sysv_errno in (errno.EINVAL, errno.EIDRM, errno.EACCES, errno.EPERM)
    else:
        _LIBC.shmdt(address)
        sysv_errno = 0
        sysv_denied = False

    posix_path = Path("/dev/shm") / posix_shm_name.removeprefix("/")
    try:
        descriptor = os.open(posix_path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        posix_errno = int(exc.errno or 0)
        posix_denied = exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM)
    else:
        os.close(descriptor)
        posix_errno = 0
        posix_denied = False

    result = {
        "host_pid_invisible": signal_denied,
        "posix_shm_denied": posix_denied,
        "posix_shm_errno": posix_errno,
        "same_uid_signal_denied": signal_denied,
        "same_uid_signal_errno": signal_errno,
        "sysv_shm_denied": sysv_denied,
        "sysv_shm_errno": sysv_errno,
    }
    if not all(result[name] is True for name in (
        "host_pid_invisible",
        "posix_shm_denied",
        "same_uid_signal_denied",
        "sysv_shm_denied",
    )):
        raise RockyIsolationError("host process or IPC object remained visible")
    return result


def _wait_status_wire(status: int) -> dict[str, int]:
    if os.WIFEXITED(status):
        return {"exit_code": os.WEXITSTATUS(status), "signal": 0}
    if os.WIFSIGNALED(status):
        return {"exit_code": -1, "signal": os.WTERMSIG(status)}
    raise RockyIsolationError("descendant entered an unsupported wait state")


def _descendant_reap_diagnostic() -> dict[str, object]:
    flags = os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0
    read_fd, write_fd = os.pipe2(flags)
    direct_pid = os.fork()
    if direct_pid == 0:
        os.close(read_fd)
        grandchild_pid = os.fork()
        if grandchild_pid == 0:
            os.close(write_fd)
            time.sleep(0.05)
            os._exit(23)
        encoded = struct.pack("i", grandchild_pid)
        if os.write(write_fd, encoded) != len(encoded):
            os._exit(90)
        os.close(write_fd)
        os._exit(17)

    os.close(write_fd)
    try:
        encoded = b""
        while len(encoded) < struct.calcsize("i"):
            block = os.read(read_fd, struct.calcsize("i") - len(encoded))
            if not block:
                break
            encoded += block
    finally:
        os.close(read_fd)
    if len(encoded) != struct.calcsize("i"):
        raise RockyIsolationError("descendant did not report its grandchild")
    grandchild_pid = struct.unpack("i", encoded)[0]
    waited_direct, direct_status = os.waitpid(direct_pid, 0)
    waited_grandchild, grandchild_status = os.waitpid(grandchild_pid, 0)
    if waited_direct != direct_pid or waited_grandchild != grandchild_pid:
        raise RockyIsolationError("namespace init reaped the wrong descendant")
    try:
        unexpected_pid, _unexpected_status = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        no_children_remaining = True
    else:
        no_children_remaining = unexpected_pid == 0 and False
    if not no_children_remaining:
        raise RockyIsolationError("namespace init retained an unexpected descendant")
    return {
        "direct_namespace_pid": direct_pid,
        "direct_status": _wait_status_wire(direct_status),
        "grandchild_namespace_pid": grandchild_pid,
        "grandchild_status": _wait_status_wire(grandchild_status),
        "namespace_init_pid": os.getpid(),
        "no_children_remaining": True,
    }


def _arm_lingering_descendant(channel: socket.socket, mode: str) -> int:
    flags = os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0
    read_fd, write_fd = os.pipe2(flags)
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        for signum in _TERMINATION_SIGNALS:
            signal.signal(signum, signal.SIG_DFL)
        try:
            send_packet(
                channel,
                {
                    "mode": mode,
                    "namespace_pid": os.getpid(),
                    "type": "lingering_descendant",
                },
            )
            if os.write(write_fd, b"A") != 1:
                os._exit(91)
            os.close(write_fd)
            while True:
                signal.pause()
        except BaseException:
            os._exit(92)
    os.close(write_fd)
    try:
        armed = os.read(read_fd, 1)
    finally:
        os.close(read_fd)
    if armed != b"A":
        raise RockyIsolationError("lingering descendant did not arm")
    return child_pid


def _verified_worker_bootstrap_flags() -> dict[str, bool]:
    prefix = sys.pycache_prefix
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.dont_write_bytecode is not True
        or type(prefix) is not str
        or not prefix.startswith("/")
    ):
        raise RockyIsolationError("worker interpreter isolation flags are incomplete")
    descriptor = os.open(prefix, _directory_open_flags())
    try:
        status = os.fstat(descriptor)
        if (
            status.st_uid != os.geteuid()
            or stat.S_IMODE(status.st_mode) != 0o700
            or os.listdir(descriptor)
        ):
            raise RockyIsolationError("worker bootstrap pycache is not private and empty")
    finally:
        os.close(descriptor)
    return {
        "isolated": True,
        "no_bytecode": True,
        "no_site": True,
        "pycache_empty": True,
    }


def _worker_main(ipc_fd: int, expected_parent_pid: int) -> int:
    """Authenticated outer bootstrap and host-visible namespace-init reaper."""

    channel = socket.socket(fileno=ipc_fd)
    phase = "early_hardening"
    try:
        _harden_early(expected_parent_pid)
        worker_bootstrap_flags = _verified_worker_bootstrap_flags()
        if dict(os.environ) != _BOOTSTRAP_ENVIRONMENT:
            raise RockyIsolationError("bootstrap environment is not exact")
        if channel.family != socket.AF_UNIX or channel.type & 0xF != socket.SOCK_SEQPACKET:
            raise RockyIsolationError("worker IPC channel has the wrong type")
        launcher_peer = _peer_credentials(channel)

        phase = "bootstrap_authentication"
        bootstrap, bootstrap_credentials = _recv_packet_with_credentials(channel)
        if bootstrap_credentials != launcher_peer:
            raise RockyIsolationError("bootstrap SCM_CREDENTIALS mismatch")
        required = {
            "challenge",
            "config",
            "interpreter_pin",
            "root_identity",
            "root_path",
            "type",
            "worker_inline_loader_sha256",
        }
        if set(bootstrap) != required or bootstrap.get("type") != "bootstrap":
            raise ValueError("bootstrap packet schema is invalid")
        challenge = bootstrap["challenge"]
        if type(challenge) is not str or re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
            raise ValueError("bootstrap challenge is invalid")
        worker_inline_loader_sha256 = _valid_sha256(
            bootstrap["worker_inline_loader_sha256"],
            "worker inline loader SHA-256",
        )
        config = RockyGPUIsolationConfig.from_wire(bootstrap["config"])
        config_sha256 = canonical_config_sha256(config)
        interpreter_pin = _exact_interpreter_pin_wire(bootstrap["interpreter_pin"])
        if interpreter_pin["sha256"] != config.interpreter_sha256:
            raise RockyIsolationError("interpreter pin/config digest mismatch")
        interpreter_descriptor = globals().get("VERIFIED_INTERPRETER_SOURCE_FD")
        if type(interpreter_descriptor) is not int or interpreter_descriptor < 3:
            raise RockyIsolationError("verified interpreter descriptor is absent")
        _revalidate_proc_self_exe(interpreter_descriptor, interpreter_pin)
        root_path = _canonical_wire_absolute(
            bootstrap["root_path"], "worker bootstrap root path"
        )
        root_identity = bootstrap["root_identity"]
        if type(root_identity) is not list or len(root_identity) != 2 or any(
            type(value) is not int or value < 0 for value in root_identity
        ):
            raise ValueError("root identity schema is invalid")
        if root_path.parent.resolve(strict=True) != config.root_parent:
            raise RockyIsolationError("ephemeral root is outside the configured parent")
        root_status = root_path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(root_status.st_mode) or [root_status.st_dev, root_status.st_ino] != root_identity:
            raise RockyIsolationError("ephemeral root identity changed")
        if any(root_path.iterdir()):
            raise RockyIsolationError("ephemeral root is not empty")
        worker_source_sha256 = _executing_worker_source_sha256()
        interpreter_sha256 = _executing_interpreter_sha256()
        if worker_source_sha256 != config.worker_source_sha256:
            raise RockyIsolationError("worker source authentication failed")
        if interpreter_sha256 != config.interpreter_sha256:
            raise RockyIsolationError("interpreter authentication failed")
        for bind in config.binds:
            if _digest_source_fd(bind) != bind.expected_sha256:
                raise RockyIsolationError("authenticated bind digest mismatch")

        phase = "namespace_setup"
        namespace_before, namespace_expected = _enter_namespaces()
        return _fork_namespace_init_and_supervise(
            channel,
            challenge=challenge,
            config=config,
            config_sha256=config_sha256,
            root_path=root_path,
            root_identity=root_identity,
            interpreter_pin=interpreter_pin,
            worker_source_sha256=worker_source_sha256,
            interpreter_sha256=interpreter_sha256,
            launcher_peer=launcher_peer,
            namespace_before=namespace_before,
            namespace_expected=namespace_expected,
            worker_inline_loader_sha256=worker_inline_loader_sha256,
            worker_bootstrap_flags=worker_bootstrap_flags,
        )
    except BaseException as exc:
        _worker_error(channel, phase, exc)
        return {
            "early_hardening": 120,
            "bootstrap_authentication": 121,
            "namespace_setup": 122,
        }.get(phase, 119)
    finally:
        channel.close()


def _namespace_init_main(
    channel: socket.socket,
    *,
    challenge: str,
    config: RockyGPUIsolationConfig,
    config_sha256: str,
    root_path: Path,
    root_identity: list[int],
    interpreter_pin: dict[str, object],
    worker_source_sha256: str,
    interpreter_sha256: str,
    launcher_peer: tuple[int, int, int],
    namespace_before: dict[str, str],
    namespace_expected: dict[str, str],
    supervisor_host_pid: int,
    liveness_fd: int,
    worker_bootstrap_flags: dict[str, bool],
    worker_inline_loader_sha256: str,
) -> int:
    phase = "namespace_init_hardening"
    previous_handlers: dict[int, object] = {}
    try:
        _harden_namespace_init(liveness_fd)
        previous_handlers = _install_namespace_init_signal_handlers()
        if dict(os.environ) != _BOOTSTRAP_ENVIRONMENT:
            raise RockyIsolationError("bootstrap environment is not exact")
        if channel.family != socket.AF_UNIX or channel.type & 0xF != socket.SOCK_SEQPACKET:
            raise RockyIsolationError("worker IPC channel has the wrong type")
        if type(challenge) is not str or re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
            raise ValueError("bootstrap challenge is invalid")
        if config_sha256 != canonical_config_sha256(config):
            raise RockyIsolationError("forked config authentication failed")
        if type(root_identity) is not list or len(root_identity) != 2 or any(
            type(value) is not int or value < 0 for value in root_identity
        ):
            raise ValueError("root identity schema is invalid")
        if root_path.parent.resolve(strict=True) != config.root_parent:
            raise RockyIsolationError("ephemeral root is outside the configured parent")
        root_status = root_path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(root_status.st_mode) or [root_status.st_dev, root_status.st_ino] != root_identity:
            raise RockyIsolationError("ephemeral root identity changed")
        if any(root_path.iterdir()):
            raise RockyIsolationError("ephemeral root is not empty")
        phase = "namespace_init_source_authentication"
        observed_worker_source_sha256 = _executing_worker_source_sha256(
            after_unshare=True
        )
        observed_interpreter_sha256 = _executing_interpreter_sha256(
            after_unshare=True
        )
        interpreter_pin = _exact_interpreter_pin_wire(interpreter_pin)
        if observed_worker_source_sha256 != worker_source_sha256 or worker_source_sha256 != config.worker_source_sha256:
            raise RockyIsolationError("worker source authentication failed")
        if observed_interpreter_sha256 != interpreter_sha256 or interpreter_sha256 != config.interpreter_sha256:
            raise RockyIsolationError("interpreter authentication failed")
        for bind in config.binds:
            if _digest_source_fd_after_unshare(bind) != bind.expected_sha256:
                raise RockyIsolationError("authenticated bind digest mismatch")

        phase = "namespace_setup"
        namespace_after = {
            name: os.readlink(f"/proc/self/ns/{name}") for name in _NAMESPACE_NAMES
        }
        namespace_distinct = {
            name: namespace_before[name] != namespace_after[name] for name in namespace_before
        }
        namespace_pid_vector = _namespace_pid_vector()
        if (
            not all(namespace_distinct.values())
            or any(
                namespace_after[name] != namespace_expected[name]
                for name in ("user", "mnt", "net", "ipc")
            )
            or os.getpid() != 1
            or namespace_pid_vector[-1] != 1
            or supervisor_host_pid <= 1
        ):
            raise RockyIsolationUnavailable("PID/IPC namespace-init topology is invalid")
        parent_peer = launcher_peer
        _prctl(_PR_SET_DUMPABLE, 0)
        _mount(None, "/", None, _MS_REC | _MS_PRIVATE)
        root_mount = _mount_entry(Path("/"))
        private_propagation = not any(
            str(value).startswith("shared:") or str(value).startswith("master:")
            for value in root_mount["optional"]
        )
        if not private_propagation:
            raise RockyIsolationUnavailable("mount propagation is not private")
        tmpfs_flags = _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        _mount(
            "tmpfs",
            os.fspath(root_path),
            "tmpfs",
            tmpfs_flags,
            f"mode=0700,size={config.root_tmpfs_bytes}",
        )
        tmpfs_entry = _mount_entry(root_path)
        tmpfs_root = tmpfs_entry["filesystem"] == "tmpfs"
        if not tmpfs_root:
            raise RockyIsolationUnavailable("ephemeral root is not tmpfs")

        phase = "readonly_bind_setup"
        bind_evidence = [_bind_readonly(root_path, bind) for bind in config.binds]
        phase = "gpu_device_setup"
        device_evidence = [_bind_device(root_path, device) for device in config.devices]
        device_dir = _inside(root_path, PurePosixPath("/dev"))
        observed_devices = sorted(item.name for item in device_dir.iterdir())
        expected_devices = sorted(device.target.name for device in config.devices)
        device_directory_exact = observed_devices == expected_devices
        if not device_directory_exact:
            raise RockyIsolationError("GPU device directory contains an unlisted entry")
        network_connect_denied = _network_connect_denied()
        if not network_connect_denied:
            raise RockyIsolationError("fresh network namespace allowed an external connection")

        phase = "root_switch"
        pycache_host_path = _prepare_workload_pycache(root_path, config)
        last_cap = _cap_last_cap()
        null_status = os.fstat(0)
        if not stat.S_ISCHR(null_status.st_mode):
            raise RockyIsolationError("standard descriptors are not null character devices")
        null_rdev = null_status.st_rdev
        executing_identity_fds = _executing_identity_fds()
        _close_unneeded_fds(
            frozenset({channel.fileno(), *executing_identity_fds})
        )
        expected_fds = frozenset(
            {0, 1, 2, channel.fileno(), *executing_identity_fds}
        )
        if _open_descriptors() != expected_fds:
            raise RockyIsolationError("descriptor allowlist is not exact before chroot")
        os.chroot(root_path)
        os.chdir("/")
        os.environ.clear()
        os.environ.update(config.workload_environment)
        sys.pycache_prefix = config.workload_environment["PYTHONPYCACHEPREFIX"]
        sys.dont_write_bytecode = True
        if any(Path(sys.pycache_prefix).iterdir()) or not pycache_host_path.name:
            raise RockyIsolationError("workload pycache prefix was not empty at root switch")
        _rewrite_python_paths(config)
        protected_denials = _protected_path_denials(config.protected_host_paths)
        if not all(protected_denials.values()):
            raise RockyIsolationError("a protected host path is visible inside chroot")
        proc_absent = not Path("/proc").exists()
        etc_passwd_absent = not Path("/etc/passwd").exists()
        if not (proc_absent and etc_passwd_absent):
            raise RockyIsolationError("host proc or account database is visible inside chroot")

        phase = "privilege_drop"
        capabilities_empty = _drop_all_capabilities(last_cap)
        if not capabilities_empty:
            raise RockyIsolationError("Linux capabilities were not completely dropped")
        seccomp_sha256 = _install_seccomp_filter()
        no_new_privileges = _prctl(_PR_GET_NO_NEW_PRIVS) == 1
        seccomp_filter = _prctl(_PR_GET_SECCOMP) == _SECCOMP_MODE_FILTER
        if not (no_new_privileges and seccomp_filter):
            raise RockyIsolationError("no-new-privileges/seccomp attestation failed")

        phase = "active_denial_probes"
        try:
            forbidden_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            socket_creation_denied = exc.errno == errno.EPERM
        else:
            forbidden_socket.close()
            socket_creation_denied = False
        Path("/tmp").mkdir(mode=0o700, exist_ok=True)
        try:
            _mount("tmpfs", "/tmp", "tmpfs", _MS_NOSUID, "size=4096")
        except OSError as exc:
            mount_after_drop_denied = exc.errno == errno.EPERM
        else:
            mount_after_drop_denied = False
        try:
            _prctl(_PR_SET_PDEATHSIG, 0)
        except OSError as exc:
            pdeathsig_change_denied = exc.errno == errno.EPERM
        else:
            pdeathsig_change_denied = False
        try:
            _prctl(_PR_SET_DUMPABLE, 1)
        except OSError as exc:
            dumpable_change_denied = exc.errno == errno.EPERM
        else:
            dumpable_change_denied = False
        ctypes.set_errno(0)
        ptrace_result = _LIBC.ptrace(0, 0, 0, 0)
        ptrace_denied = ptrace_result < 0 and ctypes.get_errno() == errno.EPERM
        ctypes.set_errno(0)
        pidfd_result = _LIBC.syscall(434, os.getppid(), 0)
        pidfd_open_denied = pidfd_result < 0 and ctypes.get_errno() == errno.EPERM
        if pidfd_result >= 0:
            os.close(pidfd_result)
        descriptors_exact = _open_descriptors() == expected_fds
        standard_descriptors_null = all(
            stat.S_ISCHR(os.fstat(descriptor).st_mode)
            and os.fstat(descriptor).st_rdev == null_rdev
            for descriptor in (0, 1, 2)
        )
        pdeathsig_kill = _pdeathsig_is_kill()
        dumpable_zero = _prctl(_PR_GET_DUMPABLE) == 0
        if not all(
            (
                socket_creation_denied,
                mount_after_drop_denied,
                pdeathsig_change_denied,
                dumpable_change_denied,
                ptrace_denied,
                pidfd_open_denied,
                descriptors_exact,
                standard_descriptors_null,
                pdeathsig_kill,
                dumpable_zero,
            )
        ):
            raise RockyIsolationError("one or more post-drop active controls failed")

        capabilities = RockyLiveCapabilityReport(
            linux=sys.platform == "linux",
            x86_64=os.uname().machine == "x86_64",
            user_namespace=namespace_distinct["user"],
            mount_namespace=namespace_distinct["mnt"],
            network_namespace=namespace_distinct["net"],
            ipc_namespace=namespace_distinct["ipc"],
            pid_namespace=namespace_distinct["pid"],
            namespace_pid_one=os.getpid() == 1 and namespace_pid_vector[-1] == 1,
            private_mount_propagation=private_propagation,
            tmpfs_root=tmpfs_root,
            chroot=proc_absent and etc_passwd_absent,
            no_new_privileges=no_new_privileges,
            capabilities_empty=capabilities_empty,
            seccomp_filter=seccomp_filter,
            unix_seqpacket=True,
            unix_peer_credentials=True,
            exact_gpu_devices=device_directory_exact,
        )
        validate_live_capabilities(capabilities)
        challenge_sha256 = hashlib.sha256(bytes.fromhex(challenge)).hexdigest()
        environment = dict(sorted(os.environ.items()))
        if environment != dict(config.workload_environment):
            raise RockyIsolationError("workload environment is not exact")
        attestation = {
            "backend_id": BACKEND_ID,
            "binds": bind_evidence,
            "capabilities": capabilities.to_wire(),
            "challenge_sha256": challenge_sha256,
            "config_sha256": config_sha256,
            "descriptors_exact": descriptors_exact,
            "device_directory_exact": device_directory_exact,
            "devices": device_evidence,
            "dumpable_change_denied": dumpable_change_denied,
            "dumpable_zero": dumpable_zero,
            "environment": environment,
            "etc_passwd_absent": etc_passwd_absent,
            "hostname": socket.gethostname(),
            "interpreter_sha256": interpreter_sha256,
            "interpreter_pin": interpreter_pin,
            "kernel_release": os.uname().release,
            "mount_after_drop_denied": mount_after_drop_denied,
            "namespace_after": namespace_after,
            "namespace_before": namespace_before,
            "namespace_init": {
                "namespace_pid": os.getpid(),
                "nspid": namespace_pid_vector,
                "supervisor_host_pid": supervisor_host_pid,
            },
            "network_connect_denied": network_connect_denied,
            "pdeathsig_change_denied": pdeathsig_change_denied,
            "pdeathsig_kill": pdeathsig_kill,
            "peer": {"gid": parent_peer[2], "pid": parent_peer[0], "uid": parent_peer[1]},
            "pid": os.getpid(),
            "proc_absent": proc_absent,
            "protected_denials": protected_denials,
            "pycache_prefix_empty": not any(Path(sys.pycache_prefix).iterdir()),
            "ptrace_denied": ptrace_denied,
            "pidfd_open_denied": pidfd_open_denied,
            "rlimits": {
                "core": list(resource.getrlimit(resource.RLIMIT_CORE)),
                "fsize": list(resource.getrlimit(resource.RLIMIT_FSIZE)),
                "nofile": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
                "nproc": list(resource.getrlimit(resource.RLIMIT_NPROC)),
            },
            "root": {
                "host_root_detached": True,
                "private_mount_propagation": private_propagation,
                "tmpfs": tmpfs_root,
            },
            "schema_version": SCHEMA_VERSION,
            "seccomp_filter_sha256": seccomp_sha256,
            "socket_creation_denied": socket_creation_denied,
            "standard_descriptors_null": standard_descriptors_null,
            "worker_source_sha256": worker_source_sha256,
            "worker_inline_loader_sha256": worker_inline_loader_sha256,
            "worker_bootstrap_flags": worker_bootstrap_flags,
        }
        send_packet(channel, {"attestation": attestation, "type": "ready"})

        phase = "command_loop"
        while True:
            command = recv_packet(channel)
            if command == {"type": "stop"}:
                end_digests = {
                    bind.label: _digest_path(Path(bind.target.as_posix())) for bind in config.binds
                }
                if end_digests != {bind.label: bind.expected_sha256 for bind in config.binds}:
                    raise RockyIsolationError("authenticated bind changed before shutdown")
                worker_source_end_sha256 = _executing_worker_source_sha256(
                    after_unshare=True
                )
                interpreter_end_sha256 = _executing_interpreter_sha256(
                    after_unshare=True
                )
                if (
                    worker_source_end_sha256 != worker_source_sha256
                    or interpreter_end_sha256 != interpreter_sha256
                ):
                    raise RockyIsolationError(
                        "executing worker/interpreter identity drifted before shutdown"
                    )
                pycache_prefix_empty = not any(Path(sys.pycache_prefix).iterdir())
                if not pycache_prefix_empty:
                    raise RockyIsolationError("workload pycache prefix was populated")
                send_packet(
                    channel,
                    {
                        "bind_end_sha256": end_digests,
                        "challenge_sha256": challenge_sha256,
                        "config_sha256": config_sha256,
                        "interpreter_end_sha256": interpreter_end_sha256,
                        "pycache_prefix_empty": True,
                        "type": "final",
                        "worker_source_end_sha256": worker_source_end_sha256,
                    },
                )
                return 0
            if command == {"type": "cuda_allocation_diagnostic"}:
                result = _cuda_allocation_diagnostic(config)
                send_packet(channel, {"result": result, "type": "cuda_allocation_result"})
                continue
            if type(command) is dict and command.get("type") == "host_isolation_probe":
                result = _host_process_ipc_isolation_probe(command)
                send_packet(channel, {"result": result, "type": "host_isolation_result"})
                continue
            if command == {"type": "descendant_reap_diagnostic"}:
                result = _descendant_reap_diagnostic()
                send_packet(channel, {"result": result, "type": "descendant_reap_result"})
                continue
            if command == {"type": "namespace_crash_diagnostic"}:
                child_pid = _arm_lingering_descendant(channel, "crash")
                send_packet(
                    channel,
                    {
                        "child_namespace_pid": child_pid,
                        "type": "namespace_crash_armed",
                    },
                )
                os.kill(os.getpid(), signal.SIGKILL)
                os._exit(129)
            if command == {"type": "namespace_hang_diagnostic"}:
                _arm_lingering_descendant(channel, "hang")
                while True:
                    signal.pause()
            if command == {"type": "namespace_parent_death_diagnostic"}:
                _arm_lingering_descendant(channel, "parent_death")
                while True:
                    signal.pause()
            raise ValueError("worker command is outside the frozen diagnostic protocol")
    except _NamespaceTermination as exc:
        return 128 + exc.signum
    except BaseException as exc:
        _worker_error(channel, phase, exc)
        return {
            "namespace_init_hardening": 120,
            "namespace_init_source_authentication": 121,
            "namespace_setup": 122,
            "readonly_bind_setup": 123,
            "gpu_device_setup": 124,
            "root_switch": 125,
            "privilege_drop": 126,
            "active_denial_probes": 127,
            "command_loop": 128,
        }.get(phase, 119)
    finally:
        try:
            _force_kill_and_reap_namespace_children()
        except BaseException:
            # A non-reapable descendant must never coexist with a successful
            # supervisor status.  Abrupt PID-1 exit invokes the kernel's PID
            # namespace teardown and makes the outer reaper report failure.
            os._exit(139)
        if previous_handlers:
            _restore_signal_handlers(previous_handlers)
        channel.close()


def _validate_ready_packet(
    packet: Mapping[str, object],
    config: RockyGPUIsolationConfig,
    *,
    expected_interpreter_pin: dict[str, object],
    expected_init_host_pid: int,
    expected_supervisor_host_pid: int,
    expected_launcher_pid: int,
    expected_namespaces: Mapping[str, str],
    challenge: bytes,
) -> RockyIsolationAttestation:
    if type(packet) is not dict:
        raise RockyIsolationError("worker returned a non-object packet")
    packet_type = packet.get("type")
    if type(packet_type) is not str:
        raise RockyIsolationError("worker packet type is invalid")
    if packet_type == "error":
        if (
            set(packet) != {"errno", "phase", "reason", "type"}
            or type(packet["errno"]) is not int
            or packet["errno"] < 0
            or type(packet["phase"]) is not str
            or not packet["phase"]
            or type(packet["reason"]) is not str
            or not packet["reason"]
        ):
            raise RockyIsolationError("worker error packet schema is invalid")
        raise RockyIsolationError(
            f"worker {packet.get('phase')} failed closed ({packet.get('reason')}, errno={packet.get('errno')})"
        )
    if set(packet) != {"attestation", "type"} or packet_type != "ready":
        raise RockyIsolationError("worker did not return a strict ready attestation")
    evidence = packet["attestation"]
    required = {
        "backend_id",
        "binds",
        "capabilities",
        "challenge_sha256",
        "config_sha256",
        "descriptors_exact",
        "device_directory_exact",
        "devices",
        "dumpable_change_denied",
        "dumpable_zero",
        "environment",
        "etc_passwd_absent",
        "hostname",
        "interpreter_pin",
        "interpreter_sha256",
        "kernel_release",
        "mount_after_drop_denied",
        "namespace_after",
        "namespace_before",
        "namespace_init",
        "network_connect_denied",
        "pdeathsig_change_denied",
        "pdeathsig_kill",
        "peer",
        "pid",
        "proc_absent",
        "protected_denials",
        "pycache_prefix_empty",
        "ptrace_denied",
        "pidfd_open_denied",
        "rlimits",
        "root",
        "schema_version",
        "seccomp_filter_sha256",
        "socket_creation_denied",
        "standard_descriptors_null",
        "worker_source_sha256",
        "worker_inline_loader_sha256",
        "worker_bootstrap_flags",
    }
    if type(evidence) is not dict or set(evidence) != required:
        raise RockyIsolationError("worker attestation schema is invalid")
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != SCHEMA_VERSION
        or type(evidence["backend_id"]) is not str
        or evidence["backend_id"] != BACKEND_ID
    ):
        raise RockyIsolationError("worker attestation version/backend mismatch")
    expected_config = canonical_config_sha256(config)
    expected_challenge = hashlib.sha256(challenge).hexdigest()
    if evidence["config_sha256"] != expected_config:
        raise RockyIsolationError("worker attestation config digest mismatch")
    if evidence["challenge_sha256"] != expected_challenge:
        raise RockyIsolationError("worker attestation challenge mismatch")
    if evidence["worker_source_sha256"] != config.worker_source_sha256:
        raise RockyIsolationError("worker source attestation mismatch")
    if evidence["worker_inline_loader_sha256"] != hashlib.sha256(
        _worker_inline_source(
            config.worker_source_sha256, config.interpreter_sha256
        ).encode("ascii")
    ).hexdigest():
        raise RockyIsolationError("worker inline-loader attestation mismatch")
    if not _exact_json_equal(
        evidence["worker_bootstrap_flags"],
        {
            "isolated": True,
            "no_bytecode": True,
            "no_site": True,
            "pycache_empty": True,
        },
    ):
        raise RockyIsolationError("worker bootstrap isolation flags are invalid")
    if evidence["interpreter_sha256"] != config.interpreter_sha256:
        raise RockyIsolationError("worker interpreter attestation mismatch")
    if (
        _exact_interpreter_pin_wire(evidence["interpreter_pin"])
        != _exact_interpreter_pin_wire(expected_interpreter_pin)
    ):
        raise RockyIsolationError("worker interpreter pin attestation mismatch")
    if type(evidence["pid"]) is not int or evidence["pid"] != 1:
        raise RockyIsolationError("worker is not namespace PID 1")
    peer = evidence["peer"]
    if not _exact_json_equal(
        peer,
        {
            "pid": expected_launcher_pid,
            "uid": os.getuid(),
            "gid": os.getgid(),
        },
    ):
        raise RockyIsolationError("launcher peer credential attestation mismatch")
    if type(evidence["hostname"]) is not str or not evidence["hostname"]:
        raise RockyIsolationError("worker hostname attestation is invalid")
    if type(evidence["kernel_release"]) is not str or not evidence["kernel_release"]:
        raise RockyIsolationError("worker kernel attestation is invalid")
    capabilities = RockyLiveCapabilityReport.from_wire(evidence["capabilities"])
    validate_live_capabilities(capabilities)
    for name in (
        "descriptors_exact",
        "device_directory_exact",
        "dumpable_change_denied",
        "dumpable_zero",
        "etc_passwd_absent",
        "mount_after_drop_denied",
        "network_connect_denied",
        "pdeathsig_change_denied",
        "pdeathsig_kill",
        "pidfd_open_denied",
        "proc_absent",
        "ptrace_denied",
        "socket_creation_denied",
        "standard_descriptors_null",
        "pycache_prefix_empty",
    ):
        if evidence[name] is not True:
            raise RockyIsolationError(f"worker control {name} is not enforced")
    if not _exact_json_equal(
        evidence["environment"], dict(config.workload_environment)
    ):
        raise RockyIsolationError("worker environment attestation mismatch")
    protected_names = set(config.protected_host_paths.as_mapping())
    if (
        type(evidence["protected_denials"]) is not dict
        or set(evidence["protected_denials"]) != protected_names
        or any(value is not True for value in evidence["protected_denials"].values())
    ):
        raise RockyIsolationError("worker protected-path denial attestation is incomplete")
    before = evidence["namespace_before"]
    after = evidence["namespace_after"]
    if (
        type(before) is not dict
        or type(after) is not dict
        or set(before) != set(_NAMESPACE_NAMES)
        or set(after) != set(_NAMESPACE_NAMES)
        or any(type(value) is not str for value in list(before.values()) + list(after.values()))
        or any(before[name] == after[name] for name in before)
        or not _exact_json_equal(after, dict(expected_namespaces))
    ):
        raise RockyIsolationError("worker namespace evidence is invalid")
    namespace_init = evidence["namespace_init"]
    if type(namespace_init) is not dict or set(namespace_init) != {
        "namespace_pid",
        "nspid",
        "supervisor_host_pid",
    }:
        raise RockyIsolationError("namespace-init mapping schema is invalid")
    nspid = namespace_init["nspid"]
    if (
        type(namespace_init["namespace_pid"]) is not int
        or namespace_init["namespace_pid"] != 1
        or type(namespace_init["supervisor_host_pid"]) is not int
        or namespace_init["supervisor_host_pid"] != expected_supervisor_host_pid
        or type(nspid) is not list
        or len(nspid) < 2
        or any(type(value) is not int or value <= 0 for value in nspid)
        or nspid[-1] != 1
        or expected_init_host_pid not in nspid
    ):
        raise RockyIsolationError("namespace-init PID mapping is invalid")
    expected_binds = [
        {
            "allow_exec": bind.allow_exec,
            "category": bind.category,
            "label": bind.label,
            "read_probe": True,
            "readonly": True,
            "sha256": bind.expected_sha256,
            "source": os.fspath(bind.source),
            "source_identity": dict(bind.source_identity),
            "source_strategy": "lexical-mount-immediate-retained-fd-cross-bind",
            "target": bind.target.as_posix(),
        }
        for bind in config.binds
    ]
    if not _exact_json_equal(evidence["binds"], expected_binds):
        raise RockyIsolationError("worker bind attestation differs from the frozen allowlist")
    expected_devices = [
        {
            "major": device.major,
            "minor": device.minor,
            "source": os.fspath(device.source),
            "target": device.target.as_posix(),
        }
        for device in config.devices
    ]
    if not _exact_json_equal(evidence["devices"], expected_devices):
        raise RockyIsolationError("worker GPU device attestation differs from the frozen allowlist")
    if not _exact_json_equal(
        evidence["root"],
        {
            "host_root_detached": True,
            "private_mount_propagation": True,
            "tmpfs": True,
        },
    ):
        raise RockyIsolationError("worker root filesystem attestation is invalid")
    if evidence["seccomp_filter_sha256"] != _seccomp_filter_sha256():
        raise RockyIsolationError("worker seccomp policy digest mismatch")
    rlimits = evidence["rlimits"]
    if type(rlimits) is not dict or set(rlimits) != {"core", "fsize", "nofile", "nproc"}:
        raise RockyIsolationError("worker rlimit attestation schema is invalid")
    if not _exact_json_equal(rlimits["core"], [0, 0]):
        raise RockyIsolationError("worker core rlimit is not sealed")
    for name in ("fsize", "nofile", "nproc"):
        values = rlimits[name]
        if (
            type(values) is not list
            or len(values) != 2
            or any(type(value) is not int or value < 0 for value in values)
        ):
            raise RockyIsolationError("worker rlimit value is invalid")
        if values[0] > values[1]:
            raise RockyIsolationError("worker rlimit soft value exceeds hard value")
    serialized = json.dumps(evidence, sort_keys=True)
    if any(os.fspath(path) in serialized for path in config.protected_host_paths.as_mapping().values()):
        raise RockyIsolationError("public attestation reveals a protected host path")
    return RockyIsolationAttestation(capabilities=capabilities, _wire=evidence)


def _validate_supervisor_topology_packet(
    topology: object,
    credentials: object,
    *,
    expected_supervisor_pid: int,
) -> tuple[int, dict[str, str]]:
    required = {
        "init_host_pid",
        "namespace_expected",
        "supervisor_host_pid",
        "type",
    }
    if (
        type(topology) is not dict
        or set(topology) != required
        or type(topology["type"]) is not str
        or topology["type"] != "namespace_supervisor"
    ):
        raise RockyIsolationError("outer supervisor topology packet is invalid")
    expected_credentials = (
        expected_supervisor_pid,
        os.getuid(),
        os.getgid(),
    )
    if (
        type(credentials) is not tuple
        or len(credentials) != 3
        or any(type(value) is not int for value in credentials)
        or credentials != expected_credentials
    ):
        raise RockyIsolationError("launcher observed wrong supervisor credentials")
    if (
        type(topology["supervisor_host_pid"]) is not int
        or topology["supervisor_host_pid"] != expected_supervisor_pid
    ):
        raise RockyIsolationError("supervisor PID topology mismatch")
    init_host_pid = topology["init_host_pid"]
    if type(init_host_pid) is not int or init_host_pid <= 1:
        raise RockyIsolationError("namespace-init host PID is invalid")
    namespace_expected = topology["namespace_expected"]
    if (
        type(namespace_expected) is not dict
        or set(namespace_expected) != set(_NAMESPACE_NAMES)
        or any(type(value) is not str for value in namespace_expected.values())
    ):
        raise RockyIsolationError("supervisor namespace topology is invalid")
    return init_host_pid, dict(namespace_expected)


class RockySandboxRun:
    """A live isolated worker with a single private control/data channel."""

    def __init__(
        self,
        *,
        config: RockyGPUIsolationConfig,
        process: subprocess.Popen[bytes],
        channel: socket.socket,
        bootstrap_pycache_path: Path,
        root_path: Path,
        challenge: bytes,
        attestation: RockyIsolationAttestation,
        init_host_pid: int,
    ) -> None:
        self.config = config
        self.process = process
        self._channel = channel
        self._bootstrap_pycache_path = bootstrap_pycache_path
        self._root_path = root_path
        self.challenge = challenge
        self.attestation = attestation
        self.init_host_pid = init_host_pid
        self.final_attestation: dict[str, object] | None = None
        self.namespace_cleanup_confirmed = False
        self._closed = False

    @staticmethod
    def _pid_absent(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except OSError as exc:
            return exc.errno == errno.ESRCH
        return False

    @classmethod
    def _wait_pid_absent(cls, pid: int, timeout_seconds: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if cls._pid_absent(pid):
                return True
            time.sleep(0.01)
        return cls._pid_absent(pid)

    def _cleanup_local_state(self) -> None:
        self._channel.close()
        error: OSError | None = None
        try:
            self._root_path.rmdir()
        except FileNotFoundError:
            pass
        except OSError as exc:
            error = exc
        try:
            if any(self._bootstrap_pycache_path.iterdir()):
                raise RockyIsolationError("worker bootstrap pycache prefix was populated")
            self._bootstrap_pycache_path.rmdir()
        except FileNotFoundError:
            pass
        except BaseException as exc:
            if error is None:
                error = exc
        self._closed = True
        if error is not None:
            raise RockyIsolationError(f"ephemeral root cleanup failed: errno={error.errno}")

    def _watchdog_reap(self) -> int:
        if self.process.poll() is None:
            self.process.send_signal(_WATCHDOG_SIGNAL)
            try:
                return_code = self.process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                return_code = self.process.wait(timeout=10.0)
        else:
            return_code = int(self.process.returncode)
        return return_code

    def host_isolation_probe(
        self,
        *,
        victim_pid: int,
        sysv_shmid: int,
        posix_shm_name: str,
    ) -> dict[str, object]:
        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(
            self._channel,
            {
                "posix_shm_name": posix_shm_name,
                "sysv_shmid": sysv_shmid,
                "type": "host_isolation_probe",
                "victim_pid": victim_pid,
            },
        )
        packet = recv_packet(self._channel)
        packet_type = packet.get("type")
        if type(packet_type) is not str:
            raise RockyIsolationError("host-isolation packet type is invalid")
        if packet_type == "error":
            cuda_detail = ""
            if {
                "cuda_cause",
                "cuda_errno",
                "cuda_stage",
            }.issubset(packet):
                cuda_detail = (
                    f", cuda_stage={packet['cuda_stage']},"
                    f" cuda_cause={packet['cuda_cause']}, cuda_errno={packet['cuda_errno']}"
                )
            raise RockyIsolationError(
                f"worker {packet.get('phase')} failed closed ({packet.get('reason')}{cuda_detail})"
            )
        if set(packet) != {"result", "type"} or packet_type != "host_isolation_result":
            raise RockyIsolationError("host-isolation probe returned an invalid packet")
        result = packet["result"]
        required = {
            "host_pid_invisible",
            "posix_shm_denied",
            "posix_shm_errno",
            "same_uid_signal_denied",
            "same_uid_signal_errno",
            "sysv_shm_denied",
            "sysv_shm_errno",
        }
        if type(result) is not dict or set(result) != required:
            raise RockyIsolationError("host-isolation result schema is invalid")
        if any(result[name] is not True for name in (
            "host_pid_invisible",
            "posix_shm_denied",
            "same_uid_signal_denied",
            "sysv_shm_denied",
        )):
            raise RockyIsolationError("host process/IPC isolation probe failed")
        errno_allowlists = {
            "posix_shm_errno": {
                errno.EACCES,
                errno.ENOENT,
                errno.ENOTDIR,
                errno.EPERM,
            },
            "same_uid_signal_errno": {errno.ESRCH},
            "sysv_shm_errno": {
                errno.EACCES,
                errno.EIDRM,
                errno.EINVAL,
                errno.EPERM,
            },
        }
        if any(
            type(result[name]) is not int
            or result[name] not in allowed
            for name, allowed in errno_allowlists.items()
        ):
            raise RockyIsolationError("host process/IPC denial errno is invalid")
        return dict(result)

    def descendant_reap_diagnostic(self) -> dict[str, object]:
        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(self._channel, {"type": "descendant_reap_diagnostic"})
        packet = recv_packet(self._channel)
        packet_type = packet.get("type")
        if type(packet_type) is not str:
            raise RockyIsolationError("descendant-reap packet type is invalid")
        if packet_type == "error":
            raise RockyIsolationError(
                f"worker {packet.get('phase')} failed closed ({packet.get('reason')})"
            )
        if set(packet) != {"result", "type"} or packet_type != "descendant_reap_result":
            raise RockyIsolationError("descendant-reap diagnostic returned an invalid packet")
        result = packet["result"]
        expected = {
            "direct_namespace_pid": 2,
            "direct_status": {"exit_code": 17, "signal": 0},
            "grandchild_namespace_pid": 3,
            "grandchild_status": {"exit_code": 23, "signal": 0},
            "namespace_init_pid": 1,
            "no_children_remaining": True,
        }
        if not _exact_json_equal(result, expected):
            raise RockyIsolationError("namespace-init descendant reaping failed")
        return dict(result)

    def _receive_lingering_descendant(self, mode: str) -> int:
        packet, credentials = _recv_packet_with_credentials(self._channel)
        pid, uid, gid = credentials
        if not _exact_json_equal(
            packet,
            {"mode": mode, "namespace_pid": 2, "type": "lingering_descendant"},
        ):
            raise RockyIsolationError("lingering-descendant packet is invalid")
        if pid in {self.init_host_pid, self.process.pid} or (uid, gid) != (os.getuid(), os.getgid()):
            raise RockyIsolationError("lingering-descendant credentials are invalid")
        return pid

    def crash_cleanup_diagnostic(self) -> dict[str, object]:
        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(self._channel, {"type": "namespace_crash_diagnostic"})
        descendant_host_pid = self._receive_lingering_descendant("crash")
        packet, credentials = _recv_packet_with_credentials(self._channel)
        if not _exact_json_equal(
            packet, {"child_namespace_pid": 2, "type": "namespace_crash_armed"}
        ):
            raise RockyIsolationError("namespace-crash arming packet is invalid")
        if credentials != (self.init_host_pid, os.getuid(), os.getgid()):
            raise RockyIsolationError("namespace-crash arming credentials are invalid")
        return_code = self.process.wait(timeout=10.0)
        self._cleanup_local_state()
        init_absent = self._wait_pid_absent(self.init_host_pid)
        descendant_absent = self._wait_pid_absent(descendant_host_pid)
        self.namespace_cleanup_confirmed = init_absent and descendant_absent
        if return_code == 0 or not self.namespace_cleanup_confirmed:
            raise RockyIsolationError("namespace-init crash left a descendant or succeeded unexpectedly")
        return {
            "descendant_absent": descendant_absent,
            "descendant_host_pid": descendant_host_pid,
            "init_absent": init_absent,
            "init_host_pid": self.init_host_pid,
            "supervisor_return_code": return_code,
        }

    def watchdog_cleanup_diagnostic(self) -> dict[str, object]:
        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(self._channel, {"type": "namespace_hang_diagnostic"})
        descendant_host_pid = self._receive_lingering_descendant("hang")
        return_code = self._watchdog_reap()
        self._cleanup_local_state()
        init_absent = self._wait_pid_absent(self.init_host_pid)
        descendant_absent = self._wait_pid_absent(descendant_host_pid)
        self.namespace_cleanup_confirmed = init_absent and descendant_absent
        if return_code == 0 or not self.namespace_cleanup_confirmed:
            raise RockyIsolationError("outer watchdog left a namespace descendant")
        return {
            "descendant_absent": descendant_absent,
            "descendant_host_pid": descendant_host_pid,
            "init_absent": init_absent,
            "init_host_pid": self.init_host_pid,
            "supervisor_return_code": return_code,
        }

    def parent_death_cleanup_diagnostic(self) -> dict[str, object]:
        """Kill the outer supervisor and verify the PDEATHSIG cascade."""

        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(self._channel, {"type": "namespace_parent_death_diagnostic"})
        descendant_host_pid = self._receive_lingering_descendant("parent_death")
        self.process.kill()
        return_code = self.process.wait(timeout=10.0)
        init_absent = self._wait_pid_absent(self.init_host_pid)
        descendant_absent = self._wait_pid_absent(descendant_host_pid)
        self._cleanup_local_state()
        self.namespace_cleanup_confirmed = init_absent and descendant_absent
        if return_code != -signal.SIGKILL or not self.namespace_cleanup_confirmed:
            raise RockyIsolationError("PDEATHSIG cascade left a namespace descendant")
        return {
            "descendant_absent": descendant_absent,
            "descendant_host_pid": descendant_host_pid,
            "init_absent": init_absent,
            "init_host_pid": self.init_host_pid,
            "supervisor_return_code": return_code,
        }

    def malformed_cleanup_diagnostic(self) -> dict[str, object]:
        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(self._channel, {"type": "malformed"})
        packet, credentials = _recv_packet_with_credentials(self._channel)
        expected_credentials = (self.init_host_pid, os.getuid(), os.getgid())
        exact_failure = _exact_json_equal(
            packet,
            {
                "errno": 0,
                "phase": "command_loop",
                "reason": "ValueError",
                "type": "error",
            },
        ) and (
            type(credentials) is tuple
            and len(credentials) == 3
            and all(type(value) is int for value in credentials)
            and credentials == expected_credentials
        )
        return_code = self.process.wait(timeout=10.0)
        self._cleanup_local_state()
        init_absent = self._wait_pid_absent(self.init_host_pid)
        self.namespace_cleanup_confirmed = init_absent
        if not exact_failure:
            raise RockyIsolationError("malformed-command failure packet is invalid")
        if return_code == 0 or not init_absent:
            raise RockyIsolationError("malformed worker was not reaped")
        return {
            "init_absent": init_absent,
            "init_host_pid": self.init_host_pid,
            "phase": packet["phase"],
            "supervisor_return_code": return_code,
        }

    def cuda_allocation_diagnostic(self) -> dict[str, object]:
        if self._closed:
            raise RockyIsolationError("isolated worker is closed")
        send_packet(self._channel, {"type": "cuda_allocation_diagnostic"})
        packet = recv_packet(self._channel)
        packet_type = packet.get("type")
        if type(packet_type) is not str:
            raise RockyIsolationError("CUDA diagnostic packet type is invalid")
        if packet_type == "error":
            raise RockyIsolationError(
                f"worker {packet.get('phase')} failed closed ({packet.get('reason')})"
            )
        if set(packet) != {"result", "type"} or packet_type != "cuda_allocation_result":
            raise RockyIsolationError("CUDA diagnostic returned an invalid packet")
        result = packet["result"]
        required = {
            "allocated_after_bytes",
            "allocated_before_bytes",
            "allocated_bytes",
            "allocated_during_bytes",
            "checksum",
            "cuda_driver_api_version",
            "cuda_runtime",
            "device_count",
            "device_name",
            "device_total_memory_bytes",
            "device_uuid",
            "diagnostic_only",
            "forbidden_modules_absent",
            "model_loaded",
            "tokenizer_loaded",
            "torch_version",
            "vllm_imported",
        }
        if type(result) is not dict or set(result) != required:
            raise RockyIsolationError("CUDA diagnostic result schema is invalid")
        if (
            result["diagnostic_only"] is not True
            or result["forbidden_modules_absent"] is not True
            or result["model_loaded"] is not False
            or result["tokenizer_loaded"] is not False
            or result["vllm_imported"] is not False
        ):
            raise RockyIsolationError("CUDA diagnostic mislabeled its evidence boundary")
        if (
            type(result["checksum"]) is not float
            or result["checksum"] != 1024.0
            or type(result["allocated_bytes"]) is not int
            or result["allocated_bytes"] != 4096
        ):
            raise RockyIsolationError("CUDA diagnostic allocation evidence is invalid")
        if (
            type(result["allocated_before_bytes"]) is not int
            or type(result["allocated_during_bytes"]) is not int
            or type(result["allocated_after_bytes"]) is not int
            or result["allocated_before_bytes"] < 0
            or result["allocated_during_bytes"] < 0
            or result["allocated_after_bytes"] < 0
            or result["allocated_during_bytes"] - result["allocated_before_bytes"] < 4096
            or result["allocated_after_bytes"] != result["allocated_before_bytes"]
        ):
            raise RockyIsolationError("CUDA diagnostic did not prove allocation release")
        expected_device_count = len(
            self.config.workload_environment["CUDA_VISIBLE_DEVICES"].split(",")
        )
        if (
            type(result["cuda_driver_api_version"]) is not int
            or result["cuda_driver_api_version"] <= 0
            or type(result["device_count"]) is not int
            or result["device_count"] != expected_device_count
            or type(result["cuda_runtime"]) is not str
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", result["cuda_runtime"])
            is None
            or type(result["torch_version"]) is not str
            or re.fullmatch(
                r"[0-9][0-9A-Za-z.+_-]{0,127}", result["torch_version"]
            )
            is None
            or type(result["device_total_memory_bytes"]) is not int
            or result["device_total_memory_bytes"] <= 0
            or type(result["device_name"]) is not str
            or not result["device_name"]
            or type(result["device_uuid"]) is not str
            or re.fullmatch(
                r"GPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                result["device_uuid"],
            )
            is None
        ):
            raise RockyIsolationError("CUDA diagnostic device identity is invalid")
        return dict(result)

    def close(self) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        try:
            send_packet(self._channel, {"type": "stop"})
            packet = recv_packet(self._channel)
            if packet.get("type") == "error":
                raise RockyIsolationError(
                    f"worker {packet.get('phase')} failed closed ({packet.get('reason')})"
                )
            expected = {
                "bind_end_sha256": {
                    bind.label: bind.expected_sha256 for bind in self.config.binds
                },
                "challenge_sha256": hashlib.sha256(self.challenge).hexdigest(),
                "config_sha256": canonical_config_sha256(self.config),
                "interpreter_end_sha256": self.config.interpreter_sha256,
                "pycache_prefix_empty": True,
                "type": "final",
                "worker_source_end_sha256": self.config.worker_source_sha256,
            }
            if not _exact_json_equal(packet, expected):
                raise RockyIsolationError("worker final digest attestation mismatch")
            self.final_attestation = dict(packet)
            return_code = self.process.wait(timeout=10.0)
            if return_code != 0:
                raise RockyIsolationError(f"worker exited with status {return_code}")
        except BaseException as exc:
            error = exc
            if self.process.poll() is None:
                self._watchdog_reap()
        finally:
            self._channel.close()
            try:
                self._root_path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                if error is None:
                    error = RockyIsolationError(f"ephemeral root cleanup failed: errno={exc.errno}")
            try:
                if any(self._bootstrap_pycache_path.iterdir()):
                    raise RockyIsolationError("worker bootstrap pycache prefix was populated")
                self._bootstrap_pycache_path.rmdir()
            except FileNotFoundError:
                pass
            except BaseException as exc:
                if error is None:
                    error = exc
            self._closed = True
            self.namespace_cleanup_confirmed = self._wait_pid_absent(self.init_host_pid)
            if not self.namespace_cleanup_confirmed and error is None:
                error = RockyIsolationError("namespace init remained after close")
        if error is not None:
            raise error

    def __enter__(self) -> "RockySandboxRun":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _root_parent_is_local(path: Path) -> bool:
    candidates = []
    for entry in _mount_table():
        mountpoint = Path(entry["mountpoint"])
        if _under(path, mountpoint):
            candidates.append((len(mountpoint.parts), entry))
    if not candidates:
        return False
    filesystem = max(candidates, key=lambda pair: pair[0])[1]["filesystem"]
    return filesystem not in {"nfs", "nfs4", "cifs", "fuse.sshfs"}


def _prepare_authenticated_launch(
    config: RockyGPUIsolationConfig,
) -> tuple[
    Path,
    int,
    int,
    dict[str, object],
    Path,
    Path,
    os.stat_result,
    socket.socket,
    socket.socket,
    bytes,
]:
    """Create launch resources transactionally and consume bind descriptors.

    Every descriptor or create-only directory acquired here is closed/removed
    if any later preflight step fails.  A successful return transfers ownership
    to ``launch_rocky_gpu_isolation``.
    """

    worker_source_fd = -1
    interpreter_fd = -1
    root_path: Path | None = None
    bootstrap_pycache_path: Path | None = None
    parent_channel: socket.socket | None = None
    child_channel: socket.socket | None = None
    try:
        if not hasattr(socket, "SO_PASSCRED") or not hasattr(socket, "SCM_CREDENTIALS"):
            raise RockyIsolationUnavailable("Linux SCM_CREDENTIALS unavailable")
        source_path = _canonical_lexical_absolute(Path(__file__), "worker source")
        worker_source_fd, worker_source_chain, worker_source_identity = (
            _open_source_chain(source_path, "worker source")
        )
        if (
            worker_source_identity["kind"] != "regular"
            or _sha256_regular_fd(worker_source_fd) != config.worker_source_sha256
        ):
            raise RockyIsolationError(
                "worker source authentication failed before launch"
            )
        _assert_source_rebound(
            source_path,
            worker_source_fd,
            worker_source_chain,
            worker_source_identity,
        )
        interpreter_fd, interpreter_pin = _pin_proc_self_exe(
            config.interpreter_sha256
        )
        for bind in config.binds:
            if _digest_source_fd(bind) != bind.expected_sha256:
                raise RockyIsolationError(
                    "bind authentication digest mismatch before launch"
                )

        root_path = Path(
            tempfile.mkdtemp(prefix="sluice-rocky-root-", dir=config.root_parent)
        )
        bootstrap_pycache_path = Path(
            tempfile.mkdtemp(
                prefix="sluice-rocky-bootstrap-pycache-", dir=config.root_parent
            )
        )
        os.chmod(bootstrap_pycache_path, 0o700)
        if any(bootstrap_pycache_path.iterdir()):
            raise RockyIsolationError(
                "worker bootstrap pycache prefix is not empty"
            )
        os.chmod(root_path, 0o700)
        root_status = root_path.stat(follow_symlinks=False)
        parent_channel, child_channel = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        parent_channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        child_channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        challenge = secrets.token_bytes(32)
        return (
            source_path,
            worker_source_fd,
            interpreter_fd,
            interpreter_pin,
            root_path,
            bootstrap_pycache_path,
            root_status,
            parent_channel,
            child_channel,
            challenge,
        )
    except BaseException:
        for descriptor in (worker_source_fd, interpreter_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        _close_bind_source_fds(config)
        for channel in (child_channel, parent_channel):
            if channel is not None:
                channel.close()
        for path in (bootstrap_pycache_path, root_path):
            if path is not None:
                try:
                    path.rmdir()
                except FileNotFoundError:
                    pass
        raise


def launch_rocky_gpu_isolation(config: RockyGPUIsolationConfig) -> RockySandboxRun:
    """Launch and attest one strict Rocky GPU worker.

    No principal model command is exposed by this module.  Built-ins are
    bounded isolation diagnostics plus an explicitly authorized allocation-
    only CUDA diagnostic.
    """

    if type(config) is not RockyGPUIsolationConfig:
        raise TypeError("config must be RockyGPUIsolationConfig")
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RockyIsolationUnavailable("strict Rocky fallback requires Linux x86_64")
    if not hasattr(socket, "SOCK_SEQPACKET") or not hasattr(socket, "SO_PEERCRED"):
        raise RockyIsolationUnavailable("AF_UNIX SEQPACKET peer credentials unavailable")
    if not _root_parent_is_local(config.root_parent):
        raise RockyIsolationUnavailable("ephemeral root parent must be on a local filesystem")
    (
        source_path,
        worker_source_fd,
        interpreter_fd,
        interpreter_pin,
        root_path,
        bootstrap_pycache_path,
        root_status,
        parent_channel,
        child_channel,
        challenge,
    ) = _prepare_authenticated_launch(config)
    process: subprocess.Popen[bytes] | None = None
    init_host_pid: int | None = None
    try:
        _revalidate_proc_self_exe(interpreter_fd, interpreter_pin)
        worker_inline_source = _worker_inline_source(
            config.worker_source_sha256, config.interpreter_sha256
        )
        worker_inline_sha256 = hashlib.sha256(worker_inline_source.encode("ascii")).hexdigest()
        process = subprocess.Popen(
            [
                f"/proc/self/fd/{interpreter_fd}",
                "-I",
                "-S",
                "-B",
                "-X",
                f"pycache_prefix={bootstrap_pycache_path}",
                "-c",
                worker_inline_source,
                str(worker_source_fd),
                str(interpreter_fd),
                str(child_channel.fileno()),
                str(os.getpid()),
                os.fspath(source_path),
            ],
            close_fds=True,
            env=dict(_BOOTSTRAP_ENVIRONMENT),
            pass_fds=(child_channel.fileno(), interpreter_fd, worker_source_fd, *_bind_source_fds(config)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(worker_source_fd)
        worker_source_fd = -1
        os.close(interpreter_fd)
        interpreter_fd = -1
        _close_bind_source_fds(config)
        child_channel.close()
        parent_channel.settimeout(float(config.startup_timeout_seconds))
        send_packet(
            parent_channel,
            {
                "challenge": challenge.hex(),
                "config": config.to_wire(),
                "interpreter_pin": interpreter_pin,
                "root_identity": [root_status.st_dev, root_status.st_ino],
                "root_path": os.fspath(root_path),
                "worker_inline_loader_sha256": worker_inline_sha256,
                "type": "bootstrap",
            },
        )
        try:
            topology, topology_credentials = _recv_packet_with_credentials(parent_channel)
        except (OSError, EOFError) as exc:
            try:
                return_code = process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return_code = None
            raise RockyIsolationError(
                f"worker channel failed before attestation (status={return_code}, errno={getattr(exc, 'errno', 0)})"
            ) from exc
        if topology.get("type") == "error":
            raise RockyIsolationError(
                f"worker {topology.get('phase')} failed closed ({topology.get('reason')})"
            )
        init_host_pid, namespace_expected = _validate_supervisor_topology_packet(
            topology,
            topology_credentials,
            expected_supervisor_pid=process.pid,
        )
        try:
            packet, packet_credentials = _recv_packet_with_credentials(parent_channel)
        except (OSError, EOFError) as exc:
            raise RockyIsolationError(
                f"namespace init failed before attestation (errno={getattr(exc, 'errno', 0)})"
            ) from exc
        if packet_credentials != (init_host_pid, os.getuid(), os.getgid()):
            raise RockyIsolationError("launcher observed wrong namespace-init credentials")
        attestation = _validate_ready_packet(
            packet,
            config,
            expected_interpreter_pin=interpreter_pin,
            expected_init_host_pid=init_host_pid,
            expected_supervisor_host_pid=process.pid,
            expected_launcher_pid=os.getpid(),
            expected_namespaces=namespace_expected,
            challenge=challenge,
        )
        return RockySandboxRun(
            config=config,
            process=process,
            channel=parent_channel,
            bootstrap_pycache_path=bootstrap_pycache_path,
            root_path=root_path,
            challenge=challenge,
            attestation=attestation,
            init_host_pid=init_host_pid,
        )
    except BaseException:
        if worker_source_fd >= 0:
            os.close(worker_source_fd)
        if interpreter_fd >= 0:
            os.close(interpreter_fd)
        _close_bind_source_fds(config)
        child_channel.close()
        parent_channel.close()
        if process is not None and process.poll() is None:
            try:
                process.send_signal(_WATCHDOG_SIGNAL)
                process.wait(timeout=10.0)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10.0)
        try:
            root_path.rmdir()
        except OSError:
            pass
        try:
            bootstrap_pycache_path.rmdir()
        except OSError:
            pass
        raise


def _main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--worker":
        try:
            ipc_fd = int(argv[2])
            expected_parent_pid = int(argv[3])
        except ValueError:
            return 125
        return _worker_main(ipc_fd, expected_parent_pid)
    return 125


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
