"""Attested Linux process isolation for the Sluice evaluation topology.

The pure validators in :mod:`sluice_v2.isolation` deliberately do not claim
that an unsandboxed interpreter is protected.  This module establishes a
small live topology and derives an :class:`~sluice_v2.isolation.EnforcementReport`
only from kernel state, OS peer credentials, schema-checked IPC, and active
denial probes.

The model bootstrap is ``execve``-separated from the trusted parent.  It gets
an exact positive-allowlist environment, connects only to the monitor's
abstract AF_UNIX endpoint, then enters fresh user and network namespaces and a
Landlock filesystem allowlist.  The evaluated synthetic effect broker is also
placed in fresh namespaces and a deny-all Landlock sandbox after loading its
canary credential and accepting its one monitor connection.

This is a bounded attestation harness, not a general container runtime.  In
particular, the protected paths supplied to ``ProtectedCanaries`` must be
owner-readable non-secret canaries: their names are intentionally presented to
the pre-workload model bootstrap to prove denial.  The same deny-by-default
Landlock policy applies to undeclared real paths without revealing their names.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
from typing import Any, Mapping

from .isolation import (
    BrokerOutcome,
    EffectBroker,
    EnforcementReport,
    IPCEnvelope,
    IPCMessageKind,
    IPCSchemaError,
    IPC_MAX_FRAME_BYTES,
    IsolationManifest,
    IsolationStartupError,
    ProcessRole,
    ProcessTopology,
    sanitize_model_environment,
    validate_startup,
)
# IPCEnvelope.public_event imports this validator lazily.  Load it before a
# model bootstrap installs a deny-by-default filesystem ruleset so validation
# continues from already-mapped trusted code without granting the source tree.
from .observer import TranscriptEvent as _PreloadedTranscriptEvent


LANDLOCK_REQUIRED_ABI = 3

_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNET = 0x40000000
_PR_SET_PDEATHSIG = 1
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39

_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446

_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

_LANDLOCK_ABI3_HANDLED_ACCESS = (
    _LANDLOCK_ACCESS_FS_EXECUTE
    | _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
    | _LANDLOCK_ACCESS_FS_REFER
    | _LANDLOCK_ACCESS_FS_TRUNCATE
)
_LANDLOCK_READ_ONLY_ACCESS = (
    _LANDLOCK_ACCESS_FS_EXECUTE
    | _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
)

_CONTROL_MAX_BYTES = IPC_MAX_FRAME_BYTES
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_SO_PEERCRED_SIZE = struct.calcsize("3i")
_STANDARD_FDS = frozenset({0, 1, 2})

# These variables are interpreted by an operating-system dynamic loader before
# the Python bootstrap can install namespaces, Landlock, or no_new_privs.  A
# positive application environment allowlist must therefore never be able to
# opt them back in.  The prefixes cover ELF/glibc and Darwin dyld families;
# the exact names cover the corresponding AIX, HP-UX, and IRIX mechanisms.
_DYNAMIC_LOADER_ENVIRONMENT_PREFIXES = ("LD_", "DYLD_")
_DYNAMIC_LOADER_ENVIRONMENT_NAMES = frozenset(
    {
        "LIBPATH",
        "SHLIB_PATH",
        "LDR_PRELOAD",
        "LDR_PRELOAD64",
        "_RLD_LIST",
        "_RLDN32_LIST",
        "_RLD64_LIST",
    }
)


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


def _raise_errno(operation: str) -> None:
    value = ctypes.get_errno()
    raise OSError(value, f"{operation} failed")


def _prctl(option: int, argument: int = 0) -> int:
    result = _LIBC.prctl(option, argument, 0, 0, 0)
    if result < 0:
        _raise_errno("prctl")
    return int(result)


def _query_landlock_abi() -> int:
    # The audited syscall numbers below are the Linux x86-64/generic values.
    # Refuse unknown architectures instead of risking a call to an unrelated
    # syscall number.
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "aarch64"}:
        return 0
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result < 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL):
            return 0
        raise OSError(error, "Landlock ABI query failed")
    return int(result)


def _apply_landlock_readonly(paths: tuple[Path, ...]) -> int:
    """Apply an ABI-v3 deny-by-default ruleset with explicit read-only roots."""

    abi = _query_landlock_abi()
    if abi < LANDLOCK_REQUIRED_ABI:
        raise IsolationStartupError(
            f"landlock_abi requires >= {LANDLOCK_REQUIRED_ABI}, detected {abi}"
        )
    attributes = _LandlockRulesetAttr(_LANDLOCK_ABI3_HANDLED_ACCESS)
    ctypes.set_errno(0)
    ruleset_fd = _LIBC.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
        ctypes.c_uint(0),
    )
    if ruleset_fd < 0:
        _raise_errno("landlock_create_ruleset")
    opened: list[int] = []
    try:
        for path in paths:
            descriptor = os.open(
                os.fspath(path), os.O_PATH | os.O_CLOEXEC
            )
            opened.append(descriptor)
            mode = os.fstat(descriptor).st_mode
            allowed = _LANDLOCK_READ_ONLY_ACCESS
            if not stat.S_ISDIR(mode):
                allowed &= ~_LANDLOCK_ACCESS_FS_READ_DIR
            rule = _LandlockPathBeneathAttr(allowed, descriptor)
            ctypes.set_errno(0)
            result = _LIBC.syscall(
                _SYS_LANDLOCK_ADD_RULE,
                ctypes.c_int(ruleset_fd),
                ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule),
                ctypes.c_uint(0),
            )
            if result < 0:
                _raise_errno("landlock_add_rule")
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
        ctypes.set_errno(0)
        result = _LIBC.syscall(
            _SYS_LANDLOCK_RESTRICT_SELF,
            ctypes.c_int(ruleset_fd),
            ctypes.c_uint(0),
        )
        if result < 0:
            _raise_errno("landlock_restrict_self")
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(ruleset_fd)
    return abi


def _write_proc_mapping(path: str, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        encoded = value.encode("ascii")
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise OSError(errno.EIO, "short namespace mapping write")
    finally:
        os.close(descriptor)


def _enter_user_and_network_namespace() -> tuple[str, str]:
    original_uid = os.getuid()
    original_gid = os.getgid()
    ctypes.set_errno(0)
    if _LIBC.unshare(_CLONE_NEWUSER) != 0:
        _raise_errno("unshare user namespace")
    try:
        _write_proc_mapping("/proc/self/setgroups", "deny")
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
    _write_proc_mapping("/proc/self/uid_map", f"0 {original_uid} 1\n")
    _write_proc_mapping("/proc/self/gid_map", f"0 {original_gid} 1\n")
    ctypes.set_errno(0)
    if _LIBC.setresgid(0, 0, 0) != 0:
        _raise_errno("setresgid in user namespace")
    ctypes.set_errno(0)
    if _LIBC.setresuid(0, 0, 0) != 0:
        _raise_errno("setresuid in user namespace")
    ctypes.set_errno(0)
    if _LIBC.unshare(_CLONE_NEWNET) != 0:
        _raise_errno("unshare network namespace")
    return (
        os.readlink("/proc/self/ns/user"),
        os.readlink("/proc/self/ns/net"),
    )


def _harden_process(expected_parent_pid: int | None = None) -> None:
    """Install process hardening and close the parent-death race.

    Production fork sites pass the launcher's PID captured *before* ``fork``.
    Registering ``PR_SET_PDEATHSIG`` and then rechecking that PID is the Linux
    kernel's required race-free pattern: if the parent died before
    registration, the recheck fails; if it dies afterwards, SIGKILL fires.

    The optional form exists for the low-level audit helper.  It still refuses
    an already-orphaned process (PID 1 cannot be a valid launcher), but callers
    establishing a security boundary must pass the pre-fork PID explicitly.
    """

    if expected_parent_pid is None:
        expected_parent_pid = os.getppid()
    if type(expected_parent_pid) is not int:
        raise TypeError("expected_parent_pid must be an integer")
    if expected_parent_pid <= 1 or expected_parent_pid == os.getpid():
        # Raising here would let a careless caller catch the error and keep an
        # orphaned privileged role alive.  This is an internal child-bootstrap
        # primitive, so an unavailable launcher is an unconditional death.
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(111)
    _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != expected_parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(111)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    current_soft, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    ceiling = 64
    hard = ceiling if current_hard == resource.RLIM_INFINITY else min(current_hard, ceiling)
    soft = min(current_soft, hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def _seal_process_visibility() -> None:
    # Setting dumpable=0 before writing uid_map/gid_map changes ownership of
    # the process's /proc files and makes an otherwise permitted unprivileged
    # user-namespace mapping fail with EACCES.  Seal visibility immediately
    # after the mapping is complete and before sandboxed work begins.
    _prctl(_PR_SET_DUMPABLE, 0)


def _no_new_privileges() -> bool:
    return _prctl(_PR_GET_NO_NEW_PRIVS) == 1


def _replace_standard_fds() -> None:
    """Replace every inherited standard descriptor with the null device.

    Landlock restricts path lookup, not access through a descriptor opened
    before the ruleset is installed.  Treating stdin/stdout/stderr as an
    implicit exception would therefore allow an inherited private file or
    socket to bypass the filesystem policy.
    """

    null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    try:
        for descriptor in sorted(_STANDARD_FDS):
            if null_fd == descriptor:
                os.set_inheritable(descriptor, True)
            else:
                os.dup2(null_fd, descriptor, inheritable=True)
    finally:
        if null_fd not in _STANDARD_FDS:
            os.close(null_fd)


def _close_unneeded_fds(keep: frozenset[int]) -> None:
    if type(keep) is not frozenset or any(
        type(descriptor) is not int or descriptor < 3 for descriptor in keep
    ):
        raise ValueError("kept descriptors must be a frozenset of integers >= 3")
    _replace_standard_fds()
    permitted = set(keep) | set(_STANDARD_FDS)
    try:
        descriptors = [int(name) for name in os.listdir("/proc/self/fd")]
    except OSError:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        maximum = 1024 if soft == resource.RLIM_INFINITY else int(soft)
        descriptors = list(range(3, maximum))
    for descriptor in descriptors:
        if descriptor in permitted:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _standard_fds_are_null() -> bool:
    try:
        null_status = os.stat("/dev/null")
        statuses = tuple(os.fstat(descriptor) for descriptor in _STANDARD_FDS)
    except OSError:
        return False
    return stat.S_ISCHR(null_status.st_mode) and all(
        stat.S_ISCHR(status.st_mode)
        and status.st_rdev == null_status.st_rdev
        for status in statuses
    )


def _descriptor_allowlist_exact(expected: frozenset[int]) -> bool:
    """Check every live descriptor, including sanitized fd 0/1/2, exactly."""

    if type(expected) is not frozenset or any(
        type(descriptor) is not int or descriptor < 0 for descriptor in expected
    ):
        return False
    if not _standard_fds_are_null():
        return False

    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return False
    live: set[int] = set()
    for name in names:
        try:
            descriptor = int(name)
        except ValueError:
            return False
        try:
            os.fstat(descriptor)
        except OSError as exc:
            # os.listdir's transient directory descriptor may be present in
            # the returned names but is closed before this loop.
            if exc.errno == errno.EBADF:
                continue
            return False
        live.add(descriptor)
    return live == set(expected)


def _send_packet(channel: socket.socket, wire: Mapping[str, object]) -> None:
    if type(wire) is not dict:
        wire = dict(wire)
    try:
        encoded = json.dumps(
            wire,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise IPCSchemaError("control packet is not finite JSON") from exc
    if not encoded or len(encoded) > _CONTROL_MAX_BYTES:
        raise IPCSchemaError("control packet exceeds the bounded frame")
    written = channel.send(encoded)
    if written != len(encoded):
        raise IPCSchemaError("short AF_UNIX packet write")


def _recv_packet(channel: socket.socket) -> dict[str, Any]:
    encoded = channel.recv(_CONTROL_MAX_BYTES + 1)
    if not encoded:
        raise EOFError("private control channel closed")
    if len(encoded) > _CONTROL_MAX_BYTES:
        raise IPCSchemaError("control packet exceeds the bounded frame")
    try:
        wire = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCSchemaError("invalid control packet") from exc
    if type(wire) is not dict or any(type(key) is not str for key in wire):
        raise IPCSchemaError("control packet must be an object with string keys")
    return wire


def _send_envelope(channel: socket.socket, message: IPCEnvelope) -> None:
    if not isinstance(message, IPCEnvelope):
        raise TypeError("message must be IPCEnvelope")
    _send_packet(channel, message.to_wire())


def _recv_envelope(channel: socket.socket) -> IPCEnvelope:
    return IPCEnvelope.from_wire(_recv_packet(channel))


def _peer_credentials(channel: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise IsolationStartupError("unix_peer_credentials unavailable")
    raw = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _SO_PEERCRED_SIZE)
    if len(raw) != _SO_PEERCRED_SIZE:
        raise IsolationStartupError("unix_peer_credentials malformed")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise IsolationStartupError("unix_peer_credentials invalid")
    return pid, uid, gid


def _socketpair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)


def _listener(address: str) -> socket.socket:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.bind(address)
    channel.listen(1)
    return channel


def _connect(address: str) -> socket.socket:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.connect(address)
    return channel


def _read_canary(path: str) -> bool:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return bool(os.read(descriptor, 1))
    finally:
        os.close(descriptor)


def _load_bounded_canary(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        value = os.read(descriptor, 1025)
    finally:
        os.close(descriptor)
    if not value or len(value) > 1024:
        raise IsolationStartupError("tool credential canary must contain 1..1024 bytes")
    return value


def _read_denied(path: str) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        return exc.errno in (errno.EACCES, errno.EPERM)
    else:
        os.close(descriptor)
        return False


def _write_denied(path: str) -> bool:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    except OSError as exc:
        return exc.errno in (errno.EACCES, errno.EPERM)
    else:
        os.close(descriptor)
        return False


@dataclass(frozen=True)
class LinuxCapabilityReport:
    linux: bool
    user_namespace: bool
    network_namespace: bool
    landlock_abi: int
    no_new_privileges: bool
    unix_seqpacket: bool
    unix_peer_credentials: bool

    def __post_init__(self) -> None:
        for name in (
            "linux",
            "user_namespace",
            "network_namespace",
            "no_new_privileges",
            "unix_seqpacket",
            "unix_peer_credentials",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be Boolean")
        if type(self.landlock_abi) is not int or self.landlock_abi < 0:
            raise TypeError("landlock_abi must be a nonnegative integer")

    @property
    def supports_strict(self) -> bool:
        return (
            self.linux
            and self.user_namespace
            and self.network_namespace
            and self.landlock_abi >= LANDLOCK_REQUIRED_ABI
            and self.no_new_privileges
            and self.unix_seqpacket
            and self.unix_peer_credentials
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "linux": self.linux,
            "user_namespace": self.user_namespace,
            "network_namespace": self.network_namespace,
            "landlock_abi": self.landlock_abi,
            "no_new_privileges": self.no_new_privileges,
            "unix_seqpacket": self.unix_seqpacket,
            "unix_peer_credentials": self.unix_peer_credentials,
        }


def probe_linux_capabilities() -> LinuxCapabilityReport:
    """Exercise all strict controls in a disposable child process."""

    linux = sys.platform == "linux"
    unix_seqpacket = hasattr(socket, "SOCK_SEQPACKET")
    unix_peer_credentials = hasattr(socket, "SO_PEERCRED")
    if not (linux and unix_seqpacket and unix_peer_credentials):
        return LinuxCapabilityReport(
            linux=linux,
            user_namespace=False,
            network_namespace=False,
            landlock_abi=0,
            no_new_privileges=False,
            unix_seqpacket=unix_seqpacket,
            unix_peer_credentials=unix_peer_credentials,
        )

    parent, child = _socketpair()
    expected_parent_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        report: dict[str, object] = {
            "user_namespace": False,
            "network_namespace": False,
            "landlock_abi": 0,
            "no_new_privileges": False,
        }
        try:
            _harden_process(expected_parent_pid)
            parent.close()
            _close_unneeded_fds(frozenset({child.fileno()}))
            before_user = os.readlink("/proc/self/ns/user")
            before_net = os.readlink("/proc/self/ns/net")
            after_user, after_net = _enter_user_and_network_namespace()
            report["user_namespace"] = after_user != before_user
            report["network_namespace"] = after_net != before_net
            report["landlock_abi"] = _apply_landlock_readonly(())
            report["no_new_privileges"] = _no_new_privileges()
            _send_packet(child, report)
            os._exit(0)
        except BaseException:
            try:
                _send_packet(child, report)
            except BaseException:
                pass
            os._exit(111)
    child.close()
    received = False
    try:
        parent.settimeout(5.0)
        try:
            wire = _recv_packet(parent)
            received = True
        except (OSError, EOFError, IPCSchemaError):
            wire = {}
        if not received:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _, status = os.waitpid(pid, 0)
    finally:
        parent.close()
    clean_exit = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    return LinuxCapabilityReport(
        linux=True,
        user_namespace=clean_exit and wire.get("user_namespace") is True,
        network_namespace=clean_exit and wire.get("network_namespace") is True,
        landlock_abi=(
            wire.get("landlock_abi")
            if clean_exit and type(wire.get("landlock_abi")) is int
            else 0
        ),
        no_new_privileges=clean_exit and wire.get("no_new_privileges") is True,
        unix_seqpacket=True,
        unix_peer_credentials=True,
    )


def validate_linux_capabilities(report: LinuxCapabilityReport) -> None:
    if not isinstance(report, LinuxCapabilityReport):
        raise TypeError("report must be LinuxCapabilityReport")
    missing: list[str] = []
    for name in (
        "linux",
        "user_namespace",
        "network_namespace",
        "no_new_privileges",
        "unix_seqpacket",
        "unix_peer_credentials",
    ):
        if not getattr(report, name):
            missing.append(name)
    if report.landlock_abi < LANDLOCK_REQUIRED_ABI:
        missing.append("landlock_abi")
    if missing:
        raise IsolationStartupError(
            "strict Linux isolation requirements unavailable: " + ", ".join(missing)
        )


def _canonical_regular_file(path: Path, name: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"{name} must not be a symbolic link")
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{name} must exist") from exc
    if not canonical.is_file():
        raise ValueError(f"{name} must be a regular file")
    return canonical


def _canonical_existing_path(path: Path, name: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"{name} must not be a symbolic link")
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{name} must exist") from exc


@dataclass(frozen=True)
class ProtectedCanaries:
    ledger: Path
    signing_key: Path
    tool_credential: Path
    raw_audit: Path

    def __post_init__(self) -> None:
        for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
            object.__setattr__(
                self,
                name,
                _canonical_regular_file(getattr(self, name), name),
            )
        if len(set(self.as_mapping().values())) != 4:
            raise ValueError("protected canaries must be four distinct files")

    def as_mapping(self) -> dict[str, Path]:
        return {
            "ledger": self.ledger,
            "raw_audit": self.raw_audit,
            "signing_key": self.signing_key,
            "tool_credential": self.tool_credential,
        }


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


@dataclass(frozen=True)
class LinuxIsolationConfig:
    manifest: IsolationManifest
    model_readonly_paths: tuple[Path, ...]
    model_allowed_read_probe: Path
    protected_canaries: ProtectedCanaries
    model_environment_allowlist: frozenset[str]
    startup_timeout_seconds: float = 10.0
    broker_tool_code: int = 7
    broker_argument_codes: tuple[int, ...] = (10, 20)
    broker_public_value_code: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, IsolationManifest):
            raise TypeError("manifest must be IsolationManifest")
        if self.manifest != IsolationManifest.strict(
            ipc_max_frame_bytes=IPC_MAX_FRAME_BYTES
        ):
            raise ValueError("live launcher requires the canonical strict manifest")
        if type(self.model_readonly_paths) is not tuple or not self.model_readonly_paths:
            raise TypeError("model_readonly_paths must be a nonempty tuple")
        canonical_roots = tuple(
            _canonical_existing_path(path, "model_readonly_path")
            for path in self.model_readonly_paths
        )
        if len(set(canonical_roots)) != len(canonical_roots):
            raise ValueError("model_readonly_paths must be unique")
        object.__setattr__(self, "model_readonly_paths", canonical_roots)
        probe = _canonical_regular_file(
            self.model_allowed_read_probe, "model_allowed_read_probe"
        )
        object.__setattr__(self, "model_allowed_read_probe", probe)
        if not any(_under(probe, root) for root in canonical_roots):
            raise ValueError("allowed read probe must be inside a read-only root")
        if not isinstance(self.protected_canaries, ProtectedCanaries):
            raise TypeError("protected_canaries must be ProtectedCanaries")
        for protected in self.protected_canaries.as_mapping().values():
            if any(_under(protected, root) for root in canonical_roots):
                raise ValueError("protected canaries cannot be under an allowed root")
        if type(self.model_environment_allowlist) is not frozenset:
            raise TypeError("model_environment_allowlist must be a frozenset")
        for name in self.model_environment_allowlist:
            if type(name) is not str or _ENVIRONMENT_NAME.fullmatch(name) is None:
                raise ValueError("model environment allowlist has an invalid name")
            if name in _DYNAMIC_LOADER_ENVIRONMENT_NAMES or name.startswith(
                _DYNAMIC_LOADER_ENVIRONMENT_PREFIXES
            ):
                raise ValueError(
                    f"model environment allowlist permits dynamic-loader variable {name}"
                )
        if (
            type(self.startup_timeout_seconds) not in (int, float)
            or isinstance(self.startup_timeout_seconds, bool)
            or not 0 < float(self.startup_timeout_seconds) <= 60
        ):
            raise ValueError("startup timeout must be in (0, 60] seconds")
        for name in ("broker_tool_code", "broker_public_value_code"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise TypeError(f"{name} must be a nonnegative integer")
        if type(self.broker_argument_codes) is not tuple or any(
            type(value) is not int or value < 0
            for value in self.broker_argument_codes
        ):
            raise TypeError("broker_argument_codes must be a finite integer tuple")

    @classmethod
    def strict(
        cls,
        *,
        model_readonly_paths: tuple[Path, ...],
        model_allowed_read_probe: Path,
        protected_canaries: ProtectedCanaries,
        model_environment_allowlist: frozenset[str],
    ) -> "LinuxIsolationConfig":
        return cls(
            manifest=IsolationManifest.strict(
                ipc_max_frame_bytes=IPC_MAX_FRAME_BYTES
            ),
            model_readonly_paths=model_readonly_paths,
            model_allowed_read_probe=model_allowed_read_probe,
            protected_canaries=protected_canaries,
            model_environment_allowlist=model_environment_allowlist,
        )


@dataclass(frozen=True)
class LinuxIsolationAttestation:
    capabilities: LinuxCapabilityReport
    enforcement_report: EnforcementReport
    topology: ProcessTopology
    parent_user_namespace: str
    parent_net_namespace: str
    model_user_namespace: str
    model_net_namespace: str
    broker_user_namespace: str
    broker_net_namespace: str
    model_landlock_abi: int
    broker_landlock_abi: int
    model_no_new_privileges: bool
    broker_no_new_privileges: bool
    model_environment_names: tuple[str, ...]
    environment_exact: bool
    model_allowed_read_succeeded: bool
    model_allowed_write_denied: bool
    model_network_probe_denied: bool
    model_direct_broker_probe_denied: bool
    protected_canary_denials: Mapping[str, bool]
    model_ipc_schema_verified: bool
    broker_ipc_schema_verified: bool
    broker_allowlist_denial_observed: bool
    broker_allowed_command_observed: bool
    broker_replay_denial_observed: bool
    model_descriptor_allowlist_exact: bool
    broker_descriptor_allowlist_exact: bool
    peer_pid_checks: Mapping[str, int]
    peer_uid_gid_checks: Mapping[str, tuple[int, int]]

    def to_wire(self) -> dict[str, object]:
        return {
            "capabilities": self.capabilities.to_wire(),
            "enforcement_report": {
                name: getattr(self.enforcement_report, name)
                for name in (
                    "kernel_enforced",
                    "distinct_processes",
                    "private_ipc",
                    "model_network_denied",
                    "model_ledger_denied",
                    "model_signing_keys_denied",
                    "model_tool_credentials_denied",
                    "model_raw_audit_denied",
                    "broker_allowlist_enforced",
                    "tool_sandbox_enforced",
                    "unshare_available",
                )
            },
            "pids": {
                role.value: pid for role, pid in self.topology.pids.items()
            },
            "namespaces": {
                "parent_user": self.parent_user_namespace,
                "parent_net": self.parent_net_namespace,
                "model_user": self.model_user_namespace,
                "model_net": self.model_net_namespace,
                "broker_user": self.broker_user_namespace,
                "broker_net": self.broker_net_namespace,
            },
            "landlock_abi": {
                "model": self.model_landlock_abi,
                "broker": self.broker_landlock_abi,
            },
            "no_new_privileges": {
                "model": self.model_no_new_privileges,
                "broker": self.broker_no_new_privileges,
            },
            "model_environment_names": list(self.model_environment_names),
            "environment_exact": self.environment_exact,
            "model_allowed_read_succeeded": self.model_allowed_read_succeeded,
            "model_allowed_write_denied": self.model_allowed_write_denied,
            "model_network_probe_denied": self.model_network_probe_denied,
            "model_direct_broker_probe_denied": self.model_direct_broker_probe_denied,
            "protected_canary_denials": dict(self.protected_canary_denials),
            "model_ipc_schema_verified": self.model_ipc_schema_verified,
            "broker_ipc_schema_verified": self.broker_ipc_schema_verified,
            "broker_allowlist_denial_observed": self.broker_allowlist_denial_observed,
            "broker_allowed_command_observed": self.broker_allowed_command_observed,
            "broker_replay_denial_observed": self.broker_replay_denial_observed,
            "model_descriptor_allowlist_exact": self.model_descriptor_allowlist_exact,
            "broker_descriptor_allowlist_exact": self.broker_descriptor_allowlist_exact,
            "peer_pid_checks": dict(self.peer_pid_checks),
            "peer_uid_gid_checks": {
                name: list(value) for name, value in self.peer_uid_gid_checks.items()
            },
        }


def _child_error(control: socket.socket, role: ProcessRole, phase: str, exc: BaseException) -> None:
    error_number = exc.errno if isinstance(exc, OSError) and exc.errno else 0
    try:
        _send_packet(
            control,
            {
                "type": "error",
                "role": role.value,
                "phase": phase,
                "errno": int(error_number),
            },
        )
    except BaseException:
        pass


def _wait_for_stop(control: socket.socket) -> None:
    try:
        wire = _recv_packet(control)
    except EOFError:
        return
    if wire != {"type": "stop"}:
        raise IPCSchemaError("child control channel accepts only stop")


def _broker_child(
    control: socket.socket,
    expected_parent_pid: int,
    address: str,
    credential_path: str,
    capability_token: str,
    tool_code: int,
    argument_codes: tuple[int, ...],
    public_value_code: int,
) -> None:
    phase = "bootstrap"
    try:
        _harden_process(expected_parent_pid)
        listener = _listener(address)
        credential = _load_bounded_canary(credential_path)
        _send_packet(
            control,
            {"type": "stage", "role": ProcessRole.EFFECT_BROKER.value, "stage": "listening"},
        )
        phase = "peer_configuration"
        expected = _recv_packet(control)
        if set(expected) != {"type", "peer_pid", "peer_uid", "peer_gid"} or expected.get("type") != "expect_peer":
            raise IPCSchemaError("invalid broker peer configuration")
        expected_monitor_pid = expected["peer_pid"]
        expected_monitor_uid = expected["peer_uid"]
        expected_monitor_gid = expected["peer_gid"]
        if (
            type(expected_monitor_pid) is not int
            or expected_monitor_pid <= 0
            or type(expected_monitor_uid) is not int
            or expected_monitor_uid < 0
            or type(expected_monitor_gid) is not int
            or expected_monitor_gid < 0
        ):
            raise IPCSchemaError("invalid monitor peer identity")
        phase = "accept_monitor"
        monitor, _ = listener.accept()
        listener.close()
        peer_pid, peer_uid, peer_gid = _peer_credentials(monitor)
        if (peer_pid, peer_uid, peer_gid) != (
            expected_monitor_pid,
            expected_monitor_uid,
            expected_monitor_gid,
        ):
            raise IsolationStartupError("broker peer credential mismatch")
        descriptors_exact = _descriptor_allowlist_exact(
            _STANDARD_FDS | frozenset({control.fileno(), monitor.fileno()})
        )
        phase = "sandbox"
        user_namespace, net_namespace = _enter_user_and_network_namespace()
        _seal_process_visibility()
        landlock_abi = _apply_landlock_readonly(())
        nnp = _no_new_privileges()
        phase = "effect_schema"
        broker = EffectBroker(
            allowed_arguments={tool_code: frozenset({argument_codes})},
            public_values={tool_code: frozenset({public_value_code})},
            tool_credentials={tool_code: credential},
            handlers={tool_code: lambda _credential, _arguments: public_value_code},
            capability_validator=lambda token, candidate_tool, candidate_arguments: (
                secrets.compare_digest(token, capability_token)
                and candidate_tool == tool_code
                and candidate_arguments == argument_codes
            ),
        )
        first = _recv_envelope(monitor)
        if first.kind is not IPCMessageKind.EFFECT_COMMAND:
            raise IPCSchemaError("broker expected effect command")
        first_reply = broker.execute(first)
        _send_envelope(monitor, first_reply)
        second = _recv_envelope(monitor)
        if second.kind is not IPCMessageKind.EFFECT_COMMAND:
            raise IPCSchemaError("broker expected effect command")
        second_reply = broker.execute(second)
        _send_envelope(monitor, second_reply)
        third = _recv_envelope(monitor)
        if third.kind is not IPCMessageKind.EFFECT_COMMAND:
            raise IPCSchemaError("broker expected replay effect command")
        third_reply = broker.execute(third)
        _send_envelope(monitor, third_reply)
        first_denied = first_reply.outcome is BrokerOutcome.DENIED
        second_allowed = (
            second_reply.outcome is BrokerOutcome.EXECUTED
            and second_reply.value_code == public_value_code
        )
        replay_denied = third_reply.outcome is BrokerOutcome.DENIED
        _send_packet(
            control,
            {
                "type": "report",
                "role": ProcessRole.EFFECT_BROKER.value,
                "peer_pid": peer_pid,
                "peer_uid": peer_uid,
                "peer_gid": peer_gid,
                "user_namespace": user_namespace,
                "net_namespace": net_namespace,
                "landlock_abi": landlock_abi,
                "no_new_privileges": nnp,
                "schema_verified": True,
                "allowlist_denial": first_denied,
                "allowed_command": second_allowed,
                "replay_denial": replay_denied,
                "descriptors_exact": descriptors_exact,
            },
        )
        phase = "wait_stop"
        _wait_for_stop(control)
        os._exit(0)
    except BaseException as exc:
        _child_error(control, ProcessRole.EFFECT_BROKER, phase, exc)
        os._exit(111)


def _monitor_child(
    control: socket.socket,
    expected_parent_pid: int,
    address: str,
    broker_address: str,
    expected_broker_pid: int,
    expected_peer_uid: int,
    expected_peer_gid: int,
    canary_paths: Mapping[str, str],
    capability_token: str,
    tool_code: int,
    argument_codes: tuple[int, ...],
    public_value_code: int,
) -> None:
    phase = "bootstrap"
    try:
        _harden_process(expected_parent_pid)
        _seal_process_visibility()
        trusted_reads = all(
            _read_canary(canary_paths[name])
            for name in ("ledger", "signing_key", "raw_audit")
        )
        listener = _listener(address)
        phase = "connect_broker"
        broker = _connect(broker_address)
        broker_peer_pid, broker_peer_uid, broker_peer_gid = _peer_credentials(broker)
        if (broker_peer_pid, broker_peer_uid, broker_peer_gid) != (
            expected_broker_pid,
            expected_peer_uid,
            expected_peer_gid,
        ):
            raise IsolationStartupError("monitor observed wrong broker credentials")
        bad = IPCEnvelope.effect_command(
            sequence=1,
            capability_token="invalid-launch-probe",
            tool_code=tool_code,
            argument_codes=argument_codes,
        )
        _send_envelope(broker, bad)
        bad_reply = _recv_envelope(broker)
        bad_denied = bad_reply.outcome is BrokerOutcome.DENIED
        good = IPCEnvelope.effect_command(
            sequence=2,
            capability_token=capability_token,
            tool_code=tool_code,
            argument_codes=argument_codes,
        )
        _send_envelope(broker, good)
        good_reply = _recv_envelope(broker)
        good_executed = (
            good_reply.outcome is BrokerOutcome.EXECUTED
            and good_reply.value_code == public_value_code
        )
        replay = IPCEnvelope.effect_command(
            sequence=3,
            capability_token=capability_token,
            tool_code=tool_code,
            argument_codes=argument_codes,
        )
        _send_envelope(broker, replay)
        replay_reply = _recv_envelope(broker)
        replay_denied = replay_reply.outcome is BrokerOutcome.DENIED
        _send_packet(
            control,
            {"type": "stage", "role": ProcessRole.MONITOR.value, "stage": "listening"},
        )
        phase = "peer_configuration"
        expected = _recv_packet(control)
        if set(expected) != {"type", "peer_pid", "peer_uid", "peer_gid"} or expected.get("type") != "expect_peer":
            raise IPCSchemaError("invalid monitor peer configuration")
        expected_model_pid = expected["peer_pid"]
        expected_model_uid = expected["peer_uid"]
        expected_model_gid = expected["peer_gid"]
        if (
            type(expected_model_pid) is not int
            or expected_model_pid <= 0
            or type(expected_model_uid) is not int
            or expected_model_uid < 0
            or type(expected_model_gid) is not int
            or expected_model_gid < 0
        ):
            raise IPCSchemaError("invalid model peer identity")
        phase = "accept_model"
        model, _ = listener.accept()
        listener.close()
        model_peer_pid, model_peer_uid, model_peer_gid = _peer_credentials(model)
        if (model_peer_pid, model_peer_uid, model_peer_gid) != (
            expected_model_pid,
            expected_model_uid,
            expected_model_gid,
        ):
            raise IsolationStartupError("monitor observed wrong model credentials")
        phase = "model_schema"
        request = _recv_envelope(model)
        if request.kind is not IPCMessageKind.MODEL_REQUEST:
            raise IPCSchemaError("monitor expected model request")
        public = IPCEnvelope.public_event(
            sequence=request.sequence,
            event={
                "schema_version": 1,
                "sequence": 1,
                "attempt": 1,
                "kind": "attempt",
                "outcome": "released",
                "value_code": public_value_code,
                "charge_units": 4,
                "terminal": False,
            },
        )
        _send_envelope(model, public)
        _send_packet(
            control,
            {
                "type": "report",
                "role": ProcessRole.MONITOR.value,
                "broker_peer_pid": broker_peer_pid,
                "broker_peer_uid": broker_peer_uid,
                "broker_peer_gid": broker_peer_gid,
                "model_peer_pid": model_peer_pid,
                "model_peer_uid": model_peer_uid,
                "model_peer_gid": model_peer_gid,
                "trusted_reads": trusted_reads,
                "schema_verified": bad_denied and good_executed and replay_denied,
                "allowlist_denial": bad_denied,
                "allowed_command": good_executed,
                "replay_denial": replay_denied,
            },
        )
        phase = "wait_stop"
        _wait_for_stop(control)
        os._exit(0)
    except BaseException as exc:
        _child_error(control, ProcessRole.MONITOR, phase, exc)
        os._exit(111)


def _model_network_denied(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.25)
        try:
            probe.connect(("127.0.0.1", port))
        except OSError:
            return True
        return False
    finally:
        probe.close()


def _broker_connection_denied(address: str) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        try:
            probe.connect(address)
        except OSError:
            return True
        return False
    finally:
        probe.close()


def _model_bootstrap(control: socket.socket) -> None:
    phase = "bootstrap_configuration"
    try:
        config = _recv_packet(control)
        required = {
            "type",
            "monitor_address",
            "broker_address",
            "monitor_pid",
            "monitor_uid",
            "monitor_gid",
            "parent_user_namespace",
            "parent_net_namespace",
            "network_probe_port",
            "readonly_paths",
            "allowed_read_probe",
            "protected_canaries",
            "environment_names",
        }
        if set(config) != required or config.get("type") != "model_bootstrap":
            raise IPCSchemaError("invalid model bootstrap configuration")
        environment_names = tuple(sorted(os.environ))
        expected_environment = config["environment_names"]
        if type(expected_environment) is not list or any(
            type(name) is not str for name in expected_environment
        ):
            raise IPCSchemaError("invalid expected environment")
        environment_exact = environment_names == tuple(expected_environment)
        monitor_pid = config["monitor_pid"]
        monitor_uid = config["monitor_uid"]
        monitor_gid = config["monitor_gid"]
        if (
            type(monitor_pid) is not int
            or monitor_pid <= 0
            or type(monitor_uid) is not int
            or monitor_uid < 0
            or type(monitor_gid) is not int
            or monitor_gid < 0
        ):
            raise IPCSchemaError("invalid monitor peer identity")
        phase = "connect_monitor"
        monitor = _connect(config["monitor_address"])
        monitor_peer_pid, monitor_peer_uid, monitor_peer_gid = _peer_credentials(monitor)
        if (monitor_peer_pid, monitor_peer_uid, monitor_peer_gid) != (
            monitor_pid,
            monitor_uid,
            monitor_gid,
        ):
            raise IsolationStartupError("model observed wrong monitor credentials")
        descriptors_exact = _descriptor_allowlist_exact(
            _STANDARD_FDS | frozenset({control.fileno(), monitor.fileno()})
        )
        phase = "sandbox"
        user_namespace, net_namespace = _enter_user_and_network_namespace()
        _seal_process_visibility()
        readonly = config["readonly_paths"]
        if type(readonly) is not list or any(type(path) is not str for path in readonly):
            raise IPCSchemaError("invalid read-only roots")
        landlock_abi = _apply_landlock_readonly(tuple(Path(path) for path in readonly))
        nnp = _no_new_privileges()
        phase = "denial_probes"
        allowed_probe = config["allowed_read_probe"]
        if type(allowed_probe) is not str:
            raise IPCSchemaError("invalid allowed probe")
        allowed_read = _read_canary(allowed_probe)
        allowed_write_denied = _write_denied(allowed_probe)
        protected = config["protected_canaries"]
        if type(protected) is not dict or set(protected) != {
            "ledger",
            "raw_audit",
            "signing_key",
            "tool_credential",
        } or any(type(path) is not str for path in protected.values()):
            raise IPCSchemaError("invalid protected canary mapping")
        protected_denials = {
            name: _read_denied(protected[name]) for name in sorted(protected)
        }
        network_port = config["network_probe_port"]
        if type(network_port) is not int or not 0 < network_port <= 65535:
            raise IPCSchemaError("invalid network probe port")
        network_denied = _model_network_denied(network_port)
        broker_denied = _broker_connection_denied(config["broker_address"])
        phase = "model_schema"
        request = IPCEnvelope.model_request(
            sequence=1,
            route_token="launch-route-slot",
            payload_code=0,
            credential="launch-attempt-credential",
        )
        _send_envelope(monitor, request)
        response = _recv_envelope(monitor)
        response.for_model()
        _send_packet(
            control,
            {
                "type": "report",
                "role": ProcessRole.MODEL.value,
                "monitor_peer_pid": monitor_peer_pid,
                "monitor_peer_uid": monitor_peer_uid,
                "monitor_peer_gid": monitor_peer_gid,
                "user_namespace": user_namespace,
                "net_namespace": net_namespace,
                "landlock_abi": landlock_abi,
                "no_new_privileges": nnp,
                "environment_names": list(environment_names),
                "environment_exact": environment_exact,
                "allowed_read": allowed_read,
                "allowed_write_denied": allowed_write_denied,
                "network_denied": network_denied,
                "broker_denied": broker_denied,
                "protected_denials": protected_denials,
                "schema_verified": response.kind is IPCMessageKind.PUBLIC_EVENT,
                "descriptors_exact": descriptors_exact,
            },
        )
        phase = "wait_stop"
        _wait_for_stop(control)
    except BaseException as exc:
        _child_error(control, ProcessRole.MODEL, phase, exc)
        raise


def _model_exec_entry(descriptor: int, expected_parent_pid: int) -> int:
    control: socket.socket | None = None
    try:
        _harden_process(expected_parent_pid)
        control = socket.socket(fileno=descriptor)
        _model_bootstrap(control)
        return 0
    except BaseException:
        return 111
    finally:
        if control is not None:
            control.close()


def _expect_control(
    channel: socket.socket,
    *,
    expected_type: str,
    role: ProcessRole,
    timeout: float,
) -> dict[str, Any]:
    channel.settimeout(timeout)
    try:
        wire = _recv_packet(channel)
    except (OSError, EOFError, IPCSchemaError) as exc:
        raise IsolationStartupError(
            f"{role.value} failed before {expected_type}"
        ) from exc
    if wire.get("type") == "error":
        phase = wire.get("phase")
        if type(phase) is not str:
            phase = "unknown"
        error_number = wire.get("errno")
        if type(error_number) is not int or error_number < 0:
            error_number = 0
        raise IsolationStartupError(
            f"{role.value} isolation setup failed at finite phase {phase} "
            f"(errno={error_number})"
        )
    if wire.get("type") != expected_type or wire.get("role") != role.value:
        raise IsolationStartupError(f"unexpected {role.value} control packet")
    return wire


def _terminate_and_reap(pids: Mapping[ProcessRole, int]) -> None:
    for pid in pids.values():
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for pid in pids.values():
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


class LiveIsolationRun:
    """A live attested topology with fail-closed sibling cleanup."""

    def __init__(
        self,
        *,
        attestation: LinuxIsolationAttestation,
        controls: Mapping[ProcessRole, socket.socket],
    ) -> None:
        self.attestation = attestation
        self._controls = dict(controls)
        self._pids = dict(attestation.topology.pids)
        self._lock = threading.RLock()
        self._closing = False
        self._reaped: dict[ProcessRole, int] = {}
        self._unexpected: ProcessRole | None = None
        self._cleanup_complete = threading.Event()
        self._watchdog = threading.Thread(
            target=self._watch_children,
            name="sluice-isolation-watchdog",
            daemon=True,
        )
        self._watchdog.start()

    def __enter__(self) -> "LiveIsolationRun":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def _watch_children(self) -> None:
        termination_deadline: float | None = None
        while True:
            newly_dead: list[ProcessRole] = []
            with self._lock:
                outstanding = [
                    (role, pid)
                    for role, pid in self._pids.items()
                    if role not in self._reaped
                ]
            for role, pid in outstanding:
                try:
                    waited, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    waited, status = pid, 0
                if waited == pid:
                    with self._lock:
                        if role not in self._reaped:
                            self._reaped[role] = status
                            newly_dead.append(role)
            with self._lock:
                if newly_dead and not self._closing and self._unexpected is None:
                    self._unexpected = newly_dead[0]
                    termination_deadline = time.monotonic() + 0.5
                    for role, pid in self._pids.items():
                        if role not in self._reaped:
                            try:
                                os.kill(pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                if len(self._reaped) == len(self._pids):
                    self._cleanup_complete.set()
                    return
                should_kill = (
                    self._unexpected is not None
                    and termination_deadline is not None
                    and time.monotonic() >= termination_deadline
                )
                if should_kill:
                    for role, pid in self._pids.items():
                        if role not in self._reaped:
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    termination_deadline = None
            time.sleep(0.02)

    def live_pids(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(
                pid for role, pid in self._pids.items() if role not in self._reaped
            )

    def wait_for_crash_cleanup(self, *, timeout: float) -> ProcessRole:
        if type(timeout) not in (int, float) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be positive")
        if not self._cleanup_complete.wait(float(timeout)):
            raise TimeoutError("isolation watchdog did not finish cleanup")
        with self._lock:
            if self._unexpected is None:
                raise IsolationStartupError("topology stopped without an unexpected crash")
            return self._unexpected

    def close(self) -> None:
        with self._lock:
            if self._closing and self._cleanup_complete.is_set():
                return
            self._closing = True
            controls = list(self._controls.values())
        for control in controls:
            try:
                _send_packet(control, {"type": "stop"})
            except (OSError, EOFError, IPCSchemaError):
                pass
        if not self._cleanup_complete.wait(2.0):
            for pid in self.live_pids():
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        if not self._cleanup_complete.wait(1.0):
            for pid in self.live_pids():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self._cleanup_complete.wait(2.0)
        for control in controls:
            control.close()
        self._controls.clear()
        self._watchdog.join(timeout=1.0)


def launch_live_isolation(config: LinuxIsolationConfig) -> LiveIsolationRun:
    """Launch, probe, and return a live strict three-process topology."""

    if not isinstance(config, LinuxIsolationConfig):
        raise TypeError("config must be LinuxIsolationConfig")
    capabilities = probe_linux_capabilities()
    validate_linux_capabilities(capabilities)
    service_uid = os.getuid()
    service_gid = os.getgid()
    parent_user_namespace = os.readlink("/proc/self/ns/user")
    parent_net_namespace = os.readlink("/proc/self/ns/net")
    broker_address = "\0sluice-broker-" + secrets.token_hex(16)
    monitor_address = "\0sluice-monitor-" + secrets.token_hex(16)
    capability_token = "launch-cap-" + secrets.token_hex(16)
    canary_paths = {
        name: os.fspath(path)
        for name, path in config.protected_canaries.as_mapping().items()
    }
    controls: dict[ProcessRole, socket.socket] = {}
    pids: dict[ProcessRole, int] = {}
    network_listener: socket.socket | None = None
    timeout = float(config.startup_timeout_seconds)
    launcher_pid = os.getpid()
    try:
        broker_parent, broker_child = _socketpair()
        broker_pid = os.fork()
        if broker_pid == 0:
            broker_parent.close()
            _close_unneeded_fds(frozenset({broker_child.fileno()}))
            _broker_child(
                broker_child,
                launcher_pid,
                broker_address,
                canary_paths["tool_credential"],
                capability_token,
                config.broker_tool_code,
                config.broker_argument_codes,
                config.broker_public_value_code,
            )
            os._exit(111)
        broker_child.close()
        controls[ProcessRole.EFFECT_BROKER] = broker_parent
        pids[ProcessRole.EFFECT_BROKER] = broker_pid
        _expect_control(
            broker_parent,
            expected_type="stage",
            role=ProcessRole.EFFECT_BROKER,
            timeout=timeout,
        )

        monitor_parent, monitor_child = _socketpair()
        monitor_pid = os.fork()
        if monitor_pid == 0:
            monitor_parent.close()
            _close_unneeded_fds(frozenset({monitor_child.fileno()}))
            _monitor_child(
                monitor_child,
                launcher_pid,
                monitor_address,
                broker_address,
                broker_pid,
                service_uid,
                service_gid,
                canary_paths,
                capability_token,
                config.broker_tool_code,
                config.broker_argument_codes,
                config.broker_public_value_code,
            )
            os._exit(111)
        monitor_child.close()
        controls[ProcessRole.MONITOR] = monitor_parent
        pids[ProcessRole.MONITOR] = monitor_pid
        _send_packet(
            broker_parent,
            {
                "type": "expect_peer",
                "peer_pid": monitor_pid,
                "peer_uid": service_uid,
                "peer_gid": service_gid,
            },
        )
        # The broker completes its schema/allowlist probes before the monitor
        # announces that it is ready for the model.  Await it first so a
        # fail-closed startup error names the actual failing child and phase.
        broker_report = _expect_control(
            broker_parent,
            expected_type="report",
            role=ProcessRole.EFFECT_BROKER,
            timeout=timeout,
        )
        _expect_control(
            monitor_parent,
            expected_type="stage",
            role=ProcessRole.MONITOR,
            timeout=timeout,
        )

        network_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        network_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        network_listener.bind(("127.0.0.1", 0))
        network_listener.listen(1)
        network_listener.setblocking(False)
        network_probe_port = int(network_listener.getsockname()[1])

        model_parent, model_child = _socketpair()
        model_environment = sanitize_model_environment(
            os.environ,
            allowed_names=config.model_environment_allowlist,
        )
        model_pid = os.fork()
        if model_pid == 0:
            _harden_process(launcher_pid)
            model_parent.close()
            descriptor = model_child.fileno()
            _close_unneeded_fds(frozenset({descriptor}))
            os.set_inheritable(descriptor, True)
            package_root = os.fspath(Path(__file__).resolve().parents[1])
            os.chdir(package_root)
            os.execve(
                sys.executable,
                [
                    sys.executable,
                    "-S",
                    "-m",
                    "sluice_v2.linux_isolation",
                    "--model-bootstrap",
                    str(descriptor),
                    str(launcher_pid),
                ],
                model_environment,
            )
            os._exit(111)
        model_child.close()
        controls[ProcessRole.MODEL] = model_parent
        pids[ProcessRole.MODEL] = model_pid
        _send_packet(
            monitor_parent,
            {
                "type": "expect_peer",
                "peer_pid": model_pid,
                "peer_uid": service_uid,
                "peer_gid": service_gid,
            },
        )
        _send_packet(
            model_parent,
            {
                "type": "model_bootstrap",
                "monitor_address": monitor_address,
                "broker_address": broker_address,
                "monitor_pid": monitor_pid,
                "monitor_uid": service_uid,
                "monitor_gid": service_gid,
                "parent_user_namespace": parent_user_namespace,
                "parent_net_namespace": parent_net_namespace,
                "network_probe_port": network_probe_port,
                "readonly_paths": [os.fspath(path) for path in config.model_readonly_paths],
                "allowed_read_probe": os.fspath(config.model_allowed_read_probe),
                "protected_canaries": canary_paths,
                "environment_names": sorted(model_environment),
            },
        )

        monitor_report = _expect_control(
            monitor_parent,
            expected_type="report",
            role=ProcessRole.MONITOR,
            timeout=timeout,
        )
        model_report = _expect_control(
            model_parent,
            expected_type="report",
            role=ProcessRole.MODEL,
            timeout=timeout,
        )
        try:
            leaked_connection, _ = network_listener.accept()
        except BlockingIOError:
            parent_network_probe_clear = True
        else:
            parent_network_probe_clear = False
            leaked_connection.close()
        network_listener.close()
        network_listener = None

        topology = ProcessTopology(
            {
                ProcessRole.MODEL: model_pid,
                ProcessRole.MONITOR: monitor_pid,
                ProcessRole.EFFECT_BROKER: broker_pid,
            }
        )
        topology.validate_live_and_distinct()
        protected_denials = model_report.get("protected_denials")
        if type(protected_denials) is not dict:
            protected_denials = {}
        peer_pid_checks = {
            "broker_observed_monitor": broker_report.get("peer_pid"),
            "model_observed_monitor": model_report.get("monitor_peer_pid"),
            "monitor_observed_broker": monitor_report.get("broker_peer_pid"),
            "monitor_observed_model": monitor_report.get("model_peer_pid"),
        }
        expected_peer_pid_checks = {
            "broker_observed_monitor": monitor_pid,
            "model_observed_monitor": monitor_pid,
            "monitor_observed_broker": broker_pid,
            "monitor_observed_model": model_pid,
        }
        peer_uid_gid_checks = {
            "broker_observed_monitor": (
                broker_report.get("peer_uid"),
                broker_report.get("peer_gid"),
            ),
            "model_observed_monitor": (
                model_report.get("monitor_peer_uid"),
                model_report.get("monitor_peer_gid"),
            ),
            "monitor_observed_broker": (
                monitor_report.get("broker_peer_uid"),
                monitor_report.get("broker_peer_gid"),
            ),
            "monitor_observed_model": (
                monitor_report.get("model_peer_uid"),
                monitor_report.get("model_peer_gid"),
            ),
        }
        expected_peer_uid_gid_checks = {
            name: (service_uid, service_gid) for name in peer_uid_gid_checks
        }
        namespaces_enforced = (
            model_report.get("user_namespace") != parent_user_namespace
            and model_report.get("net_namespace") != parent_net_namespace
            and broker_report.get("user_namespace") != parent_user_namespace
            and broker_report.get("net_namespace") != parent_net_namespace
        )
        kernel_enforced = (
            namespaces_enforced
            and model_report.get("landlock_abi", 0) >= LANDLOCK_REQUIRED_ABI
            and broker_report.get("landlock_abi", 0) >= LANDLOCK_REQUIRED_ABI
            and model_report.get("no_new_privileges") is True
            and broker_report.get("no_new_privileges") is True
        )
        private_ipc = (
            peer_pid_checks == expected_peer_pid_checks
            and peer_uid_gid_checks == expected_peer_uid_gid_checks
            and model_report.get("schema_verified") is True
            and broker_report.get("schema_verified") is True
            and monitor_report.get("schema_verified") is True
            and model_report.get("broker_denied") is True
            and model_report.get("descriptors_exact") is True
            and broker_report.get("descriptors_exact") is True
        )
        broker_allowlist = (
            broker_report.get("allowlist_denial") is True
            and broker_report.get("allowed_command") is True
            and broker_report.get("replay_denial") is True
            and monitor_report.get("allowlist_denial") is True
            and monitor_report.get("allowed_command") is True
            and monitor_report.get("replay_denial") is True
        )
        enforcement = EnforcementReport(
            kernel_enforced=kernel_enforced,
            distinct_processes=True,
            private_ipc=private_ipc,
            model_network_denied=(
                model_report.get("network_denied") is True
                and parent_network_probe_clear
            ),
            model_ledger_denied=protected_denials.get("ledger") is True,
            model_signing_keys_denied=protected_denials.get("signing_key") is True,
            model_tool_credentials_denied=(
                protected_denials.get("tool_credential") is True
            ),
            model_raw_audit_denied=protected_denials.get("raw_audit") is True,
            broker_allowlist_enforced=broker_allowlist,
            tool_sandbox_enforced=(
                broker_report.get("user_namespace") != parent_user_namespace
                and broker_report.get("net_namespace") != parent_net_namespace
                and broker_report.get("landlock_abi", 0) >= LANDLOCK_REQUIRED_ABI
                and broker_report.get("no_new_privileges") is True
            ),
            unshare_available=True,
        )
        validate_startup(config.manifest, enforcement)
        environment_names = model_report.get("environment_names")
        if type(environment_names) is not list or any(
            type(name) is not str for name in environment_names
        ):
            raise IsolationStartupError("model returned invalid environment attestation")
        attestation = LinuxIsolationAttestation(
            capabilities=capabilities,
            enforcement_report=enforcement,
            topology=topology,
            parent_user_namespace=parent_user_namespace,
            parent_net_namespace=parent_net_namespace,
            model_user_namespace=model_report["user_namespace"],
            model_net_namespace=model_report["net_namespace"],
            broker_user_namespace=broker_report["user_namespace"],
            broker_net_namespace=broker_report["net_namespace"],
            model_landlock_abi=model_report["landlock_abi"],
            broker_landlock_abi=broker_report["landlock_abi"],
            model_no_new_privileges=model_report["no_new_privileges"],
            broker_no_new_privileges=broker_report["no_new_privileges"],
            model_environment_names=tuple(environment_names),
            environment_exact=model_report.get("environment_exact") is True,
            model_allowed_read_succeeded=model_report.get("allowed_read") is True,
            model_allowed_write_denied=(
                model_report.get("allowed_write_denied") is True
            ),
            model_network_probe_denied=(
                model_report.get("network_denied") is True
                and parent_network_probe_clear
            ),
            model_direct_broker_probe_denied=(
                model_report.get("broker_denied") is True
            ),
            protected_canary_denials=dict(protected_denials),
            model_ipc_schema_verified=(
                model_report.get("schema_verified") is True
                and monitor_report.get("schema_verified") is True
            ),
            broker_ipc_schema_verified=(
                broker_report.get("schema_verified") is True
                and monitor_report.get("schema_verified") is True
            ),
            broker_allowlist_denial_observed=broker_allowlist,
            broker_allowed_command_observed=broker_allowlist,
            broker_replay_denial_observed=broker_allowlist,
            model_descriptor_allowlist_exact=(
                model_report.get("descriptors_exact") is True
            ),
            broker_descriptor_allowlist_exact=(
                broker_report.get("descriptors_exact") is True
            ),
            peer_pid_checks=peer_pid_checks,
            peer_uid_gid_checks=peer_uid_gid_checks,
        )
        return LiveIsolationRun(attestation=attestation, controls=controls)
    except BaseException:
        if network_listener is not None:
            network_listener.close()
        for control in controls.values():
            control.close()
        _terminate_and_reap(pids)
        raise


def _main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "--model-bootstrap":
        try:
            descriptor = int(argv[1])
            expected_parent_pid = int(argv[2])
        except ValueError:
            return 112
        if descriptor < 3 or expected_parent_pid <= 1:
            return 112
        return _model_exec_entry(descriptor, expected_parent_pid)
    return 112


if __name__ == "__main__":  # pragma: no cover - exercised through execve
    raise SystemExit(_main(sys.argv[1:]))
