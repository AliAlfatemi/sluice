"""G8 CPU-only matched monitor/RPC performance benchmark foundation.

This driver is intentionally separate from the historical RQ4 SQLite sweep.
It compares one finite release handler through four matched paths:

* a direct pure handler call;
* :class:`sluice_v2.secure.SecureDomain`;
* :class:`sluice_v2.durable_secure.DurableSecureDomain`; and
* :class:`sluice_v2.durable_service.SingletonMonitorService` over AF_UNIX.

Each condition/repetition is executed in a fresh worker process.  Setup and a
separate warm-up domain/ledger precede the measured domain/ledger.  The parent
randomizes all four conditions inside every storage/concurrency/repetition
block and retains failures rather than silently dropping a condition.

``diagnostic`` is the default and is never claim eligible. ``final`` is
deliberately disabled until the repaired singleton integration, storage
attestation, and independent raw validator are jointly reviewed; its dormant gate also
requires native Git, a clean tree, ten repetitions, the complete 1--64 sweep,
10,000 samples, and attested local persistent storage. tmpfs is always diagnostic.
The singleton condition measures the current RPC service path; the model-side
worker is not Landlock-confined, so this is not an OS-isolation-overhead arm.
No model, GPU, tool, checkpoint, garbage-collection, or crash experiment is
performed by this driver.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import resource
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from typing import Any, Callable, Mapping, Sequence
import uuid


HERE = Path(__file__).resolve().parent
ARTIFACT_ROOT = HERE.parent
REPOSITORY_ROOT = HERE.parents[2]
sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2.durable_secure import (  # noqa: E402
    AttemptCredential as DurableAttemptCredential,
    DurableSecureDomain,
    ObserverSpec as DurableObserverSpec,
    RouteCodebook as DurableRouteCodebook,
)
from sluice_v2.durable_service import (  # noqa: E402
    MONITOR_PROTOCOL_VERSION,
    DurableDomainOpener,
    ModelOperationCode,
    ModelRequest,
    MonitorServiceConfig,
    PeerIdentity,
    PrivateTemplateBinding,
    SingletonMonitorService,
    connect_model,
)
from sluice_v2.observer import EventKind, OutcomeCode, TranscriptEvent  # noqa: E402
from sluice_v2.secure import (  # noqa: E402
    AttemptCredential as InMemoryAttemptCredential,
    DomainConfig,
    ObserverSpec as InMemoryObserverSpec,
    RouteCodebook as InMemoryRouteCodebook,
    SecureDomain,
)


MANIFEST_SCHEMA = "sluice.g8.performance.manifest.v1"
SUMMARY_SCHEMA = "sluice.g8.performance.summary.v1"
REPETITION_SCHEMA = "sluice.g8.performance.repetition.v1"
OPERATION_SCHEMA = "sluice.g8.performance.operation.v1"
WORKER_SPEC_SCHEMA = "sluice.g8.performance.worker-spec.v1"
WORKER_RESULT_SCHEMA = "sluice.g8.performance.worker-result.v1"
STORAGE_ATTESTATION_SCHEMA = "sluice.g8.storage-attestation.v1"
NATIVE_GIT_ATTESTATION_SCHEMA = "sluice-native-git-toolchain-v2"
EXPERIMENT_ID = "g8_matched_cpu_scalability_foundation"

CONDITIONS = (
    "unmediated_handler",
    "inmemory_secure_domain",
    "durable_direct",
    "singleton_ipc",
)
DEFAULT_CONCURRENCIES = (1, 2, 4, 8, 16, 32, 64)
STORAGE_CLASSES = frozenset({"local-persistent", "tmpfs-diagnostic"})
TMPFS_TYPES = frozenset({"tmpfs", "ramfs"})
LOCAL_PERSISTENT_TYPES = frozenset(
    {
        "btrfs",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "jfs",
        "nilfs2",
        "reiserfs",
        "xfs",
        "zfs",
    }
)
MIN_FINAL_REPETITIONS = 10
MIN_P999_OPERATIONS = 10_000
DEFAULT_BOOTSTRAP_REPLICATES = 10_000
FINAL_CLAIMS_ENABLED = False
PERCENTILE_METHOD = "nearest-rank (ceil(p*n)-1)"
MAX_AUDIT_INTEGER = (1 << 63) - 1
HANDLER_VALUE_CODE = 1
EVENT_CHARGE_UNITS = 4
CALLER_KEY = b"sluice-g8-caller-key-v1-32bytes!"
COMPONENT_PATHS = (
    "source/artifact/experiments/g8_matched_scalability.py",
    "source/artifact/pyproject.toml",
    "source/artifact/requirements-lock.txt",
    "source/artifact/sluice_v2/__init__.py",
    "source/artifact/sluice_v2/observer.py",
    "source/artifact/sluice_v2/secure.py",
    "source/artifact/sluice_v2/durable_secure.py",
    "source/artifact/sluice_v2/durable_service.py",
    "source/artifact/sluice_v2/isolation.py",
    "source/artifact/sluice_v2/linux_isolation.py",
)

# The child is launched with this source through ``python -I -B -c``.  It uses
# only the standard library until every project source byte has been read from
# a non-symlink regular-file descriptor and matched to the parent-pinned
# digest.  Project imports are then served from those captured bytes, so an
# import-time mutate/restore race cannot substitute code between a hash check
# and execution.  Keep the token replacement deliberately data-only.
_WORKER_BOOTSTRAP_TEMPLATE = r'''
import hashlib
import importlib.abc
import importlib.util
import json
import os
import stat
import sys

_COMPONENT_PATHS = __G8_COMPONENT_PATHS__
_DRIVER_RELATIVE = "source/artifact/experiments/g8_matched_scalability.py"


def _abort(message):
    raise SystemExit("G8 verified worker bootstrap: " + message)


def _read_regular(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _abort("pinned input is not a regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            _abort("pinned input changed while being captured")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


if not (
    sys.flags.isolated == 1
    and sys.flags.ignore_environment == 1
    and sys.flags.no_user_site == 1
    and sys.flags.dont_write_bytecode == 1
):
    _abort("Python runtime is not -I -B isolated")
if any(
    key.upper().startswith("PYTHON")
    or key.upper().startswith("LD_")
    or key.upper().startswith("DYLD_")
    for key in os.environ
):
    _abort("environment contains a Python or loader injection key")
if len(sys.argv) != 8 or sys.argv[0] != "-c" or sys.argv[1] != "_worker" or sys.argv[2] != "--spec" or sys.argv[4] != "--output" or sys.argv[6] != "--spec-sha256":
    _abort("launcher arguments are not exact")

spec_path = os.path.abspath(sys.argv[3])
output_path = os.path.abspath(sys.argv[5])
expected_spec_sha256 = sys.argv[7]
if len(expected_spec_sha256) != 64 or any(
    character not in "0123456789abcdef" for character in expected_spec_sha256
):
    _abort("spec digest is invalid")
spec_bytes = _read_regular(spec_path)
if hashlib.sha256(spec_bytes).hexdigest() != expected_spec_sha256:
    _abort("spec changed after the parent bound the command")
try:
    spec = json.loads(spec_bytes.decode("ascii"))
except (UnicodeError, json.JSONDecodeError):
    _abort("spec is not canonical ASCII JSON")
if type(spec) is not dict:
    _abort("spec is not an object")
expected_hashes = spec.get("expected_component_sha256")
worker_hashes = spec.get("expected_worker_source_sha256")
if (
    type(expected_hashes) is not dict
    or set(expected_hashes) != set(_COMPONENT_PATHS)
    or type(worker_hashes) is not dict
    or worker_hashes != expected_hashes
):
    _abort("component manifest is not exact")
snapshot_root = spec.get("worker_source_root")
if type(snapshot_root) is not str or not os.path.isabs(snapshot_root):
    _abort("snapshot root is not absolute")
snapshot_root = os.path.abspath(snapshot_root)
if os.path.realpath(snapshot_root) != snapshot_root or not os.path.isdir(snapshot_root):
    _abort("snapshot root is not a canonical directory")

captured = {}
for relative in _COMPONENT_PATHS:
    expected = expected_hashes.get(relative)
    if type(expected) is not str or len(expected) != 64 or any(
        character not in "0123456789abcdef" for character in expected
    ):
        _abort("component digest is invalid")
    candidate = os.path.abspath(os.path.join(snapshot_root, *relative.split("/")))
    if os.path.commonpath((candidate, snapshot_root)) != snapshot_root:
        _abort("component escapes the snapshot root")
    if os.path.realpath(candidate) != candidate:
        _abort("component path contains a symlink")
    content = _read_regular(candidate)
    if hashlib.sha256(content).hexdigest() != expected:
        _abort("component bytes disagree with the parent pin")
    captured[relative] = content

module_sources = {}
module_filenames = {}
package_prefix = "source/artifact/sluice_v2/"
for relative, content in captured.items():
    if not relative.startswith(package_prefix) or not relative.endswith(".py"):
        continue
    leaf = relative[len(package_prefix):]
    if "/" in leaf:
        _abort("unexpected nested project module")
    if leaf == "__init__.py":
        name = "sluice_v2"
        is_package = True
    else:
        name = "sluice_v2." + leaf[:-3]
        is_package = False
    module_sources[name] = (content, is_package)
    module_filenames[name] = os.path.join(snapshot_root, *relative.split("/"))


class _CapturedProjectFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in module_sources:
            return importlib.util.spec_from_loader(
                fullname, self, is_package=module_sources[fullname][1]
            )
        if fullname == "sluice_v2" or fullname.startswith("sluice_v2."):
            raise ImportError("unpinned Sluice module requested: " + fullname)
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        content, is_package = module_sources[module.__name__]
        filename = module_filenames[module.__name__]
        module.__file__ = filename
        module.__cached__ = None
        if is_package:
            module.__path__ = []
        exec(compile(content, filename, "exec"), module.__dict__, module.__dict__)


sys.meta_path.insert(0, _CapturedProjectFinder())
driver_path = os.path.join(snapshot_root, *_DRIVER_RELATIVE.split("/"))
sys.argv = [driver_path, "_worker", "--spec", spec_path, "--output", output_path]
driver_globals = {
    "__name__": "__main__",
    "__file__": driver_path,
    "__package__": None,
    "__cached__": None,
    "__builtins__": __builtins__,
}
exec(
    compile(captured[_DRIVER_RELATIVE], driver_path, "exec"),
    driver_globals,
    driver_globals,
)
'''


def _worker_bootstrap_source() -> str:
    return _WORKER_BOOTSTRAP_TEMPLATE.replace(
        "__G8_COMPONENT_PATHS__", repr(COMPONENT_PATHS)
    )

SAFE_ENVIRONMENT_KEYS = (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "PYTHONHASHSEED",
    "SLURM_JOB_ID",
    "SLURM_JOB_NODELIST",
    "PBS_JOBID",
)
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_OPENPGP_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
_WORKER_PHASES = frozenset({"worker", "warmup", "measured"})
_TIMING_SCOPE = (
    "per-operation monotonic envelope; setup, credential/template construction, "
    "warm-up, storage inspection, result validation, and cleanup excluded"
)
_MEMORY_SCOPE = (
    "worker process lifetime high-water mark includes setup/warm-up; monitor VmHWM "
    "is sampled before shutdown"
)


@dataclass(frozen=True)
class StorageProfile:
    """Resolved, classified benchmark storage with optional attestation."""

    label: str
    storage_class: str
    requested_path: str
    resolved_path: str
    device_id: int
    mountpoint: str
    filesystem_type: str
    mount_source: str
    mount_options: tuple[str, ...]
    attestation_path: str | None
    attestation_sha256: str | None
    attestation_canonical_json: str | None
    operator_attested_local_persistence: bool

    @property
    def claim_storage_eligible(self) -> bool:
        return (
            self.storage_class == "local-persistent"
            and self.filesystem_type in LOCAL_PERSISTENT_TYPES
            and self.operator_attested_local_persistence is True
            and _profile_attestation_material_is_exact(self)
        )


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _is_bounded_nonnegative_int(value: object) -> bool:
    return _is_exact_int(value) and 0 <= value <= MAX_AUDIT_INTEGER


def _is_finite_nonnegative_number(value: object) -> bool:
    if type(value) is int:
        return _is_bounded_nonnegative_int(value)
    return (
        type(value) is float
        and math.isfinite(value)
        and 0.0 <= value <= float(MAX_AUDIT_INTEGER)
    )


def _positive_int(name: str, value: object) -> int:
    if not _is_exact_int(value) or not 0 < value <= MAX_AUDIT_INTEGER:
        raise ValueError(
            f"{name} must be a positive exact integer no greater than "
            f"{MAX_AUDIT_INTEGER}"
        )
    return value


def _exact_json_equal(left: object, right: object) -> bool:
    """Compare decoded JSON values without Python's bool/int aliasing."""

    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if frozenset(left) != frozenset(right):
            return False
        return all(_exact_json_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(
            _exact_json_equal(a, b) for a, b in zip(left, right)
        )
    if type(left) is float and not (math.isfinite(left) and math.isfinite(right)):
        return False
    return left == right


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for candidate in sorted(item for item in path.rglob("*") if item.is_file()):
        relative = candidate.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        file_hash = _sha256_file(candidate).encode("ascii")
        digest.update(file_hash)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "label",
        "resolved_path",
        "filesystem_type",
        "hostname",
        "device_id",
        "mountpoint",
        "mount_source",
        "mount_options",
        "node_local_verified",
        "persistence_verified",
        "verification_method",
        "verified_at_utc",
        "verified_by",
    }
)


def _profile_attestation_material_is_exact(profile: StorageProfile) -> bool:
    """Pure check that claim eligibility is backed by retained canonical bytes."""

    if (
        type(profile.attestation_path) is not str
        or not profile.attestation_path
        or not Path(profile.attestation_path).is_absolute()
        or type(profile.attestation_sha256) is not str
        or _SHA256.fullmatch(profile.attestation_sha256) is None
        or type(profile.attestation_canonical_json) is not str
        or not profile.attestation_canonical_json.endswith("\n")
    ):
        return False
    attestation_path = Path(profile.attestation_path)
    if attestation_path.is_symlink() or not attestation_path.is_file():
        return False
    try:
        encoded = profile.attestation_canonical_json.encode("ascii")
        if attestation_path.read_bytes() != encoded:
            return False
        decoded = json.loads(profile.attestation_canonical_json)
        canonical = _canonical_json(decoded) + "\n"
    except (OSError, UnicodeEncodeError, ValueError, json.JSONDecodeError):
        return False
    if canonical != profile.attestation_canonical_json:
        return False
    if hashlib.sha256(encoded).hexdigest() != profile.attestation_sha256:
        return False
    if type(decoded) is not dict or frozenset(decoded) != _ATTESTATION_FIELDS:
        return False
    exact_profile_fields = {
        "schema_version": STORAGE_ATTESTATION_SCHEMA,
        "label": profile.label,
        "resolved_path": profile.resolved_path,
        "filesystem_type": profile.filesystem_type,
        "device_id": profile.device_id,
        "mountpoint": profile.mountpoint,
        "mount_source": profile.mount_source,
        "mount_options": list(profile.mount_options),
        "node_local_verified": True,
        "persistence_verified": True,
    }
    return all(
        _exact_json_equal(decoded.get(field), expected)
        for field, expected in exact_profile_fields.items()
    )


def _atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    temporary.write_text(_canonical_json(value) + "\n", encoding="ascii")
    os.replace(temporary, path)


def _atomic_text(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    temporary.write_text(value, encoding="utf-8")
    os.replace(temporary, path)


def nearest_rank(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("cannot compute a percentile of an empty sample")
    if any(not _is_finite_nonnegative_number(value) for value in sorted_values):
        raise ValueError("percentile inputs must be finite nonnegative numbers")
    if type(probability) is not float or not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0,1]")
    index = max(
        0,
        min(
            len(sorted_values) - 1,
            math.ceil(probability * len(sorted_values)) - 1,
        ),
    )
    return float(sorted_values[index])


def summarize_latencies(latency_ns: Sequence[int]) -> dict[str, Any]:
    if not latency_ns:
        raise ValueError("at least one latency is required")
    if any(not _is_bounded_nonnegative_int(value) for value in latency_ns):
        raise ValueError("latencies must be bounded nonnegative exact integers")
    values_ms = sorted(value / 1_000_000.0 for value in latency_ns)
    p999_supported = len(values_ms) >= MIN_P999_OPERATIONS
    return {
        "n_operations": len(values_ms),
        "median_ms": statistics.median(values_ms),
        "p50_ms": nearest_rank(values_ms, 0.50),
        "p95_ms": nearest_rank(values_ms, 0.95),
        "p99_ms": nearest_rank(values_ms, 0.99),
        "p99_9_ms": nearest_rank(values_ms, 0.999) if p999_supported else None,
        "p99_9_support": {
            "supported": p999_supported,
            "minimum_operations": MIN_P999_OPERATIONS,
            "observed_operations": len(values_ms),
        },
        "minimum_ms": values_ms[0],
        "maximum_ms": values_ms[-1],
        "percentile_method": PERCENTILE_METHOD,
    }


def bootstrap_median_interval(
    values: Sequence[float],
    *,
    seed: int,
    replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
) -> dict[str, Any]:
    """Fresh-process block bootstrap for one already-stratified cell."""

    _positive_int("replicates", replicates)
    if not _is_exact_int(seed) or abs(seed) > MAX_AUDIT_INTEGER:
        raise ValueError("seed must be a bounded exact integer")
    if any(not _is_finite_nonnegative_number(value) for value in values):
        raise ValueError("bootstrap inputs must be finite nonnegative numbers")
    if not values:
        return {
            "status": "unsupported_no_successful_repetitions",
            "n_repetitions": 0,
        }
    if len(values) < 2:
        return {
            "status": "unsupported_fewer_than_two_repetitions",
            "estimate": float(values[0]),
            "n_repetitions": 1,
        }
    rng = random.Random(seed)
    sample_size = len(values)
    estimates = sorted(
        statistics.median(values[rng.randrange(sample_size)] for _ in range(sample_size))
        for _ in range(replicates)
    )
    return {
        "status": "supported",
        "estimate": statistics.median(values),
        "lower_95": nearest_rank(estimates, 0.025),
        "upper_95": nearest_rank(estimates, 0.975),
        "method": "percentile bootstrap over fresh-process repetitions",
        "replicates": replicates,
        "seed": seed,
        "n_repetitions": len(values),
    }


def finite_handler(payload: Any) -> int:
    """The exact finite operation shared by all four benchmark paths."""

    if type(payload) is not dict or frozenset(payload) != frozenset({"value_code"}):
        raise TypeError("matched payload must contain only value_code")
    value = payload["value_code"]
    if type(value) is not int or value != HANDLER_VALUE_CODE:
        raise ValueError("matched payload value is outside the one-code alphabet")
    return value


def _decode_mount_path(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def detect_mount(path: Path) -> dict[str, Any]:
    """Resolve the longest-prefix Linux mount without guessing persistence."""

    resolved = path.resolve(strict=True)
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("cannot inspect Linux mount provenance") from exc
    best: tuple[int, dict[str, Any]] | None = None
    for line in lines:
        try:
            left, right = line.split(" - ", 1)
            left_fields = left.split()
            right_fields = right.split()
            mountpoint = _decode_mount_path(left_fields[4])
            if os.path.commonpath((str(resolved), mountpoint)) != mountpoint:
                continue
            metadata = {
                "mountpoint": mountpoint,
                "filesystem_type": right_fields[0].lower(),
                "mount_source": _decode_mount_path(right_fields[1]),
                "mount_options": tuple(
                    sorted(set(left_fields[5].split(",") + right_fields[2].split(",")))
                ),
            }
        except (IndexError, ValueError):
            continue
        if best is None or len(mountpoint) > best[0]:
            best = (len(mountpoint), metadata)
    if best is None:
        raise RuntimeError(f"cannot resolve a mount for {resolved}")
    return best[1]


def parse_storage_argument(value: str) -> tuple[str, str, Path]:
    fields = value.split(":", 2)
    if len(fields) != 3:
        raise ValueError("storage profile must be LABEL:CLASS:PATH")
    label, storage_class, raw_path = fields
    if _LABEL.fullmatch(label) is None:
        raise ValueError("storage profile label is outside the finite identifier schema")
    if storage_class not in STORAGE_CLASSES:
        raise ValueError(f"storage class must be one of {sorted(STORAGE_CLASSES)}")
    if not raw_path:
        raise ValueError("storage profile path must not be empty")
    return label, storage_class, Path(raw_path)


def parse_attestation_argument(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("storage attestation must be LABEL=PATH")
    label, raw_path = value.split("=", 1)
    if _LABEL.fullmatch(label) is None or not raw_path:
        raise ValueError("storage attestation label/path is invalid")
    return label, Path(raw_path)


def _load_attestation(
    path: Path,
    *,
    label: str,
    resolved_path: Path,
    filesystem_type: str,
    hostname: str,
    device_id: int,
    mountpoint: str,
    mount_source: str,
    mount_options: Sequence[str],
) -> tuple[str, bool, str]:
    if not _is_bounded_nonnegative_int(device_id):
        raise ValueError("storage attestation device_id must be a nonnegative exact integer")
    if (
        type(hostname) is not str
        or not hostname
        or type(mountpoint) is not str
        or not mountpoint
        or type(mount_source) is not str
        or not mount_source
        or any(type(option) is not str or not option for option in mount_options)
    ):
        raise ValueError("observed storage identity has invalid text fields")
    if path.is_symlink():
        raise ValueError("storage attestation must not be a symbolic link")
    try:
        resolved_attestation = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"cannot resolve storage attestation {path}") from exc
    if not resolved_attestation.is_file():
        raise ValueError("storage attestation must be a regular file")
    try:
        value = json.loads(resolved_attestation.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read storage attestation {path}") from exc
    if type(value) is not dict or frozenset(value) != _ATTESTATION_FIELDS:
        raise ValueError("storage attestation has missing or unexpected fields")
    if value["schema_version"] != STORAGE_ATTESTATION_SCHEMA:
        raise ValueError("storage attestation schema version is unsupported")
    if value["label"] != label:
        raise ValueError("storage attestation label mismatch")
    if value["resolved_path"] != str(resolved_path):
        raise ValueError("storage attestation path mismatch")
    if value["filesystem_type"] != filesystem_type:
        raise ValueError("storage attestation filesystem mismatch")
    if not _is_bounded_nonnegative_int(value["device_id"]):
        raise ValueError("storage attestation device_id must be a nonnegative exact integer")
    if type(value["mount_options"]) is not list or any(
        type(option) is not str or not option for option in value["mount_options"]
    ):
        raise ValueError("storage attestation mount_options must be an exact string list")
    expected_mount = {
        "hostname": hostname,
        "device_id": device_id,
        "mountpoint": mountpoint,
        "mount_source": mount_source,
        "mount_options": list(mount_options),
    }
    for field, expected in expected_mount.items():
        if value[field] != expected:
            raise ValueError(f"storage attestation {field} mismatch")
    if value["node_local_verified"] is not True or value["persistence_verified"] is not True:
        raise ValueError("storage attestation does not verify node-local persistence")
    for field in ("verification_method", "verified_at_utc", "verified_by"):
        if type(value[field]) is not str or not value[field]:
            raise ValueError(f"storage attestation {field} must be a nonempty string")
    try:
        verified_at = datetime.fromisoformat(value["verified_at_utc"])
    except ValueError as exc:
        raise ValueError("storage attestation verified_at_utc is not ISO-8601") from exc
    if verified_at.tzinfo is None or verified_at.utcoffset() is None:
        raise ValueError("storage attestation verified_at_utc requires a timezone offset")
    if verified_at.utcoffset() != timedelta(0):
        raise ValueError("storage attestation verified_at_utc must use UTC")
    canonical = _canonical_json(value) + "\n"
    return hashlib.sha256(canonical.encode("ascii")).hexdigest(), True, canonical


def resolve_storage_profiles(
    arguments: Sequence[str],
    attestations: Mapping[str, Path] | None = None,
) -> tuple[StorageProfile, ...]:
    if not arguments:
        raise ValueError("at least one explicit storage profile is required")
    attestations = {} if attestations is None else dict(attestations)
    profiles: list[StorageProfile] = []
    labels: set[str] = set()
    resolved_paths: set[str] = set()
    for argument in arguments:
        label, storage_class, requested = parse_storage_argument(argument)
        if label in labels:
            raise ValueError("storage profile labels must be unique")
        if not requested.exists() or not requested.is_dir() or not os.access(requested, os.W_OK):
            raise ValueError(f"storage profile {label!r} must be an existing writable directory")
        resolved = requested.resolve(strict=True)
        if str(resolved) in resolved_paths:
            raise ValueError("storage profiles must have distinct resolved paths")
        mount = detect_mount(resolved)
        filesystem_type = mount["filesystem_type"]
        if storage_class == "tmpfs-diagnostic" and filesystem_type not in TMPFS_TYPES:
            raise ValueError("tmpfs-diagnostic profile does not resolve to tmpfs/ramfs")
        if storage_class == "local-persistent" and filesystem_type not in LOCAL_PERSISTENT_TYPES:
            raise ValueError(
                "local-persistent profile is on an unaccepted or nonpersistent filesystem"
            )
        attestation_path = attestations.get(label)
        resolved_attestation_path: Path | None = None
        attestation_sha256: str | None = None
        attestation_canonical_json: str | None = None
        attested = False
        if attestation_path is not None:
            if attestation_path.is_symlink():
                raise ValueError("storage attestation must not be a symbolic link")
            resolved_attestation_path = attestation_path.resolve(strict=True)
            attestation_sha256, attested, attestation_canonical_json = _load_attestation(
                resolved_attestation_path,
                label=label,
                resolved_path=resolved,
                filesystem_type=filesystem_type,
                hostname=platform.node(),
                device_id=resolved.stat().st_dev,
                mountpoint=mount["mountpoint"],
                mount_source=mount["mount_source"],
                mount_options=mount["mount_options"],
            )
        profiles.append(
            StorageProfile(
                label=label,
                storage_class=storage_class,
                requested_path=str(requested),
                resolved_path=str(resolved),
                device_id=resolved.stat().st_dev,
                mountpoint=mount["mountpoint"],
                filesystem_type=filesystem_type,
                mount_source=mount["mount_source"],
                mount_options=mount["mount_options"],
                attestation_path=(
                    None
                    if resolved_attestation_path is None
                    else str(resolved_attestation_path)
                ),
                attestation_sha256=attestation_sha256,
                attestation_canonical_json=attestation_canonical_json,
                operator_attested_local_persistence=attested,
            )
        )
        labels.add(label)
        resolved_paths.add(str(resolved))
    unknown_attestations = sorted(set(attestations) - labels)
    if unknown_attestations:
        raise ValueError(f"attestations name unknown storage profiles: {unknown_attestations}")
    return tuple(profiles)


def _validate_storage_profile_for_run(profile: StorageProfile) -> None:
    """Recheck profile shape, mount identity, and exact attestation bytes."""

    if type(profile) is not StorageProfile:
        raise ValueError("storage profile must be an exact StorageProfile")
    if _LABEL.fullmatch(profile.label) is None:
        raise ValueError("storage profile label is invalid")
    if profile.storage_class not in STORAGE_CLASSES:
        raise ValueError("storage profile class is invalid")
    if not _is_bounded_nonnegative_int(profile.device_id):
        raise ValueError("storage profile device_id is invalid")
    for field in (
        "requested_path",
        "resolved_path",
        "mountpoint",
        "filesystem_type",
        "mount_source",
    ):
        value = getattr(profile, field)
        if type(value) is not str or not value:
            raise ValueError(f"storage profile {field} is invalid")
    if type(profile.mount_options) is not tuple or any(
        type(option) is not str or not option for option in profile.mount_options
    ):
        raise ValueError("storage profile mount_options are invalid")
    observed = _observe_storage_identity(Path(profile.resolved_path))
    _validate_storage_identity(observed, _profile_storage_identity(profile))
    if profile.storage_class == "tmpfs-diagnostic":
        if profile.filesystem_type not in TMPFS_TYPES:
            raise ValueError("tmpfs diagnostic profile is not on tmpfs/ramfs")
        if (
            profile.operator_attested_local_persistence is not False
            or profile.attestation_path is not None
            or profile.attestation_sha256 is not None
            or profile.attestation_canonical_json is not None
        ):
            raise ValueError("tmpfs diagnostic profile must not carry persistence attestation")
        return
    if profile.filesystem_type not in LOCAL_PERSISTENT_TYPES:
        raise ValueError("local-persistent profile filesystem is not allowlisted")
    if not profile.claim_storage_eligible:
        raise ValueError("local-persistent profile lacks exact retained attestation material")
    assert profile.attestation_path is not None
    digest, attested, canonical = _load_attestation(
        Path(profile.attestation_path),
        label=profile.label,
        resolved_path=Path(profile.resolved_path),
        filesystem_type=profile.filesystem_type,
        hostname=platform.node(),
        device_id=profile.device_id,
        mountpoint=profile.mountpoint,
        mount_source=profile.mount_source,
        mount_options=profile.mount_options,
    )
    if (
        attested is not True
        or digest != profile.attestation_sha256
        or canonical != profile.attestation_canonical_json
    ):
        raise ValueError("storage attestation changed after profile resolution")


_STORAGE_IDENTITY_FIELDS = frozenset(
    {
        "resolved_path",
        "device_id",
        "mountpoint",
        "filesystem_type",
        "mount_source",
        "mount_options",
    }
)


def _observe_storage_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    mount = detect_mount(resolved)
    return {
        "resolved_path": str(resolved),
        "device_id": resolved.stat().st_dev,
        "mountpoint": mount["mountpoint"],
        "filesystem_type": mount["filesystem_type"],
        "mount_source": mount["mount_source"],
        "mount_options": list(mount["mount_options"]),
    }


def _profile_storage_identity(profile: StorageProfile) -> dict[str, Any]:
    return {
        "resolved_path": profile.resolved_path,
        "device_id": profile.device_id,
        "mountpoint": profile.mountpoint,
        "filesystem_type": profile.filesystem_type,
        "mount_source": profile.mount_source,
        "mount_options": list(profile.mount_options),
    }


def _validate_storage_identity(
    observed: object,
    expected: object,
) -> dict[str, Any]:
    for label, value in (("observed", observed), ("expected", expected)):
        if type(value) is not dict or frozenset(value) != _STORAGE_IDENTITY_FIELDS:
            raise ValueError(f"{label} storage identity has missing or unexpected fields")
        if not _is_bounded_nonnegative_int(value["device_id"]):
            raise ValueError(f"{label} storage identity device_id is invalid")
        for field in (
            "resolved_path",
            "mountpoint",
            "filesystem_type",
            "mount_source",
        ):
            if type(value[field]) is not str or not value[field]:
                raise ValueError(f"{label} storage identity {field} is invalid")
        if type(value["mount_options"]) is not list or any(
            type(option) is not str or not option for option in value["mount_options"]
        ):
            raise ValueError(f"{label} storage identity mount_options are invalid")
    for field in sorted(_STORAGE_IDENTITY_FIELDS):
        if type(observed[field]) is not type(expected[field]) or observed[field] != expected[field]:
            raise ValueError(f"storage identity {field} changed")
    return observed


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=None if environment is None else dict(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _load_native_git_attestation(
    *,
    repository_root: Path,
    native_git_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    """Validate the exact reviewed manifest before executing external Git."""

    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("native Git attestation must be a non-symlink regular file")
    resolved_manifest = manifest_path.resolve(strict=True)
    if not _path_is_within(resolved_manifest, repository_root):
        raise ValueError("native Git attestation must be retained inside the repository")
    try:
        raw = resolved_manifest.read_bytes()
        decoded = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot decode native Git attestation") from exc
    top_fields = frozenset(
        {
            "schema_version",
            "captured_utc",
            "purpose",
            "git",
            "zlib",
            "validation",
            "constraints",
        }
    )
    if type(decoded) is not dict or frozenset(decoded) != top_fields:
        raise ValueError("native Git attestation has missing or unexpected fields")
    if decoded["schema_version"] != NATIVE_GIT_ATTESTATION_SCHEMA:
        raise ValueError("native Git attestation schema is unsupported")
    try:
        captured = datetime.fromisoformat(decoded["captured_utc"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("native Git captured_utc is invalid") from exc
    if captured.tzinfo is None or captured.utcoffset() != timedelta(0):
        raise ValueError("native Git captured_utc must be UTC")
    if type(decoded["purpose"]) is not str or not decoded["purpose"]:
        raise ValueError("native Git attestation purpose is invalid")
    if type(decoded["constraints"]) is not list or any(
        type(item) is not str or not item for item in decoded["constraints"]
    ):
        raise ValueError("native Git attestation constraints are invalid")

    if native_git_path.is_symlink() or not native_git_path.is_file():
        raise ValueError("explicit native Git must be a non-symlink regular file")
    resolved_git = native_git_path.resolve(strict=True)
    git_fields = frozenset(
        {
            "version",
            "source_url",
            "source_sha256",
            "signature_url",
            "signature_sha256",
            "kernel_checksum_manifest_url",
            "kernel_checksum_manifest_sha256",
            "release_primary_key_fingerprint",
            "release_signing_subkey_fingerprint",
            "release_key_source",
            "release_key_fingerprint_source",
            "release_key_file_sha256",
            "signature_verification",
            "installations",
        }
    )
    git = decoded["git"]
    if (
        type(git) is not dict
        or frozenset(git) != git_fields
        or type(git["version"]) is not str
        or not git["version"]
        or type(git["signature_verification"]) is not str
        or git["signature_verification"]
        != "good_signature_exact_pinned_fingerprint"
        or type(git["release_primary_key_fingerprint"]) is not str
        or _OPENPGP_FINGERPRINT.fullmatch(git["release_primary_key_fingerprint"])
        is None
        or type(git["release_signing_subkey_fingerprint"]) is not str
        or _OPENPGP_FINGERPRINT.fullmatch(
            git["release_signing_subkey_fingerprint"]
        )
        is None
    ):
        raise ValueError("native Git source-signature attestation is invalid")
    git_sha_fields = (
        "source_sha256",
        "signature_sha256",
        "kernel_checksum_manifest_sha256",
        "release_key_file_sha256",
    )
    git_url_fields = (
        "source_url",
        "signature_url",
        "kernel_checksum_manifest_url",
        "release_key_source",
        "release_key_fingerprint_source",
    )
    if (
        any(
            type(git[field]) is not str or _SHA256.fullmatch(git[field]) is None
            for field in git_sha_fields
        )
        or any(type(git[field]) is not str or not git[field] for field in git_url_fields)
    ):
        raise ValueError("native Git source hashes/URLs are invalid")
    zlib_fields = frozenset(
        {"version", "source_url", "source_sha256", "published_sha256_source"}
    )
    zlib = decoded["zlib"]
    if (
        type(zlib) is not dict
        or frozenset(zlib) != zlib_fields
        or any(
            type(zlib[field]) is not str or not zlib[field]
            for field in ("version", "source_url", "published_sha256_source")
        )
        or type(zlib["source_sha256"]) is not str
        or _SHA256.fullmatch(zlib["source_sha256"]) is None
    ):
        raise ValueError("native Git zlib source attestation is invalid")

    validation_fields = frozenset(
        {
            "repository_fsck_strict",
            "tracked_diff_exit_code",
            "staged_diff_exit_code",
            "untracked_files_are_clean",
            "principal_run_authorized_at_capture",
        }
    )
    validation = decoded["validation"]
    if (
        type(validation) is not dict
        or frozenset(validation) != validation_fields
        or validation["repository_fsck_strict"] != "pass"
        or type(validation["tracked_diff_exit_code"]) is not int
        or validation["tracked_diff_exit_code"] != 0
        or type(validation["staged_diff_exit_code"]) is not int
        or validation["staged_diff_exit_code"] != 0
        or type(validation["untracked_files_are_clean"]) is not bool
        or type(validation["principal_run_authorized_at_capture"]) is not bool
    ):
        raise ValueError("native Git validation attestation is invalid")

    installation_fields = frozenset(
        {
            "label",
            "platform",
            "tool_path",
            "tool_executable_sha256",
            "version_output",
            "build",
            "runtime_libraries",
            "validated_hosts",
        }
    )
    build_fields = frozenset({"compiler", "build_kernel", "make_flags"})
    library_fields = frozenset({"path", "sha256"})
    host_fields = frozenset({"hostname", "head", "version_output"})
    installations = git["installations"]
    if type(installations) is not list or not installations:
        raise ValueError("native Git installations are invalid")

    toolchain_root = resolved_git.parents[2]

    def expand_path(path_text: object) -> Path:
        if type(path_text) is not str or not path_text:
            raise ValueError("native Git attested path is invalid")
        expanded = path_text.replace("${SLUICE_TOOLCHAIN_ROOT}", str(toolchain_root))
        if "${" in expanded or not Path(expanded).is_absolute():
            raise ValueError("native Git attested path has an unresolved placeholder")
        return Path(expanded)

    selected: dict[str, Any] | None = None
    for installation in installations:
        if type(installation) is not dict or frozenset(installation) != installation_fields:
            raise ValueError("native Git installation schema is invalid")
        if any(
            type(installation[field]) is not str or not installation[field]
            for field in ("label", "platform", "version_output")
        ):
            raise ValueError("native Git installation labels/version are invalid")
        build = installation["build"]
        if (
            type(build) is not dict
            or frozenset(build) != build_fields
            or type(build["compiler"]) is not str
            or not build["compiler"]
            or type(build["build_kernel"]) is not str
            or not build["build_kernel"]
            or type(build["make_flags"]) is not list
            or any(type(flag) is not str or not flag for flag in build["make_flags"])
        ):
            raise ValueError("native Git installation build identity is invalid")
        tool = expand_path(installation["tool_path"])
        installation_is_selected = tool.resolve(strict=False) == resolved_git
        digest = installation["tool_executable_sha256"]
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise ValueError("native Git installation executable hash is invalid")
        libraries = installation["runtime_libraries"]
        if type(libraries) is not list or not libraries:
            raise ValueError("native Git runtime-library attestation is invalid")
        observed_library_paths: set[str] = set()
        for item in libraries:
            if type(item) is not dict or frozenset(item) != library_fields:
                raise ValueError("native Git runtime-library schema is invalid")
            library = expand_path(item["path"])
            library_digest = item["sha256"]
            if (
                type(library_digest) is not str
                or _SHA256.fullmatch(library_digest) is None
            ):
                raise ValueError("native Git runtime-library hash is invalid")
            if installation_is_selected and (
                library.is_symlink()
                or not library.is_file()
                or _sha256_file(library.resolve(strict=True)) != library_digest
            ):
                raise ValueError(
                    "native Git runtime-library hash disagrees with attestation"
                )
            canonical_library = str(
                library.resolve(strict=True)
                if installation_is_selected
                else library.resolve(strict=False)
            )
            if canonical_library in observed_library_paths:
                raise ValueError("native Git runtime libraries must be unique")
            observed_library_paths.add(canonical_library)
        hosts = installation["validated_hosts"]
        if type(hosts) is not list or not hosts:
            raise ValueError("native Git validated-host list is invalid")
        for host in hosts:
            if (
                type(host) is not dict
                or frozenset(host) != host_fields
                or type(host["hostname"]) is not str
                or not host["hostname"]
                or type(host["head"]) is not str
                or _GIT_COMMIT.fullmatch(host["head"]) is None
                or type(host["version_output"]) is not str
                or host["version_output"] != installation["version_output"]
            ):
                raise ValueError("native Git validated-host identity is invalid")
        if installation_is_selected:
            if selected is not None:
                raise ValueError("native Git path matches multiple installations")
            selected = installation
    if selected is None:
        raise ValueError("explicit native Git is absent from the attested installations")
    if (
        resolved_git.is_symlink()
        or not resolved_git.is_file()
        or _sha256_file(resolved_git) != selected["tool_executable_sha256"]
    ):
        raise ValueError("native Git executable identity disagrees with attestation")

    return {
        "path": str(resolved_manifest),
        "repository_path": resolved_manifest.relative_to(
            repository_root.resolve(strict=True)
        ).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "value": decoded,
        "selected_installation": selected,
        "authorized_for_final": (
            validation["untracked_files_are_clean"] is True
            and validation["principal_run_authorized_at_capture"] is True
        ),
    }


def source_provenance(
    repository_root: Path = REPOSITORY_ROOT,
    *,
    native_git_path: Path | None = None,
    native_git_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Return a verifiable commit/dirty state; unknown is never clean."""

    if (native_git_path is None) is not (native_git_manifest_path is None):
        raise ValueError(
            "explicit native Git path and attestation must be supplied together"
        )
    native_git: Path | None = None
    native_attestation: dict[str, Any] | None = None
    if native_git_path is not None and native_git_manifest_path is not None:
        native_attestation = _load_native_git_attestation(
            repository_root=repository_root,
            native_git_path=native_git_path,
            manifest_path=native_git_manifest_path,
        )
        native_git = native_git_path.resolve(strict=True)
    native_commit = (
        _run_command([str(native_git), "rev-parse", "HEAD"], cwd=repository_root)
        if native_git is not None and native_git.is_file()
        else None
    )
    native_status = (
        _run_command(
            [str(native_git), "status", "--porcelain=v1"], cwd=repository_root
        )
        if native_git is not None and native_git.is_file()
        else None
    )
    native_version = (
        _run_command([str(native_git), "--version"], cwd=repository_root)
        if native_git is not None and native_git.is_file()
        else None
    )
    commit_text = (
        native_commit.stdout.strip() if native_commit is not None else ""
    )
    manifest_tracked = (
        _run_command(
            [
                str(native_git),
                "ls-files",
                "--error-unmatch",
                "--",
                str(native_attestation["repository_path"]),
            ],
            cwd=repository_root,
        )
        if native_git is not None and native_attestation is not None
        else None
    )
    if (
        native_commit is not None
        and native_status is not None
        and native_version is not None
        and native_commit.returncode == 0
        and native_status.returncode == 0
        and native_version.returncode == 0
        and manifest_tracked is not None
        and manifest_tracked.returncode == 0
        and _GIT_COMMIT.fullmatch(commit_text) is not None
        and native_version.stdout.strip()
        == native_attestation["selected_installation"]["version_output"]
    ):
        host_validated = any(
            host["hostname"] == platform.node()
            and host["version_output"] == native_version.stdout.strip()
            for host in native_attestation["selected_installation"][
                "validated_hosts"
            ]
        )
        return {
            "backend": "git",
            "commit": commit_text,
            "dirty": bool(native_status.stdout),
            "status_porcelain": native_status.stdout.splitlines(),
            "tool_path": str(native_git),
            "tool_executable_sha256": _sha256_file(native_git),
            "tool_version": native_version.stdout.strip(),
            "tool_manifest_path": native_attestation["path"],
            "tool_manifest_repository_path": native_attestation[
                "repository_path"
            ],
            "tool_manifest_sha256": native_attestation["sha256"],
            "tool_installation_label": native_attestation[
                "selected_installation"
            ]["label"],
            "tool_host_validated": host_validated,
            "trusted_for_final": (
                native_attestation["authorized_for_final"] is True
                and host_validated
            ),
        }
    if native_git is not None:
        if manifest_tracked is None or manifest_tracked.returncode != 0:
            raise ValueError(
                "explicit native Git attestation is not tracked by the repository"
            )
        raise ValueError(
            "explicit native Git command output/version does not match its attestation"
        )

    dulwich_program = repository_root / "tools" / "dulwich" / "bin" / "dulwich"
    dulwich_library = repository_root / "tools" / "dulwich"
    if dulwich_program.is_file() and dulwich_library.is_dir():
        environment = dict(os.environ)
        prior = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = str(dulwich_library) if not prior else f"{dulwich_library}:{prior}"
        commit = _run_command(
            [str(dulwich_program), "rev-parse", "HEAD"],
            cwd=repository_root,
            environment=environment,
        )
        status = _run_command(
            [str(dulwich_program), "status"],
            cwd=repository_root,
            environment=environment,
        )
        version = _run_command(
            [str(dulwich_program), "--version"],
            cwd=repository_root,
            environment=environment,
        )
        if commit is not None and status is not None and commit.returncode == status.returncode == 0:
            status_lines = status.stdout.splitlines()
            clean = status.stdout.strip() == "No uncommitted changes."
            return {
                "backend": "vendored-dulwich",
                "commit": commit.stdout.strip(),
                "dirty": not clean,
                "status": status_lines,
                "tool_executable_sha256": _sha256_file(dulwich_program),
                "tool_tree_sha256": _sha256_tree(dulwich_library),
                "tool_version": (
                    version.stdout.strip()
                    if version is not None and version.returncode == 0
                    else None
                ),
                "trusted_for_final": False,
            }
    return {
        "backend": "unavailable",
        "commit": None,
        "dirty": None,
        "status": [],
    }


def validate_run_parameters(
    *,
    mode: str,
    operations: int,
    warmup_operations: int,
    repetitions: int,
    concurrencies: Sequence[int],
    bootstrap_replicates: int,
    profiles: Sequence[StorageProfile],
    provenance: Mapping[str, Any],
) -> None:
    if type(mode) is not str or mode not in ("diagnostic", "final"):
        raise ValueError("mode must be diagnostic or final")
    _positive_int("operations", operations)
    if not _is_bounded_nonnegative_int(warmup_operations):
        raise ValueError("warmup_operations must be a nonnegative exact integer")
    _positive_int("repetitions", repetitions)
    _positive_int("bootstrap_replicates", bootstrap_replicates)
    if type(concurrencies) not in (tuple, list) or not concurrencies or any(
        not _is_exact_int(value) or not 0 < value <= MAX_AUDIT_INTEGER
        for value in concurrencies
    ):
        raise ValueError("concurrencies must be nonempty positive exact integers")
    if len(set(concurrencies)) != len(concurrencies):
        raise ValueError("concurrency levels must be unique")
    if max(concurrencies) > operations:
        raise ValueError("concurrency cannot exceed measured operations")
    if warmup_operations and max(concurrencies) > warmup_operations:
        raise ValueError("concurrency cannot exceed nonzero warm-up operations")
    if not profiles:
        raise ValueError("at least one storage profile is required")
    if mode == "final":
        if not FINAL_CLAIMS_ENABLED:
            raise ValueError(
                "final mode is disabled until the singleton service, storage attestation, "
                "and independent raw validator are committed and reviewed"
            )
        if provenance.get("backend") != "git" or provenance.get(
            "trusted_for_final"
        ) is not True:
            raise ValueError(
                "final mode requires native Git provenance; ignored vendored Dulwich is "
                "diagnostic-only"
            )
        if (
            type(provenance.get("commit")) is not str
            or _GIT_COMMIT.fullmatch(str(provenance.get("commit"))) is None
            or provenance.get("dirty") is not False
        ):
            raise ValueError("final mode requires a committed clean source tree")
        if repetitions < MIN_FINAL_REPETITIONS:
            raise ValueError(f"final mode requires at least {MIN_FINAL_REPETITIONS} repetitions")
        if operations < MIN_P999_OPERATIONS:
            raise ValueError(f"final mode requires at least {MIN_P999_OPERATIONS} operations")
        if bootstrap_replicates < DEFAULT_BOOTSTRAP_REPLICATES:
            raise ValueError(
                f"final mode requires at least {DEFAULT_BOOTSTRAP_REPLICATES} bootstrap replicates"
            )
        if not set(DEFAULT_CONCURRENCIES).issubset(concurrencies):
            raise ValueError("final mode requires the complete 1,2,4,8,16,32,64 sweep")
        if not all(profile.claim_storage_eligible for profile in profiles):
            raise ValueError(
                "every final-mode storage profile must be an attested "
                "local-persistent profile"
            )


def build_schedule(
    profiles: Sequence[StorageProfile],
    concurrencies: Sequence[int],
    repetitions: int,
    *,
    seed: int,
) -> list[dict[str, Any]]:
    _positive_int("repetitions", repetitions)
    if not _is_exact_int(seed) or abs(seed) > MAX_AUDIT_INTEGER:
        raise ValueError("seed must be a bounded exact integer")
    if not concurrencies or any(
        not _is_exact_int(item) or not 0 < item <= MAX_AUDIT_INTEGER
        for item in concurrencies
    ):
        raise ValueError("schedule concurrencies must be bounded positive exact integers")
    if any(type(profile) is not StorageProfile for profile in profiles):
        raise ValueError("schedule profiles must be exact StorageProfile values")
    schedule: list[dict[str, Any]] = []
    for repetition in range(repetitions):
        blocks = [(profile, concurrency) for profile in profiles for concurrency in concurrencies]
        random.Random(seed + repetition * 1_000_003).shuffle(blocks)
        for block_order, (profile, concurrency) in enumerate(blocks):
            block_id = f"r{repetition:03d}-{profile.label}-c{concurrency:03d}"
            conditions = list(CONDITIONS)
            block_seed_material = f"{seed}|{block_id}".encode("ascii")
            block_seed = int.from_bytes(hashlib.sha256(block_seed_material).digest()[:8], "big")
            random.Random(block_seed).shuffle(conditions)
            for condition_order, condition in enumerate(conditions):
                schedule.append(
                    {
                        "block_id": block_id,
                        "block_order": block_order,
                        "repetition": repetition,
                        "storage_label": profile.label,
                        "storage_class": profile.storage_class,
                        "concurrency": concurrency,
                        "condition": condition,
                        "condition_order": condition_order,
                    }
                )
    return schedule


def cell_claim_eligible(
    *,
    mode: str,
    source_clean: bool,
    profile: StorageProfile,
    status: str,
    metrics_complete: bool = True,
) -> bool:
    return (
        FINAL_CLAIMS_ENABLED
        and mode == "final"
        and source_clean is True
        and profile.claim_storage_eligible
        and status == "ok"
        and metrics_complete is True
    )


def _required_metrics_complete(condition: str, measured: Mapping[str, Any] | None) -> bool:
    if measured is None or measured.get("status") != "ok":
        return False
    latency = measured.get("latency_summary")
    if (
        type(latency) is not dict
        or not _is_finite_nonnegative_number(latency.get("p99_9_ms"))
        or type(latency.get("p99_9_support")) is not dict
        or latency["p99_9_support"].get("supported") is not True
    ):
        return False
    common = (
        measured.get("throughput_operations_per_second"),
        measured.get("worker_process_cpu_ns"),
        measured.get("combined_cpu_ns"),
        measured.get("combined_cpu_core_equivalent_percent"),
        measured.get("worker_process_lifetime_peak_rss_bytes"),
    )
    if any(not _is_finite_nonnegative_number(value) for value in common):
        return False
    if condition == "singleton_ipc":
        monitor_memory = measured.get("monitor_memory_after")
        if (
            not _is_bounded_nonnegative_int(measured.get("monitor_process_cpu_ns"))
            or type(monitor_memory) is not dict
            or not _is_bounded_nonnegative_int(monitor_memory.get("vm_hwm_bytes"))
            or not _is_bounded_nonnegative_int(monitor_memory.get("vm_rss_bytes"))
        ):
            return False
    if condition in ("durable_direct", "singleton_ipc"):
        growth = measured.get("sqlite_growth")
        if type(growth) is not dict or not _is_bounded_nonnegative_int(
            growth.get("family_bytes_growth")
        ):
            return False
    return True


def _process_memory(pid: int) -> dict[str, int | None]:
    values: dict[str, int | None] = {"vm_rss_bytes": None, "vm_hwm_bytes": None}
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                values["vm_rss_bytes"] = int(line.split()[1]) * 1024
            elif line.startswith("VmHWM:"):
                values["vm_hwm_bytes"] = int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError, UnicodeError):
        pass
    return values


def _process_cpu_ns(pid: int) -> int | None:
    try:
        encoded = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        # The executable name may contain spaces and parentheses.  Fields after
        # the final ')' begin at proc field 3; utime/stime are fields 14/15.
        fields = encoded[encoded.rfind(")") + 2 :].split()
        ticks = int(fields[11]) + int(fields[12])
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        return int(ticks * 1_000_000_000 / ticks_per_second)
    except (OSError, ValueError, IndexError):
        return None


def _database_family(path: Path) -> dict[str, int]:
    output: dict[str, int] = {}
    for suffix in ("", "-wal", "-shm"):
        candidate = path.with_name(path.name + suffix)
        if candidate.is_file():
            output[suffix or "main"] = candidate.stat().st_size
    return output


def _sqlite_metrics(path: Path) -> dict[str, Any]:
    family = _database_family(path)
    connection = sqlite3.connect(str(path), timeout=30.0)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        counts: dict[str, int | None] = {}
        for table in (
            "attempts",
            "audit_log",
            "used_credentials",
            "sluice_monitor_request_cache",
        ):
            counts[table] = (
                int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                if table in tables
                else None
            )
        audit_logical_bytes = None
        if "audit_log" in tables:
            audit_logical_bytes = int(
                connection.execute(
                    "SELECT COALESCE(SUM(length(CAST(audit_sequence AS TEXT)) + "
                    "length(CAST(lifetime_attempt AS TEXT)) + length(phase)),0) FROM audit_log"
                ).fetchone()[0]
            )
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        freelist_count = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).upper()
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
    finally:
        connection.close()
    return {
        "file_bytes": family,
        "family_bytes": sum(family.values()),
        "page_size": page_size,
        "page_count": page_count,
        "allocated_page_bytes": page_size * page_count,
        "freelist_count": freelist_count,
        "journal_mode": journal_mode,
        "synchronous_numeric": synchronous,
        "row_counts": counts,
        "audit_logical_payload_bytes": audit_logical_bytes,
    }


def _sqlite_growth(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    row_growth: dict[str, int | None] = {}
    for table, after_value in after["row_counts"].items():
        before_value = before["row_counts"].get(table)
        row_growth[table] = (
            None if before_value is None or after_value is None else int(after_value) - int(before_value)
        )
    before_audit = before["audit_logical_payload_bytes"]
    after_audit = after["audit_logical_payload_bytes"]
    return {
        "before": dict(before),
        "after": dict(after),
        "family_bytes_growth": int(after["family_bytes"]) - int(before["family_bytes"]),
        "allocated_page_bytes_growth": int(after["allocated_page_bytes"])
        - int(before["allocated_page_bytes"]),
        "row_growth": row_growth,
        "audit_logical_payload_bytes_growth": (
            None if before_audit is None or after_audit is None else int(after_audit) - int(before_audit)
        ),
        "audit_byte_scope": (
            "logical lengths of audit table scalar fields; physical SQLite pages are shared"
        ),
    }


@dataclass
class _PreparedCondition:
    operation: Callable[[int], Any]
    close: Callable[[], None]
    database_path: Path | None = None
    monitor_pid: int | None = None
    temp_directory: Path | None = None


def _domain_config(operation_count: int, token: str) -> DomainConfig:
    return DomainConfig(
        domain_id=f"g8-{token}",
        protected_objects=frozenset({"matched-object"}),
        lifetime_budget_units=operation_count * EVENT_CHARGE_UNITS,
        attempt_horizon=operation_count,
        event_charge_units=EVENT_CHARGE_UNITS,
    )


def _inmemory_observer(token: str) -> InMemoryObserverSpec:
    return InMemoryObserverSpec(
        permitted_value_codes=frozenset({HANDLER_VALUE_CODE}),
        observer_spec_id=f"g8-inmemory-{token}",
        route_codebooks=(
            InMemoryRouteCodebook(
                name="matched-release",
                public_values=frozenset({HANDLER_VALUE_CODE}),
                requires_capability=False,
            ),
        ),
        accounting_units_per_bit=1,
    )


def _durable_observer(token: str) -> DurableObserverSpec:
    return DurableObserverSpec(
        permitted_value_codes=frozenset({HANDLER_VALUE_CODE}),
        observer_spec_id=f"g8-durable-{token}",
        route_codebooks=(
            DurableRouteCodebook(
                name="matched-release",
                public_values=frozenset({HANDLER_VALUE_CODE}),
                requires_capability=False,
            ),
        ),
        accounting_units_per_bit=1,
    )


def _peer(pid: int) -> PeerIdentity:
    return PeerIdentity(pid=pid, uid=os.getuid(), gid=os.getgid())


def _terminate_monitor(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == pid:
            return
        time.sleep(0.01)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _fork_monitor(config: MonitorServiceConfig) -> int:
    ready_read, ready_write = os.pipe()
    parent_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        try:
            SingletonMonitorService(config).serve_forever(
                expected_parent_pid=parent_pid,
                ready_fd=ready_write,
            )
        finally:
            os._exit(111)
    os.close(ready_write)
    ready = os.read(ready_read, 1)
    os.close(ready_read)
    if ready != b"R":
        try:
            _, status = os.waitpid(pid, 0)
            detail = f"status={status}"
        except ChildProcessError:
            detail = "status=unknown"
        raise RuntimeError(f"singleton monitor did not become ready ({detail})")
    return pid


def _prepare_condition(condition: str, operation_count: int, storage_root: Path) -> _PreparedCondition:
    if condition not in CONDITIONS:
        raise ValueError("unknown benchmark condition")
    _positive_int("operation_count", operation_count)
    payload = {"value_code": HANDLER_VALUE_CODE}
    token = uuid.uuid4().hex[:16]

    if condition == "unmediated_handler":
        return _PreparedCondition(
            operation=lambda _index: finite_handler(payload),
            close=lambda: None,
        )

    if condition == "inmemory_secure_domain":
        domain = SecureDomain(
            _domain_config(operation_count, token),
            observer_spec=_inmemory_observer(token),
            agent_keys={"worker": CALLER_KEY},
            reauthorization_keys={},
        )
        route = domain.register_route(
            name="matched-release",
            protected_object="matched-object",
            handler=finite_handler,
            public_values=frozenset({HANDLER_VALUE_CODE}),
            requires_capability=False,
        )
        credentials = tuple(
            InMemoryAttemptCredential.sign(
                agent_id="worker",
                signing_key=CALLER_KEY,
                route=route,
                payload=payload,
                nonce=f"g8-{index}",
            )
            for index in range(operation_count)
        )
        domain.seal()
        domain.activate()
        return _PreparedCondition(
            operation=lambda index: domain.attempt(
                route,
                payload,
                credential=credentials[index],
            ),
            close=lambda: None,
        )

    temp_directory = Path(tempfile.mkdtemp(prefix="sluice-g8-", dir=storage_root))
    database_path = temp_directory / "domain.sqlite3"
    try:
        domain = DurableSecureDomain.create(
            database_path,
            config=_domain_config(operation_count, token),
            observer_spec=_durable_observer(token),
            agent_keys={"worker": CALLER_KEY},
            reauthorization_keys={},
            handler_registry={"matched-handler-v1": finite_handler},
        )
    except BaseException:
        shutil.rmtree(temp_directory)
        raise

    def abort_durable_setup() -> None:
        try:
            domain.close()
        finally:
            shutil.rmtree(temp_directory)

    try:
        route = domain.register_route(
            name="matched-release",
            protected_object="matched-object",
            handler_key="matched-handler-v1",
            public_values=frozenset({HANDLER_VALUE_CODE}),
            requires_capability=False,
        )
        credentials = tuple(
            DurableAttemptCredential.sign(
                agent_id="worker",
                signing_key=CALLER_KEY,
                domain_context=domain.credential_context,
                expected_epoch=domain.current_epoch,
                route=route,
                payload=payload,
                nonce=f"g8-{index}",
                expires_at_lifetime_attempt=operation_count,
            )
            for index in range(operation_count)
        )
        domain.seal()
        domain.activate()
    except BaseException:
        abort_durable_setup()
        raise

    if condition == "durable_direct":
        def close_direct() -> None:
            domain.close()
            shutil.rmtree(temp_directory)

        return _PreparedCondition(
            operation=lambda index: domain.attempt(
                route,
                payload,
                credential=credentials[index],
            ),
            close=close_direct,
            database_path=database_path,
            temp_directory=temp_directory,
        )

    monitor_pid: int | None = None
    try:
        bindings = tuple(
            PrivateTemplateBinding(
                template_code=index + 1,
                route=route,
                payload=payload,
                credential=credentials[index],
            )
            for index in range(operation_count)
        )
        domain.close()
        address = f"\0sluice-g8-{os.getpid()}-{uuid.uuid4().hex}"
        config = MonitorServiceConfig(
            address=address,
            opener=DurableDomainOpener(
                ledger_path=database_path,
                agent_keys={"worker": CALLER_KEY},
                reauthorization_keys={},
                handler_registry={"matched-handler-v1": finite_handler},
            ),
            templates=bindings,
            expected_model=_peer(os.getpid()),
        )
        monitor_pid = _fork_monitor(config)
        expected_monitor = _peer(monitor_pid)
        requests = tuple(
            ModelRequest(
                schema_version=MONITOR_PROTOCOL_VERSION,
                request_id=f"g8-{index}",
                operation_code=ModelOperationCode.ATTEMPT_TEMPLATE,
                template_code=index + 1,
            )
            for index in range(operation_count)
        )
    except BaseException:
        if monitor_pid is not None:
            _terminate_monitor(monitor_pid)
        abort_durable_setup()
        raise
    assert monitor_pid is not None

    def close_singleton() -> None:
        _terminate_monitor(monitor_pid)
        shutil.rmtree(temp_directory)

    return _PreparedCondition(
        operation=lambda index: connect_model(
            address,
            requests[index],
            expected_monitor=expected_monitor,
        ),
        close=close_singleton,
        database_path=database_path,
        monitor_pid=monitor_pid,
        temp_directory=temp_directory,
    )


def _validate_operation_result(condition: str, result: Any) -> tuple[int, int | None]:
    if condition == "unmediated_handler":
        if type(result) is not int or result != HANDLER_VALUE_CODE:
            raise RuntimeError("unmediated matched handler returned the wrong finite code")
        return result, None
    if type(result) is not TranscriptEvent:
        raise RuntimeError("mediated condition did not return an exact TranscriptEvent")
    if (
        result.kind is not EventKind.ATTEMPT
        or result.outcome is not OutcomeCode.RELEASED
        or type(result.value_code) is not int
        or result.value_code != HANDLER_VALUE_CODE
    ):
        raise RuntimeError("mediated matched operation was not released with the finite code")
    return HANDLER_VALUE_CODE, result.sequence


def _execute_parallel(
    *,
    condition: str,
    operation: Callable[[int], Any],
    operation_count: int,
    concurrency: int,
    capture_operations: bool,
) -> dict[str, Any]:
    _positive_int("operation_count", operation_count)
    _positive_int("concurrency", concurrency)
    if concurrency > operation_count:
        raise ValueError("concurrency cannot exceed operations")
    records: list[dict[str, Any] | None] = [None] * operation_count
    no_result = object()
    pending_results: list[Any] = [no_result] * operation_count
    successful_timings: list[tuple[int, int, int] | None] = [None] * operation_count
    barrier = threading.Barrier(concurrency + 1)
    origin_ns = time.perf_counter_ns()

    def worker(slot: int) -> None:
        indices = range(slot, operation_count, concurrency)
        try:
            barrier.wait()
        except threading.BrokenBarrierError as exc:
            for index in indices:
                records[index] = {
                    "operation_index": index,
                    "worker_slot": slot,
                    "status": "failed",
                    "start_offset_ns": None,
                    "latency_ns": None,
                    "value_code": None,
                    "transcript_sequence": None,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
            return
        for index in indices:
            started_ns = time.perf_counter_ns()
            try:
                result = operation(index)
            except BaseException as exc:  # retain every failed scheduled operation
                finished_ns = time.perf_counter_ns()
                records[index] = {
                    "operation_index": index,
                    "worker_slot": slot,
                    "status": "failed",
                    "start_offset_ns": started_ns - origin_ns,
                    "latency_ns": finished_ns - started_ns,
                    "value_code": None,
                    "transcript_sequence": None,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
            else:
                finished_ns = time.perf_counter_ns()
                pending_results[index] = result
                successful_timings[index] = (
                    slot,
                    started_ns - origin_ns,
                    finished_ns - started_ns,
                )

    threads = [
        threading.Thread(target=worker, args=(slot,), name=f"g8-worker-{slot}")
        for slot in range(concurrency)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    # Validate only after every timed call is complete. This keeps
    # condition-specific validation out of both latency and throughput gaps.
    for index, pending in enumerate(pending_results):
        if pending is no_result:
            continue
        timing = successful_timings[index]
        if timing is None:
            raise RuntimeError("parallel executor lost successful timing metadata")
        slot, start_offset_ns, latency_ns = timing
        try:
            value_code, sequence = _validate_operation_result(condition, pending)
        except BaseException as exc:
            records[index] = {
                "operation_index": index,
                "worker_slot": slot,
                "status": "failed",
                "start_offset_ns": start_offset_ns,
                "latency_ns": latency_ns,
                "value_code": None,
                "transcript_sequence": None,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
        else:
            records[index] = {
                "operation_index": index,
                "worker_slot": slot,
                "status": "ok",
                "start_offset_ns": start_offset_ns,
                "latency_ns": latency_ns,
                "value_code": value_code,
                "transcript_sequence": sequence,
                "error_type": None,
                "error_message": None,
            }
    if any(record is None for record in records):
        raise RuntimeError("parallel executor lost an operation record")
    exact_records = [record for record in records if record is not None]
    successful = [record for record in exact_records if record["status"] == "ok"]
    failed = [record for record in exact_records if record["status"] == "failed"]
    start_offsets = [
        int(record["start_offset_ns"])
        for record in exact_records
        if type(record.get("start_offset_ns")) is int
    ]
    finishes = [
        int(record["start_offset_ns"]) + int(record["latency_ns"])
        for record in exact_records
        if type(record.get("start_offset_ns")) is int
        and type(record.get("latency_ns")) is int
    ]
    envelope_ns = max(finishes) - min(start_offsets) if start_offsets and finishes else 0
    if not _is_bounded_nonnegative_int(envelope_ns):
        raise RuntimeError("measurement envelope exceeds the bounded integer schema")
    sequences = [
        int(record["transcript_sequence"])
        for record in successful
        if record.get("transcript_sequence") is not None
    ]
    sequence_valid = (
        True
        if condition == "unmediated_handler" and not failed
        else sorted(sequences) == list(range(1, operation_count + 1))
    )
    busy_failures = sum(
        "locked" in str(record.get("error_message", "")).lower()
        or "busy" in str(record.get("error_message", "")).lower()
        for record in failed
    )
    durable_transaction = condition in ("durable_direct", "singleton_ipc")
    return {
        "status": "ok" if not failed and sequence_valid else "failed",
        "expected_operations": operation_count,
        "completed_operations": len(successful),
        "failed_operations": len(failed),
        "failed_transaction_count": len(failed) if durable_transaction else None,
        "failed_transaction_rate": (
            len(failed) / operation_count if durable_transaction else None
        ),
        "lock_contention_failure_count": busy_failures if durable_transaction else None,
        "measurement_envelope_ns": envelope_ns,
        "throughput_operations_per_second": (
            operation_count / (envelope_ns / 1_000_000_000.0) if envelope_ns > 0 else None
        ),
        "transcript_sequence_set_valid": sequence_valid,
        "operations": exact_records if capture_operations else [],
        "latency_summary": (
            summarize_latencies([int(record["latency_ns"]) for record in successful])
            if successful
            else None
        ),
        "setup_or_measurement_error": None,
    }


def _synthetic_failure_operations(
    operation_count: int,
    *,
    error_type: str,
    error_message: str,
) -> list[dict[str, Any]]:
    """Make the raw denominator total when no worker sample can be trusted."""

    return [
        {
            "operation_index": index,
            "worker_slot": -1,
            "status": "failed",
            "start_offset_ns": None,
            "latency_ns": None,
            "value_code": None,
            "transcript_sequence": None,
            "error_type": error_type,
            "error_message": error_message,
        }
        for index in range(operation_count)
    ]


def execute_condition_once(
    *,
    condition: str,
    operation_count: int,
    concurrency: int,
    storage_root: Path,
    capture_operations: bool = True,
) -> dict[str, Any]:
    """Execute one fresh condition instance; used by the worker and tests."""

    prepared: _PreparedCondition | None = None
    cleanup_error: dict[str, str] | None = None
    database_before: dict[str, Any] | None = None
    database_after: dict[str, Any] | None = None
    monitor_cpu_before: int | None = None
    monitor_cpu_after: int | None = None
    monitor_memory_after: dict[str, int | None] | None = None
    self_cpu_before = time.process_time_ns()
    self_memory_before = _process_memory(os.getpid())
    try:
        prepared = _prepare_condition(condition, operation_count, storage_root)
        if prepared.database_path is not None:
            database_before = _sqlite_metrics(prepared.database_path)
        if prepared.monitor_pid is not None:
            monitor_cpu_before = _process_cpu_ns(prepared.monitor_pid)
        self_cpu_before = time.process_time_ns()
        measured = _execute_parallel(
            condition=condition,
            operation=prepared.operation,
            operation_count=operation_count,
            concurrency=concurrency,
            capture_operations=capture_operations,
        )
        self_cpu_after = time.process_time_ns()
        if prepared.monitor_pid is not None:
            monitor_cpu_after = _process_cpu_ns(prepared.monitor_pid)
            monitor_memory_after = _process_memory(prepared.monitor_pid)
        if prepared.database_path is not None:
            database_after = _sqlite_metrics(prepared.database_path)
    except BaseException as exc:
        durable_transaction = condition in ("durable_direct", "singleton_ipc")
        measured = {
            "status": "failed",
            "expected_operations": operation_count,
            "completed_operations": 0,
            "failed_operations": operation_count,
            "failed_transaction_count": operation_count if durable_transaction else None,
            "failed_transaction_rate": 1.0 if durable_transaction else None,
            "lock_contention_failure_count": 0 if durable_transaction else None,
            "measurement_envelope_ns": None,
            "throughput_operations_per_second": None,
            "transcript_sequence_set_valid": False,
            "operations": [],
            "latency_summary": None,
            "setup_or_measurement_error": {
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }
        self_cpu_after = time.process_time_ns()
    finally:
        if prepared is not None:
            try:
                prepared.close()
            except BaseException as exc:
                cleanup_error = {
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
                measured["status"] = "failed"
    if capture_operations and len(measured.get("operations", [])) != operation_count:
        error = measured.get("setup_or_measurement_error") or cleanup_error or {}
        measured["operations"] = _synthetic_failure_operations(
            operation_count,
            error_type=str(error.get("error_type", "IncompleteMeasurement")),
            error_message=str(
                error.get("error_message", "worker did not emit a complete operation denominator")
            ),
        )
        measured["completed_operations"] = 0
        measured["failed_operations"] = operation_count
        if condition in ("durable_direct", "singleton_ipc"):
            measured["failed_transaction_count"] = operation_count
            measured["failed_transaction_rate"] = 1.0
            measured["lock_contention_failure_count"] = 0
        else:
            measured["failed_transaction_count"] = None
            measured["failed_transaction_rate"] = None
            measured["lock_contention_failure_count"] = None
        measured["status"] = "failed"
    self_memory_after = _process_memory(os.getpid())
    worker_cpu_ns = self_cpu_after - self_cpu_before
    monitor_cpu_ns = (
        None
        if monitor_cpu_before is None or monitor_cpu_after is None
        else monitor_cpu_after - monitor_cpu_before
    )
    combined_cpu_ns = (
        None
        if condition == "singleton_ipc" and monitor_cpu_ns is None
        else worker_cpu_ns + (0 if monitor_cpu_ns is None else monitor_cpu_ns)
    )
    envelope = measured.get("measurement_envelope_ns")
    measured.update(
        {
            "worker_process_cpu_ns": worker_cpu_ns,
            "monitor_process_cpu_ns": monitor_cpu_ns,
            "combined_cpu_ns": combined_cpu_ns,
            "combined_cpu_core_equivalent_percent": (
                int(combined_cpu_ns) / int(envelope) * 100.0
                if type(combined_cpu_ns) is int
                and type(envelope) is int
                and envelope > 0
                else None
            ),
            "worker_memory_before": self_memory_before,
            "worker_memory_after": self_memory_after,
            "worker_process_lifetime_peak_rss_bytes": resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss
            * 1024,
            "monitor_memory_after": monitor_memory_after,
            "sqlite_growth": (
                _sqlite_growth(database_before, database_after)
                if database_before is not None and database_after is not None
                else None
            ),
            "cleanup_error": cleanup_error,
            "timing_scope": _TIMING_SCOPE,
            "memory_scope": _MEMORY_SCOPE,
        }
    )
    return measured


_OPERATION_FIELDS = frozenset(
    {
        "operation_index",
        "worker_slot",
        "status",
        "start_offset_ns",
        "latency_ns",
        "value_code",
        "transcript_sequence",
        "error_type",
        "error_message",
    }
)
_MEASURED_FIELDS = frozenset(
    {
        "status",
        "expected_operations",
        "completed_operations",
        "failed_operations",
        "failed_transaction_count",
        "failed_transaction_rate",
        "lock_contention_failure_count",
        "measurement_envelope_ns",
        "throughput_operations_per_second",
        "transcript_sequence_set_valid",
        "operations",
        "latency_summary",
        "setup_or_measurement_error",
        "worker_process_cpu_ns",
        "monitor_process_cpu_ns",
        "combined_cpu_ns",
        "combined_cpu_core_equivalent_percent",
        "worker_memory_before",
        "worker_memory_after",
        "worker_process_lifetime_peak_rss_bytes",
        "monitor_memory_after",
        "sqlite_growth",
        "cleanup_error",
        "timing_scope",
        "memory_scope",
    }
)
_WORKER_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "phase",
        "spec",
        "warmup",
        "measured",
        "worker_error",
        "integrity",
    }
)
_INTEGRITY_FIELDS = frozenset(
    {
        "component_sha256",
        "worker_source_sha256",
        "storage_identity",
        "source_commit",
        "source_dirty",
        "matches_expected",
    }
)

_ERROR_FIELDS = frozenset({"error_type", "error_message"})
_TRACEBACK_ERROR_FIELDS = frozenset({"error_type", "error_message", "traceback"})
_MEMORY_FIELDS = frozenset({"vm_rss_bytes", "vm_hwm_bytes"})
_LATENCY_FIELDS = frozenset(
    {
        "n_operations",
        "median_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "p99_9_ms",
        "p99_9_support",
        "minimum_ms",
        "maximum_ms",
        "percentile_method",
    }
)
_P999_SUPPORT_FIELDS = frozenset(
    {"supported", "minimum_operations", "observed_operations"}
)
_SQLITE_SNAPSHOT_FIELDS = frozenset(
    {
        "file_bytes",
        "family_bytes",
        "page_size",
        "page_count",
        "allocated_page_bytes",
        "freelist_count",
        "journal_mode",
        "synchronous_numeric",
        "row_counts",
        "audit_logical_payload_bytes",
    }
)
_SQLITE_ROW_FIELDS = frozenset(
    {"attempts", "audit_log", "used_credentials", "sluice_monitor_request_cache"}
)
_SQLITE_GROWTH_FIELDS = frozenset(
    {
        "before",
        "after",
        "family_bytes_growth",
        "allocated_page_bytes_growth",
        "row_growth",
        "audit_logical_payload_bytes_growth",
        "audit_byte_scope",
    }
)


def _validate_error_record(
    value: object,
    *,
    field: str,
    traceback_required: bool,
) -> dict[str, str]:
    expected = _TRACEBACK_ERROR_FIELDS if traceback_required else _ERROR_FIELDS
    if type(value) is not dict or frozenset(value) != expected:
        raise ValueError(f"{field} has an invalid exact error schema")
    if type(value["error_type"]) is not str or not value["error_type"]:
        raise ValueError(f"{field} error_type must be a nonempty string")
    if type(value["error_message"]) is not str:
        raise ValueError(f"{field} error_message must be an exact string")
    if traceback_required and type(value["traceback"]) is not str:
        raise ValueError(f"{field} traceback must be an exact string")
    return value


def _validate_memory_snapshot(value: object, *, field: str) -> dict[str, int | None]:
    if type(value) is not dict or frozenset(value) != _MEMORY_FIELDS:
        raise ValueError(f"{field} has an invalid exact memory schema")
    for name in sorted(_MEMORY_FIELDS):
        item = value[name]
        if item is not None and not _is_bounded_nonnegative_int(item):
            raise ValueError(f"{field}.{name} must be a bounded nonnegative integer or null")
    return value


def _validate_latency_summary(value: object, *, completed: int) -> dict[str, Any] | None:
    if completed == 0:
        if value is not None:
            raise ValueError("zero-success result must not contain a latency summary")
        return None
    if type(value) is not dict or frozenset(value) != _LATENCY_FIELDS:
        raise ValueError("latency summary has a missing or unexpected field")
    if not _is_bounded_nonnegative_int(value["n_operations"]) or value[
        "n_operations"
    ] != completed:
        raise ValueError("latency summary operation count is invalid")
    if value["percentile_method"] != PERCENTILE_METHOD:
        raise ValueError("latency percentile method is invalid")
    for field in (
        "median_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "minimum_ms",
        "maximum_ms",
    ):
        if not _is_finite_nonnegative_number(value[field]):
            raise ValueError(f"latency summary {field} is invalid")
    ordered = (
        value["minimum_ms"],
        value["p50_ms"],
        value["p95_ms"],
        value["p99_ms"],
        value["maximum_ms"],
    )
    if any(left > right for left, right in zip(ordered, ordered[1:])):
        raise ValueError("latency percentiles are not monotonic")
    if not value["minimum_ms"] <= value["median_ms"] <= value["maximum_ms"]:
        raise ValueError("latency median is outside the observed range")
    support = value["p99_9_support"]
    if type(support) is not dict or frozenset(support) != _P999_SUPPORT_FIELDS:
        raise ValueError("p99.9 support record is not exact")
    if type(support["supported"]) is not bool:
        raise ValueError("p99.9 support verdict must be an exact boolean")
    if (
        not _is_bounded_nonnegative_int(support["minimum_operations"])
        or support["minimum_operations"] != MIN_P999_OPERATIONS
        or not _is_bounded_nonnegative_int(support["observed_operations"])
        or support["observed_operations"] != completed
    ):
        raise ValueError("p99.9 support counts are invalid")
    should_support = completed >= MIN_P999_OPERATIONS
    if support["supported"] is not should_support:
        raise ValueError("p99.9 support verdict disagrees with the sample count")
    if should_support:
        if not _is_finite_nonnegative_number(value["p99_9_ms"]):
            raise ValueError("supported p99.9 value is invalid")
        if not value["p99_ms"] <= value["p99_9_ms"] <= value["maximum_ms"]:
            raise ValueError("p99.9 is outside the observed range")
    elif value["p99_9_ms"] is not None:
        raise ValueError("unsupported p99.9 value must be null")
    return value


def _validate_sqlite_snapshot(value: object, *, field: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != _SQLITE_SNAPSHOT_FIELDS:
        raise ValueError(f"{field} has an invalid exact SQLite schema")
    file_bytes = value["file_bytes"]
    if (
        type(file_bytes) is not dict
        or "main" not in file_bytes
        or not frozenset(file_bytes).issubset({"main", "-wal", "-shm"})
        or any(not _is_bounded_nonnegative_int(item) for item in file_bytes.values())
    ):
        raise ValueError(f"{field}.file_bytes is invalid")
    integer_fields = (
        "family_bytes",
        "page_size",
        "page_count",
        "allocated_page_bytes",
        "freelist_count",
        "synchronous_numeric",
    )
    if any(not _is_bounded_nonnegative_int(value[name]) for name in integer_fields):
        raise ValueError(f"{field} contains an invalid bounded integer")
    if value["page_size"] <= 0:
        raise ValueError(f"{field}.page_size must be positive")
    if value["family_bytes"] != sum(file_bytes.values()):
        raise ValueError(f"{field}.family_bytes disagrees with the file family")
    if value["allocated_page_bytes"] != value["page_size"] * value["page_count"]:
        raise ValueError(f"{field}.allocated_page_bytes is inconsistent")
    if type(value["journal_mode"]) is not str or not value["journal_mode"]:
        raise ValueError(f"{field}.journal_mode is invalid")
    row_counts = value["row_counts"]
    if type(row_counts) is not dict or frozenset(row_counts) != _SQLITE_ROW_FIELDS:
        raise ValueError(f"{field}.row_counts is not exact")
    if any(
        item is not None and not _is_bounded_nonnegative_int(item)
        for item in row_counts.values()
    ):
        raise ValueError(f"{field}.row_counts contains an invalid count")
    audit_bytes = value["audit_logical_payload_bytes"]
    if audit_bytes is not None and not _is_bounded_nonnegative_int(audit_bytes):
        raise ValueError(f"{field}.audit_logical_payload_bytes is invalid")
    return value


def _validate_sqlite_growth(value: object) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != _SQLITE_GROWTH_FIELDS:
        raise ValueError("sqlite_growth has a missing or unexpected field")
    before = _validate_sqlite_snapshot(value["before"], field="sqlite_growth.before")
    after = _validate_sqlite_snapshot(value["after"], field="sqlite_growth.after")
    for name in ("family_bytes_growth", "allocated_page_bytes_growth"):
        if not _is_bounded_nonnegative_int(value[name]):
            raise ValueError(f"sqlite_growth.{name} must be nonnegative")
    if value["family_bytes_growth"] != after["family_bytes"] - before["family_bytes"]:
        raise ValueError("sqlite family growth disagrees with before/after")
    if (
        value["allocated_page_bytes_growth"]
        != after["allocated_page_bytes"] - before["allocated_page_bytes"]
    ):
        raise ValueError("SQLite allocated growth disagrees with before/after")
    row_growth = value["row_growth"]
    if type(row_growth) is not dict or frozenset(row_growth) != _SQLITE_ROW_FIELDS:
        raise ValueError("sqlite_growth.row_growth is not exact")
    for table in sorted(_SQLITE_ROW_FIELDS):
        before_count = before["row_counts"][table]
        after_count = after["row_counts"][table]
        expected = (
            None
            if before_count is None or after_count is None
            else after_count - before_count
        )
        if not _exact_json_equal(row_growth[table], expected):
            raise ValueError(f"SQLite row growth for {table} is inconsistent")
        if expected is not None and not _is_bounded_nonnegative_int(expected):
            raise ValueError(f"SQLite row growth for {table} is negative or too large")
    before_audit = before["audit_logical_payload_bytes"]
    after_audit = after["audit_logical_payload_bytes"]
    expected_audit = (
        None
        if before_audit is None or after_audit is None
        else after_audit - before_audit
    )
    if not _exact_json_equal(value["audit_logical_payload_bytes_growth"], expected_audit):
        raise ValueError("SQLite audit logical growth is inconsistent")
    if expected_audit is not None and not _is_bounded_nonnegative_int(expected_audit):
        raise ValueError("SQLite audit logical growth is negative or too large")
    if type(value["audit_byte_scope"]) is not str or not value["audit_byte_scope"]:
        raise ValueError("SQLite audit byte scope is invalid")
    return value


def _validate_worker_spec(value: object) -> dict[str, Any]:
    fields = frozenset(
        {
            "schema_version",
            "run_id",
            "block_id",
            "condition",
            "storage_label",
            "storage_class",
            "storage_root",
            "repetition",
            "concurrency",
            "operations",
            "warmup_operations",
            "expected_component_sha256",
            "expected_source_commit",
            "expected_source_dirty",
            "source_repository_root",
            "worker_source_root",
            "expected_worker_source_sha256",
            "expected_storage_identity",
        }
    )
    if type(value) is not dict or frozenset(value) != fields:
        raise ValueError("worker spec has missing or unexpected fields")
    if value["schema_version"] != WORKER_SPEC_SCHEMA:
        raise ValueError("worker spec schema is unsupported")
    for field in ("run_id", "block_id", "storage_label"):
        if type(value[field]) is not str or _LABEL.fullmatch(value[field]) is None:
            raise ValueError(f"worker spec {field} is invalid")
    if type(value["condition"]) is not str or value["condition"] not in CONDITIONS:
        raise ValueError("worker condition is unsupported")
    if (
        type(value["storage_class"]) is not str
        or value["storage_class"] not in STORAGE_CLASSES
    ):
        raise ValueError("worker storage class is unsupported")
    if not _is_bounded_nonnegative_int(value["repetition"]):
        raise ValueError("worker spec repetition is invalid")
    _positive_int("worker spec concurrency", value["concurrency"])
    _positive_int("worker spec operations", value["operations"])
    if not _is_bounded_nonnegative_int(value["warmup_operations"]):
        raise ValueError("worker spec warmup_operations is invalid")
    if value["concurrency"] > value["operations"]:
        raise ValueError("worker concurrency exceeds measured operations")
    if value["warmup_operations"] and value["concurrency"] > value["warmup_operations"]:
        raise ValueError("worker concurrency exceeds warm-up operations")
    hashes = value["expected_component_sha256"]
    if type(hashes) is not dict or frozenset(hashes) != frozenset(COMPONENT_PATHS):
        raise ValueError("worker component hash manifest is not exact")
    if any(
        type(item) is not str or _SHA256.fullmatch(item) is None
        for item in hashes.values()
    ):
        raise ValueError("worker component hashes must be complete SHA-256 values")
    if (
        type(value["expected_source_commit"]) is not str
        or _GIT_COMMIT.fullmatch(value["expected_source_commit"]) is None
    ):
        raise ValueError("worker source commit must be a nonempty string")
    if type(value["expected_source_dirty"]) is not bool:
        raise ValueError("worker source dirty state must be a boolean")
    for field in ("source_repository_root", "worker_source_root"):
        if (
            type(value[field]) is not str
            or not value[field]
            or not Path(value[field]).is_absolute()
        ):
            raise ValueError(f"worker {field} must be a nonempty string")
    if (
        type(value["storage_root"]) is not str
        or not value["storage_root"]
        or not Path(value["storage_root"]).is_absolute()
    ):
        raise ValueError("worker storage_root must be an absolute path")
    worker_hashes = value["expected_worker_source_sha256"]
    if type(worker_hashes) is not dict or worker_hashes != hashes:
        raise ValueError("worker snapshot hashes must exactly match component pins")
    _validate_storage_identity(
        value["expected_storage_identity"],
        value["expected_storage_identity"],
    )
    return value


def _validate_operation_records(
    value: object,
    *,
    operation_count: int,
    condition: str,
    concurrency: int | None = None,
) -> list[dict[str, Any]]:
    _positive_int("operation_count", operation_count)
    if type(condition) is not str or condition not in CONDITIONS:
        raise ValueError("operation condition is unsupported")
    if concurrency is not None:
        _positive_int("concurrency", concurrency)
        if concurrency > operation_count:
            raise ValueError("operation concurrency exceeds the denominator")
    if type(value) is not list or len(value) != operation_count:
        raise ValueError("operation rows do not match the exact scheduled denominator")
    rows: list[dict[str, Any]] = []
    for row in value:
        if type(row) is not dict or frozenset(row) != _OPERATION_FIELDS:
            raise ValueError("operation row has missing or unexpected fields")
        if not _is_exact_int(row["operation_index"]) or not 0 <= row["operation_index"] < operation_count:
            raise ValueError("operation index is invalid")
        if (
            not _is_exact_int(row["worker_slot"])
            or row["worker_slot"] < -1
            or row["worker_slot"] > MAX_AUDIT_INTEGER
        ):
            raise ValueError("operation worker slot is invalid")
        if concurrency is not None and row["worker_slot"] >= concurrency:
            raise ValueError("operation worker slot exceeds declared concurrency")
        if (
            concurrency is not None
            and row["worker_slot"] >= 0
            and row["worker_slot"] != row["operation_index"] % concurrency
        ):
            raise ValueError("operation worker slot disagrees with deterministic assignment")
        if type(row["status"]) is not str or row["status"] not in ("ok", "failed"):
            raise ValueError("operation status is invalid")
        for field in ("start_offset_ns", "latency_ns"):
            if row[field] is not None and not _is_bounded_nonnegative_int(row[field]):
                raise ValueError(f"operation {field} is invalid")
        if row["status"] == "ok":
            if row["worker_slot"] < 0:
                raise ValueError("successful operation lacks a real worker slot")
            if row["start_offset_ns"] is None or row["latency_ns"] is None:
                raise ValueError("successful operation lacks timing")
            if type(row["value_code"]) is not int or row["value_code"] != HANDLER_VALUE_CODE:
                raise ValueError("successful operation has the wrong value code")
            if condition == "unmediated_handler":
                if row["transcript_sequence"] is not None:
                    raise ValueError("unmediated operation has a transcript sequence")
            elif not _is_exact_int(row["transcript_sequence"]) or row["transcript_sequence"] <= 0:
                raise ValueError("mediated operation lacks a valid sequence")
            if row["error_type"] is not None or row["error_message"] is not None:
                raise ValueError("successful operation contains an error")
        else:
            if row["value_code"] is not None or row["transcript_sequence"] is not None:
                raise ValueError("failed operation contains a result")
            if (
                type(row["error_type"]) is not str
                or not row["error_type"]
                or type(row["error_message"]) is not str
            ):
                raise ValueError("failed operation lacks an exact error record")
        rows.append(row)
    if sorted(row["operation_index"] for row in rows) != list(range(operation_count)):
        raise ValueError("operation indices are duplicated or incomplete")
    for row in rows:
        if (
            type(row["start_offset_ns"]) is int
            and type(row["latency_ns"]) is int
            and row["start_offset_ns"] + row["latency_ns"] > MAX_AUDIT_INTEGER
        ):
            raise ValueError("operation finish timestamp exceeds the bounded schema")
    return rows


def _derive_raw_metrics(rows: Sequence[Mapping[str, Any]], condition: str) -> dict[str, Any]:
    if not rows or condition not in CONDITIONS:
        raise ValueError("raw metric derivation requires rows and a known condition")
    successful = [row for row in rows if row["status"] == "ok"]
    failed = [row for row in rows if row["status"] == "failed"]
    starts = [int(row["start_offset_ns"]) for row in rows if type(row["start_offset_ns"]) is int]
    finishes = [
        int(row["start_offset_ns"]) + int(row["latency_ns"])
        for row in rows
        if type(row["start_offset_ns"]) is int and type(row["latency_ns"]) is int
    ]
    envelope = max(finishes) - min(starts) if starts and finishes else 0
    if not _is_bounded_nonnegative_int(envelope):
        raise ValueError("raw operation envelope exceeds the bounded schema")
    sequences = [
        int(row["transcript_sequence"])
        for row in successful
        if type(row["transcript_sequence"]) is int
    ]
    sequence_valid = (
        not failed
        if condition == "unmediated_handler"
        else sorted(sequences) == list(range(1, len(rows) + 1))
    )
    busy = sum(
        "locked" in str(row["error_message"]).lower()
        or "busy" in str(row["error_message"]).lower()
        for row in failed
    )
    durable = condition in ("durable_direct", "singleton_ipc")
    return {
        "status": "ok" if not failed and sequence_valid else "failed",
        "expected_operations": len(rows),
        "completed_operations": len(successful),
        "failed_operations": len(failed),
        "failed_transaction_count": len(failed) if durable else None,
        "failed_transaction_rate": len(failed) / len(rows) if durable else None,
        "lock_contention_failure_count": busy if durable else None,
        "measurement_envelope_ns": envelope,
        "throughput_operations_per_second": (
            len(rows) / (envelope / 1_000_000_000.0) if envelope > 0 else None
        ),
        "transcript_sequence_set_valid": sequence_valid,
        "latency_summary": (
            summarize_latencies([int(row["latency_ns"]) for row in successful])
            if successful
            else None
        ),
    }


def _validate_measured(
    value: object,
    *,
    operation_count: int,
    condition: str,
    capture_operations: bool,
    concurrency: int | None = None,
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != _MEASURED_FIELDS:
        raise ValueError("measured result has missing or unexpected fields")
    _positive_int("measured operation_count", operation_count)
    if condition not in CONDITIONS:
        raise ValueError("measured condition is unsupported")
    if concurrency is not None:
        _positive_int("measured concurrency", concurrency)
    if type(value["status"]) is not str or value["status"] not in ("ok", "failed"):
        raise ValueError("measured status is invalid")
    if (
        not _is_bounded_nonnegative_int(value["expected_operations"])
        or value["expected_operations"] != operation_count
    ):
        raise ValueError("measured expected operation count is invalid")
    for field in ("completed_operations", "failed_operations"):
        if not _is_bounded_nonnegative_int(value[field]):
            raise ValueError(f"measured {field} is invalid")
    if value["completed_operations"] + value["failed_operations"] != operation_count:
        raise ValueError("measured operation counts do not equal the denominator")
    durable = condition in ("durable_direct", "singleton_ipc")
    if durable:
        if (
            not _is_bounded_nonnegative_int(value["failed_transaction_count"])
            or value["failed_transaction_count"] != value["failed_operations"]
            or not _is_finite_nonnegative_number(value["failed_transaction_rate"])
            or value["failed_transaction_rate"] > 1.0
            or value["failed_transaction_rate"]
            != value["failed_operations"] / operation_count
            or not _is_bounded_nonnegative_int(value["lock_contention_failure_count"])
            or value["lock_contention_failure_count"] > value["failed_operations"]
        ):
            raise ValueError("durable transaction failure metrics are invalid")
    elif any(
        value[field] is not None
        for field in (
            "failed_transaction_count",
            "failed_transaction_rate",
            "lock_contention_failure_count",
        )
    ):
        raise ValueError("non-durable result contains transaction failure metrics")
    envelope = value["measurement_envelope_ns"]
    if envelope is not None and not _is_bounded_nonnegative_int(envelope):
        raise ValueError("measurement envelope is invalid")
    throughput = value["throughput_operations_per_second"]
    if throughput is not None and not _is_finite_nonnegative_number(throughput):
        raise ValueError("throughput is invalid")
    if type(value["transcript_sequence_set_valid"]) is not bool:
        raise ValueError("transcript sequence verdict must be an exact boolean")
    rows = (
        _validate_operation_records(
            value["operations"],
            operation_count=operation_count,
            condition=condition,
            concurrency=concurrency,
        )
        if capture_operations
        else []
    )
    if not capture_operations and value["operations"] != []:
        raise ValueError("warm-up result leaked operation samples")
    if capture_operations:
        derived = _derive_raw_metrics(rows, condition)
        for field, expected in derived.items():
            if field == "status":
                continue
            if not _exact_json_equal(value.get(field), expected):
                raise ValueError(f"worker aggregate {field} disagrees with retained raw operations")
        if value["status"] == "ok" and derived["status"] != "ok":
            raise ValueError("successful worker has failed raw operations")
        if (
            value["status"] == "failed"
            and derived["status"] == "ok"
            and value.get("cleanup_error") is None
        ):
            raise ValueError("failed worker has no raw or cleanup failure")
    if not capture_operations:
        expected_status = (
            "ok"
            if value["failed_operations"] == 0
            and value["transcript_sequence_set_valid"] is True
            else "failed"
        )
        if value["status"] != expected_status:
            raise ValueError("warm-up status is inconsistent")
        if envelope is not None and envelope > 0:
            expected_throughput = operation_count / (envelope / 1_000_000_000.0)
            if not _exact_json_equal(throughput, expected_throughput):
                raise ValueError("warm-up throughput disagrees with its envelope")
        elif throughput is not None:
            raise ValueError("zero/unknown warm-up envelope must have null throughput")
    _validate_latency_summary(
        value["latency_summary"], completed=value["completed_operations"]
    )
    setup_error = value["setup_or_measurement_error"]
    cleanup_error = value["cleanup_error"]
    if setup_error is not None:
        _validate_error_record(
            setup_error,
            field="setup_or_measurement_error",
            traceback_required=True,
        )
    if cleanup_error is not None:
        _validate_error_record(
            cleanup_error,
            field="cleanup_error",
            traceback_required=False,
        )
    if value["status"] == "ok" and (setup_error is not None or cleanup_error is not None):
        raise ValueError("successful result contains a setup or cleanup error")
    if value["status"] == "ok" and value["failed_operations"] != 0:
        raise ValueError("successful result contains failed operations")
    worker_cpu = value["worker_process_cpu_ns"]
    if not _is_bounded_nonnegative_int(worker_cpu):
        raise ValueError("worker CPU must be a bounded nonnegative exact integer")
    monitor_cpu = value["monitor_process_cpu_ns"]
    if monitor_cpu is not None and not _is_bounded_nonnegative_int(monitor_cpu):
        raise ValueError("monitor CPU must be a bounded nonnegative exact integer or null")
    if condition != "singleton_ipc" and monitor_cpu is not None:
        raise ValueError("non-singleton result contains monitor CPU")
    combined_cpu = value["combined_cpu_ns"]
    expected_combined = (
        None
        if condition == "singleton_ipc" and monitor_cpu is None
        else worker_cpu + (0 if monitor_cpu is None else monitor_cpu)
    )
    if not _exact_json_equal(combined_cpu, expected_combined):
        raise ValueError("combined CPU disagrees with worker/monitor CPU")
    if combined_cpu is not None and not _is_bounded_nonnegative_int(combined_cpu):
        raise ValueError("combined CPU is outside the bounded integer schema")
    expected_core_percent = (
        combined_cpu / envelope * 100.0
        if type(combined_cpu) is int and type(envelope) is int and envelope > 0
        else None
    )
    if not _exact_json_equal(
        value["combined_cpu_core_equivalent_percent"], expected_core_percent
    ):
        raise ValueError("combined CPU percent disagrees with CPU/envelope")
    if expected_core_percent is not None and not _is_finite_nonnegative_number(
        expected_core_percent
    ):
        raise ValueError("combined CPU percent is invalid")
    _validate_memory_snapshot(value["worker_memory_before"], field="worker_memory_before")
    _validate_memory_snapshot(value["worker_memory_after"], field="worker_memory_after")
    if not _is_bounded_nonnegative_int(value["worker_process_lifetime_peak_rss_bytes"]):
        raise ValueError(
            "worker memory peak RSS must be a bounded nonnegative exact integer"
        )
    monitor_memory = value["monitor_memory_after"]
    if monitor_memory is not None:
        _validate_memory_snapshot(monitor_memory, field="monitor_memory_after")
    if condition != "singleton_ipc" and monitor_memory is not None:
        raise ValueError("non-singleton result contains monitor memory")
    sqlite_growth = value["sqlite_growth"]
    if sqlite_growth is not None:
        _validate_sqlite_growth(sqlite_growth)
    if condition not in ("durable_direct", "singleton_ipc") and sqlite_growth is not None:
        raise ValueError("non-durable result contains SQLite growth")
    if value["status"] == "ok" and durable and sqlite_growth is None:
        raise ValueError("successful durable result lacks SQLite growth")
    if value["timing_scope"] != _TIMING_SCOPE or type(value["timing_scope"]) is not str:
        raise ValueError("timing scope is not the frozen exact value")
    if value["memory_scope"] != _MEMORY_SCOPE or type(value["memory_scope"]) is not str:
        raise ValueError("memory scope is not the frozen exact value")
    return value


def _integrity_snapshot(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute child-visible bytes/storage without launching external code.

    Commit and dirty state are parent-pinned metadata here.  The controller
    obtains them from native Git at run start/end and gates final eligibility;
    invoking Git or vendored Python from each child would itself introduce
    code outside the captured worker-source set before integrity acceptance.
    """

    repository_root = Path(str(spec["source_repository_root"]))
    worker_source_root = Path(str(spec["worker_source_root"]))
    components = _component_hashes(repository_root)
    worker_components = _snapshot_component_hashes(worker_source_root)
    storage_identity = _observe_storage_identity(Path(str(spec["storage_root"])))
    matches = (
        components == spec["expected_component_sha256"]
        and worker_components == spec["expected_worker_source_sha256"]
        and storage_identity == spec["expected_storage_identity"]
    )
    return {
        "component_sha256": components,
        "worker_source_sha256": worker_components,
        "storage_identity": storage_identity,
        "source_commit": spec["expected_source_commit"],
        "source_dirty": spec["expected_source_dirty"],
        "matches_expected": matches,
    }


def _validate_integrity(
    value: object,
    expected_spec: Mapping[str, Any],
    *,
    parent_observed: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != _INTEGRITY_FIELDS:
        raise ValueError("worker integrity record is not exact")
    if type(value["component_sha256"]) is not dict or type(
        value["worker_source_sha256"]
    ) is not dict:
        raise ValueError("worker integrity component manifest is invalid")
    if type(value["source_commit"]) is not str or not value["source_commit"]:
        raise ValueError("worker integrity source commit is invalid")
    if type(value["source_dirty"]) is not bool:
        raise ValueError("worker integrity source dirty flag is invalid")
    if type(value["matches_expected"]) is not bool:
        raise ValueError("worker integrity verdict is invalid")
    _validate_storage_identity(
        value["storage_identity"],
        expected_spec["expected_storage_identity"],
    )
    computed_match = (
        value["component_sha256"] == expected_spec["expected_component_sha256"]
        and value["worker_source_sha256"]
        == expected_spec["expected_worker_source_sha256"]
        and value["source_commit"] == expected_spec["expected_source_commit"]
        and value["source_dirty"] is expected_spec["expected_source_dirty"]
    )
    if value["matches_expected"] is not computed_match or not computed_match:
        raise ValueError("worker integrity fields do not exactly match the parent pins")
    if parent_observed is not None:
        if type(parent_observed) is not dict or frozenset(parent_observed) != _INTEGRITY_FIELDS:
            raise ValueError("parent integrity recomputation is not exact")
        _validate_storage_identity(
            parent_observed["storage_identity"],
            expected_spec["expected_storage_identity"],
        )
        if (
            parent_observed["component_sha256"]
            != expected_spec["expected_component_sha256"]
            or parent_observed["worker_source_sha256"]
            != expected_spec["expected_worker_source_sha256"]
            or parent_observed["source_commit"]
            != expected_spec["expected_source_commit"]
            or type(parent_observed["source_dirty"]) is not bool
            or parent_observed["source_dirty"]
            is not expected_spec["expected_source_dirty"]
        ):
            raise ValueError("parent integrity recomputation disagrees with the pins")
    return value


def _validate_worker_result(value: object, expected_spec: Mapping[str, Any]) -> dict[str, Any]:
    _validate_worker_spec(dict(expected_spec))
    if type(value) is not dict or frozenset(value) != _WORKER_RESULT_FIELDS:
        raise ValueError("worker result has missing or unexpected fields")
    if value["schema_version"] != WORKER_RESULT_SCHEMA:
        raise ValueError("worker result schema is unsupported")
    _validate_worker_spec(value["spec"])
    if not _exact_json_equal(value["spec"], expected_spec):
        raise ValueError("worker result is not bound to its exact spec")
    if type(value["status"]) is not str or value["status"] not in ("ok", "failed"):
        raise ValueError("worker result status is invalid")
    if type(value["phase"]) is not str or value["phase"] not in _WORKER_PHASES:
        raise ValueError("worker result phase is invalid")
    worker_error = value["worker_error"]
    if worker_error is not None:
        _validate_error_record(
            worker_error, field="worker_error", traceback_required=True
        )
    integrity = value["integrity"]
    if type(integrity) is not dict or frozenset(integrity) != frozenset({"start", "end"}):
        raise ValueError("worker integrity envelope is invalid")
    parent_observed = _integrity_snapshot(expected_spec)
    start = _validate_integrity(
        integrity["start"], expected_spec, parent_observed=parent_observed
    )
    end = _validate_integrity(
        integrity["end"], expected_spec, parent_observed=parent_observed
    )
    warmup = value["warmup"]
    expected_warmup = int(expected_spec["warmup_operations"])
    if warmup is not None:
        _validate_measured(
            warmup,
            operation_count=expected_warmup,
            condition=str(expected_spec["condition"]),
            capture_operations=False,
            concurrency=int(expected_spec["concurrency"]),
        )
    if expected_warmup == 0 and warmup is not None:
        raise ValueError("worker emitted warm-up data when warm-up was disabled")
    measured = value["measured"]
    if measured is not None:
        _validate_measured(
            measured,
            operation_count=int(expected_spec["operations"]),
            condition=str(expected_spec["condition"]),
            capture_operations=True,
            concurrency=int(expected_spec["concurrency"]),
        )
        if value["status"] != measured["status"]:
            raise ValueError("worker and measured statuses disagree")
    elif value["status"] == "ok":
        raise ValueError("successful worker has no measured result")
    if value["status"] == "ok" and worker_error is not None:
        raise ValueError("successful worker contains an error")
    if value["status"] == "ok" and value["phase"] != "measured":
        raise ValueError("successful worker did not finish the measured phase")
    if expected_warmup > 0 and measured is not None and warmup is None:
        raise ValueError("worker measured without the required warm-up")
    if measured is not None and value["phase"] != "measured":
        raise ValueError("worker result phase disagrees with measured output")
    if value["phase"] == "warmup" and measured is not None:
        raise ValueError("warm-up phase contains measured output")
    if (
        value["status"] == "failed"
        and measured is None
        and worker_error is None
        and not (
            value["phase"] == "warmup"
            and type(warmup) is dict
            and warmup.get("status") == "failed"
        )
    ):
        raise ValueError("failed worker status/phase lacks an exact failure cause")
    if type(warmup) is dict and warmup["status"] == "failed" and measured is not None:
        raise ValueError("worker measured after a failed warm-up")
    if value["phase"] == "worker" and (warmup is not None or measured is not None):
        raise ValueError("worker-phase failure contains later-phase results")
    return value


def _isolated_worker_environment() -> dict[str, str]:
    """Return a finite environment with no Python/user-site or loader injection."""

    return {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }


def _require_isolated_worker_runtime() -> None:
    flags = sys.flags
    if not (
        flags.isolated == 1
        and flags.ignore_environment == 1
        and flags.no_user_site == 1
        and flags.dont_write_bytecode == 1
    ):
        raise RuntimeError("G8 worker requires Python -I -B isolated mode")
    forbidden = sorted(
        key
        for key in os.environ
        if key.upper().startswith("PYTHON")
        or key.upper().startswith("LD_")
        or key.upper().startswith("DYLD_")
    )
    if forbidden:
        raise RuntimeError(f"G8 worker environment contains forbidden keys: {forbidden}")


def worker_main(spec_path: Path, output_path: Path) -> int:
    spec: dict[str, Any] | None = None
    warmup: dict[str, Any] | None = None
    measured: dict[str, Any] | None = None
    worker_error: dict[str, str] | None = None
    phase = "worker"
    integrity: dict[str, Any] = {"start": None, "end": None}
    status = "failed"
    try:
        _require_isolated_worker_runtime()
        spec = _validate_worker_spec(json.loads(spec_path.read_text(encoding="ascii")))
        integrity["start"] = _integrity_snapshot(spec)
        if not integrity["start"]["matches_expected"]:
            raise RuntimeError("worker source/components do not match the parent pins")
        if spec["warmup_operations"]:
            phase = "warmup"
            warmup = execute_condition_once(
                condition=spec["condition"],
                operation_count=spec["warmup_operations"],
                concurrency=spec["concurrency"],
                storage_root=Path(spec["storage_root"]),
                capture_operations=False,
            )
        if warmup is None or warmup["status"] == "ok":
            phase = "measured"
            measured = execute_condition_once(
                condition=spec["condition"],
                operation_count=spec["operations"],
                concurrency=spec["concurrency"],
                storage_root=Path(spec["storage_root"]),
                capture_operations=True,
            )
            status = measured["status"]
        integrity["end"] = _integrity_snapshot(spec)
        if not integrity["end"]["matches_expected"]:
            raise RuntimeError("worker source/components changed during execution")
    except BaseException as exc:
        status = "failed"
        worker_error = {
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "traceback": traceback.format_exc(),
        }
        if spec is not None:
            if integrity["start"] is None:
                integrity["start"] = _integrity_snapshot(spec)
            if integrity["end"] is None:
                integrity["end"] = _integrity_snapshot(spec)
    result = {
        "schema_version": WORKER_RESULT_SCHEMA,
        "status": status,
        "phase": phase,
        "spec": spec,
        "warmup": warmup,
        "measured": measured,
        "worker_error": worker_error,
        "integrity": integrity,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(output_path, result)
    return 0 if result["status"] == "ok" else 3


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="ascii") as stream:
        for row in rows:
            stream.write(_canonical_json(row) + "\n")


_RAW_OPERATION_CONTEXT_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "worker_id",
        "block_id",
        "condition",
        "storage_label",
        "storage_class",
        "repetition",
        "concurrency",
        "event_kind",
        "outcome_code",
    }
)
_RAW_OPERATION_FIELDS = _OPERATION_FIELDS | _RAW_OPERATION_CONTEXT_FIELDS
_REPETITION_PHASES = _WORKER_PHASES | frozenset({"timeout", "parent_validation"})
_REPETITION_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "worker_id",
        "block_id",
        "block_order",
        "repetition",
        "storage_label",
        "storage_class",
        "concurrency",
        "condition",
        "condition_order",
        "status",
        "phase",
        "required_metrics_complete",
        "claim_eligible",
        "expected_operations",
        "completed_operations",
        "failed_operations",
        "median_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "p99_9_ms",
        "p99_9_support",
        "throughput_operations_per_second",
        "worker_process_cpu_ns",
        "monitor_process_cpu_ns",
        "combined_cpu_ns",
        "combined_cpu_core_equivalent_percent",
        "worker_process_lifetime_peak_rss_bytes",
        "monitor_memory_after",
        "monitor_vm_rss_bytes",
        "monitor_vm_hwm_bytes",
        "failed_transaction_count",
        "failed_transaction_rate",
        "lock_contention_failure_count",
        "sqlite_before_after",
        "sqlite_family_bytes_growth",
        "sqlite_allocated_page_bytes_growth",
        "audit_rows_growth",
        "attempt_rows_growth",
        "used_credential_rows_growth",
        "audit_logical_payload_bytes_growth",
        "request_cache_rows_growth",
        "worker_result_path",
        "worker_stdout_path",
        "worker_stderr_path",
        "error",
        "run_invalidation_reasons",
    }
)


def _validate_optional_nonnegative_number(value: object, *, field: str) -> None:
    if value is not None and not _is_finite_nonnegative_number(value):
        raise ValueError(f"{field} must be a finite bounded nonnegative number or null")


def _validate_repetition_row(
    row: object,
    *,
    expected_entry: Mapping[str, Any],
    expected_worker_id: str,
    run_id: str,
    operations: int,
) -> dict[str, Any]:
    if type(row) is not dict or frozenset(row) != _REPETITION_FIELDS:
        raise ValueError("retained repetition row has missing or unexpected fields")
    exact_context = {
        "schema_version": REPETITION_SCHEMA,
        "run_id": run_id,
        "worker_id": expected_worker_id,
        **dict(expected_entry),
        "expected_operations": operations,
    }
    for field, expected in exact_context.items():
        if not _exact_json_equal(row[field], expected):
            raise ValueError(f"retained repetition {field} disagrees with the schedule")
    if type(row["status"]) is not str or row["status"] not in ("ok", "failed"):
        raise ValueError("retained repetition status is invalid")
    if type(row["phase"]) is not str or row["phase"] not in _REPETITION_PHASES:
        raise ValueError("retained repetition phase is invalid")
    for field in ("required_metrics_complete", "claim_eligible"):
        if type(row[field]) is not bool:
            raise ValueError(f"retained repetition {field} must be an exact boolean")
    for field in ("completed_operations", "failed_operations"):
        if not _is_bounded_nonnegative_int(row[field]):
            raise ValueError(f"retained repetition {field} is invalid")
    if row["completed_operations"] + row["failed_operations"] != operations:
        raise ValueError("retained repetition denominator is inconsistent")
    numeric_fields = (
        "median_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "p99_9_ms",
        "throughput_operations_per_second",
        "worker_process_cpu_ns",
        "monitor_process_cpu_ns",
        "combined_cpu_ns",
        "combined_cpu_core_equivalent_percent",
        "worker_process_lifetime_peak_rss_bytes",
        "monitor_vm_rss_bytes",
        "monitor_vm_hwm_bytes",
        "failed_transaction_count",
        "failed_transaction_rate",
        "lock_contention_failure_count",
        "sqlite_family_bytes_growth",
        "sqlite_allocated_page_bytes_growth",
        "audit_rows_growth",
        "attempt_rows_growth",
        "used_credential_rows_growth",
        "audit_logical_payload_bytes_growth",
        "request_cache_rows_growth",
    )
    for field in numeric_fields:
        _validate_optional_nonnegative_number(row[field], field=field)
    completed = row["completed_operations"]
    if completed:
        if any(
            not _is_finite_nonnegative_number(row[field])
            for field in ("median_ms", "p50_ms", "p95_ms", "p99_ms")
        ):
            raise ValueError("retained latency metrics are incomplete or invalid")
        # Exact raw-derived comparison below is authoritative; here ensure the
        # support record itself is finite and exact without inventing min/max.
        support = row["p99_9_support"]
        if type(support) is not dict or frozenset(support) != _P999_SUPPORT_FIELDS:
            raise ValueError("retained p99.9 support record is not exact")
        if type(support["supported"]) is not bool:
            raise ValueError("retained p99.9 support verdict is not boolean")
        if (
            not _is_bounded_nonnegative_int(support["minimum_operations"])
            or not _is_bounded_nonnegative_int(support["observed_operations"])
            or support["minimum_operations"] != MIN_P999_OPERATIONS
            or support["observed_operations"] != completed
            or support["supported"] is not (completed >= MIN_P999_OPERATIONS)
        ):
            raise ValueError("retained p99.9 support counts are invalid")
        if support["supported"] is True:
            if not _is_finite_nonnegative_number(row["p99_9_ms"]):
                raise ValueError("retained supported p99.9 value is invalid")
        elif row["p99_9_ms"] is not None:
            raise ValueError("retained unsupported p99.9 value must be null")
    elif row["p99_9_support"] is not None or any(
        row[field] is not None
        for field in ("median_ms", "p50_ms", "p95_ms", "p99_ms", "p99_9_ms")
    ):
        raise ValueError("zero-success repetition contains latency metrics")
    monitor_memory = row["monitor_memory_after"]
    if monitor_memory is not None:
        _validate_memory_snapshot(monitor_memory, field="retained monitor_memory_after")
        if not _exact_json_equal(
            row["monitor_vm_rss_bytes"], monitor_memory["vm_rss_bytes"]
        ) or not _exact_json_equal(
            row["monitor_vm_hwm_bytes"], monitor_memory["vm_hwm_bytes"]
        ):
            raise ValueError("flattened monitor memory disagrees with the raw snapshot")
    elif row["monitor_vm_rss_bytes"] is not None or row["monitor_vm_hwm_bytes"] is not None:
        raise ValueError("flattened monitor memory exists without a snapshot")
    sqlite_growth = row["sqlite_before_after"]
    if sqlite_growth is not None:
        _validate_sqlite_growth(sqlite_growth)
        sqlite_expected = {
            "sqlite_family_bytes_growth": sqlite_growth["family_bytes_growth"],
            "sqlite_allocated_page_bytes_growth": sqlite_growth[
                "allocated_page_bytes_growth"
            ],
            "audit_rows_growth": sqlite_growth["row_growth"]["audit_log"],
            "attempt_rows_growth": sqlite_growth["row_growth"]["attempts"],
            "used_credential_rows_growth": sqlite_growth["row_growth"][
                "used_credentials"
            ],
            "audit_logical_payload_bytes_growth": sqlite_growth[
                "audit_logical_payload_bytes_growth"
            ],
            "request_cache_rows_growth": sqlite_growth["row_growth"][
                "sluice_monitor_request_cache"
            ],
        }
        for field, expected in sqlite_expected.items():
            if not _exact_json_equal(row[field], expected):
                raise ValueError(f"retained {field} disagrees with SQLite before/after")
    for field in ("worker_result_path", "worker_stdout_path", "worker_stderr_path"):
        path_text = row[field]
        if (
            type(path_text) is not str
            or not path_text
            or Path(path_text).is_absolute()
            or ".." in Path(path_text).parts
        ):
            raise ValueError(f"retained repetition {field} is not a safe relative path")
    error = row["error"]
    if error is not None:
        if type(error) is not dict or frozenset(error) not in (
            _ERROR_FIELDS,
            _TRACEBACK_ERROR_FIELDS,
        ):
            raise ValueError("retained repetition error schema is invalid")
        _validate_error_record(
            error,
            field="retained repetition error",
            traceback_required=frozenset(error) == _TRACEBACK_ERROR_FIELDS,
        )
    if row["status"] == "ok" and error is not None:
        raise ValueError("successful retained repetition contains an error")
    reasons = row["run_invalidation_reasons"]
    if type(reasons) is not list or any(type(item) is not str or not item for item in reasons):
        raise ValueError("run invalidation reasons are not an exact string list")
    if reasons and row["claim_eligible"] is not False:
        raise ValueError("invalidated repetition is marked claim eligible")
    return row


def _reload_and_validate_retained_evidence(
    *,
    raw_path: Path,
    repetitions_path: Path,
    expected_repetition_rows: Sequence[Mapping[str, Any]],
    schedule: Sequence[Mapping[str, Any]],
    operations: int,
    run_id: str,
) -> tuple[list[dict[str, Any]], int]:
    """Reopen retained files and recompute repetition metrics before summary.

    Raw operations are consumed in schedule order and only one worker's bounded
    operation set is retained in memory at a time.  Besides keeping validation
    practical for the full matrix, requiring the canonical writer order closes
    duplicate/omitted-worker substitutions that preserve only a global count.
    """

    for label, path in (("raw", raw_path), ("repetition", repetitions_path)):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"retained {label} evidence must be a regular non-symlink file")

    try:
        repetition_rows = [
            json.loads(line)
            for line in repetitions_path.read_text(encoding="ascii").splitlines()
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot decode retained repetition evidence") from exc
    if not _exact_json_equal(repetition_rows, list(expected_repetition_rows)):
        raise ValueError("retained repetition rows changed before summary recomputation")
    if len(repetition_rows) != len(schedule):
        raise ValueError("retained repetition denominator does not match the schedule")

    validated_rows: list[dict[str, Any]] = []
    raw_count = 0
    try:
        with gzip.open(raw_path, "rt", encoding="ascii") as stream:
            for index, (entry, repetition_row) in enumerate(
                zip(schedule, repetition_rows)
            ):
                worker_id = f"w{index:06d}"
                validated = _validate_repetition_row(
                    repetition_row,
                    expected_entry=entry,
                    expected_worker_id=worker_id,
                    run_id=run_id,
                    operations=operations,
                )
                operation_rows: list[dict[str, Any]] = []
                for _ in range(operations):
                    try:
                        line = next(stream)
                    except StopIteration as exc:
                        raise ValueError(
                            "retained raw operation denominator is incomplete"
                        ) from exc
                    raw = json.loads(line)
                    raw_count += 1
                    if type(raw) is not dict or frozenset(raw) != _RAW_OPERATION_FIELDS:
                        raise ValueError(
                            "retained raw operation has missing or unexpected fields"
                        )
                    if (
                        raw["schema_version"] != OPERATION_SCHEMA
                        or raw["run_id"] != run_id
                    ):
                        raise ValueError(
                            "retained raw operation schema/run binding is invalid"
                        )
                    if not _exact_json_equal(raw["worker_id"], worker_id):
                        raise ValueError(
                            "retained raw operation worker order mismatches schedule"
                        )
                    if (
                        type(raw["worker_id"]) is not str
                        or _LABEL.fullmatch(raw["worker_id"]) is None
                    ):
                        raise ValueError("retained raw operation worker id is invalid")

                    context = {
                        "block_id": entry["block_id"],
                        "condition": entry["condition"],
                        "storage_label": entry["storage_label"],
                        "storage_class": entry["storage_class"],
                        "repetition": entry["repetition"],
                        "concurrency": entry["concurrency"],
                    }
                    for field, expected in context.items():
                        if not _exact_json_equal(raw[field], expected):
                            raise ValueError(
                                f"retained raw operation {field} mismatches schedule"
                            )
                    operation = {field: raw[field] for field in _OPERATION_FIELDS}
                    expected_event = (
                        EventKind.ATTEMPT.value
                        if entry["condition"] != "unmediated_handler"
                        and operation["status"] == "ok"
                        else None
                    )
                    expected_outcome = (
                        OutcomeCode.RELEASED.value
                        if entry["condition"] != "unmediated_handler"
                        and operation["status"] == "ok"
                        else None
                    )
                    if not _exact_json_equal(
                        raw["event_kind"], expected_event
                    ) or not _exact_json_equal(raw["outcome_code"], expected_outcome):
                        raise ValueError("retained raw event/outcome is inconsistent")
                    operation_rows.append(operation)

                exact_operations = _validate_operation_records(
                    operation_rows,
                    operation_count=operations,
                    condition=str(entry["condition"]),
                    concurrency=int(entry["concurrency"]),
                )
                derived = _derive_raw_metrics(
                    exact_operations, str(entry["condition"])
                )
                latency = derived["latency_summary"]
                raw_expected = {
                    "completed_operations": derived["completed_operations"],
                    "failed_operations": derived["failed_operations"],
                    "median_ms": (
                        latency.get("median_ms") if type(latency) is dict else None
                    ),
                    "p50_ms": latency.get("p50_ms") if type(latency) is dict else None,
                    "p95_ms": latency.get("p95_ms") if type(latency) is dict else None,
                    "p99_ms": latency.get("p99_ms") if type(latency) is dict else None,
                    "p99_9_ms": (
                        latency.get("p99_9_ms") if type(latency) is dict else None
                    ),
                    "p99_9_support": (
                        latency.get("p99_9_support")
                        if type(latency) is dict
                        else None
                    ),
                    "throughput_operations_per_second": derived[
                        "throughput_operations_per_second"
                    ],
                    "failed_transaction_count": derived["failed_transaction_count"],
                    "failed_transaction_rate": derived["failed_transaction_rate"],
                    "lock_contention_failure_count": derived[
                        "lock_contention_failure_count"
                    ],
                }
                for field, expected in raw_expected.items():
                    if not _exact_json_equal(validated[field], expected):
                        raise ValueError(
                            f"retained repetition {field} disagrees with retained "
                            "raw operations"
                        )
                if validated["status"] == "ok" and derived["status"] != "ok":
                    raise ValueError(
                        "successful repetition has failed retained raw operations"
                    )
                validated_rows.append(validated)

            if next(stream, None) is not None:
                raise ValueError("retained raw operation denominator has extra rows")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot decode retained raw operation evidence") from exc

    expected_raw_count = len(schedule) * operations
    if raw_count != expected_raw_count:
        raise ValueError("retained raw operation denominator is incomplete")
    return validated_rows, raw_count


def _summary_cells(
    repetitions: Sequence[Mapping[str, Any]],
    *,
    bootstrap_seed: int,
    bootstrap_replicates: int,
    expected_repetitions: int | None = None,
) -> list[dict[str, Any]]:
    _positive_int("bootstrap_replicates", bootstrap_replicates)
    if not _is_exact_int(bootstrap_seed) or abs(bootstrap_seed) > MAX_AUDIT_INTEGER:
        raise ValueError("bootstrap_seed must be a bounded exact integer")
    if expected_repetitions is not None:
        _positive_int("expected_repetitions", expected_repetitions)
    if type(repetitions) not in (list, tuple):
        raise ValueError("summary repetitions must be an exact sequence")
    for row in repetitions:
        if type(row) is not dict:
            raise ValueError("summary repetition must be an exact object")
        if (
            type(row.get("storage_label")) is not str
            or _LABEL.fullmatch(row["storage_label"]) is None
            or type(row.get("storage_class")) is not str
            or row["storage_class"] not in STORAGE_CLASSES
            or not _is_exact_int(row.get("concurrency"))
            or not 0 < row["concurrency"] <= MAX_AUDIT_INTEGER
            or type(row.get("condition")) is not str
            or row["condition"] not in CONDITIONS
            or type(row.get("status")) is not str
            or row["status"] not in ("ok", "failed")
            or type(row.get("claim_eligible")) is not bool
        ):
            raise ValueError("summary repetition grouping/status schema is invalid")
    keys = sorted(
        {
            (
                str(row["storage_label"]),
                str(row["storage_class"]),
                int(row["concurrency"]),
                str(row["condition"]),
            )
            for row in repetitions
        }
    )
    cells: list[dict[str, Any]] = []
    metric_fields = (
        "median_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "p99_9_ms",
        "throughput_operations_per_second",
        "combined_cpu_core_equivalent_percent",
        "worker_process_cpu_ns",
        "monitor_process_cpu_ns",
        "combined_cpu_ns",
        "worker_process_lifetime_peak_rss_bytes",
        "monitor_vm_rss_bytes",
        "monitor_vm_hwm_bytes",
        "failed_operations",
        "failed_transaction_count",
        "failed_transaction_rate",
        "lock_contention_failure_count",
        "sqlite_family_bytes_growth",
        "sqlite_allocated_page_bytes_growth",
        "attempt_rows_growth",
        "used_credential_rows_growth",
        "audit_rows_growth",
        "audit_logical_payload_bytes_growth",
        "request_cache_rows_growth",
    )
    for cell_index, key in enumerate(keys):
        storage_label, storage_class, concurrency, condition = key
        rows = [
            row
            for row in repetitions
            if (
                row["storage_label"],
                row["storage_class"],
                row["concurrency"],
                row["condition"],
            )
            == key
        ]
        successful = [row for row in rows if row["status"] == "ok"]
        if expected_repetitions is not None and len(rows) != expected_repetitions:
            raise ValueError("summary cell does not contain every scheduled repetition")
        metrics: dict[str, Any] = {}
        for metric_index, field in enumerate(metric_fields):
            raw_values = [row[field] for row in successful if row.get(field) is not None]
            if any(not _is_finite_nonnegative_number(item) for item in raw_values):
                raise ValueError(f"summary metric {field} contains an invalid value")
            values = [float(item) for item in raw_values]
            metrics[field] = bootstrap_median_interval(
                values,
                seed=bootstrap_seed + cell_index * 10_007 + metric_index,
                replicates=bootstrap_replicates,
            )
        cells.append(
            {
                "storage_label": storage_label,
                "storage_class": storage_class,
                "concurrency": concurrency,
                "condition": condition,
                "expected_repetitions": (
                    len(rows) if expected_repetitions is None else expected_repetitions
                ),
                "successful_repetitions": len(successful),
                "failed_repetitions": len(rows) - len(successful),
                "claim_eligible": bool(rows) and all(
                    row["claim_eligible"] is True for row in rows
                ),
                "metrics": metrics,
                "absolute_units_only": True,
            }
        )
    return cells


def _component_hashes(repository_root: Path) -> dict[str, str | None]:
    output: dict[str, str | None] = {}
    for relative in COMPONENT_PATHS:
        path = repository_root / relative
        output[relative] = (
            _sha256_file(path)
            if path.is_file()
            and not path.is_symlink()
            and _path_is_within(path, repository_root)
            else None
        )
    return output


def _build_pinned_worker_source(
    repository_root: Path,
    snapshot_root: Path,
    expected_hashes: Mapping[str, str],
) -> dict[str, str]:
    """Copy exact measured imports to a read-only, hash-addressable tree."""

    if frozenset(expected_hashes) != frozenset(COMPONENT_PATHS):
        raise ValueError("pinned worker component manifest is not exact")
    if snapshot_root.exists():
        raise FileExistsError(snapshot_root)
    snapshot_root.mkdir(parents=True, mode=0o700)
    copied: dict[str, str] = {}
    try:
        for relative in COMPONENT_PATHS:
            expected = expected_hashes[relative]
            if type(expected) is not str or _SHA256.fullmatch(expected) is None:
                raise ValueError("pinned worker component hash is invalid")
            source = repository_root / relative
            if (
                not source.is_file()
                or source.is_symlink()
                or not _path_is_within(source, repository_root)
                or _sha256_file(source) != expected
            ):
                raise RuntimeError(f"source changed before worker snapshot: {relative}")
            target = snapshot_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            observed = _sha256_file(target)
            if observed != expected or _sha256_file(source) != expected:
                raise RuntimeError(f"source changed while copying worker snapshot: {relative}")
            os.chmod(target, 0o444)
            copied[relative] = observed
        directories = sorted(
            (candidate for candidate in snapshot_root.rglob("*") if candidate.is_dir()),
            key=lambda candidate: len(candidate.parts),
            reverse=True,
        )
        for directory in directories:
            os.chmod(directory, 0o555)
        os.chmod(snapshot_root, 0o555)
    except BaseException:
        for candidate in snapshot_root.rglob("*"):
            if candidate.is_dir():
                try:
                    os.chmod(candidate, 0o700)
                except OSError:
                    pass
        try:
            os.chmod(snapshot_root, 0o700)
        except OSError:
            pass
        shutil.rmtree(snapshot_root, ignore_errors=True)
        raise
    return copied


def _snapshot_component_hashes(snapshot_root: Path) -> dict[str, str | None]:
    output: dict[str, str | None] = {}
    for relative in COMPONENT_PATHS:
        candidate = snapshot_root / relative
        output[relative] = (
            _sha256_file(candidate)
            if candidate.is_file()
            and not candidate.is_symlink()
            and _path_is_within(candidate, snapshot_root)
            else None
        )
    return output


def _path_is_within(path: Path, root: Path) -> bool:
    candidate = path.resolve(strict=False)
    boundary = root.resolve(strict=True)
    try:
        return os.path.commonpath((str(candidate), str(boundary))) == str(boundary)
    except ValueError:
        return False


def _write_checksums(run_directory: Path) -> None:
    symlinks = [candidate for candidate in run_directory.rglob("*") if candidate.is_symlink()]
    if symlinks:
        raise ValueError("retained run bundle must not contain symbolic links")
    entries = []
    for path in sorted(candidate for candidate in run_directory.rglob("*") if candidate.is_file()):
        relative = path.relative_to(run_directory)
        if relative.as_posix() == "SHA256SUMS":
            continue
        entries.append(f"{_sha256_file(path)}  {relative.as_posix()}")
    _atomic_text(run_directory / "SHA256SUMS", "\n".join(entries) + "\n")


def _subprocess_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if type(value) is bytes:
        return value.decode("utf-8", errors="replace")
    return str(value)


def _failure_detail(value: object, *, fallback_type: str, fallback_message: str) -> dict[str, str]:
    """Normalize any child/controller failure without trusting its schema."""

    if type(value) is dict:
        error_type = value.get("error_type")
        error_message = value.get("error_message")
        if type(error_type) is str and error_type and type(error_message) is str:
            return {"error_type": error_type, "error_message": error_message}
    return {"error_type": fallback_type, "error_message": fallback_message}


def _cpu_provenance() -> dict[str, Any]:
    cpuinfo = Path("/proc/cpuinfo")
    model_names: set[str] = set()
    cpuinfo_sha256: str | None = None
    if cpuinfo.is_file():
        cpuinfo_sha256 = _sha256_file(cpuinfo)
        try:
            for line in cpuinfo.read_text(encoding="utf-8").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    model_names.add(line.split(":", 1)[1].strip())
        except (OSError, UnicodeError):
            model_names = set()
    affinity = (
        sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    )
    return {
        "logical_cpu_count": os.cpu_count(),
        "allowed_cpu_affinity": affinity,
        "model_names": sorted(model_names),
        "proc_cpuinfo_sha256": cpuinfo_sha256,
        "frequency_governor_controlled": False,
        "frequency_governor_note": "not controlled by this foundation",
    }


def _source_state_stable(
    *,
    start: Mapping[str, Any],
    end: Mapping[str, Any],
    component_start: Mapping[str, Any],
    component_end: Mapping[str, Any],
    worker_start: Mapping[str, Any],
    worker_end: Mapping[str, Any],
    storage_stable: bool,
    mode: str,
) -> bool:
    if type(storage_stable) is not bool or type(mode) is not str:
        return False
    stable = (
        _exact_json_equal(dict(component_end), dict(component_start))
        and _exact_json_equal(dict(worker_end), dict(worker_start))
        and end.get("backend") == start.get("backend")
        and end.get("commit") == start.get("commit")
        and type(end.get("dirty")) is bool
        and end.get("dirty") is start.get("dirty")
        and type(end.get("trusted_for_final")) is bool
        and end.get("trusted_for_final") is start.get("trusted_for_final")
        and end.get("tool_executable_sha256")
        == start.get("tool_executable_sha256")
        and end.get("tool_path") == start.get("tool_path")
        and end.get("tool_version") == start.get("tool_version")
        and end.get("tool_manifest_path") == start.get("tool_manifest_path")
        and end.get("tool_manifest_repository_path")
        == start.get("tool_manifest_repository_path")
        and end.get("tool_manifest_sha256")
        == start.get("tool_manifest_sha256")
        and end.get("tool_installation_label")
        == start.get("tool_installation_label")
        and end.get("tool_host_validated")
        is start.get("tool_host_validated")
        and storage_stable
    )
    if mode == "final":
        stable = stable and (
            start.get("backend") == "git"
            and end.get("backend") == "git"
            and start.get("trusted_for_final") is True
            and end.get("trusted_for_final") is True
            and start.get("dirty") is False
            and end.get("dirty") is False
        )
    return bool(stable)


def run_benchmark(
    *,
    output_root: Path,
    profiles: Sequence[StorageProfile],
    mode: str,
    operations: int,
    warmup_operations: int,
    repetitions: int,
    concurrencies: Sequence[int],
    seed: int,
    bootstrap_replicates: int,
    condition_timeout_seconds: int,
    repository_root: Path = REPOSITORY_ROOT,
    native_git_path: Path | None = None,
    native_git_manifest_path: Path | None = None,
) -> dict[str, Any]:
    provenance = (
        source_provenance(repository_root)
        if native_git_path is None and native_git_manifest_path is None
        else source_provenance(
            repository_root,
            native_git_path=native_git_path,
            native_git_manifest_path=native_git_manifest_path,
        )
    )
    component_sha256_start = _component_hashes(repository_root)
    if any(value is None for value in component_sha256_start.values()):
        raise ValueError("one or more transitive benchmark components are missing")
    pinned_component_sha256 = {
        key: str(value) for key, value in component_sha256_start.items()
    }
    if (
        type(provenance.get("commit")) is not str
        or _GIT_COMMIT.fullmatch(provenance["commit"]) is None
        or type(provenance.get("dirty")) is not bool
        or type(provenance.get("backend")) is not str
    ):
        raise ValueError("benchmark source commit/dirty provenance is unavailable")
    if type(profiles) not in (tuple, list) or not profiles:
        raise ValueError("benchmark profiles must be a nonempty exact sequence")
    if any(type(profile) is not StorageProfile for profile in profiles):
        raise ValueError("benchmark profile entries must be exact StorageProfile values")
    if len({profile.label for profile in profiles}) != len(profiles):
        raise ValueError("benchmark storage labels must be unique")
    if len({profile.resolved_path for profile in profiles}) != len(profiles):
        raise ValueError("benchmark storage roots must be unique")
    for profile in profiles:
        _validate_storage_profile_for_run(profile)
    validate_run_parameters(
        mode=mode,
        operations=operations,
        warmup_operations=warmup_operations,
        repetitions=repetitions,
        concurrencies=concurrencies,
        bootstrap_replicates=bootstrap_replicates,
        profiles=profiles,
        provenance=provenance,
    )
    _positive_int("condition_timeout_seconds", condition_timeout_seconds)
    if not _is_exact_int(seed) or abs(seed) > MAX_AUDIT_INTEGER:
        raise ValueError("seed must be a bounded exact integer")
    output_root.mkdir(parents=True, exist_ok=True)
    output_root = output_root.resolve(strict=True)
    if mode == "final" and _path_is_within(output_root, repository_root):
        raise ValueError(
            "final output_root must be outside the source repository so result files "
            "cannot dirty the measured tree"
        )
    started_at = datetime.now(timezone.utc)
    load_average_start = list(os.getloadavg()) if hasattr(os, "getloadavg") else None
    run_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{platform.node()}-{uuid.uuid4().hex[:12]}"
    final_directory = output_root / run_id
    if final_directory.exists():
        raise FileExistsError(final_directory)
    staging_directory = output_root / f".{run_id}.partial"
    staging_directory.mkdir(exist_ok=False)
    worker_source_parent = staging_directory / "worker_source"
    worker_source_parent.mkdir()
    driver_hash = pinned_component_sha256[
        "source/artifact/experiments/g8_matched_scalability.py"
    ]
    worker_source_root = worker_source_parent / driver_hash
    worker_source_sha256 = _build_pinned_worker_source(
        repository_root,
        worker_source_root,
        pinned_component_sha256,
    )
    worker_directory = staging_directory / "workers"
    worker_directory.mkdir()
    profiles_by_label = {profile.label: profile for profile in profiles}
    retained_attestations: dict[str, dict[str, Any]] = {}
    if any(profile.attestation_canonical_json is not None for profile in profiles):
        attestation_directory = staging_directory / "storage_attestations"
        attestation_directory.mkdir()
        for profile in profiles:
            if profile.attestation_canonical_json is None:
                continue
            retained = attestation_directory / f"{profile.label}.json"
            _atomic_text(retained, profile.attestation_canonical_json)
            retained_hash = _sha256_file(retained)
            if retained_hash != profile.attestation_sha256:
                raise RuntimeError("retained storage attestation hash mismatch")
            retained_attestations[profile.label] = {
                "path": retained.relative_to(staging_directory).as_posix(),
                "sha256": retained_hash,
            }
            profiles_by_label[profile.label] = replace(
                profile,
                attestation_path=str(retained.resolve(strict=True)),
            )
    raw_path = staging_directory / "operations.jsonl.gz"
    repetitions_path = staging_directory / "repetitions.jsonl"
    schedule = build_schedule(
        tuple(profiles_by_label.values()), concurrencies, repetitions, seed=seed
    )
    repetition_rows: list[dict[str, Any]] = []
    worker_commands: list[dict[str, Any]] = []
    raw_count = 0
    with gzip.open(raw_path, "wt", encoding="ascii") as raw_stream:
        for schedule_index, entry in enumerate(schedule):
            worker_id = f"w{schedule_index:06d}"
            profile = profiles_by_label[entry["storage_label"]]
            spec = {
                "schema_version": WORKER_SPEC_SCHEMA,
                "run_id": run_id,
                "block_id": entry["block_id"],
                "condition": entry["condition"],
                "storage_label": profile.label,
                "storage_class": profile.storage_class,
                "storage_root": profile.resolved_path,
                "repetition": entry["repetition"],
                "concurrency": entry["concurrency"],
                "operations": operations,
                "warmup_operations": warmup_operations,
                "expected_component_sha256": pinned_component_sha256,
                "expected_source_commit": provenance["commit"],
                "expected_source_dirty": provenance["dirty"],
                "source_repository_root": str(repository_root.resolve(strict=True)),
                "worker_source_root": str(worker_source_root),
                "expected_worker_source_sha256": worker_source_sha256,
                "expected_storage_identity": _profile_storage_identity(profile),
            }
            spec_path = worker_directory / f"{worker_id}.spec.json"
            result_path = worker_directory / f"{worker_id}.result.json"
            stdout_path = worker_directory / f"{worker_id}.stdout.txt"
            stderr_path = worker_directory / f"{worker_id}.stderr.txt"
            _atomic_json(spec_path, spec)
            spec_sha256 = _sha256_file(spec_path)
            command = [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _worker_bootstrap_source(),
                "_worker",
                "--spec",
                str(spec_path),
                "--output",
                str(result_path),
                "--spec-sha256",
                spec_sha256,
            ]
            timed_out = False
            process_error: dict[str, str] | None = None
            worker_environment = _isolated_worker_environment()
            try:
                completed = subprocess.run(
                    command,
                    cwd=repository_root,
                    env=worker_environment,
                    capture_output=True,
                    text=True,
                    timeout=condition_timeout_seconds,
                    check=False,
                )
                returncode = completed.returncode
                stdout = completed.stdout
                stderr = completed.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                returncode = None
                stdout = _subprocess_text(exc.stdout)
                stderr = _subprocess_text(exc.stderr)
                process_error = {
                    "error_type": type(exc).__name__,
                    "error_message": f"condition exceeded {condition_timeout_seconds} seconds",
                }
            except OSError as exc:
                returncode = None
                stdout = ""
                stderr = ""
                process_error = {
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
            stdout = _subprocess_text(stdout)
            stderr = _subprocess_text(stderr)
            _atomic_text(stdout_path, stdout)
            _atomic_text(stderr_path, stderr)
            retained_command = [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _worker_bootstrap_source(),
                "_worker",
                "--spec",
                str(final_directory / spec_path.relative_to(staging_directory)),
                "--output",
                str(final_directory / result_path.relative_to(staging_directory)),
                "--spec-sha256",
                spec_sha256,
            ]
            worker_commands.append(
                {
                    "worker_id": worker_id,
                    "schedule_index": schedule_index,
                    "executed_argv": command,
                    "executed_cwd": str(repository_root),
                    "executed_environment": worker_environment,
                    "retained_replay_argv": retained_command,
                    "retained_replay_cwd": str(repository_root),
                    "retained_replay_environment": worker_environment,
                    "timeout_seconds": condition_timeout_seconds,
                    "timed_out": timed_out,
                    "returncode": returncode,
                    "process_error": process_error,
                }
            )
            worker_result: dict[str, Any] | None = None
            parent_error = process_error
            if (
                parent_error is None
                and result_path.is_file()
                and not result_path.is_symlink()
                and _path_is_within(result_path, staging_directory)
            ):
                try:
                    decoded = json.loads(result_path.read_text(encoding="ascii"))
                    worker_result = _validate_worker_result(decoded, spec)
                    expected_returncode = 0 if worker_result["status"] == "ok" else 3
                    if returncode != expected_returncode:
                        raise ValueError(
                            f"worker return code {returncode} disagrees with status "
                            f"{worker_result['status']}"
                        )
                except (
                    OSError,
                    UnicodeError,
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                    OverflowError,
                    RuntimeError,
                ) as exc:
                    worker_result = None
                    parent_error = {
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    }
            elif parent_error is None:
                parent_error = {
                    "error_type": "MissingWorkerResult",
                    "error_message": f"worker exited {returncode} without a result",
                }
            measured = worker_result.get("measured") if worker_result is not None else None
            phase = worker_result.get("phase") if worker_result is not None else (
                "timeout" if timed_out else "parent_validation"
            )
            worker_error = (
                worker_result.get("worker_error") if worker_result is not None else None
            )
            if type(measured) is dict:
                try:
                    operation_rows = _validate_operation_records(
                        measured["operations"],
                        operation_count=operations,
                        condition=entry["condition"],
                        concurrency=entry["concurrency"],
                    )
                except (KeyError, TypeError, ValueError, OverflowError) as exc:
                    parent_error = {
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    }
                    worker_result = None
                    measured = None
                    detail = _failure_detail(
                        parent_error,
                        fallback_type="MalformedWorkerMeasurement",
                        fallback_message="worker measurement schema is invalid",
                    )
                    operation_rows = _synthetic_failure_operations(
                        operations,
                        error_type=detail["error_type"],
                        error_message=detail["error_message"],
                    )
            else:
                error = _failure_detail(
                    parent_error or worker_error,
                    fallback_type="MissingMeasurement",
                    fallback_message="worker produced no measured operation records",
                )
                operation_rows = _synthetic_failure_operations(
                    operations,
                    error_type=error["error_type"],
                    error_message=error["error_message"],
                )
            raw_derived = _derive_raw_metrics(operation_rows, entry["condition"])
            status = (
                "ok"
                if worker_result is not None
                and worker_result["status"] == "ok"
                and parent_error is None
                and raw_derived["status"] == "ok"
                else "failed"
            )
            latency = raw_derived["latency_summary"]
            sqlite_growth = measured.get("sqlite_growth") if type(measured) is dict else None
            row_growth = sqlite_growth.get("row_growth", {}) if type(sqlite_growth) is dict else {}
            metrics_complete = _required_metrics_complete(entry["condition"], measured)
            repetition_row = {
                "schema_version": REPETITION_SCHEMA,
                "run_id": run_id,
                "worker_id": worker_id,
                **entry,
                "status": status,
                "phase": phase,
                "required_metrics_complete": metrics_complete,
                "claim_eligible": cell_claim_eligible(
                    mode=mode,
                    source_clean=provenance.get("dirty") is False,
                    profile=profile,
                    status=status,
                    metrics_complete=metrics_complete,
                ),
                "expected_operations": operations,
                "completed_operations": raw_derived["completed_operations"],
                "failed_operations": raw_derived["failed_operations"],
                "median_ms": latency.get("median_ms") if type(latency) is dict else None,
                "p50_ms": latency.get("p50_ms") if type(latency) is dict else None,
                "p95_ms": latency.get("p95_ms") if type(latency) is dict else None,
                "p99_ms": latency.get("p99_ms") if type(latency) is dict else None,
                "p99_9_ms": latency.get("p99_9_ms") if type(latency) is dict else None,
                "p99_9_support": latency.get("p99_9_support") if type(latency) is dict else None,
                "throughput_operations_per_second": (
                    raw_derived["throughput_operations_per_second"]
                ),
                "worker_process_cpu_ns": (
                    measured.get("worker_process_cpu_ns") if type(measured) is dict else None
                ),
                "monitor_process_cpu_ns": (
                    measured.get("monitor_process_cpu_ns") if type(measured) is dict else None
                ),
                "combined_cpu_ns": (
                    measured.get("combined_cpu_ns") if type(measured) is dict else None
                ),
                "combined_cpu_core_equivalent_percent": (
                    measured.get("combined_cpu_core_equivalent_percent")
                    if type(measured) is dict
                    else None
                ),
                "worker_process_lifetime_peak_rss_bytes": (
                    measured.get("worker_process_lifetime_peak_rss_bytes")
                    if type(measured) is dict
                    else None
                ),
                "monitor_memory_after": (
                    measured.get("monitor_memory_after") if type(measured) is dict else None
                ),
                "monitor_vm_rss_bytes": (
                    measured.get("monitor_memory_after", {}).get("vm_rss_bytes")
                    if type(measured) is dict
                    and type(measured.get("monitor_memory_after")) is dict
                    else None
                ),
                "monitor_vm_hwm_bytes": (
                    measured.get("monitor_memory_after", {}).get("vm_hwm_bytes")
                    if type(measured) is dict
                    and type(measured.get("monitor_memory_after")) is dict
                    else None
                ),
                "failed_transaction_count": (
                    raw_derived["failed_transaction_count"]
                ),
                "failed_transaction_rate": (
                    raw_derived["failed_transaction_rate"]
                ),
                "lock_contention_failure_count": (
                    raw_derived["lock_contention_failure_count"]
                ),
                "sqlite_before_after": sqlite_growth,
                "sqlite_family_bytes_growth": (
                    sqlite_growth.get("family_bytes_growth")
                    if type(sqlite_growth) is dict
                    else None
                ),
                "sqlite_allocated_page_bytes_growth": (
                    sqlite_growth.get("allocated_page_bytes_growth")
                    if type(sqlite_growth) is dict
                    else None
                ),
                "audit_rows_growth": row_growth.get("audit_log"),
                "attempt_rows_growth": row_growth.get("attempts"),
                "used_credential_rows_growth": row_growth.get("used_credentials"),
                "audit_logical_payload_bytes_growth": (
                    sqlite_growth.get("audit_logical_payload_bytes_growth")
                    if type(sqlite_growth) is dict
                    else None
                ),
                "request_cache_rows_growth": row_growth.get("sluice_monitor_request_cache"),
                "worker_result_path": result_path.relative_to(staging_directory).as_posix(),
                "worker_stdout_path": stdout_path.relative_to(staging_directory).as_posix(),
                "worker_stderr_path": stderr_path.relative_to(staging_directory).as_posix(),
                "error": parent_error
                or worker_error
                or (
                    measured.get("setup_or_measurement_error")
                    if type(measured) is dict
                    else None
                )
                or (
                    measured.get("cleanup_error") if type(measured) is dict else None
                ),
            }
            repetition_rows.append(repetition_row)
            for operation in operation_rows:
                raw_record = dict(operation)
                raw_record.update(
                    {
                        "schema_version": OPERATION_SCHEMA,
                        "run_id": run_id,
                        "worker_id": worker_id,
                        "block_id": entry["block_id"],
                        "condition": entry["condition"],
                        "storage_label": profile.label,
                        "storage_class": profile.storage_class,
                        "repetition": entry["repetition"],
                        "concurrency": entry["concurrency"],
                        "event_kind": (
                            EventKind.ATTEMPT.value
                            if entry["condition"] != "unmediated_handler"
                            and operation["status"] == "ok"
                            else None
                        ),
                        "outcome_code": (
                            OutcomeCode.RELEASED.value
                            if entry["condition"] != "unmediated_handler"
                            and operation["status"] == "ok"
                            else None
                        ),
                    }
                )
                raw_stream.write(_canonical_json(raw_record) + "\n")
                raw_count += 1

    expected_raw_count = len(schedule) * operations
    component_sha256_end = _component_hashes(repository_root)
    provenance_end = (
        source_provenance(repository_root)
        if native_git_path is None and native_git_manifest_path is None
        else source_provenance(
            repository_root,
            native_git_path=native_git_path,
            native_git_manifest_path=native_git_manifest_path,
        )
    )
    worker_source_sha256_end = _snapshot_component_hashes(worker_source_root)
    storage_identity_end: dict[str, dict[str, Any] | None] = {}
    storage_stable = True
    for profile in profiles:
        try:
            observed_storage = _observe_storage_identity(Path(profile.resolved_path))
            _validate_storage_identity(
                observed_storage,
                _profile_storage_identity(profile),
            )
        except (OSError, RuntimeError, ValueError):
            storage_identity_end[profile.label] = None
            storage_stable = False
        else:
            storage_identity_end[profile.label] = observed_storage
    retained_attestation_stable = True
    for label, retained_record in retained_attestations.items():
        retained_path = staging_directory / retained_record["path"]
        observed_hash: str | None = None
        try:
            if retained_path.is_file() and not retained_path.is_symlink():
                observed_hash = _sha256_file(retained_path)
        except OSError:
            observed_hash = None
        retained_record["end_sha256"] = observed_hash
        retained_record["stable_through_end"] = (
            observed_hash == retained_record["sha256"]
            and profiles_by_label[label].claim_storage_eligible
        )
        if retained_record["stable_through_end"] is not True:
            retained_attestation_stable = False
    source_stable = _source_state_stable(
        start=provenance,
        end=provenance_end,
        component_start=component_sha256_start,
        component_end=component_sha256_end,
        worker_start=worker_source_sha256,
        worker_end=worker_source_sha256_end,
        storage_stable=storage_stable and retained_attestation_stable,
        mode=mode,
    )
    run_invalidation_reasons: list[str] = []
    if raw_count != expected_raw_count:
        run_invalidation_reasons.append("raw operation denominator is incomplete")
    if not source_stable:
        run_invalidation_reasons.append(
            "source/snapshot provenance or exact storage mount identity changed"
        )
    if not retained_attestation_stable:
        run_invalidation_reasons.append(
            "retained storage attestation path/hash/content identity changed"
        )
    if run_invalidation_reasons:
        for row in repetition_rows:
            row["claim_eligible"] = False
            row["run_invalidation_reasons"] = list(run_invalidation_reasons)
    else:
        for row in repetition_rows:
            row["run_invalidation_reasons"] = []
    _write_jsonl(repetitions_path, repetition_rows)
    retained_repetition_rows, retained_raw_count = _reload_and_validate_retained_evidence(
        raw_path=raw_path,
        repetitions_path=repetitions_path,
        expected_repetition_rows=repetition_rows,
        schedule=schedule,
        operations=operations,
        run_id=run_id,
    )
    if retained_raw_count != raw_count:
        raise RuntimeError("retained raw count changed before summary construction")
    repetition_rows = retained_repetition_rows
    cells = _summary_cells(
        repetition_rows,
        bootstrap_seed=seed + 9_999_991,
        bootstrap_replicates=bootstrap_replicates,
        expected_repetitions=repetitions,
    )
    failed_repetitions = sum(row["status"] != "ok" for row in repetition_rows)
    source_clean = provenance.get("dirty") is False
    eligible_repetitions = sum(bool(row["claim_eligible"]) for row in repetition_rows)
    evidence_class = (
        "FINAL_PERSISTENT_CANDIDATE"
        if FINAL_CLAIMS_ENABLED
        and mode == "final"
        and failed_repetitions == 0
        and eligible_repetitions == len(schedule)
        and len(repetition_rows) == len(schedule)
        and all(cell["claim_eligible"] is True for cell in cells)
        and not run_invalidation_reasons
        else "NON_CLAIMABLE_DIAGNOSTIC"
    )
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "run_id": run_id,
        "evidence_class": evidence_class,
        "paper_claim_eligible": evidence_class == "FINAL_PERSISTENT_CANDIDATE",
        "raw_operation_count": raw_count,
        "expected_raw_operation_count": expected_raw_count,
        "raw_denominator_complete": raw_count == expected_raw_count,
        "expected_repetition_count": len(schedule),
        "successful_repetition_count": len(schedule) - failed_repetitions,
        "failed_repetition_count": failed_repetitions,
        "eligible_persistent_repetition_count": eligible_repetitions,
        "run_invalidation_reasons": run_invalidation_reasons,
        "cells": cells,
        "boundaries": {
            "tmpfs_is_diagnostic_only": True,
            "dirty_tree_is_never_claimable": True,
            "model_inference_measured": False,
            "tool_execution_measured": False,
            "end_to_end_workflow_measured": False,
            "signed_checkpoint_measured": False,
            "garbage_collection_measured": False,
            "crash_recovery_measured": False,
            "historical_rq4_results_reused": False,
            "singleton_model_worker_landlock_confined": False,
            "singleton_isolation_overhead_claimed": False,
            "final_claims_enabled": FINAL_CLAIMS_ENABLED,
        },
    }
    summary_path = staging_directory / "summary.json"
    _atomic_json(summary_path, summary)
    finished_at = datetime.now(timezone.utc)
    load_average_finish = list(os.getloadavg()) if hasattr(os, "getloadavg") else None
    python_binary = Path(sys.executable).resolve(strict=True)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "run_id": run_id,
        "mode": mode,
        "evidence_class": evidence_class,
        "paper_claim_eligible": summary["paper_claim_eligible"],
        "source": {
            "start": provenance,
            "end": provenance_end,
            "stable": source_stable,
            "native_git_required_for_final": True,
            "vendored_dulwich_is_diagnostic_only": True,
        },
        "component_sha256": {
            "start": component_sha256_start,
            "end": component_sha256_end,
            "stable": component_sha256_end == component_sha256_start,
        },
        "worker_source_snapshot": {
            "root": worker_source_root.relative_to(staging_directory).as_posix(),
            "start": worker_source_sha256,
            "end": worker_source_sha256_end,
            "stable": worker_source_sha256_end == worker_source_sha256,
            "files_read_only": True,
        },
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "kernel_release": platform.release(),
            "python": sys.version,
            "python_executable": sys.executable,
            "python_executable_sha256": _sha256_file(python_binary),
            "cpu": _cpu_provenance(),
            "pid": os.getpid(),
            "perf_counter": "time.perf_counter_ns",
            "load_average_start": load_average_start,
            "load_average_finish": load_average_finish,
            "safe_environment": {
                key: os.environ[key] for key in SAFE_ENVIRONMENT_KEYS if key in os.environ
            },
        },
        "time": {
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
        },
        "parameters": {
            "conditions": list(CONDITIONS),
            "operations": operations,
            "warmup_operations": warmup_operations,
            "repetitions": repetitions,
            "concurrencies": list(concurrencies),
            "randomization_seed": seed,
            "bootstrap_replicates": bootstrap_replicates,
            "percentile_method": PERCENTILE_METHOD,
            "p99_9_minimum_operations": MIN_P999_OPERATIONS,
            "condition_timeout_seconds": condition_timeout_seconds,
            "explicit_native_git_path": (
                None if native_git_path is None else str(native_git_path)
            ),
            "native_git_attestation_path": (
                None
                if native_git_manifest_path is None
                else str(native_git_manifest_path)
            ),
            "fresh_worker_process_per_condition_repetition": True,
            "separate_warmup_domain_or_ledger": True,
        },
        "storage_profiles": [asdict(profile) for profile in profiles],
        "storage_identity_end": storage_identity_end,
        "retained_storage_attestations": retained_attestations,
        "schedule": schedule,
        "worker_commands": worker_commands,
        "launch": {
            "argv": list(sys.argv),
            "cwd": os.getcwd(),
        },
        "artifacts": {
            "operations": {
                "path": raw_path.name,
                "sha256": _sha256_file(raw_path),
                "rows": raw_count,
            },
            "repetitions": {
                "path": repetitions_path.name,
                "sha256": _sha256_file(repetitions_path),
                "rows": len(repetition_rows),
            },
            "summary": {
                "path": summary_path.name,
                "sha256": _sha256_file(summary_path),
            },
        },
        "validity": {
            "source_commit_known": provenance.get("commit") is not None,
            "source_clean": source_clean,
            "source_stable_through_end": source_stable,
            "worker_source_snapshot_stable": (
                worker_source_sha256_end == worker_source_sha256
            ),
            "storage_identity_stable_through_end": storage_stable,
            "retained_storage_attestations_stable_through_end": (
                retained_attestation_stable
            ),
            "raw_denominator_complete": raw_count == expected_raw_count,
            "all_scheduled_conditions_completed": failed_repetitions == 0,
            "has_attested_local_persistent_profile": any(
                profile.claim_storage_eligible
                for profile in profiles_by_label.values()
            ),
            "tmpfs_claim_eligible": False,
            "required_metrics_complete_for_all_repetitions": all(
                row["required_metrics_complete"] is True for row in repetition_rows
            ),
            "all_scheduled_repetitions_claim_eligible": (
                len(repetition_rows) == len(schedule)
                and all(row["claim_eligible"] is True for row in repetition_rows)
            ),
            "final_claims_enabled": FINAL_CLAIMS_ENABLED,
            "final_gate_passed": summary["paper_claim_eligible"],
        },
    }
    manifest_path = staging_directory / "manifest.json"
    _atomic_json(manifest_path, manifest)
    _write_checksums(staging_directory)
    os.replace(staging_directory, final_directory)
    return {
        "run_id": run_id,
        "run_directory": str(final_directory),
        "manifest": manifest,
        "summary": summary,
        "exit_code": 0
        if failed_repetitions == 0 and not run_invalidation_reasons
        else 4,
    }


def _parse_concurrencies(value: str) -> tuple[int, ...]:
    try:
        levels = tuple(int(field) for field in value.split(","))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("concurrencies must be comma-separated integers") from exc
    if (
        not levels
        or any(not 0 < level <= MAX_AUDIT_INTEGER for level in levels)
        or len(set(levels)) != len(levels)
    ):
        raise argparse.ArgumentTypeError("concurrencies must be unique positive integers")
    return levels


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="execute the complete four-condition matrix")
    run_parser.add_argument("--output-root", type=Path, required=True)
    run_parser.add_argument(
        "--storage-profile",
        action="append",
        required=True,
        metavar="LABEL:CLASS:PATH",
    )
    run_parser.add_argument(
        "--storage-attestation",
        action="append",
        default=[],
        metavar="LABEL=PATH",
    )
    run_parser.add_argument("--mode", choices=("diagnostic", "final"), default="diagnostic")
    run_parser.add_argument("--operations", type=int, default=MIN_P999_OPERATIONS)
    run_parser.add_argument("--warmup-operations", type=int, default=1_000)
    run_parser.add_argument("--repetitions", type=int, default=MIN_FINAL_REPETITIONS)
    run_parser.add_argument(
        "--concurrencies",
        type=_parse_concurrencies,
        default=DEFAULT_CONCURRENCIES,
    )
    run_parser.add_argument("--seed", type=int, default=8675309)
    run_parser.add_argument(
        "--bootstrap-replicates",
        type=int,
        default=DEFAULT_BOOTSTRAP_REPLICATES,
    )
    run_parser.add_argument("--condition-timeout-seconds", type=int, default=3600)
    run_parser.add_argument(
        "--native-git-path",
        type=Path,
        help="explicit external native Git binary (requires tracked attestation)",
    )
    run_parser.add_argument(
        "--native-git-attestation",
        type=Path,
        help="canonical tracked attestation for --native-git-path",
    )

    worker_parser = subparsers.add_parser("_worker", help=argparse.SUPPRESS)
    worker_parser.add_argument("--spec", type=Path, required=True)
    worker_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "_worker":
        return worker_main(args.spec, args.output)

    attestations: dict[str, Path] = {}
    for value in args.storage_attestation:
        label, path = parse_attestation_argument(value)
        if label in attestations:
            parser.error(f"duplicate storage attestation for {label}")
        attestations[label] = path
    try:
        profiles = resolve_storage_profiles(args.storage_profile, attestations)
        result = run_benchmark(
            output_root=args.output_root,
            profiles=profiles,
            mode=args.mode,
            operations=args.operations,
            warmup_operations=args.warmup_operations,
            repetitions=args.repetitions,
            concurrencies=args.concurrencies,
            seed=args.seed,
            bootstrap_replicates=args.bootstrap_replicates,
            condition_timeout_seconds=args.condition_timeout_seconds,
            native_git_path=args.native_git_path,
            native_git_manifest_path=args.native_git_attestation,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(_canonical_json({"run_id": result["run_id"], "run_directory": result["run_directory"]}))
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
