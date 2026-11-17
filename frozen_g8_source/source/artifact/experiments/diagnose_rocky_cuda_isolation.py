#!/usr/bin/env python3
"""Run one allocation-only CUDA smoke inside the strict Rocky sandbox."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


COMMIT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[a-z0-9][a-z0-9_-]{7,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PROTOCOL_ID = "sluice-authenticated-local-runtime-v1"
UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z")
_IDENTITY_KEYS = frozenset({"device", "gid", "inode", "mode", "uid"})
_JSON_IDENTITY_KEYS = frozenset(
    {"device", "gid", "inode", "mode", "nlink", "size", "uid"}
)
_DESCRIPTOR_FILESYSTEM_KEYS = frozenset(
    {"filesystem_magic", "fsid", "mount_id", "statvfs_fsid"}
)
_MOUNT_KEYS = frozenset(
    {"filesystem", "mount_id", "mount_options", "mountpoint", "source", "super_options"}
)
_PROCFS_MOUNT_KEYS = frozenset((*_MOUNT_KEYS, "root"))
_INVENTORY_KEYS = frozenset(
    {
        "directories",
        "inventory_sha256",
        "mode_counts",
        "regular_bytes",
        "regular_files",
        "symlinks",
    }
)
_COPY_KEYS = frozenset(
    {"directories", "regular_bytes", "regular_files", "symlinks"}
)
_BOUNDARY_KEYS = frozenset(
    {
        "cuda_allocation_executed",
        "model_loaded",
        "principal_claims_permitted",
        "tokenizer_loaded",
        "vllm_imported",
    }
)
_STAGING_MANIFEST_KEYS = frozenset(
    {
        "atomic_rename_noreplace",
        "boundary",
        "copy_counts",
        "destination_base",
        "destination_descriptor_filesystem_after",
        "destination_descriptor_filesystem_before",
        "destination_mount_after",
        "destination_mount_before",
        "failure_path",
        "finished_utc",
        "hostname",
        "label",
        "manifest_path",
        "completion_path",
        "protocol_id",
        "published_identity",
        "published_path",
        "reused_existing",
        "run_id",
        "schema_version",
        "source_commit",
        "source_descriptor_filesystem_after",
        "source_descriptor_filesystem_before",
        "source_execution_sha256",
        "source_identity_after",
        "source_identity_before",
        "source_inventory",
        "source_mount_after",
        "source_mount_before",
        "source_path",
        "source_sha256",
        "source_timestamp_sha256",
        "source_timestamps_preserved",
        "source_treated_read_only",
        "started_utc",
        "status",
        "verified_execution",
    }
)
_COMPLETION_KEYS = frozenset(
    {
        "failure_path",
        "manifest_identity",
        "manifest_path",
        "manifest_sha256",
        "process_exit_status",
        "protocol_id",
        "run_id",
        "runtime",
        "source_commit",
        "status",
        "verified_execution_sha256",
    }
)
_RUNTIME_BINDING_KEYS = frozenset(
    {
        "destination_base",
        "execution_sha256",
        "published_identity",
        "published_path",
        "source_identity",
        "source_path",
        "timestamp_sha256",
        "tree_sha256",
    }
)
_FAILURE_KEYS = frozenset(
    {
        "bootstrap_end",
        "bootstrap_equal",
        "bootstrap_finalize_error",
        "bootstrap_start",
        "boundary",
        "completion_path",
        "error",
        "failure_path",
        "manifest_identity",
        "manifest_path",
        "manifest_published",
        "manifest_sha256",
        "manifest_valid",
        "phase",
        "process_exit_status",
        "protocol_id",
        "run_id",
        "runtime",
        "source_commit",
        "status",
    }
)
_STAGING_VERIFIED_MODULES = (
    "sluice_v2.rocky_gpu_isolation",
    "sluice_v2.runtime_staging",
    "experiments.stage_authenticated_runtime",
)


def _ensure_dependencies() -> tuple[object, object, object]:
    rocky = sys.modules.get("sluice_v2.rocky_gpu_isolation")
    staging = sys.modules.get("sluice_v2.runtime_staging")
    stage_driver = sys.modules.get("experiments.stage_authenticated_runtime")
    if rocky is None or staging is None or stage_driver is None:
        raise RuntimeError("authenticated diagnostic closure is incomplete")
    globals().update(
        {
            "AuthenticatedBind": rocky.AuthenticatedBind,
            "GPUDevice": rocky.GPUDevice,
            "ProtectedHostPaths": rocky.ProtectedHostPaths,
            "RockyGPUIsolationConfig": rocky.RockyGPUIsolationConfig,
            "assert_path_absent_authenticated": staging.assert_path_absent_authenticated,
            "canonical_config_sha256": rocky.canonical_config_sha256,
            "launch_rocky_gpu_isolation": rocky.launch_rocky_gpu_isolation,
            "read_json_authenticated_with_identity": staging.read_json_authenticated_with_identity,
            "read_regular_authenticated_with_identity": staging.read_regular_authenticated_with_identity,
            "sha256_file": rocky.sha256_file,
            "sha256_tree": rocky.sha256_tree,
            "write_json_create_only": staging.write_json_create_only,
        }
    )
    return rocky, staging, stage_driver


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


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


def _write_atomic_new(path: Path, wire: dict[str, object]) -> str:
    """Publish terminal evidence, recovering only the exact durable object."""

    expected_sha256 = hashlib.sha256(_canonical_json(wire)).hexdigest()
    try:
        observed_sha256 = write_json_create_only(path, wire)
    except BaseException:
        observed, observed_sha256, _identity = (
            read_json_authenticated_with_identity(path)
        )
        if observed != wire or observed_sha256 != expected_sha256:
            raise
    if observed_sha256 != expected_sha256:
        raise RuntimeError("diagnostic evidence publication digest mismatch")
    return observed_sha256


def _exact_object(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"{name} must have the exact frozen key set")
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


def _unsigned(value: object, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError(f"{name} must be an exact nonnegative integer")
    return value


def _canonical_path(value: object, name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or value.startswith("//")
        or ".." in path.parts
        or "\x00" in value
        or os.fspath(path) != value
    ):
        raise ValueError(f"{name} must be a canonical absolute path")
    return value


def _identity(value: object, name: str) -> dict[str, object]:
    wire = _exact_object(value, _IDENTITY_KEYS, name)
    for key in ("device", "gid", "mode", "uid"):
        _unsigned(wire[key], f"{name}.{key}")
    _unsigned(wire["inode"], f"{name}.inode", positive=True)
    if int(wire["mode"]) > 0o7777:
        raise ValueError(f"{name}.mode is outside the permission-bit range")
    return wire


def _json_identity(value: object, name: str) -> dict[str, object]:
    wire = _exact_object(value, _JSON_IDENTITY_KEYS, name)
    for key in ("device", "gid", "mode", "nlink", "size", "uid"):
        _unsigned(wire[key], f"{name}.{key}")
    _unsigned(wire["inode"], f"{name}.inode", positive=True)
    if wire["mode"] != 0o600 or wire["nlink"] != 1:
        raise ValueError(f"{name} must identify a private single-link file")
    return wire


def _descriptor_filesystem(
    value: object, name: str, expected_magic: str
) -> dict[str, object]:
    wire = _exact_object(value, _DESCRIPTOR_FILESYSTEM_KEYS, name)
    if (
        type(wire["filesystem_magic"]) is not str
        or re.fullmatch(r"[0-9a-f]{8}", wire["filesystem_magic"]) is None
        or wire["filesystem_magic"] != expected_magic
    ):
        raise ValueError(f"{name}.filesystem_magic is invalid")
    fsid = wire["fsid"]
    if (
        type(fsid) is not list
        or len(fsid) != 2
        or any(type(part) is not int or not -(1 << 31) <= part < (1 << 31) for part in fsid)
    ):
        raise ValueError(f"{name}.fsid must contain two exact signed 32-bit integers")
    _unsigned(wire["mount_id"], f"{name}.mount_id", positive=True)
    _unsigned(wire["statvfs_fsid"], f"{name}.statvfs_fsid")
    return wire


def _mount(value: object, name: str, filesystems: frozenset[str]) -> dict[str, object]:
    wire = _exact_object(value, _MOUNT_KEYS, name)
    if type(wire["filesystem"]) is not str or wire["filesystem"] not in filesystems:
        raise ValueError(f"{name}.filesystem is outside the frozen allowlist")
    _unsigned(wire["mount_id"], f"{name}.mount_id", positive=True)
    _canonical_path(wire["mountpoint"], f"{name}.mountpoint")
    if type(wire["source"]) is not str or not wire["source"]:
        raise ValueError(f"{name}.source must be a nonempty string")
    for key in ("mount_options", "super_options"):
        options = wire[key]
        if (
            type(options) is not list
            or any(type(option) is not str or not option for option in options)
            or options != sorted(set(options))
        ):
            raise ValueError(f"{name}.{key} must be unique sorted strings")
    return wire


def _procfs_mount(value: object, name: str) -> dict[str, object]:
    wire = _exact_object(value, _PROCFS_MOUNT_KEYS, name)
    if (
        wire["filesystem"] != "proc"
        or wire["mountpoint"] != "/proc"
        or wire["root"] != "/"
        or wire["source"] != "proc"
    ):
        raise ValueError(f"{name} is not the exact /proc mount")
    _unsigned(wire["mount_id"], f"{name}.mount_id", positive=True)
    for key in ("mount_options", "super_options"):
        options = wire[key]
        if (
            type(options) is not list
            or any(type(option) is not str or not option for option in options)
            or options != sorted(set(options))
        ):
            raise ValueError(f"{name}.{key} must be unique sorted strings")
    return wire


def _inventory(value: object) -> dict[str, object]:
    wire = _exact_object(value, _INVENTORY_KEYS, "source_inventory")
    for key in ("directories", "regular_bytes", "regular_files", "symlinks"):
        _unsigned(wire[key], f"source_inventory.{key}")
    if _unsigned(wire["directories"], "source_inventory.directories") < 1:
        raise ValueError("source_inventory must contain its root directory")
    if type(wire["inventory_sha256"]) is not str or SHA256.fullmatch(wire["inventory_sha256"]) is None:
        raise ValueError("source_inventory.inventory_sha256 is invalid")
    modes = wire["mode_counts"]
    if type(modes) is not dict or not modes:
        raise ValueError("source_inventory.mode_counts must be a nonempty object")
    for key, count in modes.items():
        if type(key) is not str or re.fullmatch(r"[DF]:[0-7]{4}", key) is None:
            raise ValueError("source_inventory.mode_counts has an invalid mode key")
        _unsigned(count, f"source_inventory.mode_counts.{key}", positive=True)
    directory_modes = sum(
        count for key, count in modes.items() if key.startswith("D:")
    )
    regular_file_modes = sum(
        count for key, count in modes.items() if key.startswith("F:")
    )
    if (
        directory_modes != wire["directories"]
        or regular_file_modes != wire["regular_files"]
    ):
        raise ValueError("source_inventory mode counts are not cross-bound")
    return wire


def _sha256(value: object, name: str) -> str:
    if type(value) is not str or SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be lowercase SHA-256")
    return value


def _file_identity(value: object, name: str) -> dict[str, object]:
    wire = _exact_object(value, _JSON_IDENTITY_KEYS, name)
    for key in ("device", "gid", "mode", "nlink", "size", "uid"):
        _unsigned(wire[key], f"{name}.{key}")
    _unsigned(wire["inode"], f"{name}.inode", positive=True)
    if wire["nlink"] != 1 or int(wire["mode"]) > 0o7777:
        raise ValueError(f"{name} must identify a single-link regular file")
    return wire


def _verified_execution(
    value: object, *, run_id: str, source_commit: str
) -> dict[str, object]:
    wire = _exact_object(value, frozenset({"end", "equal", "start"}), "verified execution")
    if wire["equal"] is not True or not _exact_json_equal(
        wire["start"], wire["end"]
    ):
        raise ValueError("verified execution start/end identity drifted")
    record_keys = frozenset(
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
    record = _exact_object(wire["start"], record_keys, "verified execution start")
    if record["run_id"] != run_id or record["source_commit"] != source_commit:
        raise ValueError("verified execution run/commit binding is invalid")
    _sha256(record["inline_loader_sha256"], "verified execution inline loader")
    for key in ("bootstrap", "closure_manifest"):
        item = _exact_object(
            record[key], frozenset({"identity", "path", "sha256"}), f"verified execution {key}"
        )
        _file_identity(item["identity"], f"verified execution {key}.identity")
        _canonical_path(item["path"], f"verified execution {key}.path")
        _sha256(item["sha256"], f"verified execution {key}.sha256")
    interpreter = _exact_object(
        record["interpreter"],
        frozenset({"identity", "path", "procfs_mount", "sha256"}),
        "verified execution interpreter",
    )
    _file_identity(
        interpreter["identity"], "verified execution interpreter.identity"
    )
    _canonical_path(interpreter["path"], "verified execution interpreter.path")
    _sha256(interpreter["sha256"], "verified execution interpreter.sha256")
    _procfs_mount(
        interpreter["procfs_mount"],
        "verified execution interpreter.procfs_mount",
    )
    closure = record["closure"]
    if type(closure) is not list or len(closure) != len(_STAGING_VERIFIED_MODULES):
        raise ValueError("verified execution closure has the wrong size")
    seen: set[str] = set()
    for index, raw in enumerate(closure):
        item = _exact_object(
            raw,
            frozenset({"identity", "module", "path", "sha256"}),
            f"verified execution closure[{index}]",
        )
        _file_identity(item["identity"], f"verified execution closure[{index}].identity")
        if type(item["module"]) is not str or re.fullmatch(
            r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+", item["module"]
        ) is None or item["module"] in seen or item["module"] != _STAGING_VERIFIED_MODULES[index]:
            raise ValueError("verified execution closure module is invalid")
        seen.add(item["module"])
        _canonical_path(item["path"], f"verified execution closure[{index}].path")
        _sha256(item["sha256"], f"verified execution closure[{index}].sha256")
    pycache = _exact_object(
        record["pycache"], frozenset({"empty", "identity", "path"}), "verified execution pycache"
    )
    if pycache["empty"] is not True:
        raise ValueError("verified execution pycache was not empty")
    _identity(pycache["identity"], "verified execution pycache.identity")
    _canonical_path(pycache["path"], "verified execution pycache.path")
    return wire


def _validated_bootstrap_finalize(
    value: object,
    *,
    bootstrap_start: dict[str, object],
    run_id: str,
    source_commit: str,
) -> dict[str, object]:
    wire = _verified_execution(
        value,
        run_id=run_id,
        source_commit=source_commit,
    )
    if not _exact_json_equal(wire["start"], bootstrap_start):
        raise ValueError("verified execution does not bind the bootstrap start")
    return wire


def _runtime_binding(
    value: object, *, runtime_root: Path, runtime_audit: dict[str, object]
) -> dict[str, object]:
    wire = _exact_object(value, _RUNTIME_BINDING_KEYS, "runtime binding")
    for key in ("destination_base", "published_path", "source_path"):
        _canonical_path(wire[key], f"runtime binding {key}")
    if wire["published_path"] != os.fspath(runtime_root):
        raise ValueError("runtime binding published path is invalid")
    _identity(wire["published_identity"], "runtime binding published_identity")
    _identity(wire["source_identity"], "runtime binding source_identity")
    for key, audit_key in (
        ("tree_sha256", "tree_sha256"),
        ("timestamp_sha256", "timestamp_sha256"),
        ("execution_sha256", "execution_sha256"),
    ):
        _sha256(wire[key], f"runtime binding {key}")
        if wire[key] != runtime_audit[audit_key]:
            raise ValueError(f"runtime binding {key} differs from the authenticated runtime")
    if wire["published_identity"] != runtime_audit["root_identity"]:
        raise ValueError("runtime binding published root identity differs")
    return wire


def _validate_failure_record(
    value: object,
    *,
    failure_path: Path,
    manifest_path: Path,
    run_id: str,
    source_commit: str,
) -> dict[str, object]:
    wire = _exact_object(value, _FAILURE_KEYS, "staging failure")
    if (
        wire["status"] != "failed_closed"
        or wire["protocol_id"] != PROTOCOL_ID
        or type(wire["process_exit_status"]) is not int
        or wire["process_exit_status"] != 1
        or wire["run_id"] != run_id
        or wire["source_commit"] != source_commit
        or wire["manifest_path"] != os.fspath(manifest_path)
        or wire["failure_path"] != os.fspath(failure_path)
        or wire["completion_path"] != os.fspath(manifest_path) + ".complete.json"
    ):
        raise ValueError("staging failure run/path/commit binding is invalid")
    if (
        type(wire["error"]) is not str
        or not wire["error"]
        or wire["phase"]
        not in {
            "bootstrap_finalize",
            "completion_publication",
            "manifest_publication",
            "preflight",
            "runtime_authentication",
        }
    ):
        raise ValueError("staging failure error/phase is invalid")
    boundary = _exact_object(wire["boundary"], _BOUNDARY_KEYS, "staging failure boundary")
    if any(item is not False for item in boundary.values()):
        raise ValueError("staging failure boundary is invalid")
    runtime = _exact_object(wire["runtime"], _RUNTIME_BINDING_KEYS, "staging failure runtime")
    null_runtime = all(item is None for item in runtime.values())
    full_runtime = all(item is not None for item in runtime.values())
    if not (null_runtime or full_runtime):
        raise ValueError("staging failure runtime binding is partial")
    if full_runtime:
        for key in ("destination_base", "published_path", "source_path"):
            _canonical_path(runtime[key], f"staging failure runtime.{key}")
        if Path(runtime["published_path"]).parent != Path(runtime["destination_base"]):
            raise ValueError("staging failure runtime destination binding is invalid")
        _identity(runtime["published_identity"], "staging failure runtime.published_identity")
        _identity(runtime["source_identity"], "staging failure runtime.source_identity")
        for key in ("execution_sha256", "timestamp_sha256", "tree_sha256"):
            _sha256(runtime[key], f"staging failure runtime.{key}")
    bootstrap_end = wire["bootstrap_end"]
    _verified_execution(
        {
            "end": wire["bootstrap_start"],
            "equal": True,
            "start": wire["bootstrap_start"],
        },
        run_id=run_id,
        source_commit=source_commit,
    )
    if wire["bootstrap_equal"] is True:
        if bootstrap_end is None or wire["bootstrap_finalize_error"] is not None:
            raise ValueError("staging failure bootstrap success fields are inconsistent")
        _verified_execution(
            {"end": bootstrap_end, "equal": True, "start": wire["bootstrap_start"]},
            run_id=run_id,
            source_commit=source_commit,
        )
    elif wire["bootstrap_equal"] is False:
        if wire["bootstrap_finalize_error"] is not None and (
            type(wire["bootstrap_finalize_error"]) is not str
            or not wire["bootstrap_finalize_error"]
        ):
            raise ValueError("staging failure bootstrap error is invalid")
        if bootstrap_end is not None:
            _verified_execution(
                {"end": bootstrap_end, "equal": True, "start": bootstrap_end},
                run_id=run_id,
                source_commit=source_commit,
            )
        if bootstrap_end == wire["bootstrap_start"] and wire["bootstrap_finalize_error"] is None:
            raise ValueError("staging failure bootstrap false binding is inconsistent")
    else:
        raise ValueError("staging failure bootstrap_equal must be exact Boolean")
    if wire["manifest_published"] is True:
        _sha256(wire["manifest_sha256"], "staging failure manifest_sha256")
        if wire["manifest_valid"] is True:
            _json_identity(wire["manifest_identity"], "staging failure manifest_identity")
        elif wire["manifest_valid"] is False:
            _file_identity(wire["manifest_identity"], "staging failure manifest_identity")
        else:
            raise ValueError("staging failure manifest_valid must be exact Boolean")
    elif wire["manifest_published"] is False:
        if wire["manifest_sha256"] is not None or wire["manifest_identity"] is not None or wire["manifest_valid"] is not False:
            raise ValueError("staging failure unpublished manifest fields are inconsistent")
    else:
        raise ValueError("staging failure manifest_published must be exact Boolean")
    return wire


def _assert_no_bound_failure(
    failure_path: Path,
    *,
    manifest_path: Path,
    run_id: str,
    source_commit: str,
) -> None:
    try:
        assert_path_absent_authenticated(failure_path)
        return
    except BaseException as absence_error:
        try:
            failure, _failure_sha256, _failure_identity = (
                read_json_authenticated_with_identity(failure_path)
            )
            validated = _validate_failure_record(
                failure,
                failure_path=failure_path,
                manifest_path=manifest_path,
                run_id=run_id,
                source_commit=source_commit,
            )
            if validated["manifest_published"] is True:
                if validated["manifest_valid"] is True:
                    _manifest, digest, identity = read_json_authenticated_with_identity(manifest_path)
                else:
                    digest, identity = read_regular_authenticated_with_identity(manifest_path)
                if digest != validated["manifest_sha256"] or identity != validated["manifest_identity"]:
                    raise ValueError("staging failure manifest identity cross-binding is invalid")
        except BaseException as validation_error:
            raise ValueError("staging failure sidecar is present but invalid") from validation_error
        raise ValueError("staging run has an authenticated bound failure record") from absence_error


def _validate_staging_manifest_schema(
    wire: object,
    *,
    manifest_path: Path,
    runtime_root: Path,
    runtime_audit: dict[str, object],
    run_id: str,
    source_commit: str,
) -> dict[str, object]:
    manifest = _exact_object(wire, _STAGING_MANIFEST_KEYS, "staging manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("staging manifest schema_version is invalid")
    if manifest["protocol_id"] != PROTOCOL_ID or manifest["status"] != "published":
        raise ValueError("staging manifest protocol/status is invalid")
    for key in (
        "atomic_rename_noreplace",
        "source_timestamps_preserved",
        "source_treated_read_only",
    ):
        if manifest[key] is not True:
            raise ValueError(f"staging manifest {key} must be true")
    if type(manifest["reused_existing"]) is not bool:
        raise ValueError("staging manifest reused_existing must be boolean")
    if (
        type(manifest["run_id"]) is not str
        or manifest["run_id"] != run_id
        or RUN_ID.fullmatch(manifest["run_id"]) is None
    ):
        raise ValueError("staging manifest run_id is invalid")
    if (
        type(manifest["source_commit"]) is not str
        or manifest["source_commit"] != source_commit
        or COMMIT.fullmatch(manifest["source_commit"]) is None
    ):
        raise ValueError("staging manifest source_commit is invalid")
    if (
        type(manifest["source_sha256"]) is not str
        or manifest["source_sha256"] != runtime_audit["tree_sha256"]
        or SHA256.fullmatch(manifest["source_sha256"]) is None
    ):
        raise ValueError("staging manifest source_sha256 is invalid")
    published_path = _canonical_path(manifest["published_path"], "published_path")
    destination_base = _canonical_path(manifest["destination_base"], "destination_base")
    _canonical_path(manifest["source_path"], "source_path")
    if published_path != os.fspath(runtime_root) or Path(published_path).parent != Path(destination_base):
        raise ValueError("staging manifest published path identity is invalid")
    authenticated_manifest_path = _canonical_path(
        os.fspath(manifest_path), "authenticated manifest path"
    )
    embedded_manifest_path = _canonical_path(
        manifest["manifest_path"], "manifest_path"
    )
    completion_path = _canonical_path(
        manifest["completion_path"], "completion_path"
    )
    failure_path = _canonical_path(manifest["failure_path"], "failure_path")
    if (
        embedded_manifest_path != authenticated_manifest_path
        or completion_path != authenticated_manifest_path + ".complete.json"
        or failure_path != authenticated_manifest_path + ".failure.json"
    ):
        raise ValueError("staging evidence paths do not bind the authenticated manifest")
    if type(manifest["label"]) is not str or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", manifest["label"]) is None:
        raise ValueError("staging manifest label is invalid")
    if type(manifest["hostname"]) is not str or re.fullmatch(r"[A-Za-z0-9._-]{1,255}", manifest["hostname"]) is None:
        raise ValueError("staging manifest hostname is invalid")
    for key in ("started_utc", "finished_utc"):
        if type(manifest[key]) is not str or UTC.fullmatch(manifest[key]) is None:
            raise ValueError(f"staging manifest {key} is invalid")
    if str(manifest["started_utc"]) > str(manifest["finished_utc"]):
        raise ValueError("staging manifest timestamps are reversed")
    source_before = _identity(manifest["source_identity_before"], "source_identity_before")
    source_after = _identity(manifest["source_identity_after"], "source_identity_after")
    if source_before != source_after:
        raise ValueError("staging manifest source identity drifted")
    _identity(manifest["published_identity"], "published_identity")
    source_mount_before = _mount(manifest["source_mount_before"], "source_mount_before", frozenset({"nfs", "nfs4"}))
    source_mount_after = _mount(manifest["source_mount_after"], "source_mount_after", frozenset({"nfs", "nfs4"}))
    destination_mount_before = _mount(manifest["destination_mount_before"], "destination_mount_before", frozenset({"xfs"}))
    destination_mount_after = _mount(manifest["destination_mount_after"], "destination_mount_after", frozenset({"xfs"}))
    source_descriptor_before = _descriptor_filesystem(
        manifest["source_descriptor_filesystem_before"],
        "source_descriptor_filesystem_before",
        "00006969",
    )
    source_descriptor_after = _descriptor_filesystem(
        manifest["source_descriptor_filesystem_after"],
        "source_descriptor_filesystem_after",
        "00006969",
    )
    destination_descriptor_before = _descriptor_filesystem(
        manifest["destination_descriptor_filesystem_before"],
        "destination_descriptor_filesystem_before",
        "58465342",
    )
    destination_descriptor_after = _descriptor_filesystem(
        manifest["destination_descriptor_filesystem_after"],
        "destination_descriptor_filesystem_after",
        "58465342",
    )
    if (
        source_descriptor_before != source_descriptor_after
        or destination_descriptor_before != destination_descriptor_after
        or source_mount_before != source_mount_after
        or destination_mount_before != destination_mount_after
        or source_mount_before["mount_id"] != source_descriptor_before["mount_id"]
        or destination_mount_before["mount_id"] != destination_descriptor_before["mount_id"]
    ):
        raise ValueError("staging manifest descriptor filesystem identity drifted")
    inventory = _inventory(manifest["source_inventory"])
    audit_inventory = _inventory(runtime_audit.get("inventory"))
    if not _exact_json_equal(inventory, audit_inventory):
        raise ValueError("source_inventory differs from the authenticated runtime")
    copied = _exact_object(manifest["copy_counts"], _COPY_KEYS, "copy_counts")
    for key in _COPY_KEYS:
        _unsigned(copied[key], f"copy_counts.{key}")
        if copied[key] != inventory[key]:
            raise ValueError("copy_counts differs from source_inventory")
    boundary = _exact_object(manifest["boundary"], _BOUNDARY_KEYS, "boundary")
    if any(value is not False for value in boundary.values()):
        raise ValueError("staging manifest boundary must remain entirely false")
    for key, audit_key in (
        ("source_sha256", "tree_sha256"),
        ("source_timestamp_sha256", "timestamp_sha256"),
        ("source_execution_sha256", "execution_sha256"),
    ):
        _sha256(manifest[key], f"staging manifest {key}")
        if manifest[key] != runtime_audit[audit_key]:
            raise ValueError(f"staging manifest {key} differs from runtime audit")
    if manifest["published_identity"] != runtime_audit["root_identity"]:
        raise ValueError("staging manifest published identity differs from runtime audit")
    _verified_execution(manifest["verified_execution"], run_id=run_id, source_commit=source_commit)
    return manifest


def _load_staging_manifest(
    path: Path,
    *,
    runtime_root: Path,
    runtime_audit: dict[str, object],
    run_id: str,
    source_commit: str,
) -> tuple[dict[str, object], str, str]:
    _ensure_dependencies()
    if type(run_id) is not str or RUN_ID.fullmatch(run_id) is None:
        raise ValueError("requested staging run_id is invalid")
    canonical_manifest = Path(_canonical_path(os.fspath(path), "staging manifest path"))
    failure_path = canonical_manifest.with_name(canonical_manifest.name + ".failure.json")
    _assert_no_bound_failure(
        failure_path,
        manifest_path=canonical_manifest,
        run_id=run_id,
        source_commit=source_commit,
    )
    wire, manifest_sha256, manifest_identity = read_json_authenticated_with_identity(
        canonical_manifest
    )
    validated = _validate_staging_manifest_schema(
        wire,
        manifest_path=canonical_manifest,
        runtime_root=runtime_root,
        runtime_audit=runtime_audit,
        run_id=run_id,
        source_commit=source_commit,
    )
    completion_path = canonical_manifest.with_name(canonical_manifest.name + ".complete.json")
    completion, completion_sha256, completion_identity = (
        read_json_authenticated_with_identity(completion_path)
    )
    commit = _exact_object(completion, _COMPLETION_KEYS, "staging completion")
    if (
        commit["protocol_id"] != PROTOCOL_ID
        or commit["status"] != "committed"
        or commit["run_id"] != run_id
        or commit["source_commit"] != source_commit
        or commit["process_exit_status"] != 0
        or type(commit["process_exit_status"]) is not int
        or commit["manifest_path"] != os.fspath(canonical_manifest)
        or commit["failure_path"] != os.fspath(failure_path)
        or commit["manifest_sha256"] != manifest_sha256
        or _json_identity(
            commit["manifest_identity"], "completion.manifest_identity"
        )
        != manifest_identity
    ):
        raise ValueError("staging completion identity is invalid")
    runtime_binding = _runtime_binding(commit["runtime"], runtime_root=runtime_root, runtime_audit=runtime_audit)
    expected_verified_sha256 = hashlib.sha256(
        (json.dumps(validated["verified_execution"], allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    ).hexdigest()
    if commit["verified_execution_sha256"] != expected_verified_sha256:
        raise ValueError("staging completion verified-execution binding is invalid")
    if runtime_binding != {
        "destination_base": validated["destination_base"],
        "execution_sha256": validated["source_execution_sha256"],
        "published_identity": validated["published_identity"],
        "published_path": validated["published_path"],
        "source_identity": validated["source_identity_after"],
        "source_path": validated["source_path"],
        "timestamp_sha256": validated["source_timestamp_sha256"],
        "tree_sha256": validated["source_sha256"],
    }:
        raise ValueError("staging completion runtime cross-binding is invalid")
    wire_after, manifest_sha256_after, manifest_identity_after = (
        read_json_authenticated_with_identity(canonical_manifest)
    )
    completion_after, completion_sha256_after, completion_identity_after = (
        read_json_authenticated_with_identity(completion_path)
    )
    if (
        wire_after != wire
        or manifest_sha256_after != manifest_sha256
        or manifest_identity_after != manifest_identity
        or completion_after != completion
        or completion_sha256_after != completion_sha256
        or completion_identity_after != completion_identity
    ):
        raise ValueError("staging manifest/completion changed across cross-binding")
    _assert_no_bound_failure(
        failure_path,
        manifest_path=canonical_manifest,
        run_id=run_id,
        source_commit=source_commit,
    )
    return validated, manifest_sha256, completion_sha256


def _host_gpu_identity() -> dict[str, object]:
    command = [
        "/usr/bin/nvidia-smi",
        "--id=0",
        "--query-gpu=uuid,name,memory.total,driver_version,pci.bus_id,compute_cap",
        "--format=csv,noheader,nounits",
    ]
    completed = subprocess.run(
        command,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30.0,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    lines = tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())
    if len(lines) != 1:
        raise RuntimeError("nvidia-smi did not return exactly one selected GPU")
    fields = tuple(value.strip() for value in lines[0].split(","))
    if len(fields) != 6:
        raise RuntimeError("nvidia-smi selected-GPU schema is invalid")
    uuid, name, memory_mib, driver_release, pci_bus_id, compute_capability = fields
    if (
        re.fullmatch(
            r"GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            uuid,
        )
        is None
        or not name
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", driver_release) is None
        or re.fullmatch(r"[0-9A-Fa-f]{8}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]", pci_bus_id)
        is None
        or re.fullmatch(r"[0-9]+\.[0-9]+", compute_capability) is None
    ):
        raise RuntimeError("nvidia-smi returned a malformed selected-GPU identity")
    try:
        total_memory_bytes = int(memory_mib) * 1024 * 1024
    except ValueError as exc:
        raise RuntimeError("nvidia-smi memory total is not integral MiB") from exc
    if total_memory_bytes <= 0:
        raise RuntimeError("nvidia-smi returned a nonpositive memory total")
    return {
        "compute_capability": compute_capability,
        "driver_release": driver_release,
        "index": 0,
        "memory_total_bytes": total_memory_bytes,
        "name": name,
        "pci_bus_id": pci_bus_id,
        "uuid": uuid.lower().replace("gpu-", "GPU-", 1),
    }


def _validate_identity(
    host: dict[str, object], diagnostic: dict[str, object]
) -> dict[str, bool]:
    memory_difference = int(host["memory_total_bytes"]) - int(
        diagnostic["device_total_memory_bytes"]
    )
    checks = {
        "cuda_driver_api_reported": int(diagnostic["cuda_driver_api_version"]) > 0,
        "device_name_matches": diagnostic["device_name"] == host["name"],
        "device_uuid_matches": str(diagnostic["device_uuid"]).lower()
        == str(host["uuid"]).lower(),
        "memory_matches_with_ecc_bound": 0 <= memory_difference <= 2 * 1024**3,
        "tensor_freed": diagnostic["allocated_after_bytes"]
        == diagnostic["allocated_before_bytes"],
    }
    if not all(checks.values()):
        raise RuntimeError("isolated CUDA identity differs from the selected host GPU")
    return checks


def main() -> int:
    bootstrap_start = globals().get("VERIFIED_BOOTSTRAP_START")
    bootstrap_finalize = globals().get("VERIFIED_BOOTSTRAP_FINALIZE")
    if type(bootstrap_start) is not dict or not callable(bootstrap_finalize):
        raise RuntimeError("CUDA diagnostic requires verified bootstrap execution")
    rocky, staging, _stage_driver = _ensure_dependencies()
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--libcuda", type=Path, required=True)
    parser.add_argument("--libptxjit", type=Path, required=True)
    parser.add_argument("--staging-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-commit", required=True)
    arguments = parser.parse_args()
    if COMMIT.fullmatch(arguments.source_commit) is None:
        parser.error("--source-commit must be exactly 40 lowercase hex characters")
    if RUN_ID.fullmatch(arguments.run_id) is None:
        parser.error("--run-id is invalid")
    if bootstrap_start.get("run_id") != arguments.run_id or bootstrap_start.get("source_commit") != arguments.source_commit:
        parser.error("verified bootstrap does not bind the requested run/commit")
    try:
        _verified_execution(
            {"end": bootstrap_start, "equal": True, "start": bootstrap_start},
            run_id=arguments.run_id,
            source_commit=arguments.source_commit,
        )
    except ValueError as exc:
        parser.error(f"verified bootstrap start is invalid: {exc}")
    runtime_root = Path(_canonical_path(os.fspath(arguments.runtime_root), "runtime root"))
    libcuda = Path(_canonical_path(os.fspath(arguments.libcuda), "libcuda"))
    libptxjit = Path(_canonical_path(os.fspath(arguments.libptxjit), "libptxjit"))
    output = Path(_canonical_path(os.fspath(arguments.output), "diagnostic output"))
    started = _utc_now()
    print("hashing authenticated CUDA runtime", flush=True)
    runtime_audit = staging.audit_runtime_execution(
        runtime_root, require_single_link_files=True
    )
    runtime_sha256 = runtime_audit["tree_sha256"]
    print(json.dumps({"runtime_execution_sha256": runtime_audit["execution_sha256"], "runtime_sha256": runtime_sha256, "runtime_timestamp_sha256": runtime_audit["timestamp_sha256"]}, sort_keys=True), flush=True)
    (
        staging_manifest,
        staging_manifest_sha256,
        staging_completion_sha256,
    ) = _load_staging_manifest(
        arguments.staging_manifest,
        runtime_root=runtime_root,
        runtime_audit=runtime_audit,
        run_id=arguments.run_id,
        source_commit=arguments.source_commit,
    )
    host_gpu_identity = _host_gpu_identity()

    with tempfile.TemporaryDirectory(prefix="sluice-rocky-cuda-", dir="/tmp") as raw_work:
        work = Path(raw_work)
        source = work / "source"
        cache = work / "cache"
        private = work / "private"
        home = work / "home"
        for directory in (source, cache, private, home):
            directory.mkdir(mode=0o700)
        (source / "source.probe").write_bytes(b"public-source")
        (cache / "cache.probe").write_bytes(b"public-cache")
        canaries = {}
        for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
            path = private / name
            path.write_bytes(f"private-{name}".encode("ascii"))
            path.chmod(0o600)
            canaries[name] = path
        home_canary = home / "private-home-canary"
        home_canary.write_bytes(b"private-home")
        home_canary.chmod(0o600)
        binds = (
            AuthenticatedBind(
                label="runtime",
                category="runtime",
                source=runtime_root,
                target="/opt/sluice/runtime",
                expected_sha256=runtime_sha256,
                probe_relative="bin/python",
                allow_exec=True,
            ),
            AuthenticatedBind(
                label="model_source",
                category="model_source",
                source=source,
                target="/opt/sluice/model_source",
                expected_sha256=sha256_tree(source),
                probe_relative="source.probe",
                allow_exec=False,
            ),
            AuthenticatedBind(
                label="model_cache",
                category="model_cache",
                source=cache,
                target="/opt/sluice/model_cache",
                expected_sha256=sha256_tree(cache),
                probe_relative="cache.probe",
                allow_exec=False,
            ),
            AuthenticatedBind(
                label="libcuda",
                category="support",
                source=libcuda,
                target="/opt/sluice/support/libcuda.so.1",
                expected_sha256=sha256_file(libcuda),
                probe_relative=".",
                allow_exec=True,
            ),
            AuthenticatedBind(
                label="libptxjit",
                category="support",
                source=libptxjit,
                target="/opt/sluice/support/libnvidia-ptxjitcompiler.so.1",
                expected_sha256=sha256_file(libptxjit),
                probe_relative=".",
                allow_exec=True,
            ),
        )
        config = RockyGPUIsolationConfig.strict(
            binds=binds,
            devices=tuple(
                GPUDevice.from_host(Path(value))
                for value in ("/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia0")
            ),
            protected_host_paths=ProtectedHostPaths(
                shared_home=home_canary,
                ledger=canaries["ledger"],
                signing_key=canaries["signing_key"],
                tool_credential=canaries["tool_credential"],
                raw_audit=canaries["raw_audit"],
            ),
            worker_source_sha256=next(
                item["sha256"]
                for item in bootstrap_start["closure"]
                if item["module"] == "sluice_v2.rocky_gpu_isolation"
            ),
            interpreter_sha256=bootstrap_start["interpreter"]["sha256"],
            workload_environment={
                "CUDA_VISIBLE_DEVICES": "0",
                "HF_HUB_OFFLINE": "1",
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/opt/sluice/runtime/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPYCACHEPREFIX": f"/tmp/sluice-pycache-{arguments.run_id}",
                "PYTHONHASHSEED": "0",
                "TOKENIZERS_PARALLELISM": "false",
                "TRANSFORMERS_OFFLINE": "1",
            },
            root_parent=Path("/tmp"),
            startup_timeout_seconds=1800.0,
            allow_cuda_diagnostic=True,
            cuda_preload_paths=(
                "/opt/sluice/support/libnvidia-ptxjitcompiler.so.1",
                "/opt/sluice/support/libcuda.so.1",
            ),
        )
        print("launching denial-gated allocation-only worker", flush=True)
        with launch_rocky_gpu_isolation(config) as run:
            start_attestation = run.attestation.to_wire()
            diagnostic = run.cuda_allocation_diagnostic()
        identity_checks = _validate_identity(host_gpu_identity, diagnostic)
        if run.final_attestation is None:
            raise RuntimeError("strict worker did not return a final digest attestation")
        finalized = bootstrap_finalize()
        try:
            verified_execution = _validated_bootstrap_finalize(
                finalized,
                bootstrap_start=bootstrap_start,
                run_id=arguments.run_id,
                source_commit=arguments.source_commit,
            )
        except ValueError as exc:
            raise RuntimeError(
                "CUDA diagnostic verified execution identity drifted"
            ) from exc
        wire: dict[str, object] = {
            "attestation": start_attestation,
            "config_sha256": canonical_config_sha256(config),
            "cuda_diagnostic": diagnostic,
            "host_gpu_identity": host_gpu_identity,
            "identity_checks": identity_checks,
            "evidence_boundary": {
                "allocation_only": True,
                "benchmark_executed": False,
                "model_loaded": False,
                "principal_claims_permitted": False,
                "tokenizer_loaded": False,
                "vllm_imported": False,
                "vllm_server_started": False,
            },
            "final_attestation": run.final_attestation,
            "finished_utc": _utc_now(),
            "runtime_sha256": runtime_sha256,
            "runtime_execution_sha256": runtime_audit["execution_sha256"],
            "runtime_timestamp_sha256": runtime_audit["timestamp_sha256"],
            "run_id": arguments.run_id,
            "schema_version": 1,
            "source_commit": arguments.source_commit,
            "verified_execution": verified_execution,
            "staging_manifest": {
                "completion_path": os.fspath(
                    arguments.staging_manifest.with_name(
                        arguments.staging_manifest.name + ".complete.json"
                    )
                ),
                "completion_sha256": staging_completion_sha256,
                "hostname": staging_manifest["hostname"],
                "path": os.fspath(arguments.staging_manifest),
                "sha256": staging_manifest_sha256,
                "source_sha256": staging_manifest["source_sha256"],
            },
            "started_utc": started,
        }
        serialized = json.dumps(wire, sort_keys=True)
        for path in config.protected_host_paths.as_mapping().values():
            if os.fspath(path) in serialized or path.read_text(encoding="ascii") in serialized:
                raise RuntimeError("CUDA evidence contains protected path material")
    _write_atomic_new(output, wire)
    try:
        print(
            json.dumps(
                {
                    "cuda_allocation": "passed",
                    "hostname": start_attestation["hostname"],
                    "model_loaded": False,
                    "output": os.fspath(output),
                    "principal_claims_permitted": False,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    except BaseException:
        return 0
    return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
