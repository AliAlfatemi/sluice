#!/usr/bin/env python3
"""Create and authenticate C5 node-wrapper completion attestations.

The model runner writes its receipt before control returns to the node shell.
That receipt therefore cannot attest that the shell later archived the server
log, contained the whole server process group, removed scratch, and observed a
final empty GPU process list.  This module supplies that final, create-only
wrapper boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any, Callable, Mapping, Sequence


SCHEMA = "sluice_agentdojo_c5_wrapper_completion/1"
CLEANUP_SCHEMA = "sluice_agentdojo_c5_wrapper_cleanup/1"
C5_RUN_ID = "sluice-agentdojo-c15-20260824-95f6a3dcdf56493bac934494ff3af39d"
EXPECTED_VLLM_VERSION = "0.6.4.post1"
NFS_VISIBILITY_TIMEOUT_SECONDS = 300.0
NFS_VISIBILITY_POLL_SECONDS = 0.25
PREFLIGHT_DIRECTORY = Path("policy_preflight/wrapper_completions")
EXECUTION_DIRECTORY = Path("wrapper_completions")
PREFLIGHT_CLEANUP_DIRECTORY = Path(
    "policy_preflight/wrapper_cleanup_attestations"
)
EXECUTION_CLEANUP_DIRECTORY = Path("wrapper_cleanup_attestations")

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^a(?:[0-9]|[1-9][0-9])$")
_NODE = re.compile(r"^node00[1-3]$")
_PLAN_ID = re.compile(r"^c4full_[A-Za-z0-9._-]+$")
_UTC = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

WRAPPER_STATE_FIELDS = {
    "schema",
    "c4_run_id",
    "expected_run_head",
    "expected_c4_manifest_sha256",
    "expected_wrapper_sha256",
    "expected_payload_sha256",
    "phase",
    "plan_id",
    "plan_sha256",
    "attempt",
    "node_argument",
    "physical_gpu_index",
    "receipt_path",
    "receipt_sha256",
    "server_log_path",
    "server_log_sha256",
    "server_log_bytes",
    "payload_rc",
    "wrapper_rc",
    "server_process_group_cleanup_ok",
    "server_process_group_shell_intervention",
    "server_log_archive_ok",
    "scratch_removed",
    "final_gpu_compute_process_probe",
    "finalized_utc",
}
ATTESTATION_FIELDS = WRAPPER_STATE_FIELDS | {
    "cleanup_attestation_path",
    "cleanup_attestation_sha256",
    "dispatcher_observed_wrapper_rc",
    "wrapper_exit_observed_by_dispatcher",
}
PROBE_FIELDS = {
    "command",
    "returncode",
    "stdout",
    "stderr",
    "query_succeeded",
    "no_compute_processes",
}


class WrapperCompletionError(RuntimeError):
    """Raised when wrapper completion is absent, red, or not fully bound."""


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WrapperCompletionError(f"noncanonical wrapper value: {exc}") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _regular_file_bytes(path: Path, label: str) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise WrapperCompletionError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise WrapperCompletionError(
            f"{label} is not a regular non-symlink file: {path}"
        )
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        # NFS may invalidate a just-observed directory entry before open(2).
        # Preserve the exact missing-file class so only the dispatcher wait can
        # recognize this as visibility-related; all other callers still fail.
        raise WrapperCompletionError(f"missing {label}: {path}") from exc


def _regular_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise WrapperCompletionError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise WrapperCompletionError(
            f"{label} is not a non-symlink directory: {path}"
        )


def _unique_json_object(raw: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise WrapperCompletionError(f"duplicate {label} key: {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WrapperCompletionError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise WrapperCompletionError(f"{label} is not a JSON object")
    return value


def _root_relative(root: Path, path: Path, label: str) -> str:
    root_absolute = root.absolute()
    path_absolute = path.absolute()
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise WrapperCompletionError(f"{label} escapes the run root") from exc
    if not relative.parts or ".." in relative.parts:
        raise WrapperCompletionError(f"invalid {label} relative path")
    return relative.as_posix()


def _expected_receipt_relative(
    *, phase: str, plan_id: str, attempt: str, node: str, gpu: str, receipt: Path
) -> str:
    if phase == "policy_preflight":
        if attempt != "a0":
            raise WrapperCompletionError("policy preflight attempt is not a0")
        expected = f"policy_preflight/receipts/policy_preflight_{plan_id}.json"
    elif phase == "execute":
        prefix = f"{node}_gpu{gpu}_"
        if not receipt.name.startswith(prefix) or not receipt.name.endswith(
            f"_{attempt}.json"
        ):
            raise WrapperCompletionError("execution receipt filename binding mismatch")
        expected = f"receipts/{receipt.name}"
    else:
        raise WrapperCompletionError(f"invalid wrapper phase: {phase!r}")
    return expected


def attestation_relative_path(
    *, phase: str, plan_id: str, receipt_path: Path
) -> Path:
    if phase == "policy_preflight":
        return PREFLIGHT_DIRECTORY / f"wrapper_completion_{plan_id}.json"
    if phase == "execute":
        return EXECUTION_DIRECTORY / f"wrapper_completion_{receipt_path.stem}.json"
    raise WrapperCompletionError(f"invalid wrapper phase: {phase!r}")


def cleanup_relative_path(
    *, phase: str, plan_id: str, receipt_path: Path
) -> Path:
    if phase == "policy_preflight":
        return (
            PREFLIGHT_CLEANUP_DIRECTORY
            / f"wrapper_cleanup_{plan_id}.json"
        )
    if phase == "execute":
        return (
            EXECUTION_CLEANUP_DIRECTORY
            / f"wrapper_cleanup_{receipt_path.stem}.json"
        )
    raise WrapperCompletionError(f"invalid wrapper phase: {phase!r}")


def final_gpu_command(gpu: str) -> list[str]:
    if gpu not in {"0", "1"}:
        raise WrapperCompletionError(f"invalid physical GPU index: {gpu!r}")
    return [
        "/usr/bin/nvidia-smi",
        f"--id={gpu}",
        "--query-compute-apps=pid",
        "--format=csv,noheader",
    ]


def probe_final_gpu(
    gpu: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    command = final_gpu_command(gpu)
    completed = run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=30,
        check=False,
    )
    try:
        stdout = completed.stdout.decode("ascii")
        stderr = completed.stderr.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WrapperCompletionError("non-ASCII final nvidia-smi response") from exc
    query_succeeded = completed.returncode == 0
    no_processes = query_succeeded and stdout.strip() == ""
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "query_succeeded": query_succeeded,
        "no_compute_processes": no_processes,
    }


def _validate_probe(probe: Mapping[str, Any], gpu: str) -> dict[str, Any]:
    if set(probe) != PROBE_FIELDS:
        raise WrapperCompletionError("final GPU probe fields mismatch")
    expected_command = final_gpu_command(gpu)
    if (
        probe.get("command") != expected_command
        or type(probe.get("returncode")) is not int
        or probe.get("returncode") != 0
        or probe.get("stdout") != ""
        or probe.get("stderr") != ""
        or probe.get("query_succeeded") is not True
        or probe.get("no_compute_processes") is not True
    ):
        raise WrapperCompletionError("final GPU query did not prove zero processes")
    return dict(probe)


def validate_vllm_versions(module_version: str, distribution_version: str) -> str:
    """Fail unless both independent version surfaces equal the frozen pin."""

    if module_version != EXPECTED_VLLM_VERSION:
        raise WrapperCompletionError(
            f"vllm.__version__={module_version!r}, expected {EXPECTED_VLLM_VERSION!r}"
        )
    if distribution_version != EXPECTED_VLLM_VERSION:
        raise WrapperCompletionError(
            "installed vllm distribution version="
            f"{distribution_version!r}, expected {EXPECTED_VLLM_VERSION!r}"
        )
    return EXPECTED_VLLM_VERSION


def build_wrapper_cleanup(
    *,
    root: Path,
    phase: str,
    plan_path: Path,
    receipt_path: Path,
    server_log_path: Path,
    attempt: str,
    node: str,
    gpu: str,
    expected_head: str,
    expected_manifest: str,
    expected_wrapper: str,
    expected_payload: str,
    payload_rc: int,
    wrapper_rc: int,
    cleanup_ok: bool,
    intervention: bool,
    log_archive_ok: bool,
    scratch_removed: bool,
    final_gpu_probe: Mapping[str, Any],
    finalized_utc: str,
) -> dict[str, Any]:
    """Build a post-cleanup handoff, refusing every nonterminal state."""

    _regular_directory(root, "run root")
    if _HEX_40.fullmatch(expected_head) is None:
        raise WrapperCompletionError("malformed expected run HEAD")
    for value, label in (
        (expected_manifest, "manifest"),
        (expected_wrapper, "wrapper"),
        (expected_payload, "payload"),
    ):
        if _HEX_64.fullmatch(value) is None:
            raise WrapperCompletionError(f"malformed expected {label} digest")
    if _ATTEMPT.fullmatch(attempt) is None:
        raise WrapperCompletionError("malformed attempt")
    if _NODE.fullmatch(node) is None:
        raise WrapperCompletionError("malformed node")
    if not isinstance(finalized_utc, str) or _UTC.fullmatch(finalized_utc) is None:
        raise WrapperCompletionError("malformed finalization timestamp")
    if type(payload_rc) is not int or payload_rc != 0:
        raise WrapperCompletionError("payload_rc is not zero")
    if type(wrapper_rc) is not int or wrapper_rc != 0:
        raise WrapperCompletionError("wrapper_rc is not zero")
    if cleanup_ok is not True:
        raise WrapperCompletionError("server process-group cleanup did not succeed")
    if intervention is not False:
        raise WrapperCompletionError("shell intervention invalidates green completion")
    if log_archive_ok is not True:
        raise WrapperCompletionError("server-log archive did not succeed")
    if scratch_removed is not True:
        raise WrapperCompletionError("local scratch was not removed")
    probe = _validate_probe(final_gpu_probe, gpu)

    plan_raw = _regular_file_bytes(plan_path, "plan")
    plan = _unique_json_object(plan_raw, "plan")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
        raise WrapperCompletionError("plan ID is malformed")
    plan_sha256 = sha256_bytes(plan_raw)

    receipt_raw = _regular_file_bytes(receipt_path, "runner receipt")
    receipt = _unique_json_object(receipt_raw, "runner receipt")
    receipt_relative = _root_relative(root, receipt_path, "runner receipt")
    expected_receipt = _expected_receipt_relative(
        phase=phase,
        plan_id=plan_id,
        attempt=attempt,
        node=node,
        gpu=gpu,
        receipt=receipt_path,
    )
    if receipt_relative != expected_receipt:
        raise WrapperCompletionError("runner receipt path is noncanonical")

    if not (
        receipt.get("c4_run_id") == C5_RUN_ID == plan.get("c4_run_id")
        and receipt.get("phase") == phase
        and receipt.get("plan_id") == plan_id
        and receipt.get("plan_sha256") == plan_sha256
        and receipt.get("node_argument") == node
        and str(receipt.get("physical_gpu_index")) == gpu
        and receipt.get("expected_run_head") == expected_head
        and receipt.get("expected_c4_manifest_sha256") == expected_manifest
        and receipt.get("expected_wrapper_sha256") == expected_wrapper
        and receipt.get("expected_payload_sha256") == expected_payload
        and receipt.get("error") is None
        and receipt.get("all_required_gates_true") is True
        and receipt.get("all_gates_true") is True
    ):
        raise WrapperCompletionError("runner receipt is not green or wrapper-bound")

    log_raw = _regular_file_bytes(server_log_path, "archived server log")
    log_relative = _root_relative(root, server_log_path, "archived server log")
    if not (
        receipt.get("server_log_expected_archive_relative") == log_relative
        and receipt.get("server_log_file_sha256") == sha256_bytes(log_raw)
        and receipt.get("server_log_bytes") == len(log_raw)
    ):
        raise WrapperCompletionError("archived server log disagrees with receipt")

    return {
        "schema": CLEANUP_SCHEMA,
        "c4_run_id": C5_RUN_ID,
        "expected_run_head": expected_head,
        "expected_c4_manifest_sha256": expected_manifest,
        "expected_wrapper_sha256": expected_wrapper,
        "expected_payload_sha256": expected_payload,
        "phase": phase,
        "plan_id": plan_id,
        "plan_sha256": plan_sha256,
        "attempt": attempt,
        "node_argument": node,
        "physical_gpu_index": gpu,
        "receipt_path": receipt_relative,
        "receipt_sha256": sha256_bytes(receipt_raw),
        "server_log_path": log_relative,
        "server_log_sha256": sha256_bytes(log_raw),
        "server_log_bytes": len(log_raw),
        "payload_rc": payload_rc,
        "wrapper_rc": wrapper_rc,
        "server_process_group_cleanup_ok": cleanup_ok,
        "server_process_group_shell_intervention": intervention,
        "server_log_archive_ok": log_archive_ok,
        "scratch_removed": scratch_removed,
        "final_gpu_compute_process_probe": probe,
        "finalized_utc": finalized_utc,
    }


def _create_only(
    path: Path,
    value: Mapping[str, Any],
    *,
    terminal_exit: bool = False,
) -> str:
    _regular_directory(path.parent, "wrapper-completion directory")
    payload = canonical_json_bytes(value) + b"\n"
    digest = sha256_bytes(payload)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise WrapperCompletionError(
            f"wrapper completion already exists (create-only): {path}"
        ) from exc
    file_synced = False
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise WrapperCompletionError("short wrapper-completion write")
            offset += written
        os.fsync(descriptor)
        file_synced = True
    finally:
        try:
            os.close(descriptor)
        except OSError:
            if not file_synced:
                raise
    parent = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    parent_synced = False
    try:
        os.fsync(parent)
        parent_synced = True
    finally:
        try:
            os.close(parent)
        except OSError:
            if not parent_synced:
                raise
    if terminal_exit:
        # All descriptors are closed and both file and parent are durable.
        # Bypass stdout/stderr flushing and interpreter teardown: no later
        # user-space failure may coexist with this published evidence.
        os._exit(0)
    return digest


def verify_wrapper_cleanup(
    *,
    root: Path,
    phase: str,
    plan_path: Path,
    receipt_path: Path,
    expected_head: str,
    expected_manifest: str,
) -> dict[str, Any]:
    """Authenticate the node's exact post-cleanup handoff."""

    receipt_raw = _regular_file_bytes(receipt_path, "runner receipt")
    receipt = _unique_json_object(receipt_raw, "runner receipt")
    plan_raw = _regular_file_bytes(plan_path, "plan")
    plan = _unique_json_object(plan_raw, "plan")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str):
        raise WrapperCompletionError("plan lacks an ID")
    relative = cleanup_relative_path(
        phase=phase, plan_id=plan_id, receipt_path=receipt_path
    )
    path = root / relative
    raw = _regular_file_bytes(path, "wrapper cleanup attestation")
    if not raw.endswith(b"\n"):
        raise WrapperCompletionError("wrapper cleanup lacks final newline")
    value = _unique_json_object(raw, "wrapper cleanup attestation")
    if set(value) != WRAPPER_STATE_FIELDS:
        raise WrapperCompletionError("wrapper cleanup fields mismatch")
    if raw != canonical_json_bytes(value) + b"\n":
        raise WrapperCompletionError("wrapper cleanup is not canonical JSON")

    attempt = value.get("attempt")
    node = receipt.get("node_argument")
    gpu_value = receipt.get("physical_gpu_index")
    if not isinstance(attempt, str) or not isinstance(node, str):
        raise WrapperCompletionError("wrapper identity fields are malformed")
    gpu = str(gpu_value)
    log_relative = receipt.get("server_log_expected_archive_relative")
    if not isinstance(log_relative, str):
        raise WrapperCompletionError("receipt lacks archived server-log path")
    server_log_path = root / log_relative
    expected = build_wrapper_cleanup(
        root=root,
        phase=phase,
        plan_path=plan_path,
        receipt_path=receipt_path,
        server_log_path=server_log_path,
        attempt=attempt,
        node=node,
        gpu=gpu,
        expected_head=expected_head,
        expected_manifest=expected_manifest,
        expected_wrapper=str(receipt.get("expected_wrapper_sha256")),
        expected_payload=str(receipt.get("expected_payload_sha256")),
        payload_rc=value.get("payload_rc"),
        wrapper_rc=value.get("wrapper_rc"),
        cleanup_ok=value.get("server_process_group_cleanup_ok"),
        intervention=value.get("server_process_group_shell_intervention"),
        log_archive_ok=value.get("server_log_archive_ok"),
        scratch_removed=value.get("scratch_removed"),
        final_gpu_probe=value.get("final_gpu_compute_process_probe")
        if isinstance(value.get("final_gpu_compute_process_probe"), dict)
        else {},
        finalized_utc=value.get("finalized_utc"),
    )
    if value != expected:
        raise WrapperCompletionError("wrapper cleanup binding mismatch")
    return {
        "path": str(path),
        "relative_path": relative.as_posix(),
        "sha256": sha256_bytes(raw),
        "value": value,
    }


def _completion_from_cleanup(
    cleanup: Mapping[str, Any],
    *,
    cleanup_path: str,
    cleanup_sha256: str,
    observed_wrapper_rc: int,
) -> dict[str, Any]:
    if type(observed_wrapper_rc) is not int or observed_wrapper_rc != 0:
        raise WrapperCompletionError(
            "dispatcher did not observe wrapper return code zero"
        )
    value = dict(cleanup)
    if value.get("schema") != CLEANUP_SCHEMA or value.get("wrapper_rc") != 0:
        raise WrapperCompletionError("cleanup handoff is not wrapper-green")
    value.update(
        {
            "schema": SCHEMA,
            "cleanup_attestation_path": cleanup_path,
            "cleanup_attestation_sha256": cleanup_sha256,
            "dispatcher_observed_wrapper_rc": observed_wrapper_rc,
            "wrapper_exit_observed_by_dispatcher": True,
        }
    )
    return value


def _is_nfs_visibility_miss(exc: WrapperCompletionError) -> bool:
    """Recognize only create-only handoff files hidden by a stale lookup."""

    return isinstance(exc.__cause__, FileNotFoundError) and str(exc).startswith(
        (
            "missing runner receipt:",
            "missing wrapper cleanup attestation:",
            "missing archived server log:",
        )
    )


def wait_for_wrapper_cleanup_visibility(
    *,
    root: Path,
    phase: str,
    plan_path: Path,
    receipt_path: Path,
    expected_head: str,
    expected_manifest: str,
    timeout_seconds: float = NFS_VISIBILITY_TIMEOUT_SECONDS,
    poll_seconds: float = NFS_VISIBILITY_POLL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Bound a dispatcher-only, read-only wait for NFS handoff visibility.

    Only a ``FileNotFoundError`` for the create-only receipt, cleanup
    attestation, or archived server log is retryable.  Malformed bytes,
    symlinks, binding drift and all other authentication failures remain
    immediate terminal failures.
    """

    if timeout_seconds <= 0 or poll_seconds <= 0:
        raise ValueError("NFS visibility timeout and poll interval must be positive")
    deadline = monotonic() + timeout_seconds
    while True:
        try:
            return verify_wrapper_cleanup(
                root=root,
                phase=phase,
                plan_path=plan_path,
                receipt_path=receipt_path,
                expected_head=expected_head,
                expected_manifest=expected_manifest,
            )
        except WrapperCompletionError as exc:
            if not _is_nfs_visibility_miss(exc):
                raise
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise WrapperCompletionError(
                    "bounded NFS visibility wait expired before authenticated "
                    f"wrapper handoff became visible: {exc}"
                ) from exc
            sleep(min(poll_seconds, remaining))


def finalize_wrapper_completion(
    *,
    root: Path,
    phase: str,
    plan_path: Path,
    receipt_path: Path,
    expected_head: str,
    expected_manifest: str,
    observed_wrapper_rc: int,
    terminal_exit: bool = False,
) -> dict[str, Any]:
    """Create acceptance evidence only after dispatcher-observed wrapper rc=0."""

    cleanup = wait_for_wrapper_cleanup_visibility(
        root=root,
        phase=phase,
        plan_path=plan_path,
        receipt_path=receipt_path,
        expected_head=expected_head,
        expected_manifest=expected_manifest,
    )
    value = _completion_from_cleanup(
        cleanup["value"],
        cleanup_path=str(cleanup["relative_path"]),
        cleanup_sha256=str(cleanup["sha256"]),
        observed_wrapper_rc=observed_wrapper_rc,
    )
    plan = _unique_json_object(_regular_file_bytes(plan_path, "plan"), "plan")
    relative = attestation_relative_path(
        phase=phase,
        plan_id=str(plan["plan_id"]),
        receipt_path=receipt_path,
    )
    destination = root / relative
    digest = _create_only(destination, value, terminal_exit=terminal_exit)
    return {
        "path": str(destination),
        "relative_path": relative.as_posix(),
        "sha256": digest,
        "value": value,
    }


def verify_wrapper_completion(
    *,
    root: Path,
    phase: str,
    plan_path: Path,
    receipt_path: Path,
    expected_head: str,
    expected_manifest: str,
) -> dict[str, Any]:
    """Authenticate dispatcher-observed wrapper completion for a receipt."""

    plan = _unique_json_object(_regular_file_bytes(plan_path, "plan"), "plan")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str):
        raise WrapperCompletionError("plan lacks an ID")
    relative = attestation_relative_path(
        phase=phase, plan_id=plan_id, receipt_path=receipt_path
    )
    path = root / relative
    raw = _regular_file_bytes(path, "wrapper completion")
    if not raw.endswith(b"\n"):
        raise WrapperCompletionError("wrapper completion lacks final newline")
    value = _unique_json_object(raw, "wrapper completion")
    if set(value) != ATTESTATION_FIELDS:
        raise WrapperCompletionError("wrapper completion fields mismatch")
    if raw != canonical_json_bytes(value) + b"\n":
        raise WrapperCompletionError("wrapper completion is not canonical JSON")
    cleanup = verify_wrapper_cleanup(
        root=root,
        phase=phase,
        plan_path=plan_path,
        receipt_path=receipt_path,
        expected_head=expected_head,
        expected_manifest=expected_manifest,
    )
    expected = _completion_from_cleanup(
        cleanup["value"],
        cleanup_path=str(cleanup["relative_path"]),
        cleanup_sha256=str(cleanup["sha256"]),
        observed_wrapper_rc=value.get("dispatcher_observed_wrapper_rc"),
    )
    if value != expected:
        raise WrapperCompletionError("wrapper completion binding mismatch")
    return {
        "path": str(path),
        "relative_path": relative.as_posix(),
        "sha256": sha256_bytes(raw),
        "value": value,
    }


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def main(
    argv: Sequence[str] | None = None,
    *,
    terminal_exit: bool = False,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("cleanup", "complete"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("policy_preflight", "execute"))
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--server-log", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--attempt")
    parser.add_argument("--node")
    parser.add_argument("--gpu")
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-manifest", required=True)
    parser.add_argument("--expected-wrapper")
    parser.add_argument("--expected-payload")
    parser.add_argument("--payload-rc", type=int)
    parser.add_argument("--wrapper-rc", type=int)
    parser.add_argument("--cleanup-ok", type=_parse_bool)
    parser.add_argument("--intervention", type=_parse_bool)
    parser.add_argument("--log-archive-ok", type=_parse_bool)
    parser.add_argument("--scratch-removed", type=_parse_bool)
    parser.add_argument("--finalized-utc")
    parser.add_argument("--observed-wrapper-rc", type=int)
    args = parser.parse_args(argv)

    if args.stage == "complete":
        finalize_wrapper_completion(
            root=args.root,
            phase=args.phase,
            plan_path=args.plan,
            receipt_path=args.receipt,
            expected_head=args.expected_head,
            expected_manifest=args.expected_manifest,
            observed_wrapper_rc=args.observed_wrapper_rc,
            terminal_exit=terminal_exit,
        )
        return 0

    required = {
        "server log": args.server_log,
        "scratch": args.scratch,
        "attempt": args.attempt,
        "node": args.node,
        "GPU": args.gpu,
        "wrapper digest": args.expected_wrapper,
        "payload digest": args.expected_payload,
        "payload rc": args.payload_rc,
        "wrapper rc": args.wrapper_rc,
        "cleanup flag": args.cleanup_ok,
        "intervention flag": args.intervention,
        "archive flag": args.log_archive_ok,
        "scratch flag": args.scratch_removed,
        "timestamp": args.finalized_utc,
    }
    missing = [label for label, item in required.items() if item is None]
    if missing:
        raise WrapperCompletionError(
            "cleanup stage lacks required arguments: " + ", ".join(missing)
        )
    if args.scratch.exists() or args.scratch.is_symlink():
        raise WrapperCompletionError("scratch still exists at wrapper finalization")
    probe = probe_final_gpu(args.gpu)
    value = build_wrapper_cleanup(
        root=args.root,
        phase=args.phase,
        plan_path=args.plan,
        receipt_path=args.receipt,
        server_log_path=args.server_log,
        attempt=args.attempt,
        node=args.node,
        gpu=args.gpu,
        expected_head=args.expected_head,
        expected_manifest=args.expected_manifest,
        expected_wrapper=args.expected_wrapper,
        expected_payload=args.expected_payload,
        payload_rc=args.payload_rc,
        wrapper_rc=args.wrapper_rc,
        cleanup_ok=args.cleanup_ok,
        intervention=args.intervention,
        log_archive_ok=args.log_archive_ok,
        scratch_removed=args.scratch_removed,
        final_gpu_probe=probe,
        finalized_utc=args.finalized_utc,
    )
    plan = _unique_json_object(_regular_file_bytes(args.plan, "plan"), "plan")
    relative = cleanup_relative_path(
        phase=args.phase,
        plan_id=str(plan["plan_id"]),
        receipt_path=args.receipt,
    )
    _create_only(
        args.root / relative,
        value,
        terminal_exit=terminal_exit,
    )
    return 0


if __name__ == "__main__":
    # On success the durable create-only write is the terminal user-space
    # action.  In particular, there is no stdout flush or post-create logging
    # that can turn a published completion into a nonzero process result.
    main(terminal_exit=True)
    os._exit(70)
