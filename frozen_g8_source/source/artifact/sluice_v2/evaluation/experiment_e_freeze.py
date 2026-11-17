"""Outcome-free structural freeze for Experiment E performance/scalability.

This module validates and materializes declarations only.  It never imports a
benchmark implementation, launches a worker, touches a model/tokenizer, or
collects a performance observation.  A structurally valid freeze deliberately
leaves the principal gate closed while the eleven-arm runner, authenticated
raw analyzer, runtime identities, and storage identities are absent.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
from typing import Callable, Mapping, Sequence


PROTOCOL_SCHEMA = "sluice.experiment-e.protocol.v1"
CONDITIONS_SCHEMA = "sluice.experiment-e.conditions.v1"
RUNTIME_IDENTITIES_SCHEMA = "sluice.experiment-e.runtime-identities.v1"
STORAGE_IDENTITIES_SCHEMA = "sluice.experiment-e.storage-identities.v1"
SCHEDULE_SCHEMA = "sluice.experiment-e.schedule.v1"
BINDING_SCHEMA = "sluice.experiment-e.freeze-bindings.v1"
VALIDATION_SCHEMA = "sluice.experiment-e.freeze-validation.v1"
RAW_ATTEMPT_SCHEMA = "sluice.experiment-e.raw-attempt.v1"
RAW_OPERATION_SCHEMA = "sluice.experiment-e.raw-operation.v1"
ANALYZER_CONTRACT_SCHEMA = "sluice.experiment-e.raw-analyzer-contract.v1"

FOUNDATION_COMMIT = "b703bb2f37d662fd340400f36bc0e91d3c00b4b3"
ROOT_RANDOMIZATION_SEED = 8675309
BOOTSTRAP_REPLICATES = 10_000
REPETITIONS = 10
CONCURRENCIES = (1, 2, 4, 8, 16, 32, 64)
RUNTIME_IDS = (
    "cluster-login-rocky8-node001-prospective",
    "cluster-login-rocky8-node002-prospective",
    "cluster-login-rocky8-node003-prospective",
)
REQUIRED_CONDITION_IDS = (
    "direct_function_call_without_monitor",
    "in_memory_policy_check",
    "sluice_without_durable_audit",
    "sluice_sqlite_ledger_without_signed_checkpoint",
    "full_sluice",
    "full_sluice_with_isolated_rpc",
    "wal_mode",
    "delete_full_mode",
    "local_persistent_filesystem",
    "shared_or_network_filesystem",
    "temporary_memory_filesystem_diagnostic_only",
)
EXISTING_G8_CONDITION_IDS = (
    "unmediated_handler",
    "inmemory_secure_domain",
    "durable_direct",
    "singleton_ipc",
)
SCHEDULE_KNOWN_SHA256 = "f2be8e620666b75146d3c5a33e24624942a21215931122b7b43f4bf5f903d985"

PROTOCOL_PATH = "manifests/EXPERIMENT_E_PROTOCOL.json"
CONDITIONS_PATH = "manifests/EXPERIMENT_E_CONDITIONS.json"
RUNTIME_IDENTITIES_PATH = "manifests/EXPERIMENT_E_RUNTIME_IDENTITIES.json"
STORAGE_IDENTITIES_PATH = "manifests/EXPERIMENT_E_STORAGE_IDENTITIES.json"
SCHEDULE_PATH = "manifests/EXPERIMENT_E_SCHEDULE.csv"
BINDING_PATH = "manifests/EXPERIMENT_E_FREEZE_BINDINGS.json"

FREEZE_MEMBERS = (
    "analysis/EXPERIMENT_E_PERFORMANCE_FREEZE.md",
    PROTOCOL_PATH,
    CONDITIONS_PATH,
    RUNTIME_IDENTITIES_PATH,
    STORAGE_IDENTITIES_PATH,
    SCHEDULE_PATH,
    "source/artifact/sluice_v2/evaluation/experiment_e_freeze.py",
    "source/artifact/sluice_v2/tests/test_v31_experiment_e_freeze.py",
)

FOUNDATION_BINDINGS: Mapping[str, str] = {
    "analysis/ANALYSIS_PLAN.md": "1c3d08c7ec0e0cc73c684ea70cd68ee1155474215f3988024cd04671c0ef31a4",
    "analysis/G8_PERFORMANCE_PROTOCOL.md": "a0b39ad6157cf98ba7688aaf5402e2aa4a15a93445faeb8fc3965b9f71996c18",
    "manifests/EXPERIMENT_PROTOCOL.json": "3b94101d679c8c52d57b47de945daf992a05b221e3d86e26b7b3447772f89d51",
    "source/artifact/experiments/g8_matched_scalability.py": "c1dac504429975c880a278681972dbcbbd752e809bb87653453bf95db1113b87",
    "source/artifact/pyproject.toml": "ecfc2edd6338b39c349d22d45fb15b6c3949aa5712d4466cadfc4c70baaa8f0b",
    "source/artifact/requirements-lock.txt": "4677e32b88bd90ecb8087769d072b818cfab0b4eb0cb19d20b1b65f3dacec780",
    "source/artifact/sluice_v2/__init__.py": "782dd28b6d7a59e98d66b13af8dfbbd8f180c1a4164a059a115d52e77e3b030a",
    "source/artifact/sluice_v2/observer.py": "fa0bf3ccb0ad38037a323c62d3e5377e0e8890819134a780c72897a178d04ce5",
    "source/artifact/sluice_v2/secure.py": "3c213ccf56be6e96ff57259b2ee02a31cf29dc593f2d5ba035fb7ce0152eb21d",
    "source/artifact/sluice_v2/durable_secure.py": "e47cb4072955034f76181eecc7b9c20eb9a6b820ed2fd20251ba0a64c03c12cf",
    "source/artifact/sluice_v2/durable_service.py": "52d7613c61090be39198535fbc6bf3751fb39ad7b4e02e67a73e388d2b365956",
    "source/artifact/sluice_v2/isolation.py": "1dbff172336158dd70673643da7f6c9c6310014dd23803bc06bc67c6ed30918b",
    "source/artifact/sluice_v2/linux_isolation.py": "cea081a7a8984969490326362b384da6a9a622dc8f880ee200dd091cd1c5db6b",
}

PRINCIPAL_BLOCKERS = (
    "BLOCKED_CLEAN_COMMITTED_EXPERIMENT_E_FREEZE",
    "BLOCKED_EXPERIMENT_E_ELEVEN_ARM_RUNNER",
    "BLOCKED_INDEPENDENT_EXPERIMENT_E_REAUDIT",
    "BLOCKED_PRINCIPAL_OUTPUT_DIRECTORY",
    "BLOCKED_PRINCIPAL_RUNTIME_IDENTITIES",
    "BLOCKED_PRINCIPAL_STORAGE_IDENTITIES",
    "BLOCKED_SEPARATELY_AUTHENTICATED_CONTROLLER",
    "BLOCKED_SEPARATELY_AUTHENTICATED_RAW_ANALYZER",
)

CROSS_FAMILY_BLOCKERS = (
    "BLOCKED_EXPERIMENT_A_RUNNER_AND_POLICY_IDENTITIES",
    "BLOCKED_EXPERIMENT_D_CONSTRAINED_UNCONSTRAINED_IDENTITIES",
    "BLOCKED_EXPERIMENT_D_HELDOUT_WORKFLOW_MATRIX",
    "BLOCKED_EXPERIMENT_D_MULTIPLE_WORKFLOW_IDENTITIES",
    "BLOCKED_EXPERIMENT_D_SPLIT_MANIFESTS",
    "BLOCKED_AGENTDOJO_LIVE_RUNNER",
    "BLOCKED_AGENTDOJO_POLICY_AUTHOR_GPU_SMOKE",
    "BLOCKED_AGENTLEAK_LIVE_RUNNER",
    "BLOCKED_AGENTLEAK_CHRONOLOGY_RECEIPT_GPU_SMOKE",
    "BLOCKED_AGENTLEAK_TASK_SUFFICIENCY_EVALUATOR",
    "BLOCKED_ENDPOINT_LAUNCH_AND_DECODING_MANIFEST",
    "BLOCKED_GPU_RUNTIME_ISOLATION_GATE",
    "BLOCKED_LIVE_RUNTIME_IMAGE_AND_LOCK",
    "BLOCKED_MODEL_CACHE_START_END_REAUTHENTICATION",
    "BLOCKED_RUNTIME_SOURCE_UNCOMMITTED_UNFROZEN",
    "BLOCKED_CLEAN_FINAL_SOURCE_COMMIT",
    "BLOCKED_MODEL_RUNTIME_LICENSE_SELECTION_AUTHORIZATION",
)

SCHEDULE_HEADER = (
    "schedule_schema",
    "cell_index",
    "cell_id",
    "block_index",
    "block_id",
    "runtime_id",
    "runtime_order",
    "repetition",
    "concurrency",
    "concurrency_order",
    "condition_id",
    "condition_order",
    "condition_sha256",
    "runtime_identity_sha256",
    "storage_identity_id",
    "storage_identity_sha256",
    "randomization_seed_sha256",
    "attempt_number",
    "prior_attempt_sha256",
    "principal_eligible",
    "blocker_codes",
)


class ExperimentEFreezeError(ValueError):
    """The Experiment E freeze is malformed or its principal gate is closed."""


class _LinuxInotifyGroupWatch:
    """Fail on any mutation to a freeze member or any lexical parent."""

    _IN_MODIFY = 0x00000002
    _IN_ATTRIB = 0x00000004
    _IN_CLOSE_WRITE = 0x00000008
    _IN_MOVED_FROM = 0x00000040
    _IN_MOVED_TO = 0x00000080
    _IN_CREATE = 0x00000100
    _IN_DELETE = 0x00000200
    _IN_DELETE_SELF = 0x00000400
    _IN_MOVE_SELF = 0x00000800
    _IN_UNMOUNT = 0x00002000
    _IN_Q_OVERFLOW = 0x00004000
    _IN_IGNORED = 0x00008000
    _IN_DONT_FOLLOW = 0x02000000
    _IN_EXCL_UNLINK = 0x04000000
    _IN_ONLYDIR = 0x01000000
    _SENSITIVE = (
        _IN_MODIFY
        | _IN_ATTRIB
        | _IN_CLOSE_WRITE
        | _IN_MOVED_FROM
        | _IN_MOVED_TO
        | _IN_CREATE
        | _IN_DELETE
        | _IN_DELETE_SELF
        | _IN_MOVE_SELF
        | _IN_UNMOUNT
        | _IN_Q_OVERFLOW
        | _IN_IGNORED
    )
    _EVENT = struct.Struct("iIII")

    def __init__(self, root: Path, paths: Sequence[str]) -> None:
        if sys.platform != "linux":
            raise ExperimentEFreezeError(
                "whole-group Experiment E validation requires Linux inotify"
            )
        if type(paths) not in {tuple, list} or len(paths) != len(set(paths)):
            raise ExperimentEFreezeError("inotify freeze paths are not exact and unique")
        for relative in paths:
            _relative_path(relative)
        library = ctypes.CDLL(None, use_errno=True)
        try:
            init = library.inotify_init1
            add = library.inotify_add_watch
        except AttributeError as exc:
            raise ExperimentEFreezeError(
                "Linux libc lacks required inotify entry points"
            ) from exc
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        descriptor = init(os.O_NONBLOCK | os.O_CLOEXEC)
        if descriptor < 0:
            error = ctypes.get_errno()
            raise ExperimentEFreezeError(
                "cannot initialize whole-group inotify watch"
            ) from OSError(error, os.strerror(error))
        self.descriptor = descriptor
        self._add = add
        self.paths_by_watch: dict[int, set[str]] = {}
        try:
            files = tuple(str(root / relative) for relative in sorted(paths))
            parents: set[str] = {str(root)}
            for relative in sorted(paths):
                cursor = root
                for component in PurePosixPath(relative).parent.parts:
                    cursor = cursor / component
                    parents.add(str(cursor))
            parent_mask = self._SENSITIVE | self._IN_DONT_FOLLOW | self._IN_ONLYDIR
            file_mask = self._SENSITIVE | self._IN_DONT_FOLLOW | self._IN_EXCL_UNLINK
            for path in sorted(parents):
                self._add_path(path, parent_mask)
            for path in files:
                self._add_path(path, file_mask)
        except BaseException:
            self.close()
            raise

    def _add_path(self, path: str, mask: int) -> None:
        watch = self._add(self.descriptor, os.fsencode(path), mask)
        if watch < 0:
            error = ctypes.get_errno()
            raise ExperimentEFreezeError(
                f"cannot watch Experiment E freeze path: {path}"
            ) from OSError(error, os.strerror(error))
        self.paths_by_watch.setdefault(watch, set()).add(path)

    def _drain(self) -> list[tuple[int, int, str]]:
        events: list[tuple[int, int, str]] = []
        while True:
            try:
                data = os.read(self.descriptor, 1024 * 1024)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    break
                raise ExperimentEFreezeError(
                    "cannot drain whole-group inotify queue"
                ) from exc
            if not data:
                break
            offset = 0
            while offset < len(data):
                if len(data) - offset < self._EVENT.size:
                    raise ExperimentEFreezeError(
                        "truncated whole-group inotify event"
                    )
                watch, mask, _cookie, length = self._EVENT.unpack_from(data, offset)
                offset += self._EVENT.size
                if length > len(data) - offset:
                    raise ExperimentEFreezeError(
                        "invalid whole-group inotify event length"
                    )
                raw_name = data[offset : offset + length]
                offset += length
                events.append((watch, mask, os.fsdecode(raw_name.rstrip(b"\0"))))
        return events

    def assert_quiet(self, stage: str) -> None:
        sensitive = [event for event in self._drain() if event[1] & self._SENSITIVE]
        if not sensitive:
            return
        watch, mask, name = sensitive[0]
        if mask & self._IN_Q_OVERFLOW:
            raise ExperimentEFreezeError(
                f"whole-group inotify queue overflow at {stage}"
            )
        watched = sorted(self.paths_by_watch.get(watch, {"UNKNOWN_WATCH"}))
        raise ExperimentEFreezeError(
            f"whole-group inotify mutation at {stage}: mask=0x{mask:x} "
            f"watch={watched} name={name!r}"
        )

    def close(self) -> None:
        descriptor = getattr(self, "descriptor", -1)
        if descriptor >= 0:
            self.descriptor = -1
            os.close(descriptor)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ExperimentEFreezeError(
                f"duplicate or non-string JSON key: {key!r}"
            )
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
    except (TypeError, ValueError) as exc:
        raise ExperimentEFreezeError("value is outside canonical JSON") from exc
    return (text + "\n").encode("ascii")


def parse_strict_json(data: bytes, *, label: str) -> object:
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_strict_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExperimentEFreezeError(
                    f"non-finite JSON token in {label}: {token}"
                )
            ),
        )
    except ExperimentEFreezeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExperimentEFreezeError(f"{label} is not strict ASCII JSON") from exc
    if data != canonical_json(value):
        raise ExperimentEFreezeError(f"{label} is not canonical pretty JSON")
    return value


def _condition(
    condition_id: str,
    ordinal: int,
    *,
    axis: str,
    comparator: str | None,
    implementation_state: str,
    entry_point: str | None,
    source_path: str | None,
    source_sha256: str | None,
    g8_condition: str | None,
    g8_support_entry: str | None,
    coverage: str,
    mismatch: str | None,
    audit: str,
    checkpoint: str,
    rpc: str,
    isolation: str,
    journal: str,
    sync: str,
    storage_identity: str,
    storage_semantics: str,
    role: str,
    blockers: Sequence[str],
) -> dict[str, object]:
    return {
        "audit_semantics": audit,
        "axis": axis,
        "blockers": list(blockers),
        "checkpoint_semantics": checkpoint,
        "comparator_condition_id": comparator,
        "condition_id": condition_id,
        "eligibility_role": role,
        "existing_g8_coverage": {
            "condition_id": g8_condition,
            "coverage": coverage,
            "semantic_mismatch": mismatch,
            "support_entry_point": g8_support_entry,
        },
        "handler_binding": {
            "entry_point": entry_point,
            "implementation_state": implementation_state,
            "matched_operation_contract": (
                "finite_payload_value_code_1_to_exact_integer_code_1"
            ),
            "source_path": source_path,
            "source_sha256": source_sha256,
        },
        "isolation_semantics": isolation,
        "journal_mode": journal,
        "ordinal": ordinal,
        "principal_eligible": False,
        "rpc_semantics": rpc,
        "storage_identity_id": storage_identity,
        "storage_semantics": storage_semantics,
        "synchronous_mode": sync,
    }


def expected_conditions() -> dict[str, object]:
    driver = FOUNDATION_BINDINGS[
        "source/artifact/experiments/g8_matched_scalability.py"
    ]
    conditions = [
        _condition(
            REQUIRED_CONDITION_IDS[0],
            1,
            axis="monitor_mediation",
            comparator=None,
            implementation_state="EXISTING_DIAGNOSTIC_EXACT",
            entry_point="g8_matched_scalability.finite_handler",
            source_path="source/artifact/experiments/g8_matched_scalability.py",
            source_sha256=driver,
            g8_condition="unmediated_handler",
            g8_support_entry=None,
            coverage="EXACT_MATCH_DIAGNOSTIC_ONLY",
            mismatch=None,
            audit="NONE",
            checkpoint="NONE",
            rpc="NONE_IN_PROCESS_DIRECT_CALL",
            isolation="SAME_PROCESS_NO_MONITOR",
            journal="NOT_APPLICABLE",
            sync="NOT_APPLICABLE",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="PAIRING_CONTEXT_ONLY_NO_STORAGE_IO",
            role="REFERENCE_BASELINE",
            blockers=("BLOCKED_EXISTING_G8_FINAL_MODE_DISABLED",),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[1],
            2,
            axis="monitor_mediation",
            comparator=REQUIRED_CONDITION_IDS[0],
            implementation_state="EXISTING_DIAGNOSTIC_PARTIAL_MISMATCH",
            entry_point="g8_matched_scalability._prepare_condition[inmemory_secure_domain]",
            source_path="source/artifact/experiments/g8_matched_scalability.py",
            source_sha256=driver,
            g8_condition="inmemory_secure_domain",
            g8_support_entry=None,
            coverage="PARTIAL_SEMANTIC_MISMATCH",
            mismatch=(
                "existing arm includes authentication, accounting, handler, and "
                "transcript; it is not an isolated policy-check-only arm"
            ),
            audit="IN_MEMORY_TYPED_TRANSCRIPT_NOT_DURABLE",
            checkpoint="NONE",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_SECURE_DOMAIN",
            journal="NOT_APPLICABLE",
            sync="NOT_APPLICABLE",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="PAIRING_CONTEXT_ONLY_NO_STORAGE_IO",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=(
                "BLOCKED_IN_MEMORY_POLICY_CHECK_ONLY_MATCHED_ARM_ABSENT",
                "BLOCKED_EXISTING_G8_FINAL_MODE_DISABLED",
            ),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[2],
            3,
            axis="durable_audit",
            comparator=REQUIRED_CONDITION_IDS[1],
            implementation_state="ABSENT",
            entry_point=None,
            source_path=None,
            source_sha256=None,
            g8_condition=None,
            g8_support_entry=None,
            coverage="ABSENT",
            mismatch="existing secure APIs expose no safe no-durable-audit switch",
            audit="DURABLE_AUDIT_DISABLED_WITHOUT_WEAKENING_OTHER_SEMANTICS",
            checkpoint="NONE",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_SLUICE_MONITOR",
            journal="NOT_APPLICABLE",
            sync="NOT_APPLICABLE",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="PAIRING_CONTEXT_ONLY_NO_DURABLE_IO",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=("BLOCKED_NO_DURABLE_AUDIT_IMPLEMENTATION_ABSENT",),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[3],
            4,
            axis="signed_checkpoint",
            comparator=REQUIRED_CONDITION_IDS[2],
            implementation_state="EXISTING_DIAGNOSTIC_PARTIAL_MISMATCH",
            entry_point="g8_matched_scalability._prepare_condition[durable_direct]",
            source_path="source/artifact/experiments/g8_matched_scalability.py",
            source_sha256=driver,
            g8_condition="durable_direct",
            g8_support_entry=None,
            coverage="PARTIAL_SEMANTIC_MISMATCH",
            mismatch=(
                "durable_direct measures a fixed WAL/FULL durable domain, but the "
                "API has no reviewed matched ledger-without-checkpoint switch"
            ),
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_DISABLED_MATCHED_ARM_REQUIRED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_DURABLE_DOMAIN",
            journal="WAL",
            sync="FULL",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="DURABLE_LEDGER_STORAGE_REQUIRED",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=(
                "BLOCKED_LEDGER_WITHOUT_SIGNED_CHECKPOINT_MATCHED_ARM_ABSENT",
                "BLOCKED_EXISTING_G8_FINAL_MODE_DISABLED",
            ),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[4],
            5,
            axis="signed_checkpoint",
            comparator=REQUIRED_CONDITION_IDS[3],
            implementation_state="ABSENT",
            entry_point=None,
            source_path=None,
            source_sha256=None,
            g8_condition=None,
            g8_support_entry=None,
            coverage="ABSENT",
            mismatch="the G8 foundation does not implement or time a signed checkpoint",
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_FULL_SLUICE",
            journal="WAL",
            sync="FULL",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="DURABLE_LEDGER_AND_CHECKPOINT_STORAGE_REQUIRED",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=("BLOCKED_SIGNED_CHECKPOINT_IMPLEMENTATION_ABSENT",),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[5],
            6,
            axis="authenticated_isolated_rpc",
            comparator=REQUIRED_CONDITION_IDS[4],
            implementation_state="EXISTING_DIAGNOSTIC_PARTIAL_MISMATCH",
            entry_point="g8_matched_scalability._prepare_condition[singleton_ipc]",
            source_path="source/artifact/experiments/g8_matched_scalability.py",
            source_sha256=driver,
            g8_condition="singleton_ipc",
            g8_support_entry=None,
            coverage="PARTIAL_SEMANTIC_MISMATCH",
            mismatch=(
                "singleton_ipc measures authenticated AF_UNIX RPC to a durable "
                "service, but omits signed checkpoints and full Linux client isolation"
            ),
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="AUTHENTICATED_AF_UNIX_SEPARATE_PROCESS",
            isolation="FULL_REVIEWED_LINUX_CLIENT_AND_MONITOR_ISOLATION_REQUIRED",
            journal="WAL",
            sync="FULL",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="DURABLE_LEDGER_CHECKPOINT_AND_RPC_STORAGE_REQUIRED",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=(
                "BLOCKED_FULL_ISOLATED_RPC_MATCHED_ARM_ABSENT",
                "BLOCKED_EXISTING_G8_FINAL_MODE_DISABLED",
            ),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[6],
            7,
            axis="sqlite_journal_and_sync",
            comparator=REQUIRED_CONDITION_IDS[7],
            implementation_state="EXISTING_DIAGNOSTIC_PARTIAL_MISMATCH",
            entry_point="g8_matched_scalability._prepare_condition[durable_direct]",
            source_path="source/artifact/experiments/g8_matched_scalability.py",
            source_sha256=driver,
            g8_condition="durable_direct",
            g8_support_entry=None,
            coverage="PARTIAL_SEMANTIC_MISMATCH",
            mismatch=(
                "existing durable paths fix WAL/FULL but do not expose a matched "
                "journal-mode axis against DELETE/FULL"
            ),
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_FULL_SLUICE",
            journal="WAL",
            sync="FULL",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="LOCAL_PERSISTENT_WAL_CAPABLE_REQUIRED",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=(
                "BLOCKED_WAL_MATCHED_JOURNAL_AXIS_IMPLEMENTATION_ABSENT",
                "BLOCKED_EXISTING_G8_FINAL_MODE_DISABLED",
            ),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[7],
            8,
            axis="sqlite_journal_and_sync",
            comparator=REQUIRED_CONDITION_IDS[6],
            implementation_state="ABSENT",
            entry_point=None,
            source_path=None,
            source_sha256=None,
            g8_condition=None,
            g8_support_entry=None,
            coverage="ABSENT",
            mismatch="existing secure APIs expose no reviewed DELETE/FULL durable arm",
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_FULL_SLUICE",
            journal="DELETE",
            sync="FULL",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="LOCAL_PERSISTENT_DELETE_JOURNAL_REQUIRED",
            role="PRIMARY_MATCHED_CONTRAST",
            blockers=("BLOCKED_DELETE_FULL_IMPLEMENTATION_ABSENT",),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[8],
            9,
            axis="storage_location",
            comparator=REQUIRED_CONDITION_IDS[9],
            implementation_state="ABSENT",
            entry_point=None,
            source_path=None,
            source_sha256=None,
            g8_condition=None,
            g8_support_entry="g8_matched_scalability.resolve_storage_profiles",
            coverage="PARTIAL_INFRASTRUCTURE_SUPPORT_NOT_HANDLER_ARM",
            mismatch=(
                "G8 accepts attested local-persistent profiles, but no exact storage "
                "identity or eleven-arm full-Sluice handler exists"
            ),
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_FULL_SLUICE",
            journal="WAL",
            sync="FULL",
            storage_identity="storage-local-persistent-prospective",
            storage_semantics="NODE_LOCAL_PERSISTENT_ONLY",
            role="PRIMARY_STORAGE_REFERENCE",
            blockers=("BLOCKED_LOCAL_PERSISTENT_MATCHED_ARM_ABSENT",),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[9],
            10,
            axis="storage_location",
            comparator=REQUIRED_CONDITION_IDS[8],
            implementation_state="ABSENT",
            entry_point=None,
            source_path=None,
            source_sha256=None,
            g8_condition=None,
            g8_support_entry=None,
            coverage="ABSENT",
            mismatch=(
                "the G8 foundation neither treats shared/network storage as local nor "
                "implements its required safe journal behavior"
            ),
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_FULL_SLUICE",
            journal="FILESYSTEM_COMPATIBLE_MODE_MUST_BE_FROZEN",
            sync="FULL",
            storage_identity="storage-shared-network-prospective",
            storage_semantics="SHARED_OR_NETWORK_NEVER_NODE_LOCAL",
            role="PRIMARY_MATCHED_STORAGE_CONTRAST",
            blockers=("BLOCKED_SHARED_NETWORK_MATCHED_ARM_ABSENT",),
        ),
        _condition(
            REQUIRED_CONDITION_IDS[10],
            11,
            axis="storage_location",
            comparator=REQUIRED_CONDITION_IDS[8],
            implementation_state="ABSENT",
            entry_point=None,
            source_path=None,
            source_sha256=None,
            g8_condition=None,
            g8_support_entry="g8_matched_scalability.resolve_storage_profiles",
            coverage="PARTIAL_INFRASTRUCTURE_SUPPORT_NOT_HANDLER_ARM",
            mismatch=(
                "G8 supports tmpfs only as a diagnostic storage profile; it is not a "
                "claim-bearing handler arm"
            ),
            audit="DURABLE_SQLITE_AUDIT_LEDGER",
            checkpoint="SIGNED_CHECKPOINT_INCLUDED",
            rpc="NONE_IN_PROCESS",
            isolation="SAME_PROCESS_FULL_SLUICE",
            journal="WAL",
            sync="FULL",
            storage_identity="storage-tmpfs-diagnostic-prospective",
            storage_semantics="TMPFS_DIAGNOSTIC_ONLY_NEVER_CLAIM_ELIGIBLE",
            role="DIAGNOSTIC_ONLY_EXCLUDED_FROM_CLAIM_FAMILIES",
            blockers=(
                "BLOCKED_TMPFS_MATCHED_DIAGNOSTIC_ARM_ABSENT",
                "BLOCKED_TMPFS_DIAGNOSTIC_ONLY",
            ),
        ),
    ]
    return {
        "conditions": conditions,
        "foundation_commit": FOUNDATION_COMMIT,
        "required_condition_ids_source": (
            "manifests/EXPERIMENT_PROTOCOL.json#/experiment_families/"
            "E_performance_scalability/required_conditions"
        ),
        "schema": CONDITIONS_SCHEMA,
    }


def expected_runtime_identities() -> dict[str, object]:
    identities = []
    for ordinal, (runtime_id, host) in enumerate(
        zip(RUNTIME_IDS, ("node001", "node002", "node003")), start=1
    ):
        identities.append(
            {
                "blockers": [
                    f"BLOCKED_RUNTIME_{host.upper()}_IDENTITY_NOT_CAPTURED"
                ],
                "container_or_image_digest": None,
                "cpu_identity_sha256": None,
                "declared_execution_host": host,
                "identity_state": "ABSENT_NOT_CAPTURED",
                "kernel_release": None,
                "os_release_sha256": None,
                "ordinal": ordinal,
                "principal_eligible": False,
                "python_executable_sha256": None,
                "python_version": None,
                "runtime_id": runtime_id,
                "runtime_lock_sha256": None,
                "source_commit_required": FOUNDATION_COMMIT,
            }
        )
    return {
        "foundation_commit": FOUNDATION_COMMIT,
        "identities": identities,
        "schema": RUNTIME_IDENTITIES_SCHEMA,
    }


def expected_storage_identities() -> dict[str, object]:
    common_absent = {
        "device_id": None,
        "filesystem_type": None,
        "hostname": None,
        "identity_state": "ABSENT_NOT_CAPTURED",
        "mount_options": None,
        "mount_source": None,
        "mountpoint": None,
        "persistence_attestation_path": None,
        "persistence_attestation_sha256": None,
        "principal_eligible": False,
        "resolved_path": None,
    }
    identities = [
        {
            **common_absent,
            "blockers": ["BLOCKED_LOCAL_STORAGE_IDENTITY_NOT_CAPTURED"],
            "declared_class": "local-persistent",
            "diagnostic_only": False,
            "must_be_node_local": True,
            "ordinal": 1,
            "required_locality": "NODE_LOCAL_PERSISTENT",
            "storage_identity_id": "storage-local-persistent-prospective",
        },
        {
            **common_absent,
            "blockers": ["BLOCKED_SHARED_STORAGE_IDENTITY_NOT_CAPTURED"],
            "declared_class": "shared-or-network",
            "diagnostic_only": False,
            "must_be_node_local": False,
            "ordinal": 2,
            "required_locality": "SHARED_OR_NETWORK_NEVER_LOCAL",
            "storage_identity_id": "storage-shared-network-prospective",
        },
        {
            **common_absent,
            "blockers": ["BLOCKED_TMPFS_STORAGE_IDENTITY_NOT_CAPTURED"],
            "declared_class": "tmpfs-diagnostic",
            "diagnostic_only": True,
            "must_be_node_local": False,
            "ordinal": 3,
            "required_locality": "MEMORY_FILESYSTEM_DIAGNOSTIC_ONLY",
            "storage_identity_id": "storage-tmpfs-diagnostic-prospective",
        },
    ]
    return {
        "foundation_commit": FOUNDATION_COMMIT,
        "identities": identities,
        "schema": STORAGE_IDENTITIES_SCHEMA,
    }


def _all_entity_blockers() -> tuple[str, ...]:
    result = set(PRINCIPAL_BLOCKERS) | set(CROSS_FAMILY_BLOCKERS)
    for condition in expected_conditions()["conditions"]:
        result.update(condition["blockers"])
    for identity in expected_runtime_identities()["identities"]:
        result.update(identity["blockers"])
    for identity in expected_storage_identities()["identities"]:
        result.update(identity["blockers"])
    return tuple(sorted(result))


def expected_protocol() -> dict[str, object]:
    return {
        "analysis": {
            "absolute_interval_rule": (
                "paired-block percentile bootstrap 95pct two-sided interval; "
                "fresh-process paired block is the resampling unit"
            ),
            "bootstrap_replicates": BOOTSTRAP_REPLICATES,
            "bootstrap_seed": ROOT_RANDOMIZATION_SEED,
            "holm_families": {
                "family_key": (
                    "runtime_identity x concurrency x claim-eligible storage table x "
                    "endpoint_family"
                ),
                "method": "Holm step-down",
                "two_sided_familywise_alpha": "0.05",
                "tmpfs_policy": "excluded_diagnostic_only",
            },
            "paired_contrasts": [
                [
                    "in_memory_policy_check",
                    "direct_function_call_without_monitor",
                ],
                ["sluice_without_durable_audit", "in_memory_policy_check"],
                [
                    "sluice_sqlite_ledger_without_signed_checkpoint",
                    "sluice_without_durable_audit",
                ],
                ["full_sluice", "sluice_sqlite_ledger_without_signed_checkpoint"],
                ["full_sluice_with_isolated_rpc", "full_sluice"],
                ["wal_mode", "delete_full_mode"],
                ["shared_or_network_filesystem", "local_persistent_filesystem"],
            ],
            "resampling_contract": (
                "resample complete runtime/repetition/concurrency blocks and retain "
                "all eleven paired conditions in each selected block"
            ),
        },
        "analyzer_contract": {
            "authentication": (
                "independent trust anchor must authenticate analyzer bytes and raw "
                "bundle bytes before any project code executes"
            ),
            "implementation_path": None,
            "implementation_sha256": None,
            "must_not_trust_runner_summaries": True,
            "principal_eligible": False,
            "recompute_from_raw": [
                "schedule completeness and cell uniqueness",
                "all operation and failed-attempt denominators",
                "latency percentiles from integer nanoseconds",
                "throughput from integer operations and elapsed nanoseconds",
                "CPU and memory absolute units",
                "storage growth and transaction failure rates",
                "paired block contrasts and percentile intervals",
                "Holm adjusted family decisions",
                "every source runtime storage and retry hash chain",
            ],
            "schema": ANALYZER_CONTRACT_SCHEMA,
            "state": "ABSENT_NOT_IMPLEMENTED",
        },
        "counts": {
            "cells": 2310,
            "conditions": 11,
            "concurrencies": 7,
            "paired_blocks": 210,
            "repetitions_per_runtime_concurrency": REPETITIONS,
            "runtime_identities": 3,
        },
        "design": {
            "concurrency_levels": list(CONCURRENCIES),
            "experimental_unit": (
                "one fresh process for one condition within a randomized paired "
                "runtime x repetition x concurrency block"
            ),
            "fresh_process_per_cell": True,
            "randomization_algorithm": "sha256-fisher-yates-mod-v1",
            "repetitions": REPETITIONS,
            "root_seed": ROOT_RANDOMIZATION_SEED,
            "runtime_ids": list(RUNTIME_IDS),
            "schedule_is_outcome_free": True,
        },
        "existing_g8_foundation": {
            "condition_ids": list(EXISTING_G8_CONDITION_IDS),
            "final_claims_enabled": False,
            "source_component_sha256": {
                path: digest
                for path, digest in FOUNDATION_BINDINGS.items()
                if path.startswith("source/artifact/")
            },
            "use_policy": (
                "diagnostic semantic inventory only; exact and partial mappings are "
                "declared per Experiment E condition and are never relabeled"
            ),
        },
        "failure_and_retry_policy": {
            "all_failures_remain_in_denominators": True,
            "failed_timed_out_truncated_or_unverifiable_attempt": (
                "retained total failure; never silently dropped or imputed"
            ),
            "initial_attempt_number": 1,
            "retry_rule": (
                "append a new create-once attempt with attempt_number incremented and "
                "prior_attempt_sha256 bound; never overwrite an earlier attempt"
            ),
            "runner_continues_after_cell_failure": True,
        },
        "foundation_commit": FOUNDATION_COMMIT,
        "principal_blocker_union": list(_all_entity_blockers()),
        "principal_eligible": False,
        "raw_contract": {
            "attempt_required_fields": [
                "schema",
                "cell_id",
                "attempt_number",
                "prior_attempt_sha256",
                "status",
                "failure_phase",
                "error_type",
                "error_message",
                "runtime_identity_sha256",
                "storage_identity_sha256",
                "source_sha256",
                "operations_path",
                "operations_sha256",
                "operations_expected",
                "operations_retained",
                "elapsed_ns",
                "worker_cpu_ns",
                "monitor_cpu_ns",
                "peak_rss_bytes",
                "storage_family_bytes_before",
                "storage_family_bytes_after",
                "failed_operations",
            ],
            "attempt_schema": RAW_ATTEMPT_SCHEMA,
            "operation_required_fields": [
                "schema",
                "cell_id",
                "attempt_number",
                "operation_index",
                "worker_slot",
                "start_offset_ns",
                "latency_ns",
                "status",
                "error_type",
                "error_message",
            ],
            "operation_schema": RAW_OPERATION_SCHEMA,
            "raw_units": {
                "cpu": "integer_nanoseconds",
                "latency": "integer_nanoseconds",
                "memory": "integer_bytes",
                "operation_and_failure_counts": "exact_nonnegative_integers",
                "storage": "integer_bytes",
                "throughput": "operations_per_second_derived_from_integer_counts_and_nanoseconds",
            },
            "required_latency_decomposition": [
                "direct_handler_ns",
                "monitor_policy_ns",
                "durable_audit_ns",
                "signed_checkpoint_ns",
                "isolated_rpc_ns",
                "model_inference_ns",
                "tool_execution_ns",
                "end_to_end_ns",
            ],
            "total_failure_retention": True,
        },
        "schema": PROTOCOL_SCHEMA,
        "storage_policy": {
            "local_persistent_requires_exact_attestation": True,
            "shared_or_network_must_never_be_classified_node_local": True,
            "tmpfs_is_diagnostic_only": True,
            "tmpfs_never_principal_eligible": True,
        },
    }


def _identity_digest(value: Mapping[str, object]) -> str:
    return _sha256(canonical_json(value))


def _derived_digest(label: str) -> str:
    material = f"{SCHEDULE_SCHEMA}\0{ROOT_RANDOMIZATION_SEED}\0{label}".encode(
        "ascii"
    )
    return _sha256(material)


def _deterministic_shuffle(values: Sequence[object], *, label: str) -> list[object]:
    result = list(values)
    for index in range(len(result) - 1, 0, -1):
        digest = _derived_digest(f"{label}\0{index}")
        selected = int(digest, 16) % (index + 1)
        result[index], result[selected] = result[selected], result[index]
    return result


def expected_schedule_rows() -> list[dict[str, str]]:
    conditions = {
        item["condition_id"]: item for item in expected_conditions()["conditions"]
    }
    runtimes = {
        item["runtime_id"]: item
        for item in expected_runtime_identities()["identities"]
    }
    storage = {
        item["storage_identity_id"]: item
        for item in expected_storage_identities()["identities"]
    }
    rows: list[dict[str, str]] = []
    block_index = 0
    for runtime_order, runtime_id in enumerate(RUNTIME_IDS, start=1):
        runtime = runtimes[runtime_id]
        runtime_hash = _identity_digest(runtime)
        for repetition in range(1, REPETITIONS + 1):
            concurrencies = _deterministic_shuffle(
                CONCURRENCIES,
                label=f"concurrency-blocks\0{runtime_id}\0{repetition}",
            )
            for concurrency_order, concurrency_object in enumerate(
                concurrencies, start=1
            ):
                concurrency = int(concurrency_object)
                block_material = (
                    f"{SCHEDULE_SCHEMA}\0{runtime_id}\0{repetition}\0{concurrency}"
                )
                block_id = "e-block-" + _sha256(block_material.encode("ascii"))[:24]
                seed_digest = _derived_digest(f"conditions\0{block_material}")
                condition_ordering = _deterministic_shuffle(
                    REQUIRED_CONDITION_IDS,
                    label=f"conditions\0{block_material}",
                )
                for condition_order, condition_object in enumerate(
                    condition_ordering, start=1
                ):
                    condition_id = str(condition_object)
                    condition = conditions[condition_id]
                    storage_id = str(condition["storage_identity_id"])
                    storage_identity = storage[storage_id]
                    cell_material = f"{block_material}\0{condition_id}"
                    cell_id = "e-cell-" + _sha256(cell_material.encode("ascii"))[:24]
                    blockers = sorted(
                        set(PRINCIPAL_BLOCKERS)
                        | set(CROSS_FAMILY_BLOCKERS)
                        | set(condition["blockers"])
                        | set(runtime["blockers"])
                        | set(storage_identity["blockers"])
                    )
                    rows.append(
                        {
                            "attempt_number": "1",
                            "block_id": block_id,
                            "block_index": str(block_index),
                            "blocker_codes": ";".join(blockers),
                            "cell_id": cell_id,
                            "cell_index": str(len(rows)),
                            "concurrency": str(concurrency),
                            "concurrency_order": str(concurrency_order),
                            "condition_id": condition_id,
                            "condition_order": str(condition_order),
                            "condition_sha256": _identity_digest(condition),
                            "principal_eligible": "FALSE",
                            "prior_attempt_sha256": "",
                            "randomization_seed_sha256": seed_digest,
                            "repetition": str(repetition),
                            "runtime_id": runtime_id,
                            "runtime_identity_sha256": runtime_hash,
                            "runtime_order": str(runtime_order),
                            "schedule_schema": SCHEDULE_SCHEMA,
                            "storage_identity_id": storage_id,
                            "storage_identity_sha256": _identity_digest(
                                storage_identity
                            ),
                        }
                    )
                block_index += 1
    return rows


def expected_schedule_bytes() -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=SCHEDULE_HEADER,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(expected_schedule_rows())
    return output.getvalue().encode("ascii")


def expected_binding(member_bytes: Mapping[str, bytes]) -> dict[str, object]:
    if set(member_bytes) != set(FREEZE_MEMBERS):
        raise ExperimentEFreezeError("binding member byte set is not exact")
    return {
        "counts": {
            "cells": 2310,
            "conditions": 11,
            "concurrencies": 7,
            "freeze_members": len(FREEZE_MEMBERS),
            "foundation_members": len(FOUNDATION_BINDINGS),
            "paired_blocks": 210,
            "repetitions": REPETITIONS,
            "runtime_identities": 3,
        },
        "foundation_commit": FOUNDATION_COMMIT,
        "foundation_members": [
            {"path": path, "sha256": digest}
            for path, digest in FOUNDATION_BINDINGS.items()
        ],
        "members": [
            {"path": path, "sha256": _sha256(member_bytes[path])}
            for path in FREEZE_MEMBERS
        ],
        "principal_blocker_union": list(_all_entity_blockers()),
        "principal_eligible": False,
        "schedule_sha256": _sha256(member_bytes[SCHEDULE_PATH]),
        "schema": BINDING_SCHEMA,
    }


def _relative_path(value: str) -> tuple[str, ...]:
    if type(value) is not str or not value or "//" in value or "\\" in value:
        raise ExperimentEFreezeError("path is empty or contains a noncanonical alias")
    pure = PurePosixPath(value)
    if pure.is_absolute() or str(pure) != value:
        raise ExperimentEFreezeError("path is not canonical relative POSIX form")
    if any(part in ("", ".", "..") for part in pure.parts):
        raise ExperimentEFreezeError("path alias escapes or changes lexical identity")
    return pure.parts


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_fd(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


@dataclass
class _OpenGroup:
    root_fd: int
    file_fds: dict[str, int]
    file_bytes: dict[str, bytes]
    file_stats: dict[str, tuple[int, ...]]
    parent_fds: list[tuple[str, int, tuple[int, ...]]]

    def close(self) -> None:
        for descriptor in self.file_fds.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        for _label, descriptor, _identity in self.parent_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(self.root_fd)
        except OSError:
            pass


def _open_group(root: Path, paths: Sequence[str]) -> _OpenGroup:
    if root != root.resolve() or not root.is_dir():
        raise ExperimentEFreezeError("repository root must be a canonical directory")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = os.open(root, directory_flags)
    file_fds: dict[str, int] = {}
    file_bytes: dict[str, bytes] = {}
    file_stats: dict[str, tuple[int, ...]] = {}
    parent_fds: list[tuple[str, int, tuple[int, ...]]] = []
    seen_inodes: dict[tuple[int, int], str] = {}
    try:
        for relative in paths:
            parts = _relative_path(relative)
            parent_fd = os.dup(root_fd)
            parent_fds.append((".", parent_fd, _stat_identity(os.fstat(parent_fd))))
            prefix: list[str] = []
            for part in parts[:-1]:
                child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
                prefix.append(part)
                parent_fds.append(
                    ("/".join(prefix), child_fd, _stat_identity(os.fstat(child_fd)))
                )
                parent_fd = child_fd
            descriptor = os.open(parts[-1], file_flags, dir_fd=parent_fd)
            # Transfer ownership immediately.  Every rejection below must be
            # closed by the group-wide exception cleanup, including an early
            # non-regular, hard-link, duplicate-inode, or read failure.
            file_fds[relative] = descriptor
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode):
                raise ExperimentEFreezeError(f"freeze member is not regular: {relative}")
            if observed.st_nlink != 1:
                raise ExperimentEFreezeError(
                    f"freeze member has a hard-link alias: {relative}"
                )
            inode = (observed.st_dev, observed.st_ino)
            if inode in seen_inodes:
                raise ExperimentEFreezeError(
                    f"freeze members alias one inode: {seen_inodes[inode]} and {relative}"
                )
            seen_inodes[inode] = relative
            file_stats[relative] = _stat_identity(observed)
            file_bytes[relative] = _read_fd(descriptor)
        return _OpenGroup(
            root_fd=root_fd,
            file_fds=file_fds,
            file_bytes=file_bytes,
            file_stats=file_stats,
            parent_fds=parent_fds,
        )
    except BaseException:
        group = _OpenGroup(root_fd, file_fds, file_bytes, file_stats, parent_fds)
        group.close()
        raise


def _fresh_lexical_read(root_fd: int, relative: str) -> tuple[bytes, tuple[int, ...]]:
    parts = _relative_path(relative)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    opened: list[int] = []
    parent_fd = os.dup(root_fd)
    opened.append(parent_fd)
    try:
        for part in parts[:-1]:
            parent_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            opened.append(parent_fd)
        descriptor = os.open(parts[-1], file_flags, dir_fd=parent_fd)
        opened.append(descriptor)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            raise ExperimentEFreezeError("lexically reopened member is not unique regular")
        return _read_fd(descriptor), _stat_identity(observed)
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _validate_semantics(captured: Mapping[str, bytes]) -> None:
    protocol = expected_protocol()
    conditions = expected_conditions()
    runtimes = expected_runtime_identities()
    storage = expected_storage_identities()
    expected_json = {
        PROTOCOL_PATH: protocol,
        CONDITIONS_PATH: conditions,
        RUNTIME_IDENTITIES_PATH: runtimes,
        STORAGE_IDENTITIES_PATH: storage,
    }
    for path, expected in expected_json.items():
        observed = parse_strict_json(captured[path], label=path)
        if canonical_json(observed) != canonical_json(expected):
            raise ExperimentEFreezeError(f"{path} differs from the exact declaration")

    source_protocol = parse_strict_json(
        captured["manifests/EXPERIMENT_PROTOCOL.json"],
        label="manifests/EXPERIMENT_PROTOCOL.json",
    )
    try:
        family = source_protocol["experiment_families"]["E_performance_scalability"]
    except (KeyError, TypeError) as exc:
        raise ExperimentEFreezeError("committed Experiment E family is absent") from exc
    if family.get("required_conditions") != list(REQUIRED_CONDITION_IDS):
        raise ExperimentEFreezeError("committed Experiment E condition order drifted")
    if family.get("status") != "BLOCKED_NOT_MATRIX_FROZEN":
        raise ExperimentEFreezeError("source protocol prematurely changed Experiment E status")

    schedule = captured[SCHEDULE_PATH]
    if schedule != expected_schedule_bytes():
        raise ExperimentEFreezeError("schedule is noncanonical or differs from reconstruction")
    if _sha256(schedule) != SCHEDULE_KNOWN_SHA256:
        raise ExperimentEFreezeError("schedule disagrees with known-answer SHA-256")
    try:
        decoded = schedule.decode("ascii")
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        rows = list(reader)
    except (UnicodeError, csv.Error) as exc:
        raise ExperimentEFreezeError("schedule is not strict ASCII CSV") from exc
    if tuple(reader.fieldnames or ()) != SCHEDULE_HEADER or len(rows) != 2310:
        raise ExperimentEFreezeError("schedule schema or count is not exact")
    if len({row["cell_id"] for row in rows}) != 2310:
        raise ExperimentEFreezeError("schedule contains duplicate cell identities")
    if any(row["principal_eligible"] != "FALSE" for row in rows):
        raise ExperimentEFreezeError("schedule contains a principal-eligible cell")

    expected_bind = expected_binding(
        {path: captured[path] for path in FREEZE_MEMBERS}
    )
    observed_bind = parse_strict_json(captured[BINDING_PATH], label=BINDING_PATH)
    if canonical_json(observed_bind) != canonical_json(expected_bind):
        raise ExperimentEFreezeError("freeze binding differs from exact member group")

    for path, expected_hash in FOUNDATION_BINDINGS.items():
        if _sha256(captured[path]) != expected_hash:
            raise ExperimentEFreezeError(f"foundation dependency hash drift: {path}")


ValidationHook = Callable[[str, Path, _OpenGroup], None]


def validate_repository(
    repository_root: Path,
    *,
    require_principal_ready: bool = False,
    validation_hook: ValidationHook | None = None,
) -> dict[str, object]:
    root = repository_root.resolve()
    paths = tuple(FREEZE_MEMBERS) + tuple(FOUNDATION_BINDINGS) + (BINDING_PATH,)
    if len(paths) != len(set(paths)):
        raise ExperimentEFreezeError("freeze validation group contains duplicate paths")
    watcher = _LinuxInotifyGroupWatch(root, paths)
    group: _OpenGroup | None = None
    binding_digest: str | None = None
    try:
        group = _open_group(root, paths)
        watcher.assert_quiet("after opening complete held group")

        def run_hook(stage: str) -> None:
            watcher.assert_quiet(f"before hook {stage}")
            if validation_hook is not None:
                assert group is not None
                validation_hook(stage, root, group)
            watcher.assert_quiet(f"after hook {stage}")

        run_hook("after_group_open")
        _validate_semantics(group.file_bytes)
        run_hook("after_semantic_validation")

        for label, descriptor, identity in group.parent_fds:
            if _stat_identity(os.fstat(descriptor)) != identity:
                raise ExperimentEFreezeError(
                    f"parent path mutated during validation: {label}"
                )
        for path, descriptor in group.file_fds.items():
            run_hook(f"before_final_member_recheck:{path}")
            if _stat_identity(os.fstat(descriptor)) != group.file_stats[path]:
                raise ExperimentEFreezeError(
                    f"held member identity changed during validation: {path}"
                )
            if _read_fd(descriptor) != group.file_bytes[path]:
                raise ExperimentEFreezeError(
                    f"held member bytes changed during validation: {path}"
                )
            reopened_bytes, reopened_identity = _fresh_lexical_read(group.root_fd, path)
            if reopened_identity != group.file_stats[path] or reopened_bytes != group.file_bytes[path]:
                raise ExperimentEFreezeError(
                    f"lexically reopened member changed during validation: {path}"
                )
            watcher.assert_quiet(f"after final lexical recheck: {path}")
        for label, descriptor, identity in group.parent_fds:
            if _stat_identity(os.fstat(descriptor)) != identity:
                raise ExperimentEFreezeError(
                    f"parent path mutated after validation: {label}"
                )
        for path, descriptor in group.file_fds.items():
            if (
                _stat_identity(os.fstat(descriptor)) != group.file_stats[path]
                or _read_fd(descriptor) != group.file_bytes[path]
            ):
                raise ExperimentEFreezeError(
                    f"held group changed during final complete reread: {path}"
                )
        watcher.assert_quiet("after final complete held-descriptor reread")
        binding_digest = _sha256(group.file_bytes[BINDING_PATH])
    finally:
        if group is not None:
            group.close()
        watcher.close()

    if require_principal_ready:
        raise ExperimentEFreezeError(
            "principal execution blocked: " + ",".join(_all_entity_blockers())
        )
    assert binding_digest is not None
    return {
        "binding_sha256": binding_digest,
        "cells": 2310,
        "conditions": 11,
        "paired_blocks": 210,
        "principal_eligible": False,
        "runtime_identities": 3,
        "schedule_sha256": SCHEDULE_KNOWN_SHA256,
        "schema": VALIDATION_SCHEMA,
        "status": "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED",
    }


def _atomic_write(path: Path, data: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        raise ExperimentEFreezeError(f"refusing to replace existing generated file: {path}")
    if path.is_symlink():
        raise ExperimentEFreezeError(f"refusing to write through symbolic link: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def materialize_generated_files(repository_root: Path, *, replace: bool) -> dict[str, object]:
    root = repository_root.resolve()
    generated = {
        PROTOCOL_PATH: canonical_json(expected_protocol()),
        CONDITIONS_PATH: canonical_json(expected_conditions()),
        RUNTIME_IDENTITIES_PATH: canonical_json(expected_runtime_identities()),
        STORAGE_IDENTITIES_PATH: canonical_json(expected_storage_identities()),
        SCHEDULE_PATH: expected_schedule_bytes(),
    }
    for relative, data in generated.items():
        _atomic_write(root / relative, data, replace=replace)
    member_bytes = {}
    for relative in FREEZE_MEMBERS:
        candidate = root / relative
        if not candidate.is_file() or candidate.is_symlink():
            raise ExperimentEFreezeError(
                f"freeze member must exist before binding: {relative}"
            )
        member_bytes[relative] = candidate.read_bytes()
    _atomic_write(
        root / BINDING_PATH,
        canonical_json(expected_binding(member_bytes)),
        replace=replace,
    )
    return validate_repository(root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--repository-root", type=Path, default=Path.cwd())
    validate.add_argument("--require-principal-ready", action="store_true")
    write = subparsers.add_parser("write")
    write.add_argument("--repository-root", type=Path, default=Path.cwd())
    write.add_argument("--replace-generated", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            report = validate_repository(
                args.repository_root,
                require_principal_ready=args.require_principal_ready,
            )
        else:
            report = materialize_generated_files(
                args.repository_root,
                replace=args.replace_generated,
            )
    except (ExperimentEFreezeError, OSError) as exc:
        print(f"Experiment E freeze: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
