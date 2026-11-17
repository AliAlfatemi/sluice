"""Prospective, outcome-free freeze for controlled Experiment A.

This module freezes a finite CPU-only controlled-QIF design.  It deliberately
does not load a model, tokenizer, endpoint, GPU runtime, or principal result.
The schedule contains only pre-outcome coordinates.  A separate principal
gate remains closed even when the structural freeze validates.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Callable, Iterable, Mapping, Sequence


CONDITIONS_SCHEMA = "sluice.experiment-a.conditions.v1"
MATRIX_SCHEMA = "sluice.experiment-a.matrix.v1"
PROTOCOL_SCHEMA = "sluice.experiment-a.protocol.v1"
SCHEDULE_SCHEMA = "sluice.experiment-a.schedule-path.v1"
BINDING_SCHEMA = "sluice.experiment-a.freeze-bindings.v1"
VALIDATION_SCHEMA = "sluice.experiment-a.freeze-validation.v1"
FOUNDATION_COMMIT = "bb7e7e5b629cfdc0b4b5c472d5ea896026266375"
ACCOUNTING_UNITS_PER_BIT = 1
DECISION_TOLERANCE = "0.0000000001"
PRIMARY_HORIZON = 16
SENSITIVITY_HORIZONS = (4, 8, 32)
PUBLIC_TAPES = ("tape-0", "tape-1", "tape-2", "tape-3")

CONDITIONS_PATH = "manifests/EXPERIMENT_A_CONDITIONS.json"
MATRIX_PATH = "manifests/EXPERIMENT_A_MATRIX.csv"
PROTOCOL_PATH = "manifests/EXPERIMENT_A_PROTOCOL.json"
SCHEDULE_PATH = "manifests/EXPERIMENT_A_SCHEDULE.jsonl"
BINDING_PATH = "manifests/EXPERIMENT_A_FREEZE_BINDINGS.json"

FOUNDATION_BINDINGS: Mapping[str, str] = {
    "analysis/ANALYSIS_PLAN.md": (
        "1c3d08c7ec0e0cc73c684ea70cd68ee1155474215f3988024cd04671c0ef31a4"
    ),
    "analysis/INFORMATION_THEORETIC_PROOF.md": (
        "a519e81b744253d324775534745d7120968e683ca5e2c594ea0b27aa282adb99"
    ),
    "source/artifact/sluice_v2/observer.py": (
        "fa0bf3ccb0ad38037a323c62d3e5377e0e8890819134a780c72897a178d04ce5"
    ),
    "source/artifact/sluice_v2/qif_validation.py": (
        "6bc40c08627505ffb8b55045a3a2d88bb5861eb8107649bb09c7d8e70de27833"
    ),
}

FREEZE_MEMBERS = (
    "analysis/EXPERIMENT_A_CONTROLLED_QIF_PROTOCOL.md",
    CONDITIONS_PATH,
    MATRIX_PATH,
    PROTOCOL_PATH,
    SCHEDULE_PATH,
    "source/artifact/experiments/analyze_experiment_a_exact.py",
    "source/artifact/experiments/run_experiment_a_exact.py",
    "source/artifact/experiments/validate_experiment_a_freeze.py",
    "source/artifact/sluice_v2/evaluation/experiment_a_analyzer.py",
    "source/artifact/sluice_v2/evaluation/experiment_a_freeze.py",
    "source/artifact/sluice_v2/evaluation/experiment_a_runner.py",
    "source/artifact/sluice_v2/tests/test_v31_experiment_a_freeze.py",
    "source/artifact/sluice_v2/tests/test_v32_experiment_a_runner_analyzer.py",
)

PRINCIPAL_BLOCKERS = (
    "BLOCKED_CLEAN_COMMITTED_EXPERIMENT_A_FREEZE",
    "BLOCKED_INDEPENDENT_EXPERIMENT_A_REAUDIT",
    "BLOCKED_LIVE_CONTROLLED_RUNNER_AND_ISOLATION",
    "BLOCKED_PRINCIPAL_OUTPUT_DIRECTORY_NOT_AUTHORIZED",
)

MATRIX_HEADER = (
    "matrix_schema",
    "row_index",
    "row_id",
    "prior_id",
    "condition_id",
    "condition_role",
    "epoch_attempt_horizon_h",
    "public_outer_capture_hmax",
    "max_reauthorizations",
    "reauth_horizon_increment",
    "reauth_budget_increment_units",
    "path_count",
    "observer_projections",
    "security_endpoint",
    "charge_endpoint",
    "utility_endpoint",
    "count_endpoint",
    "decision_tolerance_bits",
    "principal_eligible",
    "blocker_codes",
)


class ExperimentAFreezeError(ValueError):
    """The controlled-QIF freeze is malformed or its gate is closed."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ExperimentAFreezeError(
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
        raise ExperimentAFreezeError("value is outside canonical JSON") from exc
    return (text + "\n").encode("ascii")


def canonical_json_line(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ExperimentAFreezeError("value is outside canonical JSONL") from exc
    return (text + "\n").encode("ascii")


def parse_strict_json(data: bytes, *, label: str, canonical: bool = True) -> object:
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_strict_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ExperimentAFreezeError(f"non-finite JSON value in {label}: {item}")
            ),
        )
    except ExperimentAFreezeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExperimentAFreezeError(f"{label} is not strict ASCII JSON") from exc
    if canonical and data != canonical_json(value):
        raise ExperimentAFreezeError(f"{label} is not canonical pretty JSON")
    return value


def parse_strict_jsonl(data: bytes, *, label: str) -> list[object]:
    if not data or not data.endswith(b"\n"):
        raise ExperimentAFreezeError(f"{label} is not newline-terminated JSONL")
    result: list[object] = []
    for number, raw in enumerate(data.splitlines(keepends=True), start=1):
        try:
            value = json.loads(
                raw.decode("ascii"),
                object_pairs_hook=_strict_pairs,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    ExperimentAFreezeError(
                        f"non-finite JSON value in {label}:{number}: {item}"
                    )
                ),
            )
        except ExperimentAFreezeError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ExperimentAFreezeError(
                f"{label}:{number} is not strict ASCII JSON"
            ) from exc
        if raw != canonical_json_line(value):
            raise ExperimentAFreezeError(
                f"{label}:{number} is not canonical compact JSON"
            )
        result.append(value)
    return result


def _mechanism(
    *,
    mediation: str,
    observer_projection: str,
    reserve_before_observation: bool,
    attempt_horizon_enforced: bool,
    route_charge_rule: str,
    denials_charged: bool,
    stop_charged: bool,
    deterministic_padding: bool,
    reauth_charged: bool,
    lifetime_spend_resets: bool,
    budget_scope: str,
    postclose_stutter: bool,
    isolation_topology: str,
) -> dict[str, object]:
    return {
        "attempt_horizon_enforced": attempt_horizon_enforced,
        "budget_scope": budget_scope,
        "denials_charged": denials_charged,
        "deterministic_padding": deterministic_padding,
        "isolation_topology": isolation_topology,
        "lifetime_spend_resets": lifetime_spend_resets,
        "mediation": mediation,
        "observer_projection": observer_projection,
        "outer_capture_hmax": "PUBLIC_FIXED_PADDED_CAPTURE",
        "postclose_stutter": postclose_stutter,
        "reauth_charged": reauth_charged,
        "reserve_before_observation": reserve_before_observation,
        "route_charge_rule": route_charge_rule,
        "stop_charged": stop_charged,
    }


def expected_conditions() -> dict[str, object]:
    complete = _mechanism(
        mediation="SLUICE",
        observer_projection="COMPLETE_TYPED_TRANSCRIPT",
        reserve_before_observation=True,
        attempt_horizon_enforced=True,
        route_charge_rule="UNION_SUPPORT_PREOBSERVATION",
        denials_charged=True,
        stop_charged=True,
        deterministic_padding=True,
        reauth_charged=True,
        lifetime_spend_resets=False,
        budget_scope="SHARED_BUDGET_DOMAIN",
        postclose_stutter=True,
        isolation_topology="CONTROLLED_SINGLETON_BOUNDARY",
    )
    no_horizon = dict(complete)
    no_horizon["attempt_horizon_enforced"] = False
    success_only = dict(complete)
    success_only.update(
        {
            "denials_charged": False,
            "route_charge_rule": "SUCCESS_VALUE_ONLY",
            "stop_charged": False,
        }
    )
    per_object = dict(complete)
    per_object["budget_scope"] = "PER_OBJECT_UNCOORDINATED"
    shared = dict(complete)
    shared["budget_scope"] = "SHARED_CORRELATED_SECRET_DOMAIN"
    conditions = [
        {
            "condition_id": "unmediated",
            "controlled_family": "A1_scalar_complete_transcript",
            "ordinal": 1,
            "policy_identity": "a1.unmediated.raw-secret.v1",
            "positive_assertion": False,
            "mechanism": _mechanism(
                mediation="NONE",
                observer_projection="UNMEDIATED_RAW_BYTES",
                reserve_before_observation=False,
                attempt_horizon_enforced=False,
                route_charge_rule="NONE",
                denials_charged=False,
                stop_charged=False,
                deterministic_padding=False,
                reauth_charged=False,
                lifetime_spend_resets=True,
                budget_scope="NONE",
                postclose_stutter=False,
                isolation_topology="DIRECT_UNMEDIATED",
            ),
        },
        {
            "condition_id": "sluice_result_only_accounting_old_design",
            "controlled_family": "A1_scalar_complete_transcript",
            "ordinal": 2,
            "policy_identity": "a1.legacy.result-only-accounting.v1",
            "positive_assertion": False,
            "mechanism": _mechanism(
                mediation="SLUICE_LEGACY",
                observer_projection="RESULT_ONLY",
                reserve_before_observation=True,
                attempt_horizon_enforced=False,
                route_charge_rule="SUCCESS_VALUE_ONLY",
                denials_charged=False,
                stop_charged=False,
                deterministic_padding=False,
                reauth_charged=False,
                lifetime_spend_resets=True,
                budget_scope="PER_OBJECT_UNCOORDINATED",
                postclose_stutter=False,
                isolation_topology="IN_PROCESS_LEGACY",
            ),
        },
        {
            "condition_id": "sluice_complete_typed_transcript",
            "controlled_family": "A1_scalar_complete_transcript",
            "ordinal": 3,
            "policy_identity": "a1.complete.single-event-codebook.v1",
            "positive_assertion": True,
            "mechanism": complete,
        },
        {
            "condition_id": "sluice_without_attempt_horizon_enforcement",
            "controlled_family": "A1_scalar_complete_transcript",
            "ordinal": 4,
            "policy_identity": "a1.complete.no-mechanism-horizon.v1",
            "positive_assertion": False,
            "mechanism": no_horizon,
        },
        {
            "condition_id": "sluice_with_success_only_route_charging",
            "controlled_family": "A1_route_denial_stop",
            "ordinal": 5,
            "policy_identity": "a1.lifecycle.success-only-route-charge.v1",
            "positive_assertion": False,
            "mechanism": success_only,
        },
        {
            "condition_id": "sluice_with_route_denial_stopping_enforcement",
            "controlled_family": "A1_route_denial_stop",
            "ordinal": 6,
            "policy_identity": "a1.lifecycle.complete-enforcement.v1",
            "positive_assertion": True,
            "mechanism": dict(complete),
        },
        {
            "condition_id": "per_object_budgets",
            "controlled_family": "A2_correlated_domain_composition",
            "ordinal": 7,
            "policy_identity": "a2.per-object.uncoordinated.v1",
            "positive_assertion": False,
            "mechanism": per_object,
        },
        {
            "condition_id": "shared_correlated_secret_budget_domains",
            "controlled_family": "A2_correlated_domain_composition",
            "ordinal": 8,
            "policy_identity": "a2.shared-correlated-domain.v1",
            "positive_assertion": True,
            "mechanism": shared,
        },
    ]
    return {
        "conditions": conditions,
        "mechanism_vector_fields": [
            "mediation",
            "observer_projection",
            "reserve_before_observation",
            "attempt_horizon_enforced",
            "outer_capture_hmax",
            "route_charge_rule",
            "denials_charged",
            "stop_charged",
            "deterministic_padding",
            "reauth_charged",
            "lifetime_spend_resets",
            "budget_scope",
            "postclose_stutter",
            "isolation_topology",
        ],
        "schema": CONDITIONS_SCHEMA,
    }


def _row_id(prior_id: str, condition_id: str, horizon: int) -> str:
    material = f"{MATRIX_SCHEMA}\0{prior_id}\0{condition_id}\0{horizon}".encode(
        "ascii"
    )
    return "a-" + hashlib.sha256(material).hexdigest()[:24]


def expected_rows() -> list[dict[str, str]]:
    coordinates: list[tuple[str, str, int, str]] = []
    for condition in (
        "unmediated",
        "sluice_result_only_accounting_old_design",
        "sluice_complete_typed_transcript",
        "sluice_without_attempt_horizon_enforcement",
        "sluice_with_success_only_route_charging",
        "sluice_with_route_denial_stopping_enforcement",
    ):
        role = (
            "primary_positive_assertion"
            if condition
            in {
                "sluice_complete_typed_transcript",
                "sluice_with_route_denial_stopping_enforcement",
            }
            else "required_control_or_ablation"
        )
        coordinates.append(("A1", condition, PRIMARY_HORIZON, role))
    for horizon in SENSITIVITY_HORIZONS:
        coordinates.append(
            (
                "A1",
                "sluice_complete_typed_transcript",
                horizon,
                "secondary_positive_horizon_sensitivity",
            )
        )
    coordinates.extend(
        [
            (
                "A2",
                "per_object_budgets",
                PRIMARY_HORIZON,
                "required_control_or_ablation",
            ),
            (
                "A2",
                "shared_correlated_secret_budget_domains",
                PRIMARY_HORIZON,
                "primary_positive_assertion",
            ),
        ]
    )
    for horizon in SENSITIVITY_HORIZONS:
        coordinates.append(
            (
                "A2",
                "shared_correlated_secret_budget_domains",
                horizon,
                "secondary_positive_horizon_sensitivity",
            )
        )
    rows: list[dict[str, str]] = []
    for index, (prior, condition, horizon, role) in enumerate(coordinates, start=1):
        paths = 64 if prior == "A1" else 16
        blockers = list(PRINCIPAL_BLOCKERS)
        if condition == "sluice_without_attempt_horizon_enforcement":
            blockers.append("BLOCKED_MECHANISM_ATTEMPT_HORIZON_DISABLED")
        if condition in {
            "unmediated",
            "sluice_result_only_accounting_old_design",
            "sluice_with_success_only_route_charging",
            "per_object_budgets",
        }:
            blockers.append("BLOCKED_REQUIRED_UNSOUND_CONTROL_NOT_LAUNCH_ELIGIBLE")
        rows.append(
            {
                "matrix_schema": MATRIX_SCHEMA,
                "row_index": str(index),
                "row_id": _row_id(prior, condition, horizon),
                "prior_id": prior,
                "condition_id": condition,
                "condition_role": role,
                "epoch_attempt_horizon_h": str(horizon),
                "public_outer_capture_hmax": str(2 * horizon),
                "max_reauthorizations": "1",
                "reauth_horizon_increment": str(horizon),
                "reauth_budget_increment_units": "2",
                "path_count": str(paths),
                "observer_projections": "observer_A|observer_B|colluding_union",
                "security_endpoint": (
                    "exact_conditional_mutual_information_bits_and_"
                    "maximum_certified_bound_overshoot"
                ),
                "charge_endpoint": "exact_expected_and_max_path_charge_units",
                "utility_endpoint": "exact_weighted_requested_field_completion",
                "count_endpoint": "exact_path_mass_and_path_count",
                "decision_tolerance_bits": DECISION_TOLERANCE,
                "principal_eligible": "FALSE",
                "blocker_codes": "|".join(sorted(blockers)),
            }
        )
    return rows


def expected_matrix_bytes() -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=MATRIX_HEADER,
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    writer.writerows(expected_rows())
    return stream.getvalue().encode("ascii")


def _a1_secrets() -> list[dict[str, object]]:
    return [
        {"secret_id": f"s{value:02d}", "value": value, "weight": "1/16"}
        for value in range(16)
    ]


def _a2_secrets() -> list[dict[str, object]]:
    return [
        {"secret_id": "00", "value": [0, 0], "weight": "3/8"},
        {"secret_id": "01", "value": [0, 1], "weight": "1/8"},
        {"secret_id": "10", "value": [1, 0], "weight": "1/8"},
        {"secret_id": "11", "value": [1, 1], "weight": "3/8"},
    ]


def expected_protocol() -> dict[str, object]:
    return {
        "analysis": {
            "decision_contract": {
                "ambiguous_interval_action": "FAIL_CLOSED",
                "bound_holds": "mi_upper <= certified_bound + tolerance",
                "directed_decimal_precision_digits": 80,
                "tolerance_bits": DECISION_TOLERANCE,
            },
            "endpoints": {
                "charge": "exact weighted expected and maximum path charge",
                "counts": "exact path count and rational mass",
                "information": (
                    "exact rational joint laws plus directed high-precision "
                    "mutual-information interval in base 2"
                ),
                "security": "maximum positive certified-bound overshoot",
                "utility": "exact weighted requested-field completion fraction",
            },
            "observers": ["observer_A", "observer_B", "colluding_union"],
            "timing_and_resource_channels": "EXCLUDED_AND_NOT_CLAIMED",
        },
        "execution_boundary": {
            "cpu_only": True,
            "exact_enumeration_only": True,
            "gpu_allowed": False,
            "live_endpoint_allowed": False,
            "model_loading_allowed": False,
            "network_allowed": False,
            "principal_outcomes_allowed": False,
            "tokenizer_loading_allowed": False,
        },
        "foundation_commit": FOUNDATION_COMMIT,
        "horizon": {
            "meaning_of_h": "mechanism epoch observer-relevant attempt horizon",
            "meaning_of_hmax": (
                "public finite lifetime outer capture including the one fixed "
                "reauthorization extension; not evidence that an ablated mechanism "
                "enforces H"
            ),
            "max_reauthorizations": 1,
            "outer_hmax_formula": "H*(1+max_reauthorizations)",
            "primary_h": PRIMARY_HORIZON,
            "reauth_budget_increment_units": 2,
            "reauth_horizon_increment_formula": "H",
            "sensitivities_h": list(SENSITIVITY_HORIZONS),
        },
        "lifecycle": {
            "denied_reauthorization_is_charged_in_positive_conditions": True,
            "epoch_spend_may_restart_only_in_a_new_epoch": True,
            "lifetime_spend_resets": False,
            "postclose_slots": "typed deterministic DOMAIN_CLOSED stutter",
            "reauthorization_grant_reuse": "charged denial; no new epoch or increment",
            "successful_reauthorization": (
                "one-use; add exactly one public epoch, H horizon units, and two "
                "budget units"
            ),
        },
        "matrix": {
            "a1_paths_per_row": 64,
            "a1_rows": 9,
            "a2_paths_per_row": 16,
            "a2_rows": 5,
            "path_arithmetic": "9*64 + 5*16 = 656",
            "rows": 14,
            "total_weighted_paths": 656,
        },
        "priors": {
            "A1": {
                "public_tape_prior": [
                    {"tape_id": tape, "weight": "1/4"} for tape in PUBLIC_TAPES
                ],
                "secret_prior": _a1_secrets(),
                "secret_type": "scalar_4bit",
            },
            "A2": {
                "public_tape_prior": [
                    {"tape_id": tape, "weight": "1/4"} for tape in PUBLIC_TAPES
                ],
                "secret_prior": _a2_secrets(),
                "secret_type": "correlated_binary_pair",
            },
        },
        "principal_eligibility": {
            "blockers": list(PRINCIPAL_BLOCKERS),
            "eligible": False,
            "structural_validation_is_launch_authorization": False,
        },
        "retry_policy": {
            "attempt_numbers_start_at": 1,
            "initial_schedule_contains_retries": False,
            "retry_must_bind_prior_attempt_sha256": True,
            "write_rule": "append-only create-once; never replace an attempt",
        },
        "schedule": {
            "contains_outcomes": False,
            "order": "matrix row, public tape, canonical secret order",
            "scheduler_inputs": [
                "frozen row identity",
                "public tape identity",
                "canonical prior support identity",
            ],
            "secret_or_outcome_dependent_scheduling": False,
        },
        "schema": PROTOCOL_SCHEMA,
    }


def _weight_components(prior_id: str, secret_id: str) -> tuple[int, int]:
    if prior_id == "A1":
        return (1, 64)
    if prior_id == "A2":
        return ((3 if secret_id in {"00", "11"} else 1), 32)
    raise AssertionError(prior_id)


def expected_schedule() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    sequence = 0
    for row in expected_rows():
        prior_id = row["prior_id"]
        secrets = _a1_secrets() if prior_id == "A1" else _a2_secrets()
        for tape in PUBLIC_TAPES:
            for secret in secrets:
                numerator, denominator = _weight_components(
                    prior_id, str(secret["secret_id"])
                )
                record = {
                    "attempt_number": 1,
                    "condition_id": row["condition_id"],
                    "epoch_attempt_horizon_h": int(
                        row["epoch_attempt_horizon_h"]
                    ),
                    "path_index": sequence,
                    "path_weight_denominator": denominator,
                    "path_weight_numerator": numerator,
                    "principal_eligible": False,
                    "prior_attempt_sha256": None,
                    "prior_id": prior_id,
                    "public_outer_capture_hmax": int(
                        row["public_outer_capture_hmax"]
                    ),
                    "public_tape_id": tape,
                    "row_id": row["row_id"],
                    "run_state": "STRUCTURAL_PATH_ONLY_PRINCIPAL_BLOCKED",
                    "schedule_schema": SCHEDULE_SCHEMA,
                    "secret_id": secret["secret_id"],
                }
                records.append(record)
                sequence += 1
    if sequence != 656:
        raise AssertionError(sequence)
    return records


def expected_schedule_bytes() -> bytes:
    return b"".join(canonical_json_line(record) for record in expected_schedule())


def _relative_path(value: str) -> PurePosixPath:
    if type(value) is not str or not value or "\\" in value:
        raise ExperimentAFreezeError("freeze member path is not canonical")
    try:
        value.encode("ascii")
    except UnicodeError as exc:
        raise ExperimentAFreezeError("freeze member path is not ASCII") from exc
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ExperimentAFreezeError("freeze member escapes the repository")
    if path.as_posix() != value:
        raise ExperimentAFreezeError("freeze member path has an alias spelling")
    return path


def expected_binding(repository_root: Path) -> dict[str, object]:
    members = []
    for relative in FREEZE_MEMBERS:
        _relative_path(relative)
        data = (repository_root / relative).read_bytes()
        members.append(
            {"bytes": len(data), "path": relative, "sha256": _sha256(data)}
        )
    return {
        "evidence_boundary": (
            "prospective CPU-only structural and exact finite-model foundation; "
            "not a live, model, deployment, GPU, or principal result"
        ),
        "foundation_bindings": [
            {"path": path, "sha256": digest}
            for path, digest in sorted(FOUNDATION_BINDINGS.items())
        ],
        "foundation_commit": FOUNDATION_COMMIT,
        "members": members,
        "principal_eligible": False,
        "schema": BINDING_SCHEMA,
    }


def emit_generated_manifests(repository_root: Path) -> None:
    outputs = {
        CONDITIONS_PATH: canonical_json(expected_conditions()),
        MATRIX_PATH: expected_matrix_bytes(),
        PROTOCOL_PATH: canonical_json(expected_protocol()),
        SCHEDULE_PATH: expected_schedule_bytes(),
    }
    for relative, data in outputs.items():
        path = repository_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise ExperimentAFreezeError(f"refusing to replace existing {relative}")
        path.write_bytes(data)


def emit_binding(repository_root: Path) -> None:
    path = repository_root / BINDING_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ExperimentAFreezeError(f"refusing to replace existing {BINDING_PATH}")
    path.write_bytes(canonical_json(expected_binding(repository_root)))


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@dataclass
class _HeldMember:
    relative: str
    file_descriptor: int
    file_identity: tuple[int, ...]
    parent_descriptors: tuple[int, ...]
    parent_identities: tuple[tuple[int, ...], ...]
    data: bytes

    def close(self) -> None:
        descriptors = (self.file_descriptor,) + self.parent_descriptors
        self.file_descriptor = -1
        self.parent_descriptors = ()
        for descriptor in descriptors:
            if descriptor >= 0:
                os.close(descriptor)


def _read_fd(descriptor: int, *, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ExperimentAFreezeError("freeze member exceeds byte limit")
    return b"".join(chunks)


def _open_member(root_descriptor: int, relative: str) -> _HeldMember:
    parts = _relative_path(relative).parts
    cursor = os.dup(root_descriptor)
    parent_descriptors = [cursor]
    parent_identities = [_identity(os.fstat(cursor))]
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=cursor,
            )
            cursor = next_descriptor
            parent_descriptors.append(cursor)
            parent_identities.append(_identity(os.fstat(cursor)))
        file_descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=cursor,
        )
        info = os.fstat(file_descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(file_descriptor)
            raise ExperimentAFreezeError(
                f"freeze member must be a single-link regular file: {relative}"
            )
        maximum = 32 * 1024 * 1024 if relative == SCHEDULE_PATH else 4 * 1024 * 1024
        data = _read_fd(file_descriptor, maximum=maximum)
        return _HeldMember(
            relative=relative,
            file_descriptor=file_descriptor,
            file_identity=_identity(info),
            parent_descriptors=tuple(parent_descriptors),
            parent_identities=tuple(parent_identities),
            data=data,
        )
    except Exception:
        for descriptor in parent_descriptors:
            os.close(descriptor)
        raise


def _open_group(repository_root: Path) -> tuple[int, dict[str, _HeldMember]]:
    root_descriptor = os.open(
        repository_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    members: dict[str, _HeldMember] = {}
    identities: dict[tuple[int, int], str] = {}
    try:
        paths = tuple(sorted(set(FREEZE_MEMBERS) | set(FOUNDATION_BINDINGS) | {BINDING_PATH}))
        if len(paths) != len(FREEZE_MEMBERS) + len(FOUNDATION_BINDINGS) + 1:
            raise ExperimentAFreezeError("freeze group contains duplicate paths")
        for relative in paths:
            held = _open_member(root_descriptor, relative)
            key = (held.file_identity[0], held.file_identity[1])
            if key in identities:
                held.close()
                raise ExperimentAFreezeError(
                    f"hard-link alias between {identities[key]} and {relative}"
                )
            identities[key] = relative
            members[relative] = held
        return root_descriptor, members
    except Exception:
        for held in members.values():
            held.close()
        os.close(root_descriptor)
        raise


def _validate_semantics(members: Mapping[str, _HeldMember]) -> dict[str, object]:
    if members[CONDITIONS_PATH].data != canonical_json(expected_conditions()):
        raise ExperimentAFreezeError("conditions manifest differs from reconstruction")
    if members[MATRIX_PATH].data != expected_matrix_bytes():
        raise ExperimentAFreezeError("matrix differs from reconstruction")
    if members[PROTOCOL_PATH].data != canonical_json(expected_protocol()):
        raise ExperimentAFreezeError("protocol differs from reconstruction")
    if members[SCHEDULE_PATH].data != expected_schedule_bytes():
        raise ExperimentAFreezeError("schedule differs from reconstruction")

    binding = parse_strict_json(
        members[BINDING_PATH].data, label=BINDING_PATH, canonical=True
    )
    if type(binding) is not dict:
        raise ExperimentAFreezeError("binding root must be an object")
    exact_keys = {
        "evidence_boundary",
        "foundation_bindings",
        "foundation_commit",
        "members",
        "principal_eligible",
        "schema",
    }
    if set(binding) != exact_keys:
        raise ExperimentAFreezeError("binding has missing or unknown fields")
    if binding["schema"] != BINDING_SCHEMA:
        raise ExperimentAFreezeError("binding schema mismatch")
    if binding["foundation_commit"] != FOUNDATION_COMMIT:
        raise ExperimentAFreezeError("binding foundation commit mismatch")
    if binding["principal_eligible"] is not False:
        raise ExperimentAFreezeError("binding principal gate must be false")
    expected_foundations = [
        {"path": path, "sha256": digest}
        for path, digest in sorted(FOUNDATION_BINDINGS.items())
    ]
    if binding["foundation_bindings"] != expected_foundations:
        raise ExperimentAFreezeError("foundation binding set differs")
    expected_paths = list(FREEZE_MEMBERS)
    raw_members = binding["members"]
    if type(raw_members) is not list or len(raw_members) != len(expected_paths):
        raise ExperimentAFreezeError("binding member list has wrong cardinality")
    seen: set[str] = set()
    for index, item in enumerate(raw_members):
        if type(item) is not dict or set(item) != {"bytes", "path", "sha256"}:
            raise ExperimentAFreezeError("binding member has wrong exact schema")
        path = item["path"]
        if type(path) is not str or path != expected_paths[index] or path in seen:
            raise ExperimentAFreezeError("binding member order, identity, or uniqueness differs")
        seen.add(path)
        data = members[path].data
        if type(item["bytes"]) is not int or type(item["bytes"]) is bool:
            raise ExperimentAFreezeError("binding byte count must be a strict integer")
        if item["bytes"] != len(data) or item["sha256"] != _sha256(data):
            raise ExperimentAFreezeError(f"binding digest or size mismatch: {path}")
    for path, digest in FOUNDATION_BINDINGS.items():
        if _sha256(members[path].data) != digest:
            raise ExperimentAFreezeError(f"foundation digest mismatch: {path}")

    schedule = parse_strict_jsonl(members[SCHEDULE_PATH].data, label=SCHEDULE_PATH)
    forbidden = {"outcome", "events", "transcript", "utility", "charge"}
    for record in schedule:
        if type(record) is not dict:
            raise ExperimentAFreezeError("schedule record must be an object")
        if forbidden.intersection(record):
            raise ExperimentAFreezeError("outcome-bearing field found in schedule")
        for field in (
            "attempt_number",
            "epoch_attempt_horizon_h",
            "path_index",
            "path_weight_denominator",
            "path_weight_numerator",
            "public_outer_capture_hmax",
        ):
            if type(record[field]) is not int:
                raise ExperimentAFreezeError(f"schedule {field} must be a strict integer")
        if record["principal_eligible"] is not False:
            raise ExperimentAFreezeError("schedule principal gate must be false")
    if len(schedule) != 656:
        raise ExperimentAFreezeError("schedule must contain exactly 656 paths")
    rows = expected_rows()
    if len(rows) != 14 or sum(int(row["path_count"]) for row in rows) != 656:
        raise ExperimentAFreezeError("matrix path arithmetic differs")
    return {
        "binding_sha256": _sha256(members[BINDING_PATH].data),
        "conditions": 8,
        "matrix_rows": 14,
        "principal_eligible": False,
        "schedule_paths": 656,
        "schema": VALIDATION_SCHEMA,
        "status": "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED",
    }


def _revalidate_group(
    repository_root: Path,
    root_descriptor: int,
    members: Mapping[str, _HeldMember],
) -> None:
    for relative, held in members.items():
        if _identity(os.fstat(held.file_descriptor)) != held.file_identity:
            raise ExperimentAFreezeError(
                f"held descriptor identity changed during validation: {relative}"
            )
        maximum = 32 * 1024 * 1024 if relative == SCHEDULE_PATH else 4 * 1024 * 1024
        if _read_fd(held.file_descriptor, maximum=maximum) != held.data:
            raise ExperimentAFreezeError(
                f"held descriptor bytes changed during validation: {relative}"
            )
        for descriptor, identity in zip(
            held.parent_descriptors, held.parent_identities
        ):
            if _identity(os.fstat(descriptor)) != identity:
                raise ExperimentAFreezeError(
                    f"parent path mutated during validation: {relative}"
                )
        reopened = _open_member(root_descriptor, relative)
        try:
            if reopened.file_identity != held.file_identity or reopened.data != held.data:
                raise ExperimentAFreezeError(
                    f"lexical path rebound during validation: {relative}"
                )
        finally:
            reopened.close()
    root_info = os.fstat(root_descriptor)
    path_info = os.stat(repository_root, follow_symlinks=False)
    if (root_info.st_dev, root_info.st_ino) != (path_info.st_dev, path_info.st_ino):
        raise ExperimentAFreezeError("repository root rebound during validation")


ValidationHook = Callable[[str, Path, Mapping[str, bytes]], None]


def validate_repository(
    repository_root: Path,
    *,
    require_principal_ready: bool = False,
    validation_hook: ValidationHook | None = None,
) -> dict[str, object]:
    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be a pathlib.Path")
    root_descriptor, held = _open_group(repository_root)
    try:
        snapshot = {path: member.data for path, member in held.items()}
        if validation_hook is not None:
            validation_hook("after_group_open", repository_root, snapshot)
        report = _validate_semantics(held)
        if validation_hook is not None:
            validation_hook("after_semantic_validation", repository_root, snapshot)
        _revalidate_group(repository_root, root_descriptor, held)
        if require_principal_ready:
            raise ExperimentAFreezeError(
                "principal execution blocked: " + "|".join(PRINCIPAL_BLOCKERS)
            )
        return report
    finally:
        for member in held.values():
            member.close()
        os.close(root_descriptor)


def _repository_root_from_module() -> Path:
    return Path(__file__).resolve().parents[4]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=_repository_root_from_module())
    parser.add_argument("--require-principal-ready", action="store_true")
    parser.add_argument("--emit-generated-manifests", action="store_true")
    parser.add_argument("--emit-binding", action="store_true")
    args = parser.parse_args(argv)
    if args.emit_generated_manifests:
        emit_generated_manifests(args.repository_root)
        return 0
    if args.emit_binding:
        emit_binding(args.repository_root)
        return 0
    report = validate_repository(
        args.repository_root,
        require_principal_ready=args.require_principal_ready,
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
