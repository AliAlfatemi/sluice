"""Structural and hostile tests for the prospective Experiment A freeze."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest

from sluice_v2.evaluation import experiment_a_freeze as freeze
from sluice_v2.evaluation import experiment_a_runner as runner


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def _copy_fixture(target: Path) -> None:
    paths = set(freeze.FREEZE_MEMBERS) | set(freeze.FOUNDATION_BINDINGS) | {
        freeze.BINDING_PATH
    }
    for relative in sorted(paths):
        source = REPOSITORY_ROOT / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def test_exact_freeze_validates_but_principal_gate_stays_closed() -> None:
    report = freeze.validate_repository(REPOSITORY_ROOT)
    assert report == {
        "binding_sha256": report["binding_sha256"],
        "conditions": 8,
        "matrix_rows": 14,
        "principal_eligible": False,
        "schedule_paths": 656,
        "schema": freeze.VALIDATION_SCHEMA,
        "status": "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED",
    }
    assert len(report["binding_sha256"]) == 64
    with pytest.raises(freeze.ExperimentAFreezeError, match="principal execution blocked"):
        freeze.validate_repository(REPOSITORY_ROOT, require_principal_ready=True)


def test_exact_condition_order_vectors_and_positive_assertions() -> None:
    manifest = freeze.expected_conditions()
    identities = [item["condition_id"] for item in manifest["conditions"]]
    assert identities == [
        "unmediated",
        "sluice_result_only_accounting_old_design",
        "sluice_complete_typed_transcript",
        "sluice_without_attempt_horizon_enforcement",
        "sluice_with_success_only_route_charging",
        "sluice_with_route_denial_stopping_enforcement",
        "per_object_budgets",
        "shared_correlated_secret_budget_domains",
    ]
    assert manifest["mechanism_vector_fields"] == [
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
    ]
    vectors = {item["condition_id"]: item for item in manifest["conditions"]}
    assert {
        item["condition_id"]
        for item in manifest["conditions"]
        if item["positive_assertion"] is True
    } == {
        "sluice_complete_typed_transcript",
        "sluice_with_route_denial_stopping_enforcement",
        "shared_correlated_secret_budget_domains",
    }
    assert (
        vectors["sluice_without_attempt_horizon_enforcement"]["mechanism"]
        ["attempt_horizon_enforced"]
        is False
    )
    assert all(
        item["mechanism"]["outer_capture_hmax"] == "PUBLIC_FIXED_PADDED_CAPTURE"
        for item in manifest["conditions"]
    )


def test_fourteen_row_layout_and_656_path_arithmetic_are_exact() -> None:
    rows = freeze.expected_rows()
    assert len(rows) == 14
    assert len({row["row_id"] for row in rows}) == 14
    assert sum(int(row["path_count"]) for row in rows) == 656
    assert [
        (row["prior_id"], row["condition_id"], row["epoch_attempt_horizon_h"])
        for row in rows
    ] == [
        ("A1", "unmediated", "16"),
        ("A1", "sluice_result_only_accounting_old_design", "16"),
        ("A1", "sluice_complete_typed_transcript", "16"),
        ("A1", "sluice_without_attempt_horizon_enforcement", "16"),
        ("A1", "sluice_with_success_only_route_charging", "16"),
        ("A1", "sluice_with_route_denial_stopping_enforcement", "16"),
        ("A1", "sluice_complete_typed_transcript", "4"),
        ("A1", "sluice_complete_typed_transcript", "8"),
        ("A1", "sluice_complete_typed_transcript", "32"),
        ("A2", "per_object_budgets", "16"),
        ("A2", "shared_correlated_secret_budget_domains", "16"),
        ("A2", "shared_correlated_secret_budget_domains", "4"),
        ("A2", "shared_correlated_secret_budget_domains", "8"),
        ("A2", "shared_correlated_secret_budget_domains", "32"),
    ]
    assert all(
        int(row["public_outer_capture_hmax"])
        == 2 * int(row["epoch_attempt_horizon_h"])
        for row in rows
    )
    assert all(row["principal_eligible"] == "FALSE" for row in rows)


def test_schedule_is_outcome_free_exactly_weighted_and_publicly_ordered() -> None:
    schedule = freeze.expected_schedule()
    assert len(schedule) == 656
    assert [record["path_index"] for record in schedule] == list(range(656))
    assert all(record["attempt_number"] == 1 for record in schedule)
    assert all(record["prior_attempt_sha256"] is None for record in schedule)
    forbidden = {"outcome", "events", "transcript", "utility", "charge"}
    assert all(not forbidden.intersection(record) for record in schedule)
    rows = {row["row_id"]: row for row in freeze.expected_rows()}
    for row_id, row in rows.items():
        records = [record for record in schedule if record["row_id"] == row_id]
        assert len(records) == int(row["path_count"])
        assert runner.exact_path_mass(
            [
                {
                    "row_id": record["row_id"],
                    "path_weight_numerator": record["path_weight_numerator"],
                    "path_weight_denominator": record["path_weight_denominator"],
                }
                for record in records
            ]
        )[row_id] == 1


def test_priors_are_exact_and_correlated() -> None:
    protocol = freeze.expected_protocol()
    a1 = protocol["priors"]["A1"]
    a2 = protocol["priors"]["A2"]
    assert [item["weight"] for item in a1["secret_prior"]] == ["1/16"] * 16
    assert [(item["secret_id"], item["weight"]) for item in a2["secret_prior"]] == [
        ("00", "3/8"),
        ("01", "1/8"),
        ("10", "1/8"),
        ("11", "3/8"),
    ]
    assert all(
        item["weight"] == "1/4"
        for prior in (a1, a2)
        for item in prior["public_tape_prior"]
    )


def test_duplicate_keys_alias_paths_and_bool_integer_aliases_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(freeze.ExperimentAFreezeError, match="duplicate"):
        freeze.parse_strict_json(b'{"a":1,"a":2}\n', label="hostile")
    with pytest.raises(freeze.ExperimentAFreezeError, match="alias|escapes"):
        freeze._relative_path("manifests/../manifests/EXPERIMENT_A_PROTOCOL.json")
    with pytest.raises(freeze.ExperimentAFreezeError, match="alias|canonical"):
        freeze._relative_path("manifests//EXPERIMENT_A_PROTOCOL.json")
    hostile = dict(freeze.expected_schedule()[0])
    hostile["path_index"] = False
    with pytest.raises(runner.ExperimentARunnerError, match="integer"):
        runner.build_trace(hostile)


def test_noncanonical_json_and_secret_dependent_scheduler_mutation_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    protocol = tmp_path / freeze.PROTOCOL_PATH
    value = json.loads(protocol.read_text(encoding="ascii"))
    protocol.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")
    with pytest.raises(freeze.ExperimentAFreezeError):
        freeze.validate_repository(tmp_path)

    second = tmp_path / "second"
    _copy_fixture(second)
    schedule = second / freeze.SCHEDULE_PATH
    records = freeze.parse_strict_jsonl(schedule.read_bytes(), label="schedule")
    records[0]["public_tape_id"] = "tape-1"  # secret-specific scheduler mutation
    schedule.write_bytes(b"".join(freeze.canonical_json_line(record) for record in records))
    with pytest.raises(freeze.ExperimentAFreezeError, match="schedule|binding"):
        freeze.validate_repository(second)


def test_omitted_schedule_coordinate_and_outcome_field_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    schedule = tmp_path / freeze.SCHEDULE_PATH
    records = freeze.parse_strict_jsonl(schedule.read_bytes(), label="schedule")
    del records[0]["secret_id"]
    records[1]["outcome"] = "FORBIDDEN"
    schedule.write_bytes(b"".join(freeze.canonical_json_line(record) for record in records))
    with pytest.raises(freeze.ExperimentAFreezeError):
        freeze.validate_repository(tmp_path)


def test_symlink_and_hardlink_aliases_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    schedule = tmp_path / freeze.SCHEDULE_PATH
    saved = schedule.with_suffix(".saved")
    schedule.rename(saved)
    schedule.symlink_to(saved.name)
    with pytest.raises((OSError, freeze.ExperimentAFreezeError)):
        freeze.validate_repository(tmp_path)

    second = tmp_path / "hardlink"
    _copy_fixture(second)
    conditions = second / freeze.CONDITIONS_PATH
    conditions.unlink()
    os.link(second / freeze.PROTOCOL_PATH, conditions)
    with pytest.raises((OSError, freeze.ExperimentAFreezeError), match="link|member|condition"):
        freeze.validate_repository(second)


def test_mutate_restore_on_held_descriptor_is_detected(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    target = tmp_path / freeze.CONDITIONS_PATH
    original = target.read_bytes()
    original_stat = target.stat()

    def mutate_restore(stage: str, root: Path, _snapshot) -> None:
        if stage == "after_group_open":
            target.write_bytes(original + b" ")
            target.write_bytes(original)
            os.utime(target, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    with pytest.raises(freeze.ExperimentAFreezeError, match="identity changed"):
        freeze.validate_repository(tmp_path, validation_hook=mutate_restore)
    assert target.read_bytes() == original


def test_path_replace_restore_race_is_detected_by_parent_descriptor(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    target = tmp_path / freeze.PROTOCOL_PATH
    replacement = target.with_name("replacement.json")
    saved = target.with_name("saved.json")
    replacement.write_bytes(target.read_bytes())

    def replace_restore(stage: str, root: Path, _snapshot) -> None:
        if stage == "after_semantic_validation":
            target.rename(saved)
            replacement.rename(target)
            target.rename(replacement)
            saved.rename(target)
            replacement.unlink()

    with pytest.raises(freeze.ExperimentAFreezeError, match="parent path mutated"):
        freeze.validate_repository(tmp_path, validation_hook=replace_restore)


def test_binding_members_are_unique_exact_and_do_not_self_hash() -> None:
    binding = json.loads((REPOSITORY_ROOT / freeze.BINDING_PATH).read_text("ascii"))
    paths = [item["path"] for item in binding["members"]]
    assert paths == list(freeze.FREEZE_MEMBERS)
    assert len(paths) == len(set(paths))
    assert freeze.BINDING_PATH not in paths
    assert binding["principal_eligible"] is False
    assert binding["foundation_commit"] == freeze.FOUNDATION_COMMIT
