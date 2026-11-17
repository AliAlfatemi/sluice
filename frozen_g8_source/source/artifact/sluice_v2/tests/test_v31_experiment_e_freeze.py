"""Structural and hostile tests for the outcome-free Experiment E freeze."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil

import pytest

from sluice_v2.evaluation import experiment_e_freeze as freeze


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def _copy_fixture(target: Path) -> None:
    paths = (
        set(freeze.FREEZE_MEMBERS)
        | set(freeze.FOUNDATION_BINDINGS)
        | {freeze.BINDING_PATH}
    )
    for relative in sorted(paths):
        source = REPOSITORY_ROOT / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _conditions_by_id() -> dict[str, dict]:
    return {
        item["condition_id"]: item
        for item in freeze.expected_conditions()["conditions"]
    }


def test_exact_freeze_validates_but_principal_gate_stays_closed(capsys) -> None:
    report = freeze.validate_repository(REPOSITORY_ROOT)
    assert report == {
        "binding_sha256": report["binding_sha256"],
        "cells": 2310,
        "conditions": 11,
        "paired_blocks": 210,
        "principal_eligible": False,
        "runtime_identities": 3,
        "schedule_sha256": freeze.SCHEDULE_KNOWN_SHA256,
        "schema": freeze.VALIDATION_SCHEMA,
        "status": "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED",
    }
    assert len(report["binding_sha256"]) == 64
    with pytest.raises(freeze.ExperimentEFreezeError, match="principal execution blocked"):
        freeze.validate_repository(REPOSITORY_ROOT, require_principal_ready=True)
    assert (
        freeze.main(
            [
                "validate",
                "--repository-root",
                str(REPOSITORY_ROOT),
                "--require-principal-ready",
            ]
        )
        == 1
    )
    assert "principal execution blocked" in capsys.readouterr().err


def test_exact_eleven_condition_order_and_required_bindings() -> None:
    manifest = freeze.expected_conditions()
    conditions = manifest["conditions"]
    assert tuple(item["condition_id"] for item in conditions) == freeze.REQUIRED_CONDITION_IDS
    assert [item["ordinal"] for item in conditions] == list(range(1, 12))
    required = {
        "axis",
        "comparator_condition_id",
        "handler_binding",
        "audit_semantics",
        "checkpoint_semantics",
        "rpc_semantics",
        "isolation_semantics",
        "journal_mode",
        "synchronous_mode",
        "storage_identity_id",
        "principal_eligible",
        "blockers",
    }
    for item in conditions:
        assert required <= set(item)
        assert item["principal_eligible"] is False
        assert item["blockers"]
        binding = item["handler_binding"]
        assert set(binding) == {
            "entry_point",
            "implementation_state",
            "matched_operation_contract",
            "source_path",
            "source_sha256",
        }
        if binding["implementation_state"] == "ABSENT":
            assert binding["entry_point"] is None
            assert binding["source_path"] is None
            assert binding["source_sha256"] is None
        else:
            assert binding["entry_point"]
            assert binding["source_path"] == (
                "source/artifact/experiments/g8_matched_scalability.py"
            )
            assert binding["source_sha256"] == freeze.FOUNDATION_BINDINGS[
                binding["source_path"]
            ]


def test_existing_g8_four_arms_are_literal_and_mismatches_are_not_relabelled() -> None:
    conditions = _conditions_by_id()
    referenced = {
        item["existing_g8_coverage"]["condition_id"]
        for item in conditions.values()
        if item["existing_g8_coverage"]["condition_id"] is not None
    }
    assert referenced == set(freeze.EXISTING_G8_CONDITION_IDS)
    direct = conditions["direct_function_call_without_monitor"]
    assert direct["existing_g8_coverage"] == {
        "condition_id": "unmediated_handler",
        "coverage": "EXACT_MATCH_DIAGNOSTIC_ONLY",
        "semantic_mismatch": None,
        "support_entry_point": None,
    }
    partial_ids = {
        item["condition_id"]
        for item in conditions.values()
        if item["existing_g8_coverage"]["coverage"]
        == "PARTIAL_SEMANTIC_MISMATCH"
    }
    assert partial_ids == {
        "in_memory_policy_check",
        "sluice_sqlite_ledger_without_signed_checkpoint",
        "full_sluice_with_isolated_rpc",
        "wal_mode",
    }
    assert conditions["full_sluice"]["handler_binding"]["implementation_state"] == "ABSENT"
    assert conditions["delete_full_mode"]["existing_g8_coverage"]["coverage"] == "ABSENT"
    assert conditions["temporary_memory_filesystem_diagnostic_only"][
        "existing_g8_coverage"
    ]["condition_id"] is None


def test_schedule_has_exact_2310_cells_and_210_complete_paired_blocks() -> None:
    rows = freeze.expected_schedule_rows()
    assert len(rows) == 11 * 7 * 10 * 3 == 2310
    assert [int(row["cell_index"]) for row in rows] == list(range(2310))
    assert len({row["cell_id"] for row in rows}) == 2310
    blocks: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        blocks.setdefault(row["block_id"], []).append(row)
    assert len(blocks) == 7 * 10 * 3 == 210
    for block_rows in blocks.values():
        assert len(block_rows) == 11
        assert {row["condition_id"] for row in block_rows} == set(
            freeze.REQUIRED_CONDITION_IDS
        )
        assert sorted(int(row["condition_order"]) for row in block_rows) == list(
            range(1, 12)
        )
        assert len({row["runtime_id"] for row in block_rows}) == 1
        assert len({row["repetition"] for row in block_rows}) == 1
        assert len({row["concurrency"] for row in block_rows}) == 1
    coordinates = {
        (row["runtime_id"], int(row["repetition"]), int(row["concurrency"]))
        for row in rows
    }
    assert coordinates == {
        (runtime, repetition, concurrency)
        for runtime in freeze.RUNTIME_IDS
        for repetition in range(1, 11)
        for concurrency in freeze.CONCURRENCIES
    }


def test_known_answer_schedule_reconstruction_and_outcome_free_schema() -> None:
    schedule = freeze.expected_schedule_bytes()
    retained = (REPOSITORY_ROOT / freeze.SCHEDULE_PATH).read_bytes()
    assert retained == schedule
    assert hashlib.sha256(schedule).hexdigest() == freeze.SCHEDULE_KNOWN_SHA256
    reader = csv.DictReader(io.StringIO(schedule.decode("ascii"), newline=""), strict=True)
    rows = list(reader)
    assert tuple(reader.fieldnames or ()) == freeze.SCHEDULE_HEADER
    forbidden = {
        "outcome",
        "result",
        "latency_ns",
        "throughput",
        "status",
        "error_type",
        "error_message",
        "operations_retained",
    }
    assert not forbidden.intersection(reader.fieldnames or ())
    assert all(row["attempt_number"] == "1" for row in rows)
    assert all(row["prior_attempt_sha256"] == "" for row in rows)
    assert all(row["principal_eligible"] == "FALSE" for row in rows)
    assert all(row["blocker_codes"] for row in rows)
    # These values are independent known-answer anchors in addition to the digest.
    assert [(row["runtime_id"], row["repetition"]) for row in rows[:11]] == [
        (freeze.RUNTIME_IDS[0], "1")
    ] * 11
    assert [int(row["condition_order"]) for row in rows[:11]] == list(range(1, 12))


def test_runtime_and_storage_schemas_are_exact_absent_and_never_alias_shared_as_local() -> None:
    runtime = freeze.expected_runtime_identities()
    storage = freeze.expected_storage_identities()
    assert len(runtime["identities"]) == 3
    assert tuple(item["runtime_id"] for item in runtime["identities"]) == freeze.RUNTIME_IDS
    for item in runtime["identities"]:
        assert item["identity_state"] == "ABSENT_NOT_CAPTURED"
        assert item["principal_eligible"] is False
        assert item["blockers"]
        assert item["python_executable_sha256"] is None
        assert item["runtime_lock_sha256"] is None
    identities = {
        item["storage_identity_id"]: item for item in storage["identities"]
    }
    shared = identities["storage-shared-network-prospective"]
    local = identities["storage-local-persistent-prospective"]
    tmpfs = identities["storage-tmpfs-diagnostic-prospective"]
    assert shared["declared_class"] == "shared-or-network"
    assert shared["must_be_node_local"] is False
    assert shared["required_locality"] == "SHARED_OR_NETWORK_NEVER_LOCAL"
    assert local["must_be_node_local"] is True
    assert tmpfs["diagnostic_only"] is True
    assert tmpfs["principal_eligible"] is False
    assert all(
        item["identity_state"] == "ABSENT_NOT_CAPTURED"
        and item["resolved_path"] is None
        and item["mount_source"] is None
        for item in identities.values()
    )


def test_raw_units_total_failure_retry_analyzer_bootstrap_and_holm_are_frozen() -> None:
    protocol = freeze.expected_protocol()
    raw = protocol["raw_contract"]
    failure = protocol["failure_and_retry_policy"]
    analyzer = protocol["analyzer_contract"]
    analysis = protocol["analysis"]
    assert raw["attempt_schema"] == freeze.RAW_ATTEMPT_SCHEMA
    assert raw["operation_schema"] == freeze.RAW_OPERATION_SCHEMA
    assert raw["raw_units"] == {
        "cpu": "integer_nanoseconds",
        "latency": "integer_nanoseconds",
        "memory": "integer_bytes",
        "operation_and_failure_counts": "exact_nonnegative_integers",
        "storage": "integer_bytes",
        "throughput": "operations_per_second_derived_from_integer_counts_and_nanoseconds",
    }
    assert raw["total_failure_retention"] is True
    assert len(raw["required_latency_decomposition"]) == 8
    assert failure["all_failures_remain_in_denominators"] is True
    assert "append" in failure["retry_rule"]
    assert "prior_attempt_sha256" in failure["retry_rule"]
    assert analyzer["state"] == "ABSENT_NOT_IMPLEMENTED"
    assert analyzer["implementation_path"] is None
    assert analyzer["implementation_sha256"] is None
    assert analyzer["must_not_trust_runner_summaries"] is True
    assert "authenticate" in analyzer["authentication"]
    assert analysis["bootstrap_replicates"] == 10_000
    assert analysis["bootstrap_seed"] == 8675309
    assert analysis["holm_families"]["method"] == "Holm step-down"
    assert analysis["holm_families"]["tmpfs_policy"] == "excluded_diagnostic_only"


def test_complete_blocker_union_is_exact_and_every_cell_is_blocked() -> None:
    required_cross_family = (
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
    assert freeze.CROSS_FAMILY_BLOCKERS == required_cross_family
    assert len(set(required_cross_family)) == 17
    assert set(required_cross_family).isdisjoint(freeze.PRINCIPAL_BLOCKERS)
    expected = list(freeze._all_entity_blockers())
    protocol = freeze.expected_protocol()
    binding = json.loads((REPOSITORY_ROOT / freeze.BINDING_PATH).read_text("ascii"))
    assert protocol["principal_blocker_union"] == expected
    assert binding["principal_blocker_union"] == expected
    assert expected == sorted(set(expected))
    assert set(freeze.PRINCIPAL_BLOCKERS) | set(required_cross_family) <= set(expected)
    for row in freeze.expected_schedule_rows():
        row_blockers = set(row["blocker_codes"].split(";"))
        assert set(freeze.PRINCIPAL_BLOCKERS) | set(required_cross_family) <= row_blockers


def test_duplicate_keys_noncanonical_json_bool_alias_and_path_aliases_fail_closed(
    tmp_path: Path,
) -> None:
    with pytest.raises(freeze.ExperimentEFreezeError, match="duplicate"):
        freeze.parse_strict_json(b'{"x":1,"x":2}\n', label="hostile")
    with pytest.raises(freeze.ExperimentEFreezeError, match="alias|canonical"):
        freeze._relative_path("manifests//EXPERIMENT_E_PROTOCOL.json")
    with pytest.raises(freeze.ExperimentEFreezeError, match="alias|escapes"):
        freeze._relative_path("manifests/../manifests/EXPERIMENT_E_PROTOCOL.json")

    _copy_fixture(tmp_path)
    protocol_path = tmp_path / freeze.PROTOCOL_PATH
    value = json.loads(protocol_path.read_text("ascii"))
    protocol_path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")
    with pytest.raises(freeze.ExperimentEFreezeError, match="canonical"):
        freeze.validate_repository(tmp_path)

    second = tmp_path / "bool-alias"
    _copy_fixture(second)
    runtime_path = second / freeze.RUNTIME_IDENTITIES_PATH
    runtime = json.loads(runtime_path.read_text("ascii"))
    runtime["identities"][0]["ordinal"] = False
    runtime_path.write_bytes(freeze.canonical_json(runtime))
    with pytest.raises(freeze.ExperimentEFreezeError, match="exact declaration"):
        freeze.validate_repository(second)


def test_duplicate_schedule_cell_omission_and_reordering_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    schedule_path = tmp_path / freeze.SCHEDULE_PATH
    reader = csv.DictReader(
        io.StringIO(schedule_path.read_text("ascii"), newline=""), strict=True
    )
    rows = list(reader)
    rows[1]["cell_id"] = rows[0]["cell_id"]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=freeze.SCHEDULE_HEADER, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    schedule_path.write_text(output.getvalue(), encoding="ascii")
    with pytest.raises(freeze.ExperimentEFreezeError, match="schedule"):
        freeze.validate_repository(tmp_path)

    second = tmp_path / "omitted"
    _copy_fixture(second)
    data = (second / freeze.SCHEDULE_PATH).read_text("ascii").splitlines()
    (second / freeze.SCHEDULE_PATH).write_text("\n".join(data[:-1]) + "\n", encoding="ascii")
    with pytest.raises(freeze.ExperimentEFreezeError, match="schedule"):
        freeze.validate_repository(second)

    third = tmp_path / "reordered"
    _copy_fixture(third)
    data = (third / freeze.SCHEDULE_PATH).read_text("ascii").splitlines()
    data[1], data[2] = data[2], data[1]
    (third / freeze.SCHEDULE_PATH).write_text("\n".join(data) + "\n", encoding="ascii")
    with pytest.raises(freeze.ExperimentEFreezeError, match="schedule"):
        freeze.validate_repository(third)


def test_symlink_and_hardlink_aliases_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    schedule = tmp_path / freeze.SCHEDULE_PATH
    saved = schedule.with_name("saved-schedule.csv")
    schedule.rename(saved)
    schedule.symlink_to(saved.name)
    with pytest.raises((OSError, freeze.ExperimentEFreezeError)):
        freeze.validate_repository(tmp_path)

    second = tmp_path / "hardlink"
    _copy_fixture(second)
    conditions = second / freeze.CONDITIONS_PATH
    conditions.unlink()
    os.link(second / freeze.PROTOCOL_PATH, conditions)
    with pytest.raises((OSError, freeze.ExperimentEFreezeError), match="hard-link|alias"):
        freeze.validate_repository(second)


def test_repeated_hardlink_early_rejection_has_zero_file_descriptor_growth(
    tmp_path: Path,
) -> None:
    _copy_fixture(tmp_path)
    conditions = tmp_path / freeze.CONDITIONS_PATH
    conditions.unlink()
    os.link(tmp_path / freeze.PROTOCOL_PATH, conditions)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(5):
        with pytest.raises(
            (OSError, freeze.ExperimentEFreezeError), match="hard-link|alias"
        ):
            freeze.validate_repository(tmp_path)
        assert len(os.listdir("/proc/self/fd")) == before


def test_general_partial_open_failure_closes_all_owned_descriptors(
    tmp_path: Path, monkeypatch
) -> None:
    _copy_fixture(tmp_path)
    paths = (freeze.FREEZE_MEMBERS[0], freeze.FREEZE_MEMBERS[1])
    calls = 0

    def fail_during_first_leaf_read(_descriptor: int) -> bytes:
        nonlocal calls
        calls += 1
        raise OSError("synthetic early leaf read rejection")

    monkeypatch.setattr(freeze, "_read_fd", fail_during_first_leaf_read)
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(OSError, match="synthetic early leaf read rejection"):
        freeze._open_group(tmp_path, paths)
    assert calls == 1
    assert len(os.listdir("/proc/self/fd")) == before


def test_mutate_restore_on_held_descriptor_is_detected(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    target = tmp_path / freeze.CONDITIONS_PATH
    original = target.read_bytes()
    observed = target.stat()

    def mutate_restore(stage: str, _root: Path, _group) -> None:
        if stage == "after_group_open":
            target.write_bytes(original + b" ")
            target.write_bytes(original)
            os.utime(target, ns=(observed.st_atime_ns, observed.st_mtime_ns))

    with pytest.raises(
        freeze.ExperimentEFreezeError, match="inotify mutation|identity changed"
    ):
        freeze.validate_repository(tmp_path, validation_hook=mutate_restore)
    assert target.read_bytes() == original


def test_path_replace_restore_race_is_detected_by_held_parent(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    target = tmp_path / freeze.PROTOCOL_PATH
    saved = target.with_name("saved-protocol.json")
    replacement = target.with_name("replacement-protocol.json")
    replacement.write_bytes(target.read_bytes())

    def replace_restore(stage: str, _root: Path, _group) -> None:
        if stage == "after_semantic_validation":
            target.rename(saved)
            replacement.rename(target)
            target.rename(replacement)
            saved.rename(target)
            replacement.unlink()

    with pytest.raises(
        freeze.ExperimentEFreezeError,
        match="inotify mutation|parent path mutated",
    ):
        freeze.validate_repository(tmp_path, validation_hook=replace_restore)


def test_whole_group_watch_catches_mutate_restore_after_member_was_rechecked(
    tmp_path: Path,
) -> None:
    _copy_fixture(tmp_path)
    first = tmp_path / freeze.FREEZE_MEMBERS[0]
    original = first.read_bytes()
    observed = first.stat()
    injected = False

    def late_mutate_restore(stage: str, _root: Path, _group) -> None:
        nonlocal injected
        if (
            not injected
            and stage.startswith("before_final_member_recheck:")
            and not stage.endswith(freeze.FREEZE_MEMBERS[0])
        ):
            injected = True
            first.write_bytes(original + b" ")
            first.write_bytes(original)
            os.utime(first, ns=(observed.st_atime_ns, observed.st_mtime_ns))

    with pytest.raises(freeze.ExperimentEFreezeError, match="inotify mutation"):
        freeze.validate_repository(tmp_path, validation_hook=late_mutate_restore)
    assert injected is True
    assert first.read_bytes() == original


@pytest.mark.parametrize(
    "mask,pattern",
    (
        (freeze._LinuxInotifyGroupWatch._IN_Q_OVERFLOW, "overflow"),
        (freeze._LinuxInotifyGroupWatch._IN_IGNORED, "mutation"),
        (freeze._LinuxInotifyGroupWatch._IN_UNMOUNT, "mutation"),
    ),
)
def test_inotify_overflow_ignored_and_unmount_fail_closed(
    tmp_path: Path, monkeypatch, mask: int, pattern: str
) -> None:
    member = tmp_path / "member"
    member.write_text("frozen\n", encoding="ascii")
    watcher = freeze._LinuxInotifyGroupWatch(tmp_path, ("member",))
    try:
        monkeypatch.setattr(watcher, "_drain", lambda: [(-1, mask, "")])
        with pytest.raises(freeze.ExperimentEFreezeError, match=pattern):
            watcher.assert_quiet("hostile synthetic event")
    finally:
        watcher.close()


def test_foundation_hash_drift_and_member_hash_drift_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    foundation = tmp_path / "analysis/G8_PERFORMANCE_PROTOCOL.md"
    foundation.write_bytes(foundation.read_bytes() + b"\n")
    with pytest.raises(freeze.ExperimentEFreezeError, match="foundation dependency hash drift"):
        freeze.validate_repository(tmp_path)

    second = tmp_path / "member"
    _copy_fixture(second)
    document = second / "analysis/EXPERIMENT_E_PERFORMANCE_FREEZE.md"
    document.write_bytes(document.read_bytes() + b"\n")
    with pytest.raises(freeze.ExperimentEFreezeError, match="binding"):
        freeze.validate_repository(second)


def test_generated_files_can_be_reconstructed_without_benchmark_execution(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    for relative in (
        freeze.PROTOCOL_PATH,
        freeze.CONDITIONS_PATH,
        freeze.RUNTIME_IDENTITIES_PATH,
        freeze.STORAGE_IDENTITIES_PATH,
        freeze.SCHEDULE_PATH,
        freeze.BINDING_PATH,
    ):
        (tmp_path / relative).unlink()
    report = freeze.materialize_generated_files(tmp_path, replace=False)
    assert report["status"] == "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED"
    assert report["cells"] == 2310


def test_validator_has_no_benchmark_model_gpu_or_network_execution_surface() -> None:
    source = Path(freeze.__file__).read_text(encoding="utf-8")
    forbidden = (
        "import g8_matched_scalability",
        "import torch",
        "import transformers",
        "subprocess.",
        "socket.",
        "cuda",
        "run_benchmark(",
    )
    assert not any(token in source for token in forbidden)


def test_hostile_contract_has_no_skip_or_xfail_escape_hatch() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden = (
        "pytest." + "skip",
        "pytest.mark." + "skip",
        "pytest." + "xfail",
        "pytest.mark." + "xfail",
    )
    assert not any(token in source for token in forbidden)
