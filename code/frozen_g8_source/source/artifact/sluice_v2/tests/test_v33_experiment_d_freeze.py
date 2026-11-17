"""Structural and hostile tests for the outcome-free Experiment D freeze."""

from __future__ import annotations

from collections import Counter
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from sluice_v2.evaluation import experiment_d_freeze as freeze


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def _corpus_bytes(root: Path = REPOSITORY_ROOT) -> bytes:
    return (root / freeze.CORPUS_PATH).read_bytes()


def _copy_fixture(target: Path) -> None:
    paths = set(freeze.FREEZE_MEMBERS) | set(freeze.FOUNDATION_BINDINGS) | {
        freeze.BINDING_PATH
    }
    for relative in sorted(paths):
        source = REPOSITORY_ROOT / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def test_exact_freeze_validates_and_principal_gate_stays_closed() -> None:
    report = freeze.validate_repository(REPOSITORY_ROOT)
    assert report == {
        "binding_sha256": report["binding_sha256"],
        "development_units": 150,
        "expanded_cells": 45_000,
        "heldout_units": 450,
        "matrix_rows": 600,
        "principal_eligible": False,
        "schedule_blocks": 3_000,
        "schema": freeze.VALIDATION_SCHEMA,
        "split_sha256": report["split_sha256"],
        "status": "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED",
        "workflows": 4,
    }
    assert len(report["binding_sha256"]) == 64
    assert len(report["split_sha256"]) == 64
    with pytest.raises(
        freeze.ExperimentDFreezeError, match="principal execution blocked"
    ):
        freeze.validate_repository(REPOSITORY_ROOT, require_principal_ready=True)


def test_exact_four_workflows_and_semantic_distinction() -> None:
    manifest = freeze.expected_workflows(_corpus_bytes())
    workflows = manifest["workflows"]
    assert tuple(item["workflow_id"] for item in workflows) == freeze.WORKFLOW_IDS
    assert [item["source_vertical"] for item in workflows] == [
        "healthcare",
        "finance",
        "legal",
        "corporate",
    ]
    assert len({item["semantic_contract"] for item in workflows}) == 4
    assert all(item["implementation_state"] == "DECLARATION_ONLY" for item in workflows)
    assert all(item["principal_eligible"] is False for item in workflows)
    assert [item["population_count"] for item in workflows] == [150, 150, 150, 150]


def test_exact_three_arm_ids_and_no_semantic_relabelling() -> None:
    arms = freeze.expected_arms()["arms"]
    assert tuple(item["arm_id"] for item in arms) == freeze.ARM_IDS
    assert [item["ordinal"] for item in arms] == [1, 2, 3]
    undefended, constrained, revalidated = arms
    assert undefended["unconstrained_generation"] is True
    assert undefended["inline_sluice_enforcement"] is False
    assert constrained["inline_sluice_enforcement"] is True
    assert constrained["unconstrained_generation"] is False
    assert revalidated["unconstrained_generation"] is True
    assert revalidated["trusted_pre_effect_revalidation"] is True
    assert revalidated["internal_exposure_counts_as_security_failure"] is True
    assert all(item["runner_entry_point"] is None for item in arms)
    assert all(item["live_identity_receipt_sha256"] is None for item in arms)
    assert all(item["principal_eligible"] is False for item in arms)


def test_split_is_exact_authenticated_150_450_and_never_uses_codebooks() -> None:
    records = freeze.expected_split_records(_corpus_bytes())
    assert len(records) == 600
    assert Counter(item["split"] for item in records) == {
        "development": 150,
        "heldout": 450,
    }
    assert len({item["scenario_id"] for item in records}) == 600
    assert len({item["record_sha256"] for item in records}) == 600
    assert len({item["unit_binding_sha256"] for item in records}) == 600
    assert all(item["multiagent"] is True for item in records)
    assert all(item["principal_eligible"] is False for item in records)
    encoded = freeze.expected_split_bytes(_corpus_bytes()).decode("ascii")
    assert "agentdojo" not in encoded.lower()
    assert "codebook" not in encoded.lower()
    assert "canary" not in encoded.lower()
    assert "payload" not in encoded.lower()
    assert "evaluation" not in encoded.lower()


def test_split_stratification_exact_counts() -> None:
    records = freeze.expected_split_records(_corpus_bytes())
    by_workflow = Counter((item["workflow_id"], item["split"]) for item in records)
    assert by_workflow == {
        ("D_WF_HEALTHCARE_COORDINATED_CARE_V1", "development"): 37,
        ("D_WF_HEALTHCARE_COORDINATED_CARE_V1", "heldout"): 113,
        ("D_WF_FINANCE_DUAL_CONTROL_V1", "development"): 37,
        ("D_WF_FINANCE_DUAL_CONTROL_V1", "heldout"): 113,
        ("D_WF_LEGAL_PRIVILEGED_CASE_REVIEW_V1", "development"): 38,
        ("D_WF_LEGAL_PRIVILEGED_CASE_REVIEW_V1", "heldout"): 112,
        ("D_WF_CORPORATE_DELEGATED_OPERATIONS_V1", "development"): 38,
        ("D_WF_CORPORATE_DELEGATED_OPERATIONS_V1", "heldout"): 112,
    }
    by_family = Counter((item["attack_family"], item["split"]) for item in records)
    assert by_family == {
        ("A0", "development"): 76,
        ("A0", "heldout"): 224,
        ("F1", "development"): 25,
        ("F1", "heldout"): 72,
        ("F2", "development"): 9,
        ("F2", "heldout"): 25,
        ("F3", "development"): 10,
        ("F3", "heldout"): 36,
        ("F4", "development"): 30,
        ("F4", "heldout"): 93,
    }


def test_policy_author_boundary_is_honestly_unavailable() -> None:
    boundary = freeze.expected_policy_author_boundary(_corpus_bytes())
    assert boundary["human_blind_authoring_status"] == (
        "UNAVAILABLE_NOT_PROSPECTIVELY_ESTABLISHED"
    )
    assert boundary["retroactive_human_blind_claim"] is False
    assert boundary["policy_author_identity"] is None
    assert boundary["policy_author_isolation_receipt_sha256"] is None
    assert boundary["heldout_acl_receipt_sha256"] is None
    assert boundary["heldout_access_log_sha256"] is None
    assert boundary["heldout_acl_enforcement_state"] == "DECLARED_NOT_IMPLEMENTED"
    assert boundary["principal_eligible"] is False
    assert set(freeze.POLICY_BOUNDARY_BLOCKERS) <= set(boundary["blockers"])


def test_protocol_keeps_all_execution_and_scoring_flags_false() -> None:
    protocol = freeze.expected_protocol(_corpus_bytes())
    assert protocol["counts"] == {
        "arms": 3,
        "development_units": 150,
        "expanded_cells": 45_000,
        "heldout_units": 450,
        "matrix_rows": 600,
        "models": 5,
        "schedule_blocks": 3_000,
        "seeds": 5,
        "source_multiagent_units": 600,
        "workflows": 4,
    }
    gates = protocol["execution_gates"]
    assert gates == {
        "gpu_executed": False,
        "live_endpoint_executed": False,
        "model_executed": False,
        "network_executed": False,
        "outcome_scoring_executed": False,
        "principal_executed": False,
    }
    assert len(protocol["models"]) == 5
    assert tuple(item["slug"] for item in protocol["models"]) == freeze.MODEL_SLUGS
    assert all(item["config_only"] is True for item in protocol["models"])
    assert all(item["model_executed"] is False for item in protocol["models"])
    assert all(item["principal_eligible"] is False for item in protocol["models"])


def test_matrix_has_exact_600_rows_and_45000_expansion() -> None:
    rows = freeze.expected_matrix_rows(_corpus_bytes())
    assert len(rows) == 600
    assert len({row["row_id"] for row in rows}) == 600
    assert sum(int(row["expanded_attempts"]) for row in rows) == 45_000
    assert sum(
        int(row["expanded_attempts"])
        for row in rows
        if row["split"] == "development"
    ) == 11_250
    assert sum(
        int(row["expanded_attempts"])
        for row in rows
        if row["split"] == "heldout"
    ) == 33_750
    assert all(row["model_config_only"] == "TRUE" for row in rows)
    assert all(row["model_executed"] == "FALSE" for row in rows)
    assert all(row["principal_eligible"] == "FALSE" for row in rows)
    assert all(row["blocker_codes"] for row in rows)
    decoded = freeze.expected_matrix_bytes(_corpus_bytes()).decode("ascii")
    reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
    assert tuple(reader.fieldnames or ()) == freeze.MATRIX_HEADER
    assert len(list(reader)) == 600


def test_schedule_binds_exact_3000_blocks_and_45000_unique_cells() -> None:
    records = freeze.expected_schedule_records(_corpus_bytes())
    assert len(records) == 3_000
    assert [record["block_index"] for record in records] == list(range(3_000))
    assert len({record["block_id"] for record in records}) == 3_000
    cells = [cell for record in records for cell in record["cells"]]
    assert len(cells) == 45_000
    assert len({cell["cell_id"] for cell in cells}) == 45_000
    assert Counter(record["split"] for record in records) == {
        "development": 750,
        "heldout": 2_250,
    }
    assert all(len(record["cells"]) == 15 for record in records)
    assert all(len(record["model_order"]) == 5 for record in records)
    assert all(cell["principal_eligible"] is False for cell in cells)
    assert all(record["attempt_number"] == 1 for record in records)
    assert all(record["prior_attempt_sha256"] is None for record in records)


def test_schedule_is_canonical_outcome_free_jsonl() -> None:
    schedule = freeze.expected_schedule_bytes(_corpus_bytes())
    parsed = freeze.parse_strict_jsonl(schedule, label=freeze.SCHEDULE_PATH)
    assert schedule == b"".join(freeze.canonical_json_line(item) for item in parsed)
    forbidden = {
        "outcome",
        "result",
        "score",
        "utility",
        "leak",
        "latency",
        "tokens",
        "transcript",
        "events",
    }
    assert not forbidden.intersection(schedule.decode("ascii").lower())


def test_binding_covers_exact_candidate_and_foundation_group() -> None:
    captured = {
        path: (REPOSITORY_ROOT / path).read_bytes() for path in freeze.FREEZE_MEMBERS
    }
    expected = freeze.expected_binding(captured)
    observed = freeze.parse_strict_json(
        (REPOSITORY_ROOT / freeze.BINDING_PATH).read_bytes(),
        label=freeze.BINDING_PATH,
    )
    assert observed == expected
    assert [item["path"] for item in observed["members"]] == list(
        freeze.FREEZE_MEMBERS
    )
    assert [item["path"] for item in observed["foundation_members"]] == list(
        freeze.FOUNDATION_BINDINGS
    )
    bound_modes = {
        item["path"]: item["expected_posix_mode"]
        for item in observed["members"] + observed["foundation_members"]
    }
    bound_modes[observed["binding_member"]["path"]] = observed[
        "binding_member"
    ]["expected_posix_mode"]
    assert bound_modes == {
        path: f"{mode:04o}" for path, mode in freeze.EXPECTED_POSIX_MODES.items()
    }
    assert len(bound_modes) == 25
    assert observed["identity_policy"] == {
        "gid": "MATCH_REPOSITORY_ROOT_GID",
        "posix_mode": "EXACT_PER_PATH",
        "uid": "MATCH_REPOSITORY_ROOT_UID",
    }
    assert observed["principal_eligible"] is False
    assert observed["whole_group_validation"] == {
        "held_descriptors": True,
        "inotify_members_and_lexical_parents": True,
        "lexical_reopen_from_retained_root": True,
        "repository_root_owner_group": True,
        "single_link_regular_files": True,
        "strict_initial_posix_modes": True,
    }


@pytest.mark.parametrize(
    "payload",
    [
        b'{"x":1,"x":2}\n',
        b'{"x":NaN}\n',
        b'{"x":Infinity}\n',
        b'{ "x": 1 }\n',
        '{"x":"\u00e9"}\n'.encode("utf-8"),
        b'{"x":1}',
    ],
)
def test_strict_json_rejects_duplicates_nonfinite_noncanonical_and_nonascii(
    payload: bytes,
) -> None:
    with pytest.raises(freeze.ExperimentDFreezeError):
        freeze.parse_strict_json(payload, label="hostile.json")


def test_exact_builtin_types_reject_bool_int_and_subclasses() -> None:
    class IntSubclass(int):
        pass

    class StrSubclass(str):
        pass

    assert not freeze._exact_json_equal({"x": [False]}, {"x": [0]})
    assert not freeze._exact_json_equal({"x": [1]}, {"x": [1.0]})
    assert not freeze._exact_json_equal({"x": [IntSubclass(1)]}, {"x": [1]})
    with pytest.raises(freeze.ExperimentDFreezeError, match="strict integer"):
        freeze._strict_int(True, label="x", minimum=0)
    with pytest.raises(freeze.ExperimentDFreezeError, match="strict integer"):
        freeze._strict_int(IntSubclass(1), label="x", minimum=0)
    with pytest.raises(freeze.ExperimentDFreezeError, match="strict string"):
        freeze._strict_string(StrSubclass("x"), label="x")
    with pytest.raises(freeze.ExperimentDFreezeError, match="relative path"):
        freeze._relative_parts(StrSubclass("manifests/x"))


@pytest.mark.parametrize(
    "alias",
    (
        "",
        ".",
        "..",
        "../escape",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
    ),
)
def test_relative_path_schema_rejects_bounded_lexical_aliases(alias: str) -> None:
    with pytest.raises(freeze.ExperimentDFreezeError, match="relative path"):
        freeze._relative_parts(alias)


def test_binding_member_path_rejects_dot_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(freeze, "FREEZE_MEMBERS", (".",))
    with pytest.raises(freeze.ExperimentDFreezeError, match="lexical alias"):
        freeze.expected_binding({".": b"hostile-member"})


def test_schedule_validator_rejects_bool_for_integer() -> None:
    records = freeze.expected_schedule_records(_corpus_bytes())
    hostile = [dict(records[0])]
    hostile[0]["block_index"] = True
    with pytest.raises(freeze.ExperimentDFreezeError, match="strict integer"):
        freeze._validate_schedule_records(hostile)


def test_manifest_mutation_and_foundation_drift_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    arms = tmp_path / freeze.ARMS_PATH
    arms.write_bytes(arms.read_bytes().replace(b'"ordinal": 1', b'"ordinal": 9', 1))
    with pytest.raises(freeze.ExperimentDFreezeError):
        freeze.validate_repository(tmp_path)
    _copy_fixture(tmp_path)
    corpus = tmp_path / freeze.CORPUS_PATH
    corpus.write_bytes(corpus.read_bytes() + b"\n")
    with pytest.raises(freeze.ExperimentDFreezeError, match="foundation dependency"):
        freeze.validate_repository(tmp_path)


@pytest.mark.parametrize(
    "variant",
    ["false_to_zero", "one_to_true", "one_to_float"],
)
def test_rebound_binding_rejects_numeric_type_aliases_at_any_depth(
    tmp_path: Path, variant: str
) -> None:
    _copy_fixture(tmp_path)
    if variant == "false_to_zero":
        target = tmp_path / freeze.PROTOCOL_PATH
        document = freeze.parse_strict_json(
            target.read_bytes(), label=freeze.PROTOCOL_PATH
        )
        document["execution_gates"]["gpu_executed"] = 0
    else:
        target = tmp_path / freeze.ARMS_PATH
        document = freeze.parse_strict_json(target.read_bytes(), label=freeze.ARMS_PATH)
        document["arms"][0]["ordinal"] = True if variant == "one_to_true" else 1.0
    target.write_bytes(freeze.canonical_json(document))
    freeze.materialize_binding(tmp_path, replace=True)
    with pytest.raises(
        freeze.ExperimentDFreezeError, match="exact structural declaration"
    ):
        freeze.validate_repository(tmp_path)


@pytest.mark.parametrize(
    ("relative", "original_mode", "hostile_mode"),
    [
        (freeze.ARMS_PATH, 0o644, 0o600),
        (
            "source/artifact/experiments/validate_experiment_d_freeze.py",
            0o755,
            0o644,
        ),
    ],
)
def test_initial_posix_mode_drift_fails_before_semantic_validation(
    tmp_path: Path, relative: str, original_mode: int, hostile_mode: int
) -> None:
    _copy_fixture(tmp_path)
    target = tmp_path / relative
    assert target.stat().st_mode & 0o7777 == original_mode
    os.chmod(target, hostile_mode)
    with pytest.raises(freeze.ExperimentDFreezeError, match="POSIX mode differs"):
        freeze.validate_repository(tmp_path)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc descriptors required")
def test_partial_group_open_failure_closes_every_descriptor(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    late_member = tmp_path / "source/artifact/requirements-lock.txt"
    os.chmod(late_member, 0o600)
    baseline = len(os.listdir("/proc/self/fd"))
    for _attempt in range(5):
        with pytest.raises(freeze.ExperimentDFreezeError, match="POSIX mode differs"):
            freeze.validate_repository(tmp_path)
        assert len(os.listdir("/proc/self/fd")) == baseline


def test_symlink_and_hardlink_aliases_fail_closed(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    arms = tmp_path / freeze.ARMS_PATH
    original = arms.read_bytes()
    arms.unlink()
    arms.symlink_to(tmp_path / freeze.PROTOCOL_PATH)
    with pytest.raises((freeze.ExperimentDFreezeError, OSError)):
        freeze.validate_repository(tmp_path)
    arms.unlink()
    arms.write_bytes(original)
    matrix = tmp_path / freeze.MATRIX_PATH
    matrix.unlink()
    os.link(arms, matrix)
    with pytest.raises(
        freeze.ExperimentDFreezeError, match="hard-link|alias|single-link"
    ):
        freeze.validate_repository(tmp_path)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_inotify_and_held_fd_catch_same_byte_lexical_replacement(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    fired = False

    def replace_after_open(stage: str, root: Path, _group: object) -> None:
        nonlocal fired
        if stage != "after_group_open" or fired:
            return
        fired = True
        path = root / freeze.SCHEDULE_PATH
        replacement = path.with_name("replacement.jsonl")
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)

    with pytest.raises(
        freeze.ExperimentDFreezeError,
        match="inotify mutation|lexical path rebound|identity changed",
    ):
        freeze.validate_repository(tmp_path, validation_hook=replace_after_open)
    assert fired


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_inotify_catches_parent_directory_mutation(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    fired = False

    def mutate_parent(stage: str, root: Path, _group: object) -> None:
        nonlocal fired
        if stage != "after_group_open" or fired:
            return
        fired = True
        (root / "manifests" / "unrelated-race").write_text("race", encoding="ascii")

    with pytest.raises(
        freeze.ExperimentDFreezeError,
        match="inotify mutation|parent path mutated",
    ):
        freeze.validate_repository(tmp_path, validation_hook=mutate_parent)
    assert fired


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_inotify_catches_same_host_mutate_then_exact_byte_restore(
    tmp_path: Path,
) -> None:
    _copy_fixture(tmp_path)
    fired = False

    def mutate_then_restore(stage: str, root: Path, _group: object) -> None:
        nonlocal fired
        if stage != "after_group_open" or fired:
            return
        fired = True
        path = root / freeze.ARMS_PATH
        with path.open("r+b", buffering=0) as stream:
            original = stream.read(1)
            replacement = b"X" if original != b"X" else b"Y"
            stream.seek(0)
            stream.write(replacement)
            os.fsync(stream.fileno())
            stream.seek(0)
            stream.write(original)
            os.fsync(stream.fileno())
        assert path.read_bytes() == _copy_bytes[freeze.ARMS_PATH]

    _copy_bytes = {freeze.ARMS_PATH: (tmp_path / freeze.ARMS_PATH).read_bytes()}
    with pytest.raises(
        freeze.ExperimentDFreezeError, match="whole-group inotify mutation"
    ):
        freeze.validate_repository(tmp_path, validation_hook=mutate_then_restore)
    assert fired


@pytest.mark.parametrize(
    ("mask_name", "message"),
    [
        ("_IN_Q_OVERFLOW", "queue overflow"),
        ("_IN_IGNORED", "inotify mutation"),
    ],
)
def test_inotify_overflow_and_ignored_events_fail_closed(
    mask_name: str, message: str
) -> None:
    watch = object.__new__(freeze._LinuxInotifyGroupWatch)
    watch.paths_by_watch = {}
    mask = getattr(watch, mask_name)
    watch._drain = lambda: [(7, mask, "")]
    with pytest.raises(freeze.ExperimentDFreezeError, match=message):
        watch.assert_quiet("hostile_test")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc descriptors required")
def test_success_and_early_group_failure_close_every_descriptor(
    tmp_path: Path,
) -> None:
    _copy_fixture(tmp_path)
    baseline = len(os.listdir("/proc/self/fd"))
    freeze.validate_repository(tmp_path)
    assert len(os.listdir("/proc/self/fd")) == baseline
    early_member = tmp_path / freeze.FREEZE_MEMBERS[0]
    os.chmod(early_member, 0o600)
    with pytest.raises(freeze.ExperimentDFreezeError, match="POSIX mode differs"):
        freeze.validate_repository(tmp_path)
    assert len(os.listdir("/proc/self/fd")) == baseline


def test_master_protocol_remains_blocked_and_d_is_additive() -> None:
    source = freeze.parse_strict_json(
        (REPOSITORY_ROOT / "manifests/EXPERIMENT_PROTOCOL.json").read_bytes(),
        label="manifests/EXPERIMENT_PROTOCOL.json",
    )
    family = source["experiment_families"]["D_heldout_cross_model_workflow"]
    assert family["status"] == "BLOCKED_NOT_MATRIX_FROZEN"
    assert family["row_count"] == "BLOCKED_NOT_DECLARED"
    assert family["required_generation_arms"] == [
        "constrained_decoding_where_appropriate",
        "unconstrained_generation_then_independent_monitor_revalidation",
    ]
    assert not any("EXPERIMENT_E" in path for path in freeze.FOUNDATION_BINDINGS)


def test_candidate_group_has_no_pycache_members_or_execution_outputs() -> None:
    assert all("__pycache__" not in path for path in freeze.FREEZE_MEMBERS)
    forbidden_suffixes = (".pyc", ".pt", ".safetensors", ".bin")
    assert not any(path.endswith(forbidden_suffixes) for path in freeze.FREEZE_MEMBERS)
    assert not any(path.startswith("runs/") for path in freeze.FREEZE_MEMBERS)


def test_materializer_requires_exact_path_and_bool_types(tmp_path: Path) -> None:
    class PathSubclass(type(Path())):
        pass

    with pytest.raises(TypeError):
        freeze.materialize_generated_files(PathSubclass(tmp_path), replace=False)
    with pytest.raises(TypeError):
        freeze.materialize_generated_files(tmp_path, replace=1)


def test_cli_validator_is_self_consistent(capsys: pytest.CaptureFixture[str]) -> None:
    assert freeze.main(["validate", "--repository-root", str(REPOSITORY_ROOT)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED"
    assert output["expanded_cells"] == 45_000
