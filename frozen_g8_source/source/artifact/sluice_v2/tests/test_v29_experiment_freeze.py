from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from sluice_v2.evaluation import experiment_freeze as freeze

from sluice_v2.evaluation.experiment_freeze import (
    AGENTDOJO_COMPARISONS,
    AGENTLEAK_COMPARISONS,
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_SEED,
    BINDING_ARTIFACTS,
    CSV_HEADER,
    FreezeError,
    MODEL_LICENSE_BINDINGS,
    MODELS,
    SEEDS,
    emit_binding_manifest,
    emit_freeze,
    expected_binding_bytes,
    expected_matrix_bytes,
    expected_protocol,
    expected_rows,
    validate_repository,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def _copy_validation_fixture(target: Path) -> None:
    for relative in freeze._validation_member_limits():
        source = REPOSITORY_ROOT / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def test_repository_freeze_is_exact_and_structurally_valid() -> None:
    report = validate_repository(REPOSITORY_ROOT)
    assert report["status"] == "STRUCTURAL_FREEZE_VALID_PRINCIPAL_BLOCKED"
    assert report["matrix_rows"] == 1_085
    assert report["principal_eligible"] is False
    assert len(report["binding_sha256"]) == 64
    assert report["schema_version"] == "sluice-experiment-freeze-validation-v3"
    assert report["held_group_members"] == len(freeze._validation_member_limits())


def test_principal_gate_fails_closed_while_any_blocker_remains() -> None:
    with pytest.raises(FreezeError, match="principal execution blocked"):
        validate_repository(REPOSITORY_ROOT, require_principal_ready=True)


def test_matrix_coordinates_and_exact_population_counts_are_frozen() -> None:
    rows = expected_rows()
    assert len(CSV_HEADER) == len(set(CSV_HEADER))
    serialized_header = next(
        csv.reader(io.StringIO(expected_matrix_bytes().decode("ascii")))
    )
    assert tuple(serialized_header) == CSV_HEADER
    assert len(serialized_header) == len(set(serialized_header))
    assert len(rows) == 1_085
    assert len({row["row_id"] for row in rows}) == 1_085
    assert tuple(sorted({int(row["seed"]) for row in rows})) == SEEDS
    assert {model["tier"] for model in MODELS} == {
        "primary",
        "robustness",
        "blocked_medium_feasibility",
        "blocked_large_feasibility",
    }
    assert sum(row["benchmark"] == "agentleak" for row in rows) == 245
    assert sum(row["benchmark"] == "agentdojo" for row in rows) == 840
    assert {
        (row["attacked_units"], row["benign_units"], row["guardrail_units"])
        for row in rows
        if row["benchmark"] == "agentleak"
    } == {(496, 504, 78)}
    assert {
        row["policy_abstain_utility_failures"]
        for row in rows
        if row["benchmark"] == "agentleak"
    } == {196}
    dojo = [row for row in rows if row["benchmark"] == "agentdojo"]
    assert sum(
        row["attacked_units"]
        for row in dojo
        if row["model_id"] == MODELS[0]["model_id"]
        and row["seed"] == SEEDS[0]
        and row["comparison_id"] == "sluice_nonoracle_vs_undefended"
    ) == 949
    assert sum(
        row["benign_units"]
        for row in dojo
        if row["model_id"] == MODELS[0]["model_id"]
        and row["seed"] == SEEDS[0]
        and row["comparison_id"] == "sluice_nonoracle_vs_undefended"
    ) == 97
    assert sum(
        row["heldout_attacked_principal_units"]
        for row in dojo
        if row["model_id"] == MODELS[0]["model_id"]
        and row["seed"] == SEEDS[0]
        and row["comparison_id"] == "sluice_nonoracle_vs_undefended"
    ) == 713
    assert sum(
        row["heldout_benign_principal_units"]
        for row in dojo
        if row["model_id"] == MODELS[0]["model_id"]
        and row["seed"] == SEEDS[0]
        and row["comparison_id"] == "sluice_nonoracle_vs_undefended"
    ) == 73


def test_primary_endpoints_match_prospective_amendments() -> None:
    protocol = expected_protocol()
    analysis = protocol["analysis"]
    assert analysis["agentleak_h2_conjunction"] == [
        "L_policy_exact_any on all 1000 rows",
        "P_injected_protected_propagation on the fixed 78-row stratum",
    ]
    assert analysis["agentleak_h3"].startswith("U_sluice_owned_blinded")
    assert analysis["agentleak_raw_hybrid_role"] == "secondary_only"
    assert protocol["benchmarks"]["agentleak"]["codebook"]["abstain_rows"] == 196
    assert (
        protocol["benchmarks"]["agentleak"]["codebook"]
        ["abstain_primary_utility_classification"]
        == "FAILURE"
    )


def test_h4_and_h5_have_disjoint_populations_and_valid_bootstraps() -> None:
    dojo = [row for row in expected_rows() if row["benchmark"] == "agentdojo"]
    assert {
        (
            row["security_primary_unit"],
            row["security_bootstrap_method"],
            row["utility_primary_unit"],
            row["utility_bootstrap_method"],
        )
        for row in dojo
    } == {
        (
            "heldout_attacked_user_task_X_injection_task_pair",
            "paired_crossed_user_injection_pigeonhole_within_suite_10000",
            "heldout_benign_user_task_with_null_injection_id",
            "paired_user_task_cluster_within_suite_10000",
        )
    }
    protocol = expected_protocol()
    populations = protocol["analysis"]["endpoint_population_rule"]
    assert populations["agentdojo_h4_security"].endswith("713 total")
    assert "73 total" in populations["agentdojo_h5_utility"]
    assert "injection_id is null" in populations["agentdojo_h5_utility"]
    assert "pigeonhole" in protocol["analysis"]["bootstrap"][
        "agentdojo_h4_attacked_clusters"
    ]
    h5_bootstrap = protocol["analysis"]["bootstrap"][
        "agentdojo_h5_benign_clusters"
    ]
    assert "user-task cluster" in h5_bootstrap
    assert "injection_id is null" in h5_bootstrap


def test_bc_scope_and_blocked_a_d_e_families_are_explicit() -> None:
    protocol = expected_protocol()
    assert protocol["matrix"]["scope"] == "experiments_B_C_effectiveness_only"
    assert protocol["matrix"]["not_authoritative_for"] == [
        "A_controlled_complete_transcript_qif",
        "D_heldout_cross_model_workflow",
        "E_performance_scalability",
    ]
    families = protocol["experiment_families"]
    assert families["B_C_benchmark_effectiveness"]["status"].startswith(
        "STRUCTURAL_MATRIX_FROZEN"
    )
    for family in (
        "A_controlled_complete_transcript_qif",
        "D_heldout_cross_model_workflow",
        "E_performance_scalability",
    ):
        assert families[family]["status"] == "BLOCKED_NOT_MATRIX_FROZEN"
        assert families[family]["row_count"] == "BLOCKED_NOT_DECLARED"
        assert all(code.startswith("BLOCKED_") for code in families[family]["blockers"])
        assert set(families[family]["blockers"]).issubset(
            protocol["principal_eligibility"]["blockers"]
        )
    assert len(families["A_controlled_complete_transcript_qif"]["required_conditions"]) == 8
    assert len(families["D_heldout_cross_model_workflow"]["required_generation_arms"]) == 2
    assert len(families["E_performance_scalability"]["required_conditions"]) == 11
    family_blockers = {
        code
        for family in (
            "A_controlled_complete_transcript_qif",
            "D_heldout_cross_model_workflow",
            "E_performance_scalability",
        )
        for code in families[family]["blockers"]
    }
    assert all(
        family_blockers.issubset(set(row["blocker_codes"].split("|")))
        for row in expected_rows()
    )
    assert set(BINDING_ARTIFACTS) == {
        "STATUS.md",
        "analysis/ANALYSIS_PLAN_AMENDMENT_20260821.md",
        "manifests/EXPERIMENT_MATRIX.csv",
        "manifests/EXPERIMENT_PROTOCOL.json",
        "source/artifact/sluice_v2/evaluation/experiment_freeze.py",
        "source/artifact/sluice_v2/tests/test_v29_experiment_freeze.py",
    }


def test_model_size_license_and_robustness_roles_fail_closed() -> None:
    protocol = expected_protocol()
    by_slug = {model["slug"]: model for model in protocol["models"]}
    assert protocol["analysis"]["estimand_weighting"][
        "robustness_and_blocked_model_rows"
    ] == "excluded_from_primary_estimands"
    assert by_slug["qwen3-14b-medium-candidate"]["reported_size_gib"] == "28"
    assert by_slug["qwen3-14b-medium-candidate"]["selection_status"].startswith(
        "BLOCKED_MEDIUM_MODEL_RUNTIME_COMPATIBILITY"
    )
    assert by_slug["qwen36-27b-large-candidate"]["reported_size_gib"] == "52"
    assert by_slug["qwen36-27b-large-candidate"]["selection_status"].startswith(
        "BLOCKED_LARGE_MODEL_HARDWARE_RUNTIME_FEASIBILITY"
    )
    for model in MODELS:
        binding = MODEL_LICENSE_BINDINGS[model["slug"]]
        assert binding["license_id"]
        assert binding["audit_status"].startswith("BLOCKED_")
        if model["tier"].startswith("blocked_"):
            assert binding["source_path"].startswith("BLOCKED_")
            assert binding["source_sha256"].startswith("BLOCKED_")
        else:
            assert binding["source_path"] in {"LICENSE", "README.md"}
            assert len(binding["source_sha256"]) == 64
    selected = [row for row in expected_rows() if not row["model_tier"].startswith("blocked_")]
    assert {
        row["cache_reauthentication_evidence_sha256"] for row in selected
    } == {"ac56fc535aa8eee13443b86248633a1b539a5cc51fc4ba1619b639ede09c6008"}
    assert {row["cache_reauthentication_status"] for row in selected} == {
        "PASS_CURRENT_FULL_CONTENT_LAUNCH_START_END_BLOCKED"
    }
    cache_evidence = protocol["model_selection"]["selected_five_cache_reauthentication"]
    assert cache_evidence["status"] == "PASS_SELECTED_FIVE_CACHE_CONTENT"
    assert cache_evidence["model_or_endpoint_loaded"] is False
    assert cache_evidence["gpu_used"] is False
    assert cache_evidence["launch_limit"].startswith("BLOCKED_")
    rows = expected_rows()
    robustness = [row for row in rows if row["model_tier"] == "robustness"]
    assert robustness
    assert all(
        row["comparison_role"]
        in {"secondary_robustness", "diagnostic_appendix_only_robustness"}
        for row in robustness
    )
    blocked_models = [row for row in rows if row["model_tier"].startswith("blocked_")]
    assert blocked_models
    assert all(row["comparison_role"] == "blocked_model_feasibility" for row in blocked_models)
    assert all(row["model_license_audit_status"].startswith("BLOCKED_") for row in rows)
    for row in blocked_models:
        if row["schedule_plan_sha256"] != "BLOCKED_CONDITION_PAIR_NOT_IMPLEMENTED":
            assert row["schedule_plan_sha256"] in {
                "BLOCKED_MEDIUM_MODEL_B_C_EXPERIMENT_PLAN",
                "BLOCKED_LARGE_MODEL_B_C_EXPERIMENT_PLAN",
            }


def test_statistics_and_comparison_families_are_exact() -> None:
    assert BOOTSTRAP_REPLICATES == 10_000
    assert BOOTSTRAP_SEED == 8_675_309
    assert len(AGENTLEAK_COMPARISONS) == 7
    assert len(AGENTDOJO_COMPARISONS) == 6
    protocol = expected_protocol()
    assert protocol["analysis"]["utility_noninferiority"]["absolute_margin"] == -0.05
    assert "Holm" in protocol["analysis"]["multiplicity"]["secondary"]
    assert protocol["analysis"]["technical_exclusions"] == []


def test_runtime_failures_are_invalidated_not_frozen_as_success() -> None:
    runtime = expected_protocol()["runtime"]
    fdv3 = runtime["invalidated_node001_fdv3_split_brain_publication"]
    assert fdv3["success_looking_manifest_sha256"] == (
        "3c64876afe406b4230de17bb1f13be6f5acfe0a16002d0f554315bc8eeb4b974"
    )
    assert fdv3["failure_log_sha256"] == (
        "5d6a376393a96da9d3738804509344c838e891dad1a44d2d240aabcb8f441be1"
    )
    assert fdv3["create_only_invalidation_sha256"] == (
        "6a0742eb6b2c0bbd4a229ee5af91fdd843789f72a2b50248e142066573c40c36"
    )
    assert fdv3["status"] == "INVALID_SPLIT_BRAIN_PUBLICATION_DIAGNOSTIC_ONLY"
    assert fdv3["model_or_cuda_run"] is False
    assert runtime["principal_runtime_tree_sha256"].startswith("BLOCKED_")


def test_required_unimplemented_agentdojo_conditions_are_visible_and_blocking() -> None:
    rows = expected_rows()
    missing = [
        row
        for row in rows
        if row["benchmark"] == "agentdojo"
        and row["schedule_plan_sha256"] == "BLOCKED_CONDITION_PAIR_NOT_IMPLEMENTED"
    ]
    assert len(missing) == 560
    assert {
        row["comparison_id"] for row in missing
    } == {
        "sluice_oracle_upper_bound_vs_undefended",
        "no_exact_argument_binding_vs_sluice_nonoracle",
        "no_authenticated_callers_vs_sluice_nonoracle",
        "no_redeemer_binding_vs_sluice_nonoracle",
    }
    assert all("BLOCKED_CONDITION_PAIR_NOT_IMPLEMENTED" in row["blocker_codes"] for row in missing)


def test_every_unknown_is_explicitly_blocked_and_no_row_is_eligible() -> None:
    for row in expected_rows():
        assert row["principal_eligible"] == "FALSE"
        assert row["principal_runtime_tree_sha256"].startswith("BLOCKED_")
        assert row["launch_decoding_manifest_sha256"].startswith("BLOCKED_")
        assert row["live_condition_identity_sha256"].startswith("BLOCKED_")
        blockers = row["blocker_codes"].split("|")
        assert blockers == sorted(set(blockers))
        assert all(blocker.startswith("BLOCKED_") for blocker in blockers)
        for name, value in row.items():
            if name.endswith("_sha256"):
                text = str(value)
                assert text.startswith("BLOCKED_") or (
                    len(text) == 64
                    and all(character in "0123456789abcdef" for character in text)
                ), (name, text)


def test_canonical_emit_rejects_byte_and_coordinate_tampering(tmp_path: Path) -> None:
    _copy_validation_fixture(tmp_path)
    matrix_path = tmp_path / "manifests/EXPERIMENT_MATRIX.csv"
    original = matrix_path.read_bytes()
    assert original == expected_matrix_bytes()
    rows = list(csv.DictReader(io.StringIO(original.decode("ascii"))))
    assert tuple(rows[0]) == CSV_HEADER
    rows[0]["seed"] = "1"
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_HEADER, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    matrix_path.write_bytes(stream.getvalue().encode("ascii"))
    with pytest.raises(FreezeError, match="not the exact canonical"):
        validate_repository(tmp_path)


def test_protocol_tampering_is_rejected_before_principal_gate(tmp_path: Path) -> None:
    _copy_validation_fixture(tmp_path)
    protocol_path = tmp_path / "manifests/EXPERIMENT_PROTOCOL.json"
    wire = json.loads(protocol_path.read_text(encoding="ascii"))
    wire["analysis"]["utility_noninferiority"]["absolute_margin"] = -0.10
    protocol_path.write_text(
        json.dumps(wire, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="ascii",
    )
    with pytest.raises(FreezeError, match="not the exact canonical"):
        validate_repository(tmp_path)


def test_descriptor_read_rejects_parent_rebound_without_reading_attacker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "anchored"
    parent.mkdir()
    target = parent / "freeze.json"
    target.write_bytes(b"trusted")
    original_parent = tmp_path / "anchored-original"

    def rebound(stage: str, path: Path) -> None:
        if stage == "read_parent_pinned":
            path.parent.rename(original_parent)
            path.parent.mkdir()
            (path.parent / path.name).write_bytes(b"attacker")

    monkeypatch.setattr(freeze, "_io_identity_hook", rebound)
    with pytest.raises(
        FreezeError, match="directory identity changed|inotify mutation"
    ):
        freeze._read_regular(target, maximum=64)
    assert target.read_bytes() == b"attacker"
    assert (original_parent / target.name).read_bytes() == b"trusted"


def test_descriptor_read_rejects_leaf_replacement_after_same_fd_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "freeze.json"
    target.write_bytes(b"trusted")
    original = tmp_path / "freeze-original.json"

    def replace(stage: str, path: Path) -> None:
        if stage == "read_leaf_opened":
            path.rename(original)
            path.write_bytes(b"attacker")

    monkeypatch.setattr(freeze, "_io_identity_hook", replace)
    with pytest.raises(
        FreezeError,
        match="changed while read|leaf identity changed|inotify mutation",
    ):
        freeze._read_regular(target, maximum=64)
    assert original.read_bytes() == b"trusted"
    assert target.read_bytes() == b"attacker"


def test_descriptor_create_rejects_parent_rebound_and_does_not_write_attacker_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "emit"
    original_parent = tmp_path / "manifests-original"

    def rebound(stage: str, path: Path) -> None:
        if stage == "create_parent_pinned":
            path.parent.rename(original_parent)
            path.parent.mkdir()

    monkeypatch.setattr(freeze, "_io_identity_hook", rebound)
    with pytest.raises(
        FreezeError, match="directory identity changed|inotify mutation"
    ):
        emit_freeze(output)
    assert not (output / "manifests" / "EXPERIMENT_MATRIX.csv").exists()
    assert not (original_parent / "EXPERIMENT_MATRIX.csv").exists()


def test_descriptor_create_retains_and_rejects_postwrite_hardlink_mode_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "freeze.json"
    alias = tmp_path / "freeze.alias"
    payload = b"prospective"

    def mutate(stage: str, path: Path) -> None:
        if stage == "create_after_write":
            os.link(path, alias)
            os.chmod(path, 0o600)

    monkeypatch.setattr(freeze, "_io_identity_hook", mutate)
    with pytest.raises(
        FreezeError, match="identity or mode changed|directory identity changed"
    ):
        freeze._create_once(target, payload)
    assert target.read_bytes() == payload
    assert alias.read_bytes() == payload
    assert target.stat().st_nlink == 2
    assert target.stat().st_mode & 0o777 == 0o600


def test_detached_binding_covers_group_and_detects_status_drift(tmp_path: Path) -> None:
    for relative in BINDING_ARTIFACTS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((relative + "\n").encode("ascii"))
    report = emit_binding_manifest(tmp_path)
    binding = tmp_path / "manifests/EXPERIMENT_FREEZE_BINDINGS.json"
    before = binding.read_bytes()
    assert len(report["binding_sha256"]) == 64
    assert before == expected_binding_bytes(tmp_path)
    (tmp_path / "STATUS.md").write_bytes(b"drift\n")
    assert before != expected_binding_bytes(tmp_path)
    with pytest.raises(
        FreezeError, match="cannot create descriptor-bound|directory identity changed"
    ):
        emit_binding_manifest(tmp_path)


def test_validation_group_is_the_exact_deduplicated_member_union() -> None:
    selected_cache_manifests = {
        model["cache_manifest_path"]
        for model in MODELS
        if not model["tier"].startswith("blocked_")
    }
    expected = (
        set(BINDING_ARTIFACTS)
        | set(freeze.SOURCE_BINDINGS)
        | selected_cache_manifests
        | {
            "manifests/EXPERIMENT_FREEZE_BINDINGS.json",
            "manifests/EXPERIMENT_MATRIX.csv",
            "manifests/EXPERIMENT_PROTOCOL.json",
        }
    )
    limits = freeze._validation_member_limits()
    assert set(limits) == expected
    assert len(limits) == len(expected)
    assert tuple(limits) == tuple(sorted(limits))
    for relative in limits:
        assert freeze._relative_group_member(relative).as_posix() == relative
    for invalid in ("", "/absolute", "../escape", "a/../b", "a//b", "a/./b"):
        with pytest.raises(FreezeError, match="inadmissible"):
            freeze._relative_group_member(invalid)


def test_strict_json_rejects_duplicates_nonfinite_noncanonical_and_bool_aliases() -> None:
    with pytest.raises(FreezeError, match="duplicate"):
        freeze._parse_strict_json(
            b'{"x": 1, "x": 2}\n', label="duplicate", canonical="pretty"
        )
    with pytest.raises(FreezeError, match="non-finite"):
        freeze._parse_strict_json(
            b'{"x": NaN}\n', label="nonfinite", canonical="pretty"
        )
    with pytest.raises(FreezeError, match="canonical"):
        freeze._parse_strict_json(
            b'{"x":1}\n', label="wrong-profile", canonical="pretty"
        )
    assert freeze._json_exact_equal({"x": True}, {"x": 1}) is False

    model = dict(MODELS[0])
    license_binding = MODEL_LICENSE_BINDINGS[model["slug"]]
    entries = [
        {"bytes": 1, "path": name, "sha256": digest, "symlink_target": "blob"}
        for name, digest in (
            ("tokenizer.json", model["tokenizer_json_sha256"]),
            ("tokenizer_config.json", model["tokenizer_config_sha256"]),
            ("config.json", model["model_config_sha256"]),
            ("generation_config.json", model["generation_config_sha256"]),
            (license_binding["source_path"], license_binding["source_sha256"]),
        )
    ]
    wire = {
        "entries": entries,
        "file_count": len(entries),
        "revision": model["revision"],
        "schema_version": True,
        "total_entry_bytes": len(entries),
    }
    data = freeze._canonical_compact_json(wire)
    model["cache_manifest_sha256"] = freeze._sha256(data)
    with pytest.raises(FreezeError, match="schema version"):
        freeze._verify_cache_manifest_bytes(data, model, path=Path("cache.json"))


def test_unchanged_independent_post_read_hook_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    matrix = fixture / "manifests/EXPERIMENT_MATRIX.csv"
    protocol = fixture / "manifests/EXPERIMENT_PROTOCOL.json"
    protocol_reads = 0
    mutated = False

    def post_read_hook(stage: str, path: Path) -> None:
        nonlocal protocol_reads, mutated
        if stage == "read_parent_pinned" and path == protocol:
            protocol_reads += 1
            if protocol_reads == 2:
                matrix.write_bytes(matrix.read_bytes() + b"#post-read-mutation\n")
                mutated = True

    monkeypatch.setattr(freeze, "_io_identity_hook", post_read_hook)
    with pytest.raises(
        FreezeError, match="identity changed|bytes changed|inotify mutation"
    ):
        validate_repository(fixture)
    assert protocol_reads == 2 and mutated


def test_final_group_pass_rereads_and_rebinds_every_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    final_lexical_reads: list[str] = []

    def record(stage: str, path: Path) -> None:
        if stage == "group_final_after_lexical_read":
            final_lexical_reads.append(path.relative_to(fixture).as_posix())

    monkeypatch.setattr(freeze, "_io_identity_hook", record)
    report = validate_repository(fixture)
    assert report["principal_eligible"] is False
    assert final_lexical_reads == list(freeze._validation_member_limits())
    assert set(BINDING_ARTIFACTS).issubset(final_lexical_reads)
    assert {
        model["cache_manifest_path"]
        for model in MODELS
        if not model["tier"].startswith("blocked_")
    }.issubset(final_lexical_reads)


@pytest.mark.parametrize(
    "stage",
    (
        "read_parent_pinned",
        "read_leaf_opened",
        "read_after_same_fd",
        "group_final_before_member_recheck",
        "group_final_after_lexical_read",
    ),
)
def test_every_group_hook_epoch_rejects_transient_byte_mutation(
    stage: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    target = fixture / "analysis/ANALYSIS_PLAN.md"
    original = target.read_bytes()
    injected = False

    def transient(hook_stage: str, path: Path) -> None:
        nonlocal injected
        if not injected and hook_stage == stage:
            target.write_bytes(original + b"#transient\n")
            target.write_bytes(original)
            injected = True

    monkeypatch.setattr(freeze, "_io_identity_hook", transient)
    with pytest.raises(
        FreezeError,
        match="identity changed|directory identity changed|inotify mutation",
    ):
        validate_repository(fixture)
    assert injected and target.read_bytes() == original


@pytest.mark.parametrize(
    "relative",
    tuple(
        sorted(
            set(BINDING_ARTIFACTS)
            | {
                model["cache_manifest_path"]
                for model in MODELS
                if not model["tier"].startswith("blocked_")
            }
        )
    ),
)
def test_every_bound_artifact_and_cache_rejects_replacement_restoration(
    relative: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    target = fixture / relative
    parked = target.with_name(target.name + ".parked")
    original = target.read_bytes()
    injected = False

    def replace_and_restore(stage: str, path: Path) -> None:
        nonlocal injected
        if not injected and stage == "group_final_before_member_recheck":
            target.rename(parked)
            target.write_bytes(b"attacker\n")
            target.unlink()
            parked.rename(target)
            injected = True

    monkeypatch.setattr(freeze, "_io_identity_hook", replace_and_restore)
    with pytest.raises(
        FreezeError,
        match=(
            "identity changed|directory identity changed|lexical path rebound|"
            "inotify mutation"
        ),
    ):
        validate_repository(fixture)
    assert injected and target.read_bytes() == original


def test_descriptor_read_rejects_parent_replacement_and_restoration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "anchored"
    parent.mkdir()
    target = parent / "freeze.json"
    target.write_bytes(b"trusted")
    parked = tmp_path / "anchored-parked"

    def replace_and_restore(stage: str, path: Path) -> None:
        if stage == "read_parent_pinned":
            path.parent.rename(parked)
            path.parent.mkdir()
            (path.parent / path.name).write_bytes(b"attacker")
            (path.parent / path.name).unlink()
            path.parent.rmdir()
            parked.rename(path.parent)

    monkeypatch.setattr(freeze, "_io_identity_hook", replace_and_restore)
    with pytest.raises(
        FreezeError, match="directory identity changed|inotify mutation"
    ):
        freeze._read_regular(target, maximum=64)
    assert target.read_bytes() == b"trusted"


def test_descriptor_read_rejects_leaf_mutation_and_byte_restoration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "freeze.json"
    target.write_bytes(b"trusted")

    def mutate_and_restore(stage: str, path: Path) -> None:
        if stage == "read_leaf_opened":
            path.write_bytes(b"attacker")
            path.write_bytes(b"trusted")

    monkeypatch.setattr(freeze, "_io_identity_hook", mutate_and_restore)
    with pytest.raises(FreezeError, match="changed while read|inotify mutation"):
        freeze._read_regular(target, maximum=64)
    assert target.read_bytes() == b"trusted"


def test_descriptor_create_rejects_leaf_precreation_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "freeze.json"

    def precreate(stage: str, path: Path) -> None:
        if stage == "create_parent_pinned":
            path.write_bytes(b"attacker")

    monkeypatch.setattr(freeze, "_io_identity_hook", precreate)
    with pytest.raises(
        FreezeError,
        match="cannot create descriptor-bound|directory identity changed",
    ):
        freeze._create_once(target, b"prospective")
    assert target.read_bytes() == b"attacker"


def test_descriptor_create_rejects_leaf_replacement_after_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "freeze.json"
    parked = tmp_path / "freeze.parked"

    def replace(stage: str, path: Path) -> None:
        if stage == "create_after_write":
            path.rename(parked)
            path.write_bytes(b"attacker")

    monkeypatch.setattr(freeze, "_io_identity_hook", replace)
    with pytest.raises(
        FreezeError,
        match="identity or mode changed|leaf identity changed|directory identity changed",
    ):
        freeze._create_once(target, b"prospective")
    assert parked.read_bytes() == b"prospective"
    assert target.read_bytes() == b"attacker"


def test_group_rejects_symlink_member_before_interpreting_any_bytes(
    tmp_path: Path
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    target = fixture / "analysis/ANALYSIS_PLAN.md"
    parked = fixture / "analysis/ANALYSIS_PLAN.parked"
    target.rename(parked)
    target.symlink_to(parked.name)
    with pytest.raises(FreezeError, match="complete descriptor-bound freeze group"):
        validate_repository(fixture)


def test_group_rejects_parent_path_rebound_at_a_member_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    parent = fixture / "analysis"
    parked = fixture / "analysis-parked"
    injected = False

    def rebound(stage: str, path: Path) -> None:
        nonlocal injected
        if not injected and stage == "read_parent_pinned":
            parent.rename(parked)
            parent.mkdir()
            injected = True

    monkeypatch.setattr(freeze, "_io_identity_hook", rebound)
    with pytest.raises(
        FreezeError, match="identity changed|lexical path rebound|inotify mutation"
    ):
        validate_repository(fixture)
    assert injected
    assert parked.is_dir() and parent.is_dir()


def test_all_held_descriptors_close_when_validation_fails_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    captured: list[int] = []
    original_open = freeze._open_held_members

    def capture(root: Path, limits):
        members = original_open(root, limits)
        captured.extend(
            descriptor
            for member in members
            for descriptor in (member.parent_descriptor, member.file_descriptor)
        )
        return members

    def fail_hook(stage: str, path: Path) -> None:
        if stage == "read_parent_pinned":
            raise FreezeError("injected group failure")

    monkeypatch.setattr(freeze, "_open_held_members", capture)
    monkeypatch.setattr(freeze, "_io_identity_hook", fail_hook)
    with pytest.raises(FreezeError, match="injected group failure"):
        validate_repository(fixture)
    assert captured
    for descriptor in captured:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_partial_group_open_failure_closes_every_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    real_open = os.open
    real_close = os.close
    active: set[int] = set()
    injected = False

    def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal injected
        if path == "EXPERIMENT_PROTOCOL.json" and dir_fd is not None:
            injected = True
            raise OSError("injected partial-open failure")
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        active.add(descriptor)
        return descriptor

    def tracked_close(descriptor: int) -> None:
        active.discard(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "close", tracked_close)
    with pytest.raises(FreezeError, match="complete descriptor-bound freeze group"):
        freeze._open_held_members(
            fixture, freeze._validation_member_limits()
        )
    assert injected and not active


def test_declared_group_members_reject_duplicates_and_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate = BINDING_ARTIFACTS + (BINDING_ARTIFACTS[0],)
    monkeypatch.setattr(freeze, "BINDING_ARTIFACTS", duplicate)
    with pytest.raises(FreezeError, match="duplicate logical binding artifact"):
        freeze._validation_member_limits()

    monkeypatch.setattr(
        freeze,
        "BINDING_ARTIFACTS",
        BINDING_ARTIFACTS + ("analysis//ANALYSIS_PLAN.md",),
    )
    with pytest.raises(FreezeError, match="inadmissible freeze-group member"):
        freeze._validation_member_limits()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_linux_inotify_covers_every_file_and_lexical_parent_and_closes(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    limits = freeze._validation_member_limits()
    watcher = freeze._LinuxInotifyGroupWatch(fixture, limits)
    descriptor = watcher.descriptor
    expected_files = tuple(
        str(fixture / relative) for relative in sorted(limits)
    )
    expected_parents = {str(fixture)}
    for relative in limits:
        cursor = fixture
        for component in Path(relative).parent.parts:
            cursor = cursor / component
            expected_parents.add(str(cursor))
    assert watcher.watched_files == expected_files
    assert watcher.watched_parents == tuple(sorted(expected_parents))
    watcher.assert_quiet("unchanged fixture")
    watcher.close()
    assert watcher.descriptor == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_linux_inotify_queue_overflow_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "member"
    target.write_bytes(b"trusted")
    watcher = freeze._LinuxInotifyGroupWatch(tmp_path, {"member": 64})
    monkeypatch.setattr(
        watcher,
        "_drain",
        lambda: [(-1, watcher._IN_Q_OVERFLOW, "")],
    )
    with pytest.raises(FreezeError, match="inotify queue overflow"):
        watcher.assert_quiet("synthetic overflow")
    watcher.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_inotify_descriptor_closes_on_group_validation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture"
    _copy_validation_fixture(fixture)
    captured: list[int] = []
    original = freeze._LinuxInotifyGroupWatch

    class CapturingWatch(original):
        def __init__(self, root: Path, limits) -> None:
            super().__init__(root, limits)
            captured.append(self.descriptor)

    def fail_hook(stage: str, path: Path) -> None:
        if stage == "read_parent_pinned":
            raise FreezeError("injected watcher cleanup failure")

    monkeypatch.setattr(freeze, "_LinuxInotifyGroupWatch", CapturingWatch)
    monkeypatch.setattr(freeze, "_io_identity_hook", fail_hook)
    with pytest.raises(FreezeError, match="injected watcher cleanup failure"):
        validate_repository(fixture)
    assert captured
    for descriptor in captured:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inotify is required")
def test_inotify_descriptor_closes_on_partial_watch_setup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "member"
    target.write_bytes(b"trusted")
    captured: list[int] = []
    calls = 0
    original_add = freeze._LinuxInotifyGroupWatch._add_path

    def fail_second_add(self, path: str, mask: int) -> None:
        nonlocal calls
        calls += 1
        captured.append(self.descriptor)
        if calls == 2:
            raise FreezeError("injected watch setup failure")
        original_add(self, path, mask)

    monkeypatch.setattr(freeze._LinuxInotifyGroupWatch, "_add_path", fail_second_add)
    with pytest.raises(FreezeError, match="injected watch setup failure"):
        freeze._LinuxInotifyGroupWatch(tmp_path, {"member": 64})
    assert calls == 2 and captured
    with pytest.raises(OSError):
        os.fstat(captured[-1])
