from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from types import MappingProxyType

import pytest

import sluice_v2.evaluation.agentleak_principal_driver as principal


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
BENCHMARK_ROOT = ARTIFACT_ROOT / "benchmarks" / "agentleak"
SCHEDULE_PATH = BENCHMARK_ROOT / "public_schedule_full_1000_v1.json"
CODEBOOK_ROOT = BENCHMARK_ROOT / "codebooks_full_1000_v1"
CORPUS_PATH = BENCHMARK_ROOT / "scenarios_full_1000.jsonl"
AUDIT_ROOT = (
    REPOSITORY_ROOT / "runs" / "agentleak_principal_cpu_integrity_review_20260821"
)


@pytest.fixture(scope="module")
def plan():
    return principal.build_execution_plan(public_schedule_path=SCHEDULE_PATH)


@pytest.fixture(scope="module")
def prepared(plan):
    arm = next(
        arm
        for arm in plan.blocks[0].arms
        if arm.condition is principal.PrincipalCondition.SLUICE_COMPLETE
    )
    return principal.prepare_sluice_cpu_episode(
        plan=plan,
        arm=arm,
        public_schedule_path=SCHEDULE_PATH,
        codebook_root=CODEBOOK_ROOT,
        corpus_path=CORPUS_PATH,
    )


@pytest.fixture(scope="module")
def chronology(prepared):
    session = principal.FakeSluiceChronologySession(prepared)
    for index, route in enumerate(prepared.launched.policy_input.route_codebooks):
        session.release(
            request_id=f"release-{index:02d}",
            route_name=route.route_name,
            channel=route.channel,
        )
    session.close(request_id="close-00")
    session.close(request_id="close-01")
    return session.seal(require_all_channels=True)


def _rehash(wire: dict) -> dict:
    wire["chronology_sha256"] = principal.chronology_wire_sha256(wire)
    return wire


@pytest.mark.parametrize(
    "mutation",
    (
        "release_control_reclassified_as_charged",
        "declared_public_reclassified_as_codebook_release",
        "close_control_reclassified_as_charged",
        "close_response_reserved_metadata_forged",
        "terminal_request_binding_forged",
        "pad_route_binding_forged",
    ),
)
def test_mixed_chronology_rejects_forged_step_classification_and_binding(
    prepared, chronology, mutation: str
) -> None:
    wire = deepcopy(chronology.to_wire())
    steps = wire["steps"]
    if mutation == "release_control_reclassified_as_charged":
        step = next(
            value
            for value in steps
            if value["step_kind"] == "CONTROL_REQUEST" and value["status"] == "RELEASE"
        )
        step["accounting_class"] = "CHARGED_FINITE"
        step["charge_units"] = prepared.launched.codebooks.binding.event_charge_units
    elif mutation == "declared_public_reclassified_as_codebook_release":
        steps[0]["receipt_kind"] = "CODEBOOK_RELEASE"
    elif mutation == "close_control_reclassified_as_charged":
        step = next(
            value
            for value in steps
            if value["step_kind"] == "CONTROL_REQUEST" and value["status"] == "CLOSE"
        )
        step["accounting_class"] = "CHARGED_FINITE"
        step["charge_units"] = prepared.launched.codebooks.binding.event_charge_units
    elif mutation == "close_response_reserved_metadata_forged":
        step = next(
            value
            for value in steps
            if value["step_kind"] == "MONITOR_RESPONSE"
            and value["status"] == "DOMAIN_CLOSED"
        )
        step["reserved_units"] += 10_000
    elif mutation == "terminal_request_binding_forged":
        step = next(value for value in steps if value["step_kind"] == "TERMINAL_STATUS")
        step["request_id"] = "forged-terminal-request"
    elif mutation == "pad_route_binding_forged":
        step = next(value for value in steps if value["step_kind"] == "PAD")
        step["route_name"] = "forged-pad-route"
    else:
        raise AssertionError(mutation)

    with pytest.raises(principal.PrincipalDriverError):
        principal.validate_chronology_wire(wire=_rehash(wire), prepared=prepared)


def test_handoff_writer_rejects_parent_rebind_after_descriptor_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    displaced = tmp_path / "displaced"
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    output = output_parent / "offline_handoff.json"
    attacker_bytes = b"attacker-controlled-rebound"
    (attacker / output.name).write_bytes(attacker_bytes)

    real_open = principal.os.open
    raced = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal raced
        if path == output.name and dir_fd is not None and not raced:
            raced = True
            output_parent.rename(displaced)
            output_parent.symlink_to(attacker, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(principal.os, "open", racing_open)
    handoff = {
        "execution_mode": principal.CPU_EXECUTION_MODE,
        "principal_execution_eligible": False,
        "principal_outcome_count": 0,
    }
    with pytest.raises(principal.PrincipalDriverError):
        principal.write_redacted_handoff_create_only(path=output, handoff=handoff)

    assert raced is True
    assert output.read_bytes() == attacker_bytes


def test_raw_record_validation_rejects_file_mode_drift(tmp_path: Path, plan) -> None:
    arm = next(
        arm
        for arm in plan.blocks[0].arms
        if arm.condition is not principal.PrincipalCondition.SLUICE_COMPLETE
    )
    record = principal.build_cpu_attempt_record(
        plan=plan,
        arm=arm,
        status=principal.AttemptStatus.CPU_FAKE_COMPLETED,
    )
    store = principal.RawRunJournalStore(tmp_path / "restricted")
    try:
        receipt = store.append(record=record)
        receipt.path.chmod(0o644)
        with pytest.raises(principal.PrincipalDriverError):
            principal.validate_raw_run_record(receipt=receipt, plan=plan)
    finally:
        store.close()


def test_offline_handoff_rejects_directly_forged_validated_record(plan) -> None:
    arm = plan.blocks[0].arms[0]
    forged = principal.ValidatedAttemptRecord(
        attempt_id=arm.attempt_id,
        condition=arm.condition,
        status=principal.AttemptStatus.CPU_FAKE_COMPLETED,
        has_chronology=False,
    )
    with pytest.raises(principal.PrincipalDriverError):
        principal.build_redacted_offline_handoff(plan=plan, records=(forged,))


def test_blinded_task_builder_rejects_unbound_protected_value_projection(prepared) -> None:
    allowed_name = prepared.launched.policy_input.allowed_field_names[0]
    scenario = prepared.launched.scenario
    forbidden_names = tuple(scenario["allowed_set"]["forbidden_fields"])
    protected = next(
        str(record["fields"][name])
        for record in scenario["private_vault"]["records"]
        for name in forbidden_names
        if name in record["fields"]
    )
    forged_projection = MappingProxyType(
        {"records": (MappingProxyType({allowed_name: protected}),)}
    )
    with pytest.raises(principal.PrincipalDriverError):
        principal.build_blinded_task_input(
            policy_input=prepared.launched.policy_input,
            allowed_projection=forged_projection,
            opaque_pair_local_id="opaque-forged-projection",
            final_response=protected,
            final_artifact="",
        )


def test_public_evidence_records_contain_no_restricted_fields_or_synthetic_secret() -> None:
    evidence = REPOSITORY_ROOT / "runs" / "agentleak_principal_cpu_20260821"
    public_paths = (
        evidence / "attestation_run_a" / "cpu_attestation.json",
        evidence / "attestation_run_a" / "offline_handoff.json",
        evidence / "attestation_run_b" / "cpu_attestation.json",
        evidence / "attestation_run_b" / "offline_handoff.json",
    )
    forbidden = (
        "private_vault",
        "attack_payload",
        "canary",
        "value_code",
        "secret-synthetic",
        "scenario_id",
        "attempt_id",
    )
    for path in public_paths:
        rendered = path.read_text(encoding="utf-8").casefold()
        assert not any(value in rendered for value in forbidden)
        assert json.loads(rendered)["principal_outcome_count"] == 0


def test_rejected_candidate_audit_tree_and_committed_schedule_remain_exact() -> None:
    inventory = AUDIT_ROOT / "SHA256SUMS"
    assert hashlib.sha256(inventory.read_bytes()).hexdigest() == (
        "755ba9737fec02cd77133be428adb165016748ed1fa705ced7f614ad9ded40e6"
    )
    for line in inventory.read_text(encoding="ascii").splitlines():
        expected, relative = line.split("  ", 1)
        assert hashlib.sha256((REPOSITORY_ROOT / relative).read_bytes()).hexdigest() == expected
    assert hashlib.sha256(SCHEDULE_PATH.read_bytes()).hexdigest() == (
        "ff7956d57317510a07233f055d17cb0039dceac6b2d9e1c79bb3a98fe1da68b4"
    )
