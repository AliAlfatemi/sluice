from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

from sluice_v2.evaluation.agentleak_fullstack import UtilityOutcome
from sluice_v2.evaluation.agentleak_principal_driver import (
    CPU_FOUNDATION_ELIGIBILITY,
    PRINCIPAL_CONDITIONS,
    AttemptStatus,
    FakeSluiceChronologySession,
    PrincipalCondition,
    RawRunJournalStore,
    adjudicate_blinded_task,
    audit_cpu_only_source,
    build_blinded_task_input,
    build_cpu_attempt_record,
    build_execution_plan,
    build_redacted_offline_handoff,
    prepare_sluice_cpu_episode,
    run_synthetic_detector_metamorphic_controls,
    seal_allowed_projection_for_utility,
    validate_chronology,
    validate_raw_run_record,
    write_redacted_handoff_create_only,
)


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _eligibility_wire() -> dict[str, object]:
    value = CPU_FOUNDATION_ELIGIBILITY
    return {
        "clean_commit_eligible": value.clean_commit_eligible,
        "cpu_foundation": value.cpu_foundation,
        "dependency_eligible": value.dependency_eligible,
        "effectiveness_evidence": value.effectiveness_evidence,
        "endpoint_eligible": value.endpoint_eligible,
        "execution_mode": value.execution_mode,
        "isolated_gpu_eligible": value.isolated_gpu_eligible,
        "model_revision_eligible": value.model_revision_eligible,
        "principal_execution_eligible": value.principal_execution_eligible,
        "topology_eligible": value.topology_eligible,
        "utility_evidence": value.utility_evidence,
    }


def attest(*, repository_root: Path, output_root: Path) -> dict[str, object]:
    repository_root = repository_root.resolve(strict=True)
    artifact_root = repository_root / "source" / "artifact"
    benchmark_root = artifact_root / "benchmarks" / "agentleak"
    module_path = artifact_root / "sluice_v2" / "evaluation" / "agentleak_principal_driver.py"
    try:
        output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(output_root, 0o700)
    except OSError as exc:
        raise RuntimeError("attestation output root must be a new directory") from exc
    metadata = output_root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or output_root.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError("attestation output root is not private and owned")

    schedule_path = benchmark_root / "public_schedule_full_1000_v1.json"
    codebook_root = benchmark_root / "codebooks_full_1000_v1"
    corpus_path = benchmark_root / "scenarios_full_1000.jsonl"
    plan = build_execution_plan(public_schedule_path=schedule_path)
    block = plan.blocks[0]
    sluice_arm = next(
        arm
        for arm in block.arms
        if arm.condition is PrincipalCondition.SLUICE_COMPLETE
    )
    prepared = prepare_sluice_cpu_episode(
        plan=plan,
        arm=sluice_arm,
        public_schedule_path=schedule_path,
        codebook_root=codebook_root,
        corpus_path=corpus_path,
    )
    chronology_session = FakeSluiceChronologySession(prepared)
    delivered = {}
    for index, route in enumerate(prepared.launched.policy_input.route_codebooks):
        response = chronology_session.release(
            request_id=f"release-{index:02d}",
            route_name=route.route_name,
            channel=route.channel,
        )
        delivered[route.channel] = response.content
    chronology_session.close(request_id="close-00")
    chronology_session.close(request_id="close-01")
    chronology = chronology_session.seal(require_all_channels=True)
    chronology_validation = validate_chronology(
        chronology=chronology, prepared=prepared
    )

    journal = RawRunJournalStore(output_root / "restricted_raw_journal")
    validated_records = []
    try:
        for arm in block.arms:
            record = build_cpu_attempt_record(
                plan=plan,
                arm=arm,
                status=AttemptStatus.CPU_FAKE_COMPLETED,
                chronology=(chronology if arm is sluice_arm else None),
            )
            receipt = journal.append(
                record=record,
                prepared=(prepared if record.chronology is not None else None),
            )
            validated_records.append(
                validate_raw_run_record(
                    receipt=receipt,
                    plan=plan,
                    prepared=(prepared if record.chronology is not None else None),
                )
            )
    finally:
        journal.close()

    handoff = build_redacted_offline_handoff(
        plan=plan, records=tuple(validated_records)
    )
    handoff_sha256 = write_redacted_handoff_create_only(
        path=output_root / "offline_handoff.json", handoff=handoff
    )
    projection = seal_allowed_projection_for_utility(prepared=prepared)
    utility_input = build_blinded_task_input(
        policy_input=prepared.launched.policy_input,
        allowed_projection=projection,
        opaque_pair_local_id="opaque-cpu-control-0001",
        final_response=delivered[
            next(
                channel
                for channel in delivered
                if channel.value == "C1_final_output"
            )
        ],
        final_artifact=delivered[
            next(
                channel
                for channel in delivered
                if channel.value == "C7_artifact"
            )
        ],
    )
    utility_control = adjudicate_blinded_task(
        task_input=utility_input,
        semantic_evaluator=lambda _: UtilityOutcome.ABSTAIN,
    )
    detector_controls = run_synthetic_detector_metamorphic_controls(
        agentleak_source_root=repository_root / "external" / "agentleak"
    )
    source_audit = audit_cpu_only_source(module_path)
    if not source_audit.ok:
        raise RuntimeError("CPU-only source audit failed")
    attestation = {
        "chronology": {
            "cached_domain_closed_count": chronology_validation.cached_domain_closed_count,
            "charged_release_count": chronology_validation.charged_release_count,
            "chronology_hmax": chronology_validation.step_count,
            "delivery_count": chronology_validation.delivery_count,
            "release_horizon": chronology.release_horizon,
            "total_reserved_units": chronology_validation.total_reserved_units,
        },
        "detector_controls": detector_controls.to_public_record(),
        "driver_source_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "eligibility": _eligibility_wire(),
        "execution_mode": CPU_FOUNDATION_ELIGIBILITY.execution_mode,
        "handoff_sha256": handoff_sha256,
        "plan": plan.to_public_record(),
        "principal_condition_count": len(PRINCIPAL_CONDITIONS),
        "principal_outcome_count": 0,
        "raw_cpu_fake_record_count": len(validated_records),
        "schema_version": "sluice-agentleak-principal-cpu-attestation-v1",
        "source_audit": {
            "forbidden_call_count": len(source_audit.forbidden_calls),
            "forbidden_import_count": len(source_audit.forbidden_imports),
            "ok": source_audit.ok,
            "principal_outcome_count": source_audit.principal_outcome_count,
        },
        "utility_control": utility_control.to_public_record(),
    }
    write_redacted_handoff_create_only(
        path=output_root / "cpu_attestation.json", handoff=attestation
    )
    return attestation


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Attest the AgentLeak CPU/fake-backend foundation only"
    )
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    arguments = parser.parse_args()
    result = attest(
        repository_root=arguments.repository_root,
        output_root=arguments.output_root,
    )
    print(_canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
