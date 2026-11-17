from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest

from sluice_v2.evaluation import agentdojo_principal_construction as construction
from sluice_v2.evaluation import agentdojo_principal_driver as principal
from sluice_v2.tests import test_v25_agentdojo_principal_driver as contract


@pytest.fixture(scope="module")
def source_attestation():
    return contract.source_attestation.__wrapped__()


@pytest.fixture(scope="module")
def registry_attestation(source_attestation):
    return contract.registry_attestation.__wrapped__(source_attestation)


@pytest.fixture(scope="module")
def plan_wire(source_attestation, registry_attestation):
    return construction.build_principal_plan_wire(
        source=source_attestation,
        registry=registry_attestation,
    )


@pytest.fixture(scope="module")
def plan(plan_wire):
    return principal.PrincipalExecutionPlan.load(
        copy.deepcopy(plan_wire), expected_sha256=plan_wire["sha256"]
    )


def _rehash(value):
    value["sha256"] = principal.principal_plan_sha256(value)


def test_deeply_rehashed_schedule_condition_mutation_is_rejected(plan_wire):
    mutated = copy.deepcopy(plan_wire)
    instance = mutated["schedule_instances"][0]
    schedule = instance["schedule"]
    schedule["entries"][0]["condition"] = principal.PrincipalCondition.SLUICE_NONORACLE.value
    _rehash(schedule)
    _rehash(instance)
    _rehash(mutated)
    with pytest.raises(principal.PrincipalDriverError, match="schedule|condition"):
        principal.PrincipalExecutionPlan.load(
            mutated, expected_sha256=mutated["sha256"]
        )


def test_deeply_rehashed_universe_and_split_mutations_are_rejected(plan_wire):
    universe = copy.deepcopy(plan_wire)
    universe["universe"]["attacked_pairs"][0]["pair_id"] = "0" * 64
    _rehash(universe["universe"])
    _rehash(universe)
    with pytest.raises(principal.PrincipalDriverError, match="universe|949"):
        principal.PrincipalExecutionPlan.load(
            universe, expected_sha256=universe["sha256"]
        )

    split = copy.deepcopy(plan_wire)
    development = split["policy_author_split"]["development_task_ids"]
    heldout = split["policy_author_split"]["heldout_task_ids"]
    development[0], heldout[0] = heldout[0], development[0]
    development.sort()
    heldout.sort()
    _rehash(split["policy_author_split"])
    _rehash(split)
    with pytest.raises(principal.PrincipalDriverError, match="split"):
        principal.PrincipalExecutionPlan.load(split, expected_sha256=split["sha256"])


def test_rehashed_official_source_or_registry_substitution_is_rejected(plan_wire):
    source = copy.deepcopy(plan_wire)
    source["agentdojo_source"]["commit"] = "0" * 40
    _rehash(source)
    with pytest.raises(principal.PrincipalDriverError, match="source"):
        principal.PrincipalExecutionPlan.load(source, expected_sha256=source["sha256"])

    registry = copy.deepcopy(plan_wire)
    registry["registry"]["registry_sha256"] = "0" * 64
    _rehash(registry)
    with pytest.raises(principal.PrincipalDriverError, match="registry"):
        principal.PrincipalExecutionPlan.load(
            registry, expected_sha256=registry["sha256"]
        )


def test_cpu_eligibility_and_permit_cannot_be_upgraded_by_replace(plan):
    receipt = contract._fake_receipt(plan)
    assessment = principal.PrincipalEligibilityAssessment.assess(
        dependencies=contract._dependency_manifest().observe(),
        clean_repository=object(),
        isolation_review=object(),
        live_launcher_review=object(),
        topology=contract._topology(),
        endpoint_receipt=receipt,
    )
    with pytest.raises(principal.PrincipalDriverError, match="CPU|eligibility"):
        dataclasses.replace(
            assessment,
            principal_eligible=True,
            failed_requirements=(),
        )
    with pytest.raises(principal.PrincipalDriverError, match="CPU foundation"):
        principal.ScheduledLoopPermit(
            plan_sha256=plan.sha256,
            entry_id=plan.entries[0].entry_id,
            endpoint_receipt_sha256=receipt.sha256,
            eligibility_sha256=assessment.sha256,
            issued_monotonic_ns=1,
            sha256="0" * 64,
            _verification_token=principal._PERMIT_TOKEN,
        )


def test_journal_tables_are_insert_only_and_path_replacement_fails_closed(
    tmp_path, plan
):
    path = tmp_path / "append-only.sqlite"
    journal = principal.CreateOnlyRunJournal.create(path, plan=plan)
    entry = plan.entries[0]
    receipt = contract._fake_receipt(plan, entry)
    run_id = journal.claim_contract_test(contract._provenance(plan, receipt, entry))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        journal._connection.execute(
            "UPDATE claims SET condition_name = 'changed' WHERE run_id = ?",
            (run_id,),
        )
    held = tmp_path / "held.sqlite"
    path.rename(held)
    path.write_bytes(b"replacement")
    with pytest.raises(
        principal.PrincipalDriverError, match="identity|regular|mode"
    ):
        journal.summary()
    journal.close()


def test_handoff_rejects_a_canonically_reencoded_tampered_record(tmp_path, plan):
    journal = principal.CreateOnlyRunJournal.create(
        tmp_path / "tamper.sqlite", plan=plan
    )
    entry = plan.entries[0]
    receipt = contract._fake_receipt(plan, entry)
    run_id = journal.claim_contract_test(contract._provenance(plan, receipt, entry))
    journal.finalize_contract_test(
        run_id,
        termination=principal.TerminationCategory.ENDPOINT_ERROR,
        model_call_count=0,
        broker_record_count=0,
        raw_evidence_sha256="f" * 64,
    )
    record_path = tmp_path / "record.json"
    journal.export_raw_record(record_path, run_id=run_id)
    record = json.loads(record_path.read_bytes())
    record["condition"] = "changed"
    record_path.write_text(
        json.dumps(
            record,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    with pytest.raises(principal.PrincipalDriverError, match="digest"):
        principal.RawEvidenceHandoff.create_once(
            tmp_path / "handoff.json",
            journal=journal,
            plan_sha256=plan.sha256,
            raw_record_paths=(record_path,),
        )
    journal.close()


def test_provenance_cross_binds_manifest_and_endpoint_model_identity(plan):
    receipt = contract._fake_receipt(plan)
    mismatched = principal.PrincipalDependencyManifest.create(
        python_version="3.11.2",
        model_id="different/model",
        model_revision="4" * 40,
        model_artifact_sha256="5" * 64,
        backend="vllm",
        backend_version="9.9.9",
    )
    with pytest.raises(principal.PrincipalDriverError, match="model identities"):
        principal.PrincipalProvenanceRecord.create_contract_test(
            plan=plan,
            entry=plan.entries[0],
            endpoint_receipt=receipt,
            dependency_manifest=mismatched,
            policy_manifest_sha256="6" * 64,
            durable_binding_sha256="7" * 64,
            created_monotonic_ns=2_000_001,
        )

    provenance = contract._provenance(plan, receipt)
    with pytest.raises(principal.PrincipalDriverError, match="dependency|model"):
        dataclasses.replace(provenance, _dependency_manifest=mismatched)

    versions = {"pydantic": "2.11.4", "PyYAML": "6.0.2"}
    assessment = principal.PrincipalEligibilityAssessment.assess(
        dependencies=mismatched.observe(
            python_version="3.11.2", version_lookup=versions.__getitem__
        ),
        clean_repository=None,
        isolation_review=None,
        live_launcher_review=None,
        topology=contract._topology(),
        endpoint_receipt=receipt,
    )
    assert "manifest_endpoint_model_binding" in assessment.failed_requirements


def test_handoff_rejects_rehashed_schema_duplicates_and_unbound_exports(
    tmp_path, plan
):
    journal = principal.CreateOnlyRunJournal.create(
        tmp_path / "strict-handoff.sqlite", plan=plan
    )
    entry = plan.entries[0]
    receipt = contract._fake_receipt(plan, entry)
    run_id = journal.claim_contract_test(contract._provenance(plan, receipt, entry))
    journal.finalize_contract_test(
        run_id,
        termination=principal.TerminationCategory.ENDPOINT_ERROR,
        model_call_count=0,
        broker_record_count=0,
        raw_evidence_sha256="f" * 64,
    )
    record_path = tmp_path / "strict-record.json"
    record = journal.export_raw_record(record_path, run_id=run_id)

    with pytest.raises(principal.PrincipalDriverError, match="duplicate"):
        principal.RawEvidenceHandoff.create_once(
            tmp_path / "duplicate-handoff.json",
            journal=journal,
            plan_sha256=plan.sha256,
            raw_record_paths=(record_path, record_path),
        )

    forged = {
        "schema_version": "attacker-controlled-schema",
        "plan_sha256": plan.sha256,
        "run_id": "8" * 64,
        "principal_outcomes_present": False,
        "untrusted_payload": "independently rehashed replacement",
    }
    forged["sha256"] = principal._digest_bytes(
        b"sluice-agentdojo-principal-raw-record-v1",
        principal._canonical_json(forged),
    )
    forged_path = tmp_path / "forged.json"
    forged_path.write_bytes(principal._canonical_json(forged) + b"\n")
    forged_path.chmod(0o600)
    with pytest.raises(principal.PrincipalDriverError, match="schema fields"):
        principal.RawEvidenceHandoff.create_once(
            tmp_path / "forged-handoff.json",
            journal=journal,
            plan_sha256=plan.sha256,
            raw_record_paths=(forged_path,),
        )

    rehashed = copy.deepcopy(record)
    rehashed["condition"] = "changed"
    rehashed.pop("sha256")
    rehashed["sha256"] = principal._digest_bytes(
        b"sluice-agentdojo-principal-raw-record-v1",
        principal._canonical_json(rehashed),
    )
    rehashed_path = tmp_path / "independently-rehashed.json"
    rehashed_path.write_bytes(principal._canonical_json(rehashed) + b"\n")
    rehashed_path.chmod(0o600)
    with pytest.raises(principal.PrincipalDriverError, match="journal|export"):
        principal.RawEvidenceHandoff.create_once(
            tmp_path / "rehashed-handoff.json",
            journal=journal,
            plan_sha256=plan.sha256,
            raw_record_paths=(rehashed_path,),
        )
    journal.close()


def test_create_once_rejects_parent_swap_before_basename_open(
    tmp_path, monkeypatch
):
    intended = tmp_path / "evidence"
    intended.mkdir()
    held = tmp_path / "held-original"
    target = intended / "record.json"
    real_resolve = Path.resolve
    swapped = False

    def resolve_and_swap(self, *args, **kwargs):
        nonlocal swapped
        resolved = real_resolve(self, *args, **kwargs)
        if self == intended and not swapped:
            intended.rename(held)
            intended.mkdir()
            swapped = True
        return resolved

    monkeypatch.setattr(Path, "resolve", resolve_and_swap)
    with pytest.raises(principal.PrincipalDriverError, match="parent|identity"):
        principal._write_json_create_once(target, {"probe": "parent-swap"})
    assert not target.exists()
    assert not (held / target.name).exists()


def test_create_once_rechecks_mode_link_count_and_leaves_fault_artifact(
    tmp_path, monkeypatch
):
    target = tmp_path / "record.json"
    alias = tmp_path / "record-hardlink.json"
    real_write_all = principal._write_all

    def write_then_change_identity(descriptor, payload):
        real_write_all(descriptor, payload)
        os.chmod(target, 0o644)
        os.link(target, alias)

    monkeypatch.setattr(principal, "_write_all", write_then_change_identity)
    with pytest.raises(principal.PrincipalDriverError, match="mode|link"):
        principal._write_json_create_once(target, {"probe": "link-and-mode"})
    observed = os.stat(target, follow_symlinks=False)
    assert stat.S_IMODE(observed.st_mode) == 0o644
    assert observed.st_nlink == 2
    assert alias.exists()
    assert hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(
        alias.read_bytes()
    ).digest()
