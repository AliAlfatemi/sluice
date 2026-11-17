from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform

import pytest

from sluice_v2.durable_service import PeerIdentity
from sluice_v2.evaluation import agentdojo_live as live
from sluice_v2.evaluation import agentdojo_principal_construction as construction
from sluice_v2.evaluation import agentdojo_principal_driver as principal
from sluice_v2.tests import test_v21_agentdojo_live_pipeline as v21


REPOSITORY = Path(__file__).resolve().parents[4]
CHECKOUT = REPOSITORY / "external" / "agentdojo-v0.1.35"


@pytest.fixture(scope="module")
def source_attestation() -> live.OfficialSourceAttestation:
    return live.OfficialSourceAttestation.authenticate(CHECKOUT)


@pytest.fixture(scope="module")
def registry_attestation(source_attestation):
    return v21.registry_attestation.__wrapped__(source_attestation)


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


def _peer(pid: int) -> PeerIdentity:
    return PeerIdentity(pid=pid, uid=os.getuid(), gid=os.getgid())


def _topology() -> principal.ProcessTopologyAttestation:
    return principal.ProcessTopologyAttestation.for_cpu_test(
        monitor=_peer(41001),
        broker=_peer(41002),
        model_driver=_peer(41003),
        session_nonce="cpu-contract-session-20260821",
    )


def _dependency_manifest() -> principal.PrincipalDependencyManifest:
    return principal.PrincipalDependencyManifest.create(
        python_version="3.11.2",
        model_id="example/model",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="0.6.4.post1",
    )


def _fake_receipt(plan, entry=None, *, topology=None):
    if entry is None:
        entry = plan.entries[0]
    if topology is None:
        topology = _topology()
    expectation = live.EndpointExpectation(
        endpoint_url="http://127.0.0.1:8123/v1",
        model_id="example/model",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="0.6.4.post1",
    )

    def probe(endpoint_url):
        return live.EndpointObservation(
            endpoint_url=endpoint_url,
            model_id=expectation.model_id,
            model_revision=expectation.model_revision,
            model_artifact_sha256=expectation.model_artifact_sha256,
            backend=expectation.backend,
            backend_version=expectation.backend_version,
        )

    return principal.EndpointProbeReceipt.for_cpu_test(
        plan=plan,
        entry=entry,
        expectation=expectation,
        probe=probe,
        topology=topology,
        monotonic_ns=1_000_000,
    )


def _provenance(plan, receipt, entry=None):
    if entry is None:
        entry = plan.entries[0]
    return principal.PrincipalProvenanceRecord.create_contract_test(
        plan=plan,
        entry=entry,
        endpoint_receipt=receipt,
        dependency_manifest=_dependency_manifest(),
        policy_manifest_sha256="c" * 64,
        durable_binding_sha256="d" * 64,
        created_monotonic_ns=1_000_001,
    )


def test_exact_authenticated_universe_has_all_attacked_and_benign_units(plan):
    assert plan.attacked_pair_count == 949
    assert plan.benign_task_count == 97
    assert len(plan.scenarios) == 1_046
    attacked = [item for item in plan.scenarios if item.stratum == "attacked"]
    benign = [item for item in plan.scenarios if item.stratum == "benign"]
    assert len(attacked) == 949
    assert len(benign) == 97
    assert len({item.pair_id for item in attacked}) == 949
    assert len({item.episode_id for item in plan.scenarios}) == 1_046
    assert all(item.injection_task_id is None for item in benign)
    assert all(item.injection_task_id is not None for item in attacked)
    assert plan.suite_pair_counts == {
        "banking": 144,
        "slack": 105,
        "travel": 140,
        "workspace": 560,
    }
    assert plan.suite_task_counts == {
        "banking": (16, 9),
        "slack": (21, 5),
        "travel": (20, 7),
        "workspace": (40, 14),
    }
    assert all(len(item.pair_id) == 64 for item in attacked)
    assert all(item.pair_id is None for item in benign)


def test_policy_author_split_is_frozen_complete_and_excludes_development_from_scoring(plan):
    split = plan.policy_author_split
    assert len(split.development_task_ids) == 24
    assert len(split.heldout_task_ids) == 73
    assert set(split.development_task_ids).isdisjoint(split.heldout_task_ids)
    assert set(split.development_task_ids) | set(split.heldout_task_ids) == {
        f"{suite}:{user_task_id}"
        for suite, (users, _injections) in plan.suite_task_counts.items()
        for user_task_id in (f"user_task_{index}" for index in range(users))
    }
    assert split.sha256 == plan.policy_author_split_sha256
    assert all(
        item.policy_partition in {"development", "heldout"}
        for item in plan.scenarios
    )
    assert all(
        item.principal_scoring_eligible is (item.policy_partition == "heldout")
        for item in plan.scenarios
    )


def test_plan_is_fixed_pairwise_counterbalanced_and_complete(plan):
    assert plan.conditions == (
        principal.PrincipalCondition.UNDEFENDED.value,
        principal.PrincipalCondition.OFFICIAL_TOOL_FILTER.value,
        principal.PrincipalCondition.SLUICE_NONORACLE.value,
    )
    assert plan.seeds == (104729, 130363, 155921, 196613, 262147)
    assert plan.repetitions_per_seed == 1
    assert len(plan.schedule_instances) == 10
    assert len(plan.entries) == 20_920
    assert len({entry.entry_id for entry in plan.entries}) == len(plan.entries)
    for instance in plan.schedule_instances:
        assert len(instance.entries) == 2_092
        first = [item.condition for item in instance.entries if item.order == 1]
        left, right = instance.conditions
        assert abs(first.count(left) - first.count(right)) <= 1
        assert {item.order for item in instance.entries} == {1, 2}
        attacked = [item for item in instance.entries if item.stratum == "attacked"]
        benign = [item for item in instance.entries if item.stratum == "benign"]
        assert len(attacked) == 1_898
        assert len(benign) == 194
        assert len({item.pair_id for item in attacked}) == 949
        assert {item.injection_task_id for item in benign} == {None}


def test_plan_construction_is_deterministic(source_attestation, registry_attestation, plan_wire):
    second = construction.build_principal_plan_wire(
        source=source_attestation,
        registry=registry_attestation,
    )
    assert second == plan_wire
    assert second["sha256"] == plan_wire["sha256"]


def test_execution_loader_consumes_only_data_projection(
    plan_wire, registry_attestation, monkeypatch
):
    def poison(*_args, **_kwargs):
        raise AssertionError("execution loader traversed the official registry")

    monkeypatch.setattr(type(registry_attestation), "revalidate", poison)
    loaded = principal.PrincipalExecutionPlan.load(
        copy.deepcopy(plan_wire), expected_sha256=plan_wire["sha256"]
    )
    assert loaded.attacked_pair_count == 949
    assert loaded.benign_task_count == 97


def test_plan_loader_rejects_hash_pair_and_schedule_mutation(plan_wire):
    with pytest.raises(principal.PrincipalDriverError, match="expected digest"):
        principal.PrincipalExecutionPlan.load(
            copy.deepcopy(plan_wire), expected_sha256="0" * 64
        )

    missing = copy.deepcopy(plan_wire)
    missing["universe"]["attacked_pairs"].pop()
    missing["sha256"] = principal.principal_plan_sha256(missing)
    with pytest.raises(principal.PrincipalDriverError, match="949|universe"):
        principal.PrincipalExecutionPlan.load(
            missing, expected_sha256=missing["sha256"]
        )

    reordered = copy.deepcopy(plan_wire)
    reordered["schedule_instances"][0]["schedule"]["entries"][0]["condition"] = (
        principal.PrincipalCondition.SLUICE_NONORACLE.value
    )
    reordered["sha256"] = principal.principal_plan_sha256(reordered)
    with pytest.raises(principal.PrincipalDriverError, match="schedule|condition|counterbal"):
        principal.PrincipalExecutionPlan.load(
            reordered, expected_sha256=reordered["sha256"]
        )


def test_official_tool_filter_baseline_is_bound_to_exact_pinned_source(plan):
    baseline = plan.official_tool_filter
    assert baseline.condition == principal.PrincipalCondition.OFFICIAL_TOOL_FILTER.value
    assert baseline.config_value == "tool_filter"
    assert baseline.pipeline_source_sha256 == (
        "2b9b82b98cef3662733a8207dfed9e4386c41fb74e69531a6f0a36207f9695e9"
    )
    assert baseline.llm_source_sha256 == (
        "7f91178cb0bb354b89427650d7b8725d6aff8fe18d43fc85bf4b4fdc1ddf9574"
    )
    assert baseline.pipeline_element_qualname == (
        "agentdojo.agent_pipeline.llms.openai_llm.OpenAILLMToolFilter"
    )
    assert baseline.requires_official_openai_adapter is True


def test_dependency_manifest_fails_closed_in_current_cpu_environment(monkeypatch):
    manifest = _dependency_manifest()
    observed = manifest.observe()
    assert observed.python_version == platform.python_version()
    assert observed.pydantic_version == importlib.metadata.version("pydantic")
    assert observed.pyyaml_version == importlib.metadata.version("PyYAML")
    assert observed.principal_eligible is False
    assert "pydantic" in observed.mismatch_fields
    assert "pyyaml" in observed.mismatch_fields

    versions = {"pydantic": "2.11.4", "PyYAML": "6.0.2"}
    exact = manifest.observe(
        python_version="3.11.2", version_lookup=versions.__getitem__
    )
    assert exact.principal_eligible is True
    assert exact.mismatch_fields == ()
    assert manifest.model_id == "example/model"
    assert manifest.model_revision == "a" * 40
    assert manifest.model_artifact_sha256 == "b" * 64
    assert manifest.backend == "vllm"
    assert manifest.backend_version == "0.6.4.post1"


def test_dependency_manifest_requires_exact_principal_pins_and_model_identity():
    manifest = _dependency_manifest()
    assert manifest.pydantic_version == "2.11.4"
    assert manifest.pyyaml_version == "6.0.2"
    with pytest.raises(principal.PrincipalDriverError, match="revision"):
        principal.PrincipalDependencyManifest.create(
            python_version="3.11.2",
            model_id="example/model",
            model_revision="main",
            model_artifact_sha256="b" * 64,
            backend="vllm",
            backend_version="0.6.4.post1",
        )


def test_process_topology_requires_three_distinct_roles_and_redacts_pids():
    topology = _topology()
    assert topology.principal_eligible is False
    assert topology.monitor.pid == 41001
    assert topology.broker.pid == 41002
    assert topology.model_driver.pid == 41003
    public = topology.to_public_wire()
    assert "41001" not in repr(public)
    assert "41002" not in repr(public)
    assert "41003" not in repr(public)
    assert public["binding_sha256"] == topology.binding_sha256
    with pytest.raises(principal.PrincipalDriverError, match="distinct"):
        principal.ProcessTopologyAttestation.for_cpu_test(
            monitor=_peer(41001),
            broker=_peer(41001),
            model_driver=_peer(41003),
            session_nonce="cpu-contract-session-20260821",
        )


def test_fake_endpoint_probe_is_exact_entry_bound_and_never_principal(plan):
    receipt = _fake_receipt(plan)
    assert receipt.entry_id == plan.entries[0].entry_id
    assert receipt.plan_sha256 == plan.sha256
    assert receipt.endpoint.model_id == "example/model"
    assert receipt.endpoint.model_revision == "a" * 40
    assert receipt.principal_eligible is False
    assert receipt.probe_mode is principal.EndpointProbeMode.CPU_FAKE
    assert "127.0.0.1" not in repr(receipt.to_public_wire())

    different = plan.entries[1]
    with pytest.raises(principal.PrincipalDriverError, match="entry"):
        dataclasses.replace(receipt, entry_id=different.entry_id)


def test_fake_endpoint_probe_reprobes_for_every_exact_scheduled_entry(plan):
    calls = []
    topology = _topology()
    expectation = live.EndpointExpectation(
        endpoint_url="http://127.0.0.1:8123/v1",
        model_id="example/model",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="0.6.4.post1",
    )

    def probe(endpoint_url):
        calls.append(endpoint_url)
        return live.EndpointObservation(
            endpoint_url=endpoint_url,
            model_id=expectation.model_id,
            model_revision=expectation.model_revision,
            model_artifact_sha256=expectation.model_artifact_sha256,
            backend=expectation.backend,
            backend_version=expectation.backend_version,
        )

    receipts = [
        principal.EndpointProbeReceipt.for_cpu_test(
            plan=plan,
            entry=entry,
            expectation=expectation,
            probe=probe,
            topology=topology,
            monotonic_ns=1_000_000 + index,
        )
        for index, entry in enumerate(plan.entries[:2])
    ]
    assert len(calls) == 2
    assert receipts[0].entry_id != receipts[1].entry_id
    assert receipts[0].sha256 != receipts[1].sha256


def test_principal_eligibility_stays_false_without_all_reviewed_live_prerequisites(plan):
    receipt = _fake_receipt(plan)
    dependencies = _dependency_manifest().observe()
    eligibility = principal.PrincipalEligibilityAssessment.assess(
        dependencies=dependencies,
        clean_repository=None,
        isolation_review=None,
        live_launcher_review=None,
        topology=_topology(),
        endpoint_receipt=receipt,
    )
    assert eligibility.principal_eligible is False
    assert {
        "exact_dependencies",
        "clean_commit",
        "reviewed_isolation",
        "reviewed_live_launcher",
        "kernel_peer_bindings",
        "real_endpoint_probe",
    }.issubset(set(eligibility.failed_requirements))
    with pytest.raises(principal.PrincipalDriverError, match="ineligible"):
        principal.ScheduledLoopPermit.issue(
            plan=plan,
            entry=plan.entries[0],
            endpoint_receipt=receipt,
            eligibility=eligibility,
            issued_monotonic_ns=1_000_002,
        )


def test_provenance_has_one_scalar_condition_and_is_exactly_entry_bound(plan):
    receipt = _fake_receipt(plan)
    provenance = _provenance(plan, receipt)
    assert provenance.entry_id == plan.entries[0].entry_id
    assert provenance.condition == plan.entries[0].condition
    assert type(provenance.condition) is str
    assert provenance.endpoint_attestation_sha256 == receipt.endpoint.sha256
    assert provenance.principal_eligible is False
    assert len(provenance.sha256) == 64
    with pytest.raises(principal.PrincipalDriverError, match="provenance|condition|entry"):
        dataclasses.replace(provenance, condition=plan.entries[1].condition)

    benign_entry = next(item for item in plan.entries if item.stratum == "benign")
    benign_receipt = _fake_receipt(plan, benign_entry)
    benign_provenance = _provenance(plan, benign_receipt, benign_entry)
    assert benign_provenance.injection_task_id is None
    assert benign_provenance.stratum == "benign"


def test_create_only_journal_accounts_timeout_failure_and_unfinalized_denominators(tmp_path, plan):
    path = tmp_path / "principal-contract.sqlite"
    journal = principal.CreateOnlyRunJournal.create(path, plan=plan)
    with pytest.raises(FileExistsError):
        principal.CreateOnlyRunJournal.create(path, plan=plan)

    first = plan.entries[0]
    first_receipt = _fake_receipt(plan, first)
    first_run = journal.claim_contract_test(
        _provenance(plan, first_receipt, first)
    )
    journal.finalize_contract_test(
        first_run,
        termination=principal.TerminationCategory.TIMEOUT,
        model_call_count=0,
        broker_record_count=0,
        raw_evidence_sha256="e" * 64,
    )

    second = plan.entries[1]
    second_receipt = _fake_receipt(plan, second)
    second_run = journal.claim_contract_test(
        _provenance(plan, second_receipt, second)
    )
    assert second_run != first_run
    with pytest.raises(principal.PrincipalDriverError, match="already claimed"):
        journal.claim_contract_test(_provenance(plan, second_receipt, second))

    summary = journal.summary()
    assert summary.planned == 20_920
    assert summary.attacked_planned == 18_980
    assert summary.benign_planned == 1_940
    assert summary.claimed == 2
    assert summary.finalized == 1
    assert summary.unfinalized == 1
    assert summary.pending == 20_918
    assert summary.termination_counts[principal.TerminationCategory.TIMEOUT.value] == 1
    with pytest.raises(principal.PrincipalDriverError, match="incomplete"):
        journal.assert_complete()
    journal.close()


def test_raw_evidence_and_offline_handoff_are_redacted_and_create_once(tmp_path, plan):
    journal = principal.CreateOnlyRunJournal.create(
        tmp_path / "journal.sqlite", plan=plan
    )
    entry = plan.entries[0]
    receipt = _fake_receipt(plan, entry)
    run_id = journal.claim_contract_test(_provenance(plan, receipt, entry))
    journal.finalize_contract_test(
        run_id,
        termination=principal.TerminationCategory.ENDPOINT_ERROR,
        model_call_count=0,
        broker_record_count=0,
        raw_evidence_sha256="f" * 64,
    )
    record_path = tmp_path / "raw" / "record.json"
    record = journal.export_raw_record(record_path, run_id=run_id)
    assert record["entry_id"] == entry.entry_id
    assert record["condition"] == entry.condition
    assert record["termination"] == principal.TerminationCategory.ENDPOINT_ERROR.value
    serialized = json.dumps(record, sort_keys=True)
    assert "127.0.0.1" not in serialized
    assert "41001" not in serialized
    assert "41002" not in serialized
    assert "41003" not in serialized
    with pytest.raises(FileExistsError):
        journal.export_raw_record(record_path, run_id=run_id)

    handoff_path = tmp_path / "raw" / "handoff.json"
    handoff = principal.RawEvidenceHandoff.create_once(
        handoff_path,
        journal=journal,
        plan_sha256=plan.sha256,
        raw_record_paths=(record_path,),
    )
    assert handoff["record_count"] == 1
    assert handoff["principal_outcomes_present"] is False
    assert handoff["record_sha256"][0] == hashlib.sha256(record_path.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        principal.RawEvidenceHandoff.create_once(
            handoff_path,
            journal=journal,
            plan_sha256=plan.sha256,
            raw_record_paths=(record_path,),
        )
    journal.close()


def test_execution_source_has_no_answer_bearing_or_official_task_interfaces():
    path = Path(principal.__file__).resolve()
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = (
        "ground" + "_truth",
        "score" + "r",
        "injection" + "_answer",
        "task" + "_answer",
    )
    lowered = source.lower()
    assert all(name not in lowered for name in forbidden)
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not any("task_suite" in module for module in imports)
    assert not any("principal_construction" in module for module in imports)
    schedule_methods = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and "schedule" in node.name
    }
    assert schedule_methods
    for node in schedule_methods.values():
        text = ast.unparse(node)
        assert ".suites" not in text
        assert ".user_tasks" not in text
        assert ".injection_tasks" not in text
