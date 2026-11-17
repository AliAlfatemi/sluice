from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import inspect
import json
from pathlib import Path
from types import MappingProxyType

import pytest

import sluice_v2.evaluation.agentleak_principal_driver as principal
from sluice_v2.evaluation.agentleak import ALL_CHANNELS, ObserverChannel
from sluice_v2.evaluation.agentleak_fullstack import PolicyAuthorInput, UtilityOutcome


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
BENCHMARK_ROOT = ARTIFACT_ROOT / "benchmarks" / "agentleak"
SCHEDULE_PATH = BENCHMARK_ROOT / "public_schedule_full_1000_v1.json"
CODEBOOK_ROOT = BENCHMARK_ROOT / "codebooks_full_1000_v1"
CORPUS_PATH = BENCHMARK_ROOT / "scenarios_full_1000.jsonl"
AGENTLEAK_SOURCE_ROOT = REPOSITORY_ROOT / "external" / "agentleak"
MODULE_PATH = ARTIFACT_ROOT / "sluice_v2" / "evaluation" / "agentleak_principal_driver.py"


class AccessPoisonMapping(dict):
    def __init__(self, permitted, forbidden=()):
        super().__init__(permitted)
        self.forbidden = frozenset(forbidden)
        self.accessed: list[str] = []

    def __getitem__(self, key):
        self.accessed.append(key)
        if key in self.forbidden:
            raise AssertionError(f"forbidden execution-plan access: {key}")
        return super().__getitem__(key)

    def __iter__(self):
        raise AssertionError("execution-plan projection must not enumerate its source")

    def items(self):
        raise AssertionError("execution-plan projection must not enumerate its source")

    def keys(self):
        raise AssertionError("execution-plan projection must not enumerate its source")

    def values(self):
        raise AssertionError("execution-plan projection must not enumerate its source")


@pytest.fixture(scope="module")
def plan():
    return principal.build_execution_plan(public_schedule_path=SCHEDULE_PATH)


@pytest.fixture(scope="module")
def prepared(plan):
    block = plan.blocks[0]
    arm = next(
        candidate
        for candidate in block.arms
        if candidate.condition is principal.PrincipalCondition.SLUICE_COMPLETE
    )
    return principal.prepare_sluice_cpu_episode(
        plan=plan,
        arm=arm,
        public_schedule_path=SCHEDULE_PATH,
        codebook_root=CODEBOOK_ROOT,
        corpus_path=CORPUS_PATH,
    )


@pytest.fixture(scope="module")
def prepared_nonempty(plan):
    block = next(
        candidate
        for candidate in plan.blocks
        if candidate.scenario_id == "agentleak_hea_00001"
        and candidate.seed == principal.FROZEN_SEEDS[0]
    )
    arm = next(
        candidate
        for candidate in block.arms
        if candidate.condition is principal.PrincipalCondition.SLUICE_COMPLETE
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
        delivered = session.release(
            request_id=f"release-{index:02d}",
            route_name=route.route_name,
            channel=route.channel,
        )
        assert delivered.channel is route.channel
        assert delivered.route_name == route.route_name
        assert delivered.content
    session.close(request_id="close-00")
    session.close(request_id="close-01")
    return session.seal(require_all_channels=True)


def test_cpu_foundation_eligibility_is_structurally_false() -> None:
    eligibility = principal.CPU_FOUNDATION_ELIGIBILITY
    assert eligibility.execution_mode == "cpu_fake_backend_foundation_only"
    assert eligibility.cpu_foundation is True
    assert eligibility.model_revision_eligible is False
    assert eligibility.dependency_eligible is False
    assert eligibility.endpoint_eligible is False
    assert eligibility.topology_eligible is False
    assert eligibility.clean_commit_eligible is False
    assert eligibility.isolated_gpu_eligible is False
    assert eligibility.principal_execution_eligible is False
    assert eligibility.effectiveness_evidence is False
    assert eligibility.utility_evidence is False
    with pytest.raises(principal.PrincipalDriverError):
        replace(eligibility, principal_execution_eligible=True)


def test_execution_plan_is_exact_complete_deterministic_and_balanced(plan) -> None:
    assert plan.schema_version == "sluice-agentleak-principal-cpu-plan-v1"
    assert plan.execution_mode == "cpu_fake_backend_foundation_only"
    assert plan.public_schedule_sha256 == principal.PINNED_PUBLIC_SCHEDULE_SHA256
    assert plan.scenario_count == 1_000
    assert plan.seeds == (104729, 130363, 155921, 196613, 262147)
    assert tuple(condition.value for condition in principal.PRINCIPAL_CONDITIONS) == (
        "UNDEFENDED",
        "PROMPT_ONLY",
        "OUTPUT_ONLY",
        "STATIC_ACCESS_CONTROL",
        "SLUICE_COMPLETE",
        "NO_CUMULATIVE_BUDGET",
        "NO_INTERNAL_CHANNEL_MEDIATION",
        "NO_ROUTE_METADATA_ENFORCEMENT",
    )
    assert len(plan.blocks) == 5_000
    assert plan.scheduled_attempt_count == 40_000
    assert len({block.block_id for block in plan.blocks}) == 5_000
    assert all(len(block.arms) == 8 for block in plan.blocks)
    assert all(
        {arm.condition for arm in block.arms} == set(principal.PRINCIPAL_CONDITIONS)
        for block in plan.blocks
    )
    assert all(tuple(arm.order_index for arm in block.arms) == tuple(range(8)) for block in plan.blocks)
    assert plan.scheduled_by_condition == MappingProxyType(
        {condition: 5_000 for condition in principal.PRINCIPAL_CONDITIONS}
    )

    position_counts = {
        condition: [0] * len(principal.PRINCIPAL_CONDITIONS)
        for condition in principal.PRINCIPAL_CONDITIONS
    }
    class_counts = [0] * 16
    for block in plan.blocks:
        class_counts[block.counterbalance_class] += 1
        for arm in block.arms:
            position_counts[arm.condition][arm.order_index] += 1
    assert max(class_counts) - min(class_counts) <= 1
    assert all(max(counts) - min(counts) <= 2 for counts in position_counts.values())

    rebuilt = principal.build_execution_plan(public_schedule_path=SCHEDULE_PATH)
    assert rebuilt.plan_sha256 == plan.plan_sha256
    assert rebuilt.blocks == plan.blocks
    assert rebuilt.to_public_record() == plan.to_public_record()


def test_plan_loader_fails_closed_on_schedule_drift_and_noncanonical_bytes(
    tmp_path: Path,
) -> None:
    drifted = tmp_path / "drifted.json"
    drifted.write_bytes(SCHEDULE_PATH.read_bytes() + b"\n")
    with pytest.raises(principal.PrincipalDriverError, match="schedule SHA-256"):
        principal.build_execution_plan(public_schedule_path=drifted)

    noncanonical = tmp_path / "noncanonical.json"
    body = json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))
    noncanonical.write_text(json.dumps(body, indent=2), encoding="utf-8")
    with pytest.raises(principal.PrincipalDriverError, match="schedule SHA-256"):
        principal.build_execution_plan(public_schedule_path=noncanonical)


def test_data_only_plan_projection_never_touches_protected_or_outcome_data() -> None:
    source = AccessPoisonMapping(
        {
            "scenario_id": "agentleak-poison-0001",
            "template_code": "template-0000000000000001",
        },
        forbidden={
            "objective",
            "agents",
            "tools",
            "allowed_field_names",
            "private_vault",
            "attack",
            "evaluation",
            "target_channels",
            "canaries",
            "condition",
            "detector",
            "outcome",
        },
    )
    projected = principal.project_plan_row(source)
    assert projected == (
        "agentleak-poison-0001",
        "template-0000000000000001",
    )
    assert source.accessed == ["scenario_id", "template_code"]

    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    projector = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "project_plan_row"
    )
    observed = {
        node.value
        for node in ast.walk(projector)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not (
        observed
        & {
            "private_vault",
            "attack",
            "evaluation",
            "target_channels",
            "canaries",
            "condition",
            "detector",
            "outcome",
        }
    )


def test_public_plan_is_frozen_before_exact_committed_launch_seam(
    plan, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = plan.blocks[0]
    arm = next(
        candidate
        for candidate in block.arms
        if candidate.condition is principal.PrincipalCondition.SLUICE_COMPLETE
    )
    observed: list[tuple[bool, str]] = []

    def guarded_launch(**kwargs):
        observed.append((plan.frozen, plan.plan_sha256))
        raise RuntimeError("launch sentinel")

    monkeypatch.setattr(principal, "launch_pinned_scenario", guarded_launch)
    with pytest.raises(RuntimeError, match="launch sentinel"):
        principal.prepare_sluice_cpu_episode(
            plan=plan,
            arm=arm,
            public_schedule_path=SCHEDULE_PATH,
            codebook_root=CODEBOOK_ROOT,
            corpus_path=CORPUS_PATH,
        )
    assert observed == [(True, plan.plan_sha256)]


def test_prepared_episode_binds_plan_launch_codebooks_and_horizon(prepared, plan) -> None:
    assert prepared.plan_sha256 == plan.plan_sha256
    assert prepared.arm.condition is principal.PrincipalCondition.SLUICE_COMPLETE
    assert prepared.launched.attestation.scenario_id == prepared.arm.scenario_id
    assert prepared.launched.attestation.template_code == prepared.arm.template_code
    assert prepared.launched.attestation.route_count == 7
    binding = prepared.launched.codebooks.binding
    assert binding.horizon == 16
    assert binding.lifetime_budget_units == 16 * binding.event_charge_units
    assert tuple(route.channel for route in binding.routes) == ALL_CHANNELS
    assert all(route.support_cardinality == len(route.ordered_value_codes) for route in binding.routes)


def test_mixed_chronology_exactly_decodes_c1_c7_and_captures_close_stutter(
    prepared, chronology
) -> None:
    validated = principal.validate_chronology(chronology=chronology, prepared=prepared)
    assert validated.step_count == principal.CHRONOLOGY_HMAX
    assert validated.charged_release_count == 7
    assert validated.delivery_count == 7
    assert validated.channels == ALL_CHANNELS
    assert validated.cached_domain_closed_count == 1
    assert validated.total_reserved_units == (
        7 * prepared.launched.codebooks.binding.event_charge_units
    )
    assert validated.total_reserved_units <= prepared.launched.codebooks.binding.lifetime_budget_units
    assert chronology.release_horizon == 16
    assert chronology.chronology_hmax == principal.CHRONOLOGY_HMAX
    assert chronology.principal_outcome_count == 0
    public = json.dumps(chronology.to_public_record(), sort_keys=True)
    for forbidden in ("content", "payload", "value_code", "response_sha256"):
        assert forbidden not in public


def _mutate_wire(wire: dict, mutation: str) -> dict:
    candidate = deepcopy(wire)
    steps = candidate["steps"]
    if mutation == "unknown_kind":
        steps[0]["step_kind"] = "UNKNOWN"
    elif mutation == "malformed_response":
        response = next(step for step in steps if step["step_kind"] == "MONITOR_RESPONSE" and step["status"] == "RELEASED")
        body = json.loads(response["content"])
        body["secret_extra"] = "x"
        response["content"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
        principal.rebind_step_content_metadata(response)
    elif mutation == "multiple_response":
        index = next(index for index, step in enumerate(steps) if step["step_kind"] == "MONITOR_RESPONSE")
        steps.insert(index + 1, deepcopy(steps[index]))
        for sequence, step in enumerate(steps, 1):
            step["sequence"] = sequence
    elif mutation == "out_of_support":
        response = next(step for step in steps if step["step_kind"] == "MONITOR_RESPONSE" and step["status"] == "RELEASED")
        body = json.loads(response["content"])
        body["value_code"] = 10**9
        response["content"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
        principal.rebind_step_content_metadata(response)
    elif mutation == "replay_request":
        requests = [step for step in steps if step["step_kind"] == "CONTROL_REQUEST" and step["status"] == "RELEASE"]
        body = json.loads(requests[1]["content"])
        body["request_id"] = json.loads(requests[0]["content"])["request_id"]
        requests[1]["content"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
        principal.rebind_step_content_metadata(requests[1])
    elif mutation == "missing_delivery":
        index = next(index for index, step in enumerate(steps) if step["step_kind"] == "CHANNEL_DELIVERY")
        steps.pop(index)
        for sequence, step in enumerate(steps, 1):
            step["sequence"] = sequence
    elif mutation == "reordered":
        requests = [index for index, step in enumerate(steps) if step["step_kind"] == "CONTROL_REQUEST"]
        first = requests[0]
        steps[first], steps[first + 1] = steps[first + 1], steps[first]
    else:
        raise AssertionError(mutation)
    candidate["chronology_sha256"] = principal.chronology_wire_sha256(candidate)
    return candidate


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown_kind",
        "malformed_response",
        "multiple_response",
        "out_of_support",
        "replay_request",
        "missing_delivery",
        "reordered",
    ),
)
def test_chronology_validation_fails_closed_on_response_and_order_attacks(
    prepared, chronology, mutation: str
) -> None:
    wire = _mutate_wire(chronology.to_wire(), mutation)
    with pytest.raises(principal.PrincipalDriverError):
        principal.validate_chronology_wire(wire=wire, prepared=prepared)


def test_chronology_rejects_unknown_route_cross_channel_replay_and_budget_exhaustion(
    prepared,
) -> None:
    route = prepared.launched.policy_input.route_codebooks[0]
    session = principal.FakeSluiceChronologySession(prepared)
    with pytest.raises(principal.PrincipalDriverError, match="unknown route"):
        session.release(
            request_id="unknown-route",
            route_name="not-a-route",
            channel=route.channel,
        )
    with pytest.raises(principal.PrincipalDriverError, match="channel"):
        session.release(
            request_id="cross-channel",
            route_name=route.route_name,
            channel=ObserverChannel.C2_INTER_AGENT,
        )
    session.release(
        request_id="first-valid",
        route_name=route.route_name,
        channel=route.channel,
    )
    with pytest.raises(principal.PrincipalDriverError, match="replay"):
        session.release(
            request_id="first-valid",
            route_name=route.route_name,
            channel=route.channel,
        )
    for index in range(1, 16):
        session.release(
            request_id=f"bounded-{index:02d}",
            route_name=route.route_name,
            channel=route.channel,
        )
    with pytest.raises(principal.PrincipalDriverError, match="H=16|budget"):
        session.release(
            request_id="seventeenth",
            route_name=route.route_name,
            channel=route.channel,
        )


def test_close_is_terminal_cached_and_all_post_close_release_fails(prepared) -> None:
    session = principal.FakeSluiceChronologySession(prepared)
    route = prepared.launched.policy_input.route_codebooks[0]
    session.release(request_id="release-before-close", route_name=route.route_name, channel=route.channel)
    first = session.close(request_id="close-first")
    cached = session.close(request_id="close-cached")
    assert first.status == "DOMAIN_CLOSED"
    assert first.cached is False
    assert cached.status == "DOMAIN_CLOSED"
    assert cached.cached is True
    with pytest.raises(principal.PrincipalDriverError, match="closed"):
        session.release(request_id="release-after-close", route_name=route.route_name, channel=route.channel)


def test_create_only_raw_journal_and_redacted_complete_denominators(
    tmp_path: Path, plan, prepared, chronology
) -> None:
    block = plan.blocks[0]
    store = principal.RawRunJournalStore(tmp_path / "restricted-journal")
    validated = []
    for arm in block.arms:
        record = principal.build_cpu_attempt_record(
            plan=plan,
            arm=arm,
            status=principal.AttemptStatus.CPU_FAKE_COMPLETED,
            chronology=(
                chronology
                if arm.condition is principal.PrincipalCondition.SLUICE_COMPLETE
                else None
            ),
        )
        receipt = store.append(record=record, prepared=(prepared if record.chronology else None))
        validated.append(
            principal.validate_raw_run_record(
                receipt=receipt,
                plan=plan,
                prepared=(prepared if record.chronology else None),
            )
        )
        with pytest.raises(principal.PrincipalDriverError, match="already exists"):
            store.append(record=record, prepared=(prepared if record.chronology else None))
    handoff = principal.build_redacted_offline_handoff(plan=plan, records=tuple(validated))
    assert handoff["execution_mode"] == "cpu_fake_backend_foundation_only"
    assert handoff["principal_outcome_count"] == 0
    assert handoff["scheduled_attempt_count"] == 40_000
    assert handoff["fake_attempted_count"] == 8
    for condition in principal.PRINCIPAL_CONDITIONS:
        denominator = handoff["denominators_by_condition"][condition.value]
        assert denominator == {
            "scheduled": 5_000,
            "cpu_fake_attempted": 1,
            "cpu_fake_completed": 1,
            "timeout": 0,
            "execution_error": 0,
            "trace_invalid": 0,
            "not_cpu_fake_attempted": 4_999,
        }
    rendered = json.dumps(handoff, sort_keys=True).lower()
    for forbidden in (
        "scenario_id",
        "attempt_id",
        "response",
        "payload",
        "value_code",
        "private_vault",
        "attack",
        "canary",
        "detector_outcome",
    ):
        assert forbidden not in rendered
    output = tmp_path / "offline-handoff.json"
    digest = principal.write_redacted_handoff_create_only(path=output, handoff=handoff)
    assert digest == principal.sha256_file(output)
    with pytest.raises(principal.PrincipalDriverError, match="already exists"):
        principal.write_redacted_handoff_create_only(path=output, handoff=handoff)


def test_timeout_error_trace_invalid_denominators_are_retained(
    tmp_path: Path, plan
) -> None:
    arms = plan.blocks[0].arms[:4]
    statuses = (
        principal.AttemptStatus.CPU_FAKE_COMPLETED,
        principal.AttemptStatus.TIMEOUT,
        principal.AttemptStatus.EXECUTION_ERROR,
        principal.AttemptStatus.TRACE_INVALID,
    )
    store = principal.RawRunJournalStore(tmp_path / "denominator-journal")
    records = []
    try:
        for arm, status in zip(arms, statuses, strict=True):
            record = principal.build_cpu_attempt_record(
                plan=plan,
                arm=arm,
                status=status,
                error_code=(None if status is principal.AttemptStatus.CPU_FAKE_COMPLETED else status.value),
            )
            receipt = store.append(record=record)
            records.append(principal.validate_raw_run_record(receipt=receipt, plan=plan))
    finally:
        store.close()
    handoff = principal.build_redacted_offline_handoff(plan=plan, records=tuple(records))
    totals = {
        key: sum(item[key] for item in handoff["denominators_by_condition"].values())
        for key in ("cpu_fake_completed", "timeout", "execution_error", "trace_invalid")
    }
    assert totals == {
        "cpu_fake_completed": 1,
        "timeout": 1,
        "execution_error": 1,
        "trace_invalid": 1,
    }


def test_blinded_task_sufficiency_is_finite_deterministic_and_injected(
    prepared, prepared_nonempty,
) -> None:
    projection = principal.seal_allowed_projection_for_utility(
        prepared=prepared_nonempty
    )
    task_input = principal.build_blinded_task_input(
        policy_input=prepared_nonempty.launched.policy_input,
        allowed_projection=projection,
        opaque_pair_local_id="opaque-task-0001",
        final_response="Nicholas Richmond Penicillin",
        final_artifact="bounded artifact",
    )
    rendered = json.dumps(task_input.to_wire(), sort_keys=True).lower()
    for forbidden in ("condition", "attack", "canary", "forbidden", "detector", "other_channel"):
        assert forbidden not in rendered

    assert principal.adjudicate_blinded_task(
        task_input=task_input,
        semantic_evaluator=lambda value: UtilityOutcome.PASS,
    ).outcome is UtilityOutcome.PASS
    assert principal.adjudicate_blinded_task(
        task_input=principal.build_blinded_task_input(
            policy_input=prepared_nonempty.launched.policy_input,
            allowed_projection=projection,
            opaque_pair_local_id="opaque-task-empty",
            final_response="",
            final_artifact="",
        ),
        semantic_evaluator=lambda value: UtilityOutcome.PASS,
    ).outcome is UtilityOutcome.FAIL
    empty_projection = principal.seal_allowed_projection_for_utility(prepared=prepared)
    assert principal.adjudicate_blinded_task(
        task_input=principal.build_blinded_task_input(
            policy_input=prepared.launched.policy_input,
            allowed_projection=empty_projection,
            opaque_pair_local_id="opaque-task-abstain",
            final_response="bounded output",
            final_artifact="bounded artifact",
        ),
        semantic_evaluator=lambda value: UtilityOutcome.PASS,
    ).outcome is UtilityOutcome.ABSTAIN

    def crash(_value):
        raise KeyboardInterrupt("restricted evaluator detail")

    assert principal.adjudicate_blinded_task(
        task_input=task_input, semantic_evaluator=crash
    ).outcome is UtilityOutcome.EVALUATOR_ERROR
    assert principal.adjudicate_blinded_task(
        task_input=task_input, semantic_evaluator=lambda value: "PASS"
    ).outcome is UtilityOutcome.EVALUATOR_ERROR


def test_blinded_builder_rejects_unsealed_oracle_dto_and_ast_has_no_forbidden_path(
    prepared,
) -> None:
    with pytest.raises(principal.PrincipalDriverError, match="sealed allowed projection"):
        principal.build_blinded_task_input(
            policy_input=prepared.launched.policy_input,
            allowed_projection={"records": []},
            opaque_pair_local_id="opaque-rejected",
            final_response="x",
            final_artifact="x",
        )
    with pytest.raises(TypeError):
        principal.build_blinded_task_input(
            policy_input=prepared.launched.policy_input,
            allowed_projection=principal.seal_allowed_projection_for_utility(
                prepared=prepared
            ),
            opaque_pair_local_id="opaque-rejected-keys",
            final_response="x",
            final_artifact="x",
            condition="SLUICE_COMPLETE",
            attack="secret",
        )
    source = inspect.getsource(principal.build_blinded_task_input)
    tree = ast.parse(source)
    names = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not names & {
        "condition",
        "attack",
        "evaluation",
        "canaries",
        "forbidden_fields",
        "detector",
        "other_channels",
    }


def test_synthetic_detector_metamorphic_controls_are_not_principal_outcomes() -> None:
    result = principal.run_synthetic_detector_metamorphic_controls(
        agentleak_source_root=AGENTLEAK_SOURCE_ROOT
    )
    assert result.execution_mode == "synthetic_detector_controls_only"
    assert result.principal_outcome_count == 0
    assert result.policy_exact_channel_positive_count == 7
    assert result.allowed_channel_negative_count == 7
    assert result.ingress_only_no_propagation is True
    assert result.downstream_propagation_positive is True
    public = json.dumps(result.to_public_record(), sort_keys=True)
    assert "SECRET-SYNTHETIC" not in public
    assert "synthetic-detector" not in public


def test_source_audit_proves_cpu_driver_has_no_inference_or_endpoint_calls() -> None:
    audit = principal.audit_cpu_only_source(MODULE_PATH)
    assert audit.ok is True
    assert audit.forbidden_imports == ()
    assert audit.forbidden_calls == ()
    assert audit.execution_eligibility is False
    assert audit.principal_outcome_count == 0
