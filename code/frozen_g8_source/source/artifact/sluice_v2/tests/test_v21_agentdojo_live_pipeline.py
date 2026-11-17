from __future__ import annotations

import dataclasses
import inspect
import os
from pathlib import Path
import shutil
import sys
import threading
import types

import pytest

from agentdojo.functions_runtime import FunctionCall

from sluice_v2.evaluation import agentdojo as foundation
from sluice_v2.evaluation import agentdojo_live as live
from sluice_v2.tests import test_v11_agentdojo_nonoracle as v11


REPOSITORY = Path(__file__).resolve().parents[4]
CHECKOUT = REPOSITORY / "external" / "agentdojo-v0.1.35"


@pytest.fixture(scope="module")
def source_attestation() -> live.OfficialSourceAttestation:
    return live.OfficialSourceAttestation.authenticate(CHECKOUT)


@pytest.fixture(scope="module")
def official_binding(
    source_attestation: live.OfficialSourceAttestation,
) -> live.OfficialFunctionCallBinding:
    return live.OfficialFunctionCallBinding.bind(
        source=source_attestation,
        function_call_type=FunctionCall,
    )


@pytest.fixture(scope="module")
def registry_attestation(
    source_attestation: live.OfficialSourceAttestation,
) -> live.OfficialRegistryAttestation:
    pipeline_root = CHECKOUT / "src" / "agentdojo" / "agent_pipeline"
    package = types.ModuleType("agentdojo.agent_pipeline")
    package.__path__ = [str(pipeline_root)]
    package.__package__ = "agentdojo.agent_pipeline"
    sys.modules[package.__package__] = package
    llms = types.ModuleType("agentdojo.agent_pipeline.llms")
    llms.__path__ = [str(pipeline_root / "llms")]
    llms.__package__ = "agentdojo.agent_pipeline.llms"
    sys.modules[llms.__package__] = llms
    google = types.ModuleType("agentdojo.agent_pipeline.llms.google_llm")
    google.EMPTY_FUNCTION_NAME = "<empty-function-name>"
    sys.modules[google.__name__] = google
    from agentdojo.task_suite.load_suites import get_suites

    return live.OfficialRegistryAttestation.verify(
        source=source_attestation,
        suites=get_suites(foundation.BENCHMARK_VERSION),
    )


@pytest.fixture(scope="module")
def endpoint_attestation() -> live.EndpointAttestation:
    expectation = live.EndpointExpectation(
        endpoint_url="http://127.0.0.1:8123/v1",
        model_id="example/model",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="1.2.1",
    )
    observation = live.EndpointObservation(
        endpoint_url=expectation.endpoint_url,
        model_id=expectation.model_id,
        model_revision=expectation.model_revision,
        model_artifact_sha256=expectation.model_artifact_sha256,
        backend=expectation.backend,
        backend_version=expectation.backend_version,
    )
    return expectation.verify(lambda _endpoint: observation)


@pytest.fixture(scope="module")
def schedule(registry_attestation) -> live.PairedScheduleManifest:
    return live.PairedScheduleManifest.create(
        episode_pairs=(
            live.PairedEpisodeIdentity.create(
                episode_id="episode-1",
                suite_name="banking",
                user_task_id="user_task_0",
                injection_task_id="injection_task_0",
            ),
            live.PairedEpisodeIdentity.create(
                episode_id="episode-2",
                suite_name="slack",
                user_task_id="user_task_0",
                injection_task_id="injection_task_1",
            ),
            live.PairedEpisodeIdentity.create(
                episode_id="episode-3",
                suite_name="travel",
                user_task_id="user_task_0",
                injection_task_id="injection_task_0",
            ),
        ),
        conditions=("undefended", "sluice"),
        seed="agentdojo-test-seed",
        registry=registry_attestation,
    )


@pytest.fixture(scope="module")
def provenance(
    source_attestation: live.OfficialSourceAttestation,
    registry_attestation: live.OfficialRegistryAttestation,
    endpoint_attestation: live.EndpointAttestation,
    schedule: live.PairedScheduleManifest,
) -> live.LiveRunProvenance:
    return live.LiveRunProvenance.create(
        source=source_attestation,
        registry=registry_attestation,
        endpoint=endpoint_attestation,
        schedule=schedule,
        policy_manifest=v11._manifest(),
        durable_binding_sha256="c" * 64,
        condition="sluice",
        runtime_environment=live.RuntimeEnvironmentAttestation.authenticate(
            live.CPU_AUDIT_RUNTIME_ENVIRONMENT_ID
        ),
    )


def _executor(official_binding, provenance, **broker_kwargs):
    broker, runtime, authorizer = v11._broker(**broker_kwargs)
    executor = live.OfficialBrokerExecutor(
        binding=official_binding,
        broker=broker,
        manifest=v11._manifest(),
        provenance=provenance,
    )
    return executor, broker, runtime, authorizer


def test_authenticated_official_function_call_binding_has_no_checkout_path(
    source_attestation, official_binding
):
    assert source_attestation.loaded_asset_file_count == 112
    assert source_attestation.python_file_count == 99
    assert source_attestation.loaded_asset_tree_sha256 == (
        "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
    )
    public = source_attestation.to_wire()
    assert str(CHECKOUT) not in repr(public)
    assert str(CHECKOUT) not in repr(source_attestation)
    assert official_binding.function_call_type is FunctionCall
    assert FunctionCall.__module__ == "agentdojo.functions_runtime"
    assert FunctionCall.__qualname__ == "FunctionCall"
    assert Path(inspect.getsourcefile(FunctionCall)).resolve() == (
        CHECKOUT / "src" / "agentdojo" / "functions_runtime.py"
    ).resolve()


def test_binding_rejects_a_subclass_spoofing_official_names(source_attestation):
    class SpoofedFunctionCall(FunctionCall):
        pass

    SpoofedFunctionCall.__name__ = "FunctionCall"
    SpoofedFunctionCall.__qualname__ = "FunctionCall"
    SpoofedFunctionCall.__module__ = "agentdojo.functions_runtime"
    with pytest.raises(live.LivePipelineError, match="exact class|base class"):
        live.OfficialFunctionCallBinding.bind(
            source=source_attestation,
            function_call_type=SpoofedFunctionCall,
        )


def test_binding_rejects_a_structurally_similar_nonofficial_type(source_attestation):
    class FunctionCallLookalike:
        function = "inspect"
        args = {}
        id = None
        placeholder_args = None

    with pytest.raises(live.LivePipelineError, match="official|origin|type|class"):
        live.OfficialFunctionCallBinding.bind(
            source=source_attestation,
            function_call_type=FunctionCallLookalike,
        )


def test_source_and_registry_attestations_cannot_be_forged_by_direct_replace(
    source_attestation, registry_attestation
):
    with pytest.raises(live.LivePipelineError, match="checkout bytes|summary"):
        dataclasses.replace(source_attestation, python_tree_sha256="0" * 64)
    with pytest.raises(live.LivePipelineError, match="suite objects"):
        dataclasses.replace(registry_attestation, _verification_token=object())


def test_binding_detects_live_official_class_method_replacement(
    official_binding, monkeypatch
):
    monkeypatch.setattr(FunctionCall, "model_dump", lambda self, **_kwargs: {})
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="mutated")
    with pytest.raises(live.LivePipelineError, match="changed after binding"):
        official_binding.snapshot(call)


def test_complete_official_registry_is_exactly_74_tools(registry_attestation):
    assert registry_attestation.runtime_tool_count == 74
    assert dict(registry_attestation.suite_tool_counts) == {
        "banking": 11,
        "slack": 11,
        "travel": 28,
        "workspace": 24,
    }
    assert registry_attestation.official_suite_objects_verified is True
    assert sum(
        len(registry.read_only) + len(registry.effectful)
        for registry in foundation.V122_TOOL_REGISTRIES.values()
    ) == 74


def test_registry_attestation_rejects_missing_official_suite(source_attestation):
    with pytest.raises(foundation.AgentDojoHarnessError, match="suite set"):
        live.OfficialRegistryAttestation.verify(
            source=source_attestation,
            suites={},
        )


def test_registry_rejects_shape_equivalent_nonofficial_suite_objects(
    source_attestation, registry_attestation
):
    suites = dict(registry_attestation.suites)
    original = suites["banking"]
    suites["banking"] = types.SimpleNamespace(
        name=original.name,
        tools=original.tools,
        user_tasks=original.user_tasks,
        injection_tasks=original.injection_tasks,
        environment_type=original.environment_type,
        benchmark_version=original.benchmark_version,
        data_path=original.data_path,
    )
    with pytest.raises(live.LivePipelineError, match="class|suite object"):
        live.OfficialRegistryAttestation.verify(
            source=source_attestation,
            suites=suites,
        )


def test_source_attestation_is_rechecked_after_loaded_data_mutation(tmp_path):
    copied_checkout = tmp_path / "agentdojo-copy"
    shutil.copytree(CHECKOUT, copied_checkout)
    attestation = live.OfficialSourceAttestation.authenticate(copied_checkout)
    data_file = next((copied_checkout / "src" / "agentdojo").rglob("*.yaml"))
    data_file.write_bytes(data_file.read_bytes() + b"\n# mutation\n")
    with pytest.raises(live.LivePipelineError, match="checkout bytes"):
        attestation.revalidate()


def test_registry_detects_post_verification_suite_object_replacement(
    registry_attestation,
):
    suite = registry_attestation.suites["banking"]
    original = suite.tools[0]
    suite.tools[0] = object()
    try:
        with pytest.raises(live.LivePipelineError, match="class|suite object|identity"):
            registry_attestation.revalidate()
    finally:
        suite.tools[0] = original
    registry_attestation.revalidate()


def test_endpoint_probe_is_exact_and_public_record_redacts_socket_location(
    endpoint_attestation,
):
    wire = endpoint_attestation.to_wire()
    assert wire["model_id"] == "example/model"
    assert wire["model_revision"] == "a" * 40
    assert wire["model_artifact_sha256"] == "b" * 64
    assert "127.0.0.1" not in repr(wire)
    assert "8123" not in repr(wire)
    assert len(wire["endpoint_sha256"]) == 64


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://example.com:8123/v1",
        "https://127.0.0.1:8123/v1",
        "http://127.0.0.1:8123/v1?token=secret",
        "http://user:password@127.0.0.1:8123/v1",
    ),
)
def test_endpoint_expectation_rejects_nonlocal_or_credentialed_targets(endpoint):
    with pytest.raises(live.LivePipelineError, match="endpoint"):
        live.EndpointExpectation(
            endpoint_url=endpoint,
            model_id="example/model",
            model_revision="a" * 40,
            model_artifact_sha256="b" * 64,
            backend="vllm",
            backend_version="1.2.1",
        )


def test_endpoint_probe_rejects_model_revision_or_backend_drift():
    expected = live.EndpointExpectation(
        endpoint_url="http://127.0.0.1:8123/v1",
        model_id="example/model",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="1.2.1",
    )
    observed = live.EndpointObservation(
        endpoint_url=expected.endpoint_url,
        model_id=expected.model_id,
        model_revision="d" * 40,
        model_artifact_sha256=expected.model_artifact_sha256,
        backend=expected.backend,
        backend_version=expected.backend_version,
    )
    with pytest.raises(live.LivePipelineError, match="observation|revision"):
        expected.verify(lambda _endpoint: observed)


def test_endpoint_attestation_cannot_be_created_without_verified_probe():
    observation = live.EndpointObservation(
        endpoint_url="http://127.0.0.1:8123/v1",
        model_id="example/model",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="1.2.1",
    )
    with pytest.raises(live.LivePipelineError, match="probe"):
        live.EndpointAttestation.create(observation)


def test_paired_schedule_is_deterministic_complete_and_counterbalanced(
    schedule, registry_attestation
):
    again = live.PairedScheduleManifest.create(
        episode_pairs=(
            live.PairedEpisodeIdentity.create(
                episode_id="episode-3",
                suite_name="travel",
                user_task_id="user_task_0",
                injection_task_id="injection_task_0",
            ),
            live.PairedEpisodeIdentity.create(
                episode_id="episode-1",
                suite_name="banking",
                user_task_id="user_task_0",
                injection_task_id="injection_task_0",
            ),
            live.PairedEpisodeIdentity.create(
                episode_id="episode-2",
                suite_name="slack",
                user_task_id="user_task_0",
                injection_task_id="injection_task_1",
            ),
        ),
        conditions=("undefended", "sluice"),
        seed="agentdojo-test-seed",
        registry=registry_attestation,
    )
    assert again == schedule
    assert len(schedule.entries) == 6
    for episode in ("episode-1", "episode-2", "episode-3"):
        selected = [entry for entry in schedule.entries if entry.episode_id == episode]
        assert len(selected) == 2
        assert {entry.condition for entry in selected} == {"undefended", "sluice"}
        assert {entry.order for entry in selected} == {1, 2}
        assert len({entry.suite_name for entry in selected}) == 1
        assert len({entry.user_task_id for entry in selected}) == 1
        assert len({entry.injection_task_id for entry in selected}) == 1
        assert len({entry.pair_id for entry in selected}) == 1
    first_conditions = [
        entry.condition for entry in schedule.entries if entry.order == 1
    ]
    assert abs(
        first_conditions.count("undefended") - first_conditions.count("sluice")
    ) <= 1
    assert len(schedule.sha256) == 64


def test_schedule_direct_tampering_is_rejected(schedule):
    with pytest.raises(live.LivePipelineError, match="digest|schedule"):
        dataclasses.replace(schedule, sha256="0" * 64)


def test_schedule_binds_exact_official_pair_coordinates_and_condition(
    registry_attestation,
):
    field_names = {item.name for item in dataclasses.fields(live.PairedScheduledRun)}
    assert {
        "suite_name",
        "user_task_id",
        "injection_task_id",
        "pair_id",
        "condition",
    } <= field_names
    unknown = live.PairedEpisodeIdentity.create(
        episode_id="unknown-pair",
        suite_name="banking",
        user_task_id="user_task_999",
        injection_task_id="injection_task_0",
    )
    with pytest.raises(live.LivePipelineError, match="nonofficial task pair"):
        live.PairedScheduleManifest.create(
            episode_pairs=(unknown,),
            conditions=("undefended", "sluice"),
            seed="unknown-pair-seed",
            registry=registry_attestation,
        )


def test_provenance_binds_policy_schedule_source_registry_endpoint_and_adapter(
    provenance,
):
    wire = provenance.to_wire()
    assert wire["benchmark_version"] == "v1.2.2"
    assert wire["runtime_tool_count"] == 74
    assert wire["durable_binding_sha256"] == "c" * 64
    assert wire["suite_object_sha256"]
    assert wire["suite_name"] == "banking"
    assert wire["user_task_id"] == "user_task_0"
    assert wire["injection_task_id"] == "injection_task_0"
    assert wire["pair_id"]
    assert wire["condition"] == "sluice"
    assert wire["schedule_block"] == 0
    assert wire["schedule_order"] in (1, 2)
    assert wire["source_assets_sha256"] == (
        "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
    )
    assert len(wire["policy_manifest_sha256"]) == 64
    assert len(wire["adapter_source_sha256"]) == 64
    assert wire["python_version"]
    assert wire["pydantic_version"]
    assert wire["pyyaml_version"]
    assert wire["runtime_environment_id"] == live.CPU_AUDIT_RUNTIME_ENVIRONMENT_ID
    assert wire["principal_eligible"] is False
    assert len(wire["runtime_environment_sha256"]) == 64
    assert len(wire["runtime_dependencies_sha256"]) == 64
    assert "127.0.0.1" not in repr(wire)
    assert str(CHECKOUT) not in repr(wire)
    assert provenance.sha256 == live.live_run_provenance_sha256(wire)


def test_provenance_cannot_be_forged_by_direct_construction(provenance):
    with pytest.raises(live.LivePipelineError, match="factory"):
        dataclasses.replace(provenance, _verification_token=object())
    with pytest.raises(live.LivePipelineError, match="scheduled-run|provenance"):
        dataclasses.replace(provenance, condition="undefended")


def test_runtime_environment_is_exactly_pinned_and_discloses_cpu_nonprincipality(
    monkeypatch,
):
    cpu = live.RuntimeEnvironmentAttestation.authenticate(
        live.CPU_AUDIT_RUNTIME_ENVIRONMENT_ID
    )
    assert cpu.pydantic_version == "2.13.4"
    assert cpu.pyyaml_version == "6.0.3"
    assert cpu.principal_eligible is False

    monkeypatch.setattr(live.importlib.metadata, "version", lambda _name: "999.0")
    with pytest.raises(live.LivePipelineError, match="pin mismatch"):
        live.RuntimeEnvironmentAttestation.authenticate()
    with pytest.raises(live.LivePipelineError, match="pin mismatch"):
        live._adapter_runtime_dependencies()


def test_principal_runtime_requires_official_policy_pair_association(
    source_attestation,
    registry_attestation,
    endpoint_attestation,
    schedule,
    monkeypatch,
):
    versions = {"pydantic": "2.11.4", "PyYAML": "6.0.2"}
    monkeypatch.setattr(live.importlib.metadata, "version", versions.__getitem__)
    principal = live.RuntimeEnvironmentAttestation.authenticate()
    assert principal.principal_eligible is True
    with pytest.raises(live.LivePipelineError, match="official suite"):
        live.LiveRunProvenance.create(
            source=source_attestation,
            registry=registry_attestation,
            endpoint=endpoint_attestation,
            schedule=schedule,
            policy_manifest=v11._manifest(),
            durable_binding_sha256="c" * 64,
            condition="sluice",
            runtime_environment=principal,
        )


def test_official_read_call_is_brokered_and_returns_official_message_shape(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="provider-call-1")
    environment = {"answer": "safe", "approved": ["alice@example.test"]}
    result = executor.execute(call, environment, call_ordinal=1)
    assert result.broker_outcome is foundation.BrokerOutcome.EXECUTED_READ_ONLY
    assert result.adapter_outcome is live.CallAdapterOutcome.BROKERED
    assert result.environment is environment
    assert result.message == {
        "role": "tool",
        "content": [{"type": "text", "content": "safe"}],
        "tool_call_id": "provider-call-1",
        "tool_call": result.message["tool_call"],
        "error": None,
    }
    assert type(result.message) is dict
    assert type(result.message["tool_call"]) is FunctionCall
    assert result.message["tool_call"] is not call
    assert result.message["tool_call"].args == {"key": "answer"}
    assert runtime.calls == [("inspect", {"key": "answer"})]
    assert authorizer.calls == []
    assert len(broker.audit_log) == 1


def test_effect_call_has_one_exact_authorization_and_replay_has_none(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    environment = {"approved": ["alice@example.test"]}
    first_call = FunctionCall(
        function="mutate",
        args={"recipient": "alice@example.test", "amount": 7},
        id="effect-call-1",
    )
    first = executor.execute(first_call, environment, call_ordinal=1)
    assert first.broker_outcome is foundation.BrokerOutcome.EXECUTED_EFFECT
    assert first.environment["sent"] == [("alice@example.test", 7)]
    assert "sent" not in environment
    assert len(authorizer.calls) == 1
    assert broker.consumed_effect_count == 1
    assert broker.unused_effect_count == 0

    second_call = FunctionCall(
        function="mutate",
        args={"recipient": "alice@example.test", "amount": 7},
        id="effect-call-2",
    )
    second = executor.execute(second_call, first.environment, call_ordinal=2)
    assert second.broker_outcome is foundation.BrokerOutcome.NO_AUTHORIZED_TEMPLATE
    assert len(authorizer.calls) == 1
    assert len(broker.audit_log) == 2


def test_nested_official_function_call_is_denied_before_runtime_dispatch(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    nested = FunctionCall(
        function="mutate",
        args={"recipient": "alice@example.test", "amount": 7},
        id="nested",
    )
    outer = FunctionCall(function="inspect", args={"key": nested}, id="outer")
    result = executor.execute(
        outer,
        {"answer": "safe", "approved": ["alice@example.test"]},
        call_ordinal=1,
    )
    assert result.broker_outcome is foundation.BrokerOutcome.NESTED_CALL_DENIED
    assert result.message["error"] == "SLUICE_NESTED_CALL_DENIED"
    assert runtime.calls == []
    assert authorizer.calls == []
    assert broker.consumed_effect_count == 0
    assert broker.unused_effect_count == 1
    assert len(broker.audit_log) == 1


def test_placeholder_arguments_are_denied_without_broker_or_runtime_access(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    call = FunctionCall(
        function="inspect",
        args={"key": "answer"},
        id="placeholder",
        placeholder_args={"key": "hidden-answer"},
    )
    result = executor.execute(
        call,
        {"answer": "safe", "approved": ["alice@example.test"]},
        call_ordinal=1,
    )
    assert result.adapter_outcome is live.CallAdapterOutcome.PLACEHOLDER_ARGUMENTS_DENIED
    assert result.broker_outcome is None
    assert result.message["error"] == "SLUICE_PLACEHOLDER_ARGUMENTS_DENIED"
    assert result.message["tool_call"].placeholder_args is None
    assert runtime.calls == []
    assert authorizer.calls == []
    assert broker.consumed_effect_count == 0
    assert broker.unused_effect_count == 1
    assert broker.audit_log == ()


def test_unknown_tool_traverses_broker_and_fails_closed(official_binding, provenance):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    call = FunctionCall(function="unregistered_tool", args={}, id="unknown")
    result = executor.execute(call, {}, call_ordinal=1)
    assert result.broker_outcome is foundation.BrokerOutcome.UNKNOWN_TOOL
    assert result.message["error"] == "SLUICE_UNKNOWN_TOOL"
    assert runtime.calls == []
    assert authorizer.calls == []
    assert broker.consumed_effect_count == 0
    assert broker.unused_effect_count == 1
    assert len(broker.audit_log) == 1


def test_duplicate_ordinal_is_locally_denied_without_second_broker_attempt(
    official_binding, provenance
):
    executor, broker, runtime, _ = _executor(official_binding, provenance)
    first = FunctionCall(function="inspect", args={"key": "answer"}, id="first")
    replay = FunctionCall(function="inspect", args={"key": "answer"}, id="second")
    environment = {"answer": "safe", "approved": []}
    assert executor.execute(first, environment, call_ordinal=1).message["error"] is None
    denied = executor.execute(replay, environment, call_ordinal=1)
    assert denied.adapter_outcome is live.CallAdapterOutcome.REPLAY_DENIED
    assert denied.broker_outcome is None
    assert denied.message["error"] == "SLUICE_REPLAY_DENIED"
    assert len(runtime.calls) == 1
    assert len(broker.audit_log) == 1


def test_duplicate_provider_call_id_is_one_use_across_distinct_ordinals(
    official_binding, provenance
):
    executor, broker, runtime, _ = _executor(official_binding, provenance)
    environment = {"answer": "safe", "approved": []}
    first = FunctionCall(function="inspect", args={"key": "answer"}, id="same-id")
    duplicate = FunctionCall(
        function="inspect", args={"key": "answer"}, id="same-id"
    )
    assert executor.execute(first, environment, call_ordinal=1).message["error"] is None
    denied = executor.execute(duplicate, environment, call_ordinal=2)
    assert denied.adapter_outcome is live.CallAdapterOutcome.REPLAY_DENIED
    assert denied.message["error"] == "SLUICE_REPLAY_DENIED"
    assert len(runtime.calls) == 1
    assert len(broker.audit_log) == 1


def test_executor_rejects_nonofficial_call_object(official_binding, provenance):
    executor, broker, runtime, _ = _executor(official_binding, provenance)
    with pytest.raises(live.LivePipelineError, match="official FunctionCall"):
        executor.execute(
            {"function": "inspect", "args": {"key": "answer"}},
            {"answer": "safe"},
            call_ordinal=1,
        )
    assert runtime.calls == []
    assert broker.audit_log == ()


def test_model_argument_mutation_after_execution_cannot_change_request_or_audit(
    official_binding, provenance
):
    executor, broker, runtime, _ = _executor(official_binding, provenance)
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="snapshot")
    environment = {"answer": "safe", "other": "unsafe", "approved": []}
    result = executor.execute(call, environment, call_ordinal=1)
    call.args["key"] = "other"
    assert runtime.calls == [("inspect", {"key": "answer"})]
    assert result.message["tool_call"].args == {"key": "answer"}
    assert result.audit.args_sha256 == foundation._safe_args_digest({"key": "answer"})
    assert broker.audit_log[0].args_sha256 == result.audit.args_sha256


def test_redacted_live_audit_contains_no_raw_identifiers_arguments_or_results(
    official_binding, provenance
):
    executor, _, _, _ = _executor(official_binding, provenance)
    secret = "ULTRA-SENSITIVE-VALUE"
    call = FunctionCall(function="inspect", args={"key": secret}, id=secret)
    result = executor.execute(
        call,
        {secret: secret, "approved": []},
        call_ordinal=1,
    )
    wire = result.audit.to_wire()
    assert secret not in repr(result.audit)
    assert secret not in repr(wire)
    assert not hasattr(result.audit, "function")
    assert not hasattr(result.audit, "args")
    assert not hasattr(result.audit, "value")
    assert len(result.audit.call_id_sha256) == 64
    assert len(result.audit.tool_sha256) == 64
    assert len(result.audit.args_sha256) == 64
    assert len(result.audit.result_sha256) == 64


def test_audit_record_direct_digest_tampering_is_rejected(official_binding, provenance):
    executor, _, _, _ = _executor(official_binding, provenance)
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="audit")
    record = executor.execute(
        call, {"answer": "safe", "approved": []}, call_ordinal=1
    ).audit
    values = record.to_wire()
    values["record_sha256"] = "0" * 64
    with pytest.raises(live.LivePipelineError, match="audit.*digest|digest.*audit"):
        live.RedactedLiveCallRecord.from_wire(values)


def test_pipeline_element_processes_official_calls_only_through_bound_broker(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    element = live.OfficialBrokerPipelineElement(executor)
    messages = [
        {
            "role": "assistant",
            "content": [],
            "tool_calls": [
                FunctionCall(function="inspect", args={"key": "answer"}, id="p-read"),
                FunctionCall(
                    function="mutate",
                    args={"recipient": "alice@example.test", "amount": 7},
                    id="p-effect",
                ),
            ],
        }
    ]
    environment = {"answer": "safe", "approved": ["alice@example.test"]}
    query, returned_runtime, after, output, extra = element.query(
        "trusted user request", runtime, environment, messages, {"opaque": True}
    )
    assert query == "trusted user request"
    assert returned_runtime is runtime
    assert extra == {"opaque": True}
    assert after["sent"] == [("alice@example.test", 7)]
    assert "sent" not in environment
    assert [message["role"] for message in output] == ["assistant", "tool", "tool"]
    assert [message["error"] for message in output[1:]] == [None, None]
    assert runtime.calls == [
        ("inspect", {"key": "answer"}),
        ("mutate", {"recipient": "alice@example.test", "amount": 7}),
    ]
    assert len(authorizer.calls) == 1
    assert len(broker.audit_log) == 2
    assert len(executor.audit_log) == 2


def test_pipeline_element_rejects_runtime_substitution_before_any_dispatch(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    element = live.OfficialBrokerPipelineElement(executor)
    messages = [
        {
            "role": "assistant",
            "content": [],
            "tool_calls": [
                FunctionCall(function="inspect", args={"key": "answer"}, id="p-read")
            ],
        }
    ]
    with pytest.raises(live.LivePipelineError, match="runtime differs"):
        element.query("query", object(), {"answer": "safe"}, messages, {})
    assert runtime.calls == []
    assert authorizer.calls == []
    assert broker.audit_log == ()


@pytest.mark.parametrize(
    "assistant_message",
    (
        {"role": "assistant", "content": [], "tool_calls": ()},
        {
            "role": "assistant",
            "content": [],
            "tool_calls": [],
            "unexpected": "field",
        },
    ),
)
def test_pipeline_rejects_nonexact_assistant_response_schema_before_dispatch(
    official_binding, provenance, assistant_message
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    element = live.OfficialBrokerPipelineElement(executor)
    with pytest.raises(live.LivePipelineError, match="assistant.*exact|exact list"):
        element.query(
            "query",
            runtime,
            {"answer": "safe"},
            [assistant_message],
            {},
        )
    assert runtime.calls == []
    assert authorizer.calls == []
    assert broker.audit_log == ()


def test_executor_rejects_broker_runtime_replacement_before_any_dispatch(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    replacement = v11._runtime()
    broker._runtime = replacement
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="swap")
    with pytest.raises(live.LivePipelineError, match="identity changed"):
        executor.execute(call, {"answer": "safe"}, call_ordinal=1)
    assert runtime.calls == []
    assert replacement.calls == []
    assert authorizer.calls == []
    assert broker.audit_log == ()


def test_executor_rejects_sealed_runtime_function_replacement_before_dispatch(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    runtime.functions["inspect"].run = lambda _environment, _key: "substituted"
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="tool-swap")
    with pytest.raises(live.LivePipelineError, match="identity changed"):
        executor.execute(call, {"answer": "safe"}, call_ordinal=1)
    assert runtime.calls == []
    assert authorizer.calls == []
    assert broker.audit_log == ()


def test_executor_rejects_authorizer_replacement_before_effect_dispatch(
    official_binding, provenance
):
    executor, broker, runtime, authorizer = _executor(official_binding, provenance)
    replacement = v11.RecordingAuthorizer()
    broker._authorizer = replacement
    call = FunctionCall(
        function="mutate",
        args={"recipient": "alice@example.test", "amount": 7},
        id="authorizer-swap",
    )
    with pytest.raises(live.LivePipelineError, match="identity changed"):
        executor.execute(
            call, {"approved": ["alice@example.test"]}, call_ordinal=1
        )
    assert runtime.calls == []
    assert authorizer.calls == []
    assert replacement.calls == []
    assert broker.audit_log == ()


def test_binding_rejects_loaded_module_replacement_before_snapshot(
    official_binding, monkeypatch
):
    replacement = types.ModuleType("agentdojo.functions_runtime")
    replacement.FunctionCall = FunctionCall
    monkeypatch.setitem(sys.modules, "agentdojo.functions_runtime", replacement)
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="module-swap")
    with pytest.raises(live.LivePipelineError, match="module|identity|origin"):
        official_binding.snapshot(call)


def test_result_format_failure_is_finite_and_does_not_erase_broker_audit(
    official_binding, provenance
):
    huge = "x" * (live.MAX_RESULT_BYTES + 1)
    runtime = v11.FakeRuntime(
        {
            "inspect": lambda _environment, key: huge,
            "mutate": lambda environment, recipient, amount: None,
        }
    )
    executor, broker, _, _ = _executor(
        official_binding, provenance, runtime=runtime
    )
    call = FunctionCall(function="inspect", args={"key": "answer"}, id="huge")
    result = executor.execute(call, {"answer": "safe", "approved": []}, call_ordinal=1)
    assert result.broker_outcome is foundation.BrokerOutcome.EXECUTED_READ_ONLY
    assert result.adapter_outcome is live.CallAdapterOutcome.RESULT_FORMAT_DENIED
    assert result.message["content"] == [{"type": "text", "content": ""}]
    assert result.message["error"] == "SLUICE_RESULT_FORMAT_DENIED"
    assert len(broker.audit_log) == 1
    assert len(executor.audit_log) == 1


def test_result_formatter_matches_pinned_official_function_on_supported_values(
    registry_attestation,
):
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from pydantic import BaseModel

    class Row(BaseModel):
        name: str
        count: int

    values = (
        None,
        "plain",
        7,
        1.25,
        True,
        {"z": 1, "a": "two"},
        Row(name="alpha", count=2),
        ["alpha", 2],
        [Row(name="beta", count=3)],
    )
    assert registry_attestation.runtime_tool_count == 74
    assert [live._official_result_text(value) for value in values] == [
        tool_result_to_str(value) for value in values
    ]


def test_post_authorization_tool_failure_is_audited_and_consumes_once(
    official_binding, provenance
):
    failing_runtime = v11._runtime(effect_error=True)
    executor, broker, runtime, authorizer = _executor(
        official_binding, provenance, runtime=failing_runtime
    )
    call = FunctionCall(
        function="mutate",
        args={"recipient": "alice@example.test", "amount": 7},
        id="failing-effect",
    )
    first = executor.execute(
        call, {"approved": ["alice@example.test"]}, call_ordinal=1
    )
    assert first.broker_outcome is foundation.BrokerOutcome.TOOL_ERROR
    assert first.message["error"] == "SLUICE_TOOL_ERROR"
    assert len(authorizer.calls) == 1
    assert broker.consumed_effect_count == 1
    assert broker.unused_effect_count == 0
    assert len(runtime.calls) == 1
    assert len(broker.audit_log) == 1
    assert len(executor.audit_log) == 1

    replay = FunctionCall(
        function="mutate",
        args={"recipient": "alice@example.test", "amount": 7},
        id="failing-effect-retry",
    )
    second = executor.execute(replay, first.environment, call_ordinal=2)
    assert second.broker_outcome is foundation.BrokerOutcome.NO_AUTHORIZED_TEMPLATE
    assert len(authorizer.calls) == 1


def test_concurrent_official_reads_have_one_broker_and_live_audit_each(
    official_binding, provenance
):
    executor, broker, runtime, _ = _executor(official_binding, provenance)
    count = 12
    barrier = threading.Barrier(count)
    results = [None] * count

    def run(index):
        barrier.wait(timeout=10)
        call = FunctionCall(
            function="inspect", args={"key": "answer"}, id=f"parallel-{index}"
        )
        results[index] = executor.execute(
            call,
            {"answer": "safe", "approved": []},
            call_ordinal=index + 1,
        )

    threads = [threading.Thread(target=run, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert all(result.message["error"] is None for result in results)
    assert len(runtime.calls) == count
    assert len(broker.audit_log) == count
    assert len(executor.audit_log) == count
    assert [record.sequence for record in executor.audit_log] == list(range(1, count + 1))


def test_primary_adapter_source_has_no_hidden_answer_api_reference():
    path = Path(live.__file__).resolve()
    assert foundation.audit_primary_source_for_oracle_access(path) == ()


def test_singleton_plan_builds_exact_private_templates_and_client_is_one_shot(
    tmp_path, monkeypatch
):
    from sluice_v2.durable_secure import (
        DurableSecureDomain,
        EffectResult,
        IdempotentEffectHandler,
        ObserverSpec,
        RouteCodebook,
    )
    from sluice_v2.durable_service import PeerIdentity, PrivateTemplateBinding
    from sluice_v2.secure import DomainConfig

    key = b"a" * 32
    domain = DurableSecureDomain.create(
        tmp_path / "live-singleton-domain.sqlite",
        config=DomainConfig(
            domain_id="agentdojo-live-singleton",
            protected_objects=frozenset({"effect-object"}),
            lifetime_budget_units=8,
            attempt_horizon=2,
            event_charge_units=4,
        ),
        observer_spec=ObserverSpec(
            permitted_value_codes=frozenset({1}),
            observer_spec_id="agentdojo-live-singleton-codebook-v1",
            route_codebooks=(RouteCodebook("mutate", frozenset({1}), True),),
            accounting_units_per_bit=1,
        ),
        agent_keys={"agentdojo-planner": key},
        reauthorization_keys={"authority": b"b" * 32},
        handler_registry={
            "authorize": IdempotentEffectHandler(
                execute=lambda request: EffectResult.for_request(request, 1),
                reconcile=lambda _request: None,
            )
        },
    )
    route = domain.register_route(
        name="mutate",
        protected_object="effect-object",
        handler_key="authorize",
        public_values=frozenset({1}),
        requires_capability=True,
    )
    domain.seal()
    domain.activate()
    manifest = v11._manifest()
    grants = foundation.issue_durable_effect_grants(
        domain,
        manifest,
        route_by_tool={"mutate": route},
        agent_id="agentdojo-planner",
        signing_key=key,
        redeemer_id=f"pid:{os.getpid()}",
    )
    template_id = manifest.templates[0].template_id
    plan = live.SingletonGrantPlan.create(
        manifest=manifest,
        grants=grants,
        template_codes={template_id: 7001},
    )
    assert len(plan.private_bindings) == 1
    assert type(plan.private_bindings[0]) is PrivateTemplateBinding
    assert plan.private_bindings[0].template_code == 7001
    assert plan.private_bindings[0].payload_snapshot() == grants[0].payload()
    assert "signature" not in repr(plan)
    assert len(plan.binding_sha256) == 64
    with pytest.raises(live.LivePipelineError, match="binding digest"):
        dataclasses.replace(plan, binding_sha256="0" * 64)

    exchanges = []

    def exchange(address, request, *, expected_monitor, timeout_seconds):
        exchanges.append((address, request, expected_monitor, timeout_seconds))
        return domain.attempt(
            grants[0].route,
            grants[0].payload(),
            credential=grants[0].credential,
            capability=grants[0].capability,
            redeemer_id=grants[0].redeemer_id,
        )

    monkeypatch.setattr(live, "_singleton_exchange", exchange)
    peer = PeerIdentity(pid=os.getpid(), uid=os.getuid(), gid=os.getgid())
    client = plan.client(
        address="\0agentdojo-live-test",
        expected_monitor=peer,
        timeout_seconds=1.0,
    )
    assert client.redeem(grants[0], grants[0].payload()) is foundation.AuthorizationOutcome.RELEASED
    assert client.redeem(grants[0], grants[0].payload()) is foundation.AuthorizationOutcome.ERROR
    assert len(exchanges) == 1
    assert exchanges[0][1].template_code == 7001
    assert len(domain.transcript) == 1
    domain.close()


def test_singleton_plan_rejects_missing_duplicate_or_unbound_template_codes():
    manifest = v11._manifest()
    grant = v11._grant(manifest)
    with pytest.raises(live.LivePipelineError, match="template code"):
        live.SingletonGrantPlan.create(
            manifest=manifest,
            grants=(grant,),
            template_codes={},
        )
    with pytest.raises(live.LivePipelineError, match="template code"):
        live.SingletonGrantPlan.create(
            manifest=manifest,
            grants=(grant,),
            template_codes={manifest.templates[0].template_id: 0},
        )
