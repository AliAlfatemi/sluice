from __future__ import annotations

import hashlib
import math
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sluice_v2.evaluation.agentdojo import (
    AGENTDOJO_COMMIT,
    AGENTDOJO_VERSION,
    BENCHMARK_VERSION,
    MAX_POLICY_TEMPLATES,
    AbstentionCategory,
    ArgumentBinding,
    AuthorizationOutcome,
    BrokerOutcome,
    CallTemplateSpec,
    EvaluationSplit,
    NonOracleToolBroker,
    OrganizationPolicy,
    PolicyDecision,
    PolicyInput,
    PolicyRule,
    SecureEffectGrant,
    SplitManifest,
    StaticToolSchema,
    ToolKind,
    ToolRegistry,
    ToolRequest,
    V122_TOOL_REGISTRIES,
    audit_primary_source_for_oracle_access,
    canonical_args,
    compile_static_policy,
    generate_counterbalanced_schedule,
    issue_durable_effect_grants,
    validate_pinned_checkout,
    validate_v122_suites,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


PROMPT = "Send 7 dollars to the approved recipient."


def _schemas() -> tuple[StaticToolSchema, ...]:
    return (
        StaticToolSchema(
            name="inspect",
            parameters={
                "type": "object",
                "properties": {"key": {"type": "string"}},
                "required": ["key"],
                "additionalProperties": False,
            },
        ),
        StaticToolSchema(
            name="mutate",
            parameters={
                "type": "object",
                "properties": {
                    "recipient": {"type": "string"},
                    "amount": {"type": "integer"},
                },
                "required": ["recipient", "amount"],
                "additionalProperties": False,
            },
        ),
    )


def _registry() -> ToolRegistry:
    return ToolRegistry(
        suite_name="test-suite",
        read_only=frozenset({"inspect"}),
        effectful=frozenset({"mutate"}),
    )


def _org_policy(*, prompt_hash: str | None = None) -> OrganizationPolicy:
    return OrganizationPolicy(
        policy_id="org-policy-2026-08-20",
        rules=(
            PolicyRule(
                rule_id="send-approved",
                suite_name="test-suite",
                prompt_sha256=prompt_hash or _sha(PROMPT),
                calls=(
                    CallTemplateSpec(
                        tool="mutate",
                        arguments={
                            "recipient": ArgumentBinding.from_state("/approved/0"),
                            "amount": ArgumentBinding.literal(7),
                        },
                    ),
                ),
            ),
        ),
    )


class PoisonTask:
    PROMPT = PROMPT

    def ground_truth(self, _environment):  # pragma: no cover - must never run
        raise AssertionError("answer-key access")


def _policy_input(*, policy: OrganizationPolicy | None = None) -> PolicyInput:
    split = SplitManifest.create(
        dev_task_ids=("test-suite:user_task_0",),
        heldout_task_ids=("test-suite:user_task_1",),
    )
    return PolicyInput.from_task_prompt(
        PoisonTask(),
        task_id="test-suite:user_task_1",
        suite_name="test-suite",
        pre_injection_state={"approved": ["alice@example.test"]},
        tool_schemas=_schemas(),
        organization_policy=policy or _org_policy(),
        split_manifest=split,
    )


def _manifest():
    return compile_static_policy(
        _policy_input(),
        registry=_registry(),
        workflow_id="workflow-1",
        episode_id="episode-1",
        compiler_id="static-v1",
    )


def test_source_identity_and_primary_path_have_no_answer_key_access():
    assert AGENTDOJO_VERSION == "0.1.35"
    assert AGENTDOJO_COMMIT == "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
    assert BENCHMARK_VERSION == "v1.2.2"
    import sluice_v2.evaluation.agentdojo as module

    assert audit_primary_source_for_oracle_access(Path(module.__file__)) == ()


def test_task_whose_answer_key_raises_is_compiled_without_calling_it():
    policy_input = _policy_input()
    assert not hasattr(policy_input, "__dict__")
    assert "task" not in PolicyInput.__slots__
    assert "scorer" not in PolicyInput.__slots__
    manifest = compile_static_policy(
        policy_input,
        registry=_registry(),
        workflow_id="workflow-1",
        episode_id="episode-1",
        compiler_id="static-v1",
    )
    assert manifest.decision is PolicyDecision.COMPILED
    assert manifest.split is EvaluationSplit.HELDOUT
    assert len(manifest.templates) == 1
    template = manifest.templates[0]
    assert template.tool == "mutate"
    assert template.exact_args == canonical_args(
        {"recipient": "alice@example.test", "amount": 7}
    )
    assert manifest.prompt_sha256 == _sha(PROMPT)
    import sluice_v2.evaluation.agentdojo as module

    assert manifest.compiler_sha256 == hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
    assert len(manifest.compiler_runtime_sha256) == 64
    assert manifest.compiler_runtime_sha256 != manifest.compiler_sha256
    assert manifest.source_assets_sha256 == (
        "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
    )


def test_policy_input_rejects_instance_prompt_descriptors_and_wrong_source_pin():
    class DescriptorTask:
        @property
        def PROMPT(self):  # pragma: no cover - static access must reject it
            raise AssertionError

    split = SplitManifest.create(
        dev_task_ids=("test-suite:user_task_0",), heldout_task_ids=()
    )
    with pytest.raises(TypeError, match="class-level PROMPT"):
        PolicyInput.from_task_prompt(
            DescriptorTask(),
            task_id="test-suite:user_task_0",
            suite_name="test-suite",
            pre_injection_state={},
            tool_schemas=_schemas(),
            organization_policy=_org_policy(),
            split_manifest=split,
        )
    with pytest.raises(ValueError, match="source commit"):
        PolicyInput(
            source_commit="0" * 40,
            benchmark_version=BENCHMARK_VERSION,
            suite_name="test-suite",
            task_id="test-suite:user_task_0",
            trusted_user_prompt=PROMPT,
            pre_injection_state={},
            tool_schemas=_schemas(),
            organization_policy=_org_policy(),
            split_manifest=split,
        )


def test_type_tagged_arguments_are_injective_and_bounded():
    values = [None, False, True, 0, 1, "1", 1.0, [1], {"x": 1}]
    encodings = {canonical_args({"v": value}) for value in values}
    assert len(encodings) == len(values)
    with pytest.raises((TypeError, ValueError)):
        canonical_args({1: "coerced"})
    with pytest.raises((TypeError, ValueError)):
        canonical_args({"x": math.inf})
    with pytest.raises((TypeError, ValueError)):
        canonical_args({"x": object()})


def test_static_compiler_abstains_on_no_match_or_missing_state():
    no_match = compile_static_policy(
        _policy_input(policy=_org_policy(prompt_hash="0" * 64)),
        registry=_registry(),
        workflow_id="w",
        episode_id="e",
        compiler_id="c",
    )
    assert no_match.decision is PolicyDecision.ABSTAINED
    assert no_match.abstention is AbstentionCategory.NO_MATCHING_RULE
    assert not no_match.templates

    broken = OrganizationPolicy(
        policy_id="broken",
        rules=(
            PolicyRule(
                rule_id="missing",
                suite_name="test-suite",
                prompt_sha256=_sha(PROMPT),
                calls=(
                    CallTemplateSpec(
                        tool="mutate",
                        arguments={
                            "recipient": ArgumentBinding.from_state("/absent"),
                            "amount": ArgumentBinding.literal(7),
                        },
                    ),
                ),
            ),
        ),
    )
    missing = compile_static_policy(
        _policy_input(policy=broken),
        registry=_registry(),
        workflow_id="w",
        episode_id="e",
        compiler_id="c",
    )
    assert missing.abstention is AbstentionCategory.MISSING_STATE_VALUE

    with pytest.raises(ValueError, match="abstained policy"):
        NonOracleToolBroker(
            manifest=no_match,
            registry=_registry(),
            tool_schemas=_schemas(),
            runtime=_runtime(),
            grants=(),
            authorizer=RecordingAuthorizer(),
        )


def test_static_compiler_rejects_ambiguity_schema_mismatch_and_template_flood():
    rule = _org_policy().rules[0]
    ambiguous = OrganizationPolicy(policy_id="ambiguous", rules=(rule, rule.with_id("duplicate")))
    result = compile_static_policy(
        _policy_input(policy=ambiguous),
        registry=_registry(),
        workflow_id="w",
        episode_id="e",
        compiler_id="c",
    )
    assert result.abstention is AbstentionCategory.AMBIGUOUS_RULE

    wrong_schema = OrganizationPolicy(
        policy_id="wrong-schema",
        rules=(
            PolicyRule(
                rule_id="wrong",
                suite_name="test-suite",
                prompt_sha256=_sha(PROMPT),
                calls=(CallTemplateSpec(tool="mutate", arguments={"amount": ArgumentBinding.literal(7)}),),
            ),
        ),
    )
    result = compile_static_policy(
        _policy_input(policy=wrong_schema),
        registry=_registry(),
        workflow_id="w",
        episode_id="e",
        compiler_id="c",
    )
    assert result.abstention is AbstentionCategory.SCHEMA_MISMATCH

    calls = tuple(
        CallTemplateSpec(
            tool="mutate",
            arguments={
                "recipient": ArgumentBinding.literal(f"r{i}"),
                "amount": ArgumentBinding.literal(7),
            },
        )
        for i in range(MAX_POLICY_TEMPLATES + 1)
    )
    with pytest.raises(ValueError, match="template bound"):
        PolicyRule(
            rule_id="flood",
            suite_name="test-suite",
            prompt_sha256=_sha(PROMPT),
            calls=calls,
        )


def test_split_manifest_and_counterbalanced_schedule_are_frozen_and_balanced():
    with pytest.raises(ValueError, match="overlap"):
        SplitManifest.create(
            dev_task_ids=("test-suite:user_task_0",),
            heldout_task_ids=("test-suite:user_task_0",),
        )
    split = SplitManifest.create(
        dev_task_ids=("test-suite:user_task_0", "test-suite:user_task_1"),
        heldout_task_ids=("test-suite:user_task_2", "test-suite:user_task_3"),
    )
    assert split.assignment("test-suite:user_task_2") is EvaluationSplit.HELDOUT
    assert len(split.sha256) == 64

    first = generate_counterbalanced_schedule(
        ("e0", "e1", "e2", "e3"), arms=("baseline", "sluice"), seed="schedule-v1"
    )
    second = generate_counterbalanced_schedule(
        ("e0", "e1", "e2", "e3"), arms=("baseline", "sluice"), seed="schedule-v1"
    )
    assert first == second
    assert len(first) == 8
    by_episode = {episode: [] for episode in ("e0", "e1", "e2", "e3")}
    for run in first:
        by_episode[run.episode_id].append((run.order, run.arm))
    assert all(sorted(items) in (
        [(1, "baseline"), (2, "sluice")],
        [(1, "sluice"), (2, "baseline")],
    ) for items in by_episode.values())
    assert sum(items[0][1] == "baseline" for items in by_episode.values()) == 2


def test_v122_registry_is_exhaustive_and_marks_unread_email_effectful():
    workspace = V122_TOOL_REGISTRIES["workspace"]
    assert workspace.classify("get_unread_emails") is ToolKind.EFFECTFUL
    assert "get_unread_emails" not in workspace.read_only
    assert workspace.declared == frozenset(workspace.read_only | workspace.effectful)
    assert sum(len(registry.declared) for registry in V122_TOOL_REGISTRIES.values()) == 74


def test_pinned_official_checkout_authenticates_all_executable_python_bytes():
    repository_root = Path(__file__).resolve().parents[4]
    summary = validate_pinned_checkout(repository_root / "external" / "agentdojo-v0.1.35")
    assert summary.python_file_count == 99
    assert summary.python_tree_sha256 == (
        "1d277192874c252ca21ece753b4ab10217958a1f41511b1f7175e919d9c01114"
    )
    assert summary.loaded_asset_file_count == 112
    assert summary.loaded_asset_tree_sha256 == (
        "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
    )
    assert summary.key_file_sha256["uv.lock"] == (
        "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330"
    )


def _fake_official_suites():
    counts = {
        "banking": (16, 9),
        "slack": (21, 5),
        "travel": (20, 7),
        "workspace": (40, 14),
    }
    suites = {}
    for name, (users, injections) in counts.items():
        registry = V122_TOOL_REGISTRIES[name]
        injection_start = 1 if name == "slack" else 0
        suites[name] = SimpleNamespace(
            name=name,
            tools=[SimpleNamespace(name=tool) for tool in sorted(registry.declared)],
            user_tasks={f"user_task_{i}": object() for i in range(users)},
            injection_tasks={
                f"injection_task_{i}": object()
                for i in range(injection_start, injection_start + injections)
            },
        )
    return suites


def test_v122_validator_checks_official_registry_counts_and_949_pairs():
    summary = validate_v122_suites(_fake_official_suites())
    assert summary.benign_task_count == 97
    assert summary.attacked_pair_count == 949
    bad = _fake_official_suites()
    bad["workspace"].tools.pop()
    with pytest.raises(ValueError, match="registry mismatch"):
        validate_v122_suites(bad)


class FakeFunction:
    def __init__(self, name, schema, run):
        self.name = name
        self.parameters_schema = schema
        self.run = run


class FakeRuntime:
    def __init__(self, handlers):
        schemas = {schema.name: schema.parameters_copy() for schema in _schemas()}
        self.functions = {
            name: FakeFunction(name, schemas[name], handler)
            for name, handler in handlers.items()
        }
        self.calls = []

    def run_function(self, env, function, kwargs, raise_on_error=False):
        self.calls.append((function, dict(kwargs)))
        try:
            return self.functions[function].run(env, **kwargs), None
        except Exception as exc:
            if raise_on_error:
                raise
            return "", f"{type(exc).__name__}: {exc}"


class RecordingAuthorizer:
    def __init__(self, outcome=AuthorizationOutcome.RELEASED):
        self.outcome = outcome
        self.calls = []

    def redeem(self, grant, payload):
        self.calls.append((grant, payload))
        return self.outcome


def _grant(manifest) -> SecureEffectGrant:
    template = manifest.templates[0]
    return SecureEffectGrant(
        workflow_id=manifest.workflow_id,
        episode_id=manifest.episode_id,
        template_id=template.template_id,
        tool=template.tool,
        exact_args=template.exact_args,
        agent_id="agentdojo-planner",
        redeemer_id="agentdojo-effect-broker",
        route=object(),
        credential=object(),
        capability=object(),
    )


def _runtime(*, mutating_reader=False, effect_error=False):
    def inspect(env, key):
        value = env[key]
        if mutating_reader:
            env["read_marker"] = True
        return value

    def mutate(env, recipient, amount):
        env.setdefault("sent", []).append((recipient, amount))
        if effect_error:
            raise RuntimeError("secret-bearing failure")
        return "ok"

    return FakeRuntime({"inspect": inspect, "mutate": mutate})


def _broker(runtime=None, authorizer=None):
    manifest = _manifest()
    runtime = runtime or _runtime()
    authorizer = authorizer or RecordingAuthorizer()
    broker = NonOracleToolBroker(
        manifest=manifest,
        registry=_registry(),
        tool_schemas=_schemas(),
        runtime=runtime,
        grants=(_grant(manifest),),
        authorizer=authorizer,
    )
    return broker, runtime, authorizer


def test_broker_executes_read_only_on_copy_and_preserves_original_state():
    broker, runtime, authorizer = _broker()
    env = {"approved": ["alice@example.test"], "answer": "safe"}
    result = broker.execute(ToolRequest("call-read", "inspect", {"key": "answer"}), env)
    assert result.outcome is BrokerOutcome.EXECUTED_READ_ONLY
    assert result.value == "safe"
    assert result.environment is env
    assert authorizer.calls == []
    assert broker.consumed_effect_count == 0
    assert broker.unused_effect_count == 1


def test_broker_detects_declared_read_only_mutation_without_committing_it():
    broker, runtime, _ = _broker(runtime=_runtime(mutating_reader=True))
    env = {"approved": ["alice@example.test"], "answer": "safe"}
    result = broker.execute(ToolRequest("call-read", "inspect", {"key": "answer"}), env)
    assert result.outcome is BrokerOutcome.READ_ONLY_MUTATION
    assert "read_marker" not in env
    assert result.environment is env


def test_broker_redeems_exactly_one_bound_grant_per_effect_and_denies_replay():
    broker, runtime, authorizer = _broker()
    env = {"approved": ["alice@example.test"]}
    request = ToolRequest(
        "call-effect",
        "mutate",
        {"recipient": "alice@example.test", "amount": 7},
    )
    first = broker.execute(request, env)
    assert first.outcome is BrokerOutcome.EXECUTED_EFFECT
    assert first.environment["sent"] == [("alice@example.test", 7)]
    assert env.get("sent") is None
    assert len(authorizer.calls) == 1
    payload = authorizer.calls[0][1]
    assert payload["workflow_id"] == "workflow-1"
    assert payload["episode_id"] == "episode-1"
    assert payload["template_id"] == _manifest().templates[0].template_id
    assert broker.consumed_effect_count == 1
    assert broker.unused_effect_count == 0

    replay = broker.execute(request, first.environment)
    assert replay.outcome is BrokerOutcome.NO_AUTHORIZED_TEMPLATE
    assert len(authorizer.calls) == 1


def test_broker_denies_wrong_args_without_burning_grant():
    broker, runtime, authorizer = _broker()
    env = {"approved": ["alice@example.test"]}
    denied = broker.execute(
        ToolRequest("wrong", "mutate", {"recipient": "mallory@example.test", "amount": 7}),
        env,
    )
    assert denied.outcome is BrokerOutcome.NO_AUTHORIZED_TEMPLATE
    assert not runtime.calls
    assert not authorizer.calls
    assert broker.unused_effect_count == 1


def test_broker_rejects_nested_calls_for_read_only_and_effectful_tools():
    broker, runtime, authorizer = _broker()
    env = {"approved": ["alice@example.test"], "answer": "safe"}
    nested = ToolRequest("nested", "mutate", {"recipient": "x", "amount": 7})
    result = broker.execute(ToolRequest("outer", "inspect", {"key": nested}), env)
    assert result.outcome is BrokerOutcome.NESTED_CALL_DENIED
    result = broker.execute(
        ToolRequest("outer2", "mutate", {"recipient": nested, "amount": 7}), env
    )
    assert result.outcome is BrokerOutcome.NESTED_CALL_DENIED
    assert not runtime.calls
    assert not authorizer.calls


def test_broker_recognizes_agentdojo_shaped_model_as_nested_before_dispatch():
    broker, runtime, authorizer = _broker()
    env = {"approved": ["alice@example.test"], "answer": "safe"}
    nested_model = SimpleNamespace(function="mutate", args={"amount": 7})
    result = broker.execute(
        ToolRequest("outer-model", "inspect", {"key": nested_model}), env
    )
    assert result.outcome is BrokerOutcome.NESTED_CALL_DENIED
    assert not runtime.calls
    assert not authorizer.calls


def test_broker_fails_closed_on_authorizer_denial_and_effect_exception():
    denied_authorizer = RecordingAuthorizer(AuthorizationOutcome.DENIED)
    broker, runtime, _ = _broker(authorizer=denied_authorizer)
    env = {"approved": ["alice@example.test"]}
    request = ToolRequest("x", "mutate", {"recipient": "alice@example.test", "amount": 7})
    denied = broker.execute(request, env)
    assert denied.outcome is BrokerOutcome.AUTHORIZATION_DENIED
    assert not runtime.calls
    # Once redemption is attempted, the local grant is irreversibly retired:
    # a denial/error may be an ambiguous post-commit backend outcome.
    assert broker.unused_effect_count == 0
    assert broker.consumed_effect_count == 1

    broker, runtime, _ = _broker(runtime=_runtime(effect_error=True))
    failed = broker.execute(request, env)
    assert failed.outcome is BrokerOutcome.TOOL_ERROR
    assert failed.environment is env
    assert "sent" not in env
    assert broker.consumed_effect_count == 1


def test_broker_rechecks_complete_registry_and_logs_every_attempt_redacted():
    broker, runtime, authorizer = _broker()
    env = {"approved": ["alice@example.test"], "answer": "safe"}
    runtime.functions["surprise_mutator"] = FakeFunction(
        "surprise_mutator", {"type": "object", "properties": {}}, lambda env: None
    )
    result = broker.execute(ToolRequest("x", "inspect", {"key": "answer"}), env)
    assert result.outcome is BrokerOutcome.REGISTRY_MISMATCH
    assert len(broker.audit_log) == 1
    record = broker.audit_log[0]
    assert record.call_id_sha256 == _sha("sluice-agentdojo-call-id-v1\x00x")
    assert record.tool_sha256 == _sha("sluice-agentdojo-tool-v1\x00inspect")
    assert record.args_sha256 == _sha(canonical_args({"key": "answer"}))
    assert not hasattr(record, "call_id")
    assert not hasattr(record, "tool")
    assert not hasattr(record, "args")
    assert "answer" not in repr(record)


def test_broker_constructor_rejects_missing_grants_and_binding_mismatch():
    manifest = _manifest()
    with pytest.raises(ValueError, match="grant/template mismatch"):
        NonOracleToolBroker(
            manifest=manifest,
            registry=_registry(),
            tool_schemas=_schemas(),
            runtime=_runtime(),
            grants=(),
            authorizer=RecordingAuthorizer(),
        )
    bad = _grant(manifest).replace(episode_id="other")
    with pytest.raises(ValueError, match="grant binding"):
        NonOracleToolBroker(
            manifest=manifest,
            registry=_registry(),
            tool_schemas=_schemas(),
            runtime=_runtime(),
            grants=(bad,),
            authorizer=RecordingAuthorizer(),
        )


def test_durable_grant_issuer_binds_exact_payload_and_uses_unique_nonces(tmp_path):
    from sluice_v2.durable_secure import (
        DurableSecureDomain,
        EffectResult,
        IdempotentEffectHandler,
        ObserverSpec,
        RouteCodebook,
    )
    from sluice_v2.secure import DomainConfig

    key = b"a" * 32
    domain = DurableSecureDomain.create(
        tmp_path / "domain.sqlite",
        config=DomainConfig(
            domain_id="agentdojo-episode-1",
            protected_objects=frozenset({"effect-object"}),
            lifetime_budget_units=8,
            attempt_horizon=2,
            event_charge_units=4,
        ),
        observer_spec=ObserverSpec(
            permitted_value_codes=frozenset({1}),
            observer_spec_id="agentdojo-effect-codebook-v1",
            route_codebooks=(
                RouteCodebook("mutate", frozenset({1}), True),
            ),
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
    base_rule = _org_policy().rules[0]
    repeated_policy = OrganizationPolicy(
        policy_id="two-effect-policy",
        rules=(replace(base_rule, calls=base_rule.calls * 2),),
    )
    manifest = compile_static_policy(
        _policy_input(policy=repeated_policy),
        registry=_registry(),
        workflow_id="workflow-1",
        episode_id="episode-1",
        compiler_id="static-v1",
    )
    redeemer_id = f"pid:{os.getpid()}"
    grants = issue_durable_effect_grants(
        domain,
        manifest,
        route_by_tool={"mutate": route},
        agent_id="agentdojo-planner",
        signing_key=key,
        redeemer_id=redeemer_id,
    )
    assert len(grants) == 2
    credentials = [grant.credential for grant in grants]
    assert len({credential.nonce for credential in credentials}) == 2
    assert all(credential.domain_context == domain.credential_context for credential in credentials)
    assert all(credential.expected_epoch == domain.current_epoch for credential in credentials)
    assert all(credential.expires_at_lifetime_attempt == 2 for credential in credentials)
    broker = NonOracleToolBroker(
        manifest=manifest,
        registry=_registry(),
        tool_schemas=_schemas(),
        runtime=_runtime(),
        grants=grants,
        authorizer=domain,
    )
    result = broker.execute(
        ToolRequest("effect", "mutate", {"recipient": "alice@example.test", "amount": 7}),
        {"approved": ["alice@example.test"]},
    )
    assert result.outcome is BrokerOutcome.EXECUTED_EFFECT
    assert len(domain.transcript) == 1
    assert domain.transcript[0].outcome.value == "released"
