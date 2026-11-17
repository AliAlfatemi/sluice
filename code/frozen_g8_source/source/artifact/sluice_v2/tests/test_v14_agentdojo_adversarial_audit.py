"""Hostile fail-first audit for the non-oracle AgentDojo foundation.

This file is intentionally tests-only.  It encodes reviewer-facing security
contracts that were absent from the initial v11 foundation; it must not be
treated as benchmark-effectiveness evidence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import threading

import pytest

import sluice_v2.evaluation.agentdojo as agentdojo
from sluice_v2.evaluation.agentdojo import (
    AGENTDOJO_COMMIT,
    BENCHMARK_VERSION,
    AbstentionCategory,
    AgentDojoHarnessError,
    ArgumentBinding,
    AuthorizationOutcome,
    BrokerOutcome,
    CallTemplateSpec,
    NonOracleToolBroker,
    OrganizationPolicy,
    PolicyDecision,
    PolicyInput,
    PolicyRule,
    SplitManifest,
    StaticToolSchema,
    ToolRegistry,
    ToolRequest,
    audit_primary_source_for_oracle_access,
    canonical_args,
    compile_static_policy,
    issue_durable_effect_grants,
    validate_pinned_checkout,
    validate_v122_suites,
)
from sluice_v2.tests import test_v11_agentdojo_nonoracle as v11


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "source",
    (
        'def policy(task, env):\n    return getattr(task, "ground_" + "truth")(env)\n',
        'def policy(task, env):\n    return vars(task)["ground_truth"](env)\n',
    ),
)
def test_oracle_audit_rejects_reflective_answer_key_access(tmp_path, source):
    candidate = tmp_path / "reflective_policy.py"
    candidate.write_text(source, encoding="utf-8")
    assert audit_primary_source_for_oracle_access(candidate), (
        "the source audit must detect reflective/string-built answer-key access, "
        "not only direct attribute syntax"
    )


def test_compiler_attestation_cannot_be_redirected_to_a_decoy(
    tmp_path, monkeypatch
):
    decoy = tmp_path / "decoy.py"
    decoy.write_text("# not the compiler that is executing\n", encoding="utf-8")
    monkeypatch.setattr(agentdojo, "__file__", str(decoy))
    with pytest.raises(AgentDojoHarnessError, match="compiler|source|attest"):
        v11._manifest()


def test_compiler_runtime_attestation_is_stable_from_first_execution():
    script = """
import json
from sluice_v2.tests.test_v11_agentdojo_nonoracle import _manifest
print(json.dumps([_manifest().compiler_runtime_sha256 for _ in range(4)]))
"""
    observed = []
    for _ in range(2):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
        )
        observed.extend(__import__("json").loads(completed.stdout))
    assert len(set(observed)) == 1


def test_compiler_runtime_attestation_rejects_live_helper_replacement(monkeypatch):
    monkeypatch.setattr(agentdojo, "_arguments_match_schema", lambda *_args: True)
    with pytest.raises(AgentDojoHarnessError, match="compiler|executable|identity"):
        v11._manifest()


@pytest.mark.parametrize("case", ("overlap", "digest"))
def test_split_direct_construction_revalidates_all_invariants(case):
    if case == "overlap":
        with pytest.raises(AgentDojoHarnessError, match="overlap"):
            SplitManifest(("banking:user_task_0",), ("banking:user_task_0",), "0" * 64)
    else:
        valid = SplitManifest.create(
            dev_task_ids=("banking:user_task_0",),
            heldout_task_ids=("workspace:user_task_0",),
        )
        with pytest.raises(AgentDojoHarnessError, match="digest|sha256"):
            replace(valid, sha256="0" * 64)


def test_split_identifiers_are_suite_qualified():
    with pytest.raises(AgentDojoHarnessError, match="suite|qualified"):
        SplitManifest.create(dev_task_ids=("user_task_0",), heldout_task_ids=())


def test_split_rejects_official_task_ids_outside_the_pinned_registry():
    with pytest.raises(AgentDojoHarnessError, match="registry|identifier"):
        SplitManifest.create(
            dev_task_ids=("banking:user_task_16",), heldout_task_ids=()
        )


def _copy_official_checkout(tmp_path):
    repository_root = Path(__file__).resolve().parents[4]
    official = repository_root / "external" / "agentdojo-v0.1.35"
    candidate = tmp_path / "agentdojo-v0.1.35"
    shutil.copytree(official / "src" / "agentdojo", candidate / "src" / "agentdojo")
    for relative in ("LICENSE", "pyproject.toml", "uv.lock"):
        shutil.copy2(official / relative, candidate / relative)
    return candidate


def test_pinned_checkout_rejects_modified_benchmark_data(tmp_path):
    candidate = _copy_official_checkout(tmp_path)
    environment = candidate / "src" / "agentdojo" / "data" / "suites" / "banking" / "environment.yaml"
    environment.write_bytes(environment.read_bytes() + b"\n# adversarial benchmark mutation\n")
    with pytest.raises(AgentDojoHarnessError, match="data|tree|digest|source"):
        validate_pinned_checkout(candidate)


def test_pinned_checkout_rejects_symlinked_source_or_data_assets(tmp_path):
    candidate = _copy_official_checkout(tmp_path)
    source_root = candidate / "src" / "agentdojo"
    (source_root / "adversarial-alias.txt").symlink_to(
        source_root / "data" / "suites" / "banking" / "environment.yaml"
    )
    with pytest.raises(AgentDojoHarnessError, match="symlink"):
        validate_pinned_checkout(candidate)


def test_pinned_checkout_rejects_symlinked_checkout_root(tmp_path):
    candidate = _copy_official_checkout(tmp_path)
    alias = tmp_path / "checkout-alias"
    alias.symlink_to(candidate, target_is_directory=True)
    with pytest.raises(AgentDojoHarnessError, match="root|symlink"):
        validate_pinned_checkout(alias)


def test_pinned_checkout_rejects_unauthenticated_bytecode_cache(tmp_path):
    candidate = _copy_official_checkout(tmp_path)
    cache = candidate / "src" / "agentdojo" / "__pycache__"
    cache.mkdir()
    (cache / "malicious.cpython-311.pyc").write_bytes(b"unauthenticated bytecode")
    with pytest.raises(AgentDojoHarnessError, match="unauthenticated|file type|source"):
        validate_pinned_checkout(candidate)


def test_policy_manifest_direct_construction_cannot_spoof_source_assets():
    manifest = v11._manifest()
    with pytest.raises(AgentDojoHarnessError, match="source|data|digest"):
        replace(manifest, source_assets_sha256="0" * 64)


def test_v122_validator_rejects_noncanonical_task_identifier_sets():
    suites = v11._fake_official_suites()
    suites["banking"].user_tasks = {
        f"user_task_{100 + index}": object() for index in range(16)
    }
    with pytest.raises(AgentDojoHarnessError, match="task identifier|task-count"):
        validate_v122_suites(suites)


def _compile_schema_case(parameters, value):
    prompt = "Authorize one schema-constrained effect."
    schemas = (StaticToolSchema("mutate", parameters),)
    registry = ToolRegistry(
        "schema-suite", read_only=frozenset(), effectful=frozenset({"mutate"})
    )
    policy = OrganizationPolicy(
        "schema-policy",
        (
            PolicyRule(
                "schema-rule",
                "schema-suite",
                _sha(prompt),
                (
                    CallTemplateSpec(
                        "mutate", {"value": ArgumentBinding.literal(value)}
                    ),
                ),
            ),
        ),
    )
    policy_input = PolicyInput(
        source_commit=AGENTDOJO_COMMIT,
        benchmark_version=BENCHMARK_VERSION,
        suite_name="schema-suite",
        task_id="schema-suite:user_task_0",
        trusted_user_prompt=prompt,
        pre_injection_state={},
        tool_schemas=schemas,
        organization_policy=policy,
        split_manifest=SplitManifest.create(
            dev_task_ids=("schema-suite:user_task_0",), heldout_task_ids=()
        ),
    )
    return compile_static_policy(
        policy_input,
        registry=registry,
        workflow_id="schema-workflow",
        episode_id="schema-episode",
        compiler_id="schema-compiler",
    )


@pytest.mark.parametrize(
    ("parameters", "value"),
    (
        (
            {
                "type": "object",
                "properties": {
                    "value": {
                        "anyOf": [{"type": "string"}, {"type": "null"}]
                    }
                },
                "required": ["value"],
                "additionalProperties": False,
            },
            {"not": "a string or null"},
        ),
        (
            {
                "type": "object",
                "properties": {
                    "value": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["value"],
                "additionalProperties": False,
            },
            [{"function": "mutate", "args": {}}],
        ),
        (
            {
                "$defs": {
                    "Permission": {"type": "string", "enum": ["r", "rw"]}
                },
                "type": "object",
                "properties": {"value": {"$ref": "#/$defs/Permission"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            "admin",
        ),
        (
            {
                "type": "object",
                "properties": {"value": {"enum": [1]}},
                "required": ["value"],
                "additionalProperties": False,
            },
            True,
        ),
    ),
)
def test_compiler_enforces_complete_json_schema_semantics(parameters, value):
    manifest = _compile_schema_case(parameters, value)
    assert manifest.decision is PolicyDecision.ABSTAINED
    assert manifest.abstention is AbstentionCategory.SCHEMA_MISMATCH


def test_tiny_multiple_of_and_nonfinite_schema_numbers_have_finite_results():
    parameters = {
        "type": "object",
        "properties": {
            "value": {"type": "number", "multipleOf": 1e-323}
        },
        "required": ["value"],
        "additionalProperties": False,
    }
    # This is mathematically an exact multiple.  The old float quotient became
    # infinity and escaped through round(inf); exact rational arithmetic must
    # return a finite compiler decision instead.
    manifest = _compile_schema_case(parameters, 1)
    assert manifest.decision is PolicyDecision.COMPILED
    with pytest.raises(AgentDojoHarnessError, match="finite"):
        StaticToolSchema(
            "bad-number",
            {
                "type": "object",
                "properties": {
                    "value": {"type": "number", "multipleOf": math.nan}
                },
            },
        )


class _Function:
    def __init__(self, name, schema):
        self.name = name
        self.parameters_schema = schema


class _ReadRuntime:
    def __init__(self, schema, handler):
        self.functions = {"inspect": _Function("inspect", schema)}
        self.handler = handler
        self.calls = []

    def run_function(self, environment, function, kwargs, raise_on_error=False):
        self.calls.append((function, kwargs))
        return self.handler(environment, **kwargs), None


def _read_broker(schema, handler):
    prompt = "Inspect a value."
    schemas = (StaticToolSchema("inspect", schema),)
    registry = ToolRegistry(
        "read-suite", read_only=frozenset({"inspect"}), effectful=frozenset()
    )
    policy = OrganizationPolicy(
        "read-policy",
        (PolicyRule("read-rule", "read-suite", _sha(prompt), ()),),
    )
    policy_input = PolicyInput(
        source_commit=AGENTDOJO_COMMIT,
        benchmark_version=BENCHMARK_VERSION,
        suite_name="read-suite",
        task_id="read-suite:user_task_0",
        trusted_user_prompt=prompt,
        pre_injection_state={},
        tool_schemas=schemas,
        organization_policy=policy,
        split_manifest=SplitManifest.create(
            dev_task_ids=("read-suite:user_task_0",), heldout_task_ids=()
        ),
    )
    manifest = compile_static_policy(
        policy_input,
        registry=registry,
        workflow_id="read-workflow",
        episode_id="read-episode",
        compiler_id="read-compiler",
    )
    runtime = _ReadRuntime(schema, handler)
    broker = NonOracleToolBroker(
        manifest=manifest,
        registry=registry,
        tool_schemas=schemas,
        runtime=runtime,
        grants=(),
        authorizer=object(),
    )
    return broker, runtime


def test_dict_shaped_nested_function_call_is_denied_before_dispatch():
    schema = {
        "type": "object",
        "properties": {"payload": {"type": "object"}},
        "required": ["payload"],
        "additionalProperties": False,
    }
    broker, runtime = _read_broker(schema, lambda _environment, payload: payload)
    nested = {"function": "mutate", "args": {"recipient": "mallory"}}
    result = broker.execute(ToolRequest("nested-input", "inspect", {"payload": nested}), {})
    assert result.outcome is BrokerOutcome.NESTED_CALL_DENIED
    assert runtime.calls == []


def test_read_only_function_call_output_cannot_escape_the_broker():
    nested = ToolRequest("nested-output", "mutate", {"recipient": "mallory"})
    broker, runtime, _ = v11._broker(
        runtime=v11.FakeRuntime(
            {
                "inspect": lambda _environment, key: nested,
                "mutate": lambda environment, recipient, amount: None,
            }
        )
    )
    result = broker.execute(
        ToolRequest("read", "inspect", {"key": "answer"}),
        {"answer": "safe", "approved": ["alice@example.test"]},
    )
    assert result.outcome is BrokerOutcome.NESTED_CALL_DENIED
    assert result.value is None


def test_function_call_nested_inside_output_object_cannot_escape_the_broker():
    nested = ToolRequest("nested-output", "mutate", {"recipient": "mallory"})
    wrapped = SimpleNamespace(payload=nested)
    broker, _, _ = v11._broker(
        runtime=v11.FakeRuntime(
            {
                "inspect": lambda _environment, key: wrapped,
                "mutate": lambda environment, recipient, amount: None,
            }
        )
    )
    result = broker.execute(
        ToolRequest("read", "inspect", {"key": "answer"}),
        {"answer": "safe", "approved": ["alice@example.test"]},
    )
    assert result.outcome is BrokerOutcome.NESTED_CALL_DENIED
    assert result.value is None


def test_audit_record_identifiers_cannot_exfiltrate_argument_contents():
    secret = "sensitive-recipient@example.test"
    broker, _, _ = v11._broker()
    result = broker.execute(
        ToolRequest(secret, "inspect", {"key": secret}),
        {secret: "value", "approved": ["alice@example.test"]},
    )
    assert result.outcome is BrokerOutcome.EXECUTED_READ_ONLY
    assert secret not in repr(broker.audit_log[0])


def _durable_broker(tmp_path, authorizer_factory):
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
            domain_id="agentdojo-adversarial-episode",
            protected_objects=frozenset({"effect-object"}),
            lifetime_budget_units=8,
            attempt_horizon=2,
            event_charge_units=4,
        ),
        observer_spec=ObserverSpec(
            permitted_value_codes=frozenset({1}),
            observer_spec_id="agentdojo-adversarial-effect-codebook-v1",
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
    manifest = v11._manifest()
    grants = issue_durable_effect_grants(
        domain,
        manifest,
        route_by_tool={"mutate": route},
        agent_id="agentdojo-planner",
        signing_key=key,
        redeemer_id=f"pid:{os.getpid()}",
    )
    authorizer = authorizer_factory(domain)
    broker = NonOracleToolBroker(
        manifest=manifest,
        registry=v11._registry(),
        tool_schemas=v11._schemas(),
        runtime=v11._runtime(),
        grants=grants,
        authorizer=authorizer,
    )
    return domain, broker


class _ConsumeThenRaise:
    def __init__(self, domain, error_type):
        self.domain = domain
        self.error_type = error_type

    def attempt(self, *args, **kwargs):
        event = self.domain.attempt(*args, **kwargs)
        assert event.outcome.value == "released"
        raise self.error_type("post-consumption interruption")


@pytest.mark.parametrize("error_type", (RuntimeError, KeyboardInterrupt))
def test_indeterminate_authorizer_failure_is_finite_audited_and_burns_local_grant(
    tmp_path, error_type
):
    domain, broker = _durable_broker(
        tmp_path, lambda durable: _ConsumeThenRaise(durable, error_type)
    )
    escaped = None
    result = None
    try:
        result = broker.execute(
            ToolRequest(
                "effect",
                "mutate",
                {"recipient": "alice@example.test", "amount": 7},
            ),
            {"approved": ["alice@example.test"]},
        )
    except BaseException as error:  # the contract requires a finite result
        escaped = error
    assert len(domain.transcript) == 1
    assert domain.transcript[0].outcome.value == "released"
    assert escaped is None
    assert result is not None and result.outcome is BrokerOutcome.AUTHORIZER_ERROR
    assert broker.unused_effect_count == 0
    assert broker.consumed_effect_count == 1
    assert len(broker.audit_log) == 1


@pytest.mark.parametrize("function", ("inspect", "mutate"))
def test_runtime_baseexception_is_coarsened_and_audited(function):
    def abort(*_args, **_kwargs):
        raise KeyboardInterrupt("backend interruption")

    runtime = v11.FakeRuntime(
        {
            "inspect": abort if function == "inspect" else lambda env, key: env[key],
            "mutate": abort if function == "mutate" else lambda env, recipient, amount: None,
        }
    )
    broker, _, _ = v11._broker(runtime=runtime)
    request = (
        ToolRequest("read", "inspect", {"key": "answer"})
        if function == "inspect"
        else ToolRequest(
            "effect", "mutate", {"recipient": "alice@example.test", "amount": 7}
        )
    )
    escaped = None
    result = None
    try:
        result = broker.execute(
            request,
            {"answer": "safe", "approved": ["alice@example.test"]},
        )
    except BaseException as error:  # the contract requires a finite result
        escaped = error
    assert escaped is None
    assert result is not None and result.outcome is BrokerOutcome.TOOL_ERROR
    assert len(broker.audit_log) == 1
    if function == "mutate":
        assert broker.unused_effect_count == 0
        assert broker.consumed_effect_count == 1


def test_concurrent_replay_has_one_effect_and_consistent_audit_counters():
    broker, runtime, authorizer = v11._broker()
    request_count = 24
    barrier = threading.Barrier(request_count)

    def run(index):
        barrier.wait(timeout=10)
        return broker.execute(
            ToolRequest(
                f"call-{index}",
                "mutate",
                {"recipient": "alice@example.test", "amount": 7},
            ),
            {"approved": ["alice@example.test"]},
        ).outcome

    with ThreadPoolExecutor(max_workers=request_count) as pool:
        outcomes = list(pool.map(run, range(request_count)))
    assert outcomes.count(BrokerOutcome.EXECUTED_EFFECT) == 1
    assert outcomes.count(BrokerOutcome.NO_AUTHORIZED_TEMPLATE) == request_count - 1
    assert len(runtime.calls) == 1
    assert len(authorizer.calls) == 1
    audit = broker.audit_log
    assert [record.sequence for record in audit] == list(range(1, request_count + 1))
    assert all(
        (record.consumed_effect_count, record.unused_effect_count) == (1, 0)
        for record in audit
    )


def test_concurrent_argument_mutation_cannot_change_executed_call_audit_digest():
    entered = threading.Event()
    release = threading.Event()
    observed = []

    def inspect(_environment, values):
        observed.append(tuple(values))
        entered.set()
        assert release.wait(timeout=10)
        return "ok"

    schema = {
        "type": "object",
        "properties": {
            "values": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["values"],
        "additionalProperties": False,
    }
    broker, _ = _read_broker(schema, inspect)
    values = ["before"]
    request = ToolRequest("mutable", "inspect", {"values": values})
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(broker.execute, request, {})
        assert entered.wait(timeout=10)
        values[:] = ["after"]
        release.set()
        result = future.result(timeout=10)
    assert result.outcome is BrokerOutcome.EXECUTED_READ_ONLY
    assert observed == [("before",)]
    assert broker.audit_log[0].args_sha256 == _sha(
        canonical_args({"values": ["before"]})
    )
