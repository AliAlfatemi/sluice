#!/usr/bin/env python3
"""Sluice ``sluice_nonoracle`` condition for live AgentDojo runs (C2 fork).

C2 FORK OF ``runs/sluice_nonoracle_19a3810_20260822_s1/sluice_nonoracle_lib.py``.
S1's bytes are untouched; this file is produced from them by
``fork_harness_c2.py``, which asserts the source digest before writing.
The four wired-in changes are the C1 corrections that S1 predates:
``DerivedEffectAuthority`` in place of the fixed-charge, route-per-tool
``EffectAuthority``; a per-episode ``EffectChargeLedger`` report emitted before
the durable domain is closed; result binding inside the benign element so the
ledger also sees the tool RESULT; and no reachable reference to the old
authority name.  See ``fork_harness_c2.py`` for the full rationale.

Original docstring follows.


This is the treatment arm of the committed primary comparison
``sluice_nonoracle_vs_undefended``.  It is assembled entirely from the
project's own reference monitor -- ``compile_static_policy``,
``NonOracleToolBroker``, ``issue_durable_effect_grants``,
``OfficialBrokerExecutor`` and ``OfficialBrokerPipelineElement`` -- and adds
only (a) the policy-authoring stage those components require as input and
(b) the cross-interpreter transport that stage needs, because the compiler
cannot execute on the AgentDojo runtime's Python.

What Sluice actually enforces here, restated from the code it enforces with:

  * Read-only tools run on a deep copy, and the result is rejected if the copy
    was mutated or if the value contains a nested call.
  * An effectful tool runs only if (tool, byte-exact canonical arguments)
    matches an unused compiled template AND a durable authority releases the
    bound capability/credential for that template.  Templates are single use.
  * Templates come from a policy compiled *before the episode*, from the
    trusted user prompt and the pre-injection environment only.  Nothing that
    arrives through a tool result can create, widen or revive one.

Non-oracle discipline, enforced structurally rather than promised:

  * The policy-authoring stage runs the agent on the **uninjected** environment
    and records the effectful calls it actually attempted.  It never consults
    the benchmark's answer key, its utility or security checkers, or any
    injection task.  ``audit_primary_source_for_oracle_access`` is run over
    this module, the wire module and the policy process, and a nonempty finding
    set is fatal.
  * The compiler runs in a **separate process on a different interpreter** and
    receives JSON only -- no task object, no environment object, no suite, no
    scorer.  That is the boundary the compiler's own docstring asks for.
  * The policy-author split (24 development / 73 held-out user tasks, digest
    ``2f5ac284...``) is carried into every manifest, so which side of the split
    a result came from is recorded in the artefact itself.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping

# C2: the corrected effect mechanism.  `effect_charging` is byte-identical to
# the copy committed with C1 and validated there; this fork constructs its
# classes directly instead of going through C1's `sluice_charging_integration`
# shim, which rebound module globals at import time.
import effect_charging as charging

HARNESS_VARIANT = "c2-derived-charging"

# `_bind` resolves the authority through these module-level names.  They are
# module constants rather than the bare class names S1 used, so that the
# runner can assert -- before any arm -- which implementation the harness will
# actually construct, and so that a stale reference to S1's `EffectAuthority`
# name is a NameError instead of a silent revert to the fixed-charge authority.
EFFECT_AUTHORITY_IMPL = charging.DerivedEffectAuthority
NULL_EFFECT_AUTHORITY_IMPL = charging.NullEffectAuthority

WIRE_REQUEST_SCHEMA = "sluice-agentdojo-policy-request-v1"
POLICY_AUTHOR_SPLIT_SEED = "sluice-agentdojo-policy-author-split-v1:8675309"
COMMITTED_SPLIT_SHA256 = (
    "2f5ac284802967fb7fb373367b371fda0a04aa0a724a046742aeb75676b8df0c"
)
V122_USER_TASK_COUNTS = {"banking": 16, "slack": 21, "travel": 20, "workspace": 40}
POLICY_ID = "sluice-agentdojo-nonoracle-policy-v1"
COMPILER_ID = "sluice-static-policy-compiler-v1"
EFFECT_PROTECTED_OBJECT = "agentdojo-effect"
EFFECT_AGENT_ID = "sluice-agentdojo-agent"


# ----------------------------------------------------------------- split

def policy_author_split() -> dict:
    """Reproduce the committed 24/73 policy-author split and prove it by digest."""

    development: list[str] = []
    heldout: list[str] = []
    for suite_name in sorted(V122_USER_TASK_COUNTS):
        count = V122_USER_TASK_COUNTS[suite_name]
        ids = [f"{suite_name}:user_task_{index}" for index in range(count)]
        ordered = sorted(
            ids,
            key=lambda task_id: hashlib.sha256(
                b"sluice-agentdojo-policy-author-split-order-v1"
                + b"\0"
                + f"{POLICY_AUTHOR_SPLIT_SEED}\0{task_id}".encode("utf-8")
            ).hexdigest(),
        )
        development.extend(ordered[: count // 4])
        heldout.extend(ordered[count // 4 :])
    wire = {
        "schema_version": "sluice-agentdojo-policy-author-split-v1",
        "selection_seed": POLICY_AUTHOR_SPLIT_SEED,
        "development_task_ids": sorted(development),
        "heldout_task_ids": sorted(heldout),
    }
    committed = hashlib.sha256(
        b"sluice-agentdojo-principal-wire-v1"
        + b"\0"
        + json.dumps(
            wire, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    if committed != COMMITTED_SPLIT_SHA256:
        raise RuntimeError(
            f"policy-author split reproduction failed: {committed} != "
            f"{COMMITTED_SPLIT_SHA256}"
        )
    return {
        "dev_task_ids": sorted(development),
        "heldout_task_ids": sorted(heldout),
        "committed_sha256": committed,
    }


# --------------------------------------------------- policy authoring stage

class AuthoredPlan:
    """Effectful calls one agent attempted on the uninjected environment."""

    __slots__ = (
        "task_id", "suite_name", "prompt", "calls", "dropped", "stats",
        "failure_exception",
    )

    def __init__(self, task_id: str, suite_name: str, prompt: str) -> None:
        self.task_id = task_id
        self.suite_name = suite_name
        self.prompt = prompt
        self.calls: list[dict] = []
        self.dropped: list[dict] = []
        self.stats: dict = {}
        self.failure_exception: BaseException | None = None


def clean_environment(suite: Any, user_task: Any) -> Any:
    """The trusted, uninjected environment for one user task."""

    environment = suite.load_and_inject_default_environment({})
    return user_task.init_environment(environment)


def author_plan_for_task(
    *,
    foundation: Any,
    suite: Any,
    user_task: Any,
    task_id: str,
    pipeline: Any,
    runtime_class: Any,
    timeout_alarm: Any = None,
) -> tuple[AuthoredPlan, Any]:
    """Run the agent once on the uninjected environment and record its effects.

    Returns the authored plan and the clean pre-injection environment.  No
    scorer is called, no injection task is loaded and no answer key is read;
    the only benchmark objects touched are the suite's tools, the task's own
    class-level prompt, and the default environment.
    """

    registry = foundation.V122_TOOL_REGISTRIES[suite.name]
    prompt = type(user_task).PROMPT
    plan = AuthoredPlan(task_id, suite.name, prompt)
    environment = clean_environment(suite, user_task)
    frozen_state = copy.deepcopy(environment).model_dump(mode="json")
    runtime = runtime_class(suite.tools)
    began = time.time()
    messages: list = []
    error = None
    try:
        _, _, _env, messages, _ = pipeline.query(prompt, runtime, environment)
    except BaseException as exc:  # noqa: BLE001
        plan.failure_exception = exc
        error = repr(exc)[:400]
    plan.stats = {
        "seconds": round(time.time() - began, 2),
        "message_count": len(messages),
        "error": error,
    }
    schemas = {
        schema.name: schema
        for schema in foundation.static_tool_schemas_from_suite(suite)
    }
    effect_attempts = 0
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            name = getattr(call, "function", None)
            args = getattr(call, "args", None)
            if name is None and isinstance(call, dict):
                name = call.get("function")
                args = call.get("args")
            if name not in registry.effectful:
                continue
            effect_attempts += 1
            if not isinstance(args, Mapping) or any(
                type(key) is not str for key in args
            ):
                plan.dropped.append({"tool": name, "reason": "arguments_not_a_mapping"})
                continue
            try:
                thawed = json.loads(json.dumps(dict(args)))
            except BaseException:  # noqa: BLE001
                plan.dropped.append({"tool": name, "reason": "arguments_not_json"})
                continue
            # The organization does not write a policy rule for a call that
            # does not satisfy the tool's own declared schema.  Use the exact
            # predicate the compiler uses so a surviving call cannot later
            # abstain the whole task with SCHEMA_MISMATCH.
            if not foundation._arguments_match_schema(thawed, schemas[name]):
                plan.dropped.append({"tool": name, "reason": "schema_mismatch"})
                continue
            try:
                exact = foundation.canonical_args(thawed)
            except BaseException:  # noqa: BLE001
                plan.dropped.append({"tool": name, "reason": "not_canonicalisable"})
                continue
            plan.calls.append({"tool": name, "args": thawed, "exact_args": exact})
    plan.stats["effect_attempts_observed"] = effect_attempts
    plan.stats["authored_call_count"] = len(plan.calls)
    plan.stats["dropped_call_count"] = len(plan.dropped)
    plan.stats["state_sha256"] = hashlib.sha256(
        json.dumps(frozen_state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    plan.stats["pre_injection_state"] = frozen_state
    return plan, environment


# ------------------------------------------------------------- request wire

def build_policy_request(
    *,
    foundation: Any,
    suites: Mapping[str, Any],
    plans: Mapping[str, AuthoredPlan],
    episode_ids_by_task: Mapping[str, list[str]],
    split: Mapping[str, Any],
    execution_binding: Mapping[str, Any],
) -> dict:
    """Assemble the data-only request the policy process compiles."""

    suite_schema_wire: dict[str, list] = {}
    for suite_name in sorted({plan.suite_name for plan in plans.values()}):
        suite_schema_wire[suite_name] = [
            schema.wire()
            for schema in foundation.static_tool_schemas_from_suite(suites[suite_name])
        ]
    # SplitManifest carries its own, different, schema digest.  Both are
    # recorded so neither can be silently substituted for the other, and the
    # SplitManifest digest is taken from the module itself rather than
    # reimplemented here.
    split_manifest_sha256 = foundation.SplitManifest.create(
        dev_task_ids=split["dev_task_ids"],
        heldout_task_ids=split["heldout_task_ids"],
    ).sha256
    prompt_keys: dict[tuple[str, str], str] = {}
    tasks = []
    for task_id in sorted(plans):
        plan = plans[task_id]
        key = (
            plan.suite_name,
            hashlib.sha256(plan.prompt.encode("utf-8")).hexdigest(),
        )
        if key in prompt_keys:
            raise RuntimeError(
                "two user tasks in one suite share a byte-identical prompt "
                f"({prompt_keys[key]} and {task_id}); the compiler would "
                "abstain with AMBIGUOUS_RULE"
            )
        prompt_keys[key] = task_id
        tasks.append(
            {
                "task_id": task_id,
                "suite_name": plan.suite_name,
                "workflow_id": task_id,
                "trusted_user_prompt": plan.prompt,
                "pre_injection_state": plan.stats["pre_injection_state"],
                "expected_state_sha256": foundation._json_wire_digest(
                    plan.stats["pre_injection_state"]
                ),
                "authored_calls": [
                    {
                        "tool": call["tool"],
                        "arguments": {
                            name: {"source": "literal", "value": value}
                            for name, value in call["args"].items()
                        },
                    }
                    for call in plan.calls
                ],
                "policy_authoring": {
                    "terminal_kind": plan.stats.get("terminal_kind"),
                    "policy_origin": plan.stats.get("policy_origin"),
                    "attempt_count": plan.stats.get("attempt_count"),
                    "context_overflow_evidence": plan.stats.get(
                        "context_overflow_evidence"
                    ),
                    "context_overflow_classifier_sha256": plan.stats.get(
                        "context_overflow_classifier_sha256"
                    ),
                    "context_overflow_fallback_sha256": plan.stats.get(
                        "context_overflow_fallback_sha256"
                    ),
                },
                "episode_ids": sorted(episode_ids_by_task[task_id]),
            }
        )
    return {
        "schema": WIRE_REQUEST_SCHEMA,
        "agentdojo_commit": foundation.AGENTDOJO_COMMIT,
        "benchmark_version": foundation.BENCHMARK_VERSION,
        "policy_id": POLICY_ID,
        "compiler_id": COMPILER_ID,
        "execution_binding": dict(execution_binding),
        "split": {
            "dev_task_ids": list(split["dev_task_ids"]),
            "heldout_task_ids": list(split["heldout_task_ids"]),
            "expected_policy_author_split_sha256": split["committed_sha256"],
            "expected_split_manifest_sha256": split_manifest_sha256,
        },
        "suite_tool_schemas": suite_schema_wire,
        "tasks": tasks,
    }


def run_policy_process(
    *,
    interpreter: Path,
    policy_process: Path,
    request: Mapping[str, Any],
    request_path: Path,
    bundle_path: Path,
    timeout_s: float = 3600.0,
    monitor_root: str | None = None,
) -> dict:
    """Compile in a separate process on the interpreter the compiler requires."""

    payload = json.dumps(
        request, sort_keys=True, ensure_ascii=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if request_path.exists() or request_path.is_symlink():
        raise RuntimeError("policy request is create-only")
    if bundle_path.exists() or bundle_path.is_symlink():
        raise RuntimeError("policy bundle is create-only")
    descriptor = os.open(
        str(request_path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_fd = os.open(str(request_path.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    completed = subprocess.run(
        [str(interpreter), str(policy_process), str(request_path), str(bundle_path)],
        capture_output=True,
        timeout=timeout_s,
        env={
            **({"SLUICE_MONITOR_ROOT": str(monitor_root)} if monitor_root else {}),
            "PATH": "/usr/bin:/bin",
            "HOME": os.environ.get("HOME", "/tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "NO_COLOR": "1",
        },
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "policy process failed: rc="
            f"{completed.returncode} stderr={completed.stderr.decode('utf-8', 'replace')[-2000:]}"
        )
    return json.loads(bundle_path.read_bytes())


def load_manifests(bundle: Mapping[str, Any], foundation: Any, wire_module: Any) -> dict:
    """Rebuild exact PolicyManifest objects and re-check every recorded digest."""

    if bundle.get("schema") != "sluice-agentdojo-policy-manifest-bundle-v1":
        raise RuntimeError("unsupported manifest bundle schema")
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    if wire_module.digest(body) != bundle["bundle_sha256"]:
        raise RuntimeError("manifest bundle digest mismatch")
    if bundle["oracle_audit"] != {
        "compiler_findings": [],
        "policy_process_findings": [],
        "wire_module_findings": [],
    }:
        raise RuntimeError(f"policy path oracle audit is nonempty: {bundle['oracle_audit']}")
    manifests = {}
    for episode_id, wire in bundle["manifests"].items():
        recorded = wire["manifest_sha256"]
        body = {k: v for k, v in wire.items() if k != "manifest_sha256"}
        if wire_module.digest(body) != recorded:
            raise RuntimeError(f"manifest digest mismatch for {episode_id}")
        manifest = wire_module.manifest_from_wire(body, foundation)
        if manifest.episode_id != episode_id:
            raise RuntimeError("manifest episode identity mismatch")
        manifests[episode_id] = manifest
    return manifests


# --------------------------------------------------------- effect authority

class DurableGrantRedeemer:
    """One-shot authorizer over a real durable secure domain.

    Modelled line for line on ``SingletonAuthorizationClient.redeem`` in the
    audited ``agentdojo_live`` module: it identity-checks the grant, compares
    the supplied payload against the grant's own payload by digest, retires the
    template locally before any ambiguous step, and then asks the durable
    authority for a decision using the grant's real route, signed attempt
    credential and issued capability.

    The one difference from ``SingletonAuthorizationClient``, recorded rather
    than hidden: that class sends a ``ModelRequest`` over an abstract AF_UNIX
    socket to a separate ``SingletonMonitorService`` process and authenticates
    the monitor by ``SO_PEERCRED``; this class calls ``DurableSecureDomain
    .attempt`` in the same process.  The authorisation *decision* -- signature
    verification, capability redemption, epoch and attempt-budget accounting,
    and the durable transcript -- is made by the same code either way.  The
    separate-process monitor additionally requires a third, distinct broker
    process, which this harness does not yet have.

    ``NonOracleToolBroker`` seals ``type(authorizer).redeem`` at construction
    and the audited ``OfficialBrokerExecutor`` requires that attribute to
    exist, so this must be a real method on a real class, not a closure.
    """

    __slots__ = ("_domain", "_grant_by_id", "_consumed", "_lock")

    def __init__(self, domain: Any, grants: tuple) -> None:
        self._domain = domain
        self._grant_by_id = {grant.template_id: grant for grant in grants}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def redeem(self, grant: Any, payload: Any) -> Any:
        from sluice_v2.evaluation.agentdojo import AuthorizationOutcome
        from sluice_v2.observer import EventKind, OutcomeCode, TranscriptEvent

        if type(payload) is not dict:
            return AuthorizationOutcome.ERROR
        expected = self._grant_by_id.get(getattr(grant, "template_id", None))
        if expected is None or grant is not expected:
            return AuthorizationOutcome.ERROR
        try:
            supplied = _payload_digest(dict(payload))
            wanted = _payload_digest(expected.payload())
        except BaseException:  # noqa: BLE001
            return AuthorizationOutcome.ERROR
        if supplied != wanted:
            return AuthorizationOutcome.ERROR
        with self._lock:
            if grant.template_id in self._consumed:
                return AuthorizationOutcome.ERROR
            self._consumed.add(grant.template_id)
        try:
            event = self._domain.attempt(
                grant.route,
                grant.payload(),
                credential=grant.credential,
                capability=grant.capability,
                redeemer_id=grant.redeemer_id,
            )
        except BaseException:  # noqa: BLE001
            return AuthorizationOutcome.ERROR
        if type(event) is not TranscriptEvent or event.kind is not EventKind.ATTEMPT:
            return AuthorizationOutcome.ERROR
        return (
            AuthorizationOutcome.RELEASED
            if event.outcome is OutcomeCode.RELEASED
            else AuthorizationOutcome.DENIED
        )


def _payload_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        b"sluice-agentdojo-singleton-grant-payload-v1"
        + b"\0"
        + json.dumps(
            dict(payload), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class LegacyFixedChargeEffectAuthority:
    """S1's authority.  RETAINED FOR DIFF AND TEST REFERENCE; NOT CONSTRUCTED.

    Two defects, both corrected by `effect_charging.DerivedEffectAuthority`:

      * the per-event charge is a TRANSCRIPTION of the durable domain's own
        support bound, copied into this file, with nothing detecting it
        drifting from the implementation it copies; and
      * routes are keyed per TOOL with the single public value {1}, so two
        authorised effects on one tool share one durable gate and every
        released effect in an episode produces the identical transcript event
        `value_code=1` -- at the durable layer the trust is episode scoped and
        the transcript cannot name which effect was released.

    No alias to the old name `EffectAuthority` is left in this module, so any
    stale reference fails closed at import rather than silently reverting.
    """

    def __init__(self, *, foundation: Any, manifest: Any, scratch: Path) -> None:
        from sluice_v2.durable_secure import (
            DurableSecureDomain,
            EffectResult,
            IdempotentEffectHandler,
            ObserverSpec,
            RouteCodebook,
        )
        from sluice_v2.secure import DomainConfig

        tools = sorted({template.tool for template in manifest.templates})
        if not tools:
            raise ValueError("effect authority requires at least one template")
        count = len(manifest.templates)
        key = secrets.token_bytes(32)
        path = scratch / f"effects-{secrets.token_hex(8)}.sqlite"
        # The durable domain refuses to seal unless one event's charge can carry
        # the transcript's own support alphabet.  Its bound, verbatim from
        # durable_secure.py, is
        #     support = 4 + sum(len(public_values) + 5 for each route)
        #     required = (support - 1).bit_length() * units_per_bit
        # With one public value per route that is 4 + 6 * len(tools).  A fixed
        # charge of 4 therefore fails the moment a manifest needs three or more
        # DISTINCT effect tools -- observed on real workspace and slack tasks as
        # "event charge is below the sealed ObserverSpec support bound".
        support = 4 + sum(1 + 5 for _ in tools)
        charge = max(4, (support - 1).bit_length())
        self._domain = DurableSecureDomain.create(
            path,
            config=DomainConfig(
                domain_id="sluice-agentdojo-effects",
                protected_objects=frozenset({EFFECT_PROTECTED_OBJECT}),
                lifetime_budget_units=charge * count,
                attempt_horizon=count,
                event_charge_units=charge,
            ),
            observer_spec=ObserverSpec(
                permitted_value_codes=frozenset({1}),
                observer_spec_id="sluice-agentdojo-effect-codebook-v1",
                route_codebooks=tuple(
                    RouteCodebook(tool, frozenset({1}), True) for tool in tools
                ),
                accounting_units_per_bit=1,
            ),
            agent_keys={EFFECT_AGENT_ID: key},
            reauthorization_keys={"authority": secrets.token_bytes(32)},
            handler_registry={
                "authorize": IdempotentEffectHandler(
                    execute=lambda request: EffectResult.for_request(request, 1),
                    reconcile=lambda _request: None,
                )
            },
        )
        routes = {
            tool: self._domain.register_route(
                name=tool,
                protected_object=EFFECT_PROTECTED_OBJECT,
                handler_key="authorize",
                public_values=frozenset({1}),
                requires_capability=True,
            )
            for tool in tools
        }
        self._domain.seal()
        self._domain.activate()
        self.grants = foundation.issue_durable_effect_grants(
            self._domain,
            manifest,
            route_by_tool=routes,
            agent_id=EFFECT_AGENT_ID,
            signing_key=key,
            redeemer_id=f"pid:{os.getpid()}",
        )
        self.path = path

        self._redeemer = DurableGrantRedeemer(self._domain, self.grants)

    @property
    def authorizer(self) -> Any:
        return self._redeemer

    @property
    def domain(self) -> Any:
        return self._domain

    @property
    def transcript_length(self) -> int:
        return len(self._domain.transcript)

    def close(self) -> None:
        try:
            self._domain.close()
        finally:
            try:
                for suffix in ("", "-wal", "-shm"):
                    candidate = Path(str(self.path) + suffix)
                    if candidate.exists():
                        candidate.unlink()
            except OSError:
                pass


class LegacyNullEffectAuthority:
    """S1's null authority.  RETAINED FOR DIFF REFERENCE; NOT CONSTRUCTED.

    Superseded by `effect_charging.NullEffectAuthority`, which additionally
    carries an empty `EffectChargeLedger` so that the per-episode cross-binding
    report has the same shape for a zero-template manifest as for any other.

    Original docstring follows.

    Authority for a manifest that compiled zero templates.

    A compiled policy with no templates authorises no effect at all, so no
    durable grant exists to redeem.  ``redeem`` is still defined, and still
    fails closed, because ``NonOracleToolBroker`` seals the authorizer's
    ``redeem`` identity at construction.
    """

    grants: tuple = ()

    def redeem(self, grant: Any, payload: Any) -> Any:
        from sluice_v2.evaluation.agentdojo import AuthorizationOutcome

        return AuthorizationOutcome.DENIED

    @property
    def authorizer(self) -> Any:
        return self

    @property
    def transcript_length(self) -> int:
        return 0

    def close(self) -> None:
        return None


# ------------------------------------------------------------- benign element

class SluiceBenignBrokerElement:
    """Brokered tool executor for benign (uninjected) episodes.

    ``LiveRunProvenance`` -- and therefore the audited
    ``OfficialBrokerExecutor`` -- binds a ``PairedScheduleManifest`` entry, and
    ``OfficialRegistryAttestation._contains_pair_snapshot`` requires an official
    *injection task* for every scheduled pair.  A benign AgentDojo episode has
    none, so the audited adapter is structurally unavailable for that stratum.

    This element therefore mediates benign episodes with the same reference
    monitor (``NonOracleToolBroker``) and the same audited call-authentication
    helpers, and reproduces the adapter's own local denials -- replay by
    ordinal and by provider call id, placeholder arguments, and result
    formatting.  What it does not carry is the provenance re-validation the
    audited adapter performs at each execution boundary.  Attacked episodes,
    where the security claim is measured, use the audited adapter verbatim.
    """

    def __init__(
        self, *, live: Any, binding: Any, broker: Any, manifest: Any, ledger: Any = None
    ) -> None:
        self._live = live
        self._binding = binding
        self._broker = broker
        self._manifest = manifest
        # C2: the per-episode cross-binding ledger.  `broker` MUST remain the
        # real `NonOracleToolBroker` -- see `_bind` for why a delegating
        # wrapper cannot sit under the audited identity seal.
        self._ledger = ledger
        self._ledger_templates = {
            template.template_id: template for template in manifest.templates
        }
        self._runtime = getattr(broker, "_runtime", None)
        if self._runtime is None:
            raise RuntimeError("benign element broker runtime is unavailable")
        self._broker_guard = live._broker_identity_guard(broker)
        self._runtime_guard = live._sealed_runtime_guard(self._runtime)
        self._seen_ordinals: set[int] = set()
        self._seen_provider_ids: set[str] = set()
        self._next_ordinal = 1
        self._records: list[dict] = []
        self._lock = threading.RLock()

    @property
    def audit_log(self) -> tuple:
        with self._lock:
            return tuple(self._records)

    def _revalidate(self) -> None:
        if (
            getattr(self._broker, "_runtime", None) is not self._runtime
            or self._live._broker_identity_guard(self._broker) != self._broker_guard
            or self._live._sealed_runtime_guard(self._runtime) != self._runtime_guard
        ):
            raise self._live.LivePipelineError(
                "broker/runtime identity changed after sealing"
            )

    def _message(self, snapshot: Any, *, content: str, error: str | None) -> dict:
        return {
            "role": "tool",
            "content": [{"type": "text", "content": content}],
            "tool_call_id": snapshot.id,
            "tool_call": snapshot,
            "error": error,
        }

    def _execute(self, call: Any, environment: Any, ordinal: int) -> tuple[dict, Any]:
        live = self._live
        self._revalidate()
        snapshot = self._binding.snapshot(call)
        sanitized = self._binding.sanitized(snapshot)
        args_snapshot = copy.deepcopy(snapshot.args)
        if not isinstance(args_snapshot, Mapping) or any(
            type(key) is not str for key in args_snapshot
        ):
            raise live.LivePipelineError(
                "official tool arguments are not a string-keyed mapping"
            )
        args_sha = live._args_digest(args_snapshot)
        provider_id = None if snapshot.id is None else snapshot.id
        replay = ordinal in self._seen_ordinals or (
            provider_id is not None and provider_id in self._seen_provider_ids
        )
        if replay:
            self._records.append(
                {"ordinal": ordinal, "outcome": "replay_denied", "args_sha256": args_sha}
            )
            return self._message(sanitized, content="", error="SLUICE_REPLAY_DENIED"), environment
        self._seen_ordinals.add(ordinal)
        if provider_id is not None:
            self._seen_provider_ids.add(provider_id)
        if snapshot.placeholder_args is not None:
            self._records.append(
                {
                    "ordinal": ordinal,
                    "outcome": "placeholder_arguments_denied",
                    "args_sha256": args_sha,
                }
            )
            return (
                self._message(
                    sanitized, content="", error="SLUICE_PLACEHOLDER_ARGUMENTS_DENIED"
                ),
                environment,
            )
        request = self._live_request(snapshot, ordinal)
        before = len(self._broker.audit_log)
        self._revalidate()
        result = self._broker.execute(request, environment)
        self._revalidate()
        after = self._broker.audit_log
        if len(after) != before + 1:
            raise live.LivePipelineError("broker did not append exactly one audit record")
        broker_record = after[-1]
        if broker_record.args_sha256 != args_sha:
            raise live.LivePipelineError(
                "broker and live adapter argument snapshots differ"
            )
        # C2: bind the executed effect to its authorisation HERE, while the
        # tool's returned value is still in hand.  The broker's audit log is
        # digest-only, so this is the only seam in the benign path where the
        # RESULT can enter the ledger.  A cross-binding failure is recorded as
        # a violation and surfaces in the episode report; it deliberately does
        # NOT rewrite an authorization decision the broker has already made.
        if (
            self._ledger is not None
            and getattr(broker_record.outcome, "value", "") == "executed_effect"
        ):
            template = self._ledger_templates.get(broker_record.template_id)
            if template is None:
                self._ledger.record_violation(
                    f"executed template {broker_record.template_id!r} is not in "
                    "the manifest"
                )
            else:
                try:
                    self._ledger.bind_execution(
                        template_id=template.template_id,
                        tool=template.tool,
                        canonical_args=template.exact_args,
                        result=result.value,
                        audit_record=broker_record,
                        source="benign_element",
                    )
                except charging.CrossBindingError as exc:
                    self._ledger.record_violation(
                        f"{broker_record.template_id}: {exc}"
                    )
        text = ""
        error: str | None = f"SLUICE_{result.outcome.value.upper()}"
        adapter_outcome = "brokered"
        from sluice_v2.evaluation.agentdojo import BrokerOutcome

        if result.outcome in {
            BrokerOutcome.EXECUTED_READ_ONLY,
            BrokerOutcome.EXECUTED_EFFECT,
        }:
            try:
                text = live._official_result_text(result.value)
                error = None
            except BaseException:  # noqa: BLE001
                text = ""
                error = "SLUICE_RESULT_FORMAT_DENIED"
                adapter_outcome = "result_format_denied"
        self._records.append(
            {
                "ordinal": ordinal,
                "outcome": adapter_outcome,
                "broker_outcome": result.outcome.value,
                "authorized": broker_record.authorized,
                "executed": broker_record.executed,
                "args_sha256": args_sha,
            }
        )
        return self._message(sanitized, content=text, error=error), result.environment

    def _live_request(self, snapshot: Any, ordinal: int) -> Any:
        from sluice_v2.evaluation.agentdojo import ToolRequest

        provider = (
            "none"
            if snapshot.id is None
            else hashlib.sha256(
                b"sluice-agentdojo-provider-call-id-v1\0" + snapshot.id.encode("utf-8")
            ).hexdigest()
        )
        material = (
            f"{self._manifest.workflow_id}\x00{self._manifest.episode_id}\x00"
            f"{ordinal}\x00{provider}"
        )
        call_id = (
            "live-"
            + hashlib.sha256(
                b"sluice-agentdojo-live-request-id-v1\0" + material.encode("utf-8")
            ).hexdigest()[:59]
        )
        return ToolRequest(
            call_id=call_id, function=snapshot.function, args=copy.deepcopy(snapshot.args)
        )

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any,
        messages: Any,
        extra_args: Any,
    ):
        live = self._live
        self._revalidate()
        if type(query) is not str:
            raise live.LivePipelineError("pipeline query must be a string")
        if runtime is not self._runtime:
            raise live.LivePipelineError(
                "pipeline runtime differs from the broker runtime"
            )
        if type(messages) not in (list, tuple):
            raise live.LivePipelineError(
                "pipeline messages must be an exact finite sequence"
            )
        if type(extra_args) is not dict:
            raise live.LivePipelineError("pipeline extra_args must be an exact dict")
        original = list(messages)
        if not original:
            return query, runtime, env, original, extra_args
        last = original[-1]
        if type(last) is not dict:
            raise live.LivePipelineError("pipeline message must be an exact official dict")
        if last.get("role") != "assistant":
            return query, runtime, env, original, extra_args
        if set(last) != {"role", "content", "tool_calls"}:
            raise live.LivePipelineError("assistant message fields are not exact")
        calls = last["tool_calls"]
        if calls is None or (type(calls) is list and not calls):
            return query, runtime, env, original, extra_args
        if type(calls) is not list:
            raise live.LivePipelineError("assistant tool calls must be an exact list")
        if len(calls) > live.MAX_LIVE_CALLS:
            raise live.LivePipelineError(
                "assistant tool-call list is outside the finite bound"
            )
        appended: list = []
        working = env
        with self._lock:
            for call in calls:
                if self._next_ordinal > live.MAX_LIVE_CALLS:
                    raise live.LivePipelineError("episode call horizon is exhausted")
                ordinal = self._next_ordinal
                self._next_ordinal += 1
                message, working = self._execute(call, working, ordinal)
                appended.append(dict(message))
        return query, runtime, working, [*original, *appended], extra_args


# ------------------------------------------------- independent reverification

PINNED_COMPILER_RUNTIME_SHA256 = (
    "950876bcdc566ca830b4c29d20244fa2aa1ece77b73352164ae47cfdc930928e"
)
PINNED_LOADED_ASSET_TREE_SHA256 = (
    "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
)


def verify_bundle_against_request(*, foundation: Any, request: Mapping[str, Any],
                                  bundle: Mapping[str, Any]) -> dict:
    """Recompute on the AgentDojo-side interpreter everything the policy process
    claims, so that process is transport and not an authority.

    Only three manifest fields cannot be recomputed here -- the compiler's own
    executable-graph digest, which is checked against its pin; the compiler
    source digest, which is checked against the loaded module's bytes; and the
    decision/abstention pair, which is checked to be COMPILED/NONE.  Everything
    else, including every compiled template and its exact canonical arguments,
    is derived independently from the request and compared byte for byte.
    """

    def require(condition: bool, message: object) -> None:
        if not condition:
            raise RuntimeError(f"bundle reverification failed: {message}")

    split_manifest = foundation.SplitManifest.create(
        dev_task_ids=request["split"]["dev_task_ids"],
        heldout_task_ids=request["split"]["heldout_task_ids"],
    )
    require(
        split_manifest.sha256
        == request["split"]["expected_split_manifest_sha256"],
        "split manifest digest",
    )
    rules = tuple(
        foundation.PolicyRule(
            rule_id=task["task_id"],
            suite_name=task["suite_name"],
            prompt_sha256=hashlib.sha256(
                task["trusted_user_prompt"].encode("utf-8")
            ).hexdigest(),
            calls=tuple(
                foundation.CallTemplateSpec(
                    tool=call["tool"],
                    arguments={
                        name: (
                            foundation.ArgumentBinding.literal(spec["value"])
                            if spec["source"] == "literal"
                            else foundation.ArgumentBinding.from_state(spec["value"])
                        )
                        for name, spec in call["arguments"].items()
                    },
                )
                for call in task["authored_calls"]
            ),
        )
        for task in request["tasks"]
    )
    policy = foundation.OrganizationPolicy(
        policy_id=request["policy_id"], rules=rules
    )
    require(
        policy.sha256 == bundle["organization_policy_sha256"],
        "org policy digest",
    )
    require(
        split_manifest.sha256 == bundle["split_manifest_sha256"],
        "split digest",
    )
    compiler_source = hashlib.sha256(
        Path(foundation.__file__).resolve().read_bytes()
    ).hexdigest()
    verified = 0
    for task in request["tasks"]:
        schemas = tuple(
            foundation.StaticToolSchema(name=row["name"], parameters=row["parameters"])
            for row in request["suite_tool_schemas"][task["suite_name"]]
        )
        policy_input = foundation.PolicyInput(
            source_commit=foundation.AGENTDOJO_COMMIT,
            benchmark_version=foundation.BENCHMARK_VERSION,
            suite_name=task["suite_name"],
            task_id=task["task_id"],
            trusted_user_prompt=task["trusted_user_prompt"],
            pre_injection_state=task["pre_injection_state"],
            tool_schemas=schemas,
            organization_policy=policy,
            split_manifest=split_manifest,
        )
        expected_input_sha = foundation._policy_input_digest(policy_input)
        expected_templates = [
            {
                "template_id": f"{task['task_id']}-{index:04d}",
                "tool": call["tool"],
                "exact_args": foundation.canonical_args(
                    {n: s["value"] for n, s in call["arguments"].items()}
                ),
            }
            for index, call in enumerate(task["authored_calls"])
        ]
        for episode_id in task["episode_ids"]:
            m = bundle["manifests"][episode_id]
            for field, expected in (
                ("policy_id", request["policy_id"]),
                ("workflow_id", task["workflow_id"]),
                ("suite_name", task["suite_name"]),
                ("task_id", task["task_id"]),
                ("split", policy_input.split.value),
                ("prompt_sha256", policy_input.prompt_sha256),
                ("state_sha256", policy_input.state_sha256),
                ("tool_schema_sha256", policy_input.tool_schema_sha256),
                ("organization_policy_sha256", policy.sha256),
                ("split_manifest_sha256", split_manifest.sha256),
                ("input_sha256", expected_input_sha),
                ("compiler_sha256", compiler_source),
                ("compiler_runtime_sha256", PINNED_COMPILER_RUNTIME_SHA256),
                ("source_assets_sha256", PINNED_LOADED_ASSET_TREE_SHA256),
                ("decision", "compiled"),
                ("abstention", "none"),
            ):
                require(
                    m[field] == expected,
                    (episode_id, field, m[field], expected),
                )
            observed = [
                {"template_id": t["template_id"], "tool": t["tool"],
                 "exact_args": t["exact_args"]}
                for t in m["templates"]
            ]
            require(
                observed == expected_templates,
                (episode_id, observed, expected_templates),
            )
            verified += 1
    return {"verified_manifests": verified, "tasks": len(request["tasks"])}


# ------------------------------------------------------- late-binding element

class SluiceLateBindingExecutor:
    """Stands in for AgentDojo's ToolsExecutor inside the ToolsExecutionLoop.

    ``TaskSuite.run_task_with_pipeline`` builds the ``FunctionsRuntime`` itself
    and only then calls the pipeline, but ``NonOracleToolBroker`` and the
    audited live adapter must be bound to *that exact runtime object* -- the
    audited ``_authenticate_principal_runtime`` compares the runtime's function
    registry against the attested suite tools by object identity.  This element
    therefore defers construction of the whole Sluice stack to the first tool
    call of an episode, when the runtime is finally in hand.
    """

    def __init__(
        self,
        *,
        live: Any,
        foundation: Any,
        binding: Any,
        source: Any,
        registry_attestation: Any,
        endpoint: Any,
        scratch: Path,
        condition: str,
    ) -> None:
        self._live = live
        self._foundation = foundation
        self._binding = binding
        self._source = source
        self._registry_attestation = registry_attestation
        self._endpoint = endpoint
        self._scratch = scratch
        self._condition = condition
        self._episode: dict | None = None
        self._element: Any = None
        self._broker: Any = None
        self._ledger: Any = None
        self._authority: Any = None
        self.last_episode_report: dict = {}

    def begin_episode(
        self,
        *,
        manifest: Any,
        suite: Any,
        user_task_id: str,
        injection_task_id: str | None,
    ) -> None:
        self.end_episode()
        self._episode = {
            "manifest": manifest,
            "suite": suite,
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
        }
        self._element = None
        self._broker = None
        self._ledger = None
        self._authority = None
        self.last_episode_report = {
            "template_count": len(manifest.templates),
            "policy_split": manifest.split.value,
            "manifest_sha256": self._live.policy_manifest_sha256(manifest),
            "adapter": None,
            "bound": False,
        }

    def end_episode(self) -> None:
        if self._authority is not None:
            # ORDER IS LOAD BEARING.  `EffectChargeLedger.verify` reads the
            # live domain's `lifetime_spent_units` to check that the units the
            # domain actually spent equal the units the ledger accounts for,
            # and `close()` closes that sqlite connection.  Reporting after
            # close would silently drop the strongest cross-check in the
            # ledger, so the report is produced first and its failure is
            # recorded rather than raised: an episode that has already been
            # scored must still be journaled.
            try:
                self.last_episode_report["effect_ledger"] = self._authority.report(
                    broker=self._broker
                )
            except BaseException as exc:  # noqa: BLE001
                self.last_episode_report["effect_ledger"] = {
                    "schema": charging.LEDGER_SCHEMA,
                    "consistent": False,
                    "problems": [f"ledger report raised: {exc!r}"],
                    "authorized_count": None,
                    "observed_count": None,
                    "executed_count": None,
                }
            self.last_episode_report["event_charge_units"] = getattr(
                self._authority, "event_charge_units", None
            )
            self.last_episode_report["charge_escalations"] = list(
                getattr(self._authority, "charge_escalations", ()) or ()
            )
            self.last_episode_report["authority_impl"] = type(self._authority).__name__
            try:
                self._authority.close()
            finally:
                self._authority = None
        if self._broker is not None:
            self.last_episode_report["broker_decisions"] = [
                {
                    "outcome": record.outcome.value,
                    "authorized": record.authorized,
                    "executed": record.executed,
                    "template_id": record.template_id,
                    "tool_kind": None if record.tool_kind is None else record.tool_kind.value,
                }
                for record in self._broker.audit_log
            ]
            self.last_episode_report["consumed_effects"] = self._broker.consumed_effect_count
            self.last_episode_report["unused_effects"] = self._broker.unused_effect_count
        self._broker = None
        self._ledger = None
        self._element = None
        self._episode = None

    def _bind(self, runtime: Any) -> None:
        if self._episode is None:
            raise RuntimeError("Sluice element used outside an episode")
        live = self._live
        foundation = self._foundation
        manifest = self._episode["manifest"]
        suite = self._episode["suite"]
        registry = foundation.V122_TOOL_REGISTRIES[manifest.suite_name]
        schemas = foundation.static_tool_schemas_from_suite(suite)
        if manifest.templates:
            authority: Any = EFFECT_AUTHORITY_IMPL(
                foundation=foundation, manifest=manifest, scratch=self._scratch
            )
            # Belt and braces.  The module constant above is what `_bind`
            # resolves, but a run that silently constructed the fixed-charge
            # authority would produce numbers that look entirely normal, so the
            # identity is asserted here as well and fails the arm, not the run.
            if type(authority) is not charging.DerivedEffectAuthority:
                raise RuntimeError(
                    "C2 harness did not construct DerivedEffectAuthority "
                    f"(got {type(authority).__name__})"
                )
        else:
            authority = NULL_EFFECT_AUTHORITY_IMPL()
        self._authority = authority
        broker = foundation.NonOracleToolBroker(
            manifest=manifest,
            registry=registry,
            tool_schemas=schemas,
            runtime=runtime,
            grants=tuple(authority.grants),
            authorizer=authority.authorizer,
        )
        self._broker = broker
        # The RESULT of an executed effect exists only at the call site.  The
        # broker's audit log records a digest of the ARGUMENTS but never the
        # returned value, so `EffectChargeLedger.reconcile_from_broker` can
        # bind everything except the result.  Where this harness owns the call
        # site -- `SluiceBenignBrokerElement._execute` below -- the result is
        # bound directly, at the one moment it exists.
        #
        # WHY NOT `charging.RecordingBroker`.  That wrapper delegates through
        # `__getattr__`, and the audited `_broker_identity_guard` seals the
        # broker with `inspect.getattr_static(type(broker), "audit_log")`,
        # which deliberately does NOT consult `__getattr__`.  Wrapping the
        # broker therefore makes the audited seal raise
        # "broker identity seal is unavailable" and every benign Sluice arm
        # errors -- observed on real hardware in the first C2 smoke run, and
        # not observable from the 20-case adversarial suite, which builds its
        # own stack and never goes through `_bind`.  That guard is audited code
        # on the enforcement path and is exactly right to reject an interposed
        # object, so the binding moved into code this harness owns instead of
        # the guard being weakened.  `RecordingBroker` remains in
        # `effect_charging` and remains covered by C1's suite; it is simply not
        # the seam used here.
        self._ledger = authority.ledger
        injection_task_id = self._episode["injection_task_id"]
        if injection_task_id is not None:
            schedule = live.PairedScheduleManifest.create(
                episode_pairs=(
                    live.PairedEpisodeIdentity.create(
                        episode_id=manifest.episode_id,
                        suite_name=manifest.suite_name,
                        user_task_id=self._episode["user_task_id"],
                        injection_task_id=injection_task_id,
                    ),
                ),
                conditions=("undefended", self._condition),
                seed=f"sluice-nonoracle-schedule:{manifest.episode_id}",
                registry=self._registry_attestation,
            )
            provenance = live.LiveRunProvenance.create(
                source=self._source,
                registry=self._registry_attestation,
                endpoint=self._endpoint,
                schedule=schedule,
                policy_manifest=manifest,
                durable_binding_sha256=hashlib.sha256(
                    b"sluice-agentdojo-inprocess-durable-binding-v1\0"
                    + (";".join(sorted(g.template_id for g in authority.grants))).encode()
                ).hexdigest(),
                condition=self._condition,
            )
            executor = live.OfficialBrokerExecutor(
                binding=self._binding,
                broker=broker,
                manifest=manifest,
                provenance=provenance,
            )
            self._element = live.OfficialBrokerPipelineElement(executor)
            self.last_episode_report["adapter"] = "official_broker_pipeline_element"
            self.last_episode_report["provenance_sha256"] = provenance.sha256
            self.last_episode_report["principal_eligible"] = provenance.principal_eligible
        else:
            self._element = SluiceBenignBrokerElement(
                live=live,
                binding=self._binding,
                broker=broker,
                manifest=manifest,
                ledger=self._ledger,
            )
            self.last_episode_report["adapter"] = "sluice_benign_broker_element"
            self.last_episode_report["benign_result_binding"] = "in_element"
        self.last_episode_report["bound"] = True

    def query(self, query, runtime, env=None, messages=None, extra_args=None):
        if self._element is None:
            self._bind(runtime)
        return self._element.query(query, runtime, env, messages, extra_args)
