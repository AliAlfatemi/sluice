"""Independent adversarial regression tests for the G2 security boundary.

These tests are derived from ``analysis/SECURE_DOMAIN_DESIGN.md``.  They are
kept separate from the implementation contract so a red result is useful
evidence: no implementation code is changed by this audit.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading

import pytest

from sluice_v2.isolation import (
    BrokerOutcome,
    DurableClaimJournal,
    EffectBroker,
    IPCEnvelope,
    IPCMessageKind,
    IPCSchemaError,
    IsolationManifest,
)
from sluice_v2.observer import (
    EventKind,
    OutcomeCode,
    TranscriptEvent,
    TranscriptSchemaError,
)
from sluice_v2.secure import (
    AttemptCredential,
    DomainConfig,
    DomainLifecycleError,
    EffectCapability,
    ObserverSpec,
    ReauthorizationGrant,
    ReauthorizationPolicy,
    RouteCodebook,
    RouteToken,
    SecureDomain,
)


CALLER_KEY = b"audit-caller-key-material-32-bytes"
REAUTH_KEY = b"audit-reauth-key-material-32-bytes"


def _codebook(
    *,
    name: str = "route-a",
    public_values: frozenset[int] = frozenset({0}),
    requires_capability: bool = False,
) -> RouteCodebook:
    return RouteCodebook(
        name=name,
        public_values=public_values,
        requires_capability=requires_capability,
    )


def _domain(
    *,
    horizon: int = 4,
    charge: int = 4,
    budget: int | None = None,
    route_codebooks: tuple[RouteCodebook, ...] | None = None,
    reauthorization_policy: ReauthorizationPolicy | None = None,
) -> SecureDomain:
    if budget is None:
        budget = horizon * charge
    if route_codebooks is None:
        route_codebooks = (_codebook(),)
    permitted = frozenset(
        value for codebook in route_codebooks for value in codebook.public_values
    )
    return SecureDomain(
        DomainConfig(
            domain_id="audit-domain",
            protected_objects=frozenset({"object-a", "object-b"}),
            lifetime_budget_units=budget,
            attempt_horizon=horizon,
            event_charge_units=charge,
        ),
        observer_spec=ObserverSpec(
            permitted_value_codes=permitted,
            observer_spec_id="v9-audit-observer-spec",
            route_codebooks=route_codebooks,
        ),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        reauthorization_policy=reauthorization_policy,
    )


def _route(
    domain: SecureDomain,
    *,
    name: str = "route-a",
    protected_object: str = "object-a",
    handler=lambda payload: 0,
    public_values: frozenset[int] = frozenset({0}),
    requires_capability: bool = False,
) -> RouteToken:
    return domain.register_route(
        name=name,
        protected_object=protected_object,
        handler=handler,
        public_values=public_values,
        requires_capability=requires_capability,
    )


def _activate(domain: SecureDomain) -> None:
    domain.seal()
    domain.activate()


def _credential(
    route: RouteToken,
    payload: object,
    *,
    nonce: str,
) -> AttemptCredential:
    return AttemptCredential.sign(
        agent_id="worker",
        signing_key=CALLER_KEY,
        route=route,
        payload=payload,
        nonce=nonce,
    )


def _broker(
    *,
    handler,
    capability_validator=lambda token, tool, args: True,
) -> EffectBroker:
    return EffectBroker(
        allowed_arguments={7: frozenset({(10, 20)})},
        public_values={7: frozenset({0, 1})},
        tool_credentials={7: b"private-tool-credential"},
        handlers={7: handler},
        capability_validator=capability_validator,
    )


def test_payload_binding_is_injective_or_rejects_non_string_map_keys():
    """``{1: x}`` and ``{"1": x}`` must never share a credential."""

    domain = _domain(horizon=2)
    calls: list[object] = []
    route = _route(domain, handler=lambda payload: calls.append(payload) or 0)
    _activate(domain)
    signed_payload = {1: "same-spelling"}
    presented_payload = {"1": "same-spelling"}

    # The design permits rejecting the unsupported map at signing time.  If
    # it is accepted, however, the type-tagged canonical form must differ.
    try:
        credential = _credential(route, signed_payload, nonce="map-key-collision")
    except TypeError:
        return

    event = domain.attempt(
        route,
        presented_payload,
        credential=credential,
    )
    assert event.outcome is OutcomeCode.AUTH_DENIED
    assert calls == []


def test_failed_capability_claim_does_not_consume_valid_credential():
    """A failed claim consumes neither authorization, per design section 5."""

    domain = _domain(
        horizon=3,
        route_codebooks=(_codebook(requires_capability=True),),
    )
    calls: list[object] = []
    route = _route(
        domain,
        handler=lambda payload: calls.append(payload) or 0,
        requires_capability=True,
    )
    capability = domain.issue_capability(route)
    _activate(domain)
    payload = {"operation": "effect"}
    credential = _credential(route, payload, nonce="retry-after-missing-capability")

    denied = domain.attempt(route, payload, credential=credential)
    retried = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
    )

    assert denied.outcome is OutcomeCode.CAPABILITY_DENIED
    assert retried.outcome is OutcomeCode.RELEASED
    assert calls == [payload]


def test_wrong_route_capability_consumes_neither_credential_nor_capability():
    domain = _domain(
        horizon=4,
        route_codebooks=(
            _codebook(name="effect-a", requires_capability=True),
            _codebook(name="effect-b", requires_capability=True),
        ),
    )
    route_a = _route(domain, name="effect-a", requires_capability=True)
    route_b = _route(
        domain,
        name="effect-b",
        protected_object="object-b",
        requires_capability=True,
    )
    capability_a = domain.issue_capability(route_a)
    capability_b = domain.issue_capability(route_b)
    _activate(domain)
    payload_a = {"effect": "a"}
    payload_b = {"effect": "b"}
    credential_a = _credential(route_a, payload_a, nonce="credential-a")

    mismatch = domain.attempt(
        route_a,
        payload_a,
        credential=credential_a,
        capability=capability_b,
    )
    retry_a = domain.attempt(
        route_a,
        payload_a,
        credential=credential_a,
        capability=capability_a,
    )
    retry_b = domain.attempt(
        route_b,
        payload_b,
        credential=_credential(route_b, payload_b, nonce="credential-b"),
        capability=capability_b,
    )

    assert [mismatch.outcome, retry_a.outcome, retry_b.outcome] == [
        OutcomeCode.CAPABILITY_DENIED,
        OutcomeCode.RELEASED,
        OutcomeCode.RELEASED,
    ]


def test_committed_handler_failure_consumes_both_authorizations():
    """A committed claim is not refunded after an ordinary backend failure."""

    domain = _domain(
        horizon=3,
        route_codebooks=(_codebook(requires_capability=True),),
    )

    def fail(_payload: object) -> int:
        raise RuntimeError("private backend failure")

    route = _route(domain, handler=fail, requires_capability=True)
    capability = domain.issue_capability(route)
    _activate(domain)
    payload = {"operation": "effect"}
    credential = _credential(route, payload, nonce="committed-credential")

    failed = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
    )
    credential_replay = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
    )
    capability_replay = domain.attempt(
        route,
        payload,
        credential=_credential(route, payload, nonce="fresh-credential"),
        capability=capability,
    )

    assert [failed.outcome, credential_replay.outcome, capability_replay.outcome] == [
        OutcomeCode.INTERNAL_DENIED,
        OutcomeCode.AUTH_DENIED,
        OutcomeCode.CAPABILITY_DENIED,
    ]


def test_non_exception_worker_termination_still_finalizes_reserved_attempt():
    """Every reserved attempt must produce one typed event, even on a crash edge."""

    class WorkerTerminated(BaseException):
        pass

    domain = _domain(horizon=1)

    def terminate(_payload: object) -> int:
        raise WorkerTerminated("private worker termination")

    route = _route(domain, handler=terminate)
    _activate(domain)
    payload = {"operation": "release"}

    event = domain.attempt(
        route,
        payload,
        credential=_credential(route, payload, nonce="worker-termination"),
    )
    assert event.outcome is OutcomeCode.INTERNAL_DENIED
    assert domain.attempts_used == 1
    assert len(domain.transcript) == 1


def test_reauthorization_increment_funds_its_own_added_horizon():
    """Pre-existing slack must not make an underfunded increment valid."""

    domain = _domain(
        horizon=2,
        charge=4,
        budget=20,
        reauthorization_policy=ReauthorizationPolicy(
            budget_increment_units=8,
            attempt_increment=2,
        ),
    )
    _route(domain)
    _activate(domain)
    grant = ReauthorizationGrant.sign(
        authorizer_id="admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        budget_increment_units=1,
        attempt_increment=2,
        nonce="underfunded-increment",
    )

    event = domain.reauthorize(grant)

    assert event.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.lifetime_budget_units == 20
    assert domain.attempt_horizon == 2


def test_accepted_transcript_integer_has_a_json_round_trip():
    """Accepted public primitives must remain serializable at their bounds."""

    enormous_code = 10**5000
    try:
        event = TranscriptEvent(
            schema_version=1,
            sequence=1,
            attempt=1,
            kind=EventKind.ATTEMPT,
            outcome=OutcomeCode.RELEASED,
            value_code=enormous_code,
            charge_units=1,
            terminal=True,
        )
    except TranscriptSchemaError:
        return

    encoded = json.dumps(event.to_wire(), allow_nan=False, sort_keys=True)
    assert TranscriptEvent.from_wire(json.loads(encoded)) == event


def test_sealing_rejects_impractical_unbounded_padding_horizon():
    with pytest.raises(ValueError, match="horizon|maximum|bound|padding"):
        domain = _domain(horizon=10**12, charge=1, budget=10**12)
        _route(domain)
        domain.seal()


def test_sealing_rejects_charge_below_declared_event_support():
    """One bit cannot encode four releases plus the observable denial classes."""

    domain = _domain(
        horizon=1,
        charge=1,
        budget=1,
        route_codebooks=(
            _codebook(public_values=frozenset({0, 1, 2, 3})),
        ),
    )
    _route(domain, public_values=frozenset({0, 1, 2, 3}))

    with pytest.raises(ValueError, match="charge|support|alphabet|underfunded"):
        domain.seal()


def test_cross_thread_handler_reentry_cannot_queue_an_extra_operation():
    """RLock serialization must not turn rejected nesting into a delayed call."""

    domain = _domain(horizon=2)
    nested_results: list[object] = []
    nested_threads: list[threading.Thread] = []

    def handler(_payload: object) -> int:
        def nested_call() -> None:
            try:
                nested_results.append(domain.continue_work())
            except BaseException as exc:  # retain the exact fail-closed result
                nested_results.append(exc)

        worker = threading.Thread(target=nested_call)
        nested_threads.append(worker)
        worker.start()
        worker.join(timeout=0.05)
        return 0

    route = _route(domain, handler=handler)
    _activate(domain)
    payload = {"operation": "outer"}
    outer = domain.attempt(
        route,
        payload,
        credential=_credential(route, payload, nonce="outer-attempt"),
    )
    for worker in nested_threads:
        worker.join(timeout=2)

    assert outer.outcome is OutcomeCode.RELEASED
    assert len(nested_results) == 1
    assert isinstance(nested_results[0], DomainLifecycleError)
    assert len(domain.transcript) == 1


def test_concurrent_credential_replay_executes_handler_at_most_once():
    """A positive high-contention check for the in-memory replay lock."""

    domain = _domain(horizon=8)
    calls = 0
    calls_lock = threading.Lock()

    def handler(_payload: object) -> int:
        nonlocal calls
        with calls_lock:
            calls += 1
        return 0

    route = _route(domain, handler=handler)
    _activate(domain)
    payload = {"operation": "same"}
    credential = _credential(route, payload, nonce="racing-replay")
    barrier = threading.Barrier(8)

    def redeem() -> OutcomeCode:
        barrier.wait(timeout=5)
        return domain.attempt(route, payload, credential=credential).outcome

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _index: redeem(), range(8)))

    assert outcomes.count(OutcomeCode.RELEASED) == 1
    assert outcomes.count(OutcomeCode.AUTH_DENIED) == 7
    assert calls == 1
    assert domain.attempts_used == 8


def test_ipc_manifest_frame_ceiling_is_enforced_on_the_complete_frame():
    manifest = IsolationManifest.strict(ipc_max_frame_bytes=4096)
    with pytest.raises(IPCSchemaError, match="frame|size|token|bound"):
        IPCEnvelope.model_request(
            sequence=1,
            route_token="r" * 4096,
            payload_code=0,
            credential="c" * 4096,
        )
    assert manifest.ipc_max_frame_bytes == 4096


def test_ipc_rejects_or_serializes_enormous_integer_codes():
    enormous_code = 10**5000
    try:
        message = IPCEnvelope.effect_command(
            sequence=1,
            capability_token="opaque-capability",
            tool_code=7,
            argument_codes=(enormous_code,),
        )
    except IPCSchemaError:
        return

    encoded = json.dumps(message.to_wire(), allow_nan=False, sort_keys=True)
    assert IPCEnvelope.from_wire(json.loads(encoded)) == message


def test_effect_result_kind_enforces_outcome_value_consistency():
    with pytest.raises(IPCSchemaError, match="value|outcome|denied"):
        IPCEnvelope.effect_result(
            sequence=1,
            outcome=BrokerOutcome.DENIED,
            value_code=1,
        )


def test_broker_revalidates_direct_envelopes_before_any_effect():
    calls: list[tuple[bytes, tuple[int, ...]]] = []
    broker = _broker(handler=lambda credential, args: calls.append((credential, args)) or 0)
    # Public dataclass construction bypasses every factory check unless the
    # broker validates again at its trust boundary.
    malformed = IPCEnvelope(
        sequence=True,
        kind=IPCMessageKind.EFFECT_COMMAND,
        capability_token="opaque-capability",
        tool_code=7,
        argument_codes=(10, 20),
    )

    with pytest.raises(IPCSchemaError):
        broker.execute(malformed)
    assert calls == []


def test_broker_registry_cannot_be_expanded_through_mutable_alias():
    calls: list[tuple[int, ...]] = []
    mutable_allowlist = {(10, 20)}
    try:
        broker = EffectBroker(
            allowed_arguments={7: mutable_allowlist},  # type: ignore[arg-type]
            public_values={7: frozenset({0})},
            tool_credentials={7: b"credential"},
            handlers={7: lambda _credential, args: calls.append(args) or 0},
            capability_validator=lambda token, tool, args: True,
        )
    except (TypeError, ValueError):
        return

    mutable_allowlist.add((99,))
    reply = broker.execute(
        IPCEnvelope.effect_command(
            sequence=1,
            capability_token="opaque-capability",
            tool_code=7,
            argument_codes=(99,),
        )
    )

    assert reply.outcome is BrokerOutcome.DENIED
    assert calls == []


def test_broker_rejects_replayed_capability_before_second_effect():
    calls: list[tuple[int, ...]] = []
    broker = _broker(handler=lambda _credential, args: calls.append(args) or 0)
    command = IPCEnvelope.effect_command(
        sequence=1,
        capability_token="one-use-capability",
        tool_code=7,
        argument_codes=(10, 20),
    )

    first = broker.execute(command)
    replay = broker.execute(command)

    assert first.outcome is BrokerOutcome.EXECUTED
    assert replay.outcome is BrokerOutcome.DENIED
    assert calls == [(10, 20)]


def test_broker_rejects_nested_effect_execution():
    inner_calls: list[tuple[int, ...]] = []
    nested_results: list[IPCEnvelope] = []
    broker: EffectBroker

    inner = IPCEnvelope.effect_command(
        sequence=2,
        capability_token="nested-capability",
        tool_code=8,
        argument_codes=(30,),
    )

    def outer_handler(_credential: bytes, _args: tuple[int, ...]) -> int:
        nested_results.append(broker.execute(inner))
        return 0

    broker = EffectBroker(
        allowed_arguments={
            7: frozenset({(10, 20)}),
            8: frozenset({(30,)}),
        },
        public_values={7: frozenset({0}), 8: frozenset({0})},
        tool_credentials={7: b"outer-credential", 8: b"inner-credential"},
        handlers={
            7: outer_handler,
            8: lambda _credential, args: inner_calls.append(args) or 0,
        },
        capability_validator=lambda token, tool, args: True,
    )
    outer = IPCEnvelope.effect_command(
        sequence=1,
        capability_token="outer-capability",
        tool_code=7,
        argument_codes=(10, 20),
    )

    broker.execute(outer)

    assert inner_calls == []
    assert not nested_results or nested_results[0].outcome is BrokerOutcome.DENIED


def test_direct_manifest_construction_cannot_downgrade_strict_policy():
    with pytest.raises((TypeError, ValueError), match="network|strict|canonical|deny"):
        IsolationManifest(
            ipc_max_frame_bytes=4096,
            model_network="allow",
        )


def test_durable_claim_journal_same_request_race_has_one_winner(tmp_path: Path):
    """Repeated contention must produce exactly one durable authorization."""

    journal = DurableClaimJournal(tmp_path / "race.sqlite3")
    contenders = 32
    barrier = threading.Barrier(contenders)

    def claim(_index: int) -> bool:
        barrier.wait(timeout=10)
        return journal.claim_once(
            request_id="same-request",
            command_fingerprint="same-command",
        )

    with ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(claim, range(contenders)))

    assert results.count(True) == 1
    assert results.count(False) == contenders - 1
    assert journal.durable_claim_count("same-request") == 1


def test_durable_claim_journal_conflicting_race_never_rebinds(tmp_path: Path):
    journal = DurableClaimJournal(tmp_path / "conflicting-race.sqlite3")
    contenders = 24
    barrier = threading.Barrier(contenders)

    def claim(index: int) -> str:
        barrier.wait(timeout=10)
        fingerprint = "command-a" if index % 2 == 0 else "command-b"
        try:
            created = journal.claim_once(
                request_id="shared-request-id",
                command_fingerprint=fingerprint,
            )
        except IPCSchemaError:
            return "conflict"
        return "created" if created else "same"

    with ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(claim, range(contenders)))

    assert results.count("created") == 1
    assert results.count("same") == (contenders // 2) - 1
    assert results.count("conflict") == contenders // 2
    assert journal.durable_claim_count("shared-request-id") == 1
