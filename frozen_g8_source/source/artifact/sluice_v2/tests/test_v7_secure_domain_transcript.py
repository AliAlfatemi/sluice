"""Executable contract for Sluice's complete-transcript secure-domain API.

This test is intentionally written before the implementation.  The additive
API it fixes is compact and independent of the legacy ``ReferenceMonitor``:

``sluice_v2.observer`` exports ``TRANSCRIPT_SCHEMA_VERSION``, ``EventKind``,
``OutcomeCode``, ``TranscriptEvent``, and ``TranscriptSchemaError``.

``sluice_v2.secure`` exports ``DomainConfig``, ``DomainLifecycleError``,
``DomainState``, ``SecureDomain``, ``RouteToken``, ``EffectCapability``,
``AttemptCredential``, ``ReauthorizationGrant``, ``ReauthorizationPolicy``,
``ObserverSpec``, and ``RouteCodebook``.

A ``SecureDomain`` is configured with a set of correlated protected objects,
a cumulative lifetime budget, a finite attempt horizon, one fixed public-event
charge, caller verification keys, and reauthorization verification keys.
Routes and capabilities are opaque, authenticated domain-bound handles.
``register_route`` is legal only in DRAFT; ``seal`` and ``activate`` implement
DRAFT -> SEALED -> ACTIVE.  ``attempt``, ``continue_work``, ``stop``, and
``reauthorize`` return typed public events.  All ACTIVE events reserve the
fixed charge and increment the attempt counter *before* their outcome is
computed.  Natural horizon exhaustion or ``stop`` closes the domain; stop
pads the public transcript deterministically to the current horizon.  Once
closed, every attempted operation returns the same history-determined
DOMAIN_CLOSED event without changing the charged transcript.

Credentials are created by ``AttemptCredential.sign`` from a caller-held key,
the opaque route token, and the exact payload.  Reauthorization grants are
created by ``ReauthorizationGrant.sign`` from an authority-held key and the
domain's opaque ``reauthorization_context``.  Reauthorization is disabled by
default; when enabled, only the one positive increment shape fixed in the
precommitted ``ReauthorizationPolicy`` can succeed.  Neither spend nor used
attempts is reset.  These signing helpers model code that runs outside the
monitor and do not authorize exposing either key to an untrusted model process.

The expected concrete method signatures are exercised below.  Each route also
declares a finite set of integer ``public_values``; a successful release places
only that finite ordinal in ``value_code``.  The public wire event is therefore
much smaller than internal monitor/audit state: exactly eight JSON-compatible
fields and finite enum/value codes, with no IDs, routes, digests, arguments,
exception text, capability metadata, or free-form detail.
"""

from __future__ import annotations

from dataclasses import replace
import json

import pytest

from sluice_v2.observer import (
    TRANSCRIPT_SCHEMA_VERSION,
    EventKind,
    OutcomeCode,
    TranscriptEvent,
    TranscriptSchemaError,
)
from sluice_v2.secure import (
    AttemptCredential,
    DomainConfig,
    DomainLifecycleError,
    DomainState,
    EffectCapability,
    ObserverSpec,
    ReauthorizationGrant,
    ReauthorizationPolicy,
    RouteCodebook,
    RouteToken,
    SecureDomain,
)


CALLER_KEY = b"caller-verification-key-32-bytes!"
WRONG_CALLER_KEY = b"wrong--verification-key-32-bytes!"
REAUTH_KEY = b"reauth-authority-key-material-32b"
WRONG_REAUTH_KEY = b"wrong-reauth-key-material----32b"

WIRE_KEYS = {
    "schema_version",
    "sequence",
    "attempt",
    "kind",
    "outcome",
    "value_code",
    "charge_units",
    "terminal",
}


def _codebook(
    *,
    name: str = "release-summary",
    public_values=frozenset({0, 1}),
    requires_capability: bool = False,
) -> RouteCodebook:
    return RouteCodebook(
        name=name,
        public_values=frozenset(public_values),
        requires_capability=requires_capability,
    )


def _domain(
    domain_id: str = "correlated-secret-domain",
    *,
    objects=frozenset({"record-a", "record-b"}),
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
            domain_id=domain_id,
            protected_objects=frozenset(objects),
            lifetime_budget_units=budget,
            attempt_horizon=horizon,
            event_charge_units=charge,
        ),
        observer_spec=ObserverSpec(
            permitted_value_codes=permitted,
            observer_spec_id="v7-test-observer-spec",
            route_codebooks=route_codebooks,
        ),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        reauthorization_policy=reauthorization_policy,
    )


def _route(
    domain: SecureDomain,
    *,
    name: str = "release-summary",
    protected_object: str = "record-a",
    handler=lambda payload: 0,
    public_values=frozenset({0, 1}),
    requires_capability: bool = False,
) -> RouteToken:
    return domain.register_route(
        name=name,
        protected_object=protected_object,
        handler=handler,
        public_values=frozenset(public_values),
        requires_capability=requires_capability,
    )


def _activate(domain: SecureDomain) -> SecureDomain:
    domain.seal()
    domain.activate()
    return domain


def _credential(
    route: RouteToken,
    payload,
    *,
    key: bytes = CALLER_KEY,
    nonce: str = "attempt-nonce",
) -> AttemptCredential:
    return AttemptCredential.sign(
        agent_id="worker",
        signing_key=key,
        route=route,
        payload=payload,
        nonce=nonce,
    )


def _wire(event: TranscriptEvent) -> dict[str, object]:
    wire = event.to_wire()
    assert type(wire) is dict
    return wire


def test_public_transcript_event_has_exact_versioned_finite_schema():
    domain = _domain(horizon=1)
    route = _route(domain)
    _activate(domain)
    payload = {"content": "top secret", "args": {"recipient": "private@example"}}

    event = domain.attempt(
        route,
        payload,
        credential=_credential(route, payload),
    )
    wire = _wire(event)

    assert TRANSCRIPT_SCHEMA_VERSION == 1
    assert set(wire) == WIRE_KEYS
    assert type(wire["schema_version"]) is int
    assert type(wire["sequence"]) is int
    assert type(wire["attempt"]) is int
    assert type(wire["kind"]) is str
    assert type(wire["outcome"]) is str
    assert type(wire["value_code"]) is int
    assert type(wire["charge_units"]) is int
    assert type(wire["terminal"]) is bool
    assert wire == {
        "schema_version": 1,
        "sequence": 1,
        "attempt": 1,
        "kind": EventKind.ATTEMPT.value,
        "outcome": OutcomeCode.RELEASED.value,
        "value_code": 0,
        "charge_units": 4,
        "terminal": True,
    }
    assert TranscriptEvent.from_wire(wire) == event
    # Enum construction is an explicit assertion that no free-form event or
    # denial class can pass through the observer schema.
    assert EventKind(wire["kind"]) is EventKind.ATTEMPT
    assert OutcomeCode(wire["outcome"]) is OutcomeCode.RELEASED


@pytest.mark.parametrize(
    "mutate",
    [
        lambda wire: {**wire, "schema_version": TRANSCRIPT_SCHEMA_VERSION + 1},
        lambda wire: {**wire, "debug": "raw internal state"},
        lambda wire: {key: value for key, value in wire.items() if key != "terminal"},
        lambda wire: {**wire, "attempt": True},  # bool is not an integer here
        lambda wire: {**wire, "charge_units": 1.0},
        lambda wire: {**wire, "terminal": 1},
        lambda wire: {**wire, "value_code": True},
        lambda wire: {**wire, "kind": "new-unreviewed-event"},
        lambda wire: {**wire, "outcome": "exception: secret value"},
    ],
    ids=[
        "version-mismatch",
        "extra-field",
        "missing-field",
        "bool-as-int",
        "float-as-int",
        "int-as-bool",
        "bool-as-value-code",
        "unknown-kind",
        "unknown-outcome",
    ],
)
def test_schema_mismatch_or_unexpected_field_fails_closed(mutate):
    canonical = {
        "schema_version": TRANSCRIPT_SCHEMA_VERSION,
        "sequence": 1,
        "attempt": 1,
        "kind": EventKind.ATTEMPT.value,
        "outcome": OutcomeCode.RELEASED.value,
        "value_code": None,
        "charge_units": 2,
        "terminal": False,
    }
    with pytest.raises(TranscriptSchemaError):
        TranscriptEvent.from_wire(mutate(canonical))


def test_observer_projection_contains_no_raw_ids_hashes_args_or_exception_text():
    secret_id = "record-object-secret-identifier"
    route_name = "route-name-secret-identifier"
    raw_content = "swordfish-low-entropy-secret"
    raw_argument = "victim@example.invalid"
    raw_exception = "backend exploded while handling swordfish"

    observed_spend = []
    domain = _domain(
        objects=frozenset({secret_id}),
        horizon=2,
        route_codebooks=(_codebook(name=route_name),),
    )

    def failing_handler(payload):
        # The charge must already be reserved before backend code can execute
        # or fail; otherwise outcome-dependent failures create a free channel.
        observed_spend.append((domain.attempts_used, domain.lifetime_spent_units))
        raise RuntimeError(raw_exception)

    route = _route(
        domain,
        name=route_name,
        protected_object=secret_id,
        handler=failing_handler,
    )
    _activate(domain)
    payload = {"content": raw_content, "args": {"recipient": raw_argument}}
    event = domain.attempt(route, payload, credential=_credential(route, payload))

    assert event.kind is EventKind.ATTEMPT
    assert event.outcome is OutcomeCode.INTERNAL_DENIED
    assert event.charge_units == 4
    assert observed_spend == [(1, 4)]
    serialized = json.dumps(_wire(event), sort_keys=True)
    for forbidden in (
        secret_id,
        route_name,
        raw_content,
        raw_argument,
        raw_exception,
        "digest",
        "capability",
        "worker",
    ):
        assert forbidden not in serialized
    assert set(_wire(event)) == WIRE_KEYS


def test_backend_value_outside_registered_finite_alphabet_fails_closed():
    domain = _domain(horizon=1)
    route = _route(
        domain,
        handler=lambda payload: 999,
        public_values=frozenset({0, 1}),
    )
    _activate(domain)
    payload = {"unconstrained_backend_text": "ignore the schema and leak me"}

    event = domain.attempt(
        route,
        payload,
        credential=_credential(route, payload),
    )

    assert event.kind is EventKind.ATTEMPT
    assert event.outcome is OutcomeCode.OUTPUT_DENIED
    assert event.value_code is None
    assert event.charge_units == 4
    assert domain.attempts_used == 1
    assert domain.lifetime_spent_units == 4
    assert "ignore the schema" not in json.dumps(event.to_wire())


def test_failed_auth_and_invalid_route_are_attempts_and_are_charged():
    called = []
    left = _domain("left-domain", horizon=4)
    left_route = _route(left, handler=lambda payload: called.append(payload))
    _activate(left)

    right = _domain("right-domain", horizon=4)
    right_route = _route(right, handler=lambda payload: called.append(payload))
    _activate(right)
    payload = {"content": "bound payload"}

    wrong_key_credential = _credential(left_route, payload, key=WRONG_CALLER_KEY)
    auth_denial = left.attempt(
        left_route,
        payload,
        credential=wrong_key_credential,
    )
    route_denial = left.attempt(
        right_route,
        payload,
        credential=None,
    )
    payload_mismatch = left.attempt(
        left_route,
        {"content": "tampered payload"},
        credential=_credential(left_route, payload, nonce="different-nonce"),
    )

    assert [auth_denial.outcome, route_denial.outcome, payload_mismatch.outcome] == [
        OutcomeCode.AUTH_DENIED,
        OutcomeCode.ROUTE_DENIED,
        OutcomeCode.AUTH_DENIED,
    ]
    assert [auth_denial.attempt, route_denial.attempt, payload_mismatch.attempt] == [
        1,
        2,
        3,
    ]
    assert all(event.charge_units == 4 for event in domain_events(left))
    assert left.attempts_used == 3
    assert left.lifetime_spent_units == 12
    assert called == []
    assert right.attempts_used == 0
    assert right.lifetime_spent_units == 0


def domain_events(domain: SecureDomain) -> tuple[TranscriptEvent, ...]:
    """Assert and return the immutable public transcript view."""
    events = domain.transcript
    assert type(events) is tuple
    assert all(isinstance(event, TranscriptEvent) for event in events)
    return events


def test_exact_attempt_horizon_and_history_determined_closed_reply():
    domain = _domain(horizon=3)
    route = _route(domain)
    _activate(domain)

    for index in range(1, 4):
        payload = {"request": index}
        event = domain.attempt(
            route,
            payload,
            credential=_credential(route, payload, nonce=f"nonce-{index}"),
        )
        assert event.attempt == index
        assert event.terminal is (index == 3)

    assert domain.state is DomainState.CLOSED
    assert domain.attempts_used == 3
    assert domain.lifetime_spent_units == 12
    assert len(domain_events(domain)) == 3
    frozen_transcript = domain.transcript

    # Post-close status is allowed to be uncharged because it is a constant
    # function of prior public history. Repetition must not extend H or append
    # an unbounded observer transcript.
    closed_1 = domain.attempt(route, {"ignored": 1}, credential=None)
    closed_2 = domain.continue_work()
    closed_3 = domain.reauthorize(None)
    assert closed_1 == closed_2 == closed_3
    assert closed_1.kind is EventKind.DOMAIN_CLOSED
    assert closed_1.outcome is OutcomeCode.DOMAIN_CLOSED
    assert closed_1.charge_units == 0
    assert closed_1.terminal is True
    assert domain.transcript == frozen_transcript
    assert domain.attempts_used == 3
    assert domain.lifetime_spent_units == 12


def test_stop_continue_and_padding_are_typed_charged_and_deterministic():
    def stopped_transcript(domain_id: str, route_name: str):
        domain = _domain(
            domain_id,
            horizon=4,
            route_codebooks=(_codebook(name=route_name),),
        )
        _route(domain, name=route_name)
        _activate(domain)
        continued = domain.continue_work()
        stopped = domain.stop()
        return domain, continued, stopped

    left, continued, stopped = stopped_transcript(
        "secret-domain-left", "secret-route-left"
    )
    right, _, _ = stopped_transcript("secret-domain-right", "secret-route-right")

    assert continued.kind is EventKind.CONTINUE
    assert continued.outcome is OutcomeCode.CONTINUED
    assert stopped.kind is EventKind.STOP
    assert stopped.outcome is OutcomeCode.STOPPED
    assert stopped.terminal is True
    assert left.state is DomainState.CLOSED
    assert left.attempts_used == 4
    assert left.lifetime_spent_units == 16
    assert [event.kind for event in domain_events(left)] == [
        EventKind.CONTINUE,
        EventKind.STOP,
        EventKind.PADDING,
        EventKind.PADDING,
    ]
    assert [event.outcome for event in left.transcript] == [
        OutcomeCode.CONTINUED,
        OutcomeCode.STOPPED,
        OutcomeCode.PADDED,
        OutcomeCode.PADDED,
    ]
    assert all(event.charge_units == 4 for event in left.transcript)
    assert len(left.transcript) == left.attempt_horizon == 4
    # Domain and route names, as well as the reason for stopping, are hidden;
    # equal public histories therefore produce byte-for-byte equal transcripts.
    assert [event.to_wire() for event in left.transcript] == [
        event.to_wire() for event in right.transcript
    ]


def test_correlated_objects_debit_one_shared_lifetime_budget():
    # Two route-specific alphabets increase the combined slot support from
    # 11 to 18 outcomes, requiring a five-bit conservative envelope.
    domain = _domain(
        horizon=2,
        charge=5,
        budget=10,
        route_codebooks=(
            _codebook(name="release-a"),
            _codebook(name="release-b"),
        ),
    )
    route_a = _route(domain, name="release-a", protected_object="record-a")
    route_b = _route(domain, name="release-b", protected_object="record-b")
    _activate(domain)

    payload_a = {"record": "a"}
    payload_b = {"record": "b"}
    event_a = domain.attempt(
        route_a,
        payload_a,
        credential=_credential(route_a, payload_a, nonce="a"),
    )
    assert domain.lifetime_spent_units == 5
    event_b = domain.attempt(
        route_b,
        payload_b,
        credential=_credential(route_b, payload_b, nonce="b"),
    )

    assert event_a.outcome is OutcomeCode.RELEASED
    assert event_b.outcome is OutcomeCode.RELEASED
    assert domain.lifetime_budget_units == 10
    assert domain.lifetime_spent_units == 10
    assert domain.attempts_used == 2
    assert domain.state is DomainState.CLOSED


def test_route_tokens_are_opaque_round_trip_handles():
    domain = _domain(
        "internal-domain-id",
        route_codebooks=(_codebook(name="private-route-name"),),
    )
    route = _route(
        domain,
        name="private-route-name",
        protected_object="record-a",
    )

    assert isinstance(route, RouteToken)
    wire = route.to_wire()
    assert type(wire) is str
    assert RouteToken.from_wire(wire) == route
    for forbidden in ("internal-domain-id", "private-route-name", "record-a"):
        assert forbidden not in wire
        assert forbidden not in repr(route)
    for forbidden_attribute in (
        "domain_id",
        "route_id",
        "route_name",
        "protected_object",
    ):
        assert not hasattr(route, forbidden_attribute)


def test_cross_domain_route_and_capability_confusion_is_rejected():
    left = _domain(
        "left-domain",
        horizon=4,
        route_codebooks=(
            _codebook(name="left-effect", requires_capability=True),
        ),
    )
    left_route = _route(
        left,
        name="left-effect",
        requires_capability=True,
    )
    # Capability creation is a trusted, hidden setup operation; the untrusted
    # model sees neither this call nor the resulting handle.  Only the effect
    # broker receives the opaque handle after a successful mediated release.
    left_capability = left.issue_capability(left_route)
    _activate(left)
    assert isinstance(left_capability, EffectCapability)

    right = _domain(
        "right-domain",
        horizon=4,
        route_codebooks=(
            _codebook(name="right-effect", requires_capability=True),
        ),
    )
    right_route = _route(
        right,
        name="right-effect",
        requires_capability=True,
    )
    _activate(right)
    payload = {"action": "send"}

    foreign_route = right.attempt(left_route, payload, credential=None)
    right_credential = _credential(right_route, payload, nonce="right")
    foreign_capability = right.attempt(
        right_route,
        payload,
        credential=right_credential,
        capability=left_capability,
    )

    assert foreign_route.outcome is OutcomeCode.ROUTE_DENIED
    assert foreign_capability.outcome is OutcomeCode.CAPABILITY_DENIED
    assert [event.attempt for event in right.transcript] == [1, 2]
    assert all(event.charge_units == 4 for event in right.transcript)
    assert left.attempts_used == 0
    assert left.lifetime_spent_units == 0


def test_signed_reauthorization_adds_budget_and_horizon_without_resetting_lifetime():
    domain = _domain(
        horizon=2,
        budget=8,
        reauthorization_policy=ReauthorizationPolicy(
            budget_increment_units=8,
            attempt_increment=2,
        ),
    )
    route = _route(domain)
    _activate(domain)
    payload = {"request": "before reauth"}
    domain.attempt(
        route,
        payload,
        credential=_credential(route, payload, nonce="before"),
    )
    assert (domain.attempts_used, domain.lifetime_spent_units) == (1, 4)

    grant = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        budget_increment_units=8,
        attempt_increment=2,
        nonce="reauth-1",
    )
    event = domain.reauthorize(grant)

    assert event.kind is EventKind.REAUTHORIZE
    assert event.outcome is OutcomeCode.REAUTHORIZED
    assert event.charge_units == 4
    assert event.terminal is False  # grant extends H at the old boundary
    assert domain.state is DomainState.ACTIVE
    assert domain.lifetime_budget_units == 16
    assert domain.attempt_horizon == 4
    # The reauthorization event itself is attempt 2 and costs 4 units.  Neither
    # lifetime counter is reset when the signed increments are applied.
    assert domain.attempts_used == 2
    assert domain.lifetime_spent_units == 8

    after = {"request": "after reauth"}
    domain.attempt(
        route,
        after,
        credential=_credential(route, after, nonce="after"),
    )
    assert domain.attempts_used == 3
    assert domain.lifetime_spent_units == 12


def test_tampered_or_replayed_reauthorization_is_denied_but_still_charged():
    domain = _domain(
        horizon=5,
        budget=20,
        reauthorization_policy=ReauthorizationPolicy(
            budget_increment_units=4,
            attempt_increment=1,
        ),
    )
    _route(domain)
    _activate(domain)
    grant = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        budget_increment_units=4,
        attempt_increment=1,
        nonce="one-use-grant",
    )

    accepted = domain.reauthorize(grant)
    baseline = (
        domain.lifetime_budget_units,
        domain.attempt_horizon,
        domain.attempts_used,
        domain.lifetime_spent_units,
    )
    replayed = domain.reauthorize(grant)
    tampered = domain.reauthorize(
        replace(grant, budget_increment_units=1_000_000)
    )

    assert accepted.outcome is OutcomeCode.REAUTHORIZED
    assert replayed.outcome is OutcomeCode.REAUTH_DENIED
    assert tampered.outcome is OutcomeCode.REAUTH_DENIED
    # Only the accepted grant changes the limits. Denied events still consume
    # one attempt and one fixed public-event charge each.
    assert domain.lifetime_budget_units == baseline[0]
    assert domain.attempt_horizon == baseline[1]
    assert domain.attempts_used == baseline[2] + 2
    assert domain.lifetime_spent_units == baseline[3] + 8
    assert replayed.charge_units == tampered.charge_units == 4


def test_domain_lifecycle_cannot_be_skipped_or_reopened():
    domain = _domain(horizon=1)
    route = _route(domain)
    payload = {"message": "x"}
    credential = _credential(route, payload)
    assert domain.state is DomainState.DRAFT

    with pytest.raises(DomainLifecycleError):
        domain.activate()
    with pytest.raises(DomainLifecycleError):
        domain.attempt(route, payload, credential=credential)

    domain.seal()
    assert domain.state is DomainState.SEALED
    with pytest.raises(DomainLifecycleError):
        _route(domain, name="late-route")

    domain.activate()
    assert domain.state is DomainState.ACTIVE
    domain.attempt(route, payload, credential=credential)
    assert domain.state is DomainState.CLOSED
    with pytest.raises(DomainLifecycleError):
        domain.activate()
    with pytest.raises(DomainLifecycleError):
        domain.register_route(
            name="reopen-route",
            protected_object="record-a",
            handler=lambda value: value,
        )


def test_invalid_domain_envelope_is_rejected_before_sealing():
    # A fixed H transcript needs enough lifetime budget to reserve every slot;
    # otherwise a secret-dependent early stop could make padding unaffordable.
    underfunded = _domain(horizon=3, charge=2, budget=5)
    _route(underfunded)
    with pytest.raises(ValueError, match="budget|horizon|charge"):
        underfunded.seal()

    for field, invalid in (
        ("lifetime_budget_units", True),
        ("attempt_horizon", 0),
        ("event_charge_units", 0),
    ):
        values = {
            "domain_id": "invalid-domain",
            "protected_objects": frozenset({"record-a"}),
            "lifetime_budget_units": 2,
            "attempt_horizon": 1,
            "event_charge_units": 2,
        }
        values[field] = invalid
        with pytest.raises((TypeError, ValueError)):
            DomainConfig(**values)
