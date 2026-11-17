"""Fail-first contract for the durable sealed secure-domain service.

The durable API is additive.  It stores private monitor state in SQLite while
the only observer-visible results remain the finite eight-field
``TranscriptEvent`` schema.  Backend callables are never serialized: routes
persist a stable handler key and trusted code rebinds that key on reopen.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
import os
import sqlite3
import time

import pytest

from sluice_v2.durable_secure import (
    AttemptCredential,
    DomainConfig,
    DomainLifecycleError,
    DomainState,
    DurableConfigurationError,
    DurableSecureDomain,
    EffectCapability,
    EffectRequest,
    EffectResult,
    IdempotentEffectHandler,
    ObserverSpec,
    ReauthorizationGrant,
    ReauthorizationPolicy,
    RouteCodebook,
    RouteToken,
)
from sluice_v2.observer import EventKind, OutcomeCode, TranscriptEvent


CALLER_KEY = b"durable-caller-verification-key!"
REAUTH_KEY = b"durable-reauth-authority-key!!"


def _effect_adapter(handler):
    if type(handler) is IdempotentEffectHandler:
        return handler

    def execute(request: EffectRequest) -> EffectResult:
        return EffectResult.for_request(request, handler(request.payload))

    return IdempotentEffectHandler(execute=execute, reconcile=lambda _request: None)


def _config(*, horizon=4, charge=4, budget=None, objects=None):
    if budget is None:
        budget = horizon * charge
    if objects is None:
        objects = frozenset({"object-a", "object-b"})
    return DomainConfig(
        domain_id="private-correlated-domain",
        protected_objects=frozenset(objects),
        lifetime_budget_units=budget,
        attempt_horizon=horizon,
        event_charge_units=charge,
    )


def _create(
    path,
    *,
    config=None,
    handlers=None,
    values=None,
    codebooks=None,
    reauthorization_policy=None,
    fault_hook=None,
):
    if config is None:
        config = _config()
    if handlers is None:
        handlers = {"release-v1": lambda payload: 0}
    if values is None:
        values = frozenset({0, 1})
    if codebooks is None:
        codebooks = (RouteCodebook("release", frozenset(values)),)
    return DurableSecureDomain.create(
        path,
        config=config,
        observer_spec=ObserverSpec(
            permitted_value_codes=frozenset(values),
            observer_spec_id="durable-v8-public-codebook-v1",
            route_codebooks=tuple(codebooks),
            accounting_units_per_bit=1,
        ),
        reauthorization_policy=reauthorization_policy,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry=handlers,
        fault_hook=fault_hook,
    )


def _reopen(path, *, handlers=None, fault_hook=None):
    if handlers is None:
        handlers = {"release-v1": lambda payload: 0}
    handlers = dict(handlers)
    connection = sqlite3.connect(path)
    try:
        effect_keys = {
            row[0]
            for row in connection.execute(
                "SELECT handler_key FROM routes WHERE requires_capability=1"
            )
        }
    finally:
        connection.close()
    for key in effect_keys.intersection(handlers):
        handlers[key] = _effect_adapter(handlers[key])
    return DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry=handlers,
        fault_hook=fault_hook,
    )


def _route(domain, *, name="release", obj="object-a", handler_key="release-v1",
           values=frozenset({0, 1}), effect=False):
    if effect:
        domain._handlers[handler_key] = _effect_adapter(domain._handlers[handler_key])
    return domain.register_route(
        name=name,
        protected_object=obj,
        handler_key=handler_key,
        public_values=frozenset(values),
        requires_capability=effect,
    )


def _credential(domain, route, payload, nonce):
    return AttemptCredential.sign(
        agent_id="worker",
        signing_key=CALLER_KEY,
        domain_context=domain.credential_context,
        expected_epoch=domain.current_epoch,
        route=route,
        payload=payload,
        nonce=nonce,
        expires_at_lifetime_attempt=domain.attempt_horizon,
    )


def _activate(domain):
    domain.seal()
    domain.activate()
    return domain


def test_lifecycle_observer_spec_and_handler_key_survive_reopen(tmp_path):
    path = tmp_path / "domain.sqlite3"
    domain = _create(path, handlers={"release-v1": lambda payload: 0})
    route = _route(domain)
    assert domain.state is DomainState.DRAFT

    domain = _reopen(path, handlers={"release-v1": lambda payload: 1})
    assert domain.state is DomainState.DRAFT
    domain.seal()
    assert domain.state is DomainState.SEALED
    domain = _reopen(path, handlers={"release-v1": lambda payload: 1})
    domain.activate()
    assert domain.state is DomainState.ACTIVE

    payload = {"request": "private"}
    event = domain.attempt(
        route, payload, credential=_credential(domain, route, payload, "stable-handler")
    )
    assert event.outcome is OutcomeCode.RELEASED
    assert event.value_code == 1

    with pytest.raises(DomainLifecycleError):
        _route(domain, name="late-route")
    with pytest.raises(DurableConfigurationError):
        _reopen(path, handlers={})


def test_seal_rejects_undercharged_or_underfunded_finite_support(tmp_path):
    undercharged = _create(
        tmp_path / "undercharged.sqlite3",
        config=_config(horizon=2, charge=3, budget=6),
    )
    _route(undercharged)
    # One two-valued route plus finite denials/lifecycle outcomes has eleven
    # possible public outcomes under the conservative envelope: ceil(log2)=4.
    with pytest.raises(ValueError, match="support"):
        undercharged.seal()

    underfunded = _create(
        tmp_path / "underfunded.sqlite3",
        config=_config(horizon=3, charge=4, budget=11),
    )
    _route(underfunded)
    with pytest.raises(ValueError, match="fund"):
        underfunded.seal()


def test_type_tagged_payload_binding_and_invalid_payload_are_charged(tmp_path):
    domain = _create(tmp_path / "payload.sqlite3")
    route = _route(domain)
    _activate(domain)

    integer_credential = _credential(domain, route, 1, "typed")
    mismatch = domain.attempt(route, "1", credential=integer_credential)
    # A failed claim does not burn the credential, so its exact typed payload
    # can still claim a later (separately charged) attempt.
    accepted = domain.attempt(route, 1, credential=integer_credential)
    malformed = AttemptCredential(
        agent_id="worker",
        domain_context=domain.credential_context,
        expected_epoch=domain.current_epoch,
        route_handle=route.to_wire(),
        nonce="non-string-map-key",
        expires_at_lifetime_attempt=domain.attempt_horizon,
        signature="invalid",
    )
    invalid = domain.attempt(route, {1: "unsupported"}, credential=malformed)

    assert [mismatch.outcome, accepted.outcome, invalid.outcome] == [
        OutcomeCode.AUTH_DENIED,
        OutcomeCode.RELEASED,
        OutcomeCode.AUTH_DENIED,
    ]
    assert domain.attempts_used == 3
    assert domain.lifetime_spent_units == 12


def test_failed_claim_consumes_neither_credential_nor_exact_capability(tmp_path):
    domain = _create(
        tmp_path / "claim.sqlite3",
        config=_config(horizon=3),
        codebooks=(
            RouteCodebook("release", frozenset({0, 1}), True),
        ),
    )
    route = _route(domain, effect=True)
    payload = {"slot": 7, "argument": "private"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker-process-7",
        expires_at_lifetime_attempt=3,
    )
    _activate(domain)
    credential = _credential(domain, route, payload, "atomic-claim")

    denied = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="different-broker",
    )
    accepted = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker-process-7",
    )
    replay = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker-process-7",
    )

    assert [denied.outcome, accepted.outcome, replay.outcome] == [
        OutcomeCode.CAPABILITY_DENIED,
        OutcomeCode.RELEASED,
        OutcomeCode.AUTH_DENIED,
    ]
    assert domain.audit_start_count == 3


class _Crash(BaseException):
    pass


def _abrupt_attempt_worker(
    path,
    route_wire,
    payload,
    credential,
    capability_wire,
    crash_stage,
):
    """Child-process target: terminate without Python/SQLite cleanup."""

    def abrupt(stage):
        if stage == crash_stage:
            os._exit(73)

    domain = _reopen(path, fault_hook=abrupt)
    domain.attempt(
        RouteToken.from_wire(route_wire),
        payload,
        credential=credential,
        capability=EffectCapability.from_wire(capability_wire),
        redeemer_id="broker",
    )


def test_crash_before_reservation_commit_rolls_back_every_claim_component(tmp_path):
    path = tmp_path / "before.sqlite3"

    def crash_before(stage):
        if stage == "before_reservation_commit":
            raise _Crash("simulated process loss before COMMIT")

    domain = _create(
        path,
        config=_config(horizon=2),
        codebooks=(RouteCodebook("release", frozenset({0, 1}), True),),
        fault_hook=crash_before,
    )
    route = _route(domain, effect=True)
    payload = {"effect": 1}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    _activate(domain)
    credential = _credential(domain, route, payload, "rollback-all")

    with pytest.raises(_Crash):
        domain.attempt(
            route,
            payload,
            credential=credential,
            capability=capability,
            redeemer_id="broker",
        )
    assert domain.attempts_used == 0
    assert domain.lifetime_spent_units == 0
    assert domain.audit_start_count == 0
    assert domain.transcript == ()

    domain = _reopen(path)
    event = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker",
    )
    assert event.outcome is OutcomeCode.RELEASED


def test_crash_after_commit_recovers_one_internal_denial_and_no_replay(tmp_path):
    path = tmp_path / "after.sqlite3"

    def crash_after(stage):
        if stage == "after_reservation_commit":
            raise _Crash("simulated process loss after COMMIT")

    domain = _create(
        path,
        config=_config(horizon=2),
        codebooks=(RouteCodebook("release", frozenset({0, 1}), True),),
        fault_hook=crash_after,
    )
    route = _route(domain, effect=True)
    payload = {"effect": "once"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    _activate(domain)
    credential = _credential(domain, route, payload, "committed-once")

    with pytest.raises(_Crash):
        domain.attempt(
            route,
            payload,
            credential=credential,
            capability=capability,
            redeemer_id="broker",
        )
    assert domain.attempts_used == 1
    assert domain.lifetime_spent_units == 4
    assert domain.audit_start_count == 1
    assert domain.transcript == ()  # RESERVED is not yet public.

    recovered = _reopen(path)
    assert len(recovered.transcript) == 1
    event = recovered.transcript[0]
    assert event.outcome is OutcomeCode.INTERNAL_DENIED
    assert event.attempt == 1
    assert event.charge_units == 4
    assert recovered.audit_start_count == 1

    replay = recovered.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker",
    )
    assert replay.outcome is OutcomeCode.AUTH_DENIED
    assert recovered.attempts_used == 2
    assert [item.attempt for item in recovered.transcript] == [1, 2]


@pytest.mark.parametrize(
    ("stage", "expected_attempts", "expected_events"),
    [
        ("before_reservation_commit", 0, 0),
        ("after_reservation_commit", 1, 1),
    ],
)
def test_abrupt_process_loss_obeys_the_sqlite_commit_boundary(
    tmp_path, stage, expected_attempts, expected_events
):
    path = tmp_path / f"abrupt-{stage}.sqlite3"
    domain = _create(
        path,
        config=_config(horizon=2),
        codebooks=(RouteCodebook("release", frozenset({0, 1}), True),),
    )
    route = _route(domain, effect=True)
    payload = {"effect": "abrupt"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    _activate(domain)
    credential = _credential(domain, route, payload, f"abrupt-{stage}")

    process = multiprocessing.get_context("fork").Process(
        target=_abrupt_attempt_worker,
        args=(
            str(path),
            route.to_wire(),
            payload,
            credential,
            capability.to_wire(),
            stage,
        ),
    )
    process.start()
    process.join(10)
    assert process.exitcode == 73

    recovered = _reopen(path)
    assert recovered.attempts_used == expected_attempts
    assert recovered.lifetime_spent_units == expected_attempts * 4
    assert recovered.audit_start_count == expected_attempts
    assert len(recovered.transcript) == expected_events
    if stage == "after_reservation_commit":
        assert recovered.transcript[0].outcome is OutcomeCode.INTERNAL_DENIED
        assert recovered.transcript[0].attempt == 1
    else:
        accepted = recovered.attempt(
            route,
            payload,
            credential=credential,
            capability=capability,
            redeemer_id="broker",
        )
        assert accepted.outcome is OutcomeCode.RELEASED


def test_correlated_objects_epochs_and_one_use_additive_reauthorization(tmp_path):
    path = tmp_path / "epochs.sqlite3"
    domain = _create(
        path,
        config=_config(horizon=2, charge=5, budget=10),
        handlers={"a": lambda payload: 0, "b": lambda payload: 1},
        codebooks=(
            RouteCodebook("a", frozenset({0, 1})),
            RouteCodebook("b", frozenset({0, 1})),
        ),
        reauthorization_policy=ReauthorizationPolicy(10, 2),
    )
    route_a = _route(domain, name="a", obj="object-a", handler_key="a")
    route_b = _route(domain, name="b", obj="object-b", handler_key="b")
    _activate(domain)

    payload_a = {"object": "a"}
    first = domain.attempt(
        route_a, payload_a, credential=_credential(domain, route_a, payload_a, "a")
    )
    grant = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=domain.current_epoch,
        budget_increment_units=10,
        attempt_increment=2,
        nonce="epoch-one",
        expires_at_lifetime_attempt=domain.attempt_horizon,
    )
    transition = domain.reauthorize(grant)

    assert first.outcome is OutcomeCode.RELEASED
    assert transition.outcome is OutcomeCode.REAUTHORIZED
    assert domain.current_epoch == 1
    assert domain.attempts_used == 2  # lifetime counters were not reset
    assert domain.lifetime_spent_units == 10
    assert domain.attempt_horizon == 4
    assert domain.lifetime_budget_units == 20
    assert [(e.epoch, e.attempts, e.spent_units, e.horizon_limit) for e in domain.epoch_stats] == [
        (0, 2, 10, 2),
        (1, 0, 0, 2),
    ]

    payload_b = {"object": "b"}
    second = domain.attempt(
        route_b, payload_b, credential=_credential(domain, route_b, payload_b, "b")
    )
    replay = domain.reauthorize(grant)
    assert second.value_code == 1
    assert replay.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.state is DomainState.CLOSED
    assert domain.attempts_used == 4
    assert domain.lifetime_spent_units == 20
    assert [(e.epoch, e.attempts, e.spent_units) for e in domain.epoch_stats] == [
        (0, 2, 10),
        (1, 2, 10),
    ]

    reopened = _reopen(path, handlers={"a": lambda payload: 0, "b": lambda payload: 1})
    assert reopened.current_epoch == 1
    assert reopened.attempts_used == 4
    assert reopened.reauthorization_context == domain.reauthorization_context


def test_underfunded_reauthorization_is_not_consumed_and_carries_unused_horizon(tmp_path):
    domain = _create(
        tmp_path / "reauth-funding.sqlite3",
        reauthorization_policy=ReauthorizationPolicy(8, 2),
    )
    _route(domain)
    _activate(domain)
    context = domain.reauthorization_context
    underfunded = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=context,
        expected_epoch=domain.current_epoch,
        budget_increment_units=7,
        attempt_increment=2,
        nonce="funding-check",
        expires_at_lifetime_attempt=domain.attempt_horizon,
    )
    denied = domain.reauthorize(underfunded)
    assert denied.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.current_epoch == 0
    assert domain.attempt_horizon == 4

    # The failed claim did not consume the authority/nonce pair.  A genuinely
    # funded grant using that pair can create the explicit epoch transition.
    funded = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=context,
        expected_epoch=domain.current_epoch,
        budget_increment_units=8,
        attempt_increment=2,
        nonce="funding-check",
        expires_at_lifetime_attempt=domain.attempt_horizon,
    )
    accepted = domain.reauthorize(funded)
    assert accepted.outcome is OutcomeCode.REAUTHORIZED
    assert domain.current_epoch == 1
    assert domain.attempts_used == 2
    assert domain.lifetime_spent_units == 8
    assert domain.attempt_horizon == 6
    assert domain.lifetime_budget_units == 24
    # Two unused old slots plus two added slots remain in the new epoch.
    assert domain.epoch_stats[1].horizon_limit == 4
    assert domain.reauthorize(funded).outcome is OutcomeCode.REAUTH_DENIED


def test_stop_padding_and_closed_reply_are_durable_and_uncharged(tmp_path):
    path = tmp_path / "stop.sqlite3"
    domain = _create(path, config=_config(horizon=3))
    route = _route(domain)
    _activate(domain)
    continued = domain.continue_work()
    stopped = domain.stop()

    assert continued.kind is EventKind.CONTINUE
    assert stopped.kind is EventKind.STOP
    assert stopped.terminal is True
    assert [event.kind for event in domain.transcript] == [
        EventKind.CONTINUE,
        EventKind.STOP,
        EventKind.PADDING,
    ]
    assert domain.attempts_used == 3
    assert domain.lifetime_spent_units == 12
    frozen = domain.transcript

    reopened = _reopen(path)
    payload = {"ignored": "after-close"}
    replies = [
        reopened.continue_work(),
        reopened.reauthorize(None),
        reopened.attempt(route, payload, credential=None),
    ]
    assert replies[0] == replies[1] == replies[2]
    assert replies[0].kind is EventKind.DOMAIN_CLOSED
    assert replies[0].charge_units == 0
    assert replies[0].terminal is True
    assert reopened.transcript == frozen
    assert reopened.attempts_used == 3


def test_concurrent_callers_cannot_oversubscribe_horizon(tmp_path):
    path = tmp_path / "race.sqlite3"

    def delayed(payload):
        time.sleep(0.02)
        return 0

    domain = _create(
        path,
        config=_config(horizon=2),
        handlers={"release-v1": delayed},
    )
    route = _route(domain)
    _activate(domain)

    def call(index):
        payload = {"index": index}
        return domain.attempt(
            route,
            payload,
            credential=_credential(domain, route, payload, f"race-{index}"),
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(call, range(12)))

    assert sum(event.kind is EventKind.ATTEMPT for event in results) == 2
    assert sum(event.kind is EventKind.DOMAIN_CLOSED for event in results) == 10
    assert domain.attempts_used == 2
    assert domain.lifetime_spent_units == 8
    assert len(domain.transcript) == 2
    assert [event.attempt for event in domain.transcript] == [1, 2]


def test_finalized_transcript_is_typed_private_and_database_immutable(tmp_path):
    path = tmp_path / "immutable.sqlite3"
    secret_id = "private-object-id"
    secret_route = "private-route-name"
    secret_payload = {"argument": "never-public@example.invalid"}
    domain = _create(
        path,
        config=_config(horizon=1, objects=frozenset({secret_id})),
        codebooks=(
            RouteCodebook(secret_route, frozenset({0, 1})),
        ),
    )
    route = _route(domain, name=secret_route, obj=secret_id)
    _activate(domain)
    event = domain.attempt(
        route,
        secret_payload,
        credential=_credential(domain, route, secret_payload, "private-nonce"),
    )

    assert isinstance(event, TranscriptEvent)
    assert type(domain.transcript) is tuple
    public = json.dumps([item.to_wire() for item in domain.transcript], sort_keys=True)
    for forbidden in (
        secret_id,
        secret_route,
        secret_payload["argument"],
        "private-nonce",
        route.to_wire(),
        "worker",
    ):
        assert forbidden not in public

    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE attempts SET event_json = '{}' WHERE state = 'FINALIZED'"
        )
    connection.close()
