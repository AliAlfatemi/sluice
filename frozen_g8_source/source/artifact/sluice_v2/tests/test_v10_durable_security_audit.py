"""Independent fail-first probes for the durable secure-domain boundary.

These tests intentionally exercise contracts that are easy to miss in a
single-process happy-path suite: handler failure coarsening, argument TOCTOU,
live-owner recovery races, public delivery order, OS redeemer identity,
epoch freshness, sealed configuration, and process-level claim races.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields
import multiprocessing
import os
import sqlite3
import threading
import time

import pytest

from sluice_v2.durable_secure import (
    AttemptCredential,
    DomainConfig,
    DomainLifecycleError,
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


CALLER_KEY = b"durable-audit-caller-key-32bytes"
REAUTH_KEY = b"durable-audit-reauth-key-32bytes"


def _zero(_payload):
    return 0


def _effect_adapter(handler):
    if type(handler) is IdempotentEffectHandler:
        return handler

    def execute(request: EffectRequest) -> EffectResult:
        return EffectResult.for_request(request, handler(request.payload))

    return IdempotentEffectHandler(execute=execute, reconcile=lambda _request: None)


def _config(*, horizon: int = 4, charge: int = 4) -> DomainConfig:
    return DomainConfig(
        domain_id="audit-domain",
        protected_objects=frozenset({"object-a"}),
        lifetime_budget_units=horizon * charge,
        attempt_horizon=horizon,
        event_charge_units=charge,
    )


def _create(
    path,
    *,
    handler=_zero,
    horizon: int = 4,
    reauthorization_policy: ReauthorizationPolicy | None = None,
):
    domain = DurableSecureDomain.create(
        path,
        config=_config(horizon=horizon),
        observer_spec=ObserverSpec(
            frozenset({0, 1}),
            observer_spec_id="durable-v10-release-codebook-v1",
            route_codebooks=(
                RouteCodebook("release", frozenset({0, 1})),
            ),
        ),
        reauthorization_policy=reauthorization_policy,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": handler},
    )
    route = domain.register_route(
        name="release",
        protected_object="object-a",
        handler_key="handler",
        public_values=frozenset({0, 1}),
        requires_capability=False,
    )
    return domain, route


def _create_effect(path, *, handler=_zero, horizon: int = 4):
    handler = _effect_adapter(handler)
    domain = DurableSecureDomain.create(
        path,
        config=_config(horizon=horizon),
        observer_spec=ObserverSpec(
            frozenset({0, 1}),
            observer_spec_id="durable-v10-effect-codebook-v1",
            route_codebooks=(
                RouteCodebook("effect", frozenset({0, 1}), True),
            ),
        ),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": handler},
    )
    route = domain.register_route(
        name="effect",
        protected_object="object-a",
        handler_key="handler",
        public_values=frozenset({0, 1}),
        requires_capability=True,
    )
    return domain, route


def _activate(domain: DurableSecureDomain) -> None:
    domain.seal()
    domain.activate()


def _credential(
    domain: DurableSecureDomain, route: RouteToken, payload, nonce: str
) -> AttemptCredential:
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


def _reopen(path, *, handler=_zero) -> DurableSecureDomain:
    connection = sqlite3.connect(path)
    try:
        effectful = connection.execute(
            "SELECT 1 FROM routes WHERE handler_key='handler' "
            "AND requires_capability=1 LIMIT 1"
        ).fetchone() is not None
    finally:
        connection.close()
    if effectful:
        handler = _effect_adapter(handler)
    return DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": handler},
    )


class _FatalHandlerError(BaseException):
    pass


def test_handler_baseexception_is_coarsened_and_finalized_immediately(tmp_path):
    def fatal(_payload):
        raise _FatalHandlerError("private backend detail must not escape")

    domain, route = _create(tmp_path / "baseexception.sqlite3", handler=fatal)
    _activate(domain)
    payload = {"request": "private"}

    event = domain.attempt(
        route,
        payload,
        credential=_credential(domain, route, payload, "baseexception"),
    )

    assert event.outcome is OutcomeCode.INTERNAL_DENIED
    assert domain.transcript == (event,)
    assert domain.attempts_used == 1


def test_unicode_redeemer_never_causes_an_uncharged_raw_exception(tmp_path):
    domain, route = _create_effect(tmp_path / "unicode-redeemer.sqlite3")
    payload = {"effect": 1}
    # The identifier validator permits Unicode.  It is also acceptable for a
    # future stricter implementation to reject this at issuance, but accepting
    # it must not make compare_digest raise outside the transcript contract.
    try:
        capability = domain.issue_capability(
            route,
            payload=payload,
            redeemer_id="bröker",
            expires_at_lifetime_attempt=2,
        )
    except (TypeError, ValueError):
        return
    _activate(domain)

    event = domain.attempt(
        route,
        payload,
        credential=_credential(domain, route, payload, "unicode-redeemer"),
        capability=capability,
        redeemer_id="bröker",
    )

    assert isinstance(event, TranscriptEvent)
    assert event.outcome is OutcomeCode.RELEASED
    assert domain.attempts_used == 1


def test_effect_handler_receives_the_payload_snapshot_that_was_authorized(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    observed: list[str] = []

    def handler(payload):
        entered.set()
        assert release.wait(5)
        observed.append(payload["argument"])
        return 0

    domain, route = _create_effect(
        tmp_path / "payload-snapshot.sqlite3", handler=handler, horizon=2
    )
    payload = {"argument": "authorized"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    credential = _credential(domain, route, payload, "payload-snapshot")
    _activate(domain)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            domain.attempt,
            route,
            payload,
            credential=credential,
            capability=capability,
            redeemer_id="broker",
        )
        assert entered.wait(5)
        payload["argument"] = "altered-after-claim"
        release.set()
        event = future.result(timeout=5)

    assert event.outcome is OutcomeCode.RELEASED
    assert observed == ["authorized"]


def test_reopen_does_not_recover_an_attempt_owned_by_a_live_monitor(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    def slow(_payload):
        entered.set()
        assert release.wait(5)
        return 1

    path = tmp_path / "live-owner.sqlite3"
    domain, route = _create(path, handler=slow, horizon=2)
    _activate(domain)
    payload = {"request": "slow"}

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            domain.attempt,
            route,
            payload,
            credential=_credential(domain, route, payload, "live-owner"),
        )
        assert entered.wait(5)
        concurrent_instance = _reopen(path, handler=slow)
        release.set()
        event = future.result(timeout=5)

    assert event.outcome is OutcomeCode.RELEASED
    assert event.value_code == 1
    assert concurrent_instance.transcript == (event,)


def test_domain_closed_reply_is_not_delivered_before_terminal_event(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    def slow(_payload):
        entered.set()
        assert release.wait(5)
        return 0

    domain, route = _create(
        tmp_path / "closed-order.sqlite3", handler=slow, horizon=1
    )
    _activate(domain)
    payload = {"request": "terminal"}

    with ThreadPoolExecutor(max_workers=2) as pool:
        terminal_future = pool.submit(
            domain.attempt,
            route,
            payload,
            credential=_credential(domain, route, payload, "terminal-order"),
        )
        assert entered.wait(5)
        closed_future = pool.submit(domain.continue_work)
        time.sleep(0.1)
        closed_was_visible_early = closed_future.done()
        release.set()
        terminal = terminal_future.result(timeout=5)
        closed = closed_future.result(timeout=5)

    assert not closed_was_visible_early
    assert terminal.sequence == 1
    assert closed.kind is EventKind.DOMAIN_CLOSED
    assert closed.sequence == 2


def test_public_attempt_results_are_delivered_in_sequence_order(tmp_path):
    first_entered = threading.Event()
    release_first = threading.Event()

    def ordered(payload):
        if payload["request"] == "first":
            first_entered.set()
            assert release_first.wait(5)
        return 0

    domain, route = _create(
        tmp_path / "delivery-order.sqlite3", handler=ordered, horizon=2
    )
    _activate(domain)
    first_payload = {"request": "first"}
    second_payload = {"request": "second"}

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(
            domain.attempt,
            route,
            first_payload,
            credential=_credential(domain, route, first_payload, "delivery-first"),
        )
        assert first_entered.wait(5)
        second_future = pool.submit(
            domain.attempt,
            route,
            second_payload,
            credential=_credential(domain, route, second_payload, "delivery-second"),
        )
        time.sleep(0.1)
        second_was_visible_early = second_future.done()
        transcript_was_visible_early = domain.transcript
        release_first.set()
        first = first_future.result(timeout=5)
        second = second_future.result(timeout=5)

    assert not second_was_visible_early
    assert transcript_was_visible_early == ()
    assert [first.sequence, second.sequence] == [1, 2]


def test_handler_cannot_reenter_the_durable_domain(tmp_path):
    holder: dict[str, object] = {}
    nested_was_rejected = False

    def nested(_payload):
        nonlocal nested_was_rejected
        domain = holder["domain"]
        assert isinstance(domain, DurableSecureDomain)
        try:
            domain.continue_work()
        except DomainLifecycleError:
            nested_was_rejected = True
        return 0

    domain, route = _create(
        tmp_path / "nested.sqlite3", handler=nested, horizon=3
    )
    holder["domain"] = domain
    _activate(domain)
    payload = {"request": "outer"}

    event = domain.attempt(
        route,
        payload,
        credential=_credential(domain, route, payload, "nested"),
    )

    assert event.outcome is OutcomeCode.RELEASED
    assert nested_was_rejected
    assert domain.attempts_used == 1
    assert len(domain.transcript) == 1


def _spoofed_redeemer_worker(
    path: str,
    route_wire: str,
    payload,
    credential: AttemptCredential,
    capability_wire: str,
    asserted_redeemer: str,
    queue,
) -> None:
    domain = _reopen(path)
    event = domain.attempt(
        RouteToken.from_wire(route_wire),
        payload,
        credential=credential,
        capability=EffectCapability.from_wire(capability_wire),
        redeemer_id=asserted_redeemer,
    )
    queue.put(event.to_wire())


def test_redeemer_binding_uses_process_identity_not_caller_asserted_text(tmp_path):
    path = tmp_path / "redeemer-process.sqlite3"
    domain, route = _create_effect(path, horizon=2)
    payload = {"effect": "bound"}
    parent_identity = f"pid:{os.getpid()}"
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id=parent_identity,
        expires_at_lifetime_attempt=2,
    )
    credential = _credential(domain, route, payload, "process-redeemer")
    _activate(domain)

    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    process = context.Process(
        target=_spoofed_redeemer_worker,
        args=(
            str(path),
            route.to_wire(),
            payload,
            credential,
            capability.to_wire(),
            parent_identity,
            queue,
        ),
    )
    process.start()
    process.join(10)
    assert process.exitcode == 0
    event = TranscriptEvent.from_wire(queue.get(timeout=2))

    assert event.outcome is OutcomeCode.CAPABILITY_DENIED


def test_credential_from_an_old_epoch_cannot_claim_in_a_new_epoch(tmp_path):
    domain, route = _create(
        tmp_path / "credential-epoch.sqlite3",
        horizon=4,
        reauthorization_policy=ReauthorizationPolicy(4, 1),
    )
    payload = {"request": "epoch-bound"}
    old_epoch_credential = _credential(domain, route, payload, "old-epoch")
    _activate(domain)
    grant = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=domain.current_epoch,
        budget_increment_units=4,
        attempt_increment=1,
        nonce="new-epoch",
        expires_at_lifetime_attempt=domain.attempt_horizon,
    )
    assert domain.reauthorize(grant).outcome is OutcomeCode.REAUTHORIZED
    assert domain.current_epoch == 1

    event = domain.attempt(route, payload, credential=old_epoch_credential)

    assert event.outcome is OutcomeCode.AUTH_DENIED


def test_sealed_lifecycle_cannot_be_downgraded_by_direct_sql(tmp_path):
    path = tmp_path / "sealed-state.sqlite3"
    domain, _route = _create(path)
    _activate(domain)

    connection = sqlite3.connect(path)
    rejected = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("UPDATE metadata SET state='draft' WHERE singleton=1")
        except sqlite3.IntegrityError:
            rejected = True
    finally:
        connection.rollback()
        connection.close()

    assert rejected


def test_durable_credentials_expose_commit_checked_expiry_field():
    credential_fields = {field.name for field in fields(AttemptCredential)}
    assert "expires_at_lifetime_attempt" in credential_fields


def test_durable_grants_expose_commit_checked_expiry_field():
    grant_fields = {field.name for field in fields(ReauthorizationGrant)}
    assert "expires_at_lifetime_attempt" in grant_fields


def test_credential_expiry_is_checked_inside_the_atomic_claim(tmp_path):
    domain, route = _create(tmp_path / "credential-expiry.sqlite3", horizon=3)
    payload = {"request": "expires-after-first-slot"}
    credential = AttemptCredential.sign(
        agent_id="worker",
        signing_key=CALLER_KEY,
        domain_context=domain.credential_context,
        expected_epoch=domain.current_epoch,
        route=route,
        payload=payload,
        nonce="credential-expiry",
        expires_at_lifetime_attempt=1,
    )
    _activate(domain)
    assert domain.continue_work().attempt == 1

    expired = domain.attempt(route, payload, credential=credential)

    assert expired.outcome is OutcomeCode.AUTH_DENIED
    assert domain.attempts_used == 2


def test_grant_epoch_and_expiry_are_checked_inside_the_atomic_claim(tmp_path):
    domain, _route = _create(
        tmp_path / "grant-expiry.sqlite3",
        horizon=3,
        reauthorization_policy=ReauthorizationPolicy(4, 1),
    )
    grant = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=domain.current_epoch,
        budget_increment_units=4,
        attempt_increment=1,
        nonce="grant-expiry",
        expires_at_lifetime_attempt=1,
    )
    _activate(domain)
    assert domain.continue_work().attempt == 1

    expired = domain.reauthorize(grant)

    assert expired.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.current_epoch == 0
    assert domain.attempts_used == 2


def test_effect_result_must_link_request_id_and_fingerprint(tmp_path):
    def mismatched(request: EffectRequest) -> EffectResult:
        return EffectResult(
            request_id="sluice-effect-request-v1." + "x" * 43,
            fingerprint=request.fingerprint,
            value_code=0,
        )

    domain, route = _create_effect(
        tmp_path / "effect-linkage.sqlite3",
        handler=IdempotentEffectHandler(
            execute=mismatched,
            reconcile=lambda _request: None,
        ),
        horizon=2,
    )
    payload = {"effect": "linked"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    credential = _credential(domain, route, payload, "effect-linkage")
    _activate(domain)

    event = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker",
    )

    assert event.outcome is OutcomeCode.OUTPUT_DENIED


def _effect_then_exit_worker(
    path: str,
    effect_journal_path: str,
    route_wire: str,
    payload,
    credential: AttemptCredential,
    capability_wire: str,
) -> None:
    def commit_effect_then_exit(request: EffectRequest):
        connection = sqlite3.connect(effect_journal_path)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS completed "
            "(request_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, "
            "value_code INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO completed VALUES (?, ?, 0)",
            (request.request_id, request.fingerprint),
        )
        connection.commit()
        connection.close()
        os._exit(74)

    domain = _reopen(
        path,
        handler=IdempotentEffectHandler(
            execute=commit_effect_then_exit,
            reconcile=lambda _request: None,
        ),
    )
    domain.attempt(
        RouteToken.from_wire(route_wire),
        payload,
        credential=credential,
        capability=EffectCapability.from_wire(capability_wire),
        redeemer_id="broker",
    )


def test_recovery_reconciles_a_committed_effect_result(tmp_path):
    path = tmp_path / "effect-recovery.sqlite3"
    effect_journal = tmp_path / "effect-journal.sqlite3"
    domain, route = _create_effect(path, horizon=2)
    payload = {"effect": "crash-after-tool-commit"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    credential = _credential(domain, route, payload, "effect-recovery")
    _activate(domain)

    context = multiprocessing.get_context("fork")
    process = context.Process(
        target=_effect_then_exit_worker,
        args=(
            str(path),
            str(effect_journal),
            route.to_wire(),
            payload,
            credential,
            capability.to_wire(),
        ),
    )
    process.start()
    process.join(10)
    assert process.exitcode == 74

    connection = sqlite3.connect(effect_journal)
    completed = connection.execute(
        "SELECT request_id, fingerprint, value_code FROM completed"
    ).fetchall()
    connection.close()
    assert len(completed) == 1
    assert completed[0][0].startswith("sluice-effect-request-v1.")
    assert len(completed[0][1]) == 64
    assert completed[0][2] == 0

    # A broker adapter can make replay idempotent by returning its journaled
    # result. Recovery must consult that durable edge instead of labeling a
    # definitely committed effect as an internal denial.
    def reconcile(request: EffectRequest):
        connection = sqlite3.connect(effect_journal)
        row = connection.execute(
            "SELECT request_id, fingerprint, value_code FROM completed "
            "WHERE request_id=?",
            (request.request_id,),
        ).fetchone()
        connection.close()
        if row is None:
            return None
        return EffectResult(
            request_id=row[0], fingerprint=row[1], value_code=row[2]
        )

    recovered = _reopen(
        path,
        handler=IdempotentEffectHandler(
            execute=lambda request: EffectResult.for_request(request, 0),
            reconcile=reconcile,
        ),
    )
    assert len(recovered.transcript) == 1
    assert recovered.transcript[0].outcome is OutcomeCode.RELEASED
    assert recovered.transcript[0].value_code == 0


def _racing_claim_worker(
    path: str,
    route_wire: str,
    payload,
    credential: AttemptCredential,
    capability_wire: str,
    barrier,
    queue,
) -> None:
    domain = _reopen(path)
    barrier.wait(timeout=10)
    event = domain.attempt(
        RouteToken.from_wire(route_wire),
        payload,
        credential=credential,
        capability=EffectCapability.from_wire(capability_wire),
        redeemer_id="broker",
    )
    queue.put(event.to_wire())


def test_two_processes_cannot_both_redeem_one_credential_and_capability(tmp_path):
    path = tmp_path / "process-race.sqlite3"
    domain, route = _create_effect(path, horizon=2)
    payload = {"effect": "once"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    credential = _credential(domain, route, payload, "process-race")
    _activate(domain)

    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    barrier = context.Barrier(2)
    args = (
        str(path),
        route.to_wire(),
        payload,
        credential,
        capability.to_wire(),
        barrier,
        queue,
    )
    processes = [context.Process(target=_racing_claim_worker, args=args) for _ in range(2)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0

    outcomes = [
        TranscriptEvent.from_wire(queue.get(timeout=2)).outcome for _ in processes
    ]
    assert outcomes.count(OutcomeCode.RELEASED) == 1
    assert outcomes.count(OutcomeCode.AUTH_DENIED) == 1
    reopened = _reopen(path)
    assert reopened.attempts_used == 2
    assert reopened.lifetime_spent_units == 8


def test_capability_expiry_is_checked_at_the_atomic_claim_attempt(tmp_path):
    domain, route = _create_effect(tmp_path / "expiry.sqlite3", horizon=3)
    payload = {"effect": "expires"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=1,
    )
    credential = _credential(domain, route, payload, "expiry")
    _activate(domain)

    denied = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="wrong",
    )
    expired = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker",
    )

    assert denied.outcome is OutcomeCode.CAPABILITY_DENIED
    assert expired.outcome is OutcomeCode.CAPABILITY_DENIED
    assert domain.attempts_used == 2


def test_audit_start_failure_rolls_back_reservation_and_authorizations(tmp_path):
    path = tmp_path / "audit-rollback.sqlite3"
    domain, route = _create_effect(path, horizon=2)
    payload = {"effect": "audit"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=2,
    )
    credential = _credential(domain, route, payload, "audit-rollback")
    _activate(domain)

    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TRIGGER fail_audit_insert BEFORE INSERT ON audit_log "
        "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END"
    )
    connection.commit()
    connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="audit failure"):
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

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER fail_audit_insert")
    connection.commit()
    connection.close()
    event = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker",
    )
    assert event.outcome is OutcomeCode.RELEASED
