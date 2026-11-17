"""Independent fail-first contracts for the frozen durable-v2 repair.

These probes separate three properties that happy-path SQLite tests can blur:
persisted transcript order versus actual response-delivery order, same-thread
versus cross-thread backend reentry, and SQLite transaction durability versus
the filesystem on which the WAL lives.  They intentionally do not modify the
implementation under audit.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import time

import pytest

import sluice_v2.durable_secure as durable_secure
from sluice_v2.durable_secure import (
    AttemptCredential,
    DomainConfig,
    DurableConfigurationError,
    DurableDeliveryError,
    DurableSecureDomain,
    EffectRequest,
    EffectResult,
    IdempotentEffectHandler,
    ObserverSpec,
    ReauthorizationGrant,
    ReauthorizationPolicy,
    RouteCodebook,
    _decode_canonical_payload,
)
from sluice_v2.observer import OutcomeCode
from sluice_v2.secure import _canonical_payload


CALLER_KEY = b"durable-v14-caller-key-32bytes"
REAUTH_KEY = b"durable-v14-reauth-key-32bytes"


def _config(*, horizon: int = 4) -> DomainConfig:
    return DomainConfig(
        domain_id="durable-v14-domain",
        protected_objects=frozenset({"object-a"}),
        lifetime_budget_units=horizon * 4,
        attempt_horizon=horizon,
        event_charge_units=4,
    )


def _observer_spec(
    *,
    route_name: str = "release",
    values: frozenset[int] = frozenset({0, 1}),
    requires_capability: bool = False,
) -> ObserverSpec:
    return ObserverSpec(
        frozenset({0, 1}),
        observer_spec_id=f"durable-v14-{route_name}-codebook-v1",
        route_codebooks=(
            RouteCodebook(route_name, values, requires_capability),
        ),
    )


def _create(
    path: Path,
    handler,
    *,
    horizon: int = 4,
    reauthorization_policy: ReauthorizationPolicy | None = None,
):
    domain = DurableSecureDomain.create(
        path,
        config=_config(horizon=horizon),
        observer_spec=_observer_spec(),
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
    )
    domain.seal()
    domain.activate()
    return domain, route


def _credential(domain, route, payload, nonce: str) -> AttemptCredential:
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


def test_durable_payload_snapshot_canonicalization_is_type_injective():
    values = (
        None,
        False,
        True,
        0,
        1,
        0.0,
        -0.0,
        1.0,
        "",
        "0",
        "é",
        "e\u0301",
        [],
        (),
        {},
        [1],
        (1,),
        {"a": 1},
        {"a": "1"},
        {"a": [1]},
        {"a": (1,)},
    )
    encodings = tuple(_canonical_payload(value) for value in values)

    assert len(set(encodings)) == len(values)
    for original, encoded in zip(values, encodings, strict=True):
        snapshot = _decode_canonical_payload(encoded)
        assert _canonical_payload(snapshot) == _canonical_payload(original)


def test_route_alphabet_must_match_precommitted_public_codebook(tmp_path):
    """A secret-selected realized alphabet cannot define its own charge."""

    observer_spec = _observer_spec(values=frozenset({0, 1}))
    path = tmp_path / "precommitted-codebook.sqlite3"
    domain = DurableSecureDomain.create(
        path,
        config=_config(horizon=2),
        observer_spec=observer_spec,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": lambda _payload: 0},
    )

    # The public manifest is already immutable in DRAFT, before any route or
    # protected backend execution can select a realized alphabet.
    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="manifest|immutable"):
            connection.execute(
                "UPDATE metadata SET route_codebooks_json='[]' WHERE singleton=1"
            )
    finally:
        connection.close()

    secret_realized_value = 1
    with pytest.raises(ValueError, match="precommitted|codebook"):
        domain.register_route(
            name="release",
            protected_object="object-a",
            handler_key="handler",
            public_values=frozenset({secret_realized_value}),
        )

    route = domain.register_route(
        name="release",
        protected_object="object-a",
        handler_key="handler",
        public_values=frozenset({0, 1}),
    )
    assert route is not None
    domain.seal()
    assert domain.observer_spec_id == observer_spec.observer_spec_id
    assert domain.codebook_sha256 == observer_spec.codebook_sha256

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE metadata SET route_codebooks_json='[]' WHERE singleton=1"
            )
    finally:
        connection.close()


def test_seal_requires_every_precommitted_route_codebook_entry(tmp_path):
    observer_spec = ObserverSpec(
        frozenset({0, 1}),
        observer_spec_id="durable-v14-complete-codebook-v1",
        route_codebooks=(
            RouteCodebook("release", frozenset({0, 1})),
            RouteCodebook("second", frozenset({0})),
        ),
    )
    domain = DurableSecureDomain.create(
        tmp_path / "incomplete-codebook.sqlite3",
        config=_config(horizon=2),
        observer_spec=observer_spec,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": lambda _payload: 0},
    )
    domain.register_route(
        name="release",
        protected_object="object-a",
        handler_key="handler",
        public_values=frozenset({0, 1}),
    )

    with pytest.raises(ValueError, match="precommitted|codebook"):
        domain.seal()


def test_reauthorization_policy_is_public_persisted_and_commit_checked(tmp_path):
    policy = ReauthorizationPolicy(
        budget_increment_units=8,
        attempt_increment=2,
    )
    path = tmp_path / "fixed-reauthorization.sqlite3"
    domain, _route = _create(
        path,
        lambda _payload: 0,
        horizon=5,
        reauthorization_policy=policy,
    )
    assert domain.reauthorization_policy == policy

    mismatch = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=0,
        budget_increment_units=12,
        attempt_increment=3,
        nonce="fixed-shape",
        expires_at_lifetime_attempt=5,
    )
    denied = domain.reauthorize(mismatch)
    assert denied.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.current_epoch == 0

    exact = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=0,
        budget_increment_units=8,
        attempt_increment=2,
        nonce="fixed-shape",
        expires_at_lifetime_attempt=5,
    )
    accepted = domain.reauthorize(exact)
    assert accepted.outcome is OutcomeCode.REAUTHORIZED
    assert domain.current_epoch == 1
    assert domain.attempt_horizon == 7
    assert domain.lifetime_budget_units == 28

    replay = domain.reauthorize(exact)
    assert replay.outcome is OutcomeCode.REAUTH_DENIED
    stale = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=0,
        budget_increment_units=8,
        attempt_increment=2,
        nonce="stale-fixed-shape",
        expires_at_lifetime_attempt=7,
    )
    assert domain.reauthorize(stale).outcome is OutcomeCode.REAUTH_DENIED

    reopened = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": lambda _payload: 0},
    )
    assert reopened.reauthorization_policy == policy
    assert reopened.codebook_sha256 == domain.codebook_sha256


def test_reauthorization_is_securely_disabled_without_frozen_policy(tmp_path):
    domain, _route = _create(
        tmp_path / "reauthorization-disabled.sqlite3",
        lambda _payload: 0,
        horizon=3,
    )
    grant = ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=0,
        budget_increment_units=4,
        attempt_increment=1,
        nonce="disabled",
        expires_at_lifetime_attempt=3,
    )

    event = domain.reauthorize(grant)

    assert event.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.current_epoch == 0
    assert domain.attempt_horizon == 3


def test_schema_two_ledger_reopen_fails_closed_without_policy_or_codebook(tmp_path):
    path = tmp_path / "old-schema.sqlite3"
    domain = DurableSecureDomain.create(
        path,
        config=_config(horizon=2),
        observer_spec=_observer_spec(),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": lambda _payload: 0},
    )
    domain.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER public_manifest_is_immutable")
        connection.execute("UPDATE metadata SET schema_version=2 WHERE singleton=1")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(DurableConfigurationError, match="schema"):
        DurableSecureDomain.reopen(
            path,
            agent_keys={"worker": CALLER_KEY},
            reauthorization_keys={"security-admin": REAUTH_KEY},
            handler_registry={"handler": lambda _payload: 0},
        )


def test_persisted_order_does_not_substitute_for_response_delivery_order(tmp_path):
    """Concurrent public returns must be serialized, or IPC must be single-writer.

    Pausing slot 1 only after it is FINALIZED exposes the gap in a waiter that
    checks merely for earlier RESERVED rows.  The database history remains
    ordered even though the later Python response overtakes the earlier one.
    """

    domain, route = _create(
        tmp_path / "response-order.sqlite3", lambda _payload: 0, horizon=2
    )
    first_at_delivery = threading.Event()
    release_first = threading.Event()
    completion_order: list[int] = []
    completion_lock = threading.Lock()
    original_delivery = domain._deliver_in_order

    def gated_delivery(event):
        if event.attempt == 1:
            first_at_delivery.set()
            assert release_first.wait(20)
        return original_delivery(event)

    # Test-only scheduling instrumentation: the same gap can occur from an OS
    # deschedule after commit and before the method returns.
    domain._deliver_in_order = gated_delivery

    def invoke(payload, nonce):
        event = domain.attempt(
            route,
            payload,
            credential=_credential(domain, route, payload, nonce),
        )
        with completion_lock:
            completion_order.append(event.sequence)
        return event

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke, {"request": "first"}, "first")
        assert first_at_delivery.wait(5)
        second = pool.submit(invoke, {"request": "second"}, "second")
        deadline = time.monotonic() + 0.25
        while not second.done() and time.monotonic() < deadline:
            time.sleep(0.005)
        later_returned_while_first_was_held = second.done()
        release_first.set()
        first_event = first.result(timeout=5)
        second_event = second.result(timeout=5)

    # Persistence is correctly causal; this assertion deliberately separates
    # it from the externally visible method-return order below.
    assert [event.sequence for event in domain.transcript] == [1, 2]
    assert [first_event.sequence, second_event.sequence] == [1, 2]
    assert not later_returned_while_first_was_held
    assert completion_order == [1, 2]


def test_capability_protected_route_requires_explicit_effect_reconciler(tmp_path):
    """Every route labelled effectful must cross the request/journal seam."""

    domain = DurableSecureDomain.create(
        tmp_path / "plain-effect.sqlite3",
        config=_config(horizon=2),
        observer_spec=_observer_spec(
            route_name="effect", requires_capability=True
        ),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"plain": lambda _payload: 0},
    )
    rejected_at_registration = False
    try:
        domain.register_route(
            name="effect",
            protected_object="object-a",
            handler_key="plain",
            public_values=frozenset({0, 1}),
            requires_capability=True,
        )
    except DurableConfigurationError:
        rejected_at_registration = True

    if not rejected_at_registration:
        with pytest.raises(DurableConfigurationError, match="effect|reconcil|idempot"):
            domain.seal()


def test_ambiguous_effect_exception_reconciles_before_finalization(tmp_path):
    """A committed broker effect is not mislabeled when its reply is lost."""

    journal: dict[str, tuple[str, int]] = {}
    reconcile_calls: list[str] = []

    class LostReply(BaseException):
        pass

    def execute(request: EffectRequest):
        journal[request.request_id] = (request.fingerprint, 1)
        raise LostReply("effect committed but broker reply was lost")

    def reconcile(request: EffectRequest):
        reconcile_calls.append(request.request_id)
        persisted = journal.get(request.request_id)
        if persisted is None:
            return None
        return EffectResult(request.request_id, persisted[0], persisted[1])

    handler = IdempotentEffectHandler(execute=execute, reconcile=reconcile)
    domain = DurableSecureDomain.create(
        tmp_path / "ambiguous-effect.sqlite3",
        config=_config(horizon=3),
        observer_spec=_observer_spec(
            route_name="effect", requires_capability=True
        ),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"effect": handler},
    )
    route = domain.register_route(
        name="effect",
        protected_object="object-a",
        handler_key="effect",
        public_values=frozenset({0, 1}),
        requires_capability=True,
    )
    payload = {"effect": "committed"}
    capability = domain.issue_capability(
        route,
        payload=payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=3,
    )
    credential = _credential(domain, route, payload, "ambiguous-effect")
    domain.seal()
    domain.activate()

    event = domain.attempt(
        route,
        payload,
        credential=credential,
        capability=capability,
        redeemer_id="broker",
    )

    assert event.outcome is OutcomeCode.RELEASED
    assert event.value_code == 1
    assert len(reconcile_calls) == 1
    # The same-thread handler context is released even though execute raised
    # BaseException; a later top-level operation remains available.
    assert domain.continue_work().outcome is OutcomeCode.CONTINUED


def test_post_finalize_interruption_recovers_event_and_does_not_wedge_delivery(
    tmp_path,
):
    """A lost COMMIT reply must not strand the same-process response prefix."""

    domain, route = _create(
        tmp_path / "post-finalize-interruption.sqlite3",
        lambda _payload: 0,
        horizon=3,
    )
    original_finalize = domain._finalize_attempt
    interrupted = False

    class LostFinalizeReply(BaseException):
        pass

    def finalize_then_interrupt(*args, **kwargs):
        nonlocal interrupted
        event = original_finalize(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise LostFinalizeReply("FINALIZED committed; local reply was lost")
        return event

    domain._finalize_attempt = finalize_then_interrupt
    first_payload = {"request": "first"}
    first = domain.attempt(
        route,
        first_payload,
        credential=_credential(domain, route, first_payload, "first-finalized"),
    )
    domain._finalize_attempt = original_finalize

    second_payload = {"request": "second"}
    second = domain.attempt(
        route,
        second_payload,
        credential=_credential(domain, route, second_payload, "second-finalized"),
    )

    assert [first.sequence, second.sequence] == [1, 2]
    assert [event.sequence for event in domain.transcript] == [1, 2]


def test_recovery_lost_finalize_reply_still_advances_abandoned_response(
    tmp_path, monkeypatch
):
    """Recovery has the same COMMIT-reply ambiguity as a live finalizer."""

    path = tmp_path / "recovery-finalize-interruption.sqlite3"
    domain, route = _create(path, lambda _payload: 0, horizon=2)
    payload = {"request": "reserved-before-recovery"}

    class SimulatedProcessLoss(BaseException):
        pass

    def interrupt_after_reservation(stage):
        if stage == "after_reservation_commit":
            raise SimulatedProcessLoss("caller disappeared with RESERVED row")

    domain._fault_hook = interrupt_after_reservation
    with pytest.raises(SimulatedProcessLoss):
        domain.attempt(
            route,
            payload,
            credential=_credential(domain, route, payload, "reserved-recovery"),
        )
    domain._fault_hook = None
    assert domain.transcript == ()

    original_finalize = DurableSecureDomain._finalize_attempt
    interrupted = False

    class LostRecoveryFinalizeReply(BaseException):
        pass

    def finalize_then_interrupt(self, *args, **kwargs):
        nonlocal interrupted
        event = original_finalize(self, *args, **kwargs)
        if not interrupted:
            interrupted = True
            raise LostRecoveryFinalizeReply("recovery FINALIZED; reply lost")
        return event

    monkeypatch.setattr(
        DurableSecureDomain,
        "_finalize_attempt",
        finalize_then_interrupt,
    )
    recovered = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry={"handler": lambda _payload: 0},
    )
    monkeypatch.setattr(DurableSecureDomain, "_finalize_attempt", original_finalize)

    assert recovered.transcript[0].outcome is OutcomeCode.INTERNAL_DENIED
    second_payload = {"request": "after-recovery"}
    second = recovered.attempt(
        route,
        second_payload,
        credential=_credential(
            recovered,
            route,
            second_payload,
            "after-recovery",
        ),
    )
    assert second.sequence == 2


def test_interrupted_stop_delivery_skips_nonreturning_padding_prefix(tmp_path):
    """An abandoned STOP response must advance across its persisted padding."""

    handler_entered = threading.Event()
    release_handler = threading.Event()

    def handler(_payload):
        handler_entered.set()
        assert release_handler.wait(10)
        return 0

    domain, route = _create(
        tmp_path / "interrupted-stop.sqlite3",
        handler,
        horizon=4,
    )
    payload = {"request": "holds-first-slot"}
    first_result: list[object] = []
    first_thread = threading.Thread(
        target=lambda: first_result.append(
            domain.attempt(
                route,
                payload,
                credential=_credential(domain, route, payload, "first-before-stop"),
            )
        ),
        daemon=True,
    )
    first_thread.start()
    assert handler_entered.wait(5)

    original_recover = domain._recover_reserved_attempts
    interrupted = False

    class LostStopTransport(BaseException):
        pass

    def interrupt_stop_wait_once():
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise LostStopTransport("STOP response transport disappeared")
        return original_recover()

    domain._recover_reserved_attempts = interrupt_stop_wait_once
    stop_errors: list[BaseException] = []

    def stop_worker():
        try:
            domain.stop()
        except BaseException as exc:
            stop_errors.append(exc)

    stop_thread = threading.Thread(target=stop_worker, daemon=True)
    stop_thread.start()
    stop_thread.join(5)
    assert not stop_thread.is_alive()
    assert len(stop_errors) == 1
    assert type(stop_errors[0]) is DurableDeliveryError
    assert str(stop_errors[0]) == "durable response delivery was interrupted"

    domain._recover_reserved_attempts = original_recover
    release_handler.set()
    first_thread.join(5)
    assert not first_thread.is_alive()
    assert len(first_result) == 1

    closed = domain.continue_work()
    assert closed.sequence == 5
    assert closed.outcome is OutcomeCode.DOMAIN_CLOSED
    assert [event.sequence for event in domain.transcript] == [1, 2, 3, 4]


def _mount_filesystem_type(path: Path) -> str | None:
    """Return Linux's longest-prefix mount type without invoking a shell."""

    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    target = str(path.resolve())
    best: tuple[int, str] | None = None
    for line in lines:
        try:
            left, right = line.split(" - ", 1)
            mountpoint = left.split()[4]
            mountpoint = (
                mountpoint.replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\")
            )
            filesystem_type = right.split()[0]
            if os.path.commonpath((target, mountpoint)) != mountpoint:
                continue
        except (IndexError, ValueError):
            continue
        if best is None or len(mountpoint) > best[0]:
            best = (len(mountpoint), filesystem_type)
    return None if best is None else best[1]


def test_wal_database_rejects_network_filesystem_by_default(tmp_path, monkeypatch):
    """SQLite WAL's local-host/shared-memory premise is an enforced precondition."""

    network_filesystems = {"nfs", "nfs4", "cifs", "smb3", "9p"}
    live_root = Path.cwd()
    filesystem_type = _mount_filesystem_type(live_root)
    if filesystem_type in network_filesystems:
        directory = Path(
            tempfile.mkdtemp(prefix=".durable-nfs-probe-", dir=live_root)
        )
    else:
        # Portable no-skip fallback: exercise the exact fail-closed decision
        # while the cluster-login evidence run above exercises a live NFS4 mount.
        directory = tmp_path / "synthetic-network-mount"
        directory.mkdir()
        monkeypatch.setattr(durable_secure, "_filesystem_type", lambda _path: "nfs4")
    try:
        with pytest.raises(
            DurableConfigurationError, match="filesystem|network|NFS|local"
        ):
            DurableSecureDomain.create(
                directory / "domain.sqlite3",
                config=_config(horizon=2),
                observer_spec=_observer_spec(),
                agent_keys={"worker": CALLER_KEY},
                reauthorization_keys={"security-admin": REAUTH_KEY},
                handler_registry={"handler": IdempotentEffectHandler(
                    execute=lambda request: None,
                    reconcile=lambda request: None,
                )},
            )
    finally:
        shutil.rmtree(directory)


def test_reopen_validates_database_mount_not_only_parent(tmp_path, monkeypatch):
    """A network-backed file bind mount must not inherit its parent's trust."""

    path = tmp_path / "file-mount.sqlite3"
    domain, _route = _create(path, lambda _payload: 0, horizon=2)
    domain.close()
    database_path = os.path.realpath(path)
    checked: list[str] = []

    def synthetic_mount_type(candidate):
        resolved = os.path.realpath(os.fspath(candidate))
        checked.append(resolved)
        return "nfs4" if resolved == database_path else "xfs"

    monkeypatch.setattr(durable_secure, "_filesystem_type", synthetic_mount_type)
    with pytest.raises(DurableConfigurationError, match="filesystem|local"):
        DurableSecureDomain.reopen(
            path,
            agent_keys={"worker": CALLER_KEY},
            reauthorization_keys={"security-admin": REAUTH_KEY},
            handler_registry={"handler": lambda _payload: 0},
        )

    assert database_path in checked
