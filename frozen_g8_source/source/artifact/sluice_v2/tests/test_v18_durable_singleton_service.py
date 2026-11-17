"""Hostile contract for the singleton durable monitor-service CPU foundation.

These tests exercise the real AF_UNIX/SOCK_SEQPACKET and SO_PEERCRED boundary.
No test is skipped: cluster-login is the Linux CPU host on which this integration is
claimed.  The model-facing wire is deliberately much smaller than the private
durable-domain API.
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import threading
import time

import pytest

from sluice_v2.durable_secure import (
    AttemptCredential,
    DurableSecureDomain,
    EffectRequest,
    EffectResult,
    IdempotentEffectHandler,
    ObserverSpec,
    RouteCodebook,
)
from sluice_v2.observer import EventKind, OutcomeCode, TranscriptEvent
from sluice_v2.secure import DomainConfig
from sluice_v2.durable_service import (
    BROKER_PROTOCOL_VERSION,
    MONITOR_PROTOCOL_VERSION,
    AuthenticatedBrokerEffectAdapter,
    BrokerCommand,
    BrokerJournal,
    BrokerOutcomeCode,
    BrokerReply,
    BrokerTemplateBinding,
    DurableDomainOpener,
    ModelOperationCode,
    ModelRequest,
    ModelResponse,
    MonitorServiceConfig,
    PeerIdentity,
    PrivateTemplateBinding,
    RequestConfusionError,
    SingletonMonitorService,
    connect_model,
    serve_broker,
)


CALLER_KEY = b"singleton-monitor-caller-key-v1!"
REAUTH_KEY = b"singleton-monitor-reauth-key-v1!"


def _abstract(label: str) -> str:
    return "\0sluice-v18-" + label + "-" + str(os.getpid()) + "-" + os.urandom(8).hex()


def _peer(pid: int | None = None) -> PeerIdentity:
    return PeerIdentity(
        pid=os.getpid() if pid is None else pid,
        uid=os.getuid(),
        gid=os.getgid(),
    )


def _effect(handler):
    def execute(request: EffectRequest) -> EffectResult:
        return EffectResult.for_request(request, handler(request.payload))

    return IdempotentEffectHandler(execute=execute, reconcile=lambda _request: None)


def _make_domain(
    path: Path,
    *,
    templates: tuple[tuple[int, object], ...] = ((11, {"slot": 11}), (12, {"slot": 12})),
    handler=None,
    effect: bool = False,
):
    if handler is None:
        handler = lambda payload: int(payload["slot"])
    values = frozenset(int(payload["slot"]) for _, payload in templates)
    handler_key = "effect-v1" if effect else "release-v1"
    registry = {handler_key: _effect(handler) if effect else handler}
    domain = DurableSecureDomain.create(
        path,
        config=DomainConfig(
            domain_id="singleton-private-domain",
            protected_objects=frozenset({"object-a"}),
            lifetime_budget_units=48,
            attempt_horizon=8,
            event_charge_units=6,
        ),
        observer_spec=ObserverSpec(
            permitted_value_codes=values,
            observer_spec_id="singleton-service-observer-v1",
            route_codebooks=(RouteCodebook("release", values, effect),),
            accounting_units_per_bit=1,
        ),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry=registry,
    )
    route = domain.register_route(
        name="release",
        protected_object="object-a",
        handler_key=handler_key,
        public_values=values,
        requires_capability=effect,
    )
    bindings = []
    for code, payload in templates:
        capability = None
        if effect:
            capability = domain.issue_capability(
                route,
                payload=payload,
                redeemer_id="isolated-broker",
                expires_at_lifetime_attempt=8,
            )
        credential = AttemptCredential.sign(
            agent_id="worker",
            signing_key=CALLER_KEY,
            domain_context=domain.credential_context,
            expected_epoch=domain.current_epoch,
            route=route,
            payload=payload,
            nonce=f"template-{code}",
            expires_at_lifetime_attempt=8,
        )
        bindings.append(
            PrivateTemplateBinding(
                template_code=code,
                route=route,
                payload=payload,
                credential=credential,
                capability=capability,
                redeemer_id="isolated-broker" if effect else None,
            )
        )
    domain.seal()
    domain.activate()
    domain.close()
    return tuple(bindings), handler_key


def _opener(path: Path, handler_registry):
    return DurableDomainOpener(
        ledger_path=path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry=handler_registry,
    )


def _fork_monitor(
    *,
    path: Path,
    address: str,
    templates: tuple[PrivateTemplateBinding, ...],
    handler_registry,
    expected_model: PeerIdentity | None = None,
    expected_broker: PeerIdentity | None = None,
    crash_stage: str | None = None,
):
    ready_read, ready_write = os.pipe()
    parent_pid = os.getpid()
    config = MonitorServiceConfig(
        address=address,
        opener=_opener(path, handler_registry),
        templates=templates,
        expected_model=_peer() if expected_model is None else expected_model,
        expected_broker=expected_broker,
    )
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)

        def fault(stage: str) -> None:
            if stage == crash_stage:
                os._exit(73)

        try:
            SingletonMonitorService(config, fault_hook=fault).serve_forever(
                expected_parent_pid=parent_pid,
                ready_fd=ready_write,
            )
        finally:
            os._exit(111)
    os.close(ready_write)
    ready = os.read(ready_read, 1)
    os.close(ready_read)
    assert ready == b"R"
    return pid


def _terminate(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


def _wait_exit(pid: int, expected: int) -> None:
    waited, status = os.waitpid(pid, 0)
    assert waited == pid
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == expected


def _attempt(request_id: str, template_code: int) -> ModelRequest:
    return ModelRequest(
        schema_version=MONITOR_PROTOCOL_VERSION,
        request_id=request_id,
        operation_code=ModelOperationCode.ATTEMPT_TEMPLATE,
        template_code=template_code,
    )


def _operation(request_id: str, code: ModelOperationCode) -> ModelRequest:
    return ModelRequest(
        schema_version=MONITOR_PROTOCOL_VERSION,
        request_id=request_id,
        operation_code=code,
        template_code=None,
    )


def _raw_exchange(address: str, wire: object) -> bytes:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.settimeout(2.0)
    channel.connect(address)
    encoded = json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        channel.send(encoded)
    except (BrokenPipeError, ConnectionResetError):
        channel.close()
        return b""
    try:
        return channel.recv(4097)
    except (ConnectionResetError, socket.timeout):
        return b""
    finally:
        channel.close()


def test_model_schema_is_exact_finite_and_contains_no_private_authority():
    request = _attempt("request-A", 11)
    wire = request.to_wire()
    assert wire == {
        "schema_version": MONITOR_PROTOCOL_VERSION,
        "request_id": "request-A",
        "operation_code": int(ModelOperationCode.ATTEMPT_TEMPLATE),
        "template_code": 11,
    }
    encoded = json.dumps(wire, sort_keys=True)
    for forbidden in (
        "route",
        "token",
        "signing",
        "credential",
        "capability",
        "payload",
        "digest",
        "audit",
        "fingerprint",
        "redeemer",
    ):
        assert forbidden not in encoded.lower()

    for extra in (
        "route_token",
        "credential",
        "capability",
        "payload",
        "digest",
        "audit_data",
    ):
        with pytest.raises(ValueError):
            ModelRequest.from_wire({**wire, extra: "private"})

    with pytest.raises(ValueError):
        ModelRequest.from_wire({**wire, "schema_version": True})
    with pytest.raises(ValueError):
        ModelRequest.from_wire({**wire, "operation_code": 999})
    with pytest.raises(ValueError):
        ModelRequest.from_wire({**wire, "request_id": "x" * 65})
    with pytest.raises(ValueError):
        replace(request, operation_code=ModelOperationCode.STOP, template_code=11)


def test_model_response_is_only_request_binding_plus_public_transcript():
    event = TranscriptEvent(
        schema_version=1,
        sequence=1,
        attempt=1,
        kind=EventKind.ATTEMPT,
        outcome=OutcomeCode.RELEASED,
        value_code=11,
        charge_units=6,
        terminal=False,
    )
    response = ModelResponse(
        schema_version=MONITOR_PROTOCOL_VERSION,
        request_id="response-A",
        event=event,
    )
    assert ModelResponse.from_wire(response.to_wire()) == response
    with pytest.raises(ValueError):
        ModelResponse.from_wire({**response.to_wire(), "diagnostic": "secret"})


def test_retry_is_durable_idempotent_confusion_is_rejected_and_order_is_serial(tmp_path: Path):
    path = tmp_path / "domain.sqlite3"
    templates, _ = _make_domain(path)
    address = _abstract("retry")
    pid = _fork_monitor(
        path=path,
        address=address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    try:
        first = connect_model(address, _attempt("same-id", 11), expected_monitor=_peer(pid))
        retry = connect_model(address, _attempt("same-id", 11), expected_monitor=_peer(pid))
        second = connect_model(address, _attempt("next-id", 12), expected_monitor=_peer(pid))
        assert first == retry
        assert [first.sequence, second.sequence] == [1, 2]
        assert [first.value_code, second.value_code] == [11, 12]

        with pytest.raises((RequestConfusionError, EOFError, ConnectionError)):
            connect_model(address, _attempt("same-id", 12), expected_monitor=_peer(pid))
    finally:
        _terminate(pid)

    reopened = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    assert reopened.attempts_used == 2
    assert len(reopened.transcript) == 2
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT request_id, state FROM sluice_monitor_request_cache ORDER BY request_id"
        ).fetchall()
    finally:
        connection.close()
    assert rows == [("next-id", "DONE"), ("same-id", "DONE")]


def test_monitor_crash_after_domain_commit_recovers_same_event_without_recharge(tmp_path: Path):
    path = tmp_path / "crash.sqlite3"
    templates, _ = _make_domain(path)
    address1 = _abstract("crash-one")
    first_pid = _fork_monitor(
        path=path,
        address=address1,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
        crash_stage="after_domain_before_cache",
    )
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.connect(address1)
    channel.send(json.dumps(_attempt("crash-id", 11).to_wire(), separators=(",", ":")).encode("ascii"))
    assert channel.recv(4096) == b""
    channel.close()
    _wait_exit(first_pid, 73)

    address2 = _abstract("crash-two")
    second_pid = _fork_monitor(
        path=path,
        address=address2,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    try:
        recovered = connect_model(
            address2, _attempt("crash-id", 11), expected_monitor=_peer(second_pid)
        )
        replay = connect_model(
            address2, _attempt("crash-id", 11), expected_monitor=_peer(second_pid)
        )
        assert recovered == replay
        assert recovered.sequence == 1
        assert recovered.value_code == 11
    finally:
        _terminate(second_pid)

    domain = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    assert domain.attempts_used == 1
    assert domain.audit_start_count == 1


def test_monitor_crash_after_pending_before_domain_executes_only_once_on_recovery(tmp_path: Path):
    path = tmp_path / "pre-domain-crash.sqlite3"
    templates, _ = _make_domain(path)
    first_address = _abstract("pre-domain-one")
    first_pid = _fork_monitor(
        path=path,
        address=first_address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
        crash_stage="after_pending_before_domain",
    )
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.connect(first_address)
    channel.send(json.dumps(_attempt("pending-id", 11).to_wire(), separators=(",", ":")).encode("ascii"))
    assert channel.recv(4096) == b""
    channel.close()
    _wait_exit(first_pid, 73)

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT lifetime_attempts FROM metadata").fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM sluice_monitor_request_cache WHERE request_id='pending-id'"
        ).fetchone() == ("PENDING",)
    finally:
        connection.close()

    second_address = _abstract("pre-domain-two")
    second_pid = _fork_monitor(
        path=path,
        address=second_address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    try:
        event = connect_model(
            second_address, _attempt("pending-id", 11), expected_monitor=_peer(second_pid)
        )
        assert event.sequence == 1 and event.value_code == 11
    finally:
        _terminate(second_pid)

    domain = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    assert domain.attempts_used == 1


def test_client_reply_loss_keeps_monitor_live_and_retry_is_cached(tmp_path: Path):
    path = tmp_path / "reply-loss.sqlite3"
    templates, _ = _make_domain(path)
    address = _abstract("reply-loss")
    pid = _fork_monitor(
        path=path,
        address=address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    try:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.connect(address)
        channel.send(
            json.dumps(_attempt("lost-reply", 11).to_wire(), separators=(",", ":")).encode("ascii")
        )
        channel.close()
        deadline = time.monotonic() + 3.0
        state = None
        while time.monotonic() < deadline:
            connection = sqlite3.connect(path)
            try:
                row = connection.execute(
                    "SELECT state FROM sluice_monitor_request_cache WHERE request_id='lost-reply'"
                ).fetchone()
                state = None if row is None else row[0]
            finally:
                connection.close()
            if state == "DONE":
                break
            time.sleep(0.01)
        assert state == "DONE"
        retry = connect_model(address, _attempt("lost-reply", 11), expected_monitor=_peer(pid))
        assert retry.sequence == 1 and retry.value_code == 11
        next_event = connect_model(address, _attempt("after-loss", 12), expected_monitor=_peer(pid))
        assert next_event.sequence == 2
    finally:
        _terminate(pid)


def test_malformed_and_crashed_clients_fail_closed_without_a_charged_attempt(tmp_path: Path):
    path = tmp_path / "malformed.sqlite3"
    templates, _ = _make_domain(path)
    address = _abstract("malformed")
    pid = _fork_monitor(
        path=path,
        address=address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    try:
        # Authenticated client disconnect before a complete packet.
        empty = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        empty.connect(address)
        empty.close()

        forbidden = {**_attempt("bad-id", 11).to_wire(), "payload": {"secret": 1}}
        assert _raw_exchange(address, forbidden) == b""
        assert _raw_exchange(address, {"schema_version": 1}) == b""

        event = connect_model(address, _attempt("good-id", 11), expected_monitor=_peer(pid))
        assert event.sequence == 1
    finally:
        _terminate(pid)

    domain = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    assert domain.attempts_used == 1


def test_wrong_peer_pid_is_rejected_before_request_parsing(tmp_path: Path):
    path = tmp_path / "peer.sqlite3"
    templates, _ = _make_domain(path)
    address = _abstract("wrong-peer")
    pid = _fork_monitor(
        path=path,
        address=address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    read_fd, write_fd = os.pipe()
    attacker = os.fork()
    if attacker == 0:
        os.close(read_fd)
        result = _raw_exchange(address, _attempt("attacker", 11).to_wire())
        os.write(write_fd, b"closed" if result == b"" else b"accepted")
        os._exit(0)
    os.close(write_fd)
    verdict = os.read(read_fd, 16)
    os.close(read_fd)
    os.waitpid(attacker, 0)
    try:
        assert verdict == b"closed"
        legitimate = connect_model(address, _attempt("legitimate", 11), expected_monitor=_peer(pid))
        assert legitimate.sequence == 1
    finally:
        _terminate(pid)


def test_handler_spawned_thread_and_process_cannot_reenter_monitor_ipc(tmp_path: Path):
    path = tmp_path / "reentry.sqlite3"
    address = _abstract("handler-reentry")

    def reentering_handler(payload):
        wire = _attempt("forged-from-handler", 12).to_wire()

        def thread_attack():
            try:
                channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                channel.connect(address)
                channel.send(json.dumps(wire, separators=(",", ":")).encode("ascii"))
                channel.close()
            except OSError:
                pass

        thread = threading.Thread(target=thread_attack)
        thread.start()
        thread.join(timeout=1.0)
        child = os.fork()
        if child == 0:
            thread_attack()
            os._exit(0)
        return int(payload["slot"])

    templates, _ = _make_domain(path, handler=reentering_handler)
    pid = _fork_monitor(
        path=path,
        address=address,
        templates=templates,
        handler_registry={"release-v1": reentering_handler},
    )
    try:
        first = connect_model(address, _attempt("model-one", 11), expected_monitor=_peer(pid))
        second = connect_model(address, _attempt("model-two", 12), expected_monitor=_peer(pid))
        assert [first.sequence, second.sequence] == [1, 2]
        assert first.kind is EventKind.ATTEMPT
        assert second.kind is EventKind.ATTEMPT
    finally:
        _terminate(pid)

    domain = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    assert domain.attempts_used == 2
    assert all(event.kind is EventKind.ATTEMPT for event in domain.transcript)


def test_second_singleton_monitor_cannot_open_same_ledger(tmp_path: Path):
    path = tmp_path / "singleton.sqlite3"
    templates, _ = _make_domain(path)
    address1 = _abstract("singleton-one")
    pid = _fork_monitor(
        path=path,
        address=address1,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    address2 = _abstract("singleton-two")
    error_read, error_write = os.pipe()
    parent_pid = os.getpid()
    challenger = os.fork()
    if challenger == 0:
        os.close(error_read)
        config = MonitorServiceConfig(
            address=address2,
            opener=_opener(path, {"release-v1": lambda payload: int(payload["slot"])}),
            templates=templates,
            expected_model=_peer(parent_pid),
        )
        try:
            SingletonMonitorService(config).serve_forever(
                expected_parent_pid=parent_pid,
                ready_fd=None,
            )
        except BaseException:
            os.write(error_write, b"B")
            os._exit(0)
        os._exit(1)
    os.close(error_write)
    try:
        assert os.read(error_read, 1) == b"B"
        _wait_exit(challenger, 0)
    finally:
        os.close(error_read)
        _terminate(pid)


def test_broker_schema_journal_reconcile_and_request_confusion(tmp_path: Path):
    effects: dict[str, int] = {}

    def execute(request_id: str) -> int:
        effects.setdefault(request_id, 12)
        return effects[request_id]

    def reconcile(request_id: str) -> int | None:
        return effects.get(request_id)

    binding = BrokerTemplateBinding(
        template_code=91,
        public_values=frozenset({12}),
        execute=execute,
        reconcile=reconcile,
    )
    journal = BrokerJournal(tmp_path / "broker.sqlite3", (binding,))
    command = BrokerCommand(
        schema_version=BROKER_PROTOCOL_VERSION,
        request_id="effect-A",
        fingerprint="a" * 64,
        template_code=91,
    )
    first = journal.execute(command)
    replay = journal.execute(command)
    assert first == replay
    assert first.outcome_code is BrokerOutcomeCode.EXECUTED
    assert first.value_code == 12
    assert effects == {"effect-A": 12}

    with pytest.raises(RequestConfusionError):
        journal.execute(replace(command, fingerprint="b" * 64))
    with pytest.raises(RequestConfusionError):
        journal.execute(replace(command, template_code=92))
    with pytest.raises(ValueError):
        BrokerCommand.from_wire({**command.to_wire(), "raw_payload": "secret"})
    assert BrokerReply.from_wire(first.to_wire()) == first


def test_broker_crash_edges_reconcile_or_fail_closed_without_reexecution(tmp_path: Path):
    class InjectedCrash(BaseException):
        pass

    effects: dict[str, int] = {}
    execute_calls: list[str] = []

    def execute(request_id: str) -> int:
        execute_calls.append(request_id)
        effects[request_id] = 12
        return 12

    def reconcile(request_id: str) -> int | None:
        return effects.get(request_id)

    binding = BrokerTemplateBinding(91, frozenset({12}), execute, reconcile)
    command = BrokerCommand(BROKER_PROTOCOL_VERSION, "effect-crash", "c" * 64, 91)

    def after_effect(stage: str) -> None:
        if stage == "after_execute_before_done":
            raise InjectedCrash()

    crashed = BrokerJournal(tmp_path / "after-effect.sqlite3", (binding,), fault_hook=after_effect)
    with pytest.raises(InjectedCrash):
        crashed.execute(command)
    assert execute_calls == ["effect-crash"]
    recovered = BrokerJournal(tmp_path / "after-effect.sqlite3", (binding,)).execute(command)
    assert recovered.outcome_code is BrokerOutcomeCode.EXECUTED
    assert recovered.value_code == 12
    assert execute_calls == ["effect-crash"]

    execute_calls.clear()
    effects.clear()
    before_command = BrokerCommand(BROKER_PROTOCOL_VERSION, "before-effect", "e" * 64, 91)

    def before_effect(stage: str) -> None:
        if stage == "after_claim_before_execute":
            raise InjectedCrash()

    claimed = BrokerJournal(tmp_path / "before-effect.sqlite3", (binding,), fault_hook=before_effect)
    with pytest.raises(InjectedCrash):
        claimed.execute(before_command)
    denied = BrokerJournal(tmp_path / "before-effect.sqlite3", (binding,)).execute(before_command)
    assert denied.outcome_code is BrokerOutcomeCode.DENIED
    assert execute_calls == []
    assert effects == {}


def test_continue_stop_padding_and_closed_stutter_use_the_same_cache_contract(tmp_path: Path):
    path = tmp_path / "lifecycle.sqlite3"
    templates, _ = _make_domain(path)
    address = _abstract("lifecycle")
    pid = _fork_monitor(
        path=path,
        address=address,
        templates=templates,
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    try:
        continued = connect_model(
            address,
            _operation("continue-id", ModelOperationCode.CONTINUE),
            expected_monitor=_peer(pid),
        )
        stopped = connect_model(
            address,
            _operation("stop-id", ModelOperationCode.STOP),
            expected_monitor=_peer(pid),
        )
        closed = connect_model(
            address,
            _attempt("closed-id", 11),
            expected_monitor=_peer(pid),
        )
        closed_retry = connect_model(
            address,
            _attempt("closed-id", 11),
            expected_monitor=_peer(pid),
        )
        assert continued.kind is EventKind.CONTINUE and continued.sequence == 1
        assert stopped.kind is EventKind.STOP and stopped.sequence == 2
        assert closed == closed_retry
        assert closed.kind is EventKind.DOMAIN_CLOSED
        assert closed.sequence == 9 and closed.attempt == 8 and closed.charge_units == 0

        # STOP consumed the remaining horizon as padding, so novel uncharged
        # request IDs must still have a finite cache bound.  There are three
        # rows above; six more reach H+1, and the next novel ID is rejected.
        for index in range(6):
            extra = connect_model(
                address,
                _attempt(f"closed-extra-{index}", 11),
                expected_monitor=_peer(pid),
            )
            assert extra == closed
        with pytest.raises((EOFError, ConnectionError, socket.timeout)):
            connect_model(
                address,
                _attempt("closed-extra-over-bound", 11),
                expected_monitor=_peer(pid),
            )
    finally:
        _terminate(pid)

    domain = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={"release-v1": lambda payload: int(payload["slot"])},
    )
    assert domain.attempts_used == 8
    assert [event.kind for event in domain.transcript] == [
        EventKind.CONTINUE,
        EventKind.STOP,
        EventKind.PADDING,
        EventKind.PADDING,
        EventKind.PADDING,
        EventKind.PADDING,
        EventKind.PADDING,
        EventKind.PADDING,
    ]
    connection = sqlite3.connect(path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM sluice_monitor_request_cache"
        ).fetchone()[0] == 9
    finally:
        connection.close()


def test_effect_route_uses_authenticated_broker_and_durable_broker_result(tmp_path: Path):
    domain_path = tmp_path / "effect-domain.sqlite3"
    broker_path = tmp_path / "effect-broker.sqlite3"
    templates, handler_key = _make_domain(
        domain_path,
        templates=((12, {"slot": 12}),),
        effect=True,
    )
    broker_address = _abstract("broker")
    broker_ready_read, broker_ready_write = os.pipe()
    broker_config_read, broker_config_write = os.pipe()
    launcher_pid = os.getpid()
    broker_binding = BrokerTemplateBinding(
        template_code=91,
        public_values=frozenset({12}),
        execute=lambda _request_id: 12,
        reconcile=lambda _request_id: 12,
    )
    broker_journal = BrokerJournal(broker_path, (broker_binding,))
    broker_pid = os.fork()
    if broker_pid == 0:
        os.close(broker_ready_read)
        os.close(broker_config_write)
        try:
            serve_broker(
                address=broker_address,
                expected_monitor=None,
                expected_monitor_fd=broker_config_read,
                journal=broker_journal,
                expected_parent_pid=launcher_pid,
                ready_fd=broker_ready_write,
            )
        finally:
            os._exit(111)
    os.close(broker_ready_write)
    os.close(broker_config_read)

    adapter = AuthenticatedBrokerEffectAdapter(
        address=broker_address,
        expected_broker=_peer(broker_pid),
        payload_templates=(({"slot": 12}, 91),),
    )
    monitor_address = _abstract("effect-monitor")
    ready_read, ready_write = os.pipe()
    parent_pid = os.getpid()
    monitor_config = MonitorServiceConfig(
        address=monitor_address,
        opener=_opener(domain_path, {handler_key: adapter.as_effect_handler()}),
        templates=templates,
        expected_model=_peer(),
        expected_broker=_peer(broker_pid),
    )
    monitor_pid = os.fork()
    if monitor_pid == 0:
        os.close(ready_read)
        os.close(broker_config_write)
        try:
            SingletonMonitorService(monitor_config).serve_forever(
                expected_parent_pid=parent_pid,
                ready_fd=ready_write,
            )
        finally:
            os._exit(111)
    os.close(ready_write)
    broker_peer_wire = json.dumps(
        {"pid": monitor_pid, "uid": os.getuid(), "gid": os.getgid()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    os.write(broker_config_write, broker_peer_wire)
    os.close(broker_config_write)
    assert os.read(broker_ready_read, 1) == b"R"
    os.close(broker_ready_read)
    assert os.read(ready_read, 1) == b"R"
    os.close(ready_read)
    try:
        event = connect_model(
            monitor_address,
            _attempt("effect-model-request", 12),
            expected_monitor=_peer(monitor_pid),
        )
        replay = connect_model(
            monitor_address,
            _attempt("effect-model-request", 12),
            expected_monitor=_peer(monitor_pid),
        )
        assert event == replay
        assert event.outcome is OutcomeCode.RELEASED
        assert event.value_code == 12

        # A direct model-to-broker connection has the wrong SO_PEERCRED PID.
        command = BrokerCommand(
            schema_version=BROKER_PROTOCOL_VERSION,
            request_id="direct-model-bypass",
            fingerprint="d" * 64,
            template_code=91,
        )
        assert _raw_exchange(broker_address, command.to_wire()) == b""
    finally:
        _terminate(monitor_pid)
        _terminate(broker_pid)

    domain = DurableSecureDomain.reopen(
        domain_path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry={handler_key: adapter.as_effect_handler()},
    )
    assert domain.attempts_used == 1
    connection = sqlite3.connect(broker_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM broker_requests WHERE state='DONE'"
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_monitor_rejects_broker_adapter_bound_to_another_pid(tmp_path: Path):
    path = tmp_path / "broker-binding.sqlite3"
    templates, handler_key = _make_domain(
        path,
        templates=((12, {"slot": 12}),),
        effect=True,
    )
    adapter = AuthenticatedBrokerEffectAdapter(
        address=_abstract("missing-broker"),
        expected_broker=_peer(os.getpid()),
        payload_templates=(({"slot": 12}, 91),),
    )
    with pytest.raises(ValueError, match="broker"):
        MonitorServiceConfig(
            address=_abstract("bad-binding"),
            opener=_opener(path, {handler_key: adapter.as_effect_handler()}),
            templates=templates,
            expected_model=_peer(),
            expected_broker=_peer(os.getpid() + 1),
        )
