"""Fail-first contract for the isolated Sluice deployment boundary.

The complete-channel result in ``test_v7_secure_domain_transcript.py`` is not
an isolation result if the untrusted model shares a process, signing material,
tool credentials, the durable ledger, or unrestricted network access with the
monitor.  This module fixes the additive ``sluice_v2.isolation`` API expected
of the evaluated deployment.

The contract deliberately separates two questions:

* ``detect_host_enforcement`` reports what this host can actually enforce;
  ``validate_startup`` must refuse a strict manifest when any requirement is
  unavailable.  Configuration intent is never treated as enforcement.
* Pure control-plane validators accept an explicit ``EnforcementReport`` so
  every fail-closed branch is deterministic in CI.  These reports do not
  provide a production bypass: the service entry point is required to use the
  detected host report.

The model, monitor, and effect broker are distinct roles and processes.  The
model-facing reply is only the v7 finite public event.  Monitor-to-broker IPC
contains an opaque validated capability plus finite tool/argument codes.  A
credential-holding broker executes only an allowlisted combination, and its
reply never transports raw backend output or exception text.  A small durable
claim journal makes the before/after-commit recovery rule executable using a
real child process killed with ``os._exit``.
"""

from __future__ import annotations

from dataclasses import replace
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from sluice_v2.isolation import (
    IPC_SCHEMA_VERSION,
    BrokerOutcome,
    CrashPoint,
    DurableClaimJournal,
    EffectBroker,
    EnforcementReport,
    IPCEnvelope,
    IPCMessageKind,
    IPCSchemaError,
    InjectedCrash,
    IsolationManifest,
    IsolationStartupError,
    ProcessRole,
    ProcessTopology,
    RecoveryDisposition,
    detect_host_enforcement,
    sanitize_model_environment,
    validate_startup,
)


PUBLIC_EVENT_WIRE = {
    "schema_version": 1,
    "sequence": 1,
    "attempt": 1,
    "kind": "attempt",
    "outcome": "released",
    "value_code": 0,
    "charge_units": 2,
    "terminal": False,
}


def _strict_manifest() -> IsolationManifest:
    return IsolationManifest.strict(ipc_max_frame_bytes=4096)


def _enforced_report(**changes: object) -> EnforcementReport:
    report = EnforcementReport(
        kernel_enforced=True,
        distinct_processes=True,
        private_ipc=True,
        model_network_denied=True,
        model_ledger_denied=True,
        model_signing_keys_denied=True,
        model_tool_credentials_denied=True,
        model_raw_audit_denied=True,
        broker_allowlist_enforced=True,
        tool_sandbox_enforced=True,
    )
    return replace(report, **changes)


def _crash_claim_worker(
    path: str,
    request_id: str,
    crash_point_value: str,
) -> None:
    """Run a journal transition in a real child and die at the injected edge."""

    journal = DurableClaimJournal(Path(path))
    try:
        journal.claim_once(
            request_id=request_id,
            command_fingerprint="internal-command-fingerprint",
            crash_point=CrashPoint(crash_point_value),
        )
    except InjectedCrash:
        # Bypass Python cleanup to model process loss, not an ordinary raised
        # exception that might accidentally commit in a context-manager exit.
        os._exit(73)
    os._exit(0)


def test_strict_manifest_serializes_the_enforced_non_timing_boundary():
    manifest = _strict_manifest()

    assert manifest.to_wire() == {
        "schema_version": 1,
        "process_roles": ["model", "monitor", "effect_broker"],
        "ipc_transport": "unix_domain_socket",
        "ipc_max_frame_bytes": 4096,
        "require_kernel_enforcement": True,
        "model_network": "deny",
        "model_ledger": "deny",
        "model_signing_keys": "deny",
        "model_tool_credentials": "deny",
        "model_raw_audit": "deny",
        "broker_effects": "allowlist",
        "tool_sandbox": "required",
        "worker_error_policy": "fail_closed",
    }
    assert IsolationManifest.from_wire(manifest.to_wire()) == manifest


@pytest.mark.parametrize(
    "missing",
    [
        "kernel_enforced",
        "distinct_processes",
        "private_ipc",
        "model_network_denied",
        "model_ledger_denied",
        "model_signing_keys_denied",
        "model_tool_credentials_denied",
        "model_raw_audit_denied",
        "broker_allowlist_enforced",
        "tool_sandbox_enforced",
    ],
)
def test_startup_refuses_each_unenforceable_strict_requirement(missing: str):
    report = _enforced_report(**{missing: False})

    with pytest.raises(IsolationStartupError, match=missing):
        validate_startup(_strict_manifest(), report)


def test_host_detection_never_silently_downgrades_strict_startup():
    manifest = _strict_manifest()
    detected = detect_host_enforcement()

    assert isinstance(detected, EnforcementReport)
    assert all(
        type(getattr(detected, field)) is bool
        for field in (
            "kernel_enforced",
            "distinct_processes",
            "private_ipc",
            "model_network_denied",
            "model_ledger_denied",
            "model_signing_keys_denied",
            "model_tool_credentials_denied",
            "model_raw_audit_denied",
            "broker_allowlist_enforced",
            "tool_sandbox_enforced",
        )
    )
    missing = detected.missing_requirements(manifest)
    assert type(missing) is tuple
    assert all(type(name) is str for name in missing)
    if missing:
        with pytest.raises(IsolationStartupError):
            validate_startup(manifest, detected)
    else:
        validate_startup(manifest, detected)

    # Record the portable fact the implementation can use on cluster-login without
    # asserting that possession of the binary implies namespace permission.
    assert detected.unshare_available is (shutil.which("unshare") is not None)


def test_topology_requires_three_live_distinct_processes():
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        for _ in range(3)
    ]
    try:
        topology = ProcessTopology(
            {
                ProcessRole.MODEL: workers[0].pid,
                ProcessRole.MONITOR: workers[1].pid,
                ProcessRole.EFFECT_BROKER: workers[2].pid,
            }
        )
        topology.validate_live_and_distinct()
        assert len(set(topology.pids.values())) == 3
        assert os.getpid() not in topology.pids.values()

        duplicate = ProcessTopology(
            {
                ProcessRole.MODEL: workers[0].pid,
                ProcessRole.MONITOR: workers[0].pid,
                ProcessRole.EFFECT_BROKER: workers[2].pid,
            }
        )
        with pytest.raises(IsolationStartupError, match="distinct"):
            duplicate.validate_live_and_distinct()
    finally:
        for worker in workers:
            worker.terminate()
        for worker in workers:
            try:
                worker.wait(timeout=3)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=3)


def test_model_environment_is_a_positive_allowlist_not_secret_name_guessing():
    parent = {
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "SLUICE_MONITOR_SIGNING_KEY": "monitor-secret-material",
        "REAL_TOOL_CREDENTIAL": "provider-secret-material",
        "LEDGER_PATH": "/private/monitor/ledger.sqlite3",
        "RAW_AUDIT_PATH": "/private/monitor/audit.jsonl",
        # An arbitrary name demonstrates why a denylist is insufficient.
        "INNOCENT_LOOKING_NAME": "also-secret-material",
    }

    child = sanitize_model_environment(
        parent,
        allowed_names=frozenset({"PATH", "LANG"}),
    )

    assert child == {"PATH": "/usr/bin", "LANG": "C.UTF-8"}
    serialized = json.dumps(child, sort_keys=True)
    for forbidden in (
        "monitor-secret-material",
        "provider-secret-material",
        "ledger.sqlite3",
        "audit.jsonl",
        "also-secret-material",
    ):
        assert forbidden not in serialized


def test_ipc_tagged_union_round_trips_only_finite_versioned_schemas():
    messages = [
        IPCEnvelope.model_request(
            sequence=1,
            route_token="opaque-route-token",
            payload_code=3,
            credential="opaque-attempt-credential",
        ),
        IPCEnvelope.public_event(sequence=2, event=PUBLIC_EVENT_WIRE),
        IPCEnvelope.effect_command(
            sequence=3,
            capability_token="opaque-effect-capability",
            tool_code=7,
            argument_codes=(10, 20),
        ),
        IPCEnvelope.effect_result(
            sequence=4,
            outcome=BrokerOutcome.EXECUTED,
            value_code=1,
        ),
    ]

    assert IPC_SCHEMA_VERSION == 1
    assert [message.kind for message in messages] == [
        IPCMessageKind.MODEL_REQUEST,
        IPCMessageKind.PUBLIC_EVENT,
        IPCMessageKind.EFFECT_COMMAND,
        IPCMessageKind.EFFECT_RESULT,
    ]
    for message in messages:
        wire = message.to_wire()
        assert wire["schema_version"] == IPC_SCHEMA_VERSION
        assert type(wire["sequence"]) is int
        assert IPCEnvelope.from_wire(wire) == message
        assert len(json.dumps(wire).encode("utf-8")) <= 4096

    assert set(messages[0].to_wire()) == {
        "schema_version",
        "sequence",
        "kind",
        "route_token",
        "payload_code",
        "credential",
    }
    assert set(messages[1].to_wire()) == {
        "schema_version",
        "sequence",
        "kind",
        "event",
    }
    assert set(messages[2].to_wire()) == {
        "schema_version",
        "sequence",
        "kind",
        "capability_token",
        "tool_code",
        "argument_codes",
    }
    assert set(messages[3].to_wire()) == {
        "schema_version",
        "sequence",
        "kind",
        "outcome",
        "value_code",
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda wire: {**wire, "schema_version": IPC_SCHEMA_VERSION + 1},
        lambda wire: {**wire, "raw_exception": "secret backend exception"},
        lambda wire: {**wire, "raw_output": "secret backend output"},
        lambda wire: {**wire, "raw_audit": {"object_id": "secret"}},
        lambda wire: {**wire, "ledger_path": "/secret/ledger.sqlite3"},
        lambda wire: {**wire, "tool_credentials": "provider-token"},
        lambda wire: {**wire, "sequence": True},
        lambda wire: {**wire, "argument_codes": [10, "unbounded-string"]},
        lambda wire: {key: value for key, value in wire.items() if key != "tool_code"},
    ],
    ids=[
        "wrong-version",
        "raw-exception",
        "raw-output",
        "raw-audit",
        "ledger-path",
        "tool-credential",
        "bool-sequence",
        "non-finite-argument",
        "missing-required-field",
    ],
)
def test_ipc_rejects_unknown_sensitive_or_unbounded_fields(mutate):
    canonical = IPCEnvelope.effect_command(
        sequence=1,
        capability_token="opaque-capability",
        tool_code=7,
        argument_codes=(10, 20),
    ).to_wire()

    with pytest.raises(IPCSchemaError):
        IPCEnvelope.from_wire(mutate(canonical))


def test_effect_broker_executes_only_validated_allowlisted_combinations():
    credential = b"real-provider-credential-never-on-ipc"
    calls: list[tuple[bytes, tuple[int, ...]]] = []

    def handler(tool_credential: bytes, argument_codes: tuple[int, ...]) -> int:
        calls.append((tool_credential, argument_codes))
        return 1

    broker = EffectBroker(
        allowed_arguments={7: frozenset({(10, 20)})},
        public_values={7: frozenset({0, 1})},
        tool_credentials={7: credential},
        handlers={7: handler},
        capability_validator=lambda token, tool, args: (
            token == "valid-capability" and tool == 7 and args == (10, 20)
        ),
    )

    bad_argument = broker.execute(
        IPCEnvelope.effect_command(
            sequence=1,
            capability_token="valid-capability",
            tool_code=7,
            argument_codes=(10, 99),
        )
    )
    bad_capability = broker.execute(
        IPCEnvelope.effect_command(
            sequence=2,
            capability_token="tampered-capability",
            tool_code=7,
            argument_codes=(10, 20),
        )
    )
    good = broker.execute(
        IPCEnvelope.effect_command(
            sequence=3,
            capability_token="valid-capability",
            tool_code=7,
            argument_codes=(10, 20),
        )
    )

    assert bad_argument.outcome is BrokerOutcome.DENIED
    assert bad_capability.outcome is BrokerOutcome.DENIED
    assert good.outcome is BrokerOutcome.EXECUTED
    assert good.value_code == 1
    assert calls == [(credential, (10, 20))]
    for reply in (bad_argument, bad_capability, good):
        serialized = json.dumps(reply.to_wire(), sort_keys=True)
        assert credential.decode("ascii") not in serialized


@pytest.mark.parametrize(
    ("handler", "expected"),
    [
        (
            lambda credential, arguments: (_ for _ in ()).throw(
                RuntimeError("swordfish in raw broker exception")
            ),
            BrokerOutcome.INTERNAL_DENIED,
        ),
        (
            lambda credential, arguments: "swordfish in unconstrained output",
            BrokerOutcome.OUTPUT_DENIED,
        ),
        (lambda credential, arguments: 999, BrokerOutcome.OUTPUT_DENIED),
    ],
    ids=["exception", "raw-string-output", "out-of-alphabet-code"],
)
def test_broker_exception_and_unconstrained_output_are_suppressed(handler, expected):
    broker = EffectBroker(
        allowed_arguments={7: frozenset({(10, 20)})},
        public_values={7: frozenset({0, 1})},
        tool_credentials={7: b"provider-secret"},
        handlers={7: handler},
        capability_validator=lambda token, tool, args: True,
    )
    command = IPCEnvelope.effect_command(
        sequence=1,
        capability_token="opaque-capability",
        tool_code=7,
        argument_codes=(10, 20),
    )

    reply = broker.execute(command)
    wire = reply.to_wire()

    assert reply.outcome is expected
    assert reply.value_code is None
    assert set(wire) == {
        "schema_version",
        "sequence",
        "kind",
        "outcome",
        "value_code",
    }
    serialized = json.dumps(wire, sort_keys=True)
    for forbidden in (
        "swordfish",
        "RuntimeError",
        "provider-secret",
        "raw broker exception",
        "unconstrained output",
    ):
        assert forbidden not in serialized


def test_model_facing_channel_accepts_only_the_public_event_variant():
    public = IPCEnvelope.public_event(sequence=1, event=PUBLIC_EVENT_WIRE)
    effect = IPCEnvelope.effect_result(
        sequence=1,
        outcome=BrokerOutcome.EXECUTED,
        value_code=1,
    )

    assert public.for_model().kind is IPCMessageKind.PUBLIC_EVENT
    with pytest.raises(IPCSchemaError, match="model|public_event"):
        effect.for_model()


def test_crash_before_commit_leaves_no_partial_durable_claim(tmp_path: Path):
    journal_path = tmp_path / "claims-before.sqlite3"
    context = multiprocessing.get_context("fork")
    worker = context.Process(
        target=_crash_claim_worker,
        args=(str(journal_path), "request-before", CrashPoint.BEFORE_COMMIT.value),
    )
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert worker.exitcode == 73

    reopened = DurableClaimJournal(journal_path)
    assert reopened.recover("request-before") is RecoveryDisposition.NOT_COMMITTED
    assert reopened.durable_claim_count("request-before") == 0
    assert reopened.claim_once(
        request_id="request-before",
        command_fingerprint="internal-command-fingerprint",
    ) is True
    assert reopened.durable_claim_count("request-before") == 1


def test_crash_after_commit_recovers_exactly_one_durable_claim(tmp_path: Path):
    journal_path = tmp_path / "claims-after.sqlite3"
    context = multiprocessing.get_context("fork")
    worker = context.Process(
        target=_crash_claim_worker,
        args=(str(journal_path), "request-after", CrashPoint.AFTER_COMMIT.value),
    )
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert worker.exitcode == 73

    reopened = DurableClaimJournal(journal_path)
    assert reopened.recover("request-after") is RecoveryDisposition.COMMITTED
    assert reopened.durable_claim_count("request-after") == 1
    # A retry after an ambiguous transport failure must not authorize a second
    # effect. False means the prior durable claim was found, not re-created.
    assert reopened.claim_once(
        request_id="request-after",
        command_fingerprint="internal-command-fingerprint",
    ) is False
    assert reopened.durable_claim_count("request-after") == 1


def test_recovery_refuses_same_request_id_with_different_command(tmp_path: Path):
    journal = DurableClaimJournal(tmp_path / "claims-confusion.sqlite3")
    assert journal.claim_once(
        request_id="stable-request-id",
        command_fingerprint="command-a",
    ) is True

    with pytest.raises(IPCSchemaError, match="fingerprint|request"):
        journal.claim_once(
            request_id="stable-request-id",
            command_fingerprint="command-b",
        )
    assert journal.durable_claim_count("stable-request-id") == 1
