"""Adjacent regressions for the independently identified endpoint defects."""

from __future__ import annotations

import copy
import dataclasses
import itertools

import pytest

from sluice_v2.evaluation import agentdojo_principal_construction as dojo_construction
from sluice_v2.evaluation import agentdojo_principal_driver as dojo_principal
from sluice_v2.evaluation import live_endpoint_integration as integration
from sluice_v2.tests.test_v29_live_endpoint_integration import (
    _endpoint,
    _session,
    dojo_plan,
    dojo_registry,
    dojo_source,
    leak_plan,
    model_pin,
    runtime_pins,
    topology,
)


_DOJO_INDICES = itertools.count(15_000)
_LEAK_INDICES = itertools.count(4_500)


class StringSubclass(str):
    pass


class IntegerSubclass(int):
    pass


@pytest.fixture
def dojo_binding(dojo_plan) -> integration.ScheduleBinding:
    return integration.ScheduleBinding.for_agentdojo(
        plan=dojo_plan,
        entry=dojo_plan.entries[next(_DOJO_INDICES)],
    )


@pytest.fixture
def leak_binding(leak_plan) -> integration.ScheduleBinding:
    index = next(_LEAK_INDICES)
    block, arm = divmod(index, 8)
    return integration.ScheduleBinding.for_agentleak(
        plan=leak_plan,
        arm=leak_plan.blocks[block].arms[arm],
    )


def _rehash_request(wire: dict[str, object]) -> dict[str, object]:
    wire["sha256"] = integration.cpu_request_sha256(wire)
    return wire


def _rehash_reply(wire: dict[str, object]) -> dict[str, object]:
    wire["sha256"] = integration.cpu_reply_sha256(wire)
    return wire


def _rehash_event(wire: dict[str, object]) -> dict[str, object]:
    wire["sha256"] = integration.chronology_event_sha256(wire)
    return wire


def _rehash_chronology(wire: dict[str, object]) -> dict[str, object]:
    wire["chronology_sha256"] = integration.cpu_chronology_sha256(wire)
    return wire


def _rehash_public_receipt(wire: dict[str, object]) -> dict[str, object]:
    body = dict(wire)
    body.pop("sha256", None)
    wire["sha256"] = integration._digest(
        b"sluice-cpu-endpoint-receipt-v1", body
    )
    return wire


def test_loader_registry_rejects_a_field_for_field_plan_copy(dojo_plan) -> None:
    dojo_plan.revalidate()
    copied = dataclasses.replace(dojo_plan)
    assert copied is not dojo_plan
    assert copied.sha256 == dojo_plan.sha256
    assert copied._validation_sha256 == dojo_plan._validation_sha256
    with pytest.raises(integration.LiveEndpointIntegrationError, match="authenticated"):
        integration.ScheduleBinding.for_agentdojo(
            plan=copied,
            entry=copied.entries[0],
        )


def test_deep_plan_mutation_after_binding_before_admission_is_rejected(
    dojo_plan, model_pin, runtime_pins, topology
) -> None:
    binding = integration.ScheduleBinding.for_agentdojo(
        plan=dojo_plan,
        entry=dojo_plan.entries[next(_DOJO_INDICES)],
    )
    scenario = dojo_plan.scenarios[-1]
    original = scenario.stratum
    object.__setattr__(scenario, "stratum", "tampered")
    try:
        with pytest.raises(
            integration.LiveEndpointIntegrationError,
            match="source plan drifted before endpoint admission",
        ):
            _session(
                binding=binding,
                model_pin=model_pin,
                runtime_pins=runtime_pins,
                topology=topology,
            )
    finally:
        object.__setattr__(scenario, "stratum", original)
    dojo_plan.revalidate()


@pytest.mark.parametrize("mutation", ("repetition_bool", "registry_bool"))
def test_plan_loader_rejects_nested_bool_integer_alias(
    dojo_source, dojo_registry, mutation
) -> None:
    wire = dojo_construction.build_principal_plan_wire(
        source=dojo_source,
        registry=dojo_registry,
    )
    changed = copy.deepcopy(wire)
    if mutation == "repetition_bool":
        instance = changed["schedule_instances"][0]
        instance["repetition"] = False
        instance["sha256"] = dojo_principal.principal_plan_sha256(instance)
    else:
        changed["registry"]["official_suite_objects_verified"] = 1
    changed["sha256"] = dojo_principal.principal_plan_sha256(changed)
    with pytest.raises(dojo_principal.PrincipalDriverError):
        dojo_principal.PrincipalExecutionPlan.load(
            changed,
            expected_sha256=changed["sha256"],
        )


def test_agentleak_plan_top_level_string_alias_is_rejected(leak_plan) -> None:
    original = leak_plan.schema_version
    object.__setattr__(leak_plan, "schema_version", StringSubclass(original))
    try:
        with pytest.raises(integration.LiveEndpointIntegrationError, match="exact"):
            integration.ScheduleBinding.for_agentleak(
                plan=leak_plan,
                arm=leak_plan.blocks[0].arms[0],
            )
    finally:
        object.__setattr__(leak_plan, "schema_version", original)
    leak_plan.__post_init__()


@pytest.mark.parametrize(
    "field,value",
    (
        ("attempt_number", True),
        ("principal_outcome_count", False),
        ("schema_version", StringSubclass("sluice-cpu-loopback-request-v1")),
        ("transport_mode", StringSubclass(integration.TRANSPORT_MODE)),
        ("role", StringSubclass("broker")),
    ),
)
def test_request_wire_rejects_every_python_type_alias(
    dojo_binding, model_pin, runtime_pins, topology, field, value
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    request = integration.CpuLoopbackRequest.create(
        permit=session.permit,
        request_id=f"request-alias-{field}",
        attempt_number=1,
        input_commitment_sha256="a" * 64,
    )
    wire = request.to_wire()
    wire[field] = value
    _rehash_request(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuLoopbackRequest.from_wire(wire)


@pytest.mark.parametrize(
    "field,value",
    (
        ("attempt_number", True),
        ("principal_outcome_count", False),
        ("schema_version", StringSubclass("sluice-cpu-loopback-reply-v1")),
        ("transport_mode", StringSubclass(integration.TRANSPORT_MODE)),
        ("role", StringSubclass("model_driver")),
        ("status", StringSubclass("CPU_FAKE_ACK")),
        ("retryable", 0),
        ("acknowledgement_sha256", "9" * 64),
    ),
)
def test_reply_wire_rejects_every_python_alias_or_ack_forgery(
    dojo_binding, model_pin, runtime_pins, topology, field, value
) -> None:
    endpoint = _endpoint(model_pin, topology)
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        endpoint=endpoint,
    )
    request = integration.CpuLoopbackRequest.create(
        permit=session.permit,
        request_id=f"reply-alias-{field}",
        attempt_number=1,
        input_commitment_sha256="b" * 64,
    )
    wire = endpoint.handle(request.to_wire(), observed_peer=topology.broker)
    wire[field] = value
    _rehash_reply(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuLoopbackReply.from_wire(wire)


@pytest.mark.parametrize(
    "field,value",
    (
        ("sequence", True),
        ("principal_outcome_count", False),
        (
            "schema_version",
            StringSubclass("sluice-cpu-endpoint-chronology-event-v1"),
        ),
        ("kind", StringSubclass("PREFLIGHT")),
        ("status", StringSubclass("CPU_FAKE_ENDPOINT_VERIFIED")),
    ),
)
def test_chronology_event_rejects_python_type_alias(field, value) -> None:
    event = integration.CpuChronologyEvent.create(
        sequence=1,
        kind=integration.ChronologyKind.PREFLIGHT,
        status="CPU_FAKE_ENDPOINT_VERIFIED",
    )
    wire = event.to_wire()
    wire[field] = value
    _rehash_event(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuChronologyEvent.from_wire(wire)


@pytest.mark.parametrize(
    "field,value",
    (
        ("chronology_hmax", IntegerSubclass(16)),
        ("request_count", True),
        ("reply_count", True),
        ("principal_outcome_count", False),
        ("schema_version", StringSubclass("sluice-cpu-endpoint-chronology-v1")),
        ("transport_mode", StringSubclass(integration.TRANSPORT_MODE)),
        ("terminal_status", StringSubclass("CPU_FAKE_COMPLETED")),
    ),
)
def test_chronology_wrapper_rejects_python_type_alias(
    dojo_binding, model_pin, runtime_pins, topology, field, value
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="c" * 64,
        request_id=f"chronology-wrapper-{field}",
        observed_broker_peer=topology.broker,
    )
    wire = receipt.chronology.to_wire()
    wire[field] = value
    _rehash_chronology(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.validate_cpu_chronology_wire(
            wire=wire,
            permit=session.permit,
            requests=receipt.restricted_requests,
            replies=receipt.restricted_replies,
        )


@pytest.mark.parametrize(
    "change",
    (
        {"attempt_count": True},
        {"principal_outcome_count": False},
        {"fake_endpoint_exercised": 1},
    ),
)
def test_internal_receipt_rejects_count_and_boolean_aliases(
    dojo_binding, model_pin, runtime_pins, topology, change
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="d" * 64,
        request_id=f"receipt-alias-{next(_DOJO_INDICES)}",
        observed_broker_peer=topology.broker,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError):
        dataclasses.replace(receipt, **change)


@pytest.mark.parametrize(
    "field,value",
    (
        ("attempt_count", True),
        ("chronology_step_count", IntegerSubclass(16)),
        ("principal_outcome_count", False),
        ("schema_version", StringSubclass("sluice-cpu-endpoint-receipt-v1")),
        ("transport_mode", StringSubclass(integration.TRANSPORT_MODE)),
        ("peer_identity_mode", StringSubclass(integration.PEER_IDENTITY_MODE)),
        ("fake_endpoint_exercised", 1),
        ("model_executed", 0),
        ("status", StringSubclass("CPU_FAKE_COMPLETED")),
    ),
)
def test_public_evidence_loader_rejects_every_type_alias(
    dojo_binding, model_pin, runtime_pins, topology, field, value
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="e" * 64,
        request_id=f"public-receipt-alias-{field}",
        observed_broker_peer=topology.broker,
    )
    wire = receipt.to_public_wire()
    wire[field] = value
    _rehash_public_receipt(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration._validate_cpu_public_receipt_wire(wire)


def test_public_evidence_loader_requires_exact_keys_digest_and_chronology(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="f" * 64,
        request_id="public-receipt-exact-schema",
        observed_broker_peer=topology.broker,
    )
    valid = receipt.to_public_wire()
    assert integration._validate_cpu_public_receipt_wire(valid) == valid

    extra = dict(valid)
    extra["task_answer"] = "forbidden"
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration._validate_cpu_public_receipt_wire(extra)

    missing = dict(valid)
    missing.pop("chronology_sha256")
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration._validate_cpu_public_receipt_wire(missing)

    digest_drift = dict(valid)
    digest_drift["sha256"] = "0" * 64
    with pytest.raises(integration.LiveEndpointIntegrationError, match="digest"):
        integration._validate_cpu_public_receipt_wire(digest_drift)

    chronology_count = dict(valid)
    chronology_count["chronology_step_count"] = 15
    _rehash_public_receipt(chronology_count)
    with pytest.raises(integration.LiveEndpointIntegrationError, match="chronology"):
        integration._validate_cpu_public_receipt_wire(chronology_count)

    exhausted = dict(valid)
    exhausted["status"] = "CPU_FAKE_RETRY_EXHAUSTED"
    exhausted["attempt_count"] = 1
    _rehash_public_receipt(exhausted)
    with pytest.raises(integration.LiveEndpointIntegrationError, match="attempt"):
        integration._validate_cpu_public_receipt_wire(exhausted)
