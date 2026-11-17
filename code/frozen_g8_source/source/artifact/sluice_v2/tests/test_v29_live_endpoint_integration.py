from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import stat
import sys
import threading
from types import MappingProxyType, SimpleNamespace

import pytest

_REPOSITORY_FOR_IMPORT = Path(__file__).resolve().parents[4]
sys.dont_write_bytecode = True
sys.path.insert(0, str(_REPOSITORY_FOR_IMPORT / "external" / "agentdojo-v0.1.35" / "src"))

from sluice_v2.durable_service import PeerIdentity
from sluice_v2.evaluation import agentdojo_live as dojo_live
from sluice_v2.evaluation import agentdojo_principal_construction as dojo_construction
from sluice_v2.evaluation import agentdojo_principal_driver as dojo_principal
from sluice_v2.evaluation import agentleak_principal_driver as leak_principal
from sluice_v2.evaluation import live_endpoint_integration as integration
from sluice_v2.rocky_gpu_isolation import BACKEND_ID as ROCKY_BACKEND_ID
from sluice_v2.rocky_gpu_isolation import SCHEMA_VERSION as ROCKY_SCHEMA_VERSION
from sluice_v2.runtime_staging import PROTOCOL_ID as RUNTIME_PROTOCOL_ID
from sluice_v2.runtime_staging import SCHEMA_VERSION as RUNTIME_SCHEMA_VERSION
from sluice_v2.tests import test_v21_agentdojo_live_pipeline as v21


REPOSITORY = Path(__file__).resolve().parents[4]
ARTIFACT = REPOSITORY / "source" / "artifact"
AGENTDOJO_CHECKOUT = REPOSITORY / "external" / "agentdojo-v0.1.35"
AGENTLEAK_ROOT = ARTIFACT / "benchmarks" / "agentleak"
MODULE_PATH = ARTIFACT / "sluice_v2" / "evaluation" / "live_endpoint_integration.py"
CLI_PATH = ARTIFACT / "experiments" / "attest_live_endpoint_cpu.py"
ENDPOINT_URL = "http://127.0.0.1:18123/v1"
_DOJO_BINDING_INDICES = itertools.count()
_LEAK_BINDING_INDICES = itertools.count()


def _peer(pid: int, *, uid: int | None = None, gid: int | None = None) -> PeerIdentity:
    return PeerIdentity(
        pid=pid,
        uid=os.getuid() if uid is None else uid,
        gid=os.getgid() if gid is None else gid,
    )


@pytest.fixture(scope="module")
def topology() -> dojo_principal.ProcessTopologyAttestation:
    return dojo_principal.ProcessTopologyAttestation.for_cpu_test(
        monitor=_peer(51001),
        broker=_peer(51002),
        model_driver=_peer(51003),
        session_nonce="cpu-loopback-integration-20260821",
    )


@pytest.fixture(scope="module")
def dojo_source() -> dojo_live.OfficialSourceAttestation:
    return dojo_live.OfficialSourceAttestation.authenticate(AGENTDOJO_CHECKOUT)


@pytest.fixture(scope="module")
def dojo_registry(dojo_source):
    return v21.registry_attestation.__wrapped__(dojo_source)


@pytest.fixture(scope="module")
def dojo_plan(dojo_source, dojo_registry) -> dojo_principal.PrincipalExecutionPlan:
    wire = dojo_construction.build_principal_plan_wire(
        source=dojo_source,
        registry=dojo_registry,
    )
    return dojo_principal.PrincipalExecutionPlan.load(
        copy.deepcopy(wire), expected_sha256=wire["sha256"]
    )


@pytest.fixture(scope="module")
def leak_plan() -> leak_principal.FrozenExecutionPlan:
    return leak_principal.build_execution_plan(
        public_schedule_path=AGENTLEAK_ROOT / "public_schedule_full_1000_v1.json"
    )


@pytest.fixture
def dojo_binding(dojo_plan) -> integration.ScheduleBinding:
    return integration.ScheduleBinding.for_agentdojo(
        plan=dojo_plan, entry=dojo_plan.entries[next(_DOJO_BINDING_INDICES)]
    )


@pytest.fixture
def leak_binding(leak_plan) -> integration.ScheduleBinding:
    index = next(_LEAK_BINDING_INDICES)
    block, arm = divmod(index, 8)
    return integration.ScheduleBinding.for_agentleak(
        plan=leak_plan, arm=leak_plan.blocks[block].arms[arm]
    )


@pytest.fixture(scope="module")
def model_pin() -> integration.PinnedModelIdentity:
    return integration.PinnedModelIdentity.create(
        model_id="Qwen/Qwen2.5-3B-Instruct",
        model_revision="a" * 40,
        model_artifact_sha256="b" * 64,
        backend="vllm",
        backend_version="0.6.4.post1",
    )


@pytest.fixture(scope="module")
def runtime_pins() -> integration.RuntimeIsolationPins:
    return integration.RuntimeIsolationPins.for_cpu_test(
        runtime_tree_sha256="c" * 64,
        runtime_source_commit="d" * 40,
        isolation_config_sha256="e" * 64,
    )


def _observation(
    model_pin: integration.PinnedModelIdentity,
    *,
    endpoint_url: str = ENDPOINT_URL,
    **changes: str,
) -> dojo_live.EndpointObservation:
    fields = {
        "endpoint_url": endpoint_url,
        "model_id": model_pin.model_id,
        "model_revision": model_pin.model_revision,
        "model_artifact_sha256": model_pin.model_artifact_sha256,
        "backend": model_pin.backend,
        "backend_version": model_pin.backend_version,
    }
    fields.update(changes)
    return dojo_live.EndpointObservation(**fields)


def _endpoint(
    model_pin: integration.PinnedModelIdentity,
    topology: dojo_principal.ProcessTopologyAttestation,
    *,
    retry_policy: integration.FakeRetryPolicy = integration.FakeRetryPolicy.NEVER,
    observation: dojo_live.EndpointObservation | None = None,
) -> integration.FakeLoopbackEndpoint:
    return integration.FakeLoopbackEndpoint(
        observation=(observation or _observation(model_pin)),
        model_driver_peer=topology.model_driver,
        retry_policy=retry_policy,
    )


def _session(
    *,
    binding: integration.ScheduleBinding,
    model_pin: integration.PinnedModelIdentity,
    runtime_pins: integration.RuntimeIsolationPins,
    topology: dojo_principal.ProcessTopologyAttestation,
    retry_policy: integration.FakeRetryPolicy = integration.FakeRetryPolicy.NEVER,
    endpoint: integration.FakeLoopbackEndpoint | None = None,
) -> integration.CpuLoopbackSession:
    endpoint = endpoint or _endpoint(model_pin, topology, retry_policy=retry_policy)
    return integration.establish_cpu_loopback(
        schedule=binding,
        model=model_pin,
        runtime_isolation=runtime_pins,
        topology=topology,
        endpoint=endpoint,
        expected_endpoint_url=ENDPOINT_URL,
    )


def test_committed_agentdojo_and_agentleak_plans_bind_without_task_payloads(
    dojo_binding, leak_binding
) -> None:
    assert dojo_binding.plan_sha256 == (
        "49ccb6836e59471541746b5467afa55242d0ae053f29f4587bdda12e694e4200"
    )
    assert leak_binding.plan_sha256 == (
        "1bc2b9499a2098b79d9e58deeafab71cf8e61e0ee54a01709f07a49d7bb28728"
    )
    assert dojo_binding.benchmark is integration.BenchmarkKind.AGENTDOJO
    assert leak_binding.benchmark is integration.BenchmarkKind.AGENTLEAK
    for binding in (dojo_binding, leak_binding):
        binding.revalidate()
        wire = binding.to_public_wire()
        assert frozenset(wire) == {
            "benchmark",
            "binding_sha256",
            "condition",
            "generation_seed",
            "plan_sha256",
            "schedule_unit_sha256",
            "schema_version",
        }
        rendered = json.dumps(wire, sort_keys=True).casefold()
        assert not any(
            value in rendered
            for value in (
                "user_task",
                "injection_task",
                "scenario_id",
                "attempt_id",
                "ground_truth",
                "expected_answer",
                "private_vault",
            )
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"model_id": "Qwen/wrong"},
        {"model_revision": "f" * 40},
        {"model_artifact_sha256": "0" * 64},
        {"backend": "not-vllm"},
        {"backend_version": "9.9.9"},
        {"endpoint_url": "http://127.0.0.1:18124/v1"},
    ),
)
def test_preflight_rejects_every_endpoint_or_model_identity_mismatch(
    dojo_binding, model_pin, runtime_pins, topology, changes
) -> None:
    changed = dict(changes)
    endpoint_url = changed.pop("endpoint_url", ENDPOINT_URL)
    endpoint = _endpoint(
        model_pin,
        topology,
        observation=_observation(model_pin, endpoint_url=endpoint_url, **changed),
    )
    with pytest.raises(integration.LiveEndpointIntegrationError):
        _session(
            binding=dojo_binding,
            model_pin=model_pin,
            runtime_pins=runtime_pins,
            topology=topology,
            endpoint=endpoint,
        )


def test_model_pin_itself_requires_exact_vllm_revision_and_artifact() -> None:
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.PinnedModelIdentity.create(
            model_id="Qwen/Qwen2.5-3B-Instruct",
            model_revision="short",
            model_artifact_sha256="b" * 64,
            backend="vllm",
            backend_version="0.6.4.post1",
        )
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.PinnedModelIdentity.create(
            model_id="Qwen/Qwen2.5-3B-Instruct",
            model_revision="a" * 40,
            model_artifact_sha256="short",
            backend="vllm",
            backend_version="0.6.4.post1",
        )
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.PinnedModelIdentity.create(
            model_id="Qwen/Qwen2.5-3B-Instruct",
            model_revision="a" * 40,
            model_artifact_sha256="b" * 64,
            backend="fake",
            backend_version="0.6.4.post1",
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"runtime_protocol_id": "wrong-runtime"},
        {"runtime_schema_version": 999},
        {"isolation_backend_id": "wrong-isolation"},
        {"isolation_schema_version": 999},
        {"node_local_xfs_verified": True},
        {"strict_isolation_verified": True},
        {"cuda_allocation_verified": True},
        {"model_execution_verified": True},
        {"principal_eligible": True},
    ),
)
def test_runtime_isolation_cpu_pins_cannot_claim_or_drift(runtime_pins, changes) -> None:
    with pytest.raises(integration.LiveEndpointIntegrationError):
        dataclasses.replace(runtime_pins, **changes)


def test_runtime_isolation_pins_match_committed_api_constants(runtime_pins) -> None:
    assert runtime_pins.runtime_protocol_id == RUNTIME_PROTOCOL_ID
    assert runtime_pins.runtime_schema_version == RUNTIME_SCHEMA_VERSION
    assert runtime_pins.isolation_backend_id == ROCKY_BACKEND_ID
    assert runtime_pins.isolation_schema_version == ROCKY_SCHEMA_VERSION
    assert runtime_pins.node_local_xfs_verified is False
    assert runtime_pins.strict_isolation_verified is False
    assert runtime_pins.cuda_allocation_verified is False
    assert runtime_pins.model_execution_verified is False
    assert runtime_pins.principal_eligible is False


def test_topology_and_peer_roles_fail_closed(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    with pytest.raises(dojo_principal.PrincipalDriverError):
        dojo_principal.ProcessTopologyAttestation.for_cpu_test(
            monitor=_peer(52001),
            broker=_peer(52001),
            model_driver=_peer(52003),
            session_nonce="duplicate-role-pid",
        )
    wrong_endpoint = integration.FakeLoopbackEndpoint(
        observation=_observation(model_pin),
        model_driver_peer=_peer(59999),
        retry_policy=integration.FakeRetryPolicy.NEVER,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError):
        _session(
            binding=dojo_binding,
            model_pin=model_pin,
            runtime_pins=runtime_pins,
            topology=topology,
            endpoint=wrong_endpoint,
        )


@pytest.mark.parametrize(
    "peer",
    (
        _peer(59998),
        _peer(51002, uid=os.getuid() + 1),
        _peer(51002, gid=os.getgid() + 1),
        _peer(51001),
        _peer(51003),
    ),
)
def test_broker_pid_uid_gid_or_role_confusion_is_rejected(
    dojo_binding, model_pin, runtime_pins, topology, peer
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError):
        session.execute_cpu_fake(
            input_commitment_sha256="1" * 64,
            request_id="peer-confusion-01",
            observed_broker_peer=peer,
        )


def test_single_attempt_cpu_fake_exchange_has_finite_schema_and_false_gates(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256=hashlib.sha256(b"opaque task input").hexdigest(),
        request_id="single-attempt-01",
        observed_broker_peer=topology.broker,
    )
    assert receipt.status is integration.CpuExchangeStatus.CPU_FAKE_COMPLETED
    assert receipt.attempt_count == 1
    assert len(receipt.restricted_requests) == 1
    assert len(receipt.restricted_replies) == 1
    assert receipt.restricted_replies[0].status is integration.FakeReplyStatus.CPU_FAKE_ACK
    assert receipt.chronology.step_count == integration.CHRONOLOGY_HMAX == 16
    assert receipt.chronology.request_count == 1
    assert receipt.chronology.reply_count == 1
    assert receipt.fake_endpoint_exercised is True
    assert receipt.principal_eligible is False
    assert receipt.model_executed is False
    assert receipt.gpu_executed is False
    assert receipt.scoring_executed is False
    assert receipt.detector_executed is False
    assert receipt.effectiveness_evidence is False
    assert receipt.utility_evidence is False
    assert receipt.principal_outcome_count == 0
    integration.validate_cpu_chronology_wire(
        wire=receipt.chronology.to_wire(),
        permit=session.permit,
        requests=receipt.restricted_requests,
        replies=receipt.restricted_replies,
    )


def test_retry_once_is_two_distinct_attempts_with_exact_chronology(
    leak_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=leak_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        retry_policy=integration.FakeRetryPolicy.ONCE,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="2" * 64,
        request_id="retry-once-01",
        observed_broker_peer=topology.broker,
    )
    assert receipt.status is integration.CpuExchangeStatus.CPU_FAKE_COMPLETED
    assert receipt.attempt_count == integration.MAX_ATTEMPTS == 2
    assert tuple(request.attempt_number for request in receipt.restricted_requests) == (1, 2)
    assert tuple(reply.status for reply in receipt.restricted_replies) == (
        integration.FakeReplyStatus.CPU_FAKE_RETRYABLE,
        integration.FakeReplyStatus.CPU_FAKE_ACK,
    )
    assert len({request.sha256 for request in receipt.restricted_requests}) == 2


def test_retry_exhaustion_is_finite_and_never_principal(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        retry_policy=integration.FakeRetryPolicy.ALWAYS,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="3" * 64,
        request_id="retry-exhausted-01",
        observed_broker_peer=topology.broker,
    )
    assert receipt.status is integration.CpuExchangeStatus.CPU_FAKE_RETRY_EXHAUSTED
    assert receipt.attempt_count == 2
    assert all(
        reply.status is integration.FakeReplyStatus.CPU_FAKE_RETRYABLE
        for reply in receipt.restricted_replies
    )
    assert receipt.principal_eligible is False
    assert receipt.principal_outcome_count == 0


def test_duplicate_request_attempt_and_out_of_order_retry_are_rejected(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    endpoint = _endpoint(
        model_pin, topology, retry_policy=integration.FakeRetryPolicy.ONCE
    )
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        endpoint=endpoint,
    )
    first = integration.CpuLoopbackRequest.create(
        permit=session.permit,
        request_id="direct-retry-01",
        attempt_number=1,
        input_commitment_sha256="4" * 64,
    )
    reply = integration.CpuLoopbackReply.from_wire(
        endpoint.handle(first.to_wire(), observed_peer=topology.broker)
    )
    assert reply.status is integration.FakeReplyStatus.CPU_FAKE_RETRYABLE
    with pytest.raises(integration.LiveEndpointIntegrationError, match="duplicate"):
        endpoint.handle(first.to_wire(), observed_peer=topology.broker)

    out_of_order = integration.CpuLoopbackRequest.create(
        permit=session.permit,
        request_id="out-of-order-01",
        attempt_number=2,
        input_commitment_sha256="5" * 64,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="order"):
        endpoint.handle(out_of_order.to_wire(), observed_peer=topology.broker)


def test_session_request_id_replay_and_endpoint_rebinding_are_rejected(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    endpoint = _endpoint(model_pin, topology)
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        endpoint=endpoint,
    )
    session.execute_cpu_fake(
        input_commitment_sha256="6" * 64,
        request_id="session-replay-01",
        observed_broker_peer=topology.broker,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="one-shot"):
        session.execute_cpu_fake(
            input_commitment_sha256="6" * 64,
            request_id="session-replay-01",
            observed_broker_peer=topology.broker,
        )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="second request"):
        session.execute_cpu_fake(
            input_commitment_sha256="7" * 64,
            request_id="entirely-novel-request-02",
            observed_broker_peer=topology.broker,
        )
    independent_endpoint = _endpoint(model_pin, topology)
    with pytest.raises(integration.LiveEndpointIntegrationError, match="already"):
        integration.establish_cpu_loopback(
            schedule=dojo_binding,
            model=model_pin,
            runtime_isolation=runtime_pins,
            topology=topology,
            endpoint=independent_endpoint,
            expected_endpoint_url=ENDPOINT_URL,
        )


@pytest.mark.parametrize(
    "request_ids",
    (("concurrent-same", "concurrent-same"), ("concurrent-left", "concurrent-right")),
)
def test_concurrent_same_or_different_ids_admit_exactly_one_request(
    leak_binding, model_pin, runtime_pins, topology, request_ids
) -> None:
    session = _session(
        binding=leak_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    barrier = threading.Barrier(2)
    receipts = []
    errors = []

    def invoke(index: int) -> None:
        barrier.wait()
        try:
            receipts.append(
                session.execute_cpu_fake(
                    input_commitment_sha256=f"{index + 1}" * 64,
                    request_id=request_ids[index],
                    observed_broker_peer=topology.broker,
                )
            )
        except integration.LiveEndpointIntegrationError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=invoke, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert len(receipts) == 1
    assert len(errors) == 1
    assert "one-shot" in str(errors[0])
    assert receipts[0].attempt_count == 1


def test_plan_drift_after_binding_but_before_establish_fails_closed(
    leak_binding, model_pin, runtime_pins, topology
) -> None:
    plan = leak_binding._plan
    original_sha256 = plan.plan_sha256
    object.__setattr__(plan, "plan_sha256", "0" * 64)
    try:
        with pytest.raises(
            integration.LiveEndpointIntegrationError,
            match="source plan drifted before endpoint admission",
        ):
            _session(
                binding=leak_binding,
                model_pin=model_pin,
                runtime_pins=runtime_pins,
                topology=topology,
            )
    finally:
        object.__setattr__(plan, "plan_sha256", original_sha256)


def test_admitted_permit_carries_only_compact_schedule_snapshot(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    snapshot = session.permit._schedule
    assert not hasattr(snapshot, "_plan")
    assert not hasattr(snapshot, "_unit")
    assert snapshot.binding_sha256 == dojo_binding.binding_sha256
    snapshot.revalidate()


def test_failed_partial_endpoint_bind_releases_only_the_failed_schedule_claim(
    dojo_plan, model_pin, runtime_pins, topology
) -> None:
    first_binding = integration.ScheduleBinding.for_agentdojo(
        plan=dojo_plan, entry=dojo_plan.entries[next(_DOJO_BINDING_INDICES)]
    )
    recovery_binding = integration.ScheduleBinding.for_agentdojo(
        plan=dojo_plan, entry=dojo_plan.entries[next(_DOJO_BINDING_INDICES)]
    )
    shared_endpoint = _endpoint(model_pin, topology)
    first_session = _session(
        binding=first_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        endpoint=shared_endpoint,
    )
    assert first_session.permit.schedule_binding_sha256 == first_binding.binding_sha256
    with pytest.raises(integration.LiveEndpointIntegrationError, match="already bound"):
        _session(
            binding=recovery_binding,
            model_pin=model_pin,
            runtime_pins=runtime_pins,
            topology=topology,
            endpoint=shared_endpoint,
        )
    recovered = _session(
        binding=recovery_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    assert recovered.permit.schedule_binding_sha256 == recovery_binding.binding_sha256


def test_post_bind_session_constructor_failure_is_monotone(
    dojo_plan, model_pin, runtime_pins, topology, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = integration.ScheduleBinding.for_agentdojo(
        plan=dojo_plan, entry=dojo_plan.entries[next(_DOJO_BINDING_INDICES)]
    )
    endpoint = _endpoint(model_pin, topology)

    def fail_after_bind(**_kwargs):
        raise RuntimeError("deterministic post-bind constructor failure")

    monkeypatch.setattr(integration, "CpuLoopbackSession", fail_after_bind)
    with pytest.raises(RuntimeError, match="post-bind constructor failure"):
        _session(
            binding=binding,
            model_pin=model_pin,
            runtime_pins=runtime_pins,
            topology=topology,
            endpoint=endpoint,
        )
    assert endpoint._bound_permit is not None
    with pytest.raises(integration.LiveEndpointIntegrationError, match="already admitted"):
        _session(
            binding=binding,
            model_pin=model_pin,
            runtime_pins=runtime_pins,
            topology=topology,
        )


def test_regular_file_identity_tuple_has_each_metadata_coordinate_once() -> None:
    metadata = SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_uid=3,
        st_gid=4,
        st_mode=stat.S_IFREG | 0o600,
        st_nlink=5,
        st_size=6,
        st_mtime_ns=7,
        st_ctime_ns=8,
    )
    assert integration._regular_identity(metadata) == (
        1,
        2,
        3,
        4,
        stat.S_IFREG,
        0o600,
        5,
        6,
        7,
        8,
    )


def test_endpoint_drift_after_preflight_is_rejected_before_dispatch(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    endpoint = _endpoint(model_pin, topology)
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        endpoint=endpoint,
    )
    endpoint.drift_observation_for_test(
        _observation(model_pin, backend_version="drifted-version")
    )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="drift"):
        session.execute_cpu_fake(
            input_commitment_sha256="7" * 64,
            request_id="endpoint-drift-01",
            observed_broker_peer=topology.broker,
        )
    assert endpoint.accepted_packet_count == 0


def test_endpoint_drift_between_retry_attempts_is_rejected_before_packet_two(
    leak_binding, model_pin, runtime_pins, topology
) -> None:
    endpoint = _endpoint(
        model_pin, topology, retry_policy=integration.FakeRetryPolicy.ONCE
    )
    session = _session(
        binding=leak_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        endpoint=endpoint,
    )
    endpoint.drift_after_first_reply_for_test(
        _observation(model_pin, model_artifact_sha256="f" * 64)
    )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="drift"):
        session.execute_cpu_fake(
            input_commitment_sha256="e" * 64,
            request_id="between-attempt-drift-01",
            observed_broker_peer=topology.broker,
        )
    assert endpoint.accepted_packet_count == 1


@pytest.mark.parametrize(
    "field,value",
    (
        ("session_sha256", "0" * 64),
        ("plan_sha256", "0" * 64),
        ("schedule_binding_sha256", "0" * 64),
        ("model_identity_sha256", "0" * 64),
        ("runtime_isolation_sha256", "0" * 64),
        ("endpoint_attestation_sha256", "0" * 64),
    ),
)
def test_rehashed_request_binding_forgery_is_rejected_by_endpoint(
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
        request_id=f"forged-{field}",
        attempt_number=1,
        input_commitment_sha256="8" * 64,
    )
    wire = request.to_wire()
    wire[field] = value
    wire["sha256"] = integration.cpu_request_sha256(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError, match="binding"):
        endpoint.handle(wire, observed_peer=topology.broker)


def test_request_reply_wire_schema_rejects_extra_missing_role_and_digest_drift(
    dojo_binding, model_pin, runtime_pins, topology
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
        request_id="strict-wire-01",
        attempt_number=1,
        input_commitment_sha256="9" * 64,
    )
    extra = request.to_wire()
    extra["task_answer"] = "forbidden"
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuLoopbackRequest.from_wire(extra)
    missing = request.to_wire()
    missing.pop("plan_sha256")
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuLoopbackRequest.from_wire(missing)
    wrong_role = request.to_wire()
    wrong_role["role"] = "monitor"
    wrong_role["sha256"] = integration.cpu_request_sha256(wrong_role)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuLoopbackRequest.from_wire(wrong_role)
    drifted = request.to_wire()
    drifted["input_commitment_sha256"] = "a" * 64
    with pytest.raises(integration.LiveEndpointIntegrationError, match="digest"):
        integration.CpuLoopbackRequest.from_wire(drifted)

    reply_wire = endpoint.handle(request.to_wire(), observed_peer=topology.broker)
    reply = integration.CpuLoopbackReply.from_wire(reply_wire)
    assert reply.role is integration.EndpointRole.MODEL_DRIVER
    reply_extra = dict(reply_wire)
    reply_extra["response_text"] = "forbidden"
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.CpuLoopbackReply.from_wire(reply_extra)


@pytest.mark.parametrize(
    "mutation",
    (
        "preflight_status",
        "request_reply_binding",
        "reply_attempt",
        "terminal_status",
        "pad_binding",
        "sequence_duplicate",
    ),
)
def test_chronology_semantic_forgery_fails_after_rehash(
    dojo_binding, model_pin, runtime_pins, topology, mutation
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
        retry_policy=integration.FakeRetryPolicy.ONCE,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="a" * 64,
        request_id=f"chronology-{mutation}",
        observed_broker_peer=topology.broker,
    )
    wire = receipt.chronology.to_wire()
    steps = wire["steps"]
    if mutation == "preflight_status":
        steps[0]["status"] = "CPU_FAKE_COMPLETED"
        steps[0]["sha256"] = integration.chronology_event_sha256(steps[0])
    elif mutation == "request_reply_binding":
        request_step = next(step for step in steps if step["kind"] == "REQUEST")
        request_step["reply_sha256"] = "b" * 64
        request_step["sha256"] = integration.chronology_event_sha256(request_step)
    elif mutation == "reply_attempt":
        reply_step = next(step for step in steps if step["kind"] == "REPLY")
        reply_step["attempt_number"] = 2
        reply_step["sha256"] = integration.chronology_event_sha256(reply_step)
    elif mutation == "terminal_status":
        terminal = next(step for step in steps if step["kind"] == "TERMINAL")
        terminal["status"] = "CPU_FAKE_RETRY_EXHAUSTED"
        terminal["sha256"] = integration.chronology_event_sha256(terminal)
    elif mutation == "pad_binding":
        pad = next(step for step in steps if step["kind"] == "PAD")
        pad["request_sha256"] = "c" * 64
        pad["sha256"] = integration.chronology_event_sha256(pad)
    elif mutation == "sequence_duplicate":
        steps[-1]["sequence"] = steps[-2]["sequence"]
        steps[-1]["sha256"] = integration.chronology_event_sha256(steps[-1])
    else:
        raise AssertionError(mutation)
    wire["chronology_sha256"] = integration.cpu_chronology_sha256(wire)
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.validate_cpu_chronology_wire(
            wire=wire,
            permit=session.permit,
            requests=receipt.restricted_requests,
            replies=receipt.restricted_replies,
        )


def test_restricted_wire_and_public_receipt_exclude_task_answer_and_scorer_data(
    leak_binding, model_pin, runtime_pins, topology
) -> None:
    sentinel = "DO-NOT-EXPOSE-TASK-ANSWER-919191"
    session = _session(
        binding=leak_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256=hashlib.sha256(sentinel.encode()).hexdigest(),
        request_id="no-task-answer-01",
        observed_broker_peer=topology.broker,
    )
    public = receipt.to_public_wire()
    rendered_public = json.dumps(public, sort_keys=True).casefold()
    rendered_restricted = json.dumps(
        {
            "requests": [value.to_wire() for value in receipt.restricted_requests],
            "replies": [value.to_wire() for value in receipt.restricted_replies],
        },
        sort_keys=True,
    ).casefold()
    for rendered in (rendered_public, rendered_restricted):
        assert sentinel.casefold() not in rendered
        assert not any(
            forbidden in rendered
            for forbidden in (
                "ground_truth",
                "expected_answer",
                "task_answer",
                "scorer_result",
                "detector_result",
                "response_text",
                "prompt_text",
            )
        )
    request_keys = frozenset(receipt.restricted_requests[0].to_wire())
    reply_keys = frozenset(receipt.restricted_replies[0].to_wire())
    assert not request_keys & {
        "condition_result",
        "detector_result",
        "expected_answer",
        "ground_truth",
        "scorer_result",
        "task_answer",
    }
    assert not reply_keys & {
        "condition_result",
        "detector_result",
        "expected_answer",
        "ground_truth",
        "scorer_result",
        "task_answer",
    }


def test_principal_gate_and_cpu_receipt_flags_cannot_be_promoted(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    assert session.permit.principal_eligible is False
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.PrincipalEndpointPermit.issue(
            cpu_permit=session.permit,
            clean_commit=True,
            live_runtime=True,
            strict_isolation=True,
            cuda_verified=True,
            real_endpoint=True,
        )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="d" * 64,
        request_id="false-gates-01",
        observed_broker_peer=topology.broker,
    )
    for change in (
        {"principal_eligible": True},
        {"model_executed": True},
        {"gpu_executed": True},
        {"scoring_executed": True},
        {"detector_executed": True},
        {"effectiveness_evidence": True},
        {"utility_evidence": True},
        {"principal_outcome_count": 1},
    ):
        with pytest.raises(integration.LiveEndpointIntegrationError):
            dataclasses.replace(receipt, **change)


def test_direct_construction_subclasses_and_mapping_aliases_cannot_bypass_contract(
    dojo_binding, model_pin, runtime_pins, topology
) -> None:
    with pytest.raises(integration.LiveEndpointIntegrationError):
        integration.PrincipalEndpointPermit()

    class ModelSubclass(integration.PinnedModelIdentity):
        pass

    with pytest.raises(integration.LiveEndpointIntegrationError, match="subclass"):
        ModelSubclass(
            model_id=model_pin.model_id,
            model_revision=model_pin.model_revision,
            model_artifact_sha256=model_pin.model_artifact_sha256,
            backend=model_pin.backend,
            backend_version=model_pin.backend_version,
            sha256=model_pin.sha256,
        )

    class EndpointSubclass(integration.FakeLoopbackEndpoint):
        pass

    subclass_endpoint = EndpointSubclass(
        observation=_observation(model_pin),
        model_driver_peer=topology.model_driver,
        retry_policy=integration.FakeRetryPolicy.NEVER,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="type is not exact"):
        integration.establish_cpu_loopback(
            schedule=dojo_binding,
            model=model_pin,
            runtime_isolation=runtime_pins,
            topology=topology,
            endpoint=subclass_endpoint,
            expected_endpoint_url=ENDPOINT_URL,
        )

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
        request_id="mapping-alias-01",
        attempt_number=1,
        input_commitment_sha256="e" * 64,
    )
    with pytest.raises(integration.LiveEndpointIntegrationError, match="exact"):
        integration.CpuLoopbackRequest.from_wire(MappingProxyType(request.to_wire()))
    with pytest.raises(integration.LiveEndpointIntegrationError):
        dataclasses.replace(session.permit, principal_eligible=True)


def test_create_once_public_evidence_is_private_bound_and_revalidated(
    tmp_path: Path, leak_binding, model_pin, runtime_pins, topology
) -> None:
    session = _session(
        binding=leak_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="f" * 64,
        request_id="evidence-create-once-01",
        observed_broker_peer=topology.broker,
    )
    output_parent = tmp_path / "evidence"
    output_parent.mkdir(mode=0o700)
    output = output_parent / "cpu-receipt.json"
    evidence_receipt = integration.write_cpu_receipt_create_once(
        path=output, receipt=receipt
    )
    metadata = output.stat(follow_symlinks=False)
    assert metadata.st_mode & 0o777 == 0o600
    assert metadata.st_nlink == 1
    assert integration.validate_cpu_evidence_receipt(evidence_receipt) == receipt.to_public_wire()
    with pytest.raises(integration.LiveEndpointIntegrationError, match="already exists"):
        integration.write_cpu_receipt_create_once(path=output, receipt=receipt)
    output.chmod(0o644)
    with pytest.raises(integration.LiveEndpointIntegrationError, match="identity"):
        integration.validate_cpu_evidence_receipt(evidence_receipt)


def test_create_once_evidence_rejects_parent_rebind_and_preserves_rebound_bytes(
    tmp_path: Path,
    dojo_binding,
    model_pin,
    runtime_pins,
    topology,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session(
        binding=dojo_binding,
        model_pin=model_pin,
        runtime_pins=runtime_pins,
        topology=topology,
    )
    receipt = session.execute_cpu_fake(
        input_commitment_sha256="0" * 64,
        request_id="evidence-parent-rebind-01",
        observed_broker_peer=topology.broker,
    )
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    displaced = tmp_path / "displaced"
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    output = output_parent / "cpu-receipt.json"
    attacker_bytes = b"attacker-controlled-rebound"
    (attacker / output.name).write_bytes(attacker_bytes)
    real_open = integration.os.open
    raced = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal raced
        if path == output.name and dir_fd is not None and flags & os.O_CREAT and not raced:
            raced = True
            output_parent.rename(displaced)
            output_parent.symlink_to(attacker, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(integration.os, "open", racing_open)
    with pytest.raises(integration.LiveEndpointIntegrationError, match="parent binding"):
        integration.write_cpu_receipt_create_once(path=output, receipt=receipt)
    assert raced is True
    assert output.read_bytes() == attacker_bytes
    assert not (displaced / output.name).exists()


def test_cpu_integration_source_has_no_network_model_gpu_or_execution_calls() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    forbidden_imports = {
        "aiohttp",
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "torch",
        "transformers",
        "urllib",
        "vllm",
    }
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            else:
                continue
            if name in {"connect", "generate", "post", "request", "run", "urlopen"}:
                calls.add(name)
    assert not (imports & forbidden_imports)
    assert not calls


def test_static_attestation_cli_reports_only_false_cpu_foundation_gates() -> None:
    spec = importlib.util.spec_from_file_location("attest_live_endpoint_cpu_v29", CLI_PATH)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    result = cli.attest(REPOSITORY)
    assert result["status"] == "PASS_CPU_FAKE_FOUNDATION_ONLY"
    assert result["source"]["sha256"] == hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
    assert set(result["false_gates"].values()) == {False}
    assert set(result["operations_performed"].values()) == {False}
    assert result["boundary"] == {
        "endpoint_kind": "in_process_fake_callable",
        "peer_identity": "synthetic_cpu_api_only",
        "process_scope": "single_interpreter_process_local_registry",
        "serialized_cross_process_binding": False,
    }
