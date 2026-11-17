"""Adversarial contracts for G8 provenance, storage, and timing integrity."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

import pytest


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = ARTIFACT_ROOT / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

import g8_matched_scalability as g8  # noqa: E402


def test_parent_rejects_fabricated_worker_integrity_even_when_boolean_says_match(
    monkeypatch,
):
    expected_hashes = {path: "0" * 64 for path in g8.COMPONENT_PATHS}
    storage_identity = {
        "resolved_path": "/tmp",
        "device_id": 1,
        "mountpoint": "/tmp",
        "filesystem_type": "tmpfs",
        "mount_source": "tmpfs",
        "mount_options": ["rw"],
    }
    expected_spec = {
        "schema_version": g8.WORKER_SPEC_SCHEMA,
        "run_id": "audit",
        "block_id": "r000-tmpfs-c001",
        "condition": "unmediated_handler",
        "storage_label": "tmpfs",
        "storage_class": "tmpfs-diagnostic",
        "storage_root": "/tmp",
        "repetition": 0,
        "concurrency": 1,
        "operations": 1,
        "warmup_operations": 0,
        "expected_component_sha256": expected_hashes,
        "expected_source_commit": "real-commit",
        "expected_source_dirty": True,
        "source_repository_root": "/repository",
        "worker_source_root": "/snapshot",
        "expected_worker_source_sha256": expected_hashes,
        "expected_storage_identity": storage_identity,
    }
    honest_observation = {
        "component_sha256": expected_hashes,
        "worker_source_sha256": expected_hashes,
        "storage_identity": storage_identity,
        "source_commit": "real-commit",
        "source_dirty": True,
        "matches_expected": True,
    }
    monkeypatch.setattr(g8, "_integrity_snapshot", lambda _spec: honest_observation)
    fabricated_integrity = {
        **honest_observation,
        "component_sha256": {path: "f" * 64 for path in g8.COMPONENT_PATHS},
        "source_commit": "fabricated-commit",
        "matches_expected": True,
    }
    fabricated = {
        "schema_version": g8.WORKER_RESULT_SCHEMA,
        "status": "failed",
        "phase": "worker",
        "spec": expected_spec,
        "warmup": None,
        "measured": None,
        "worker_error": {"error_type": "Audit", "error_message": "fabricated"},
        "integrity": {
            "start": fabricated_integrity,
            "end": fabricated_integrity,
        },
    }
    with pytest.raises(ValueError, match="integrity|component|source|spec"):
        g8._validate_worker_result(fabricated, expected_spec)


def test_integrity_rejects_boolean_integer_aliases():
    hashes = {path: "0" * 64 for path in g8.COMPONENT_PATHS}
    storage = {
        "resolved_path": "/tmp",
        "device_id": 1,
        "mountpoint": "/tmp",
        "filesystem_type": "tmpfs",
        "mount_source": "tmpfs",
        "mount_options": ["rw"],
    }
    spec = {
        "expected_component_sha256": hashes,
        "expected_worker_source_sha256": hashes,
        "expected_source_commit": "commit",
        "expected_source_dirty": True,
        "expected_storage_identity": storage,
    }
    integrity = {
        "component_sha256": hashes,
        "worker_source_sha256": hashes,
        "storage_identity": storage,
        "source_commit": "commit",
        "source_dirty": 1,
        "matches_expected": True,
    }
    with pytest.raises(ValueError, match="dirty"):
        g8._validate_integrity(integrity, spec)


@pytest.mark.parametrize("bad_device", [True, -1])
def test_attestation_rejects_boolean_and_negative_device_aliases(
    tmp_path: Path, bad_device
):
    root = tmp_path.resolve()
    attestation = tmp_path / "attestation.json"
    value = {
        "schema_version": g8.STORAGE_ATTESTATION_SCHEMA,
        "label": "node-local",
        "resolved_path": str(root),
        "filesystem_type": "ext4",
        "hostname": "test-host",
        "device_id": bad_device,
        "mountpoint": str(root),
        "mount_source": "/dev/test",
        "mount_options": ["rw"],
        "node_local_verified": True,
        "persistence_verified": True,
        "verification_method": "test",
        "verified_at_utc": "2026-08-20T00:00:00+00:00",
        "verified_by": "auditor",
    }
    attestation.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="device_id"):
        g8._load_attestation(
            attestation,
            label="node-local",
            resolved_path=root,
            filesystem_type="ext4",
            hostname="test-host",
            device_id=bad_device,
            mountpoint=str(root),
            mount_source="/dev/test",
            mount_options=("rw",),
        )


def test_attestation_rejects_timezone_naive_verification_timestamp(tmp_path: Path):
    root = tmp_path.resolve()
    attestation = tmp_path / "attestation.json"
    value = {
        "schema_version": g8.STORAGE_ATTESTATION_SCHEMA,
        "label": "node-local",
        "resolved_path": str(root),
        "filesystem_type": "ext4",
        "hostname": "test-host",
        "device_id": root.stat().st_dev,
        "mountpoint": str(root),
        "mount_source": "/dev/test",
        "mount_options": ["rw"],
        "node_local_verified": True,
        "persistence_verified": True,
        "verification_method": "test",
        "verified_at_utc": "2026-08-20T00:00:00",
        "verified_by": "auditor",
    }
    attestation.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="timezone|offset"):
        g8._load_attestation(
            attestation,
            label="node-local",
            resolved_path=root,
            filesystem_type="ext4",
            hostname="test-host",
            device_id=root.stat().st_dev,
            mountpoint=str(root),
            mount_source="/dev/test",
            mount_options=("rw",),
        )


def test_hash_addressed_worker_copy_survives_original_mutate_restore(
    monkeypatch, tmp_path: Path
):
    repository = tmp_path / "repo"
    source = repository / "source" / "artifact" / "experiments" / "worker.py"
    source.parent.mkdir(parents=True)
    source.write_text("ORIGINAL\n", encoding="ascii")
    relative = "source/artifact/experiments/worker.py"
    monkeypatch.setattr(g8, "COMPONENT_PATHS", (relative,))
    expected = {relative: g8._sha256_file(source)}
    snapshot_root = tmp_path / "snapshot"
    snapshot = g8._build_pinned_worker_source(repository, snapshot_root, expected)

    source.write_text("MUTATED\n", encoding="ascii")
    source.write_text("ORIGINAL\n", encoding="ascii")
    copied = snapshot_root / relative
    assert copied.read_text(encoding="ascii") == "ORIGINAL\n"
    assert snapshot == expected
    assert stat.S_IMODE(copied.stat().st_mode) == 0o444


def test_storage_identity_rejects_remount_or_source_substitution():
    expected = {
        "resolved_path": "/node/local",
        "device_id": 17,
        "mountpoint": "/node/local",
        "filesystem_type": "xfs",
        "mount_source": "/dev/nvme0n1p1",
        "mount_options": ["rw"],
    }
    observed = {**expected, "mount_source": "/dev/loop7"}
    with pytest.raises(ValueError, match="storage.*identity|mount_source"):
        g8._validate_storage_identity(observed, expected)


def test_validator_delay_is_outside_latency_and_throughput_envelope(monkeypatch):
    order = []

    def operation(index):
        order.append(f"operation-{index}")
        return 1

    def delayed_validator(condition, result):
        order.append(f"validate-{len([item for item in order if item.startswith('validate-')])}")
        return 1, None

    monkeypatch.setattr(g8, "_validate_operation_result", delayed_validator)
    result = g8._execute_parallel(
        condition="unmediated_handler",
        operation=operation,
        operation_count=3,
        concurrency=1,
        capture_operations=True,
    )
    assert result["status"] == "ok"
    assert order == [
        "operation-0",
        "operation-1",
        "operation-2",
        "validate-0",
        "validate-1",
        "validate-2",
    ]


def test_adversarial_contract_has_no_skip_or_xfail_escape_hatch():
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden = (
        "pytest." + "skip",
        "pytest.mark." + "skip",
        "pytest." + "xfail",
        "pytest.mark." + "xfail",
    )
    assert not any(token in source for token in forbidden)
