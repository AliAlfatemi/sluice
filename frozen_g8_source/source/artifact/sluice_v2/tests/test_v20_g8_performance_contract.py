"""Fail-closed contract tests for the additive G8 performance foundation.

The integration test deliberately uses cluster-login ``/tmp`` and must fail, rather
than skip, when the declared Linux/tmpfs/singleton boundary is unavailable.
Its tiny outputs are diagnostic test artifacts, never performance evidence.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
import sys
import tempfile

import pytest


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = ARTIFACT_ROOT / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

import g8_matched_scalability as g8  # noqa: E402


def _profile(storage_class: str, *, attested: bool) -> g8.StorageProfile:
    filesystem_type = "ext4" if storage_class == "local-persistent" else "tmpfs"
    return g8.StorageProfile(
        label="persistent" if storage_class == "local-persistent" else "tmpfs",
        storage_class=storage_class,
        requested_path="/diagnostic",
        resolved_path="/diagnostic",
        device_id=1,
        mountpoint="/diagnostic",
        filesystem_type=filesystem_type,
        mount_source="diagnostic",
        mount_options=("rw",),
        attestation_path="attestation.json" if attested else None,
        attestation_sha256="0" * 64 if attested else None,
        attestation_canonical_json="{}\n" if attested else None,
        operator_attested_local_persistence=attested,
    )


def test_frozen_four_conditions_and_scaling_range_are_complete():
    assert g8.CONDITIONS == (
        "unmediated_handler",
        "inmemory_secure_domain",
        "durable_direct",
        "singleton_ipc",
    )
    assert g8.DEFAULT_CONCURRENCIES == (1, 2, 4, 8, 16, 32, 64)
    assert g8.MIN_FINAL_REPETITIONS == 10
    assert g8.MIN_P999_OPERATIONS == 10_000


def test_nearest_rank_and_p999_support_are_explicit():
    assert g8.nearest_rank([1.0, 2.0, 3.0, 4.0], 0.50) == 2.0
    unsupported = g8.summarize_latencies([1, 2, 3])
    assert unsupported["p99_9_ms"] is None
    assert unsupported["p99_9_support"] == {
        "supported": False,
        "minimum_operations": 10_000,
        "observed_operations": 3,
    }
    supported = g8.summarize_latencies(list(range(1, 10_001)))
    assert supported["p99_9_support"]["supported"] is True
    assert supported["p99_9_ms"] is not None


def test_block_schedule_is_paired_randomized_total_and_deterministic():
    profiles = (_profile("local-persistent", attested=True), _profile("tmpfs-diagnostic", attested=False))
    first = g8.build_schedule(profiles, (1, 4), 3, seed=8675309)
    second = g8.build_schedule(profiles, (1, 4), 3, seed=8675309)
    assert first == second
    assert len(first) == 2 * 2 * 3 * len(g8.CONDITIONS)
    by_block: dict[str, list[dict]] = {}
    for row in first:
        by_block.setdefault(row["block_id"], []).append(row)
    assert len(by_block) == 12
    for rows in by_block.values():
        assert {row["condition"] for row in rows} == set(g8.CONDITIONS)
        assert sorted(row["condition_order"] for row in rows) == [0, 1, 2, 3]


def test_final_mode_is_disabled_while_foundation_and_singleton_are_unreviewed():
    clean = {"commit": "1" * 40, "dirty": False}
    dirty = {"commit": "1" * 40, "dirty": True}
    common = {
        "mode": "final",
        "operations": 10_000,
        "warmup_operations": 1_000,
        "repetitions": 10,
        "concurrencies": g8.DEFAULT_CONCURRENCIES,
        "bootstrap_replicates": 10_000,
    }
    with pytest.raises(ValueError, match="final mode is disabled"):
        g8.validate_run_parameters(
            **common,
            profiles=(_profile("local-persistent", attested=True),),
            provenance=dirty,
        )
    with pytest.raises(ValueError, match="final mode is disabled"):
        g8.validate_run_parameters(
            **common,
            profiles=(_profile("local-persistent", attested=False),),
            provenance=clean,
        )
    with pytest.raises(ValueError, match="final mode is disabled"):
        g8.validate_run_parameters(
            **common,
            profiles=(_profile("tmpfs-diagnostic", attested=False),),
            provenance=clean,
        )
    assert g8.FINAL_CLAIMS_ENABLED is False


def test_tmpfs_and_diagnostic_mode_are_never_claim_eligible():
    persistent = _profile("local-persistent", attested=True)
    tmpfs = _profile("tmpfs-diagnostic", attested=False)
    assert not g8.cell_claim_eligible(
        mode="final", source_clean=True, profile=persistent, status="ok"
    )
    assert not g8.cell_claim_eligible(
        mode="diagnostic", source_clean=True, profile=persistent, status="ok"
    )
    assert not g8.cell_claim_eligible(
        mode="final", source_clean=True, profile=tmpfs, status="ok"
    )
    assert not g8.cell_claim_eligible(
        mode="final", source_clean=True, profile=persistent, status="failed"
    )


def test_worker_schema_is_exact_and_rejects_boolean_integers():
    spec = {
        "schema_version": g8.WORKER_SPEC_SCHEMA,
        "run_id": "diagnostic",
        "block_id": "r000-tmpfs-c001",
        "condition": "unmediated_handler",
        "storage_label": "tmpfs",
        "storage_class": "tmpfs-diagnostic",
        "storage_root": "/tmp",
        "repetition": 0,
        "concurrency": 1,
        "operations": 2,
        "warmup_operations": 1,
        "expected_component_sha256": {
            path: "0" * 64 for path in g8.COMPONENT_PATHS
        },
        "expected_source_commit": "1" * 40,
        "expected_source_dirty": True,
        "source_repository_root": "/repository",
        "worker_source_root": "/snapshot",
        "expected_worker_source_sha256": {
            path: "0" * 64 for path in g8.COMPONENT_PATHS
        },
        "expected_storage_identity": {
            "resolved_path": "/tmp",
            "device_id": 1,
            "mountpoint": "/tmp",
            "filesystem_type": "tmpfs",
            "mount_source": "tmpfs",
            "mount_options": ["rw"],
        },
    }
    assert g8._validate_worker_spec(spec) == spec
    with pytest.raises(ValueError, match="missing or unexpected"):
        g8._validate_worker_spec({**spec, "private_secret": "forbidden"})
    with pytest.raises(ValueError, match="operations"):
        g8._validate_worker_spec({**spec, "operations": True})


def test_raw_recomputation_is_exact_and_detects_worker_aggregate_tampering():
    rows = [
        {
            "operation_index": index,
            "worker_slot": 0,
            "status": "ok",
            "start_offset_ns": index * 10,
            "latency_ns": 5,
            "value_code": 1,
            "transcript_sequence": index + 1,
            "error_type": None,
            "error_message": None,
        }
        for index in range(3)
    ]
    exact = g8._validate_operation_records(
        rows, operation_count=3, condition="inmemory_secure_domain"
    )
    derived = g8._derive_raw_metrics(exact, "inmemory_secure_domain")
    assert derived["completed_operations"] == 3
    assert derived["measurement_envelope_ns"] == 25
    assert derived["failed_transaction_count"] is None

    measured = {
        "status": "ok",
        "expected_operations": 3,
        "completed_operations": 3,
        "failed_operations": 0,
        "failed_transaction_count": None,
        "failed_transaction_rate": None,
        "lock_contention_failure_count": None,
        "measurement_envelope_ns": 25,
        "throughput_operations_per_second": derived["throughput_operations_per_second"],
        "transcript_sequence_set_valid": True,
        "operations": rows,
        "latency_summary": derived["latency_summary"],
        "setup_or_measurement_error": None,
        "worker_process_cpu_ns": 1,
        "monitor_process_cpu_ns": None,
        "combined_cpu_ns": 1,
        "combined_cpu_core_equivalent_percent": 4.0,
        "worker_memory_before": {"vm_rss_bytes": 1, "vm_hwm_bytes": 1},
        "worker_memory_after": {"vm_rss_bytes": 1, "vm_hwm_bytes": 1},
        "worker_process_lifetime_peak_rss_bytes": 1,
        "monitor_memory_after": None,
        "sqlite_growth": None,
        "cleanup_error": None,
        "timing_scope": g8._TIMING_SCOPE,
        "memory_scope": g8._MEMORY_SCOPE,
    }
    assert g8._validate_measured(
        measured,
        operation_count=3,
        condition="inmemory_secure_domain",
        capture_operations=True,
    ) == measured
    with pytest.raises(ValueError, match="latency_summary"):
        g8._validate_measured(
            {
                **measured,
                "latency_summary": {**measured["latency_summary"], "p99_ms": 99.0},
            },
            operation_count=3,
            condition="inmemory_secure_domain",
            capture_operations=True,
        )


def test_malformed_or_missing_worker_can_receive_a_total_failure_denominator():
    rows = g8._synthetic_failure_operations(
        4,
        error_type="TimeoutExpired",
        error_message="diagnostic timeout",
    )
    validated = g8._validate_operation_records(
        rows,
        operation_count=4,
        condition="singleton_ipc",
    )
    assert [row["operation_index"] for row in validated] == [0, 1, 2, 3]
    derived = g8._derive_raw_metrics(validated, "singleton_ipc")
    assert derived["failed_operations"] == 4
    assert derived["failed_transaction_count"] == 4
    assert derived["throughput_operations_per_second"] is None
    assert g8._subprocess_text(b"partial\xff") == "partial\ufffd"

    duplicated = [dict(row) for row in rows]
    duplicated[-1]["operation_index"] = 0
    with pytest.raises(ValueError, match="duplicated or incomplete"):
        g8._validate_operation_records(
            duplicated,
            operation_count=4,
            condition="singleton_ipc",
        )


def test_storage_attestation_is_exact_and_bound_to_mount(tmp_path: Path):
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
        "verification_method": "operator checked mount source and reboot persistence",
        "verified_at_utc": "2026-08-20T00:00:00+00:00",
        "verified_by": "test-operator",
    }
    attestation.write_text(json.dumps(value), encoding="utf-8")
    digest, verified, canonical = g8._load_attestation(
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
    assert verified is True
    assert digest == g8.hashlib.sha256(canonical.encode("ascii")).hexdigest()
    value["unexpected"] = True
    attestation.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="missing or unexpected"):
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


def test_all_four_real_paths_emit_complete_nonclaimable_diagnostic_bundle():
    assert sys.platform.startswith("linux"), "singleton G8 integration requires Linux"
    mount = g8.detect_mount(Path("/tmp"))
    assert mount["filesystem_type"] in g8.TMPFS_TYPES, (
        "cluster-login /tmp must remain an explicitly diagnostic tmpfs"
    )
    profiles = g8.resolve_storage_profiles(("tmpfs:tmpfs-diagnostic:/tmp",))
    with tempfile.TemporaryDirectory(prefix="sluice-g8-contract-", dir="/tmp") as temporary:
        output_root = Path(temporary) / "output"
        result = g8.run_benchmark(
            output_root=output_root,
            profiles=profiles,
            mode="diagnostic",
            operations=2,
            warmup_operations=1,
            repetitions=1,
            concurrencies=(1,),
            seed=8675309,
            bootstrap_replicates=20,
            condition_timeout_seconds=120,
        )
        run_directory = Path(result["run_directory"])
        assert result["exit_code"] == 0
        assert result["summary"]["evidence_class"] == "NON_CLAIMABLE_DIAGNOSTIC"
        assert result["summary"]["paper_claim_eligible"] is False
        assert result["summary"]["raw_operation_count"] == 8
        assert result["summary"]["expected_repetition_count"] == 4
        assert result["summary"]["failed_repetition_count"] == 0
        assert result["manifest"]["validity"]["tmpfs_claim_eligible"] is False
        assert not any(row["claim_eligible"] for row in _read_jsonl(run_directory / "repetitions.jsonl"))

        with gzip.open(run_directory / "operations.jsonl.gz", "rt", encoding="ascii") as stream:
            operations = [json.loads(line) for line in stream]
        assert len(operations) == 8
        assert {row["condition"] for row in operations} == set(g8.CONDITIONS)
        assert all(row["status"] == "ok" for row in operations)

        repetitions = _read_jsonl(run_directory / "repetitions.jsonl")
        assert len(repetitions) == 4
        durable = next(row for row in repetitions if row["condition"] == "durable_direct")
        singleton = next(row for row in repetitions if row["condition"] == "singleton_ipc")
        assert durable["audit_rows_growth"] == 4
        assert singleton["audit_rows_growth"] == 4
        assert singleton["request_cache_rows_growth"] == 2

        reloaded, retained_raw_count = g8._reload_and_validate_retained_evidence(
            raw_path=run_directory / "operations.jsonl.gz",
            repetitions_path=run_directory / "repetitions.jsonl",
            expected_repetition_rows=repetitions,
            schedule=result["manifest"]["schedule"],
            operations=2,
            run_id=result["run_id"],
        )
        assert retained_raw_count == 8
        recomputed_cells = g8._summary_cells(
            reloaded,
            bootstrap_seed=8675309 + 9_999_991,
            bootstrap_replicates=20,
            expected_repetitions=1,
        )
        assert recomputed_cells == result["summary"]["cells"]

        checksum_lines = (run_directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        assert checksum_lines
        for line in checksum_lines:
            digest, relative = line.split("  ", 1)
            assert g8._sha256_file(run_directory / relative) == digest


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def test_contract_contains_no_skip_or_expected_failure_escape_hatch():
    source = Path(__file__).read_text(encoding="utf-8")
    driver = (EXPERIMENTS / "g8_matched_scalability.py").read_text(encoding="utf-8")
    forbidden = (
        "pytest." + "skip",
        "pytest.mark." + "skip",
        "pytest." + "xfail",
        "pytest.mark." + "xfail",
    )
    assert not any(token in source for token in forbidden)
    assert not any(token in driver for token in forbidden)
