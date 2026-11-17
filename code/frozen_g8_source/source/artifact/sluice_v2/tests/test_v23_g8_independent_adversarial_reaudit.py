"""Independent fail-first probes for adjacent G8 integrity boundaries.

These tests preserve the independent fail-first requirements and must stay
green before the additive foundation can be committed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
EXPERIMENT = REPOSITORY_ROOT / "source/artifact/experiments/g8_matched_scalability.py"
sys.path.insert(0, str(EXPERIMENT.parent))
import g8_matched_scalability as g8  # noqa: E402


def _storage_identity(path: str = "/tmp") -> dict:
    return {
        "resolved_path": path,
        "device_id": 1,
        "mountpoint": path,
        "filesystem_type": "tmpfs",
        "mount_source": "tmpfs",
        "mount_options": ["rw"],
    }


def _spec(*, operations: int = 1) -> dict:
    hashes = {path: "0" * 64 for path in g8.COMPONENT_PATHS}
    return {
        "schema_version": g8.WORKER_SPEC_SCHEMA,
        "run_id": "reaudit",
        "block_id": "r000-tmpfs-c001",
        "condition": "unmediated_handler",
        "storage_label": "tmpfs",
        "storage_class": "tmpfs-diagnostic",
        "storage_root": "/tmp",
        "repetition": 0,
        "concurrency": 1,
        "operations": operations,
        "warmup_operations": 0,
        "expected_component_sha256": hashes,
        "expected_source_commit": "1" * 40,
        "expected_source_dirty": True,
        "source_repository_root": "/repository",
        "worker_source_root": "/snapshot",
        "expected_worker_source_sha256": hashes,
        "expected_storage_identity": _storage_identity(),
    }


def _honest_integrity(spec: dict) -> dict:
    return {
        "component_sha256": spec["expected_component_sha256"],
        "worker_source_sha256": spec["expected_worker_source_sha256"],
        "storage_identity": spec["expected_storage_identity"],
        "source_commit": spec["expected_source_commit"],
        "source_dirty": spec["expected_source_dirty"],
        "matches_expected": True,
    }


def _result(spec: dict, **changes) -> dict:
    integrity = _honest_integrity(spec)
    result = {
        "schema_version": g8.WORKER_RESULT_SCHEMA,
        "status": "failed",
        "phase": "worker",
        "spec": spec,
        "warmup": None,
        "measured": None,
        "worker_error": {
            "error_type": "BoundedAudit",
            "error_message": "synthetic failure",
            "traceback": "",
        },
        "integrity": {"start": integrity, "end": integrity},
    }
    result.update(changes)
    return result


def _measured(condition: str = "unmediated_handler") -> dict:
    row = {
        "operation_index": 0,
        "worker_slot": 0,
        "status": "ok",
        "start_offset_ns": 0,
        "latency_ns": 10,
        "value_code": 1,
        "transcript_sequence": None if condition == "unmediated_handler" else 1,
        "error_type": None,
        "error_message": None,
    }
    derived = g8._derive_raw_metrics([row], condition)
    return {
        **derived,
        "operations": [row],
        "setup_or_measurement_error": None,
        "worker_process_cpu_ns": 10,
        "monitor_process_cpu_ns": 10 if condition == "singleton_ipc" else None,
        "combined_cpu_ns": 20 if condition == "singleton_ipc" else 10,
        "combined_cpu_core_equivalent_percent": 100.0,
        "worker_memory_before": {"vm_rss_bytes": 1, "vm_hwm_bytes": 1},
        "worker_memory_after": {"vm_rss_bytes": 1, "vm_hwm_bytes": 1},
        "worker_process_lifetime_peak_rss_bytes": 1,
        "monitor_memory_after": (
            {"vm_rss_bytes": 1, "vm_hwm_bytes": 1}
            if condition == "singleton_ipc"
            else None
        ),
        "sqlite_growth": (
            {
                "family_bytes_growth": 1,
                "allocated_page_bytes_growth": 1,
                "row_growth": {
                    "attempts": 1,
                    "audit_log": 2,
                    "used_credentials": 1,
                    "sluice_monitor_request_cache": (
                        1 if condition == "singleton_ipc" else None
                    ),
                },
                "audit_logical_payload_bytes_growth": 1,
            }
            if condition in ("durable_direct", "singleton_ipc")
            else None
        ),
        "cleanup_error": None,
        "timing_scope": g8._TIMING_SCOPE,
        "memory_scope": g8._MEMORY_SCOPE,
    }


def test_operation_value_code_rejects_boolean_integer_alias():
    measured = _measured()
    measured["operations"][0]["value_code"] = True
    with pytest.raises(ValueError, match="value|code|integer"):
        g8._validate_operation_records(
            measured["operations"], operation_count=1, condition="unmediated_handler"
        )


def test_worker_result_spec_rejects_boolean_integer_alias(monkeypatch):
    expected = _spec(operations=1)
    monkeypatch.setattr(g8, "_integrity_snapshot", lambda _spec: _honest_integrity(expected))
    aliased = dict(expected)
    aliased["operations"] = True
    with pytest.raises(ValueError, match="spec|operations|integer"):
        g8._validate_worker_result(_result(aliased), expected)


@pytest.mark.parametrize(
    "mutation",
    (
        {"worker_process_cpu_ns": -1},
        {"worker_process_lifetime_peak_rss_bytes": -1},
        {"cleanup_error": {"error_type": "Cleanup", "error_message": "failed"}},
        {"setup_or_measurement_error": {"error_type": "Setup", "error_message": "failed"}},
    ),
)
def test_successful_measured_result_rejects_forged_auxiliary_metrics(mutation):
    measured = _measured()
    measured.update(mutation)
    with pytest.raises(ValueError, match="CPU|memory|cleanup|setup|metric|status"):
        g8._validate_measured(
            measured,
            operation_count=1,
            condition="unmediated_handler",
            capture_operations=True,
        )


def test_durable_result_rejects_forged_sqlite_growth():
    measured = _measured("durable_direct")
    measured["sqlite_growth"]["family_bytes_growth"] = -999_999
    measured["sqlite_growth"]["row_growth"]["audit_log"] = -999_999
    with pytest.raises(ValueError, match="sqlite|growth|row"):
        g8._validate_measured(
            measured,
            operation_count=1,
            condition="durable_direct",
            capture_operations=True,
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"phase": True},
        {"worker_error": True},
        {"phase": "measured", "worker_error": None},
    ),
)
def test_failed_child_result_has_exact_phase_and_error_schema(monkeypatch, changes):
    expected = _spec()
    monkeypatch.setattr(g8, "_integrity_snapshot", lambda _spec: _honest_integrity(expected))
    with pytest.raises(ValueError, match="phase|worker.error|schema|status"):
        g8._validate_worker_result(_result(expected, **changes), expected)


def test_claim_eligibility_requires_retained_exact_attestation(monkeypatch):
    monkeypatch.setattr(g8, "FINAL_CLAIMS_ENABLED", True)
    profile = g8.StorageProfile(
        label="forged",
        storage_class="local-persistent",
        requested_path="/local",
        resolved_path="/local",
        device_id=1,
        mountpoint="/local",
        filesystem_type="xfs",
        mount_source="/dev/nvme0n1",
        mount_options=("rw",),
        attestation_path=None,
        attestation_sha256=None,
        attestation_canonical_json=None,
        operator_attested_local_persistence=True,
    )
    assert profile.claim_storage_eligible is False
    assert not g8.cell_claim_eligible(
        mode="final", source_clean=True, profile=profile, status="ok"
    )


def test_pinned_worker_rejects_unpinned_sitecustomize_execution(tmp_path: Path):
    component_hashes = {
        key: str(value)
        for key, value in g8._component_hashes(REPOSITORY_ROOT).items()
    }
    assert all(value != "None" for value in component_hashes.values())
    snapshot_root = tmp_path / "snapshot"
    worker_hashes = g8._build_pinned_worker_source(
        REPOSITORY_ROOT, snapshot_root, component_hashes
    )
    provenance = g8.source_provenance(REPOSITORY_ROOT)
    storage_identity = g8._observe_storage_identity(tmp_path)
    spec = {
        "schema_version": g8.WORKER_SPEC_SCHEMA,
        "run_id": "sitecustomize-reaudit",
        "block_id": "r000-tmpfs-c001",
        "condition": "unmediated_handler",
        "storage_label": "tmpfs",
        "storage_class": "tmpfs-diagnostic",
        "storage_root": str(tmp_path),
        "repetition": 0,
        "concurrency": 1,
        "operations": 1,
        "warmup_operations": 0,
        "expected_component_sha256": component_hashes,
        "expected_source_commit": provenance["commit"],
        "expected_source_dirty": provenance["dirty"],
        "source_repository_root": str(REPOSITORY_ROOT),
        "worker_source_root": str(snapshot_root),
        "expected_worker_source_sha256": worker_hashes,
        "expected_storage_identity": storage_identity,
    }
    spec_path = tmp_path / "spec.json"
    result_path = tmp_path / "result.json"
    spec_path.write_text(g8._canonical_json(spec), encoding="ascii")
    injection_root = tmp_path / "injection"
    injection_root.mkdir()
    marker = tmp_path / "UNPINNED_CODE_EXECUTED"
    (injection_root / "sitecustomize.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['G8_AUDIT_MARKER']).write_text('executed\\n')\n",
        encoding="ascii",
    )
    worker_driver = snapshot_root / g8.COMPONENT_PATHS[0]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(injection_root)
    environment["G8_AUDIT_MARKER"] = str(marker)
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(worker_driver),
                "_worker",
                "--spec",
                str(spec_path),
                "--output",
                str(result_path),
            ],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        decoded = json.loads(result_path.read_text(encoding="ascii"))
        executed = marker.exists()
    finally:
        for candidate in sorted(snapshot_root.rglob("*"), reverse=True):
            try:
                os.chmod(candidate, 0o700 if candidate.is_dir() else 0o600)
            except OSError:
                pass
        os.chmod(snapshot_root, 0o700)
    assert completed.returncode != 0 or decoded["status"] != "ok" or not executed


def _verified_worker_command(spec_path: Path, result_path: Path) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        "-c",
        g8._worker_bootstrap_source(),
        "_worker",
        "--spec",
        str(spec_path),
        "--output",
        str(result_path),
        "--spec-sha256",
        g8._sha256_file(spec_path),
    ]


def _make_snapshot_removable(snapshot_root: Path) -> None:
    for candidate in sorted(snapshot_root.rglob("*"), reverse=True):
        try:
            os.chmod(candidate, 0o700 if candidate.is_dir() else 0o600)
        except OSError:
            pass
    try:
        os.chmod(snapshot_root, 0o700)
    except OSError:
        pass


def test_verified_bootstrap_rejects_modified_driver_before_first_project_byte(
    tmp_path: Path,
):
    component_hashes = {
        key: str(value)
        for key, value in g8._component_hashes(REPOSITORY_ROOT).items()
    }
    snapshot_root = tmp_path / "startup-snapshot"
    worker_hashes = g8._build_pinned_worker_source(
        REPOSITORY_ROOT, snapshot_root, component_hashes
    )
    storage_root = tmp_path / "startup-storage"
    storage_root.mkdir()
    spec = {
        **_spec(),
        "run_id": "startup-reaudit",
        "storage_root": str(storage_root.resolve()),
        "expected_component_sha256": component_hashes,
        "expected_source_commit": "a" * 40,
        "source_repository_root": str(REPOSITORY_ROOT.resolve()),
        "worker_source_root": str(snapshot_root.resolve()),
        "expected_worker_source_sha256": worker_hashes,
        "expected_storage_identity": g8._observe_storage_identity(storage_root),
    }
    spec_path = tmp_path / "startup.spec.json"
    result_path = tmp_path / "startup.result.json"
    spec_path.write_text(g8._canonical_json(spec), encoding="ascii")
    marker = tmp_path / "MODIFIED_DRIVER_EXECUTED"
    worker_driver = snapshot_root / g8.COMPONENT_PATHS[0]
    os.chmod(worker_driver, 0o644)
    worker_driver.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='ascii')\n",
        encoding="ascii",
    )
    try:
        completed = subprocess.run(
            _verified_worker_command(spec_path, result_path),
            cwd=REPOSITORY_ROOT,
            env=g8._isolated_worker_environment(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    finally:
        _make_snapshot_removable(snapshot_root)
    assert completed.returncode != 0
    assert "component bytes disagree" in completed.stderr
    assert not marker.exists()
    assert not result_path.exists()


def test_verified_bootstrap_defeats_import_time_mutate_restore(tmp_path: Path):
    repository = tmp_path / "mutate-repository"
    for relative in g8.COMPONENT_PATHS:
        source = REPOSITORY_ROOT / relative
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    marker = tmp_path / "MUTATED_OBSERVER_EXECUTED"
    malicious_observer = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='ascii')\n"
    )
    init_path = repository / "source/artifact/sluice_v2/__init__.py"
    init_path.write_text(
        "from pathlib import Path\n"
        "_target = Path(__file__).with_name('observer.py')\n"
        "_original = _target.read_bytes()\n"
        "_target.chmod(0o644)\n"
        f"_target.write_text({malicious_observer!r}, encoding='ascii')\n"
        "try:\n"
        "    import sluice_v2.observer\n"
        "finally:\n"
        "    _target.write_bytes(_original)\n"
        "    _target.chmod(0o444)\n",
        encoding="ascii",
    )
    component_hashes = {
        key: str(value) for key, value in g8._component_hashes(repository).items()
    }
    snapshot_root = tmp_path / "mutate-snapshot"
    worker_hashes = g8._build_pinned_worker_source(
        repository, snapshot_root, component_hashes
    )
    storage_root = tmp_path / "mutate-storage"
    storage_root.mkdir()
    spec = {
        **_spec(),
        "run_id": "mutate-restore-reaudit",
        "storage_root": str(storage_root.resolve()),
        "expected_component_sha256": component_hashes,
        "expected_source_commit": "b" * 40,
        "expected_source_dirty": False,
        "source_repository_root": str(repository.resolve()),
        "worker_source_root": str(snapshot_root.resolve()),
        "expected_worker_source_sha256": worker_hashes,
        "expected_storage_identity": g8._observe_storage_identity(storage_root),
    }
    spec_path = tmp_path / "mutate.spec.json"
    result_path = tmp_path / "mutate.result.json"
    spec_path.write_text(g8._canonical_json(spec), encoding="ascii")
    try:
        completed = subprocess.run(
            _verified_worker_command(spec_path, result_path),
            cwd=repository,
            env=g8._isolated_worker_environment(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        decoded = json.loads(result_path.read_text(encoding="ascii"))
        restored_hash = g8._sha256_file(
            snapshot_root / "source/artifact/sluice_v2/observer.py"
        )
    finally:
        _make_snapshot_removable(snapshot_root)
    assert completed.returncode == 0, completed.stderr
    assert decoded["status"] == "ok"
    assert restored_hash == component_hashes[
        "source/artifact/sluice_v2/observer.py"
    ]
    assert not marker.exists()


def test_run_candidate_requires_every_repetition_to_be_claim_eligible(
    monkeypatch, tmp_path: Path
):
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    identity = {
        "resolved_path": str(storage_root.resolve()),
        "device_id": storage_root.stat().st_dev,
        "mountpoint": str(storage_root.resolve()),
        "filesystem_type": "xfs",
        "mount_source": "/dev/audit",
        "mount_options": ["rw"],
    }
    attestation_value = {
        "schema_version": g8.STORAGE_ATTESTATION_SCHEMA,
        "label": "audit-local",
        "resolved_path": identity["resolved_path"],
        "filesystem_type": "xfs",
        "hostname": g8.platform.node(),
        "device_id": identity["device_id"],
        "mountpoint": identity["mountpoint"],
        "mount_source": identity["mount_source"],
        "mount_options": identity["mount_options"],
        "node_local_verified": True,
        "persistence_verified": True,
        "verification_method": "bounded adversarial contract",
        "verified_at_utc": "2026-08-20T00:00:00+00:00",
        "verified_by": "independent-test",
    }
    attestation_canonical = g8._canonical_json(attestation_value) + "\n"
    attestation_path = tmp_path / "bounded-audit.json"
    attestation_path.write_text(attestation_canonical, encoding="ascii")
    profile = g8.StorageProfile(
        label="audit-local",
        storage_class="local-persistent",
        requested_path=str(storage_root),
        resolved_path=str(storage_root.resolve()),
        device_id=identity["device_id"],
        mountpoint=identity["mountpoint"],
        filesystem_type="xfs",
        mount_source=identity["mount_source"],
        mount_options=("rw",),
        attestation_path=str(attestation_path.resolve()),
        attestation_sha256=g8.hashlib.sha256(
            attestation_canonical.encode("ascii")
        ).hexdigest(),
        attestation_canonical_json=attestation_canonical,
        operator_attested_local_persistence=True,
    )
    monkeypatch.setattr(g8, "FINAL_CLAIMS_ENABLED", True)
    monkeypatch.setattr(g8, "MIN_P999_OPERATIONS", 1)
    monkeypatch.setattr(g8, "validate_run_parameters", lambda **_kwargs: None)
    clean = {
        "backend": "git",
        "commit": "a" * 40,
        "dirty": False,
        "status_porcelain": [],
        "trusted_for_final": True,
    }
    monkeypatch.setattr(g8, "source_provenance", lambda _root: dict(clean))
    monkeypatch.setattr(g8, "_observe_storage_identity", lambda _path: dict(identity))

    def integrity(spec):
        return {
            "component_sha256": spec["expected_component_sha256"],
            "worker_source_sha256": spec["expected_worker_source_sha256"],
            "storage_identity": spec["expected_storage_identity"],
            "source_commit": spec["expected_source_commit"],
            "source_dirty": spec["expected_source_dirty"],
            "matches_expected": True,
        }

    monkeypatch.setattr(g8, "_integrity_snapshot", integrity)

    real_run = g8.subprocess.run

    def fake_worker(command, **kwargs):
        if "_worker" not in command:
            return real_run(command, **kwargs)
        assert command[1:3] == ["-I", "-B"]
        assert kwargs["env"] == g8._isolated_worker_environment()
        assert not any(
            key.startswith(("PYTHON", "LD_", "DYLD_")) for key in kwargs["env"]
        )
        spec_path = Path(command[command.index("--spec") + 1])
        output_path = Path(command[command.index("--output") + 1])
        spec = json.loads(spec_path.read_text(encoding="ascii"))
        measured = g8.execute_condition_once(
            condition=spec["condition"],
            operation_count=spec["operations"],
            concurrency=spec["concurrency"],
            storage_root=Path(spec["storage_root"]),
            capture_operations=True,
        )
        if spec["condition"] == "singleton_ipc":
            measured["monitor_process_cpu_ns"] = None
            measured["combined_cpu_ns"] = None
            measured["combined_cpu_core_equivalent_percent"] = None
            measured["monitor_memory_after"] = None
        observed = integrity(spec)
        result = {
            "schema_version": g8.WORKER_RESULT_SCHEMA,
            "status": measured["status"],
            "phase": "measured",
            "spec": spec,
            "warmup": None,
            "measured": measured,
            "worker_error": None,
            "integrity": {"start": observed, "end": observed},
        }
        g8._atomic_json(output_path, result)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(g8.subprocess, "run", fake_worker)
    result = g8.run_benchmark(
        output_root=tmp_path / "outside-output",
        profiles=(profile,),
        mode="final",
        operations=1,
        warmup_operations=0,
        repetitions=1,
        concurrencies=(1,),
        seed=8675309,
        bootstrap_replicates=2,
        condition_timeout_seconds=60,
        repository_root=REPOSITORY_ROOT,
    )
    assert result["summary"]["failed_repetition_count"] == 0
    assert result["summary"]["eligible_persistent_repetition_count"] < 4
    assert result["summary"]["paper_claim_eligible"] is False


def test_malformed_failed_child_is_retained_as_total_failure_denominator(
    monkeypatch, tmp_path: Path
):
    profile = g8.resolve_storage_profiles(("tmpfs:tmpfs-diagnostic:/tmp",))[0]

    def integrity(spec):
        return {
            "component_sha256": spec["expected_component_sha256"],
            "worker_source_sha256": spec["expected_worker_source_sha256"],
            "storage_identity": spec["expected_storage_identity"],
            "source_commit": spec["expected_source_commit"],
            "source_dirty": spec["expected_source_dirty"],
            "matches_expected": True,
        }

    monkeypatch.setattr(g8, "_integrity_snapshot", integrity)

    real_run = g8.subprocess.run

    def malformed_worker(command, **_kwargs):
        if "_worker" not in command:
            return real_run(command, **_kwargs)
        spec_path = Path(command[command.index("--spec") + 1])
        output_path = Path(command[command.index("--output") + 1])
        spec = json.loads(spec_path.read_text(encoding="ascii"))
        observed = integrity(spec)
        result = {
            "schema_version": g8.WORKER_RESULT_SCHEMA,
            "status": "failed",
            "phase": "worker",
            "spec": spec,
            "warmup": None,
            "measured": None,
            "worker_error": True,
            "integrity": {"start": observed, "end": observed},
        }
        g8._atomic_json(output_path, result)
        return subprocess.CompletedProcess(command, 3, "", "")

    monkeypatch.setattr(g8.subprocess, "run", malformed_worker)
    result = g8.run_benchmark(
        output_root=tmp_path / "diagnostic-output",
        profiles=(profile,),
        mode="diagnostic",
        operations=2,
        warmup_operations=0,
        repetitions=1,
        concurrencies=(1,),
        seed=8675309,
        bootstrap_replicates=2,
        condition_timeout_seconds=60,
        repository_root=REPOSITORY_ROOT,
    )
    assert result["summary"]["failed_repetition_count"] == 4
    assert result["summary"]["raw_operation_count"] == 8


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), -1, 2**63])
def test_auxiliary_numbers_reject_nan_infinity_negative_and_huge(bad_value):
    measured = _measured()
    measured["worker_process_cpu_ns"] = bad_value
    with pytest.raises(ValueError, match="CPU|finite|bounded|invalid"):
        g8._validate_measured(
            measured,
            operation_count=1,
            condition="unmediated_handler",
            capture_operations=True,
        )


def test_operation_finish_rejects_bounded_integer_overflow():
    row = _measured()["operations"][0]
    row["start_offset_ns"] = g8.MAX_AUDIT_INTEGER
    row["latency_ns"] = 1
    with pytest.raises(ValueError, match="finish|bounded"):
        g8._validate_operation_records(
            [row], operation_count=1, condition="unmediated_handler", concurrency=1
        )


def test_nested_schemas_reject_extra_keys(monkeypatch):
    measured = _measured()
    measured["worker_memory_before"]["unexpected"] = 1
    with pytest.raises(ValueError, match="memory|schema"):
        g8._validate_measured(
            measured,
            operation_count=1,
            condition="unmediated_handler",
            capture_operations=True,
        )

    expected = _spec()
    monkeypatch.setattr(g8, "_integrity_snapshot", lambda _spec: _honest_integrity(expected))
    worker_error = {
        "error_type": "Audit",
        "error_message": "bad",
        "traceback": "",
        "unexpected": True,
    }
    with pytest.raises(ValueError, match="worker.error|schema"):
        g8._validate_worker_result(
            _result(expected, worker_error=worker_error), expected
        )


def _write_attestation(tmp_path: Path, *, verified_at_utc: str) -> tuple[Path, dict]:
    root = tmp_path.resolve()
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
        "verification_method": "bounded audit",
        "verified_at_utc": verified_at_utc,
        "verified_by": "auditor",
    }
    path = tmp_path / "attestation.json"
    path.write_text(g8._canonical_json(value) + "\n", encoding="ascii")
    return path, value


def test_final_parameters_reject_any_scheduled_diagnostic_profile(
    monkeypatch, tmp_path: Path
):
    attestation_path, value = _write_attestation(
        tmp_path, verified_at_utc="2026-08-20T00:00:00+00:00"
    )
    canonical = g8._canonical_json(value) + "\n"
    persistent = g8.StorageProfile(
        label=value["label"],
        storage_class="local-persistent",
        requested_path=value["resolved_path"],
        resolved_path=value["resolved_path"],
        device_id=value["device_id"],
        mountpoint=value["mountpoint"],
        filesystem_type=value["filesystem_type"],
        mount_source=value["mount_source"],
        mount_options=tuple(value["mount_options"]),
        attestation_path=str(attestation_path.resolve()),
        attestation_sha256=g8.hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        attestation_canonical_json=canonical,
        operator_attested_local_persistence=True,
    )
    diagnostic = g8.StorageProfile(
        label="tmpfs",
        storage_class="tmpfs-diagnostic",
        requested_path="/tmp",
        resolved_path="/tmp",
        device_id=1,
        mountpoint="/tmp",
        filesystem_type="tmpfs",
        mount_source="tmpfs",
        mount_options=("rw",),
        attestation_path=None,
        attestation_sha256=None,
        attestation_canonical_json=None,
        operator_attested_local_persistence=False,
    )
    monkeypatch.setattr(g8, "FINAL_CLAIMS_ENABLED", True)
    with pytest.raises(ValueError, match="every final-mode storage profile"):
        g8.validate_run_parameters(
            mode="final",
            operations=g8.MIN_P999_OPERATIONS,
            warmup_operations=1_000,
            repetitions=g8.MIN_FINAL_REPETITIONS,
            concurrencies=g8.DEFAULT_CONCURRENCIES,
            bootstrap_replicates=g8.DEFAULT_BOOTSTRAP_REPLICATES,
            profiles=(persistent, diagnostic),
            provenance={
                "backend": "git",
                "trusted_for_final": True,
                "commit": "a" * 40,
                "dirty": False,
            },
        )


def test_attestation_requires_utc_not_merely_timezone_aware(tmp_path: Path):
    path, value = _write_attestation(
        tmp_path, verified_at_utc="2026-08-20T01:00:00+01:00"
    )
    with pytest.raises(ValueError, match="UTC"):
        g8._load_attestation(
            path,
            label=value["label"],
            resolved_path=tmp_path.resolve(),
            filesystem_type=value["filesystem_type"],
            hostname=value["hostname"],
            device_id=value["device_id"],
            mountpoint=value["mountpoint"],
            mount_source=value["mount_source"],
            mount_options=value["mount_options"],
        )


def test_attestation_and_component_symlinks_are_rejected(monkeypatch, tmp_path: Path):
    attestation, value = _write_attestation(
        tmp_path, verified_at_utc="2026-08-20T00:00:00+00:00"
    )
    linked_attestation = tmp_path / "linked-attestation.json"
    linked_attestation.symlink_to(attestation)
    with pytest.raises(ValueError, match="symbolic link"):
        g8._load_attestation(
            linked_attestation,
            label=value["label"],
            resolved_path=tmp_path.resolve(),
            filesystem_type=value["filesystem_type"],
            hostname=value["hostname"],
            device_id=value["device_id"],
            mountpoint=value["mountpoint"],
            mount_source=value["mount_source"],
            mount_options=value["mount_options"],
        )

    repository = tmp_path / "repo"
    outside = tmp_path / "outside.py"
    outside.write_text("PINNED = True\n", encoding="ascii")
    relative = "source/artifact/experiments/linked.py"
    source = repository / relative
    source.parent.mkdir(parents=True)
    source.symlink_to(outside)
    monkeypatch.setattr(g8, "COMPONENT_PATHS", (relative,))
    assert g8._component_hashes(repository)[relative] is None
    with pytest.raises(RuntimeError, match="source changed"):
        g8._build_pinned_worker_source(
            repository,
            tmp_path / "snapshot",
            {relative: g8._sha256_file(outside)},
        )
    linked_snapshot = tmp_path / "linked-snapshot"
    linked_snapshot_source = linked_snapshot / relative
    linked_snapshot_source.parent.mkdir(parents=True)
    linked_snapshot_source.symlink_to(outside)
    assert g8._snapshot_component_hashes(linked_snapshot)[relative] is None


def test_worker_environment_is_finite_and_injection_free():
    environment = g8._isolated_worker_environment()
    assert environment == {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    assert not any(
        key.startswith(("PYTHON", "LD_", "DYLD_")) for key in environment
    )


def test_final_source_stability_rejects_backend_downgrade():
    start = {
        "backend": "git",
        "commit": "a" * 40,
        "dirty": False,
        "trusted_for_final": True,
        "tool_path": "/usr/bin/git",
        "tool_executable_sha256": "b" * 64,
        "tool_version": "git version audit",
    }
    end = {
        **start,
        "backend": "vendored-dulwich",
        "trusted_for_final": False,
    }
    pins = {"component": "c" * 64}
    assert not g8._source_state_stable(
        start=start,
        end=end,
        component_start=pins,
        component_end=pins,
        worker_start=pins,
        worker_end=pins,
        storage_stable=True,
        mode="final",
    )


def test_native_git_requires_tracked_hash_attestation(tmp_path: Path):
    repository = tmp_path / "repository"
    (repository / "analysis").mkdir(parents=True)
    toolchain_root = tmp_path / "toolchains"
    tool = toolchain_root / "git-2.46.0" / "bin" / "git"
    tool.parent.mkdir(parents=True)
    tool.write_text(
        "#!/usr/bin/python3\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['rev-parse', 'HEAD']:\n"
        "    print('c' * 40)\n"
        "elif args == ['status', '--porcelain=v1']:\n"
        "    pass\n"
        "elif args == ['--version']:\n"
        "    print('git version 2.46.0')\n"
        "elif args[:2] == ['ls-files', '--error-unmatch']:\n"
        "    print(args[-1])\n"
        "else:\n"
        "    raise SystemExit(2)\n",
        encoding="ascii",
    )
    tool.chmod(0o755)
    runtime_library = toolchain_root / "git-2.46.0" / "lib" / "libz.so.1"
    runtime_library.parent.mkdir(parents=True)
    runtime_library.write_bytes(b"bounded-runtime-library\n")
    manifest_path = repository / "analysis/G8_NATIVE_GIT_ATTESTATION.json"
    manifest = {
        "schema_version": g8.NATIVE_GIT_ATTESTATION_SCHEMA,
        "captured_utc": "2026-08-21T00:00:00Z",
        "purpose": "bounded authenticated native Git test",
        "git": {
            "version": "2.46.0",
            "source_url": "https://example.invalid/git.tar.xz",
            "source_sha256": "1" * 64,
            "signature_url": "https://example.invalid/git.tar.sign",
            "signature_sha256": "2" * 64,
            "kernel_checksum_manifest_url": "https://example.invalid/sha256sums.asc",
            "kernel_checksum_manifest_sha256": "3" * 64,
            "release_primary_key_fingerprint": "96E07AF25771955980DAD10020D04E5A713660A7",
            "release_signing_subkey_fingerprint": "E1F036B1FEE7221FC778ECEFB0B5E88696AFE6CB",
            "release_key_source": "https://example.invalid/release-key.asc",
            "release_key_fingerprint_source": "authenticated release documentation",
            "release_key_file_sha256": "4" * 64,
            "signature_verification": "good_signature_exact_pinned_fingerprint",
            "installations": [
                {
                    "label": "test-host",
                    "platform": "test-platform",
                    "tool_path": "${SLUICE_TOOLCHAIN_ROOT}/git-2.46.0/bin/git",
                    "tool_executable_sha256": g8._sha256_file(tool),
                    "version_output": "git version 2.46.0",
                    "build": {
                        "compiler": "test compiler",
                        "build_kernel": "test kernel",
                        "make_flags": ["NO_CURL=YesPlease"],
                    },
                    "runtime_libraries": [
                        {
                            "path": "${SLUICE_TOOLCHAIN_ROOT}/git-2.46.0/lib/libz.so.1",
                            "sha256": g8._sha256_file(runtime_library),
                        }
                    ],
                    "validated_hosts": [
                        {
                            "hostname": g8.platform.node(),
                            "head": "d" * 40,
                            "version_output": "git version 2.46.0",
                        }
                    ],
                }
            ],
        },
        "zlib": {
            "version": "1.3.2",
            "source_url": "https://example.invalid/zlib.tar.gz",
            "source_sha256": "5" * 64,
            "published_sha256_source": "https://example.invalid/zlib",
        },
        "validation": {
            "repository_fsck_strict": "pass",
            "tracked_diff_exit_code": 0,
            "staged_diff_exit_code": 0,
            "untracked_files_are_clean": True,
            "principal_run_authorized_at_capture": True,
        },
        "constraints": ["explicit path and manifest required"],
    }
    manifest_path.write_text(g8._canonical_json(manifest) + "\n", encoding="ascii")
    provenance = g8.source_provenance(
        repository,
        native_git_path=tool,
        native_git_manifest_path=manifest_path,
    )
    assert provenance["backend"] == "git"
    assert provenance["trusted_for_final"] is True
    assert provenance["dirty"] is False
    assert provenance["tool_manifest_sha256"] == g8._sha256_file(manifest_path)

    runtime_library.write_bytes(b"tampered-runtime-library\n")
    with pytest.raises(ValueError, match="runtime-library hash"):
        g8.source_provenance(
            repository,
            native_git_path=tool,
            native_git_manifest_path=manifest_path,
        )


def test_summary_bootstrap_rejects_nonfinite_values():
    with pytest.raises(ValueError, match="finite"):
        g8.bootstrap_median_interval([1.0, float("nan")], seed=1, replicates=2)


def test_summary_rejects_boolean_grouping_and_unused_bootstrap_aliases():
    with pytest.raises(ValueError, match="grouping/status"):
        g8._summary_cells(
            [
                {
                    "storage_label": "tmpfs",
                    "storage_class": "tmpfs-diagnostic",
                    "concurrency": True,
                    "condition": "unmediated_handler",
                    "status": "failed",
                    "claim_eligible": False,
                }
            ],
            bootstrap_seed=1,
            bootstrap_replicates=2,
        )
    with pytest.raises(ValueError, match="positive exact integer"):
        g8.bootstrap_median_interval([], seed=1, replicates=True)
    with pytest.raises(ValueError, match="bounded"):
        g8.summarize_latencies([2**63])


def test_output_path_symlink_is_resolved_against_repository(tmp_path: Path):
    linked = tmp_path / "linked-repository"
    linked.symlink_to(REPOSITORY_ROOT, target_is_directory=True)
    assert g8._path_is_within(linked, REPOSITORY_ROOT)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    external = tmp_path / "external.txt"
    external.write_text("outside\n", encoding="ascii")
    (bundle / "linked-evidence.txt").symlink_to(external)
    with pytest.raises(ValueError, match="symbolic links"):
        g8._write_checksums(bundle)
