"""Pure schema/bootstrap checks for the allocation-only CUDA boundary."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import experiments.diagnose_rocky_cuda_isolation as diagnostic
import experiments.stage_authenticated_runtime as stage_driver
import sluice_v2.rocky_gpu_isolation as isolation
from experiments.diagnose_rocky_cuda_isolation import (
    _load_staging_manifest,
    _validate_staging_manifest_schema,
)
from experiments.stage_authenticated_runtime import _failure_wire
from experiments.verified_inline_loader import (
    build_inline_loader_source,
    inline_loader_sha256,
)
from experiments import verified_execution_trust_anchor as trust_anchor
from sluice_v2.rocky_gpu_isolation import RockyIsolationError, RockySandboxRun
from sluice_v2.runtime_staging import (
    read_json_authenticated_with_identity,
    write_json_create_only,
)


COMMIT = "1" * 40
RUN_ID = "fdv4_schema_test"


def _valid_result() -> dict[str, object]:
    return {
        "allocated_after_bytes": 0,
        "allocated_before_bytes": 0,
        "allocated_bytes": 4096,
        "allocated_during_bytes": 4096,
        "checksum": 1024.0,
        "cuda_driver_api_version": 13000,
        "cuda_runtime": "12.4",
        "device_count": 1,
        "device_name": "Tesla V100-PCIE-32GB",
        "device_total_memory_bytes": 34072559616,
        "device_uuid": "GPU-a4cc2488-da8f-8899-4f73-1096469a850f",
        "diagnostic_only": True,
        "forbidden_modules_absent": True,
        "model_loaded": False,
        "tokenizer_loaded": False,
        "torch_version": "2.5.1+cu124",
        "vllm_imported": False,
    }


def _identity() -> dict[str, int]:
    return {"device": 2050, "gid": 200, "inode": 1234, "mode": 0o755, "uid": 8146}


def _json_identity() -> dict[str, int]:
    return {"device": 2050, "gid": 200, "inode": 9001, "mode": 0o600, "nlink": 1, "size": 101, "uid": 8146}


def _file_identity(inode: int) -> dict[str, int]:
    return {"device": 2050, "gid": 200, "inode": inode, "mode": 0o644, "nlink": 1, "size": 10, "uid": 8146}


def _verified_start() -> dict[str, object]:
    modules = (
        ("sluice_v2.rocky_gpu_isolation", "/artifact/sluice_v2/rocky_gpu_isolation.py", "b" * 64),
        ("sluice_v2.runtime_staging", "/artifact/sluice_v2/runtime_staging.py", "c" * 64),
        ("experiments.stage_authenticated_runtime", "/artifact/experiments/stage_authenticated_runtime.py", "d" * 64),
    )
    return {
        "bootstrap": {"identity": _file_identity(8001), "path": "/artifact/experiments/verified_execution_bootstrap.py", "sha256": "e" * 64},
        "closure": [
            {"identity": _file_identity(8100 + index), "module": module, "path": path, "sha256": digest}
            for index, (module, path, digest) in enumerate(modules)
        ],
        "closure_manifest": {"identity": _file_identity(8201), "path": "/evidence/closure.json", "sha256": "f" * 64},
        "inline_loader_sha256": "9" * 64,
        "interpreter": {
            "identity": _file_identity(8301),
            "path": "/usr/bin/python3",
            "procfs_mount": {
                "filesystem": "proc",
                "mount_id": 25,
                "mount_options": ["nodev", "noexec", "nosuid", "rw"],
                "mountpoint": "/proc",
                "root": "/",
                "source": "proc",
                "super_options": ["rw"],
            },
            "sha256": "8" * 64,
        },
        "pycache": {"empty": True, "identity": _identity(), "path": "/local/pycache/fdv4_schema_test"},
        "run_id": RUN_ID,
        "source_commit": COMMIT,
    }


def _verified_execution() -> dict[str, object]:
    start = _verified_start()
    return {"end": deepcopy(start), "equal": True, "start": start}


def _valid_inventory() -> dict[str, object]:
    return {
        "directories": 3,
        "inventory_sha256": "5" * 64,
        "mode_counts": {"D:0755": 3, "F:0644": 2},
        "regular_bytes": 32,
        "regular_files": 2,
        "symlinks": 1,
    }


def _runtime_audit() -> dict[str, object]:
    return {
        "execution_sha256": "7" * 64,
        "inventory": _valid_inventory(),
        "root_identity": _identity(),
        "timestamp_sha256": "6" * 64,
        "tree_sha256": "a" * 64,
    }


def _valid_staging_manifest() -> dict[str, object]:
    inventory = _valid_inventory()
    source_descriptor = {"filesystem_magic": "00006969", "fsid": [11, 12], "mount_id": 31, "statvfs_fsid": 13}
    destination_descriptor = {"filesystem_magic": "58465342", "fsid": [21, 22], "mount_id": 32, "statvfs_fsid": 23}
    source_mount = {"filesystem": "nfs4", "mount_id": 31, "mount_options": ["rw"], "mountpoint": "/u", "source": "server:/u", "super_options": ["rw"]}
    destination_mount = {"filesystem": "xfs", "mount_id": 32, "mount_options": ["rw"], "mountpoint": "/local", "source": "/dev/sda2", "super_options": ["rw"]}
    return {
        "atomic_rename_noreplace": True,
        "boundary": dict(stage_driver.BOUNDARY),
        "completion_path": "/evidence/staging.json.complete.json",
        "copy_counts": {key: inventory[key] for key in ("directories", "regular_bytes", "regular_files", "symlinks")},
        "destination_base": "/local/runtime",
        "destination_descriptor_filesystem_after": deepcopy(destination_descriptor),
        "destination_descriptor_filesystem_before": deepcopy(destination_descriptor),
        "destination_mount_after": deepcopy(destination_mount),
        "destination_mount_before": deepcopy(destination_mount),
        "failure_path": "/evidence/staging.json.failure.json",
        "finished_utc": "2026-08-21T06:00:01.000000Z",
        "hostname": "node001",
        "label": "qwnccr",
        "manifest_path": "/evidence/staging.json",
        "protocol_id": stage_driver.PROTOCOL_ID,
        "published_identity": _identity(),
        "published_path": "/local/runtime/qwnccr-sha256-" + "a" * 64,
        "reused_existing": False,
        "run_id": RUN_ID,
        "schema_version": 1,
        "source_commit": COMMIT,
        "source_descriptor_filesystem_after": deepcopy(source_descriptor),
        "source_descriptor_filesystem_before": deepcopy(source_descriptor),
        "source_execution_sha256": "7" * 64,
        "source_identity_after": _identity(),
        "source_identity_before": _identity(),
        "source_inventory": inventory,
        "source_mount_after": deepcopy(source_mount),
        "source_mount_before": deepcopy(source_mount),
        "source_path": "/u/cluster-login/runtime",
        "source_sha256": "a" * 64,
        "source_timestamp_sha256": "6" * 64,
        "source_timestamps_preserved": True,
        "source_treated_read_only": True,
        "started_utc": "2026-08-21T06:00:00.000000Z",
        "status": "published",
        "verified_execution": _verified_execution(),
    }


def _run_with_result(monkeypatch: pytest.MonkeyPatch, result: dict[str, object]):
    run = object.__new__(RockySandboxRun)
    run._closed = False
    run._channel = object()
    run.config = type(
        "SyntheticConfig",
        (),
        {"workload_environment": {"CUDA_VISIBLE_DEVICES": "0"}},
    )()
    monkeypatch.setattr(isolation, "send_packet", lambda channel, packet: None)
    monkeypatch.setattr(isolation, "recv_packet", lambda channel: {"result": result, "type": "cuda_allocation_result"})
    return run.cuda_allocation_diagnostic()


def test_allocation_result_requires_uuid_driver_memory_and_explicit_free(monkeypatch):
    result = _run_with_result(monkeypatch, _valid_result())
    assert result["device_uuid"].startswith("GPU-")
    assert result["allocated_after_bytes"] == result["allocated_before_bytes"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("model_loaded", True, "boundary"),
        ("tokenizer_loaded", True, "boundary"),
        ("vllm_imported", True, "boundary"),
        ("forbidden_modules_absent", False, "boundary"),
        ("allocated_after_bytes", 4096, "allocation release"),
        ("allocated_during_bytes", 2048, "allocation release"),
        ("device_uuid", "not-a-uuid", "device identity"),
        ("device_total_memory_bytes", 0, "device identity"),
        ("cuda_driver_api_version", 0, "device identity"),
        ("allocated_bytes", 4096.0, "allocation evidence"),
        ("checksum", 1024, "allocation evidence"),
        ("allocated_before_bytes", -4096, "allocation release"),
        ("allocated_during_bytes", True, "allocation release"),
        ("device_count", 1.0, "device identity"),
        ("device_count", -1, "device identity"),
        ("cuda_runtime", 12.4, "device identity"),
        ("cuda_runtime", "12", "device identity"),
        ("torch_version", 2.5, "device identity"),
        ("torch_version", "", "device identity"),
    ),
)
def test_allocation_result_fails_closed_on_boundary_or_identity_drift(monkeypatch, field, value, message):
    result = deepcopy(_valid_result())
    result[field] = value
    with pytest.raises(RockyIsolationError, match=message):
        _run_with_result(monkeypatch, result)


def test_cuda_runtime_version_parser_is_strict():
    assert isolation._cuda_runtime_version_number("12.4") == 12040
    with pytest.raises(RockyIsolationError, match="noncanonical"):
        isolation._cuda_runtime_version_number("12.4.1")


@pytest.mark.parametrize("mount_id", (True, 31.0, 0, -1, "31"))
def test_staging_mount_id_requires_an_exact_positive_integer(
    mount_id: object,
) -> None:
    mount = deepcopy(_valid_staging_manifest()["source_mount_before"])
    mount["mount_id"] = mount_id
    with pytest.raises(ValueError, match="mount_id"):
        diagnostic._mount(mount, "source_mount", frozenset({"nfs", "nfs4"}))


def test_staging_manifest_exact_schema_accepts_frozen_wire():
    wire = _valid_staging_manifest()
    assert _validate_staging_manifest_schema(
        wire,
        manifest_path=Path(wire["manifest_path"]),
        runtime_root=Path(wire["published_path"]),
        runtime_audit=_runtime_audit(),
        run_id=RUN_ID,
        source_commit=COMMIT,
    ) is wire


def test_staging_manifest_embedded_paths_bind_the_authenticated_opened_path(
    tmp_path: Path,
) -> None:
    actual_path = tmp_path / "authenticated-staging.json"
    wire = _valid_staging_manifest()
    runtime_root = Path(wire["published_path"])
    write_json_create_only(actual_path, wire)
    with pytest.raises(ValueError, match="authenticated manifest"):
        _load_staging_manifest(
            actual_path,
            runtime_root=runtime_root,
            runtime_audit=_runtime_audit(),
            run_id=RUN_ID,
            source_commit=COMMIT,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "top_extra",
        "nested_extra",
        "bool_as_int",
        "run_id",
        "mount_id",
        "procfs_extra",
        "procfs_bool",
        "procfs_filesystem",
        "float_mount_id",
        "inventory_runtime_drift",
        "inventory_mode_count_drift",
        "verified_end_numeric_alias",
        "verified_end_bool_alias",
    ),
)
def test_staging_manifest_exact_schema_rejects_aliases_or_cross_binding(mutation: str):
    wire = _valid_staging_manifest()
    if mutation == "top_extra":
        wire["unexpected"] = False
    elif mutation == "nested_extra":
        wire["boundary"]["unexpected"] = False
    elif mutation == "bool_as_int":
        wire["copy_counts"]["regular_files"] = True
        wire["source_inventory"]["regular_files"] = True
    elif mutation == "run_id":
        wire["run_id"] = "other_run_id"
    elif mutation == "mount_id":
        wire["source_mount_after"]["mount_id"] = 99
    elif mutation == "procfs_extra":
        wire["verified_execution"]["start"]["interpreter"]["procfs_mount"]["extra"] = False
        wire["verified_execution"]["end"] = deepcopy(
            wire["verified_execution"]["start"]
        )
    elif mutation == "procfs_bool":
        wire["verified_execution"]["start"]["interpreter"]["procfs_mount"]["mount_id"] = True
        wire["verified_execution"]["end"] = deepcopy(
            wire["verified_execution"]["start"]
        )
    elif mutation == "procfs_filesystem":
        wire["verified_execution"]["start"]["interpreter"]["procfs_mount"]["filesystem"] = "sysfs"
        wire["verified_execution"]["end"] = deepcopy(
            wire["verified_execution"]["start"]
        )
    elif mutation == "float_mount_id":
        wire["source_mount_before"]["mount_id"] = 31.0
        wire["source_mount_after"]["mount_id"] = 31.0
    elif mutation == "inventory_runtime_drift":
        wire["source_inventory"]["regular_bytes"] = 33
        wire["copy_counts"]["regular_bytes"] = 33
    elif mutation == "inventory_mode_count_drift":
        wire["source_inventory"]["mode_counts"]["D:0755"] = 4
    elif mutation == "verified_end_numeric_alias":
        wire["verified_execution"]["end"]["bootstrap"]["identity"]["size"] = 10.0
    else:
        wire["verified_execution"]["end"]["bootstrap"]["identity"]["nlink"] = True
    with pytest.raises(ValueError):
        _validate_staging_manifest_schema(
            wire,
            manifest_path=Path(wire["manifest_path"]),
            runtime_root=Path(wire["published_path"]),
            runtime_audit=_runtime_audit(),
            run_id=RUN_ID,
            source_commit=COMMIT,
        )


def _runtime_binding(wire: dict[str, object]) -> dict[str, object]:
    return {
        "destination_base": wire["destination_base"],
        "execution_sha256": wire["source_execution_sha256"],
        "published_identity": wire["published_identity"],
        "published_path": wire["published_path"],
        "source_identity": wire["source_identity_after"],
        "source_path": wire["source_path"],
        "timestamp_sha256": wire["source_timestamp_sha256"],
        "tree_sha256": wire["source_sha256"],
    }


def _write_staging_bundle(tmp_path: Path, *, completion: bool, failure: bool, invalid_manifest_identity: bool = False, completion_mutation: str | None = None) -> tuple[Path, Path]:
    manifest_path = tmp_path / "staging.json"
    runtime_root = tmp_path / "runtime" / ("qwnccr-sha256-" + "a" * 64)
    wire = _valid_staging_manifest()
    wire.update({
        "completion_path": str(manifest_path) + ".complete.json",
        "destination_base": str(runtime_root.parent),
        "failure_path": str(manifest_path) + ".failure.json",
        "manifest_path": str(manifest_path),
        "published_path": str(runtime_root),
    })
    manifest_sha256 = write_json_create_only(manifest_path, wire)
    _, observed_sha256, manifest_identity = read_json_authenticated_with_identity(manifest_path)
    assert observed_sha256 == manifest_sha256
    if completion:
        if invalid_manifest_identity:
            manifest_identity = dict(manifest_identity)
            manifest_identity["inode"] += 1
        complete_wire = {
            "failure_path": wire["failure_path"],
            "manifest_identity": manifest_identity,
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "process_exit_status": 0,
            "protocol_id": wire["protocol_id"],
            "run_id": RUN_ID,
            "runtime": _runtime_binding(wire),
            "source_commit": COMMIT,
            "status": "committed",
            "verified_execution_sha256": hashlib.sha256((json.dumps(wire["verified_execution"], allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")).hexdigest(),
        }
        if completion_mutation == "extra":
            complete_wire["unexpected"] = False
        elif completion_mutation == "bool_alias":
            complete_wire["run_id"] = True
        elif completion_mutation == "bool_exit":
            complete_wire["process_exit_status"] = False
        write_json_create_only(Path(wire["completion_path"]), complete_wire)
    if failure:
        failure_wire = _failure_wire(
            bootstrap_end=deepcopy(wire["verified_execution"]["end"]),
            bootstrap_equal=True,
            bootstrap_finalize_error=None,
            bootstrap_start=deepcopy(wire["verified_execution"]["start"]),
            completion_path=wire["completion_path"],
            error=RuntimeError("synthetic"),
            failure_path=wire["failure_path"],
            manifest_binding={"identity": manifest_identity, "published": True, "sha256": manifest_sha256, "valid": True},
            manifest_path=str(manifest_path),
            phase="completion_publication",
            run_id=RUN_ID,
            runtime=_runtime_binding(wire),
            source_commit=COMMIT,
        )
        write_json_create_only(Path(wire["failure_path"]), failure_wire)
    return manifest_path, runtime_root


def _load(path: Path, root: Path):
    return _load_staging_manifest(path, runtime_root=root, runtime_audit=_runtime_audit(), run_id=RUN_ID, source_commit=COMMIT)


def test_staging_manifest_requires_matching_completion_record(tmp_path: Path):
    manifest_path, runtime_root = _write_staging_bundle(tmp_path, completion=True, failure=False)
    wire, manifest_sha256, completion_sha256 = _load(manifest_path, runtime_root)
    assert wire["run_id"] == RUN_ID
    assert len(manifest_sha256) == len(completion_sha256) == 64


def test_staging_manifest_without_completion_is_unclaimable(tmp_path: Path):
    manifest_path, runtime_root = _write_staging_bundle(tmp_path, completion=False, failure=False)
    with pytest.raises(FileNotFoundError):
        _load(manifest_path, runtime_root)


def test_staging_failure_sidecar_overrides_success_and_completion(tmp_path: Path):
    manifest_path, runtime_root = _write_staging_bundle(tmp_path, completion=True, failure=True)
    with pytest.raises(ValueError, match="failure"):
        _load(manifest_path, runtime_root)


def test_staging_completion_binds_exact_manifest_inode(tmp_path: Path):
    manifest_path, runtime_root = _write_staging_bundle(tmp_path, completion=True, failure=False, invalid_manifest_identity=True)
    with pytest.raises(ValueError, match="completion identity"):
        _load(manifest_path, runtime_root)


@pytest.mark.parametrize("mutation", ("extra", "bool_alias", "bool_exit"))
def test_staging_completion_rejects_extra_keys_and_bool_aliases(tmp_path: Path, mutation: str):
    manifest_path, runtime_root = _write_staging_bundle(tmp_path, completion=True, failure=False, completion_mutation=mutation)
    with pytest.raises(ValueError):
        _load(manifest_path, runtime_root)


def test_staging_failure_appearing_between_bundle_reads_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest_path, runtime_root = _write_staging_bundle(tmp_path, completion=True, failure=False)
    diagnostic._ensure_dependencies()
    original = diagnostic.read_json_authenticated_with_identity
    injected = False

    def inject_failure(path: Path):
        nonlocal injected
        result = original(path)
        if Path(path) == manifest_path and not injected:
            injected = True
            wire = result[0]
            failure_wire = _failure_wire(
                bootstrap_end=deepcopy(wire["verified_execution"]["end"]),
                bootstrap_equal=True,
                bootstrap_finalize_error=None,
                bootstrap_start=deepcopy(wire["verified_execution"]["start"]),
                completion_path=wire["completion_path"],
                error=RuntimeError("injected"),
                failure_path=wire["failure_path"],
                manifest_binding={"identity": result[2], "published": True, "sha256": result[1], "valid": True},
                manifest_path=str(manifest_path),
                phase="completion_publication",
                run_id=RUN_ID,
                runtime=_runtime_binding(wire),
                source_commit=COMMIT,
            )
            write_json_create_only(Path(wire["failure_path"]), failure_wire)
        return result

    monkeypatch.setattr(
        sys.modules["sluice_v2.runtime_staging"],
        "read_json_authenticated_with_identity",
        inject_failure,
    )
    with pytest.raises(ValueError, match="failure"):
        _load(manifest_path, runtime_root)


def test_stage_failure_evidence_exact_types_and_exit_status() -> None:
    start = _verified_start()
    wire = _failure_wire(
        bootstrap_end=deepcopy(start), bootstrap_equal=True, bootstrap_finalize_error=None,
        bootstrap_start=start, completion_path="/evidence/staging.complete.json",
        error=RuntimeError("synthetic"), failure_path="/evidence/staging.failure.json",
        manifest_binding={"identity": None, "published": False, "sha256": None, "valid": False},
        manifest_path="/evidence/staging", phase="preflight", run_id=RUN_ID,
        runtime={key: None for key in diagnostic._RUNTIME_BINDING_KEYS}, source_commit=COMMIT,
    )
    assert type(wire["process_exit_status"]) is int and wire["process_exit_status"] == 1
    assert wire["run_id"] == RUN_ID


@pytest.mark.parametrize("alias", (True, 1.0))
def test_staging_failure_rejects_process_exit_type_alias(alias: object) -> None:
    start = _verified_start()
    wire = _failure_wire(
        bootstrap_end=deepcopy(start),
        bootstrap_equal=True,
        bootstrap_finalize_error=None,
        bootstrap_start=start,
        completion_path="/evidence/staging.complete.json",
        error=RuntimeError("synthetic"),
        failure_path="/evidence/staging.failure.json",
        manifest_binding={
            "identity": None,
            "published": False,
            "sha256": None,
            "valid": False,
        },
        manifest_path="/evidence/staging",
        phase="preflight",
        run_id=RUN_ID,
        runtime={key: None for key in diagnostic._RUNTIME_BINDING_KEYS},
        source_commit=COMMIT,
    )
    wire["process_exit_status"] = alias
    with pytest.raises(ValueError, match="binding"):
        diagnostic._validate_failure_record(
            wire,
            failure_path=Path(wire["failure_path"]),
            manifest_path=Path(wire["manifest_path"]),
            run_id=RUN_ID,
            source_commit=COMMIT,
        )


def test_failure_binding_hashes_invalid_published_manifest_from_same_fd(tmp_path: Path) -> None:
    manifest = tmp_path / "staging.json"
    payload = b'{"status":"published"}\n'
    manifest.write_bytes(payload)
    manifest.chmod(0o644)
    binding = stage_driver._published_manifest_binding(manifest)
    assert binding["published"] is True
    assert binding["valid"] is False
    assert binding["sha256"] == hashlib.sha256(payload).hexdigest()
    assert binding["identity"]["inode"] == manifest.stat(follow_symlinks=False).st_ino


def test_stage_completion_broken_pipe_is_success_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "staging.json"
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    start = _verified_start()
    monkeypatch.setattr(stage_driver, "VERIFIED_BOOTSTRAP_START", start, raising=False)
    monkeypatch.setattr(stage_driver, "VERIFIED_BOOTSTRAP_FINALIZE", lambda: {"end": deepcopy(start), "equal": True, "start": start}, raising=False)
    result = _valid_staging_manifest()
    for key in ("boundary", "completion_path", "failure_path", "manifest_path", "run_id", "status", "verified_execution"):
        result.pop(key)
    monkeypatch.setattr(isolation.sys.modules["sluice_v2.runtime_staging"], "stage_authenticated_runtime", lambda **_kwargs: deepcopy(result))
    monkeypatch.setattr(sys, "argv", ["stage", "--source", str(source), "--destination-base", str(destination), "--manifest-output", str(manifest), "--run-id", RUN_ID, "--source-commit", COMMIT])
    monkeypatch.setattr("builtins.print", lambda *_args, **_kwargs: (_ for _ in ()).throw(BrokenPipeError()))
    assert stage_driver.main() == 0
    assert Path(str(manifest) + ".complete.json").exists()
    assert not Path(str(manifest) + ".failure.json").exists()


@pytest.mark.parametrize("mutation", ("numeric_alias", "run_id_drift"))
def test_stage_rejects_verified_execution_end_alias_or_record_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    manifest = tmp_path / "staging.json"
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    start = _verified_start()
    end = deepcopy(start)
    if mutation == "numeric_alias":
        end["bootstrap"]["identity"]["nlink"] = True
    else:
        end["run_id"] = "different_run_id"
    monkeypatch.setattr(
        stage_driver, "VERIFIED_BOOTSTRAP_START", start, raising=False
    )
    monkeypatch.setattr(
        stage_driver,
        "VERIFIED_BOOTSTRAP_FINALIZE",
        lambda: {"end": end, "equal": True, "start": start},
        raising=False,
    )
    result = _valid_staging_manifest()
    for key in (
        "boundary",
        "completion_path",
        "failure_path",
        "manifest_path",
        "run_id",
        "status",
        "verified_execution",
    ):
        result.pop(key)
    monkeypatch.setattr(
        isolation.sys.modules["sluice_v2.runtime_staging"],
        "stage_authenticated_runtime",
        lambda **_kwargs: deepcopy(result),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "stage",
            "--source",
            str(source),
            "--destination-base",
            str(destination),
            "--manifest-output",
            str(manifest),
            "--run-id",
            RUN_ID,
            "--source-commit",
            COMMIT,
        ],
    )
    assert stage_driver.main() == 1
    assert not manifest.exists()
    assert Path(str(manifest) + ".failure.json").exists()


@pytest.mark.parametrize("mutation", ("numeric_alias", "run_id_drift"))
def test_diagnostic_finalize_validates_the_actual_end_record(
    mutation: str,
) -> None:
    start = _verified_start()
    end = deepcopy(start)
    if mutation == "numeric_alias":
        end["bootstrap"]["identity"]["size"] = 10.0
    else:
        end["run_id"] = "different_run_id"
    with pytest.raises(ValueError, match="drift|binding|start/end"):
        diagnostic._validated_bootstrap_finalize(
            {"end": end, "equal": True, "start": start},
            bootstrap_start=start,
            run_id=RUN_ID,
            source_commit=COMMIT,
        )


def test_exact_completion_publication_error_converges_to_success(
    tmp_path: Path,
) -> None:
    completion = tmp_path / "completion.json"
    wire = {
        "process_exit_status": 0,
        "run_id": RUN_ID,
        "status": "committed",
    }

    class PublishedThenRaised:
        @staticmethod
        def write_json_create_only(path: Path, value: dict[str, object]) -> str:
            write_json_create_only(path, value)
            raise RuntimeError("synthetic post-publication failure")

        read_json_authenticated_with_identity = staticmethod(
            read_json_authenticated_with_identity
        )

    observed = stage_driver._publish_completion_terminal(
        PublishedThenRaised, completion, wire
    )
    assert observed == hashlib.sha256(
        (json.dumps(wire, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    ).hexdigest()


def test_exact_diagnostic_output_publication_error_converges_to_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diagnostic._ensure_dependencies()
    output = tmp_path / "diagnostic.json"
    wire = {"model_loaded": False, "run_id": RUN_ID, "status": "passed"}

    def publish_then_raise(path: Path, value: dict[str, object]) -> str:
        write_json_create_only(path, value)
        raise RuntimeError("synthetic post-publication failure")

    monkeypatch.setattr(diagnostic, "write_json_create_only", publish_then_raise)
    observed = diagnostic._write_atomic_new(output, wire)
    assert observed == hashlib.sha256(
        (json.dumps(wire, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    ).hexdigest()


def _bootstrap_fixture(tmp_path: Path) -> tuple[str, list[str], Path, Path]:
    artifact = tmp_path / "artifact"
    (artifact / "sluice_v2").mkdir(parents=True)
    (artifact / "experiments").mkdir()
    module_records = []
    for module, relative, payload in (
        ("sluice_v2.rocky_gpu_isolation", "sluice_v2/rocky_gpu_isolation.py", b"VALUE = 1\n"),
        ("sluice_v2.runtime_staging", "sluice_v2/runtime_staging.py", b"VALUE = 2\n"),
        ("experiments.stage_authenticated_runtime", "experiments/stage_authenticated_runtime.py", b"import os,sys\ndef main():\n VERIFIED_BOOTSTRAP_FINALIZE()\n fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,b'authenticated');os.close(fd);return 0\n"),
    ):
        path = artifact / relative
        path.write_bytes(payload)
        module_records.append({"module": module, "path": relative, "sha256": hashlib.sha256(payload).hexdigest()})
    bootstrap = Path(__file__).parents[2] / "experiments" / "verified_execution_bootstrap.py"
    bootstrap_sha = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    loader = build_inline_loader_source(bootstrap_sha)
    loader_sha = inline_loader_sha256(loader)
    manifest = tmp_path / "closure.json"
    manifest_wire = {"artifact_root": str(artifact), "entry_module": "experiments.stage_authenticated_runtime", "inline_loader_sha256": loader_sha, "modules": module_records, "run_id": "fdv4_bootstrap_test", "schema_version": 1, "source_commit": COMMIT}
    manifest.write_bytes((json.dumps(manifest_wire, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii"))
    marker = tmp_path / "authenticated.marker"
    argv = [str(bootstrap), str(manifest), hashlib.sha256(manifest.read_bytes()).hexdigest(), loader_sha, "fdv4_bootstrap_test", COMMIT, str(marker)]
    return loader, argv, marker, artifact / "experiments" / "stage_authenticated_runtime.py"


def _run_bootstrap(tmp_path: Path, loader: str, argv: list[str], *, preseed: bool = False) -> subprocess.CompletedProcess[bytes]:
    prefix = tmp_path / ("pycache-preseed" if preseed else "pycache-empty")
    prefix.mkdir(mode=0o700)
    prefix.chmod(0o700)
    if preseed:
        (prefix / "hostile.pyc").write_bytes(b"not-bytecode")
    hostile = tmp_path / "hostile-pythonpath"
    hostile.mkdir()
    hostile_marker = tmp_path / "sitecustomize.marker"
    (hostile / "sitecustomize.py").write_text(f"open({str(hostile_marker)!r},'w').write('executed')\n", encoding="ascii")
    completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={prefix}", "-c", loader, *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"HOME": str(tmp_path), "PYTHONPATH": str(hostile)}, timeout=30.0)
    assert not hostile_marker.exists()
    return completed


@pytest.mark.skipif(sys.platform != "linux", reason="verified bootstrap binds /proc/self/exe")
def test_verified_inline_loader_executes_only_authenticated_closure_under_isolated_python(tmp_path: Path):
    loader, argv, marker, _entry = _bootstrap_fixture(tmp_path)
    completed = _run_bootstrap(tmp_path, loader, argv)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert marker.read_bytes() == b"authenticated"


def test_verified_inline_loader_uses_preimport_literal_seek_whence() -> None:
    loader = (
        Path(__file__).parents[2]
        / "experiments"
        / "verified_inline_loader_v1.txt"
    ).read_text(encoding="ascii")
    assert "os.lseek(fd,0,0)" in loader
    assert "SEEK_SET" not in loader


@pytest.mark.skipif(sys.platform != "linux", reason="verified bootstrap binds /proc/self/exe")
def test_verified_inline_loader_rejects_preseeded_external_pycache(tmp_path: Path):
    loader, argv, marker, _entry = _bootstrap_fixture(tmp_path)
    completed = _run_bootstrap(tmp_path, loader, argv, preseed=True)
    assert completed.returncode != 0
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="verified bootstrap binds /proc/self/exe")
def test_verified_inline_loader_mutate_restore_never_executes_mutated_entry(tmp_path: Path):
    loader, argv, marker, entry = _bootstrap_fixture(tmp_path)
    original = entry.read_bytes()
    hostile_marker = tmp_path / "mutated.marker"
    entry.write_text(f"open({str(hostile_marker)!r},'w').write('bad')\n", encoding="ascii")
    entry.write_bytes(original)
    completed = _run_bootstrap(tmp_path, loader, argv)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert marker.exists() and not hostile_marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="verified bootstrap binds /proc/self/exe")
def test_proc_magic_link_exception_does_not_allow_ordinary_manifest_symlink(
    tmp_path: Path,
) -> None:
    loader, argv, marker, _entry = _bootstrap_fixture(tmp_path)
    manifest = Path(argv[1])
    alias = tmp_path / "closure-symlink.json"
    alias.symlink_to(manifest)
    argv[1] = str(alias)
    completed = _run_bootstrap(tmp_path, loader, argv)
    assert completed.returncode != 0
    assert not marker.exists()


def test_direct_stage_entry_fails_before_operational_work(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delattr(stage_driver, "VERIFIED_BOOTSTRAP_START", raising=False)
    monkeypatch.delattr(stage_driver, "VERIFIED_BOOTSTRAP_FINALIZE", raising=False)
    with pytest.raises(RuntimeError, match="verified bootstrap"):
        stage_driver.main()


def test_independent_hard_coded_trust_anchor_matches_reviewed_literal() -> None:
    artifact_root = Path(__file__).parents[2]
    observed = trust_anchor.verify_frozen_anchor(artifact_root)
    assert observed == {
        "bootstrap_sha256": trust_anchor.EXPECTED_BOOTSTRAP_SHA256,
        "inline_loader_bytes": trust_anchor.EXPECTED_INLINE_LOADER_BYTES,
        "inline_loader_sha256": trust_anchor.EXPECTED_INLINE_LOADER_SHA256,
        "source_commit": trust_anchor.EXPECTED_SOURCE_COMMIT,
    }
    literal = (
        artifact_root / "experiments" / "verified_inline_loader_v1.txt"
    ).read_text(encoding="ascii")
    assert literal == build_inline_loader_source(
        trust_anchor.EXPECTED_BOOTSTRAP_SHA256
    )
    assert inline_loader_sha256(literal) == trust_anchor.EXPECTED_INLINE_LOADER_SHA256


def test_independent_trust_anchor_rejects_unreviewed_execution_hash() -> None:
    artifact_root = Path(__file__).parents[2]
    start = _verified_start()
    start["bootstrap"]["path"] = str(
        artifact_root / "experiments" / "verified_execution_bootstrap.py"
    )
    start["bootstrap"]["sha256"] = trust_anchor.EXPECTED_BOOTSTRAP_SHA256
    start["inline_loader_sha256"] = trust_anchor.EXPECTED_INLINE_LOADER_SHA256
    start["source_commit"] = trust_anchor.EXPECTED_SOURCE_COMMIT
    for item, module in zip(
        start["closure"],
        trust_anchor.ENTRY_CLOSURES["experiments.stage_authenticated_runtime"],
        strict=True,
    ):
        relative, digest = trust_anchor.EXPECTED_MODULES[module]
        item.update(
            {
                "module": module,
                "path": str(artifact_root / relative),
                "sha256": digest,
            }
        )
    verified = {"end": deepcopy(start), "equal": True, "start": start}
    trust_anchor.verify_execution_record(
        verified,
        artifact_root=artifact_root,
        entry_module="experiments.stage_authenticated_runtime",
        run_id=RUN_ID,
    )
    for field, alias in (("nlink", True), ("size", 10.0)):
        aliased_end = deepcopy(verified)
        aliased_end["end"]["bootstrap"]["identity"][field] = alias
        with pytest.raises(trust_anchor.TrustAnchorError, match="start/end"):
            trust_anchor.verify_execution_record(
                aliased_end,
                artifact_root=artifact_root,
                entry_module="experiments.stage_authenticated_runtime",
                run_id=RUN_ID,
            )
    verified["end"]["inline_loader_sha256"] = "0" * 64
    verified["start"]["inline_loader_sha256"] = "0" * 64
    with pytest.raises(trust_anchor.TrustAnchorError, match="trust-anchor"):
        trust_anchor.verify_execution_record(
            verified,
            artifact_root=artifact_root,
            entry_module="experiments.stage_authenticated_runtime",
            run_id=RUN_ID,
        )
