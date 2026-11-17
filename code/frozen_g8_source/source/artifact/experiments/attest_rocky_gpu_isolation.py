#!/usr/bin/env python3
"""Emit one diagnostic-only Rocky GPU isolation attestation.

This driver never runs a model or benchmark.  It creates three tiny public
bind roots and five private canaries, launches the strict backend, closes it,
and writes only the public start/final attestations plus source provenance.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from sluice_v2.rocky_gpu_isolation import (
    AuthenticatedBind,
    GPUDevice,
    ProtectedHostPaths,
    RockyGPUIsolationConfig,
    canonical_config_sha256,
    launch_rocky_gpu_isolation,
    sha256_file,
    sha256_tree,
)


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SOURCE = ARTIFACT_ROOT / "sluice_v2" / "rocky_gpu_isolation.py"
CONTRACT_SOURCE = ARTIFACT_ROOT / "sluice_v2" / "tests" / "test_v24_rocky_gpu_isolation.py"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _write_atomic_new(path: Path, wire: dict[str, object]) -> None:
    path = path.resolve(strict=False)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to replace existing evidence: {path}")
    encoded = (
        json.dumps(
            wire,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
        0o600,
    )
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _interpreter_sha256() -> str:
    return sha256_file(Path(os.readlink("/proc/self/exe")))


def _make_config(work: Path) -> RockyGPUIsolationConfig:
    directories = {name: work / name for name in ("runtime", "source", "cache", "private", "home")}
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    for name in ("runtime", "source", "cache"):
        (directories[name] / f"{name}.probe").write_bytes(f"public-{name}".encode("ascii"))
    protected = {}
    for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
        path = directories["private"] / name
        path.write_bytes(f"private-{name}".encode("ascii"))
        path.chmod(0o600)
        protected[name] = path
    shared_home = directories["home"] / "private-home-canary"
    shared_home.write_bytes(b"private-home")
    shared_home.chmod(0o600)
    binds = tuple(
        AuthenticatedBind(
            label="model_source" if name == "source" else ("model_cache" if name == "cache" else name),
            category="model_source" if name == "source" else ("model_cache" if name == "cache" else name),
            source=directories[name],
            target=f"/opt/sluice/{'model_source' if name == 'source' else ('model_cache' if name == 'cache' else name)}",
            expected_sha256=sha256_tree(directories[name]),
            probe_relative=f"{name}.probe",
            allow_exec=name == "runtime",
        )
        for name in ("runtime", "source", "cache")
    )
    devices = tuple(
        GPUDevice.from_host(Path(value))
        for value in ("/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia0")
    )
    return RockyGPUIsolationConfig.strict(
        binds=binds,
        devices=devices,
        protected_host_paths=ProtectedHostPaths(
            shared_home=shared_home,
            ledger=protected["ledger"],
            signing_key=protected["signing_key"],
            tool_credential=protected["tool_credential"],
            raw_audit=protected["raw_audit"],
        ),
        worker_source_sha256=sha256_file(BACKEND_SOURCE),
        interpreter_sha256=_interpreter_sha256(),
        workload_environment={
            "CUDA_VISIBLE_DEVICES": "0",
            "HF_HUB_OFFLINE": "1",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/opt/sluice/runtime/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TOKENIZERS_PARALLELISM": "false",
            "TRANSFORMERS_OFFLINE": "1",
        },
        root_parent=Path("/tmp"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    arguments = parser.parse_args()
    if COMMIT.fullmatch(arguments.source_commit) is None:
        parser.error("--source-commit must be exactly 40 lowercase hex characters")
    started = _utc_now()
    with tempfile.TemporaryDirectory(prefix="sluice-rocky-attest-", dir="/tmp") as raw_work:
        work = Path(raw_work)
        config = _make_config(work)
        protected_paths = config.protected_host_paths
        with launch_rocky_gpu_isolation(config) as run:
            start_attestation = run.attestation.to_wire()
        final_attestation = run.final_attestation
        if final_attestation is None:
            raise RuntimeError("strict worker did not return its final digest attestation")
        wire: dict[str, object] = {
            "attestation": start_attestation,
            "config_sha256": canonical_config_sha256(config),
            "evidence_boundary": {
                "cuda_allocation_executed": False,
                "model_loaded": False,
                "principal_claims_permitted": False,
                "purpose": "live Rocky kernel capability and denial attestation",
            },
            "final_attestation": final_attestation,
            "finished_utc": _utc_now(),
            "schema_version": 1,
            "source_commit": arguments.source_commit,
            "source_sha256": {
                "experiments/attest_rocky_gpu_isolation.py": sha256_file(Path(__file__)),
                "sluice_v2/rocky_gpu_isolation.py": sha256_file(BACKEND_SOURCE),
                "sluice_v2/tests/test_v24_rocky_gpu_isolation.py": sha256_file(CONTRACT_SOURCE),
                "worker_interpreter": _interpreter_sha256(),
            },
            "started_utc": started,
        }
        serialized = json.dumps(wire, sort_keys=True)
        for path in protected_paths.as_mapping().values():
            if os.fspath(path) in serialized or path.read_text(encoding="ascii") in serialized:
                raise RuntimeError("public evidence contains protected path material")
        _write_atomic_new(arguments.output, wire)
    print(
        json.dumps(
            {
                "config_sha256": wire["config_sha256"],
                "hostname": start_attestation["hostname"],
                "output": os.fspath(arguments.output.resolve()),
                "principal_claims_permitted": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
