#!/usr/bin/env python3
"""Produce one public, source-bound live Linux-isolation attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile

from sluice_v2.linux_isolation import (
    LinuxIsolationConfig,
    ProtectedCanaries,
    launch_live_isolation,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_paths(artifact_root: Path, driver: Path) -> dict[str, Path]:
    """Return the complete local source trust base for this attestation."""

    return {
        "sluice_v2/linux_isolation.py": artifact_root
        / "sluice_v2"
        / "linux_isolation.py",
        "sluice_v2/isolation.py": artifact_root / "sluice_v2" / "isolation.py",
        "sluice_v2/observer.py": artifact_root / "sluice_v2" / "observer.py",
        "sluice_v2/tests/test_v10_live_linux_isolation.py": artifact_root
        / "sluice_v2"
        / "tests"
        / "test_v10_live_linux_isolation.py",
        "experiments/attest_linux_isolation.py": driver,
    }


def _hash_sources(paths: dict[str, Path]) -> dict[str, str]:
    return {name: _sha256(path) for name, path in paths.items()}


def _interpreter_identity(path: Path) -> dict[str, object]:
    status = path.stat()
    return {
        "path": os.fspath(path),
        "sha256": _sha256(path),
        "device": status.st_dev,
        "inode": status.st_ino,
        "size_bytes": status.st_size,
        "mtime_ns": status.st_mtime_ns,
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--work-dir",
        required=True,
        type=Path,
        help="existing private directory used only for non-secret canaries",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new JSON evidence path (existing files are never overwritten)",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    work_dir = arguments.work_dir.resolve(strict=True)
    if not work_dir.is_dir():
        raise SystemExit("--work-dir must be a directory")
    output = arguments.output.resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise SystemExit("refusing to overwrite existing attestation")

    # Snapshot every local source dependency and the exact interpreter before
    # launching any attested role.  Post-run hashes below detect replacement
    # during the run; ``source_sha256`` always names the bytes selected at the
    # beginning rather than whatever happens to occupy those paths later.
    driver = Path(__file__).resolve(strict=True)
    artifact_root = driver.parents[1]
    source_paths = _source_paths(artifact_root, driver)
    source_sha256_before = _hash_sources(source_paths)
    interpreter_path = Path(sys.executable).resolve(strict=True)
    interpreter_before = _interpreter_identity(interpreter_path)

    with tempfile.TemporaryDirectory(
        prefix="sluice-live-attestation-", dir=work_dir
    ) as temporary:
        root = Path(temporary)
        public = root / "public"
        private = root / "private"
        public.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        model_probe = public / "model.bin"
        model_probe.write_bytes(b"public-model-canary")
        protected: dict[str, Path] = {}
        for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
            path = private / name
            path.write_bytes(("non-secret-denial-canary-" + name).encode("ascii"))
            path.chmod(0o600)
            protected[name] = path

        config = LinuxIsolationConfig.strict(
            model_readonly_paths=(public,),
            model_allowed_read_probe=model_probe,
            protected_canaries=ProtectedCanaries(
                ledger=protected["ledger"],
                signing_key=protected["signing_key"],
                tool_credential=protected["tool_credential"],
                raw_audit=protected["raw_audit"],
            ),
            model_environment_allowlist=frozenset({"LANG", "PATH"}),
        )
        with launch_live_isolation(config) as run:
            live_attestation = run.attestation.to_wire()
        clean_shutdown = run.live_pids() == ()
        if not clean_shutdown:
            raise SystemExit("strict topology did not shut down cleanly")

    source_sha256_after = _hash_sources(source_paths)
    interpreter_after = _interpreter_identity(interpreter_path)
    changed_sources = sorted(
        name
        for name in source_sha256_before
        if source_sha256_before[name] != source_sha256_after[name]
    )
    trust_base_unchanged = (
        not changed_sources and interpreter_before == interpreter_after
    )

    evidence = {
        "schema_version": 1,
        "status": (
            "strict_live_attestation_passed"
            if trust_base_unchanged
            else "invalid_trust_base_changed_during_run"
        ),
        "scope": "synthetic three-process enforcement and denial probes",
        "canaries": "fixed non-secret owner-readable values; paths omitted",
        "host": {
            "machine": platform.machine(),
            "kernel_release": platform.release(),
            "python": platform.python_version(),
            "uid": os.getuid(),
            "gid": os.getgid(),
        },
        "source_sha256": source_sha256_before,
        "trust_binding": {
            "hash_phase": "before_launch_and_after_clean_shutdown",
            "all_sources_unchanged_after_run": not changed_sources,
            "changed_sources": changed_sources,
            "source_sha256_after": source_sha256_after,
            "interpreter": interpreter_before,
            "interpreter_unchanged_after_run": (
                interpreter_before == interpreter_after
            ),
            "interpreter_after": interpreter_after,
        },
        "manifest": config.manifest.to_wire(),
        "attestation": live_attestation,
        "clean_shutdown": clean_shutdown,
        "limitations": [
            "attests the synthetic bootstrap and effect handler, not a GPU model process",
            "timing and resource-exhaustion availability remain out of scope",
            "protected canary names are pre-workload probes, never production secret paths",
        ],
    }
    encoded = json.dumps(
        evidence,
        allow_nan=False,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ) + "\n"
    with output.open("x", encoding="ascii", newline="\n") as destination:
        destination.write(encoded)
    print(f"wrote {output}")
    print(f"sha256 {hashlib.sha256(encoded.encode('ascii')).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
