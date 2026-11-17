#!/usr/bin/env python3
"""Create-only authenticated staging driver; never imports or runs a model.

Operational execution is accepted only when this module was installed from
the stdlib-only verified bootstrap's authenticated in-memory closure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable


PROTOCOL_ID = "sluice-authenticated-local-runtime-v1"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[a-z0-9][a-z0-9_-]{7,127}\Z")
BOUNDARY = {
    "cuda_allocation_executed": False,
    "model_loaded": False,
    "principal_claims_permitted": False,
    "tokenizer_loaded": False,
    "vllm_imported": False,
}


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("ascii")


def _exact_json_equal(observed: object, expected: object) -> bool:
    """Compare JSON-shaped values without Python's bool/numeric aliases."""

    if type(observed) is not type(expected):
        return False
    if type(expected) is dict:
        return set(observed) == set(expected) and all(
            _exact_json_equal(observed[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(observed) == len(expected) and all(
            _exact_json_equal(left, right)
            for left, right in zip(observed, expected, strict=True)
        )
    if type(expected) not in (str, int, float, bool, type(None)):
        return False
    return observed == expected


def _canonical_path(path: Path, name: str) -> Path:
    candidate = Path(path)
    text = os.fspath(candidate)
    if not candidate.is_absolute() or ".." in candidate.parts or "\x00" in text or text != candidate.as_posix():
        raise ValueError(f"{name} must be a canonical absolute path")
    return candidate


def _failure_output(path: Path) -> Path:
    return path.with_name(path.name + ".failure.json")


def _completion_output(path: Path) -> Path:
    return path.with_name(path.name + ".complete.json")


def _runtime_binding(result: object) -> dict[str, object]:
    empty = {
        "destination_base": None,
        "execution_sha256": None,
        "published_identity": None,
        "published_path": None,
        "source_identity": None,
        "source_path": None,
        "timestamp_sha256": None,
        "tree_sha256": None,
    }
    if type(result) is not dict:
        return empty
    return {
        "destination_base": result.get("destination_base"),
        "execution_sha256": result.get("source_execution_sha256"),
        "published_identity": result.get("published_identity"),
        "published_path": result.get("published_path"),
        "source_identity": result.get("source_identity_after"),
        "source_path": result.get("source_path"),
        "timestamp_sha256": result.get("source_timestamp_sha256"),
        "tree_sha256": result.get("source_sha256"),
    }


def _bootstrap_start() -> dict[str, object]:
    value = globals().get("VERIFIED_BOOTSTRAP_START")
    if type(value) is not dict:
        raise RuntimeError("stage driver requires verified bootstrap execution")
    return value


def _bootstrap_finalize() -> Callable[[], dict[str, object]]:
    value = globals().get("VERIFIED_BOOTSTRAP_FINALIZE")
    if not callable(value):
        raise RuntimeError("stage driver requires verified bootstrap finalizer")
    return value


def _dependencies() -> tuple[object, object]:
    rocky = sys.modules.get("sluice_v2.rocky_gpu_isolation")
    staging = sys.modules.get("sluice_v2.runtime_staging")
    if rocky is None or staging is None:
        raise RuntimeError("authenticated staging closure is incomplete")
    return rocky, staging


def _published_manifest_binding(path: Path) -> dict[str, object]:
    _rocky, staging = _dependencies()
    try:
        _wire, digest, identity = staging.read_json_authenticated_with_identity(path)
    except FileNotFoundError:
        return {"identity": None, "published": False, "sha256": None, "valid": False}
    except BaseException:
        digest, identity = staging.read_regular_authenticated_with_identity(path)
        return {"identity": identity, "published": True, "sha256": digest, "valid": False}
    return {"identity": identity, "published": True, "sha256": digest, "valid": True}


def _failure_wire(
    *,
    bootstrap_end: dict[str, object] | None,
    bootstrap_equal: bool,
    bootstrap_finalize_error: str | None,
    bootstrap_start: dict[str, object],
    completion_path: str,
    error: BaseException,
    failure_path: str,
    manifest_binding: dict[str, object],
    manifest_path: str,
    phase: str,
    run_id: str,
    runtime: dict[str, object],
    source_commit: str,
) -> dict[str, object]:
    return {
        "bootstrap_end": bootstrap_end,
        "bootstrap_equal": bootstrap_equal,
        "bootstrap_finalize_error": bootstrap_finalize_error,
        "bootstrap_start": bootstrap_start,
        "boundary": dict(BOUNDARY),
        "completion_path": completion_path,
        "error": type(error).__name__,
        "failure_path": failure_path,
        "manifest_identity": manifest_binding["identity"],
        "manifest_path": manifest_path,
        "manifest_published": manifest_binding["published"],
        "manifest_sha256": manifest_binding["sha256"],
        "manifest_valid": manifest_binding["valid"],
        "phase": phase,
        "process_exit_status": 1,
        "protocol_id": PROTOCOL_ID,
        "run_id": run_id,
        "runtime": runtime,
        "source_commit": source_commit,
        "status": "failed_closed",
    }


def _publish_completion_terminal(
    staging: object, path: Path, wire: dict[str, object]
) -> str:
    """Publish completion or recover only an exact authenticated publication.

    Some network filesystems can report an error after the create-only file is
    already durable.  Once an exact completion exists, the CLI must converge
    to exit status zero; it must not emit a contradictory nonzero outcome.
    """

    expected_sha256 = hashlib.sha256(_canonical_json(wire)).hexdigest()
    try:
        observed_sha256 = staging.write_json_create_only(path, wire)
    except BaseException:
        observed, observed_sha256, _identity = (
            staging.read_json_authenticated_with_identity(path)
        )
        if observed != wire or observed_sha256 != expected_sha256:
            raise
    if observed_sha256 != expected_sha256:
        raise RuntimeError("completion publication returned a mismatched digest")
    return observed_sha256


def main() -> int:
    bootstrap_start = _bootstrap_start()
    bootstrap_finalize = _bootstrap_finalize()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination-base", required=True, type=Path)
    parser.add_argument("--label", default="qwnccr")
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-commit", required=True)
    arguments = parser.parse_args()
    if COMMIT.fullmatch(arguments.source_commit) is None:
        parser.error("--source-commit must be exactly 40 lowercase hexadecimal characters")
    if RUN_ID.fullmatch(arguments.run_id) is None:
        parser.error("--run-id is invalid")
    if bootstrap_start.get("run_id") != arguments.run_id or bootstrap_start.get("source_commit") != arguments.source_commit:
        parser.error("verified bootstrap does not bind the requested run/commit")

    manifest_path = _canonical_path(arguments.manifest_output, "manifest output")
    completion_path = _canonical_path(_completion_output(manifest_path), "completion output")
    failure_path = _canonical_path(_failure_output(manifest_path), "failure output")
    source = _canonical_path(arguments.source, "runtime source")
    destination_base = _canonical_path(arguments.destination_base, "runtime destination base")
    phase = "preflight"
    result: dict[str, object] | None = None
    finalized: dict[str, object] | None = None
    _rocky, staging = _dependencies()
    try:
        staging.assert_path_absent_authenticated(failure_path)
        staging.assert_path_absent_authenticated(manifest_path)
        staging.assert_path_absent_authenticated(completion_path)
        phase = "runtime_authentication"
        result = staging.stage_authenticated_runtime(
            source=source,
            destination_base=destination_base,
            label=arguments.label,
            source_commit=arguments.source_commit,
        )
        phase = "bootstrap_finalize"
        finalized = bootstrap_finalize()
        if (
            type(finalized) is not dict
            or set(finalized) != {"end", "equal", "start"}
            or finalized["equal"] is not True
            or not _exact_json_equal(finalized["start"], bootstrap_start)
            or not _exact_json_equal(finalized["start"], finalized["end"])
        ):
            raise RuntimeError("verified execution provenance changed")
        runtime = _runtime_binding(result)
        phase = "manifest_publication"
        manifest_wire = {
            **result,
            "boundary": dict(BOUNDARY),
            "completion_path": os.fspath(completion_path),
            "failure_path": os.fspath(failure_path),
            "manifest_path": os.fspath(manifest_path),
            "run_id": arguments.run_id,
            "status": "published",
            "verified_execution": finalized,
        }
        manifest_sha256 = staging.write_json_create_only(manifest_path, manifest_wire)
        observed, observed_sha256, manifest_identity = staging.read_json_authenticated_with_identity(manifest_path)
        if observed != manifest_wire or observed_sha256 != manifest_sha256:
            raise RuntimeError("published staging manifest failed authenticated readback")
        staging.assert_path_absent_authenticated(failure_path)
        success_wire = {
            "completion_path": os.fspath(completion_path),
            "manifest_path": os.fspath(manifest_path),
            "manifest_sha256": manifest_sha256,
            "model_loaded": False,
            "published_path": result["published_path"],
            "run_id": arguments.run_id,
            "runtime_execution_sha256": runtime["execution_sha256"],
            "runtime_sha256": runtime["tree_sha256"],
        }
        phase = "completion_publication"
        completion_wire = {
            "failure_path": os.fspath(failure_path),
            "manifest_identity": manifest_identity,
            "manifest_path": os.fspath(manifest_path),
            "manifest_sha256": manifest_sha256,
            "process_exit_status": 0,
            "protocol_id": PROTOCOL_ID,
            "run_id": arguments.run_id,
            "runtime": runtime,
            "source_commit": arguments.source_commit,
            "status": "committed",
            "verified_execution_sha256": hashlib.sha256(_canonical_json(finalized)).hexdigest(),
        }
        completion_sha256 = _publish_completion_terminal(
            staging, completion_path, completion_wire
        )
    except BaseException as exc:
        finalize_error: str | None = None
        if finalized is None:
            try:
                finalized = bootstrap_finalize()
            except BaseException as bootstrap_error:
                finalize_error = type(bootstrap_error).__name__
        manifest_binding = _published_manifest_binding(manifest_path)
        failure = _failure_wire(
            bootstrap_end=(finalized.get("end") if type(finalized) is dict else None),
            bootstrap_equal=(type(finalized) is dict and finalized.get("equal") is True),
            bootstrap_finalize_error=finalize_error,
            bootstrap_start=bootstrap_start,
            completion_path=os.fspath(completion_path),
            error=exc,
            failure_path=os.fspath(failure_path),
            manifest_binding=manifest_binding,
            manifest_path=os.fspath(manifest_path),
            phase=phase,
            run_id=arguments.run_id,
            runtime=_runtime_binding(result),
            source_commit=arguments.source_commit,
        )
        try:
            failure_sha256 = staging.write_json_create_only(failure_path, failure)
        except BaseException as failure_error:
            try:
                print(json.dumps({"error": type(exc).__name__, "failure_record_error": type(failure_error).__name__, "process_exit_status": 1, "run_id": arguments.run_id, "status": "failed_closed_without_new_failure_record"}, sort_keys=True), flush=True)
            except BaseException:
                pass
            return 1
        try:
            print(json.dumps({"error": type(exc).__name__, "failure_path": os.fspath(failure_path), "failure_sha256": failure_sha256, "process_exit_status": 1, "run_id": arguments.run_id, "status": "failed_closed"}, sort_keys=True), flush=True)
        except BaseException:
            pass
        return 1

    success_wire["completion_sha256"] = completion_sha256
    # Completion is terminal.  A BrokenPipe or other final reporting failure
    # cannot convert durable authenticated success into a nonzero outcome.
    try:
        print(json.dumps(success_wire, sort_keys=True), flush=True)
    except BaseException:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
