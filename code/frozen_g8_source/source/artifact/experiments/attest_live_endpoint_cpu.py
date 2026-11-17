#!/usr/bin/env python3
"""Statically attest the fake-only CPU live-endpoint integration boundary."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import stat
import sys


sys.dont_write_bytecode = True

MODULE_RELATIVE_PATH = Path(
    "source/artifact/sluice_v2/evaluation/live_endpoint_integration.py"
)
EXPECTED_CONSTANTS = {
    "CHRONOLOGY_HMAX": 16,
    "MAX_ATTEMPTS": 2,
    "PEER_IDENTITY_MODE": "synthetic_cpu_api_only",
    "PROTOCOL_ID": "sluice-principal-cpu-loopback-integration-v1",
    "TRANSPORT_MODE": "cpu_fake_loopback_callable_only",
}
EXPECTED_CLASSES = frozenset(
    {
        "CpuEndpointChronology",
        "CpuEndpointReceipt",
        "CpuIntegrationPermit",
        "CpuLoopbackReply",
        "CpuLoopbackRequest",
        "CpuLoopbackSession",
        "FakeLoopbackEndpoint",
        "PinnedModelIdentity",
        "PrincipalEndpointPermit",
        "RuntimeIsolationPins",
        "ScheduleBinding",
    }
)
EXPECTED_FUNCTIONS = frozenset(
    {
        "establish_cpu_loopback",
        "validate_cpu_chronology_wire",
        "validate_cpu_evidence_receipt",
        "write_cpu_receipt_create_once",
    }
)
FORBIDDEN_IMPORTS = frozenset(
    {
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
)
FORBIDDEN_CALLS = frozenset(
    {"connect", "generate", "post", "request", "run", "urlopen"}
)


def _literal_assignments(tree: ast.AST) -> dict[str, object]:
    values: dict[str, object] = {}
    for statement in getattr(tree, "body", ()):  # module statements only
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            values[target.id] = ast.literal_eval(statement.value)
        except (TypeError, ValueError):
            continue
    return values


def attest(repository_root: Path) -> dict[str, object]:
    root = repository_root.resolve(strict=True)
    module_path = root / MODULE_RELATIVE_PATH
    metadata = module_path.lstat()
    if module_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("integration source must be a regular nonsymlink file")
    raw = module_path.read_bytes()
    if not raw or len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("integration source exceeds its finite audit bound")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename=str(MODULE_RELATIVE_PATH))
    except (UnicodeError, SyntaxError) as exc:
        raise RuntimeError("integration source is not valid finite UTF-8 Python") from exc

    imports: set[str] = set()
    calls: set[str] = set()
    classes: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.ClassDef):
            classes.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(node.name)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            else:
                continue
            if name in FORBIDDEN_CALLS:
                calls.add(name)

    forbidden_imports = sorted(imports & FORBIDDEN_IMPORTS)
    if forbidden_imports or calls:
        raise RuntimeError(
            f"integration source crosses CPU boundary: imports={forbidden_imports}, "
            f"calls={sorted(calls)}"
        )
    missing_classes = sorted(EXPECTED_CLASSES - classes)
    missing_functions = sorted(EXPECTED_FUNCTIONS - functions)
    if missing_classes or missing_functions:
        raise RuntimeError(
            f"integration API is incomplete: classes={missing_classes}, "
            f"functions={missing_functions}"
        )
    assignments = _literal_assignments(tree)
    observed_constants = {
        name: assignments.get(name) for name in sorted(EXPECTED_CONSTANTS)
    }
    if observed_constants != {
        name: EXPECTED_CONSTANTS[name] for name in sorted(EXPECTED_CONSTANTS)
    }:
        raise RuntimeError("integration protocol constants drifted")

    return {
        "boundary": {
            "endpoint_kind": "in_process_fake_callable",
            "peer_identity": "synthetic_cpu_api_only",
            "process_scope": "single_interpreter_process_local_registry",
            "serialized_cross_process_binding": False,
        },
        "false_gates": {
            "detector_executed": False,
            "effectiveness_evidence": False,
            "gpu_executed": False,
            "live_endpoint": False,
            "model_executed": False,
            "principal_eligible": False,
            "scoring_executed": False,
            "utility_evidence": False,
        },
        "operations_performed": {
            "detector": False,
            "endpoint_probe": False,
            "gpu": False,
            "model_call": False,
            "scorer": False,
            "task_answer_load": False,
        },
        "plan_sha256": {
            "agentdojo": "49ccb6836e59471541746b5467afa55242d0ae053f29f4587bdda12e694e4200",
            "agentleak": "1bc2b9499a2098b79d9e58deeafab71cf8e61e0ee54a01709f07a49d7bb28728",
        },
        "protocol_constants": observed_constants,
        "schema_version": "sluice-live-endpoint-cpu-source-attestation-v1",
        "source": {
            "relative_path": MODULE_RELATIVE_PATH.as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        },
        "static_audit": {
            "forbidden_call_count": 0,
            "forbidden_import_count": 0,
            "required_class_count": len(EXPECTED_CLASSES),
            "required_function_count": len(EXPECTED_FUNCTIONS),
        },
        "status": "PASS_CPU_FAKE_FOUNDATION_ONLY",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    arguments = parser.parse_args(argv)
    print(json.dumps(attest(arguments.repository_root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
