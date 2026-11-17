#!/usr/bin/env python3
"""Static and integration regressions for the G8 activation markers."""

from __future__ import annotations

from pathlib import Path
import re
import tempfile

import c4_shard_status


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def main() -> int:
    source = (Path(__file__).with_name("launch_c4_matrix.sh")
              .read_text(encoding="utf-8"))
    matrix = source.index('durable_marker "$here/MATRIX_ACTIVE"')
    matrix_end = source.index('log_line "MATRIX_ACTIVE created"', matrix)
    preflight = source.index('log_line "phase=policy_preflight')
    seal = source.index('policy_seal_sha256="$(sha256sum')
    execution = source.index('durable_marker "$execution_active"')
    execution_end = source.index(
        'log_line "C4_EXECUTION_ACTIVE created"', execution)
    phase_e = source.index('log_line "phase=execute"')
    status = source.index('"$here/c4_shard_status.py"', phase_e)

    require(matrix < preflight, "MATRIX_ACTIVE is not published before preflight")
    require(preflight < seal < execution < phase_e < status,
            "execution activation does not precede Phase-E status")

    quoted_line = re.compile(r'^\s+"([^"\\]*(?:\\.[^"\\]*)*)"(?: \\)?$', re.M)
    matrix_lines = quoted_line.findall(source[matrix:matrix_end])
    execution_lines = quoted_line.findall(source[execution:execution_end])
    matrix_fields = [line.split("=", 1)[0] for line in matrix_lines]
    execution_fields = [line.split("=", 1)[0] for line in execution_lines]
    require(matrix_fields == [
        "head", "manifest_sha256", "launch_sha256", "dispatch_sha256",
        "agentdojo_runtime_manifest_sha256",
        "agentdojo_loaded_asset_tree_sha256", "protocol", "started_utc",
    ], f"wrong MATRIX_ACTIVE schema/order: {matrix_fields}")
    require(execution_fields == [
        "head", "manifest_sha256", "policy_set_file_sha256",
        "policy_seal_file_sha256", "started_utc",
    ], f"wrong C4_EXECUTION_ACTIVE schema/order: {execution_fields}")
    matrix_block = source[matrix:matrix_end]
    require(
        "agentdojo_runtime_manifest_sha256="
        "301db416517d7d0b32392ac7913c9a024ded713d77975c626d1f00b5ee94b996"
        in matrix_block,
        "wrong AgentDojo runtime-manifest binding",
    )
    require(
        "agentdojo_loaded_asset_tree_sha256="
        "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
        in matrix_block,
        "wrong AgentDojo loaded-asset binding",
    )
    require(
        "protocol=all_90_policy_preflights_then_global_seal_then_execution"
        in matrix_block,
        "wrong activation protocol binding",
    )
    require("execution_evidence_predates_execution_active" in source,
            "missing pre-activation evidence refusal")

    with tempfile.TemporaryDirectory(prefix="g8_active_markers_") as raw:
        root = Path(raw)
        matrix_payload = [
            "head=" + "a" * 40,
            "manifest_sha256=" + "b" * 64,
            "launch_sha256=" + "c" * 64,
            "dispatch_sha256=" + "d" * 64,
            "agentdojo_runtime_manifest_sha256="
            + c4_shard_status.AGENTDOJO_RUNTIME_MANIFEST_SHA256,
            "agentdojo_loaded_asset_tree_sha256="
            + c4_shard_status.AGENTDOJO_LOADED_ASSET_TREE_SHA256,
            "protocol=all_90_policy_preflights_then_global_seal_then_execution",
            "started_utc=2026-08-25T00:00:00Z",
        ]
        execution_payload = [
            "head=" + "a" * 40,
            "manifest_sha256=" + "b" * 64,
            "policy_set_file_sha256=" + "e" * 64,
            "policy_seal_file_sha256=" + "f" * 64,
            "started_utc=2026-08-25T00:01:00Z",
        ]
        (root / "MATRIX_ACTIVE").write_text(
            "\n".join(matrix_payload) + "\n", encoding="ascii")
        (root / "C4_EXECUTION_ACTIVE").write_text(
            "\n".join(execution_payload) + "\n", encoding="ascii")
        require(c4_shard_status.active_bindings_for(root) == {
            "expected_run_head": "a" * 40,
            "expected_c4_manifest_sha256": "b" * 64,
            "expected_launch_sha256": "c" * 64,
            "expected_dispatch_sha256": "d" * 64,
            "policy_set_file_sha256": "e" * 64,
            "policy_seal_file_sha256": "f" * 64,
        }, "active marker integration binding mismatch")
        (root / "MATRIX_ACTIVE").write_text(
            "\n".join(matrix_payload + ["unexpected=x"]) + "\n",
            encoding="ascii")
        try:
            c4_shard_status.active_bindings_for(root)
        except RuntimeError as exc:
            require("fields mismatch" in str(exc),
                    f"wrong extra-field refusal: {exc}")
        else:
            raise RuntimeError("extra MATRIX_ACTIVE field was accepted")

    print("10/10 activation-marker assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
