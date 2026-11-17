#!/usr/bin/env python3
"""The Sluice policy process for AgentDojo.

Runs under the audited CPython 3.11 artifact interpreter.  Reads one data-only
policy request, compiles it with the project's real
``sluice_v2.evaluation.agentdojo.compile_static_policy``, and writes a data-only
manifest bundle.  It imports AgentDojo not at all, constructs no task object,
touches no environment object, calls no scorer, opens no socket and runs no
model.  The only inputs it can see are the four trusted fields the compiler's
own contract admits: suite name, task id, trusted user prompt, pre-injection
state -- plus the organization policy and the frozen policy-author split.

Usage:
    sluice_policy_process.py REQUEST_JSON BUNDLE_JSON
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys

sys.dont_write_bytecode = True

REPO = Path("/srv/review/USENIX27_SLUICE/sluice_usenix_revision")
# An optional candidate reference-monitor root, routed by the caller.  The
# resulting manifests record the candidate's own source digest in
# `compiler_sha256`, so an artefact compiled against a candidate is
# self-identifying.  See NESTED_CALL_GUARD_DEFECT.md.
_MONITOR_ROOT = os.environ.get("SLUICE_MONITOR_ROOT")
sys.path.insert(0, str(REPO / "source" / "artifact"))
if _MONITOR_ROOT:
    # inserted LAST so it ends up at sys.path[0] and actually wins
    sys.path.insert(0, _MONITOR_ROOT)
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from sluice_policy_wire import (  # noqa: E402
    WIRE_BUNDLE_SCHEMA,
    WIRE_REQUEST_SCHEMA,
    canonical,
    digest,
    manifest_to_wire,
)


def _optional_version(name: str):
    try:
        return importlib.metadata.version(name)
    except Exception:  # noqa: BLE001
        return None


def _binding(foundation, spec: dict):
    source = spec["source"]
    if source == "literal":
        return foundation.ArgumentBinding.literal(spec["value"])
    if source == "state_pointer":
        return foundation.ArgumentBinding.from_state(spec["value"])
    raise ValueError(f"unsupported argument source {source!r}")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 64
    request_path = Path(argv[1])
    bundle_path = Path(argv[2])

    from sluice_v2.evaluation import agentdojo as foundation

    loaded = str(Path(foundation.__file__).resolve())
    expected_root = _MONITOR_ROOT or str(REPO / "source" / "artifact")
    if not loaded.startswith(str(Path(expected_root).resolve())):
        raise SystemExit(
            f"policy process loaded sluice_v2 from {loaded}, not {expected_root}"
        )

    request = json.loads(request_path.read_bytes())
    if request.get("schema") != WIRE_REQUEST_SCHEMA:
        raise SystemExit(f"unsupported policy request schema {request.get('schema')!r}")
    if request["agentdojo_commit"] != foundation.AGENTDOJO_COMMIT:
        raise SystemExit("policy request AgentDojo commit does not match the pin")
    if request["benchmark_version"] != foundation.BENCHMARK_VERSION:
        raise SystemExit("policy request benchmark version does not match the pin")

    # ---- the compiler's source identity, and the answer-key AST audit on both
    # the compiler and this file.  A nonempty finding set is fatal.
    foundation_path = Path(foundation.__file__).resolve()
    findings_foundation = foundation.audit_primary_source_for_oracle_access(
        foundation_path
    )
    findings_self = foundation.audit_primary_source_for_oracle_access(
        Path(__file__).resolve()
    )
    findings_wire = foundation.audit_primary_source_for_oracle_access(
        _HERE / "sluice_policy_wire.py"
    )
    if findings_foundation or findings_self or findings_wire:
        raise SystemExit(
            "answer-key reference found on the policy path: "
            f"{findings_foundation} {findings_self} {findings_wire}"
        )

    split = foundation.SplitManifest.create(
        dev_task_ids=request["split"]["dev_task_ids"],
        heldout_task_ids=request["split"]["heldout_task_ids"],
    )
    if split.sha256 != request["split"]["expected_split_manifest_sha256"]:
        raise SystemExit(
            f"split manifest digest mismatch: {split.sha256} != "
            f"{request['split']['expected_split_manifest_sha256']}"
        )
    policy_author_wire = {
        "schema_version": "sluice-agentdojo-policy-author-split-v1",
        "selection_seed": "sluice-agentdojo-policy-author-split-v1:8675309",
        "development_task_ids": sorted(request["split"]["dev_task_ids"]),
        "heldout_task_ids": sorted(request["split"]["heldout_task_ids"]),
    }
    policy_author_digest = hashlib.sha256(
        b"sluice-agentdojo-principal-wire-v1" + b"\0" + canonical(policy_author_wire)
    ).hexdigest()
    if policy_author_digest != request["split"]["expected_policy_author_split_sha256"]:
        raise SystemExit(
            f"policy-author split digest mismatch: {policy_author_digest} != "
            f"{request['split']['expected_policy_author_split_sha256']}"
        )

    schemas_by_suite = {}
    for suite_name, rows in request["suite_tool_schemas"].items():
        schemas_by_suite[suite_name] = tuple(
            foundation.StaticToolSchema(name=row["name"], parameters=row["parameters"])
            for row in rows
        )

    # ---- one organization policy for the whole request: one rule per user task,
    # keyed by (suite, exact trusted prompt digest), exactly as PolicyRule does.
    rules = []
    for task in request["tasks"]:
        calls = tuple(
            foundation.CallTemplateSpec(
                tool=call["tool"],
                arguments={
                    name: _binding(foundation, spec)
                    for name, spec in call["arguments"].items()
                },
            )
            for call in task["authored_calls"]
        )
        rules.append(
            foundation.PolicyRule(
                rule_id=task["task_id"],
                suite_name=task["suite_name"],
                prompt_sha256=hashlib.sha256(
                    task["trusted_user_prompt"].encode("utf-8")
                ).hexdigest(),
                calls=calls,
            )
        )
    organization_policy = foundation.OrganizationPolicy(
        policy_id=request["policy_id"], rules=tuple(rules)
    )

    manifests: dict[str, dict] = {}
    decisions: dict[str, int] = {}
    abstentions: dict[str, int] = {}
    errors: list[dict] = []
    for task in request["tasks"]:
        suite_name = task["suite_name"]
        registry = foundation.V122_TOOL_REGISTRIES[suite_name]
        policy_input = foundation.PolicyInput(
            source_commit=foundation.AGENTDOJO_COMMIT,
            benchmark_version=foundation.BENCHMARK_VERSION,
            suite_name=suite_name,
            task_id=task["task_id"],
            trusted_user_prompt=task["trusted_user_prompt"],
            pre_injection_state=task["pre_injection_state"],
            tool_schemas=schemas_by_suite[suite_name],
            organization_policy=organization_policy,
            split_manifest=split,
        )
        if policy_input.state_sha256 != task["expected_state_sha256"]:
            raise SystemExit(
                f"pre-injection state digest mismatch for {task['task_id']}"
            )
        for episode_id in task["episode_ids"]:
            try:
                manifest = foundation.compile_static_policy(
                    policy_input,
                    registry=registry,
                    workflow_id=task["workflow_id"],
                    episode_id=episode_id,
                    compiler_id=request["compiler_id"],
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append({"episode_id": episode_id, "error": repr(exc)[:400]})
                continue
            wire = manifest_to_wire(manifest)
            wire["manifest_sha256"] = digest(wire)
            manifests[episode_id] = wire
            decisions[manifest.decision.value] = (
                decisions.get(manifest.decision.value, 0) + 1
            )
            abstentions[manifest.abstention.value] = (
                abstentions.get(manifest.abstention.value, 0) + 1
            )

    bundle = {
        "schema": WIRE_BUNDLE_SCHEMA,
        "request_sha256": hashlib.sha256(request_path.read_bytes()).hexdigest(),
        "request_canonical_sha256": digest(request),
        "policy_id": request["policy_id"],
        "compiler_id": request["compiler_id"],
        "organization_policy_sha256": organization_policy.sha256,
        "split_manifest_sha256": split.sha256,
        "policy_author_split_sha256": policy_author_digest,
        "policy_process": {
            "python_version": platform.python_version(),
            "executable": sys.executable,
            "pydantic": _optional_version("pydantic"),
            "pyyaml": _optional_version("PyYAML"),
            "compiler_runtime_sha256": foundation._executing_compiler_digest(),
            "compiler_runtime_pin_matches": (
                foundation._executing_compiler_digest()
                == foundation._PINNED_COMPILER_RUNTIME_SHA256
            ),
            "compiler_source_sha256": hashlib.sha256(
                foundation_path.read_bytes()
            ).hexdigest(),
            "agentdojo_imported": "agentdojo" in sys.modules,
            "monitor_root": _MONITOR_ROOT,
            "monitor_is_committed_tree": _MONITOR_ROOT is None,
        },
        "oracle_audit": {
            "compiler_findings": list(findings_foundation),
            "policy_process_findings": list(findings_self),
            "wire_module_findings": list(findings_wire),
        },
        "counts": {
            "tasks": len(request["tasks"]),
            "manifests": len(manifests),
            "decisions": decisions,
            "abstentions": abstentions,
            "errors": len(errors),
        },
        "errors": errors,
        "manifests": manifests,
    }
    bundle["bundle_sha256"] = digest(
        {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    )
    tmp = bundle_path.with_suffix(bundle_path.suffix + ".tmp")
    tmp.write_bytes(canonical(bundle))
    tmp.replace(bundle_path)
    print(
        json.dumps(
            {k: v for k, v in bundle.items() if k not in ("manifests", "errors")},
            indent=1,
            sort_keys=True,
        )
    )
    if errors:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
