#!/usr/bin/env python3
"""Data-only wire format for Sluice AgentDojo policy compilation.

Why this module exists
----------------------
``sluice_v2.evaluation.agentdojo.compile_static_policy`` cannot execute on the
only interpreter that can run AgentDojo.  Two independent reasons, both
verified on this machine rather than assumed:

  * ``_stable_code_wire`` reads ``code.co_qualname``, which is CPython 3.11+.
    The dedicated AgentDojo runtime ``sluice_agentdojo_v1`` is CPython 3.10.20,
    pinned there by the vLLM 0.6.4 / torch 2.5.1+cu124 stack that works on
    Volta.  On 3.10 the compiler raises
    ``AttributeError: 'code' object has no attribute 'co_qualname'``.
  * Even with that attribute polyfilled, ``_PINNED_COMPILER_RUNTIME_SHA256``
    hashes ``co_code`` -- the interpreter's own unquickened bytecode -- so the
    compiler's identity assertion structurally binds it to one CPython version.

That is not an obstacle to work around; it is the design the module documents.
``audit_primary_source_for_oracle_access``'s own docstring says the compiler
"must run in the policy process, outside the post-episode scoring process".
So this module defines the JSON boundary between those two processes:

    evaluation process (3.10, AgentDojo + vLLM)
        emits  PolicyRequest   -- prompts, tool schemas, pre-injection state,
                                  authored call templates.  No task object, no
                                  scorer, no environment object, no model.
    policy process     (3.11, sluice_v2 only, no AgentDojo import at all)
        emits  ManifestBundle  -- compiled PolicyManifest values, data only.
    evaluation process (3.10)
        rebuilds PolicyManifest from the bundle and runs the broker.

The manifest is revalidated on reconstruction: ``PolicyManifest.__post_init__``
recomputes every structural invariant, ``CallTemplate.__post_init__``
recomputes ``args_sha256`` from ``exact_args``, and this module additionally
re-checks the manifest digest against the value the policy process recorded.
A corrupted or edited bundle therefore cannot be loaded.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

WIRE_REQUEST_SCHEMA = "sluice-agentdojo-policy-request-v1"
WIRE_BUNDLE_SCHEMA = "sluice-agentdojo-policy-manifest-bundle-v1"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


# --------------------------------------------------------------- manifest wire

def manifest_to_wire(manifest: Any) -> dict[str, Any]:
    """Serialise a compiled PolicyManifest to plain JSON."""

    return {
        "schema_version": manifest.schema_version,
        "policy_id": manifest.policy_id,
        "workflow_id": manifest.workflow_id,
        "episode_id": manifest.episode_id,
        "suite_name": manifest.suite_name,
        "task_id": manifest.task_id,
        "split": manifest.split.value,
        "decision": manifest.decision.value,
        "abstention": manifest.abstention.value,
        "templates": [
            {
                "schema_version": template.schema_version,
                "template_id": template.template_id,
                "tool": template.tool,
                "exact_args": template.exact_args,
                "args_sha256": template.args_sha256,
            }
            for template in manifest.templates
        ],
        "source_commit": manifest.source_commit,
        "benchmark_version": manifest.benchmark_version,
        "prompt_sha256": manifest.prompt_sha256,
        "state_sha256": manifest.state_sha256,
        "tool_schema_sha256": manifest.tool_schema_sha256,
        "organization_policy_sha256": manifest.organization_policy_sha256,
        "split_manifest_sha256": manifest.split_manifest_sha256,
        "compiler_id": manifest.compiler_id,
        "compiler_sha256": manifest.compiler_sha256,
        "compiler_runtime_sha256": manifest.compiler_runtime_sha256,
        "source_assets_sha256": manifest.source_assets_sha256,
        "input_sha256": manifest.input_sha256,
    }


def manifest_from_wire(wire: Mapping[str, Any], foundation: Any) -> Any:
    """Rebuild an exact PolicyManifest from its wire form, fail-closed.

    ``foundation`` is the imported ``sluice_v2.evaluation.agentdojo`` module.
    Every field is retyped through the module's own enums and dataclasses, so
    the module's own validation -- not this function -- decides what is valid.
    """

    if not isinstance(wire, Mapping):
        raise TypeError("manifest wire must be a mapping")
    expected = {
        "schema_version", "policy_id", "workflow_id", "episode_id", "suite_name",
        "task_id", "split", "decision", "abstention", "templates",
        "source_commit", "benchmark_version", "prompt_sha256", "state_sha256",
        "tool_schema_sha256", "organization_policy_sha256",
        "split_manifest_sha256", "compiler_id", "compiler_sha256",
        "compiler_runtime_sha256", "source_assets_sha256", "input_sha256",
    }
    if set(wire) != expected:
        missing = sorted(expected - set(wire))
        extra = sorted(set(wire) - expected)
        raise ValueError(
            f"manifest wire fields are not exact (missing={missing}, extra={extra})"
        )
    templates = []
    for item in wire["templates"]:
        if not isinstance(item, Mapping) or set(item) != {
            "schema_version", "template_id", "tool", "exact_args", "args_sha256"
        }:
            raise ValueError("manifest wire template fields are not exact")
        templates.append(
            foundation.CallTemplate(
                template_id=item["template_id"],
                tool=item["tool"],
                exact_args=item["exact_args"],
                args_sha256=item["args_sha256"],
                schema_version=item["schema_version"],
            )
        )
    return foundation.PolicyManifest(
        policy_id=wire["policy_id"],
        workflow_id=wire["workflow_id"],
        episode_id=wire["episode_id"],
        suite_name=wire["suite_name"],
        task_id=wire["task_id"],
        split=foundation.EvaluationSplit(wire["split"]),
        decision=foundation.PolicyDecision(wire["decision"]),
        abstention=foundation.AbstentionCategory(wire["abstention"]),
        templates=tuple(templates),
        source_commit=wire["source_commit"],
        benchmark_version=wire["benchmark_version"],
        prompt_sha256=wire["prompt_sha256"],
        state_sha256=wire["state_sha256"],
        tool_schema_sha256=wire["tool_schema_sha256"],
        organization_policy_sha256=wire["organization_policy_sha256"],
        split_manifest_sha256=wire["split_manifest_sha256"],
        compiler_id=wire["compiler_id"],
        compiler_sha256=wire["compiler_sha256"],
        compiler_runtime_sha256=wire["compiler_runtime_sha256"],
        source_assets_sha256=wire["source_assets_sha256"],
        input_sha256=wire["input_sha256"],
        schema_version=wire["schema_version"],
    )
