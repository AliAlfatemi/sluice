#!/usr/bin/env python3
"""Authenticate and validate the pinned AgentDojo v1.2.2 registry.

This CPU-only audit intentionally prevents AgentDojo's provider-heavy
``agent_pipeline`` package initializer from importing Anthropic, Cohere,
Google, or OpenAI clients.  The suite loader needs only the base pipeline
modules and one sentinel constant from ``google_llm``; no model object is
created and no provider/network call is possible.

Minimal import-only dependencies, pinned by AgentDojo's official ``uv.lock``:
docstring-parser==0.16, deepdiff==8.6.1, orderly-set==5.5.0,
email-validator==2.2.0, dnspython==2.7.0, rich==14.0.0,
markdown-it-py==3.0.0, mdurl==0.1.2.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import sys
import types

# The authenticated checkout must remain source-only.  Disable cache creation
# before importing the harness or any pinned AgentDojo module so subsequent
# validation runs cannot introduce executable bytes outside the 112-file pin.
sys.dont_write_bytecode = True

from sluice_v2.evaluation.agentdojo import (
    AGENTDOJO_COMMIT,
    AGENTDOJO_TREE,
    AGENTDOJO_VERSION,
    BENCHMARK_VERSION,
    V122_TOOL_REGISTRIES,
    validate_pinned_checkout,
    validate_v122_suites,
)


IMPORT_DEPENDENCIES = {
    "docstring-parser": "0.16",
    "deepdiff": "8.6.1",
    "orderly-set": "5.5.0",
    "email-validator": "2.2.0",
    "dnspython": "2.7.0",
    "rich": "14.0.0",
    "markdown-it-py": "3.0.0",
    "mdurl": "0.1.2",
}


def _verify_dependencies() -> dict[str, str]:
    observed: dict[str, str] = {}
    for distribution, expected in IMPORT_DEPENDENCIES.items():
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise SystemExit(f"missing import-only dependency: {distribution}=={expected}") from exc
        if version != expected:
            raise SystemExit(
                f"dependency mismatch for {distribution}: expected {expected}, got {version}"
            )
        observed[distribution] = version
    return observed


def _disable_unused_provider_initializers(checkout: Path) -> tuple[str, ...]:
    pipeline_root = checkout / "src" / "agentdojo" / "agent_pipeline"
    package = types.ModuleType("agentdojo.agent_pipeline")
    package.__path__ = [str(pipeline_root)]
    package.__package__ = "agentdojo.agent_pipeline"
    sys.modules[package.__package__] = package

    llms = types.ModuleType("agentdojo.agent_pipeline.llms")
    llms.__path__ = [str(pipeline_root / "llms")]
    llms.__package__ = "agentdojo.agent_pipeline.llms"
    sys.modules[llms.__package__] = llms

    google_llm = types.ModuleType("agentdojo.agent_pipeline.llms.google_llm")
    google_llm.EMPTY_FUNCTION_NAME = "<empty-function-name>"
    sys.modules[google_llm.__name__] = google_llm
    return (
        "agentdojo.agent_pipeline.__init__",
        "agentdojo.agent_pipeline.llms.__init__",
        "agentdojo.agent_pipeline.llms.google_llm (sentinel only)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    args = parser.parse_args(argv)
    # Preserve the caller-supplied final path component for the validator's
    # root-symlink rejection; use the authenticated resolved root afterward.
    source = validate_pinned_checkout(args.checkout)
    checkout = source.root
    dependencies = _verify_dependencies()
    disabled = _disable_unused_provider_initializers(checkout)
    sys.path.insert(0, str(checkout / "src"))

    from agentdojo.task_suite.load_suites import get_suites

    summary = validate_v122_suites(
        get_suites(BENCHMARK_VERSION), authenticate_schemas=True
    )
    output = {
        "schema_version": "sluice-agentdojo-registry-validation-v1",
        "source": {
            "version": AGENTDOJO_VERSION,
            "commit": AGENTDOJO_COMMIT,
            "git_tree": AGENTDOJO_TREE,
            "checkout": str(source.root),
            "python_file_count": source.python_file_count,
            "python_tree_sha256": source.python_tree_sha256,
            "loaded_asset_file_count": source.loaded_asset_file_count,
            "loaded_asset_tree_sha256": source.loaded_asset_tree_sha256,
            "key_file_sha256": dict(source.key_file_sha256),
        },
        "benchmark_version": BENCHMARK_VERSION,
        "counts": {
            "benign_tasks": summary.benign_task_count,
            "injection_tasks": summary.injection_task_count,
            "attacked_pairs": summary.attacked_pair_count,
            "suite_tools": dict(summary.suite_tool_counts),
            "suite_tool_schema_sha256": dict(summary.suite_tool_schema_sha256),
        },
        "registry": {
            suite: {
                "effectful": sorted(registry.effectful),
                "read_only": sorted(registry.read_only),
            }
            for suite, registry in V122_TOOL_REGISTRIES.items()
        },
        "provider_modules_disabled": list(disabled),
        "provider_or_model_calls": 0,
        "import_dependencies": dependencies,
        "result": "PASS",
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
