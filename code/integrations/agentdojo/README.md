## RQ6: Sluice x AgentDojo integration

Evaluates Sluice's ENDORSE-direction ActionTemplate mechanism against
AgentDojo (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks Track,
arXiv:2406.13352) -- a published benchmark and attack suite this project
did not author. See the paper's Evaluation section (RQ6) for the full
writeup and results tables.

### Files

- `sluice_agentdojo_bridge.py` -- `SluiceMediatedToolsExecutor`, a drop-in
  replacement for AgentDojo's `ToolsExecutor` pipeline element. Mediates
  only effectful tools through Sluice's real `ReferenceMonitor.invoke()` /
  `consume_action_capability()` API; read-only tools pass through
  unmediated. Also: `author_task_gate()` (builds a per-episode gate whose
  `ActionTemplate` scopes the tool's recipient-bearing argument to the
  values in that task's own trusted `ground_truth()`), and
  `ExactMatchBackend` (the Sluice `Backend` used here -- the planner LLM
  has already selected a tool name; this backend independently re-validates
  that selection against the committed alphabet rather than trusting it).
- `agentdojo_pilot.py` -- orchestration script. Runs a suite's user tasks
  x AgentDojo's own `ImportantInstructionsAttack` injection tasks, in both
  undefended and Sluice-mediated conditions, via AgentDojo's own
  `TaskSuite.run_task_with_pipeline`. Every episode gets an independently
  authored gate (no budget carries across trials). Checkpoints to
  `<out>.partial` after every episode.
- `results/` -- raw JSON output for the five (model, suite) runs reported
  in the paper: `full_banking_granite.json`, `full_banking_mistral.json`,
  `full_workspace_granite.json`, `full_travel_granite.json`,
  `full_slack_mistral.json` -- all four of AgentDojo's `v1` suites covered.

### Dependency: AgentDojo itself, and one patch to it

This integration depends on AgentDojo (`pip install -e .` against a local
checkout of https://github.com/ethz-spylab/agentdojo, tag/commit used:
the `main` branch as of 2026-08-16). AgentDojo is not vendored into this
backup (its own repo, ~40MB+ with docs/examples/notebooks); install it
separately, then apply the one patch below before use.

**Patch**: `src/agentdojo/agent_pipeline/llms/openai_llm.py`,
`_message_to_openai()`. Upstream AgentDojo unconditionally maps the
internal `system` role to OpenAI's proprietary `developer` role for every
`OpenAILLM`-based provider, including local/`vllm_parsed` ones. That role
is not part of the standard OpenAI-compatible chat completions surface
most local servers implement; Mistral-7B-Instruct-v0.3 served via vLLM
with `--tokenizer-mode mistral` rejects it outright via a strict request
validator. Fix: emit the standard `system` role instead.

```python
# before (upstream):
case "system":
    return ChatCompletionDeveloperMessageParam(
        role="developer", content=_content_blocks_to_openai_content_blocks(message)
    )

# after (this patch):
case "system":
    return ChatCompletionSystemMessageParam(
        role="system", content=_content_blocks_to_openai_content_blocks(message)
    )
```

(Also add `ChatCompletionSystemMessageParam` to that file's imports from
`openai.types.chat`.) This does not touch Sluice itself -- it is an
AgentDojo/local-server interop fix.

### Serving models

Each model needs a local OpenAI-compatible endpoint before running
`agentdojo_pilot.py` (`LOCAL_LLM_PORT=<port> python agentdojo_pilot.py
--suite {banking,workspace,travel,slack} --out results.json`). Example
(V100-class GPUs
require `--dtype half`; bfloat16 is unsupported on compute capability 7.0):

```bash
python -m vllm.entrypoints.openai.api_server \
  --model ibm-granite/granite-3.1-8b-instruct --port 8101 \
  --gpu-memory-utilization 0.85 --max-model-len 8192 \
  --enable-auto-tool-choice --tool-call-parser granite --dtype half
```

vLLM release actually used: 0.6.6+cu118 (a version whose CUDA build and
manylinux tag are compatible with an older glibc/driver pair than the
cluster's default GPU conda environment provides -- newer vLLM releases in
the same environment failed with a glibc-version or CUDA-driver-version
mismatch before reaching the model). Installed into an isolated venv, not
the shared research conda environment, to avoid any risk to that
environment's other pinned dependencies.

### What worked and what didn't (RQ5 model pool, this harness)

| Model | Tool-call parser | Outcome |
|---|---|---|
| Qwen2.5-3B-Instruct | Hermes (native) | Serves; model declines to autonomously act |
| Phi-3.5-mini-instruct | Hermes (attempted) | Tool-call requests fail (HTTP 500) |
| Mistral-7B-Instruct-v0.3 | Mistral (native, patched) | Serves; model never attempts a mediated tool (banking, slack) |
| OLMo-2-1124-7B-Instruct | Hermes (attempted) | Tool-call requests fail (HTTP 500); max context 4096 not 8192 |
| granite-3.1-8b-instruct | Granite (native) | Full results, banking/workspace/travel |

Phi/OLMo failures were isolated to requests containing a `tools` argument
specifically -- plain completions succeed against both servers -- so this
is a tool-call-parser gap, not a general serving failure.
