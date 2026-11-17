# Reproducing the real-model evidence (RQ6 non-oracle, RQ7 real-LLM, the CaMeL baseline)

Unlike every other result in this project, `real_llm_multiagent_workflow.py`,
`agentdojo_non_oracle_condition.py`, and `camel_baseline_run.py` need a live
LLM inference server, not just a from-scratch `pip install`. This is a real
gap relative to the rest of the artifact: `run_all_tests.sh` reproduces the
whole test suite with one command and no external dependency; these three
scripts do not, and cannot, without the steps below.

## What's required

An OpenAI-compatible chat-completions endpoint intended to serve
`ibm-granite/granite-3.1-8b-instruct` at revision
`4009206d5fc95d2e65a7b7633e159d6e97e25d35`. The live-model drivers require
that revision string and record it as an **operator attestation**. They do
not query the endpoint for its loaded weight hash and therefore cannot
verify the attestation themselves. A defensible rerun must preserve the
server launch log and a cache manifest (or equivalent provider record)
showing the revision actually loaded.

## Standing up an equivalent server

```sh
pip install vllm
python -m vllm.entrypoints.openai.api_server \
  --model ibm-granite/granite-3.1-8b-instruct \
  --revision 4009206d5fc95d2e65a7b7633e159d6e97e25d35 \
  --port 8101 \
  --gpu-memory-utilization 0.85 \
  --max-model-len 8192 \
  --enable-auto-tool-choice \
  --tool-call-parser granite \
  --dtype half
```

This needs a GPU with enough memory for an 8B-parameter model at half
precision (roughly 16-20GB free, more with a large `--max-model-len`). The
historical run did not preserve a frozen vLLM package lock, so it is not an
exactly reproducible software environment. Before producing replacement
evidence, pin the vLLM release and CUDA/container digest and verify that its
`granite` tool-call parser is registered.

Then point each script at it:

```sh
python3 integrations/real_llm_multiagent_workflow.py \
  --base-url http://localhost:8101 \
  --model-revision 4009206d5fc95d2e65a7b7633e159d6e97e25d35

LOCAL_LLM_PORT=8101 \
MODEL_REVISION=4009206d5fc95d2e65a7b7633e159d6e97e25d35 \
  python3 agentdojo_non_oracle_condition.py --suite banking
```

## What was actually used to produce the archived results

A vLLM server already running on a separate GPU node was reached through a
local port-forward. That infrastructure, its container/package lock, and
its launch log are not included. The commands above describe a prospective
equivalent setup from public weights, not an exact reconstruction of that
historical server. Supplying `--model-revision` or `MODEL_REVISION` records
the operator's assertion; it does not prove that the endpoint loaded the
asserted weights.
