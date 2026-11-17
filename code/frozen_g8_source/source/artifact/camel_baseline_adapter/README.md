# CaMeL local-model adapter

Two small patches against CaMeL (`google-research/camel-prompt-injection`,
upstream commit in `upstream_commit.txt`) that let it run against a locally
hosted, OpenAI-compatible endpoint (this project's vLLM server) instead of
only the cloud APIs its model dispatch otherwise hardcodes.

`camel_models.patch` adds a `"local:"` model-name branch to
`make_tools_pipeline()` (both the privileged and quarantined LLM
construction) that points an `openai.OpenAI`/`pydantic_ai.OpenAIChatModel`
client at `$SLUICE_LOCAL_BASE_URL` instead of OpenAI's real API.
`camel_privileged_llm.patch` guards `_get_quarantined_llm()`'s `"openai"
in model` check with an `isinstance(model, str)` check, since the
quarantined LLM here is a `Model` instance, not a string (pydantic-ai's
string-based provider inference has no `"local:"` prefix to recognize).

Neither patch intentionally touches CaMeL's interpreter, capability tracking,
or security-policy code -- only which HTTP endpoint requests go to. This is a
project-maintained compatibility adapter, not an official CaMeL configuration
or effectiveness result.

## Applying

```sh
git clone https://github.com/google-research/camel-prompt-injection.git
cd camel-prompt-injection
git checkout <hash in upstream_commit.txt>
patch -p1 < ../camel_models.patch      # against src/camel/models.py
patch -p1 < ../camel_privileged_llm.patch  # against src/camel/pipeline_elements/privileged_llm.py
pip install -e .
```

Then, with a local vLLM server running (see
`integrations/REAL_MODEL_EVIDENCE.md`):

```sh
export SLUICE_LOCAL_BASE_URL=http://localhost:8101/v1
python3 camel_baseline_run.py   # in code/source/, alongside this directory
```

`camel_baseline_run.py` is this project's own driver (not part of CaMeL),
which builds a `"local:ibm-granite/granite-3.1-8b-instruct"` pipeline via
the patched `make_tools_pipeline()`. The archived run is only a compatibility
smoke test: two of six utility tasks hit context limits, and its sole attack
pair was not vulnerable in the undefended arm. Do not treat it as a
security-discriminating CaMeL-versus-Sluice comparison.
