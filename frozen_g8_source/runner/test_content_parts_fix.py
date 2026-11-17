#!/usr/bin/env python3
"""Regression test for the content-parts classifier bug that terminated C10.

Run with the project's vLLM environment so the real chat template and the real
vLLM reducer are both importable:

  /srv/review/USENIX27_SLUICE/envs/sluice_agentdojo_v1/bin/python \\
      test_content_parts_fix.py <patched_node_arm_runner_c4.py>
"""
from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

SNAPSHOT = ("/srv/review/USENIX27_SLUICE/code_data_model/model/"
            "hf_cache/hub/models--Qwen--Qwen2.5-3B-Instruct/snapshots/"
            "aa8e72537993ba99e69dfaafa59ed015b17504d1")
GRANITE_SNAPSHOT = (
    "/srv/review/USENIX27_SLUICE/code_data_model/model/"
    "hf_cache/hub/models--ibm-granite--granite-3.1-8b-instruct/snapshots/"
    "4009206d5fc95d2e65a7b7633e159d6e97e25d35"
)

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f" -- {detail}" if not ok else ""))
    if not ok:
        FAILURES.append(name)


def load_flatten(runner_path: Path):
    """Load only the normalizer, without importing the whole runner module."""
    source = runner_path.read_text(encoding="utf-8")
    start = source.index("def _flatten_content_parts(")
    end = source.index("def attest_policy_author_context_overflow(")
    namespace: dict = {"RuntimeError": RuntimeError, "json": json}
    exec(compile(source[start:end], "flatten", "exec"), namespace)  # noqa: S102
    return namespace["_flatten_content_parts"]


def main() -> int:
    runner = Path(sys.argv[1])
    flatten = load_flatten(runner)
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(SNAPSHOT, local_files_only=True,
                                        trust_remote_code=False)
    tools = [{"type": "function", "function": {
        "name": "get_channels", "description": "List channels.",
        "parameters": {"type": "object", "properties": {}}}}]

    parts_messages = [
        {"role": "system", "content": "You are an assistant."},
        {"role": "user", "content": [
            {"type": "text", "text": "first chunk"},
            {"type": "text", "text": "second chunk"}]},
    ]
    equivalent = [
        {"role": "system", "content": "You are an assistant."},
        {"role": "user", "content": "first chunk\nsecond chunk"},
    ]

    print("\nTest 1: the unpatched path is genuinely broken")
    try:
        tok.apply_chat_template(parts_messages, tools=tools, tokenize=False,
                                add_generation_prompt=True)
        check("raw content-part list raises TypeError", False, "it did not raise")
    except TypeError as exc:
        check("raw content-part list raises TypeError",
              "can only concatenate str" in str(exc), str(exc)[:80])

    print("\nTest 2: the fix makes it render")
    rendered = tok.apply_chat_template(flatten(parts_messages), tools=tools,
                                       tokenize=False, add_generation_prompt=True)
    check("patched path renders without raising", isinstance(rendered, str) and rendered)

    print("\nTest 3: the fix reproduces vLLM's content reduction exactly")
    reference = tok.apply_chat_template(equivalent, tools=tools, tokenize=False,
                                        add_generation_prompt=True)
    check("rendered string equals the newline-joined equivalent",
          rendered == reference,
          f"len {len(rendered)} vs {len(reference)}")
    check("token ids are identical",
          tok.encode(rendered, add_special_tokens=False)
          == tok.encode(reference, add_special_tokens=False))
    print("\nTest 4: assistant tool-call arguments match pinned vLLM exactly")
    sys.path.insert(0, str(Path(
        "/srv/review/USENIX27_SLUICE/envs/sluice_agentdojo_v1/"
        "lib/python3.10/site-packages")))
    from vllm.config import ModelConfig
    from vllm.entrypoints.chat_utils import apply_hf_chat_template, parse_chat_messages

    tool_messages = [
        {"role": "system", "content": [{"type": "text", "text": "Assist."}]},
        {"role": "user", "content": [{"type": "text", "text": "Find Paris."}]},
        {"role": "assistant", "content": [{"type": "text", "text": ""}],
         "tool_calls": [{"id": "1", "type": "function",
                         "function": {"name": "get_channels",
                                      "arguments": '{"city": "Paris"}'}}]},
        {"role": "tool", "content": [{"type": "text", "text": "sunny"}],
         "tool_call_id": "1"},
    ]
    config = ModelConfig(
        model=SNAPSHOT, task="auto", tokenizer=SNAPSHOT,
        tokenizer_mode="auto", trust_remote_code=False, dtype="auto", seed=0,
        max_model_len=32768, chat_template_text_format="string")
    conversation, _ = parse_chat_messages(deepcopy(tool_messages), config, tok)
    vllm_rendered = apply_hf_chat_template(
        tok, conversation=conversation, chat_template=None, tools=tools,
        tokenize=False, add_generation_prompt=True,
        continue_final_message=False)
    patched_rendered = tok.apply_chat_template(
        flatten(deepcopy(tool_messages)), tools=tools, tokenize=False,
        add_generation_prompt=True)
    g2_content_only = deepcopy(tool_messages)
    for message in g2_content_only:
        if isinstance(message.get("content"), list):
            message["content"] = "\n".join(
                part["text"] for part in message["content"])
    g2_rendered = tok.apply_chat_template(
        g2_content_only, tools=tools, tokenize=False, add_generation_prompt=True)
    check("G2 content-only rendering differs from pinned vLLM",
          g2_rendered != vllm_rendered)
    check("patched rendering equals pinned vLLM", patched_rendered == vllm_rendered)
    check("patched token ids equal pinned vLLM",
          tok.encode(patched_rendered, add_special_tokens=False)
          == tok.encode(vllm_rendered, add_special_tokens=False))
    check("tool arguments are decoded to an object",
          flatten(deepcopy(tool_messages))[2]["tool_calls"][0]["function"]["arguments"]
          == {"city": "Paris"})

    print("\nTest 5: None content matches pinned vLLM and Granite exactly")
    plain = [{"role": "user", "content": "hi"},
             {"role": "assistant", "content": None},
             {"role": "tool", "content": "ok", "tool_call_id": "1"},
             {"role": "assistant"}]
    original_plain = deepcopy(plain)
    expected_plain = deepcopy(plain)
    expected_plain[1]["content"] = ""
    expected_plain[3]["content"] = ""
    check("explicit and missing None become the empty string",
          flatten(deepcopy(plain)) == expected_plain)
    check("None normalization does not mutate its input", plain == original_plain)

    granite_tok = AutoTokenizer.from_pretrained(
        GRANITE_SNAPSHOT, local_files_only=True, trust_remote_code=False)
    granite_tools = [{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get weather.",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    }]
    granite_messages = [
        {"role": "system", "content": "Assist."},
        {"role": "user", "content": "Find Paris."},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "1", "type": "function",
                         "function": {"name": "get_weather",
                                      "arguments": json.dumps(
                                          {"city": "Paris"})}}]},
        {"role": "tool", "content": "sunny", "tool_call_id": "1"},
    ]
    granite_config = ModelConfig(
        model=GRANITE_SNAPSHOT, task="auto", tokenizer=GRANITE_SNAPSHOT,
        tokenizer_mode="auto", trust_remote_code=False, dtype="auto", seed=0,
        max_model_len=16384, chat_template_text_format="string")
    granite_conversation, _ = parse_chat_messages(
        deepcopy(granite_messages), granite_config, granite_tok)
    expected_granite_conversation = deepcopy(granite_messages)
    expected_granite_conversation[2]["content"] = ""
    expected_granite_conversation[2]["tool_calls"][0]["function"][
        "arguments"] = {"city": "Paris"}
    check("pinned vLLM normalizes Granite None and tool arguments",
          granite_conversation == expected_granite_conversation)
    try:
        granite_tok.apply_chat_template(
            deepcopy(granite_messages), tools=granite_tools, tokenize=False,
            add_generation_prompt=True)
        check("raw Granite None path raises TypeError", False,
              "it did not raise")
    except TypeError as exc:
        check("raw Granite None path raises TypeError",
              "NoneType" in str(exc), str(exc)[:90])
    granite_input = deepcopy(granite_messages)
    granite_patched = flatten(granite_input)
    check("Granite normalizer is non-mutating",
          granite_input == granite_messages)
    check("Granite normalized conversation equals pinned vLLM",
          granite_patched == granite_conversation)
    granite_vllm_rendered = apply_hf_chat_template(
        granite_tok, conversation=granite_conversation, chat_template=None,
        tools=granite_tools, tokenize=False, add_generation_prompt=True,
        continue_final_message=False)
    granite_patched_rendered = granite_tok.apply_chat_template(
        granite_patched, tools=granite_tools, tokenize=False,
        add_generation_prompt=True)
    granite_vllm_ids = granite_tok.encode(
        granite_vllm_rendered, add_special_tokens=False)
    granite_patched_ids = granite_tok.encode(
        granite_patched_rendered, add_special_tokens=False)
    check("Granite rendered string equals pinned vLLM",
          granite_patched_rendered == granite_vllm_rendered)
    check("Granite token ids equal pinned vLLM",
          granite_patched_ids == granite_vllm_ids)
    check("Granite rendered fixture digest is pinned",
          hashlib.sha256(granite_vllm_rendered.encode("utf-8")).hexdigest()
          == "0987f17f124f5c021b79eff644deea621877c736be71005562fe988944475929")
    check("Granite rendered fixture has 121 tokens",
          len(granite_vllm_ids) == 121)

    print("\nTest 6: it fails closed on a part it cannot reproduce")
    bad = [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]
    try:
        flatten(bad)
        check("non-text part is refused", False, "it was silently accepted")
    except RuntimeError as exc:
        check("non-text part is refused", "non-text content part" in str(exc),
              str(exc)[:90])

    print("\nTest 7: malformed tool arguments fail closed")
    malformed = deepcopy(tool_messages)
    malformed[2]["tool_calls"][0]["function"]["arguments"] = "{not-json"
    try:
        flatten(malformed)
        check("malformed tool arguments are refused", False, "they were accepted")
    except RuntimeError as exc:
        check("malformed tool arguments are refused",
              "not valid JSON" in str(exc), str(exc)[:90])

    print(f"\n{len(FAILURES)} failure(s)" if FAILURES else "\nALL PASS")
    for name in FAILURES:
        print(f"  FAILED: {name}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
