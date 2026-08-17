"""CPU-only contract tests for the optional v2 Transformers backend.

These tests use tiny fakes deliberately: loading a real model belongs to the
GPU pilot, while the unit suite should still catch interface drift, accidental
output repair, and loss of deterministic generation parameters.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import types
from contextlib import nullcontext
from pathlib import Path

import pytest

from backends_transformers import TransformersConstrainedBackend, _major_version


class _FakeTokenizer:
    def encode(self, value, add_special_tokens=False):
        assert add_special_tokens is False
        return list(range(max(1, len(value.split("_")))))


class _FakeGenerator:
    def __init__(self, output):
        self.output = output
        self.calls = []

    def __call__(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.output


class _FakeOutlines:
    class inputs:
        @staticmethod
        def Chat(messages):
            return {"messages": messages}

    def __init__(self, output="alpha"):
        self.output = output
        self.generator_calls = []

    def Generator(self, model, output_type, backend=None):
        generator = _FakeGenerator(self.output)
        self.generator_calls.append((model, output_type, backend, generator))
        return generator


class _FakeTorch:
    @staticmethod
    def inference_mode():
        return nullcontext()


def _fake_backend(output="alpha"):
    backend = TransformersConstrainedBackend.__new__(TransformersConstrainedBackend)
    backend._torch = _FakeTorch()
    backend._outlines = _FakeOutlines(output)
    backend._model = object()
    backend._tokenizer = _FakeTokenizer()
    backend._generators = {}
    backend._max_new_tokens = {}
    backend._decode_lock = threading.RLock()
    return backend


def test_decode_matches_v2_contract_and_caches_generator():
    backend = _fake_backend("alpha")

    assert backend.decode("untrusted", ("alpha", "beta_value")) == "alpha"
    assert backend.decode("different content", ("alpha", "beta_value")) == "alpha"

    assert len(backend._outlines.generator_calls) == 1
    _, _, grammar_backend, generator = backend._outlines.generator_calls[0]
    assert grammar_backend == "outlines_core"
    assert len(generator.calls) == 2
    _, kwargs = generator.calls[0]
    assert kwargs == {
        "do_sample": False,
        "num_beams": 1,
        "num_return_sequences": 1,
        "repetition_penalty": 1.0,
        "max_new_tokens": 8,
        "use_cache": True,
        "temperature": None,
        "top_k": None,
        "top_p": None,
    }


def test_decode_returns_exact_backend_text_without_repair():
    backend = _fake_backend(" alpha ")
    assert backend.decode("content", ("alpha", "beta")) == " alpha "


@pytest.mark.parametrize(
    ("symbols", "message"),
    [
        ((), "empty alphabet"),
        (("",), "non-empty"),
        (("alpha", "alpha"), "unique"),
    ],
)
def test_decode_rejects_invalid_alphabet(symbols, message):
    backend = _fake_backend()
    with pytest.raises(ValueError, match=message):
        backend.decode("content", symbols)


def test_transformers_major_version_parser():
    assert _major_version("5.13.0") == 5
    assert _major_version("4.40.1.dev0") == 4
    assert _major_version("unknown") == 0


def test_git_metadata_resolver_supports_linked_worktrees(tmp_path):
    pilot_path = Path(__file__).resolve().parents[2] / "experiments" / "real_pilot_v2.py"
    spec = importlib.util.spec_from_file_location("real_pilot_v2_git_testmodule", pilot_path)
    assert spec is not None and spec.loader is not None
    pilot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pilot)

    common = tmp_path / "main.git"
    per_worktree = common / "worktrees" / "pilot"
    per_worktree.mkdir(parents=True)
    branch_ref = common / "refs" / "heads" / "codex"
    branch_ref.mkdir(parents=True)
    commit = "a" * 40
    (branch_ref / "hardening").write_text(commit + "\n", encoding="ascii")
    (per_worktree / "HEAD").write_text(
        "ref: refs/heads/codex/hardening\n", encoding="ascii"
    )
    (per_worktree / "commondir").write_text("../..\n", encoding="ascii")

    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / ".git").write_text(
        f"gitdir: {per_worktree}\n", encoding="utf-8"
    )
    assert pilot._head_from_git_metadata(linked) == commit


def test_pilot_artifact_flow_with_fake_backend(tmp_path, monkeypatch):
    """Exercise monitor/storage/artifact integration without loading a model."""
    pilot_path = Path(__file__).resolve().parents[2] / "experiments" / "real_pilot_v2.py"
    spec = importlib.util.spec_from_file_location("real_pilot_v2_testmodule", pilot_path)
    assert spec is not None and spec.loader is not None
    pilot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pilot)

    class FakeCuda:
        @staticmethod
        def is_available():
            return False

        @staticmethod
        def device_count():
            return 0

    class FakeCudnn:
        @staticmethod
        def version():
            return None

    class FakePilotTorch:
        __version__ = "fake"
        cuda = FakeCuda()
        version = types.SimpleNamespace(cuda=None)
        backends = types.SimpleNamespace(cudnn=FakeCudnn())

    class FakePilotBackend:
        def __init__(self, model, *, revision, device, dtype, local_files_only, seed):
            self._torch = FakePilotTorch()
            self._revision = revision

        def decode(self, content, symbol_values):
            return symbol_values[0]

        def provenance(self):
            return {
                "model_id": "fake/model",
                "requested_revision": self._revision,
                "resolved_revision": self._revision,
                "prompt_template_sha256": "0" * 64,
            }

        def generation_parameters(self, symbol_values):
            return {"do_sample": False, "max_new_tokens": 8}

    monkeypatch.setitem(
        sys.modules,
        "backends_transformers",
        types.SimpleNamespace(TransformersConstrainedBackend=FakePilotBackend),
    )
    monkeypatch.setattr(
        pilot,
        "_gpu_snapshot",
        lambda: {"available": False, "gpus": [], "compute_process_count": 0},
    )
    # Captured GPU-node provenance shows that Git is not on PATH there.  The
    # pilot must still resolve the shared checkout's commit from .git metadata.
    monkeypatch.setattr(pilot, "_run_text", lambda command, cwd=None: None)
    output_root = tmp_path / "artifacts"
    revision = "a" * 40
    status = pilot.main([
        "--model", "fake/model",
        "--revision", revision,
        "--device", "cpu",
        "--expected-git-head", pilot._head_from_git_metadata(pilot.REPO_ROOT),
        "--output-root", str(output_root),
    ])

    assert status == 0
    run_dirs = list(output_root.iterdir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    result = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    assert result["status"] == "complete"
    assert result["summary"]["security_checks_passed"] is True
    assert result["summary"]["audit_linkage_valid"] is True
    assert result["summary"]["total_cases"] == 5
    assert result["summary"]["final_spent_units"] == 15_000_000
    assert result["summary"]["lifetime_spent_units"] == 15_000_000
    assert all(row["authorized_cost_units"] == 3_000_000 for row in result["results"])
    assert all(row["charged_units"] == 3_000_000 for row in result["results"])
    assert result["source"]["git"]["head_source"] == "git_metadata"
    assert len(result["source"]["git"]["head"]) == 40
    assert result["source"]["cleanliness_attestation"] == (
        "external_clean_check_plus_expected_head_and_source_hashes"
    )
    assert all("content" not in row for row in result["results"])
    assert (run_dir / "monitor.sqlite3").is_file()
    assert (run_dir / "events.jsonl").is_file()
    assert (run_dir / "SHA256SUMS.json").is_file()
