"""Fast regression tests for the redesigned RQ1/RQ2/RQ4 harnesses."""

from __future__ import annotations

import gzip
import errno
import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

import rq2_bound_tightness as rq2  # noqa: E402
import rq4_overhead as rq4  # noqa: E402

try:  # The lightweight local environment may omit the integration extra.
    import langgraph  # noqa: F401
except ImportError:
    rq1 = None
else:
    import rq1_undefended_vs_sluice as rq1  # noqa: E402


@pytest.mark.skipif(rq1 is None, reason="LangGraph integration dependency is not installed")
def test_rq1_uses_attack_conditional_denominator_and_matched_graph(tmp_path):
    result = rq1.run_experiment(temp_root=str(tmp_path))

    assert result["workload"] == {
        "n_cases": 5,
        "n_attack_cases": 3,
        "n_control_cases": 2,
        "classifier": "monitor.MockBackend",
    }
    assert result["paired_graph"]["shape_match"] is True
    assert set(result["paired_graph"]["shape"]["nodes"]) >= {
        "classify",
        "act",
    }

    undefended = result["metrics"]["undefended"]
    sluice = result["metrics"]["sluice"]
    assert undefended["attack_success"] == {
        "successes": 3,
        "total": 3,
        "rate": 1.0,
    }
    assert sluice["attack_success"] == {
        "successes": 0,
        "total": 3,
        "rate": 0.0,
    }
    assert undefended["clean_task_completion"]["successes"] == 2
    assert sluice["clean_task_completion"]["successes"] == 2
    assert undefended["attacked_task_completion"]["successes"] == 0
    assert sluice["attacked_task_completion"]["successes"] == 3
    assert sluice["overall_task_completion"]["successes"] == 5

    for row in result["cases"]:
        assert row["undefended"]["label"] == row["sluice"]["label"]
    assert list(tmp_path.iterdir()) == []


def test_rq2_balanced_partition_is_total_and_nearly_equal():
    candidates = tuple(range(10))
    buckets = rq2.balanced_partition(candidates, 4)
    flattened = [candidate for bucket in buckets.values() for candidate in bucket]
    sizes = [len(bucket) for bucket in buckets.values()]

    assert flattened == list(candidates)
    assert max(sizes) - min(sizes) == 1
    assert sizes == [3, 3, 2, 2]


def test_rq2_policy_stops_before_an_unaffordable_gate():
    policy = rq2.make_balanced_policy(max_cardinality=8)
    below_binary_cost = math.nextafter(rq2.gate_cost_bits(2), -math.inf)
    plan = policy(8, below_binary_cost)

    assert plan.first_arity is None
    assert plan.leaf_sizes == (8,)
    assert plan.mutual_information_bits == 0.0


def test_rq2_exact_enumeration_shannon_and_bayes(tmp_path):
    cap = 2.0 * rq2.gate_cost_bits(2)
    result = rq2.run_experiment(
        n_secrets=8,
        caps=[cap],
        cardinalities=[2],
        temp_root=str(tmp_path),
    )
    config = result["configs"][0]

    assert result["enumeration_complete"] is True
    assert config["n_secrets_evaluated"] == 8
    assert config["n_distinct_transcripts"] == 4
    assert sum(row["count"] for row in config["transcript_class_counts"]) == 8
    assert config["shannon"]["mutual_information_bits"] == pytest.approx(2.0)
    assert config["shannon"]["conditional_entropy_bits"] == pytest.approx(1.0)
    assert config["bayes"]["prior_vulnerability"]["decimal"] == pytest.approx(1 / 8)
    assert config["bayes"]["posterior_vulnerability"]["decimal"] == pytest.approx(1 / 2)
    assert config["bayes"]["min_entropy_leakage_bits"] == pytest.approx(2.0)
    assert config["budget"]["budget_exhausted_outcomes"] == 0
    assert config["shannon"]["configured_cap_bound_holds"] is True
    assert config["bayes"]["configured_cap_bound_holds"] is True
    assert config["all_audit_linkage_checks_passed"] is True
    assert all(row["secret_in_remaining"] for row in config["raw_executions"])

    # A public transcript prefix determines the next public query; the
    # policy never branches on the secret except through the observed bucket.
    queries_by_prefix: dict[tuple[tuple[str, str | None], ...], set[str]] = {}
    for execution in config["raw_executions"]:
        prefix: list[tuple[str, str | None]] = []
        for step, query in zip(execution["transcript"], execution["query_trace"]):
            queries_by_prefix.setdefault(tuple(prefix), set()).add(query["query_sha256"])
            prefix.append((step["outcome"], step["value"]))
    assert all(len(query_hashes) == 1 for query_hashes in queries_by_prefix.values())
    assert list(tmp_path.iterdir()) == []


def test_rq4_nearest_rank_percentiles():
    samples = [1.0, 2.0, 3.0, 4.0]
    assert rq4.nearest_rank(samples, 0.50) == 2.0
    assert rq4.nearest_rank(samples, 0.95) == 4.0
    assert rq4.nearest_rank(samples, 0.99) == 4.0


def test_rq4_default_factorial_has_primary_and_phase_ablations():
    configs = rq4.build_configurations(["tmpfs", "persistent"])
    assert len(configs) == 10
    assert len({config["config_id"] for config in configs}) == 10
    assert sum(config["operation"] == "author_invoke" for config in configs) == 6
    assert sum(config["operation"] == "author_only" for config in configs) == 2
    assert sum(config["operation"] == "invoke_only" for config in configs) == 2


def test_rq4_smoke_writes_raw_samples_manifest_and_cleans_databases(tmp_path):
    storage_root = tmp_path / "storage"
    output_root = tmp_path / "output"
    storage_root.mkdir()

    result = rq4.run_benchmark(
        storage_profiles={"test": storage_root},
        output_root=output_root,
        n_calls=3,
        warmup_calls=1,
        repetitions=2,
        synchronous_modes=["OFF"],
        include_phase_ablation=False,
        require_distinct_filesystems=False,
    )

    summary = result["summary"]
    config = summary["configurations"][0]
    assert config["completed_repetitions"] == 2
    assert config["errors"] == []
    assert config["cleanup_warnings"] == []
    assert summary["raw_samples"]["count"] == 6
    assert Path(result["manifest_path"]).is_file()
    assert Path(result["summary_path"]).is_file()
    assert Path(result["raw_samples_path"]).is_file()
    assert list(storage_root.iterdir()) == []

    with gzip.open(result["raw_samples_path"], "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    assert len(rows) == 6
    assert {(row["repetition"], row["sample_index"]) for row in rows} == {
        (0, 0),
        (0, 1),
        (0, 2),
        (1, 0),
        (1, 1),
        (1, 2),
    }
    assert all(row["synchronous"] == "OFF" for row in rows)
    assert all(
        repetition["sqlite_pragmas"]["effective_synchronous"] == "OFF"
        for repetition in config["per_repetition"]
    )
    assert len(
        {
            repetition["temporary_directory_id"]
            for repetition in config["per_repetition"]
        }
    ) == 2

    first_rep_ns = [row["latency_ns"] for row in rows if row["repetition"] == 0]
    recomputed = rq4.summarize_latencies(first_rep_ns)
    assert config["per_repetition"][0]["mean_ms"] == pytest.approx(
        recomputed["mean_ms"]
    )


def test_rq4_retries_transient_nfs_cleanup(monkeypatch, tmp_path):
    benchmark_dir = tmp_path / "benchmark"
    benchmark_dir.mkdir()
    (benchmark_dir / ".nfs-placeholder").write_text("open", encoding="utf-8")
    real_rmtree = rq4.shutil.rmtree
    calls = 0

    def transient_busy(path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError(errno.EBUSY, "simulated NFS close delay")
        real_rmtree(path)

    monkeypatch.setattr(rq4.shutil, "rmtree", transient_busy)
    warning = rq4._cleanup_benchmark_directory(
        benchmark_dir, attempts=2, initial_delay_seconds=0
    )

    assert warning is None
    assert calls == 2
    assert not benchmark_dir.exists()


def test_rq4_retries_disappearing_child_when_root_remains(monkeypatch, tmp_path):
    benchmark_dir = tmp_path / "benchmark"
    benchmark_dir.mkdir()
    (benchmark_dir / "still-present").write_text("data", encoding="utf-8")
    real_rmtree = rq4.shutil.rmtree
    calls = 0

    def disappearing_child(path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise FileNotFoundError(errno.ENOENT, "simulated disappearing child")
        real_rmtree(path)

    monkeypatch.setattr(rq4.shutil, "rmtree", disappearing_child)
    warning = rq4._cleanup_benchmark_directory(
        benchmark_dir, attempts=2, initial_delay_seconds=0
    )

    assert warning is None
    assert calls == 2
    assert not benchmark_dir.exists()


def test_rq4_cleanup_warning_does_not_discard_completed_measurement(
    monkeypatch, tmp_path
):
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    warning = {
        "exception_type": "OSError",
        "errno": errno.EBUSY,
        "message": "simulated residual .nfs file",
        "attempts": 8,
        "max_attempts": 8,
        "path_id": "redacted-test-id",
    }
    monkeypatch.setattr(rq4, "_cleanup_benchmark_directory", lambda path: warning)

    measured = rq4.measure_repetition(storage_root, "OFF", "author_invoke", 2)

    assert len(measured["latency_ns"]) == 2
    assert measured["audit_linkage_valid"] is True
    assert measured["cleanup_warning"] == warning

    # The monkeypatched cleanup deliberately leaves the unique database behind.
    for path in storage_root.iterdir():
        rq4.shutil.rmtree(path)


def test_rq4_persistent_cleanup_warning_is_serialized_without_sample_loss(
    monkeypatch, tmp_path
):
    storage_root = tmp_path / "storage"
    output_root = tmp_path / "output"
    storage_root.mkdir()
    real_rmtree = rq4.shutil.rmtree

    def persistently_busy(path):
        raise OSError(errno.EBUSY, "simulated persistent .nfs file")

    monkeypatch.setattr(rq4.shutil, "rmtree", persistently_busy)
    result = rq4.run_benchmark(
        storage_profiles={"test": storage_root},
        output_root=output_root,
        n_calls=2,
        warmup_calls=0,
        repetitions=1,
        synchronous_modes=["OFF"],
        include_phase_ablation=False,
        require_distinct_filesystems=False,
    )

    config = result["summary"]["configurations"][0]
    assert result["summary"]["schema_version"] == "sluice.rq4.summary.v4"
    assert result["manifest"]["schema_version"] == "sluice.rq4.manifest.v4"
    assert config["completed_repetitions"] == 1
    assert config["errors"] == []
    assert len(config["cleanup_warnings"]) == 1
    assert config["cleanup_warnings"][0]["phase"] == "measured"
    assert config["cleanup_warnings"][0]["errno"] == errno.EBUSY
    assert result["summary"]["raw_samples"]["count"] == 2

    monkeypatch.setattr(rq4.shutil, "rmtree", real_rmtree)
    for path in storage_root.iterdir():
        real_rmtree(path)
