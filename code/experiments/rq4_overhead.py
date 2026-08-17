"""RQ4: repeated reference-monitor latency benchmark with raw artifacts.

The paper profile compares an explicit persistent root with an explicit
tmpfs root.  Each configuration/repetition receives a fresh UUID-named
temporary directory, so concurrent launches cannot collide.  FULL, NORMAL,
and OFF SQLite synchronous modes are measured for ``author_gate+invoke``;
every configuration explicitly fixes ``journal_mode=WAL``.  This is a named
benchmark profile, not the ``DurableStore`` default (``DELETE/FULL``) or a
WAL-on-NFS deployment recommendation.
FULL additionally receives ``author_only`` and ``invoke_only`` phase
ablations.  Warm-up runs use separate databases and are never included in
the raw timing samples.

Example on eval-host-a (where /tmp is tmpfs and <HOME_PARENT> is NFSv4):

    python rq4_overhead.py \
      --tmpfs-root /tmp \
      --persistent-root <HOME>/rq4-persistent
"""

from __future__ import annotations

import argparse
import errno
import gzip
import hashlib
import json
import math
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sluice_v2"))

from monitor import Direction, MockBackend, Outcome, ReferenceMonitor, Symbol  # noqa: E402
from store import DurableStore  # noqa: E402

SYNCHRONOUS_MODES = ("FULL", "NORMAL", "OFF")
JOURNAL_MODES = ("WAL", "DELETE")
OPERATIONS = ("author_invoke", "author_only", "invoke_only")
SYNC_NUMERIC_NAMES = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
BENCHMARK_CAP_BITS = 1_000_000_000.0
PERCENTILE_METHOD = "nearest-rank (ceil(p*n)-1)"


class BenchmarkRepetitionError(RuntimeError):
    """A real measurement/finalization failure with cleanup context."""

    def __init__(
        self,
        stage: str,
        original: Exception,
        cleanup_warning: Optional[dict[str, Any]],
    ) -> None:
        super().__init__(str(original))
        self.stage = stage
        self.original = original
        self.cleanup_warning = cleanup_warning


def nearest_rank(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("cannot compute a percentile of an empty sample")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0, 1]")
    index = max(0, min(len(sorted_values) - 1, math.ceil(probability * len(sorted_values)) - 1))
    return float(sorted_values[index])


def summarize_latencies(latency_ns: Sequence[int]) -> dict[str, Any]:
    if not latency_ns:
        raise ValueError("at least one latency sample is required")
    sorted_ms = sorted(value / 1_000_000.0 for value in latency_ns)
    return {
        "n_samples": len(sorted_ms),
        "mean_ms": statistics.fmean(sorted_ms),
        "median_ms": statistics.median(sorted_ms),
        "stdev_ms": statistics.stdev(sorted_ms) if len(sorted_ms) > 1 else 0.0,
        "p50_ms": nearest_rank(sorted_ms, 0.50),
        "p95_ms": nearest_rank(sorted_ms, 0.95),
        "p99_ms": nearest_rank(sorted_ms, 0.99),
        "minimum_ms": sorted_ms[0],
        "maximum_ms": sorted_ms[-1],
        "percentile_method": PERCENTILE_METHOD,
    }


def _run_command(command: list[str], cwd: Optional[Path] = None) -> Optional[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def git_provenance() -> dict[str, Any]:
    commit = _run_command(["git", "rev-parse", "HEAD"], cwd=HERE.parent)
    status = _run_command(["git", "status", "--porcelain"], cwd=HERE.parent)
    return {
        "git_commit": commit,
        "git_dirty": None if status is None else bool(status),
    }


def storage_metadata(root: Path) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    stat_result = resolved.stat()
    metadata: dict[str, Any] = {
        "requested_path": str(root),
        "resolved_path": str(resolved),
        "device_id": stat_result.st_dev,
    }
    findmnt = _run_command(
        ["findmnt", "-T", str(resolved), "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]
    )
    if findmnt:
        try:
            filesystems = json.loads(findmnt).get("filesystems", [])
            if filesystems:
                metadata["mount"] = filesystems[0]
        except json.JSONDecodeError:
            metadata["findmnt_raw"] = findmnt
    return metadata


def validate_storage_profiles(
    storage_profiles: dict[str, Path],
    require_distinct_filesystems: bool,
) -> dict[str, dict[str, Any]]:
    if not storage_profiles:
        raise ValueError("at least one storage profile is required")
    metadata: dict[str, dict[str, Any]] = {}
    for name, root in storage_profiles.items():
        if not name or not root.exists() or not root.is_dir():
            raise ValueError(f"storage root for {name!r} must be an existing directory")
        if not os.access(root, os.W_OK):
            raise ValueError(f"storage root for {name!r} is not writable")
        metadata[name] = storage_metadata(root)

    resolved_paths = [item["resolved_path"] for item in metadata.values()]
    if len(set(resolved_paths)) != len(resolved_paths):
        raise ValueError("storage profiles must use distinct resolved paths")
    if require_distinct_filesystems:
        device_ids = [item["device_id"] for item in metadata.values()]
        if len(set(device_ids)) != len(device_ids):
            raise ValueError(
                "persistent and tmpfs profiles resolve to the same filesystem device"
            )
    return metadata


def _config_id(profile: str, journal_mode: str, synchronous: str, operation_suffix: str) -> str:
    # WAL is the profile every existing (frozen) config_id was named under, so
    # it stays unprefixed; only a non-WAL journal mode adds a segment. This
    # keeps every default-invocation config_id byte-identical to the original
    # WAL-only benchmark.
    journal_segment = "" if journal_mode == "WAL" else f"{journal_mode.lower()}-"
    return f"{profile}-{journal_segment}{synchronous.lower()}-{operation_suffix}"


def build_configurations(
    profile_names: Sequence[str],
    synchronous_modes: Sequence[str] = SYNCHRONOUS_MODES,
    include_phase_ablation: bool = True,
    journal_modes: Sequence[str] = ("WAL",),
) -> list[dict[str, str]]:
    modes = [mode.upper() for mode in synchronous_modes]
    unknown = sorted(set(modes) - set(SYNCHRONOUS_MODES))
    if unknown:
        raise ValueError(f"unsupported SQLite synchronous modes: {unknown}")
    journals = [mode.upper() for mode in journal_modes]
    unknown_journals = sorted(set(journals) - set(JOURNAL_MODES))
    if unknown_journals:
        raise ValueError(f"unsupported SQLite journal modes: {unknown_journals}")
    configurations = [
        {
            "profile": profile,
            "journal_mode": journal,
            "synchronous": synchronous,
            "operation": "author_invoke",
            "config_id": _config_id(profile, journal, synchronous, "author-invoke"),
        }
        for profile in profile_names
        for journal in journals
        for synchronous in modes
    ]
    if include_phase_ablation:
        configurations.extend(
            {
                "profile": profile,
                "journal_mode": journal,
                "synchronous": "FULL",
                "operation": operation,
                "config_id": _config_id(
                    profile, journal, "FULL", operation.replace("_", "-")
                ),
            }
            for profile in profile_names
            for journal in journals
            for operation in ("author_only", "invoke_only")
        )
    return configurations


def effective_sqlite_pragmas(
    store: DurableStore, requested_mode: str, requested_journal_mode: str = "WAL"
) -> dict[str, Any]:
    """Read back benchmark PRAGMAs after validating the requested value.

    DurableStore's validated constructor applies the requested ablation mode;
    this function independently records what SQLite actually accepted.
    """
    mode = requested_mode.upper()
    if mode not in SYNCHRONOUS_MODES:
        raise ValueError(f"unsupported SQLite synchronous mode {requested_mode!r}")
    journal_mode = requested_journal_mode.upper()
    if journal_mode not in JOURNAL_MODES:
        raise ValueError(f"unsupported SQLite journal mode {requested_journal_mode!r}")
    effective = store.effective_pragmas()
    effective_sync_number = int(effective["synchronous"])
    effective_journal = str(effective["journal_mode"]).upper()
    effective_sync_name = SYNC_NUMERIC_NAMES.get(
        effective_sync_number, f"UNKNOWN_{effective_sync_number}"
    )
    if effective_journal != journal_mode:
        raise RuntimeError(
            f"SQLite did not accept requested journal_mode={journal_mode} "
            f"(effective={effective_journal})"
        )
    if effective_sync_name != mode:
        raise RuntimeError(
            f"SQLite did not accept requested synchronous={mode} "
            f"(effective={effective_sync_name})"
        )
    return {
        "requested_synchronous": mode,
        "effective_synchronous_number": effective_sync_number,
        "effective_synchronous": effective_sync_name,
        "requested_journal_mode": journal_mode,
        "effective_journal_mode": effective_journal,
    }


def _author_gate(monitor: ReferenceMonitor, gate_id: str, symbols: list[Symbol]):
    return monitor.author_gate(
        gate_id,
        "rq4-benchmark",
        "rq4-benchmark-object",
        Direction.ENDORSE,
        symbols,
        "benchmark_planner",
        frozenset({"benchmark_agent"}),
        cap_bits=BENCHMARK_CAP_BITS,
    )


def _cleanup_benchmark_directory(
    path: Path,
    *,
    attempts: int = 8,
    initial_delay_seconds: float = 0.05,
) -> Optional[dict[str, Any]]:
    """Remove a closed benchmark database without invalidating measurements.

    NFS can briefly retain an unlinked, still-closing SQLite file as ``.nfs*``
    and report ``EBUSY`` from ``rmtree``.  Directory deletion occurs after all
    timed calls and audit verification, so a residual cleanup problem is
    artifact-hygiene metadata rather than a failed latency repetition.
    """
    if attempts < 1:
        raise ValueError("cleanup attempts must be positive")
    last_error: Optional[OSError] = None
    attempts_used = 0
    for attempt in range(attempts):
        attempts_used = attempt + 1
        try:
            shutil.rmtree(path)
            return None
        except FileNotFoundError as exc:
            if not path.exists():
                return None
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(initial_delay_seconds * (2**attempt))
                continue
            break
        except OSError as exc:
            last_error = exc
            if exc.errno not in {errno.EBUSY, errno.ENOTEMPTY}:
                break
            if attempt + 1 < attempts:
                time.sleep(initial_delay_seconds * (2**attempt))
    assert last_error is not None
    return {
        "exception_type": type(last_error).__name__,
        "errno": last_error.errno,
        "message": str(last_error),
        "attempts": attempts_used,
        "max_attempts": attempts,
        "path_id": path.name,
    }


def measure_repetition(
    storage_root: Path,
    synchronous: str,
    operation: str,
    n_calls: int,
    journal_mode: str = "WAL",
) -> dict[str, Any]:
    if operation not in OPERATIONS:
        raise ValueError(f"unsupported benchmark operation {operation!r}")
    if n_calls < 1:
        raise ValueError("n_calls must be positive")

    unique_prefix = f"sluice-rq4-{uuid.uuid4().hex}-"
    temp_path = Path(tempfile.mkdtemp(prefix=unique_prefix, dir=storage_root))
    temporary_directory_id = temp_path.name
    db_path = temp_path / "monitor.db"
    store: Optional[DurableStore] = None
    cleanup_warning: Optional[dict[str, Any]] = None
    measurement_error: Optional[BaseException] = None
    close_error: Optional[BaseException] = None
    try:
        store = DurableStore(str(db_path), journal_mode=journal_mode, synchronous=synchronous)
        pragmas = effective_sqlite_pragmas(store, synchronous, journal_mode)
        monitor = ReferenceMonitor(
            store,
            MockBackend(),
            default_cap_bits=BENCHMARK_CAP_BITS,
            max_cardinality=8,
            trusted_planner_identities=frozenset({"benchmark_planner"}),
        )
        symbols = [Symbol(f"v{index}") for index in range(8)]

        handles = []
        if operation == "invoke_only":
            handles = [
                _author_gate(monitor, f"g-{index}", symbols)
                for index in range(n_calls)
            ]

        latency_ns: list[int] = []
        loop_started_ns = time.perf_counter_ns()
        for index in range(n_calls):
            sample_started_ns = time.perf_counter_ns()
            if operation == "author_invoke":
                handle = _author_gate(monitor, f"g-{index}", symbols)
                observation = monitor.invoke(
                    handle, "content says v0", "benchmark_agent"
                )
                if observation.outcome != Outcome.OK:
                    raise RuntimeError(
                        f"benchmark invocation returned {observation.outcome.value!r}"
                    )
            elif operation == "author_only":
                _author_gate(monitor, f"g-{index}", symbols)
            else:
                observation = monitor.invoke(
                    handles[index], "content says v0", "benchmark_agent"
                )
                if observation.outcome != Outcome.OK:
                    raise RuntimeError(
                        f"benchmark invocation returned {observation.outcome.value!r}"
                    )
            latency_ns.append(time.perf_counter_ns() - sample_started_ns)
        loop_elapsed_ns = time.perf_counter_ns() - loop_started_ns
        audit_linkage_valid = store.verify_audit_chain()
    except BaseException as exc:
        measurement_error = exc
    finally:
        try:
            if store is not None:
                try:
                    store.close()
                except BaseException as exc:
                    close_error = exc
        finally:
            cleanup_warning = _cleanup_benchmark_directory(temp_path)

    if measurement_error is not None:
        if not isinstance(measurement_error, Exception):
            raise measurement_error
        raise BenchmarkRepetitionError(
            "measurement", measurement_error, cleanup_warning
        ) from measurement_error
    if close_error is not None:
        if not isinstance(close_error, Exception):
            raise close_error
        raise BenchmarkRepetitionError(
            "store_close", close_error, cleanup_warning
        ) from close_error

    return {
        "latency_ns": latency_ns,
        "loop_elapsed_ns": loop_elapsed_ns,
        "calls_per_second": n_calls / (loop_elapsed_ns / 1_000_000_000.0),
        "sqlite_pragmas": pragmas,
        "audit_linkage_valid": audit_linkage_valid,
        "temporary_directory_id": temporary_directory_id,
        "cleanup_warning": cleanup_warning,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _across_repetitions(per_repetition: Sequence[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for field in ("mean_ms", "median_ms", "p95_ms", "p99_ms", "calls_per_second"):
        values = [float(repetition[field]) for repetition in per_repetition]
        output[field] = {
            "median": statistics.median(values),
            "minimum": min(values),
            "maximum": max(values),
        }
    return output


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_benchmark(
    storage_profiles: dict[str, Path],
    output_root: Path,
    n_calls: int = 5000,
    warmup_calls: int = 500,
    repetitions: int = 5,
    synchronous_modes: Sequence[str] = SYNCHRONOUS_MODES,
    include_phase_ablation: bool = True,
    seed: int = 2701,
    require_distinct_filesystems: bool = True,
    journal_modes: Sequence[str] = ("WAL",),
) -> dict[str, Any]:
    if n_calls < 1 or warmup_calls < 0 or repetitions < 1:
        raise ValueError("calls and repetitions must be positive; warmup may be zero")
    storage_info = validate_storage_profiles(
        storage_profiles, require_distinct_filesystems=require_distinct_filesystems
    )
    configurations = build_configurations(
        list(storage_profiles),
        synchronous_modes,
        include_phase_ablation,
        journal_modes=journal_modes,
    )

    now = datetime.now(timezone.utc)
    run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{platform.node()}-{uuid.uuid4().hex[:10]}"
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    raw_path = run_dir / "samples.jsonl.gz"
    manifest_path = run_dir / "manifest.json"
    summary_path = run_dir / "summary.json"

    run_started = time.time()
    results_by_config: dict[str, dict[str, Any]] = {
        config["config_id"]: {
            **config,
            "per_repetition": [],
            "errors": [],
            "cleanup_warnings": [],
        }
        for config in configurations
    }
    execution_order: list[dict[str, Any]] = []
    raw_sample_count = 0

    with gzip.open(raw_path, "wt", encoding="utf-8") as raw_stream:
        for repetition in range(repetitions):
            ordered = list(configurations)
            random.Random(seed + repetition).shuffle(ordered)
            for order_index, config in enumerate(ordered):
                execution_order.append(
                    {
                        "repetition": repetition,
                        "order_index": order_index,
                        "config_id": config["config_id"],
                    }
                )
                profile_root = storage_profiles[config["profile"]]
                current_phase = "warmup"
                try:
                    if warmup_calls:
                        warmup = measure_repetition(
                            profile_root,
                            config["synchronous"],
                            config["operation"],
                            warmup_calls,
                            journal_mode=config["journal_mode"],
                        )
                        if warmup["cleanup_warning"] is not None:
                            results_by_config[config["config_id"]][
                                "cleanup_warnings"
                            ].append(
                                {
                                    "repetition": repetition,
                                    "phase": "warmup",
                                    **warmup["cleanup_warning"],
                                }
                            )
                    current_phase = "measured"
                    measured = measure_repetition(
                        profile_root,
                        config["synchronous"],
                        config["operation"],
                        n_calls,
                        journal_mode=config["journal_mode"],
                    )
                except Exception as exc:  # noqa: BLE001 - preserve partial benchmark artifacts
                    error = {
                        "repetition": repetition,
                        "phase": current_phase,
                        "exception_type": type(exc).__name__,
                        "message": str(exc),
                    }
                    if isinstance(exc, BenchmarkRepetitionError):
                        error.update(
                            {
                                "stage": exc.stage,
                                "exception_type": type(exc.original).__name__,
                                "message": str(exc.original),
                            }
                        )
                        if exc.cleanup_warning is not None:
                            results_by_config[config["config_id"]][
                                "cleanup_warnings"
                            ].append(
                                {
                                    "repetition": repetition,
                                    "phase": current_phase,
                                    "measurement_failed": True,
                                    **exc.cleanup_warning,
                                }
                            )
                    results_by_config[config["config_id"]]["errors"].append(error)
                    continue

                latency_summary = summarize_latencies(measured["latency_ns"])
                repetition_summary = {
                    "repetition": repetition,
                    **latency_summary,
                    "calls_per_second": measured["calls_per_second"],
                    "loop_elapsed_ns": measured["loop_elapsed_ns"],
                    "sqlite_pragmas": measured["sqlite_pragmas"],
                    "audit_linkage_valid": measured["audit_linkage_valid"],
                    "temporary_directory_id": measured["temporary_directory_id"],
                }
                results_by_config[config["config_id"]]["per_repetition"].append(
                    repetition_summary
                )
                if measured["cleanup_warning"] is not None:
                    results_by_config[config["config_id"]]["cleanup_warnings"].append(
                        {
                            "repetition": repetition,
                            "phase": "measured",
                            **measured["cleanup_warning"],
                        }
                    )

                for sample_index, latency in enumerate(measured["latency_ns"]):
                    raw_stream.write(
                        json.dumps(
                            {
                                "schema_version": "sluice.rq4.sample.v2",
                                "run_id": run_id,
                                "config_id": config["config_id"],
                                "profile": config["profile"],
                                "journal_mode": config["journal_mode"],
                                "synchronous": config["synchronous"],
                                "operation": config["operation"],
                                "repetition": repetition,
                                "sample_index": sample_index,
                                "latency_ns": latency,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    raw_sample_count += 1

    run_finished = time.time()
    configuration_summaries = []
    for config in configurations:
        entry = results_by_config[config["config_id"]]
        per_repetition = entry["per_repetition"]
        configuration_summaries.append(
            {
                **entry,
                "completed_repetitions": len(per_repetition),
                "expected_repetitions": repetitions,
                "across_repetitions": _across_repetitions(per_repetition)
                if per_repetition
                else None,
            }
        )

    raw_sha256 = _sha256_file(raw_path)
    summary = {
        "schema_version": "sluice.rq4.summary.v4",
        "experiment_id": "rq4_reference_monitor_overhead",
        "run_id": run_id,
        "raw_samples": {
            "path": raw_path.name,
            "sha256": raw_sha256,
            "count": raw_sample_count,
        },
        "configurations": configuration_summaries,
    }
    _write_json(summary_path, summary)
    summary_sha256 = _sha256_file(summary_path)
    manifest = {
        "schema_version": "sluice.rq4.manifest.v4",
        "experiment_id": "rq4_reference_monitor_overhead",
        "run_id": run_id,
        "provenance": {
            **git_provenance(),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": sys.version,
            "argv": list(sys.argv),
            "working_directory": os.getcwd(),
            "logical_cpu_count": os.cpu_count(),
            "load_average_at_manifest": list(os.getloadavg())
            if hasattr(os, "getloadavg")
            else None,
            "pid": os.getpid(),
            "perf_counter": "time.perf_counter_ns",
            "started_at_unix": run_started,
            "finished_at_unix": run_finished,
            "started_at_utc": datetime.fromtimestamp(
                run_started, timezone.utc
            ).isoformat(),
            "finished_at_utc": datetime.fromtimestamp(
                run_finished, timezone.utc
            ).isoformat(),
        },
        "parameters": {
            "n_calls": n_calls,
            "warmup_calls": warmup_calls,
            "repetitions": repetitions,
            "synchronous_modes": [mode.upper() for mode in synchronous_modes],
            "journal_modes": [mode.upper() for mode in journal_modes],
            "include_phase_ablation": include_phase_ablation,
            "seed": seed,
            "config_order_randomized_per_repetition": True,
            "percentile_method": PERCENTILE_METHOD,
            "benchmark_cap_bits": BENCHMARK_CAP_BITS,
        },
        "storage_profiles": storage_info,
        "execution_order": execution_order,
        "artifacts": {
            "summary": summary_path.name,
            "summary_sha256": summary_sha256,
            "raw_samples": raw_path.name,
            "raw_samples_sha256": raw_sha256,
        },
    }
    _write_json(manifest_path, manifest)
    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "manifest_path": str(manifest_path),
        "summary_path": str(summary_path),
        "raw_samples_path": str(raw_path),
        "summary": summary,
        "manifest": manifest,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tmpfs-root", type=Path, default=Path("/tmp"))
    parser.add_argument(
        "--persistent-root",
        type=Path,
        required=True,
        help="existing writable persistent directory (explicit; never inferred)",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=HERE / "results" / "rq4",
    )
    parser.add_argument("--calls", type=int, default=5000)
    parser.add_argument("--warmup-calls", type=int, default=500)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument(
        "--synchronous-modes",
        nargs="+",
        default=list(SYNCHRONOUS_MODES),
    )
    parser.add_argument("--seed", type=int, default=2701)
    parser.add_argument(
        "--no-phase-ablation",
        action="store_true",
        help="measure only author_gate+invoke",
    )
    parser.add_argument(
        "--allow-same-filesystem",
        action="store_true",
        help="diagnostic/smoke runs only; invalid for paper measurements",
    )
    parser.add_argument(
        "--journal-modes",
        nargs="+",
        default=["WAL"],
        help=(
            "SQLite journal modes to sweep, e.g. 'WAL' (paper profile) or "
            "'DELETE' (DurableStore's production default, synchronous=FULL "
            "only unless combined with --synchronous-modes)"
        ),
    )
    args = parser.parse_args(argv)

    result = run_benchmark(
        storage_profiles={
            "tmpfs": args.tmpfs_root,
            "persistent": args.persistent_root,
        },
        output_root=args.output_root,
        n_calls=args.calls,
        warmup_calls=args.warmup_calls,
        repetitions=args.repetitions,
        synchronous_modes=args.synchronous_modes,
        journal_modes=args.journal_modes,
        include_phase_ablation=not args.no_phase_ablation,
        seed=args.seed,
        require_distinct_filesystems=not args.allow_same_filesystem,
    )
    print(f"RQ4 artifacts: {result['run_dir']}")
    failed = [
        config
        for config in result["summary"]["configurations"]
        if config["completed_repetitions"] != config["expected_repetitions"]
    ]
    if failed:
        print(f"ERROR: {len(failed)} configuration(s) were incomplete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
