"""Recompute G8 primary estimates and frozen bootstrap from derived terminals.

This statistical reconstruction does not authenticate original hash chains.
Use the original result inventory for raw-evidence integrity verification.
"""
import argparse
import csv
import gzip
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path


def yes(x):
    return x == "True"


def cells(rows, endpoint):
    values = defaultdict(list)
    for r in rows:
        if r["partition"] != "heldout" or r["stratum"] != ("attacked" if endpoint == "h4" else "benign"):
            continue
        value = (yes(r["security"]) or yes(r["error"])) if endpoint == "h4" else (
            yes(r["utility"]) and yes(r["parsed_tool_call"]) and not yes(r["error"]))
        key = (r["suite"], r["user_task"], r["injection_task"])
        values[(key, r["condition"])].append(float(value))
    result = {}
    for key in sorted({k[0] for k in values}):
        u = values[(key, "undefended")]
        t = values[(key, "sluice_nonoracle")]
        if len(u) != 15 or len(t) != 15:
            raise ValueError("unbalanced model/seed cell")
        result[key] = {"u": statistics.fmean(u), "t": statistics.fmean(t),
                       "delta": statistics.fmean(t) - statistics.fmean(u)}
    return result


def macro(table, field):
    suites = sorted({x[0] for x in table})
    return statistics.fmean(statistics.fmean(v[field] for k, v in table.items() if k[0] == s) for s in suites)


def interval(table, endpoint, count=10000):
    rng = random.Random(8675309 if endpoint == "h4" else 8675410)
    suites = sorted({x[0] for x in table})
    tables = {s: {(k[1], k[2]): v["delta"] for k, v in table.items() if k[0] == s} for s in suites}
    axes = {s: (sorted({k[0] for k in t}), sorted({k[1] for k in t})) for s, t in tables.items()}
    draws = []
    for _ in range(count):
        values = []
        for s in suites:
            t = tables[s]
            users, injections = axes[s]
            if endpoint == "h4":
                uw = Counter(rng.choice(users) for _ in users)
                iw = Counter(rng.choice(injections) for _ in injections)
                numerator, denominator = 0.0, 0
                for (u, i), v in t.items():
                    w = uw[u] * iw[i]
                    numerator += w * v
                    denominator += w
                values.append(numerator / denominator)
            else:
                values.append(statistics.fmean(t[(rng.choice(users), "")] for _ in users))
        draws.append(statistics.fmean(values))
    draws.sort()
    return [draws[math.ceil(q * count) - 1] for q in (.025, .975)]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results", type=Path, default=Path(__file__).resolve().parents[1] / "results/g8_20260829")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    with gzip.open(a.results / "terminal_arms.csv.gz", "rt") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != 31380 or len({r["arm_id"] for r in rows}) != 31380:
        raise ValueError("terminal count/uniqueness mismatch")
    frozen = json.loads((a.results / "c4_primary.json").read_text())
    result = {"arm_count": len(rows), "endpoints": {}, "original_raw_integrity_verified_here": False}
    for endpoint, expected in [("h4", frozen["h4_security"]["fail_closed"]),
                               ("h5", frozen["h5_utility"]["supported_primary"])]:
        table = cells(rows, endpoint)
        actual = {"undefended": macro(table, "u"), "sluice": macro(table, "t"),
                  "delta": macro(table, "delta"), "ci95": interval(table, endpoint), "cells": len(table)}
        for key, reference in [("undefended", expected["rates"]["comparator_macro"]),
                               ("sluice", expected["rates"]["treatment_macro"]),
                               ("delta", expected["rates"]["delta"])]:
            if abs(actual[key] - reference) > 1e-12:
                raise ValueError(f"{endpoint} point mismatch: {key}")
        if any(abs(x - y) > 1e-12 for x, y in zip(actual["ci95"], expected["bootstrap"]["ci95"])):
            raise ValueError(f"{endpoint} interval mismatch")
        result["endpoints"][endpoint] = actual
    result["primary_estimates_and_intervals_match"] = True
    a.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
