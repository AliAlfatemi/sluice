"""Derive a path-free G8 terminal table without rewriting frozen evidence.

This export is sufficient for descriptive counts and primary point estimates.
It is not the original hash-chained evidence and does not replace validation
of the original receipts, journals, server logs, or bootstrap implementation.
"""
import argparse
import csv
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    rows, outcomes = [], Counter()
    for journal in sorted((a.evidence / "journals").glob("*.jsonl")):
        with journal.open() as f:
            header = json.loads(next(f))
            plan = json.loads((a.evidence / "plans" / ("plan_" + header["plan_id"] + ".json")).read_text())
            heldout = {(x["suite"], x["user_task"]): x["principal_scoring_eligible"] for x in plan["rows"]}
            for line in f:
                d = json.loads(line)
                if "utility" not in d:
                    continue
                s, au = d.get("sluice") or {}, d.get("policy_authoring") or {}
                decisions = [x.get("outcome") for x in s.get("broker_decisions", [])]
                outcomes.update(decisions)
                rows.append({
                    "arm_id": d["arm_id"], "model": d["model_slug"], "seed": d["generation_seed"],
                    "suite": d["suite"], "user_task": d["user_task"], "injection_task": d.get("injection_task"),
                    "stratum": d["stratum"], "condition": d["condition"],
                    "partition": "heldout" if heldout[(d["suite"], d["user_task"])] else "development",
                    "utility": d["utility"], "security": d["security"],
                    "parsed_tool_call": d.get("parsed_any_official_tool_call"), "error": bool(d.get("error")),
                    "official_verdict": d.get("official_agentdojo_verdict_observed"),
                    "policy_origin": au.get("policy_origin"), "policy_terminal": au.get("terminal_kind"),
                    "template_count": s.get("template_count"), "consumed_effects": s.get("consumed_effects"),
                    "broker_outcomes": json.dumps(decisions),
                })
    if len(rows) != 31380 or len({x["arm_id"] for x in rows}) != 31380:
        raise ValueError("G8 terminal arm count or uniqueness mismatch")
    with gzip.open(a.output / "terminal_arms.csv.gz", "wt", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summary = {"schema": "sluice-g8-derived-terminal-export-v1", "arms": len(rows),
               "partition_counts": dict(Counter(x["partition"] for x in rows)), "broker_outcomes": dict(outcomes),
               "source_manifest_sha256": hashlib.sha256((a.evidence / "C4_RESULT_SHA256SUMS").read_bytes()).hexdigest(),
               "limitations": ["Derived terminal table, not original hash-chain evidence", "No counterfactual ablation inferred"]}
    (a.output / "export_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
