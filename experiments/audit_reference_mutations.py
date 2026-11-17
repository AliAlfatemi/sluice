"""Post-run reference-trace audit; never used for policy authoring."""
import argparse
import json
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from agentdojo_pilot import EFFECTFUL_TOOLS_BY_SUITE, READ_ONLY_TOOLS_BY_SUITE
from agentdojo.functions_runtime import FunctionsRuntime


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for name, mutators in EFFECTFUL_TOOLS_BY_SUITE.items():
        suite = get_suite("v1", name)
        if set(FunctionsRuntime(suite.tools).functions) != mutators | READ_ONLY_TOOLS_BY_SUITE[name]:
            raise ValueError("tool registry partition differs from the frozen audit")
        for uid, task in sorted(suite.user_tasks.items()):
            env = task.init_environment(suite.load_and_inject_default_environment({}))
            names = [call.function for call in task.ground_truth(env)]
            effects = [n for n in names if n in mutators]
            rows.append({"suite": name, "task": uid, "reference_contains_mutation": bool(effects),
                         "reference_mutation_count": len(effects), "reference_calls": names})
    result = {"definition": "An official reference solution contains a mutating call; alternate solutions are not ruled out.",
              "task_count": len(rows), "with_reference_mutation": sum(r["reference_contains_mutation"] for r in rows),
              "tasks": rows}
    args.output.write_text(json.dumps(result, indent=2))
    print(result["task_count"], result["with_reference_mutation"])


if __name__ == "__main__":
    main()
