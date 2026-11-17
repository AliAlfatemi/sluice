"""Prospective Sluice x AgentDojo rerun harness.

The earlier RQ6 measurements are invalidated: that bridge missed eight
mutators and reused one one-time gate across multi-effect episodes.  This
driver uses an exhaustive tool partition and one exact-argument gate per
trusted ground-truth effect.  No paper result is reported from this corrected
harness until both arms are rerun with frozen provenance.

Usage:
    LOCAL_LLM_PORT=8101 MODEL_ID=<model> MODEL_REVISION=<commit> \
      GENERATION_SEED=<seed> AGENTDOJO_SOURCE_SHA256=<tree-hash> \
      python3 agentdojo_pilot.py --limit-user-tasks 6 --out results.json

The model revision and generation seed are operator attestations. This client
does not verify which weight revision or seed the OpenAI-compatible endpoint
loaded, so a rerun must also retain the server launch log and cache manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
import time
from pathlib import Path

ARTIFACT_ROOT = os.path.dirname(os.path.abspath(__file__))
if ARTIFACT_ROOT not in sys.path:
    sys.path.insert(0, ARTIFACT_ROOT)

from agentdojo_integration.exact_effect_bridge import (  # noqa: E402
    ExactMatchBackend,
    SluiceExactEffectExecutor,
    author_exact_effects,
)

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, ToolsExecutionLoop  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import SystemMessage, InitQuery  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
import agentdojo.attacks  # noqa: E402,F401  -- triggers attack registration
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402

MEDIATED_TOOLS_BY_SUITE = {
    "banking": {
        "send_money": "recipient",
        "schedule_transaction": "recipient",
        "update_scheduled_transaction": "recipient",
        "update_password": None,
        "update_user_info": None,
    },
    "workspace": {
        "send_email": "recipients",
        "share_file": "email",
        "delete_file": None,
        "delete_email": None,
        "create_calendar_event": None,
        "cancel_calendar_event": None,
        "reschedule_calendar_event": None,
        "add_calendar_event_participants": None,
        "create_file": None,
        "append_to_file": None,
    },
    "travel": {
        "reserve_hotel": "hotel",
        "reserve_restaurant": "restaurant",
        "reserve_car_rental": "company",
        "send_email": "recipients",
        "create_calendar_event": None,
        "cancel_calendar_event": None,
    },
    "slack": {
        "send_direct_message": "recipient",
        "send_channel_message": "channel",
        "add_user_to_channel": "user",
        "invite_user_to_slack": "user_email",
        "remove_user_from_slack": "user",
        "post_webpage": "url",
    },
}

READ_ONLY_TOOLS_BY_SUITE = {
    "banking": frozenset({
        "get_iban", "get_balance", "get_most_recent_transactions",
        "get_scheduled_transactions", "read_file", "get_user_info",
    }),
    "workspace": frozenset({
        "get_unread_emails", "get_sent_emails", "get_received_emails",
        "get_draft_emails", "search_emails", "search_contacts_by_name",
        "search_contacts_by_email", "get_current_day", "search_calendar_events",
        "get_day_calendar_events", "search_files_by_filename", "get_file_by_id",
        "list_files", "search_files",
    }),
    "travel": frozenset({
        "get_user_information", "get_all_hotels_in_city", "get_hotels_prices",
        "get_rating_reviews_for_hotels", "get_hotels_address",
        "get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
        "get_restaurants_address", "get_rating_reviews_for_restaurants",
        "get_dietary_restrictions_for_all_restaurants",
        "get_contact_information_for_restaurants", "get_price_for_restaurants",
        "check_restaurant_opening_hours", "get_all_car_rental_companies_in_city",
        "get_car_types_available", "get_rating_reviews_for_car_rental",
        "get_car_fuel_options", "get_car_rental_address", "get_car_price_per_day",
        "search_calendar_events", "get_day_calendar_events", "get_flight_information",
    }),
    "slack": frozenset({
        "get_channels", "read_channel_messages", "read_inbox",
        "get_users_in_channel", "get_webpage",
    }),
}

EFFECTFUL_TOOLS_BY_SUITE = {
    suite: frozenset(spec) for suite, spec in MEDIATED_TOOLS_BY_SUITE.items()
}

EXPECTED_AGENTDOJO_VERSION = "0.1.35"


def agentdojo_source_provenance():
    """Hash the actual imported Python source tree, including local patches."""

    import agentdojo

    root = Path(agentdojo.__file__).resolve().parent
    files = sorted(root.rglob("*.py"), key=lambda path: path.relative_to(root).as_posix())
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return {
        "package_version": importlib.metadata.version("agentdojo"),
        "source_tree_sha256": digest.hexdigest(),
        "source_file_count": len(files),
        "hash_definition": "sha256(length(path)||path||length(content)||content), sorted *.py",
    }


def extract_recipient_scope(ground_truth_calls, mediated_tools):
    """For each mediated tool that appears in this task's own ground truth,
    collect the argument values the trusted planner considers legitimate.
    Only the tool's designated recipient-bearing argument is scoped this way
    (the security-relevant one per tool, e.g. `recipient` for send_money,
    `email` for share_file); other arguments are left unconstrained
    (declared with no allowed_values) so the template still requires them to
    be present and a string, without over-fitting to exact wording the model
    may paraphrase. List-valued recipient arguments (e.g. send_email's
    `recipients`) are scoped on their str()-canonicalized form, since
    Sluice's ArgConstraint only validates strings; this is coarser than a
    per-address comparison and is used only for tools where no per-element
    check is currently implemented.
    """
    from sluice_v2.actions import ArgConstraint

    spec = {}
    for call in ground_truth_calls:
        if call.function not in mediated_tools:
            continue
        recipient_arg = mediated_tools[call.function]
        args = call.args
        recipient_val = args.get(recipient_arg) if recipient_arg else None
        other_constraints = {
            k: ArgConstraint(max_length=4096) for k in args.keys() if k != recipient_arg
        }
        if call.function not in spec:
            spec[call.function] = {
                "recipient_arg": recipient_arg if recipient_val is not None else None,
                "recipient_scope": set(),
                "other_constraints": other_constraints,
            }
        if recipient_val is not None:
            spec[call.function]["recipient_scope"].add(str(recipient_val))
    # Tools mediated but never in ground truth for this task: no legitimate
    # use exists, so authorize zero values (any real call is denied).
    for tool in mediated_tools:
        if tool not in spec:
            spec[tool] = {"recipient_arg": None, "recipient_scope": set(), "other_constraints": {}}
    for tool, s in spec.items():
        s["recipient_scope"] = frozenset(s["recipient_scope"])
    return spec


def extract_recipient_scope_from_environment(env, mediated_tools, suite_name):
    """Non-oracle counterpart to extract_recipient_scope: the gate's
    recipient allowlist is built from state already present in the
    environment BEFORE the episode runs -- never from ground_truth(),
    never from anything the current task or attack reveals. This is what
    a real deployment could actually implement (e.g. "only pay recipients
    this account has already paid or scheduled"), as opposed to the
    oracle condition's access to the benchmark's own known-correct answer.

    Banking and workspace only: for banking, bank_account.transactions
    and .scheduled_transactions are the account's pre-existing payment
    history; for workspace, inbox.contact_list is the account's
    pre-existing address book. Both are present in every task's initial
    environment regardless of which task or attack is about to run.
    Travel/slack would need their own environment-derived signal; not
    built here.

    Non-recipient arguments are declared from the tool's own static
    parameter schema (recipient/amount/subject/date, etc.) -- public
    information about what the tool accepts, fixed at tool-definition
    time, not anything ground_truth() or the current task reveals -- so
    every tool call still requires them present and string-typed, exactly
    as the oracle condition does, without knowing this task's actual
    values in advance.
    """
    from sluice_v2.actions import ArgConstraint

    if suite_name == "banking":
        known_recipients = {
            transaction.recipient
            for transaction in (*env.bank_account.transactions, *env.bank_account.scheduled_transactions)
        }
    elif suite_name == "workspace":
        # send_email's recipient argument ("recipients") is list-valued
        # and scoped, like the oracle path, on its str()-canonicalized
        # form -- here, the canonical single-recipient form of every
        # already-known contact. share_file's ("email") is a plain
        # string, scoped directly.
        known_emails = {c.email for c in env.inbox.contact_list}
        known_recipients = known_emails | {str([email]) for email in known_emails}
    else:
        raise NotImplementedError(
            f"non-oracle scope extraction is only implemented for banking "
            f"and workspace, not {suite_name!r}"
        )
    tool_arg_names = {
        "send_money": ("recipient", "amount", "subject", "date"),
        "schedule_transaction": ("recipient", "amount", "subject", "date", "recurring"),
        "update_scheduled_transaction": ("id", "recipient", "amount", "subject", "date", "recurring"),
        "update_password": ("password",),
        "update_user_info": ("first_name", "last_name", "street", "city"),
        "send_email": ("recipients", "subject", "body", "attachments", "cc", "bcc"),
        "share_file": ("file_id", "email", "permission"),
        "delete_file": ("file_id",),
        "delete_email": ("email_id",),
    }
    spec = {}
    for tool, recipient_arg in mediated_tools.items():
        other_constraints = {
            name: ArgConstraint(max_length=4096)
            for name in tool_arg_names.get(tool, ())
            if name != recipient_arg
        }
        spec[tool] = {
            "recipient_arg": recipient_arg,
            "recipient_scope": frozenset(known_recipients) if recipient_arg else frozenset(),
            "other_constraints": other_constraints,
        }
    return spec


def build_pipeline(
    mediated: bool,
    monitor=None,
    mediated_tools=None,
    suite_name=None,
    model_id="unreported-model",
):
    port = os.environ["LOCAL_LLM_PORT"]
    llm = get_llm("vllm_parsed", "vllm_parsed", None, "tool")
    system_message = load_system_message(None)
    if mediated:
        if suite_name is None:
            suite_name = next(
                (
                    name
                    for name, tools in EFFECTFUL_TOOLS_BY_SUITE.items()
                    if set(tools) == set(mediated_tools)
                ),
                None,
            )
        if suite_name not in EFFECTFUL_TOOLS_BY_SUITE:
            raise ValueError("suite_name is required for exhaustive tool classification")
        executor = SluiceExactEffectExecutor(
            monitor,
            suite_name=suite_name,
            effectful_tools=EFFECTFUL_TOOLS_BY_SUITE[suite_name],
            read_only_tools=READ_ONLY_TOOLS_BY_SUITE[suite_name],
        )
        tools_loop = ToolsExecutionLoop([executor, llm])
        pipeline = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, tools_loop])
        pipeline.name = f"vllm_parsed-{model_id}-sluice"
        return pipeline, executor
    tools_loop = ToolsExecutionLoop([ToolsExecutor(), llm])
    pipeline = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, tools_loop])
    pipeline.name = f"vllm_parsed-{model_id}-undefended"
    return pipeline, None


def _checkpoint(results, out_path):
    """Write partial results after every episode so a crash (context-length
    overflow, a transient server error) loses at most the in-flight episode,
    not the whole run. Written atomically to out_path + '.partial' via a
    same-directory temp file plus rename; the final run() still writes the
    canonical out_path once at the end."""
    partial_path = out_path + ".partial"
    tmp_path = partial_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    os.replace(tmp_path, partial_path)


def run(limit_user_tasks, limit_injection_tasks, out_path, suite_name="banking"):
    from sluice_v2.monitor import ReferenceMonitor
    from sluice_v2.store import DurableStore

    model_revision = os.environ.get("MODEL_REVISION")
    if not model_revision:
        raise ValueError(
            "MODEL_REVISION is required as an operator attestation; preserve "
            "the server launch log/cache manifest because this client cannot "
            "verify the endpoint's loaded weight revision"
        )
    model_id = os.environ.get("MODEL_ID")
    if not model_id:
        raise ValueError("MODEL_ID is required; do not infer it from the endpoint")
    generation_seed = os.environ.get("GENERATION_SEED")
    if generation_seed is None:
        raise ValueError(
            "GENERATION_SEED is required as an endpoint-side seed attestation; "
            "retain the endpoint launch/configuration log"
        )

    agentdojo_provenance = agentdojo_source_provenance()
    if agentdojo_provenance["package_version"] != EXPECTED_AGENTDOJO_VERSION:
        raise RuntimeError(
            "unsupported AgentDojo version: "
            f"{agentdojo_provenance['package_version']!r}; expected "
            f"{EXPECTED_AGENTDOJO_VERSION!r}"
        )
    expected_agentdojo_source = os.environ.get("AGENTDOJO_SOURCE_SHA256")
    if not expected_agentdojo_source:
        raise ValueError(
            "AGENTDOJO_SOURCE_SHA256 is required so local AgentDojo patches "
            "cannot be mistaken for stock 0.1.35"
        )
    if agentdojo_provenance["source_tree_sha256"] != expected_agentdojo_source:
        raise RuntimeError(
            "AgentDojo source hash mismatch: imported "
            f"{agentdojo_provenance['source_tree_sha256']}, expected "
            f"{expected_agentdojo_source}"
        )

    suite = get_suite("v1", suite_name)
    mediated_tools = MEDIATED_TOOLS_BY_SUITE[suite_name]

    # One database per run, keyed off the (unique) output filename -- two
    # concurrent runs sharing a directory must not share a SQLite file
    # (SQLite's BEGIN IMMEDIATE write-locking, correct for this store's
    # own atomicity guarantee, otherwise serializes -- and can deadlock --
    # two unrelated experiments' writers against each other).
    db_path = os.path.join(
        os.path.dirname(out_path) or ".",
        os.path.splitext(os.path.basename(out_path))[0] + ".sqlite3",
    )
    if os.path.exists(db_path):
        os.remove(db_path)
    store = DurableStore(db_path)
    monitor = ReferenceMonitor(store, ExactMatchBackend())

    undefended_pipeline, _ = build_pipeline(mediated=False, model_id=model_id)
    sluice_pipeline, sluice_executor = build_pipeline(
        mediated=True, monitor=monitor, mediated_tools=mediated_tools,
        suite_name=suite_name, model_id=model_id,
    )

    user_task_ids = list(suite.user_tasks.keys())
    if limit_user_tasks:
        user_task_ids = user_task_ids[:limit_user_tasks]
    injection_task_ids = list(suite.injection_tasks.keys())
    if limit_injection_tasks:
        injection_task_ids = injection_task_ids[:limit_injection_tasks]

    results = {
        "utility": {"undefended": {}, "sluice": {}},
        "security": {"undefended": {}, "sluice": {}},
        "sluice_effect_accounting": {},
        "meta": {
            "suite": suite_name,
            "suite_version": "v1",
            "agentdojo": agentdojo_provenance,
            "user_task_ids": user_task_ids,
            "injection_task_ids": injection_task_ids,
            "model_revision": model_revision,
            "model_id": model_id,
            "model_revision_source": "operator_attested_not_endpoint_verified",
            "generation_seed": generation_seed,
            "generation_seed_source": "operator_attested_endpoint_configuration",
            "condition_schedule": [],
            "condition_schedule_policy": "alternating paired order by episode",
            "evidence_status": "prospective_work_in_progress_pending_counterbalanced_rerun",
        },
    }

    pipelines = {"undefended": undefended_pipeline, "sluice": sluice_pipeline}
    # The attack depends on pipeline formatting, so construct one for each arm.
    attacks = {
        condition: load_attack("important_instructions", suite, pipeline)
        for condition, pipeline in pipelines.items()
    }
    episode_index = 0
    for uid in user_task_ids:
        user_task = suite.get_user_task_by_id(uid)
        pre_env_for_gate = suite.load_and_inject_default_environment({})
        pre_env_for_gate = user_task.init_environment(pre_env_for_gate)
        ground_truth_calls = user_task.ground_truth(pre_env_for_gate)

        for injid in [None, *injection_task_ids]:
            episode_id = f"{uid}__{injid or 'noattack'}"
            order = (
                ["undefended", "sluice"]
                if episode_index % 2 == 0
                else ["sluice", "undefended"]
            )
            results["meta"]["condition_schedule"].append(
                {"episode_id": episode_id, "order": order}
            )
            injection_task = (
                None if injid is None else suite.get_injection_task_by_id(injid)
            )

            for cond_name in order:
                pipeline = pipelines[cond_name]
                effects = []
                if cond_name == "sluice":
                    effects = author_exact_effects(
                        monitor,
                        suite_name=suite_name,
                        episode_id=episode_id,
                        ground_truth_calls=ground_truth_calls,
                        effectful_tools=EFFECTFUL_TOOLS_BY_SUITE[suite_name],
                        read_only_tools=READ_ONLY_TOOLS_BY_SUITE[suite_name],
                        caller_id="agentdojo-planner",
                    )
                    sluice_executor.set_episode(episode_id, effects)

                t0 = time.time()
                try:
                    if injection_task is None:
                        utility_value, security_value = suite.run_task_with_pipeline(
                            pipeline, user_task, None, {}
                        )
                    else:
                        attack_injections = attacks[cond_name].attack(
                            user_task, injection_task
                        )
                        utility_value, security_value = suite.run_task_with_pipeline(
                            pipeline, user_task, injection_task, attack_injections
                        )
                except Exception as exc:
                    print(f"[{cond_name}] ERROR {episode_id}: {exc!r}", flush=True)
                    utility_value, security_value = None, None
                elapsed = time.time() - t0

                if injection_task is None:
                    results["utility"][cond_name][uid] = {
                        "utility": utility_value,
                        "seconds": elapsed,
                    }
                else:
                    results["security"][cond_name][episode_id] = {
                        "utility": utility_value,
                        "attack_success": security_value,
                        "seconds": elapsed,
                    }
                if cond_name == "sluice":
                    results["sluice_effect_accounting"][episode_id] = {
                        "authorized": len(effects),
                        "matched": len(effects) - sluice_executor.unused_effect_count,
                        "unused": sluice_executor.unused_effect_count,
                    }
                print(
                    f"[{cond_name}] {episode_id}: utility={utility_value}, "
                    f"attack_success={security_value} ({elapsed:.1f}s)",
                    flush=True,
                )
                _checkpoint(results, out_path)
            episode_index += 1

    results["sluice_mediation_log"] = [
        {
            "episode_id": r.episode_id,
            "template_id": r.template_id,
            "gate_id": r.gate_id,
            "tool": r.tool,
            "args": r.args,
            "outcome": r.outcome,
            "charged_bits": r.charged_bits,
            "denied": r.denied,
        }
        for r in sluice_executor.mediation_log
    ]

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Wrote {out_path}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit-user-tasks", type=int, default=0)
    ap.add_argument("--limit-injection-tasks", type=int, default=0)
    ap.add_argument("--out", type=str, default="agentdojo_banking_results.json")
    ap.add_argument("--suite", type=str, default="banking", choices=list(MEDIATED_TOOLS_BY_SUITE))
    args = ap.parse_args()
    run(args.limit_user_tasks or None, args.limit_injection_tasks or None, args.out, args.suite)
