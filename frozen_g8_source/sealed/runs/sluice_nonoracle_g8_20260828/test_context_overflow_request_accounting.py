#!/usr/bin/env python3
"""Regression for G5's attempted-versus-admitted request-count failure."""

from __future__ import annotations

import c4_policy_set


OBSERVED_G5_COUNTS = (
    # shard, served engine generations, attempted HTTP requests, fallbacks
    (0, 30, 31, 1),
    (1, 31, 32, 1),
    (2, 31, 31, 0),
    (3, 34, 34, 0),
    (4, 32, 33, 1),
    (5, 31, 32, 1),
)


def receipt(served: int, attempted: int) -> dict:
    scoped = attempted - 2
    return {
        "policy_authoring_output_cap_server_log_evidence": {
            "schema": "sluice-agentdojo-c10-policy-authoring-output-cap-log/1",
            "upper_bound": c4_policy_set.POLICY_AUTHORING_MAX_TOKENS,
            "served_generation_request_count": served,
            "served_max_tokens_histogram": {
                "8": 1,
                "256": 1,
                "4096": served - 2,
            },
            "missing_max_tokens_count": 0,
            "malformed_max_tokens_count": 0,
            "nonpositive_max_tokens_count": 0,
            "above_cap_max_tokens_count": 0,
            "verified": True,
        },
        "request_normalizer": {
            "chat_completion_requests_seen": attempted,
            "policy_authoring_max_tokens": (
                c4_policy_set.POLICY_AUTHORING_MAX_TOKENS
            ),
            "policy_authoring_scope_active": False,
            "policy_authoring_scope_request_count": scoped,
            "policy_authoring_max_tokens_filled_count": scoped,
            "policy_authoring_max_tokens_reduced_count": 0,
            "policy_authoring_original_max_tokens_histogram": {
                "absent": scoped,
            },
            "policy_authoring_applied_max_tokens_histogram": {
                "4096": scoped,
            },
        },
    }


def require_rejected(value: dict, rejected_count: int) -> None:
    try:
        c4_policy_set._verify_policy_authoring_output_cap_evidence(
            value,
            "fixture",
            authenticated_context_overflow_rejection_count=rejected_count,
        )
    except c4_policy_set.PolicySetError:
        return
    raise RuntimeError("invalid request-admission relation was accepted")


def main() -> int:
    for shard, served, attempted, fallbacks in OBSERVED_G5_COUNTS:
        c4_policy_set._verify_policy_authoring_output_cap_evidence(
            receipt(served, attempted),
            f"G5 shard {shard}",
            authenticated_context_overflow_rejection_count=fallbacks,
        )

    require_rejected(receipt(30, 31), 0)
    require_rejected(receipt(31, 31), 1)
    require_rejected(receipt(30, 31), -1)

    print("9/9 request-admission contract assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
