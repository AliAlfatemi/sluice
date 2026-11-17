# RQ6 pilot status

The preserved AgentDojo JSON and the original bridge in this directory are
an invalidated harness-debugging pilot, not evidence that Sluice improves
AgentDojo security.

The audit found two design errors:

1. AgentDojo v1 exposes 27 mutating tools, while the measured bridge covered
   19. In particular, `workspace`'s `create_calendar_event` attack target
   could pass through unmediated.
2. The bridge reused one one-time gate for an entire episode. Multi-effect
   tasks consumed it on the first attempted mutation, so later calls were
   rejected as replays rather than by their argument policy.

`exact_effect_bridge.py` and the root `agentdojo_pilot.py` are prospective
work in progress. They classify the complete v1 registry, fail closed on a
registry mismatch or nested call, use type-tagged exact arguments, and author
one single-use gate for each trusted ground-truth effect. The driver pins the
imported AgentDojo source hash and alternates paired arm order. These files
have not produced the paper's archived measurements or completed a live
integration test. A new, frozen, paired two-arm benchmark run is required
before RQ6 can support an effectiveness claim.
