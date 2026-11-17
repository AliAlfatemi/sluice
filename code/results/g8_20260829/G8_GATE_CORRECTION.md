# G8 zero-tool-call outcome correction

This file records the only semantic correction from G7 to G8 before any G8
policy preflight or evaluated arm was observed.

G7 Mistral seed 196613 completed all 2,092 scheduled arms with zero errors.
Its authenticated six-receipt barrier reconstructed 12 parsed tool-calling
treatment arms, all 12 brokered and zero unbound, and passed. G7 then ran
Mistral seed 104729 to completion: 2,092/2,092 terminal arms, zero execution
errors, every required receipt gate true, zero tool-calling arms, zero bound
arms, and zero unbound arms. The mandatory G7 batch verifier rejected that complete
outcome solely because its aggregate tool-call count was zero.

The exact six G7 seed-104729 receipt SHA-256 values, in shard order, are
`27b85712723498067b786f985e24e1b3dac6f7d962a49e5ca4e5387fa558c3d5`,
`6444218a6ee2476a677ddcf5c7cfc3f52fbc32250dd2915d019c89f60d6ed29d`,
`ca45fb8184b4ac6721647d22da64ee9ed5cf4258ed7e82e4aae0e2e562ac9fc8`,
`b83136ccc97dc65432b8d4e122456eeb677de610aa3cf1fb09f32830ea9a4770`,
`10e4bfb67b1bed35fd34fd7505c29e37b9c2082216b99eb1d5aac3b7b119e300`,
and `dcab4951e4fff74b3f306d134924c273b5f4c2971ea5201fbb0e7767a08f9132`.
The terminal marker was written at `2026-08-27T01:47:31Z` and has SHA-256
`f3ab59c6b9a9c8cb6f16031102e9ccaf5e398a39dde0aff330d38c034b25e876`.

Tool use is a measured model behavior, not an experimental precondition. A
complete model/seed batch can legitimately contain no parsed official tool
calls. Rejecting that result selects on the dependent variable and prevents
the planned denominator from being observed. The zero-call result is therefore
recorded as `0/0/0` brokerage evidence and is not an integrity failure.

G8 makes one executable semantic change: `verify_c4_batch.py` removes only the
`toolcalling == 0` rejection. It still requires exactly six distinct shards;
strict nonnegative integer counters; empty tool-calling-but-unbound and
bound-without-tool-call lists on every shard; equal tool-calling/bound counts
per shard and in aggregate; journal-bound GREEN receipts; 2,092 planned and
terminal arms; a shared sealed C4 policy context; and analysis-time
authentication of all 2,092 selected arms. Any violation remains terminal.

The C15 design identity, models, snapshots, seeds, all 90 plan bytes, policy
authoring, scoring, denominators, arm outcomes, estimands, and model/seed order
remain unchanged. G8 has a fresh execution identity, committed HEAD, manifest,
empty evidence root, policy preflights, global policy seal, journals, and
receipts. No G7 runtime evidence is reused. After each authenticated batch the
detached launcher advances automatically until all 31,380 arms finish or a
genuine integrity failure occurs.
