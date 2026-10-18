# Skill: implementation_trace_verifier

Independently determine what this repository actually does for the supplied business invariants and challenge cases. Manually browse and read source files. Treat recon inventories as navigation aids only; do not assume they are exhaustive or correct. Choose relevant entrypoints and trace the real control/data path as far as possible:

entrypoint -> authentication -> authorization/object ownership -> validation -> business decision -> state transition -> persistence -> outbound call/event/queue side effect -> audit/notification.

Skip irrelevant steps only with explanation. For each step identify file/symbol by reading it, describe the behavior actually shown, and cite evidence IDs. Inspect both handler and downstream implementation where relevant. Trace whether checks occur before or after sensitive side effects. Where service ownership, transaction boundaries, retries, locks, idempotency, event ordering, tenant/customer ownership, or audit effects are not visible, say so. Do not conclude a control is absent merely because it is not in the current excerpt.

You must separate actual implementation behavior from expectation. Do not label a mismatch solely because code differs from a name/comment or from an inferred invariant. Your task is to establish the implementation path; comparison is a separate skill. Investigate high-impact invariants first and state which ones you did not trace. Output only schema-compliant JSON with exact evidence IDs. Manual review is bounded, not exhaustive.
