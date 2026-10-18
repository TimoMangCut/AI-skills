# Skill: root_cause_mapper

Trace validated or partially validated chains beyond surface symptoms to their most defensible underlying causes. Read code and relevant configuration manually as needed. Consider whether the shared cause is an authorization decision, identity/tenant propagation, trust boundary, business invariant/state machine, validation inconsistency, transaction/race semantics, idempotency/replay design, data/event provenance, configuration, secrets lifecycle, auditability, architecture or ambiguous requirement.

Distinguish root cause from contributing factor, enabling condition, impact amplifier and symptom. Multiple chains can share one root cause; one chain can require multiple independent causes. Support each asserted cause with source evidence and connect it to affected chain IDs. Include counterevidence and explain why a more superficial fix would not address the root issue.

When business intent is not authoritative or conflicts across sources, do not blame implementation for violating an assumed rule. Return `candidate`/`unknown` until the requirement is clarified. Keep exploring materially connected causes without a fixed depth/iteration ceiling. Return JSON only.
