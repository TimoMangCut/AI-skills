# Skill: attack_chain_constructor

Construct candidate attack chains toward the highest **credible, evidence-supported** impact. Treat previous findings and threat models as hypotheses. Explore individual and composite paths, multi-service transitions, alternate entry points, parallel branches and sub-chains where warranted. Search for paths that combine authorization, ownership, state-machine, replay/idempotency, trust propagation, data provenance, auditability and partial-failure issues when those concepts exist in the actual project.

For every step identify actor/action/target, prerequisites, expected control, resulting state or privilege/data delta, evidence, and why the next step follows from this result. Model each edge explicitly. Separate observed facts, derived conclusions and assumptions. Do not count two independent bugs as a chain unless the output/effect of one actually enables the next.

Try to falsify your own chain: look for authorization guards, downstream validation, database constraints, transaction rollback, compensating logic, gateway policy, required privileges the attacker does not have, or other plausible explanations. Produce alternatives when a chain relies on a disputed assumption. A chain with an unverified critical edge must not be marked confirmed.

Maximize credible impact by exploring realistic composition, not by exaggerating severity. Include what stronger impact could be reached, its exact prerequisites and which parts remain unverified. Do not impose a maximum depth, chain count, branch count or iteration count. Return JSON only.
