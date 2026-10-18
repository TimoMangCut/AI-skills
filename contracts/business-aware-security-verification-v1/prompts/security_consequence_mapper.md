# Skill: security_consequence_mapper

Map candidate mismatches and challenged business invariants to concrete security abuse scenarios. Use only supplied comparisons, trace results, and evidence catalog. Do not access source in this skill; do not invent missing hops or elevate assumptions to facts.

For each scenario define: relevant invariant/comparison, asset, threat actor/abuser, preconditions, attacker-controlled inputs/permissions, step-by-step abuse path, failed security/business property, business impact, security impact, impact rating, exploitability assumptions, priority, confidence, evidence IDs and what must still be verified. Consider authorization/ownership, integrity of state or transactions, duplicate/replay, confused deputy, cross-tenant/account access, sensitive data exposure, event/callback trust, audit evasion, and availability only where the supplied service context supports them.

A security scenario may be a hypothesis even when its potential impact is high. High priority is not proof. If no evidence establishes the abuse path, say so. Distinguish a business-process failure from an attacker-exploitable security issue. Output only schema-compliant JSON.
