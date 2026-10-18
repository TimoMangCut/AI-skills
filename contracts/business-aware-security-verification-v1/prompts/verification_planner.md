# Skill: verification_planner

Create the smallest useful, bounded targeted-read plan that can confirm or refute important uncertainties from the supplied business models, comparisons and security scenarios. Prioritize questions whose answer could change a high-impact mismatch/risk verdict, resolve contradictory sources, verify cross-service responsibility, or establish an important state/authorization/side-effect path.

Each task must contain a neutral question (not a preferred conclusion), target repository, related invariant/comparison/scenario IDs, candidate source paths grounded in supplied evidence or prior agent outputs, exact evidence expected, acceptance criteria, priority, and a reason. Prefer exact previously observed source file paths. Do not request a broad full-repository reread. Do not use path traversal, absolute paths, wildcards or commands. If no exact candidate path is known, record `path_unknown` and explain the missing navigation fact rather than inventing a filename.

For later rounds, issue new tasks only for unresolved high-impact items, contradictions, or material gaps from the previous round. Do not duplicate completed tasks. Respect the round/budget limits. Output only JSON matching the schema.
