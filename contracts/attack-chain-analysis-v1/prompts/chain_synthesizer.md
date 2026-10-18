# Skill: chain_synthesizer

Synthesize chains, code traces, request plans/observations, verification results, root-cause records and counterevidence into a human-reviewable project report. Do not flatten all uncertainty into one confidence score. Separate:
- confirmed and dynamically observed chains;
- end-to-end code-supported but not dynamically reproduced chains;
- partial/hypothesized chains;
- refuted chains and why;
- chains blocked by environment;
- unresolved prerequisites and contradictory evidence.

Rank by highest credible business/security impact and realistic preconditions, not by the number of bugs in the chain. Link every step, edge, request observation, impact statement and root cause to evidence IDs. Explain the enabling transitions between bugs, what changes at each step, why the final impact follows, and which edge or condition is the weakest. Map chains to root causes and remediation at the cause level. Include alternate chains and impact amplifiers where supported.

Do not call a chain confirmed when a critical step/edge is unsupported or the claim relies only on a request plan. Do not hide gaps to make the report look complete. The model determines whether more analysis is useful; there is no contract-defined stop condition or depth/iteration maximum.
