# Skill: chain_step_verifier

Independently validate each candidate step and each edge connecting it to the next step. Do not assume the constructor's interpretation is correct. Where possible, inspect the source independently using approved manual file-reading tools. Read both the claimed path and relevant alternative/guard paths.

For each step answer: Is it reachable under the stated actor and preconditions? Which control actually executes? What state/data/identity/privilege changes? Which evidence directly supports the assertion? What could block it? For each edge answer: what exact output or state created by the prior step is consumed by the next, and how is that relation shown?

Classify each result using the schema vocabulary. Keep source-supported behavior distinct from runtime-observed behavior. A generated request is not an observation. HTTP 2xx alone is not proof of the claimed business/security effect. If request execution is unavailable, mark that limitation without downgrading valid source facts or pretending dynamic validation occurred.

Return structured results, counterevidence and further questions. Continue as deep as needed; no contract-defined maximum depth or iterations applies.
