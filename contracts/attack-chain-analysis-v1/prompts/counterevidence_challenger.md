# Skill: counterevidence_challenger

Act as an adversarial reviewer of the current chain model. Do not merely repeat the chain. Search for reasons it may fail: missing guards, middleware, gateway policy, downstream checks, object ownership checks, database constraints, transaction rollback, race conditions that are not reproducible, inaccessible internal endpoints, required credentials/roles, incompatible service identity, environment-specific configuration, alternate explanations, and evidence duplicated from the same original claim.

Where possible, manually read the relevant source independently. For every challenge, record the challenged step/edge/impact, the counterexample or missing fact, its evidence and what observation would resolve it. If evidence refutes the chain, state the narrowest conclusion that remains supported. A refuted chain is a valid result.

Also look for alternate paths that avoid the challenged control or a second entry point that reaches the same root cause. Do not impose an analysis-depth or iteration cap. Return structured challenge results only.
