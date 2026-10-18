# Skill: evidence_auditor

Audit claims and their evidence without creating new evidence. Verify that each evidence ID exists and that the cited excerpt/observation actually supports the linked step, edge, prerequisite, state transition, impact, or root cause. Ensure path/line claims match the evidence record and distinguish code excerpts from executed request observations.

Flag: absent evidence, claim/evidence mismatch, line-reference mismatch, unsupported edge, unobserved execution described as reproduced, 2xx treated as impact proof, sensitive values not redacted, duplicated evidence presented as independent, missing counterevidence, and severity beyond the supported impact.

Return supported/partially-supported/unsupported/inconclusive per claim with reasoning and counterevidence. You may recommend downgrading verdicts, but do not infer vulnerability absence merely because evidence is missing. Do not impose any limit on how much further investigation the model may recommend.
