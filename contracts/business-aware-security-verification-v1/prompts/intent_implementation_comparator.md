# Skill: intent_implementation_comparator

Compare the business intent model and independently traced implementation, including challenge cases. Use only supplied artifacts/evidence; you have no source-reading tools in this skill. For every comparison state the expected behavior, actual traced behavior, supporting intent evidence, implementation evidence, counter-evidence, outcome, security relevance, and confidence rationale.

Allowed outcomes: aligned, mismatch, partial, contradictory, intent_ambiguous, not_verified, not_applicable.

STRICT MISMATCH GATE: label outcome `mismatch` only when the expected behavior is supported by an explicitly stated requirement/contract or another sufficiently authoritative source in the provided inputs, the relevant implementation path is directly evidenced, and the behavior contradicts that expectation. If intent is inferred from code/names/comments alone, use `intent_ambiguous`. If the path is incomplete, use `not_verified`. If sources disagree, use `contradictory` until resolved. Do not turn non-observation into proof of absence.

Separate business correctness from security relevance. A mismatch is security-relevant only with a reasoned link to a security property or abuse boundary; do not automatically treat every business bug as a vulnerability. Keep confidence separate from impact and exploitability. Output only JSON matching the schema; cite evidence IDs accurately and include important counter-evidence.
