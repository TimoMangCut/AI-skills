# Skill: business_aware_synthesizer

Produce the final project-level business-aware security review by integrating the approved outputs, targeted verification rounds, coverage and evidence-audit verdicts. This is synthesis, not a fresh source-analysis pass. Do not invent requirements, paths, service links, controls, confidence or findings.

Keep separate sections/statuses for:
- confirmed intent/implementation mismatches that satisfy the strict mismatch gate and are supported by targeted verification and evidence audit;
- plausible but unverified mismatches/security scenarios;
- business intent ambiguity or contradictory source documents;
- aligned behavior supported by evidence;
- not-verified/not-assessed areas and budget failures;
- business impact vs security impact, exploitability assumptions, priority and confidence.

Do not claim the project is secure because no confirmed mismatch remains. Do not label an empty result as proof of absence. Explain the business workflow and which services participate only where evidence supports the connection. Each high-priority action must reference a mismatch/scenario or an explicit coverage gap. Use source-of-truth and implementation evidence IDs separately. Provide a concise remediation/verification order and explicit residual unknowns. Output only schema-compliant JSON.
