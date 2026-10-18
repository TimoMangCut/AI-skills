# Decision examples (fictional, illustrative only)

These examples demonstrate classification logic. They are not assumptions about the user's application or expected banking behavior.

## Case A — Requirement not available

The repo contains an endpoint called `CancelTransfer`, a code comment mentioning cancellation and a branch that changes transaction status. No approved requirement, API contract, acceptance criteria or domain owner statement is supplied. The inspected implementation appears to allow cancellation after a downstream request may have started, but the downstream transition is not traced.

Correct classification:

- `intent_basis = implementation_inference` or `readme_or_comment`;
- `authority_assessment = unclear` / `not_provided`;
- comparison `intent_ambiguous` or `not_verified`;
- a challenge can ask whether late cancellation is permitted and what compensating action is required;
- a potential security scenario may be recorded as a hypothesis, not a confirmed developer/business mismatch.

Incorrect classification: “Confirmed transaction-state vulnerability because cancellation should always be blocked after submission.” That rule was invented unless an authoritative source establishes it.

## Case B — Requirement and contradictory implementation are both evidenced

A supplied, version-identified product requirement states that an account inquiry must be restricted to the authenticated customer's account or a privileged role. The verifier reads the actual request path and downstream query; the query uses a client-controlled account identifier without a relevant owner/role check on this path. A separate targeted session rereads the candidate handler/query and confirms the behavior. The evidence auditor finds the requirement and code excerpts support the claim, and no supplied downstream authorization/tenant enforcement contradicts it.

Possible classification, only if the facts above are really evidenced:

- intent source `explicit_requirement`, authority `authoritative_in_input`;
- implementation outcome `contradicts_expected`;
- comparison `mismatch`, security relevance `security_relevant`, confidence `high`;
- security scenario: unauthorized account data access, with privacy/confidentiality impact and a concrete abuse path;
- still record any unseen gateway/production policy as a limitation if not reviewed.

This remains a fictional example. The final system must use real evidence IDs and must not omit counter-evidence or uninspected trust boundaries.
