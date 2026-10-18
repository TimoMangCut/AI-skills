# Business-aware Security Verification (BASV) — Normative Contract v1.0

**Status:** phase contract for implementation after repository reconnaissance.  
**Applies to:** a mobile-banking application and its .NET / Go microservices, without assuming that every service handles money or that every common banking control applies to every service.

## 1. Mission and non-goals

BASV must answer four separate questions:

1. **What business outcome is the system intended to provide?**
2. **What business rules/invariants can be established from available sources, and how authoritative are those sources?**
3. **What does the inspected implementation actually do along the relevant execution path?**
4. **Where is the difference security-relevant, what could an actor abuse, and what evidence is still needed?**

BASV is not a second generic recon report, a one-shot synthesis prompt, a static-analysis phase, or a claim that requirements can be recovered reliably from source-code names. It must use AI-driven manual exploration and targeted re-reading. It may consume prior recon artifacts as navigation aids, but must independently revisit source before confirming high-impact behavior.

## 2. Non-negotiable reasoning rules

### 2.1 Separate intent from implementation

Every material claim must be classified as one of:

- **Intent evidence:** a statement about what the business/product/system is supposed to do.
- **Implementation evidence:** a statement about what inspected code/config/tests actually do.
- **Derived relationship:** a conclusion linking multiple observed facts.
- **Hypothesis:** a plausible interpretation or attack path that is not yet established.
- **Unknown / not assessed:** insufficient basis to conclude.

A source-code branch may establish current behavior, but it does not by itself prove that behavior is intended. README text, names, comments, test cases, API contracts, deployment config and approved business requirements have different authority levels. Record source type and authority evidence; do not silently treat all documentation as equally authoritative.

### 2.2 Do not manufacture business requirements

A mismatch may be called a **confirmed intent/implementation mismatch** only when:

1. the expected behavior is stated or otherwise established by a sufficiently authoritative input source;
2. the actual relevant code path was directly inspected and is adequately traced;
3. the actual behavior contradicts the expectation, rather than simply lacking a visible control in the inspected excerpt; and
4. no unresolved contradictory requirement, runtime configuration or omitted component plausibly explains the difference.

If a requirement is only inferred from names/comments/code structure, use `intent_ambiguous` or `not_verified`. Describe the rule as an assumption or hypothesis, not a developer defect.

### 2.3 Distinguish absence from non-observation

- `not_observed_in_reviewed_scope` means the AI did not see the behavior in the files/lines it actually inspected.
- `not_verified` means the relevant path could not be traced well enough.
- `conflicting` means credible input sources disagree.
- None of these means the control is absent from the whole repository or deployed system.

### 2.4 Actively seek counterexamples

Every high-impact invariant must be challenged with at least one plausible counterexample, boundary case, alternate path, or cross-service path. The challenger must not see existing threat models/findings before producing its challenge set. It should ask what would falsify the current interpretation, not merely restate it.

### 2.5 Verify independently

Implementation tracing and targeted verification run in isolated model sessions. A targeted verifier receives neutral questions, the invariant/expected behavior, the minimal relevant context, and an exact list of candidate files. It should not receive the previous agent's mismatch verdict, impact score, or preferred conclusion. This reduces confirmation bias.

### 2.6 Security relevance is an additional judgment

A business mismatch is not automatically a security vulnerability. Map a mismatch to a security scenario only when there is a reasoned threat path affecting a security property or business abuse boundary, such as authorization, customer/account isolation, transaction integrity, confidentiality, availability, auditability/non-repudiation, fraud exposure, or abuse of service trust. Keep business correctness impact and security impact separate.

### 2.7 No numeric confidence theater

Do not use model-generated percentages such as `0.91` unless calibrated against a known test set. Use categorical confidence (`high`, `medium`, `low`, `not_assessed`) and explain why. Confidence in evidence is not the same as attack likelihood or business impact.

## 3. Authority and evidence model

Each proposed invariant must include:

- `intent_basis`: `explicit_requirement`, `api_or_event_contract`, `acceptance_criteria_or_test`, `architecture_decision`, `readme_or_comment`, `implementation_inference`, `conflicting_sources`, or `unknown`;
- `authority_assessment`: `authoritative_in_input`, `supporting_only`, `unclear`, `contradictory`, or `not_provided`;
- `evidence_ids` referencing actual AI-requested reads, when applicable;
- a note explaining why the source supports the expected behavior and any authority/version uncertainty.

The orchestrator must preserve source provenance. If business materials are unavailable, the model should derive candidate invariants for investigation but label them `implementation_inference` and avoid declaring an implementation mismatch solely against them.

Evidence status semantics:

| Status | Meaning |
|---|---|
| `observed` | Directly present in an inspected excerpt or supplied artifact. |
| `derived` | Follows from multiple observed facts whose relationship is explained. |
| `hypothesis` | Plausible but not established, or requires more source/operational context. |
| `unknown` | Current evidence is insufficient or contradictory. |
| `not_assessed` | The task has not been performed. |

A cited evidence ID establishes provenance for an excerpt, not semantic correctness by itself. Every high-priority mismatch requires independent targeted verification plus evidence auditing before it can appear as confirmed in the final synthesis.

## 4. Scope and inputs

The phase receives:

1. all per-repository recon artifacts available: repo profiles, business capabilities, API/authZ inventory, inbound/outbound flows, dataflow/trust boundaries, threat models, architecture reviews, findings, evidence indexes and coverage reports;
2. existing project/cross-repository artifacts: service interaction candidates, system threats, dependencies, evidence audit and coverage gaps;
3. read access to the current source repositories for manual verification;
4. any available business requirements, acceptance criteria, API/event contracts, architecture decisions, workflow/state-machine documentation and relevant tests that reside in the supplied read scope;
5. an immutable job spec, per-skill tool allow-list, evidence policy and budget.

Previous recon outputs may be stale or incomplete. Their evidence is a lead, not a substitute for targeted re-reading. The model must not assume a recon inventory is exhaustive.

## 5. Required reasoning pipeline

### Stage 0 — Intake and artifact quality check

The orchestrator confirms which dossiers exist and records missing files/status. It does not infer missing content. Repo names and project scope are provided without absolute filesystem paths. Any absent recon artifact becomes a coverage gap.

### Stage 1 — Business intent model (`business_intent_modeler`, per repo)

The agent explores relevant business documentation, endpoint contracts, tests, domain models, workflow/state transitions and implementation cues. It outputs capabilities, actors, workflows, candidate invariants, source authority and unknowns. It must label requirements inferred from code separately from explicit requirements.

### Stage 2 — Invariant challenge (`business_invariant_challenger`, project scope, blinded)

The agent receives service capabilities, interface/dataflow maps and source-backed candidate invariants. It is not given prior security findings or the per-service threat-model conclusions. It enumerates counterexamples: alternate entrypoints, state transitions, race/replay/duplicate requests, inconsistent authorization across hops, cross-service responsibility gaps, retries/compensation, ownership/tenant mismatch, event/message consumer trust, and failure-mode behavior where relevant. These are challenges to verify, not findings.

### Stage 3 — Implementation trace (`implementation_trace_verifier`, per repo)

The agent independently opens source. For each high-priority invariant, trace the relevant path as far as the evidence permits:

`entrypoint → identity/authentication → authorization/object ownership → validation → business decision → state transition → persistence → outbound/queue side effect → audit/notification`

Not every flow uses every step. Explicitly record the missing/unseen links. Inspect caller and callee when authorization or validation might be split across service boundaries. Do not treat a request DTO, controller attribute, function name, or shared network location as sufficient evidence of the full path.

### Stage 4 — Intent/implementation comparison (`intent_implementation_comparator`, independent synthesis)

Compare expected behavior against observed paths. Allowed outcomes:

- `aligned`
- `mismatch`
- `partial`
- `contradictory`
- `intent_ambiguous`
- `not_verified`
- `not_applicable`

A `mismatch` requires adequate intent authority and a directly evidenced contradictory implementation. Use `intent_ambiguous` when expected behavior is not established. Use `not_verified` if the path/side effect/deployment assumption remains untraced. Attach supporting and counter-evidence separately.

### Stage 5 — Preliminary security consequence mapping (`security_consequence_mapper`)

For each plausible mismatch/challenge, map: actor, preconditions, path, business asset, violated property, business consequence, security consequence, severity/impact, exploitation assumptions, and validation needed. At this stage, unverified scenarios remain hypotheses. This mapping is also used to prioritize re-reading, but must not bias the targeted verifier.

### Stage 6 — Targeted verification planning (`verification_planner`)

Create bounded, actionable tasks. Each task includes a neutral question, a repository, candidate source paths grounded in prior evidence or inspected model output, priority, expected evidence and acceptance criteria. Prefer a minimal path set that can confirm or falsify the claim. The orchestrator must validate that every candidate path is relative, inside the selected repo, non-symlink, and an allowed text file; only validated exact paths are passed to the targeted verifier.

### Stage 7 — Targeted re-read (`targeted_verifier`, isolated and path-scoped)

The agent rereads the planned files in a fresh session. It receives no prior mismatch verdict, likelihood or impact conclusion. It can report `confirmed`, `refuted`, `inconclusive`, `unable_to_verify`, or `budget_exhausted` for each task. It must cite fresh evidence from its own read or clearly identify evidence it was supplied. Its read tools must be restricted to the exact orchestrator-approved candidate paths. No shell, grep, parser, AST/IR or static scanner is allowed.

### Stage 8 — Bounded verification loop

Default `max_targeted_rounds = 2`; hard maximum recommended is 3. After each round, the planner may issue tasks only for unresolved high-impact items, contradictory evidence, high-impact cross-service paths, or an explicit evidence gap that could change the verdict. The orchestrator deduplicates repeated tasks and rejects path expansion not tied to a task. Stop when high-impact tasks are confirmed/refuted or explicitly unresolved, no new actionable path exists, or the configured budget is exhausted.

Budget exhaustion must produce `partial` plus unresolved tasks. It must never force a positive or negative conclusion.

### Stage 9 — Re-map consequences and final synthesis

Update the risk scenarios from targeted findings. Synthesis may integrate or prioritize results, but must not promote unsupported hypotheses to confirmed mismatches. It should produce per-service and cross-service views, a prioritized remediation/verification plan, assumptions, contradictory sources, uninspected paths, and explicit limitations.

### Stage 10 — Evidence audit

Run the existing `evidence_auditor` on high-priority claims, mismatches, and system-level scenarios. Claims not audited due to budget must be listed. Downgrade claims with unsupported or inconclusive evidence. Auditor output is independent critique, not formal proof.

## 6. State machine and transition gates

```text
INTAKE
  -> BUSINESS_INTENT_MODELLING (per repo)
  -> BLINDED_INVARIANT_CHALLENGE
  -> IMPLEMENTATION_TRACING (per repo)
  -> INTENT_IMPLEMENTATION_COMPARISON
  -> PRELIMINARY_SECURITY_MAPPING
  -> VERIFICATION_PLANNING
  -> TARGETED_REREAD (round 1..N)
  -> FINAL_SECURITY_MAPPING
  -> FINAL_SYNTHESIS
  -> EVIDENCE_AUDIT
  -> PUBLISH
```

Transition requirements:

- Do not run comparison before intent and implementation trace are available; missing prerequisites force `not_verified`/`unknown`.
- Do not mark a mismatch confirmed from source inference alone.
- Do not spawn targeted verification without a question, repo and approved exact path list.
- Do not let the verifier choose or expand its own allowed paths.
- Do not publish a high-priority mismatch as confirmed until targeted verification and evidence audit support it.
- If any mandatory job fails, publish partial results with a failure/coverage record instead of fabricating an empty success.

## 7. Priority and confidence

### Priority (triage urgency)

- `P0`: potential critical financial/customer/account integrity, cross-account authorization, major data exposure or systemic trust failure. This is review urgency, not a confirmed severity.
- `P1`: high-impact authorization, transaction/state integrity, identity/token propagation, sensitive-data boundary, replay/idempotency or auditability question.
- `P2`: medium impact or limited scope with a plausible security consequence.
- `P3`: low-impact hardening, design hygiene, or low-confidence lead.

Priority may be high while the claim remains unverified. Never conflate priority with proof or exploitability.

### Confidence

- `high`: authoritative expected behavior is evidenced; relevant implementation path is directly traced; independent targeted verification corroborates the comparison; no unresolved contradiction changes the outcome.
- `medium`: most of the path is traced but one material hop/source-authority issue remains, or the conclusion depends on a bounded derivation.
- `low`: intent is inferred, trace is partial, behavior depends on unseen configuration/runtime, or the scenario is chiefly a hypothesis.
- `not_assessed`: evidence has not been evaluated.

A high-confidence mismatch is not the same as high attack likelihood. Store `business_impact`, `security_impact`, `exploitability` and `confidence` separately.

## 8. Business invariant coverage guide

Use this as a *question bank*, not as proof that every listed rule applies. Select applicable categories only when supported by service context:

- identity/account/customer ownership and tenant isolation;
- actor, role, delegation, approval and segregation-of-duties constraints;
- transaction amount, currency, fee, limit, balance/reservation and ledger consistency;
- valid state transitions, replay, idempotency, duplication, retries and compensation/reversal;
- onboarding/KYC/account lifecycle where present;
- card/token/credential handling and callback/event authenticity where present;
- message producer/consumer authorization and schema/event trust;
- privacy, data minimization, response filtering and notification leakage;
- audit, reconciliation, trace/correlation and non-repudiation;
- consistency of checks across mobile/BFF/gateway/service/worker/consumer hops;
- availability and failure behavior where retry storms, lock contention or partial success can affect customers or transaction integrity.

Do not automatically assume a payment invariant applies to an unrelated service. If the domain is unknown, ask a question or mark `not_assessed`.

## 9. Final outputs

Per repository, write:

- `15_business_intent.json`
- `16_implementation_trace.json`
- `17_targeted_verification.json`
- `18_business_phase_coverage.json`
- `19_business_phase_evidence_index.json`
- `20_business_phase_execution.json`
- `21_business_aware_review.md`

Under `documents/_system/`, write:

- `06_business_invariant_challenges.json`
- `07_intent_implementation_comparison.json`
- `08_preliminary_security_consequences.json`
- `09_verification_plan.json`
- `10_final_security_consequences.json`
- `11_business_aware_security_review.json`
- `12_business_aware_security_review.md`
- `13_business_phase_evidence_audit.json`
- `14_business_phase_coverage.json`
- `15_business_phase_execution.json`

The final system report must contain: project business workflow map, invariant register, confirmed mismatches, plausible/unverified mismatches, security scenarios, cross-service responsibility gaps, prioritized actions, conflicting source notes, uncovered paths, tasks not run, and explicit statements of what remains unknown.

## 10. Job contract and prompt ownership

Every specialist job uses `job-contract.schema.json`. Its system mandate is loaded from a version-controlled template referenced by `registry.json`. The orchestrator fills only schema-defined runtime fields (run/repo IDs, bounded input artifacts, invariant/task IDs, exact path allow-list, evidence catalog and budget). It must not generate a new role prompt or dynamically rewrite the mandate.

The source and docs read by AI are untrusted data, not prompt instructions. No agent may run shell commands, make network calls, write to source repositories, or self-modify the registry, schemas or prompts.

## 11. Coverage reporting

Report coverage by dimensions, not a fake percent of repository reviewed:

- which repositories had business-intent and implementation-trace jobs;
- which invariants were modeled, traced, compared, targeted and audited;
- exact files/line ranges read during targeted verification;
- high-priority items lacking authoritative intent;
- unresolved/contradictory sources;
- candidate paths unavailable or rejected by scope validation;
- tasks skipped, failed, or not audited due to budget;
- budget exhaustion and model/session failures.

`phase_workflow_status = completed` means the configured jobs completed. It does not mean every business invariant or vulnerability was found. `security_posture` must remain `undetermined` unless independent operational testing outside this phase establishes more.
