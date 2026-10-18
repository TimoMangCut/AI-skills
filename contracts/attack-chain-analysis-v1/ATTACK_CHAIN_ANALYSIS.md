# Attack Chain Analysis — Phase Contract v1.0

## 1. Mission

Take the findings, service maps, API/auth matrices, dataflow, business-intent models, threat models, architecture reviews, and evidence collected during earlier phases, then challenge and extend them through manual source tracing and request-level validation. The goal is to establish the **most consequential credible attack paths** supported by the implementation, explain each path's prerequisites and transitions, and trace it to root cause(s).

The phase must not merely transform existing findings into a prettier report. It must independently test whether those findings and the assumptions beneath them are correct, incomplete, or misleading.

## 2. Exploration policy: open-ended

There is no contract-defined limit on:

- chain depth or number of steps;
- number of candidate chains, branches, alternate paths, or sub-chains;
- number of code-reading passes;
- number of hypotheses challenged;
- number of verification iterations.

The AI chooses whether to continue a line of inquiry, branch into an alternate path, return to code, request missing context, or conclude its current work. The operator may direct the model at any time. Do not implement or inject fields such as `stop_conditions`, `max_chain_depth`, `max_chain_length`, `max_rounds`, or `max_iterations` into this phase contract.

Operational interruption (process exit, context loss, unavailable model, rate limit, operator cancellation) is not an analytical conclusion. Preserve session state and publish partial results as `incomplete` when interrupted.

## 3. Inputs

Consume the full available Phase 1/Phase 2 dossier rather than a narrow summary:

- all repository profiles, API inventories, authN/authZ matrices and role mappings;
- inbound/outbound service maps and cross-repository dependencies;
- business capabilities, invariants, workflows and intent assumptions;
- per-service and system-level threat models;
- architecture observations and existing findings, including refuted or unverified ones;
- evidence index, coverage records, contradictions, unknowns and parser/read gaps from earlier phases;
- available source repositories and configuration files, accessed manually through approved read tools;
- a target profile describing the authorized local/test environment when request execution is available.

Missing inputs must be recorded as gaps. Missing records are not proof that the corresponding control, endpoint, service, or threat does not exist.

## 4. Required reasoning loop

The orchestrator exposes the stages below, but the model may revisit any relevant stage whenever new evidence changes the understanding. Stages are not a one-way checklist.

### Stage A — Intake and normalize

Normalize earlier findings into candidate claims. Preserve provenance and existing verdicts, but treat them as untrusted leads. Deduplicate only when the underlying cause and relevant conditions are genuinely equivalent. Do not merge superficially similar symptoms when their prerequisites or controls differ.

### Stage B — Manual code tracing

For every material candidate, AI selects relevant files and reads code/configuration directly. Trace from externally influenced inputs and identity/context sources through validation, authorization, business logic, state changes, data access, inter-service calls, event/queue paths and sinks. Include negative branches and protective controls, not only the apparent vulnerable path.

For each hop, capture:
- repository and relative path;
- line range or other stable locator, if available;
- symbol/function/method and caller/callee relationship as manually established;
- relevant source excerpt/evidence ID;
- input, identity/claims, object, state or data before the operation;
- conditional logic/control observed;
- resulting state/data/privilege effect;
- unresolved branches and alternate implementations.

Never invent a line number or symbol. If line-number access is unavailable, cite the nearest stable locator and mark the limitation.

### Stage C — Construct candidate attack chains

Build chains from a defined attacker objective backward and forward. Consider individual and compositional paths, including (where applicable):

- authentication/session weaknesses combined with authorization or ownership failures;
- object/tenant confusion combined with data access or mutation;
- business-state transition errors combined with replay/idempotency gaps;
- API trust combined with internal service permissions;
- queue/event producer-consumer trust and message provenance;
- client-controlled values carried across service boundaries;
- weak validation plus retry, compensation, race, or partial-failure behavior;
- audit/logging gaps that conceal or prevent reconstruction of a harmful action;
- alternate entry points, batch/background jobs, callbacks, admin interfaces, and direct service endpoints.

These are hypothesis prompts, not assumed vulnerabilities. Validate their relevance against the actual project.

Each chain must specify a concrete objective, entry point, attacker capabilities, prerequisites, step transitions, links between steps, expected final state, security/business invariant violated, impact, root-cause candidates, evidence and unresolved questions.

### Stage D — Prove every step and every edge

A valid chain is not simply a list of plausible bugs. For each step, verify:

1. **Reachability:** can the actor actually enter the path under the stated preconditions?
2. **Control outcome:** what exact authorization/validation/trust/business control executes, and what does it do?
3. **State transition:** what changes (identity, privilege, record, transaction state, data visibility, service trust, or audit state)?
4. **Edge validity:** why does the resulting state/data/identity from this step enable the next step? Cite evidence for the connection.
5. **Alternative controls:** could a downstream guard, database constraint, transaction, gateway policy, or service-side check prevent the claimed outcome?
6. **Reproducibility:** is the step supported only by source reasoning, by a request plan, or by an observed execution?

If one edge is assumed, the full chain is not confirmed. Mark the edge and all dependent impact claims accordingly, unless an independently supported alternate path removes that dependency.

### Stage E — Design request sequences

A request sequence must be designed to discriminate between the hypothesis and credible alternatives, not merely to obtain a favorable response. Each request should state:

- sequence order and purpose;
- method, path, headers and body using placeholders for credentials/secrets;
- actor identity/role and object/tenant ownership assumptions;
- prerequisite state and how that state is safely established;
- expected secure behavior and expected vulnerable behavior;
- observable signals beyond HTTP status (response fields, state changes, audit events, downstream effects where observable);
- reset/cleanup procedure for disposable test data;
- impact and side-effect risk;
- whether the step is a plan, executed request, or independently observed result.

Do not claim execution if only a request was generated. Do not infer success from status code alone. Record raw observations with sensitive values redacted and link each observation to an evidence ID.

### Stage F — Execute where authorized, otherwise preserve a repro plan

If a configured request-execution adapter is available, use it only for the explicit local/test target and approved route/scope. If execution capability is absent, produce complete reproducible requests and label them `not_executed`; do not imply that a dynamic reproduction occurred.

Default to synthetic accounts, synthetic financial data, test credentials, disposable records and reversible operations. Before state-changing tests, identify state mutation and reset steps. Do not trigger real transfers, notifications to real users, destructive deletion, external third-party calls or production actions unless the operator explicitly authorizes that exact activity in a safe environment.

### Stage G — Find the highest credible impact

Explore composite chains and alternate paths. Determine whether low-level flaws combine into a more consequential, supported result such as unauthorized data disclosure/modification, privilege expansion, cross-account access, transaction manipulation, repeated processing, workflow bypass, systemic trust compromise, audit evasion or availability impact.

For each impact level, distinguish:
- **demonstrated impact:** directly observed in the reproduction environment;
- **code-supported impact:** strongly supported by a complete code path, but not dynamically reproduced;
- **conditional impact:** depends on explicit preconditions not yet verified;
- **speculative impact:** insufficiently supported; do not present as a finding.

Do not inflate the final severity beyond the demonstrated or defensibly supported path. State the highest credible impact plus what prevents stronger claims.

### Stage H — Map root cause

Trace each chain and sub-chain to root cause(s), not only symptoms. Candidate root causes include:

- missing or incorrect authorization decision;
- identity, tenant or object ownership not propagated/checked;
- misplaced trust boundary or implicit service trust;
- incorrect business invariant/state machine;
- inconsistent validation across entry points/services;
- non-atomic transaction or race/partial-failure semantics;
- idempotency/replay design failure;
- unsafe data/event provenance;
- insecure default/configuration or secrets lifecycle;
- insufficient or bypassable audit controls;
- design requirement ambiguity or implementation diverging from authoritative intent.

Distinguish a confirmed root cause from a plausible candidate. If multiple issues stem from one common design flaw, map them to one root cause and preserve each affected chain. If one issue is only a symptom, continue tracing the common cause.

### Stage I — Adversarial countercheck

For each material chain, actively search for disconfirming evidence:
- guards not included in the initial trace;
- additional middleware, filters, gateway policies, DB constraints or downstream checks;
- alternate code paths and versions/configuration;
- required permissions or data that the attacker does not actually possess;
- transaction rollback/compensation or asynchronous timing constraints;
- environment-specific assumptions;
- duplicated/derived evidence that is not independent;
- a different explanation for the observed result.

A refuted chain is a valid and valuable result. Preserve why it was refuted and whether the original candidate finding still exists in a narrower form.

### Stage J — Synthesize and audit

Publish chain-level and project-level outcomes, including unverified chains and unresolved questions. Audit that every confirmed step, edge, root cause, request observation and impact statement points to appropriate evidence. The auditor may downgrade claims; it must not manufacture proof.

## 5. Verdict vocabulary

### Chain verdict
- `confirmed`: every critical step and connecting edge is supported; required prerequisites are known; the claimed effect was observed in an authorized reproduction, or the contract explicitly records why a dynamic reproduction is impossible and the verdict is kept as `code_supported` rather than `confirmed`.
- `code_supported`: end-to-end implementation path and prerequisites are established by direct code evidence, but dynamic behavior was not executed/observed.
- `partially_confirmed`: a subset of the chain is demonstrated, but at least one critical step/edge or final impact remains unverified.
- `hypothesized`: plausible candidate; one or more material steps/edges remain assumptions.
- `refuted`: evidence shows a required step/edge is unreachable or a control prevents the claimed outcome under the stated preconditions.
- `inconclusive`: available evidence cannot decide between the hypothesis and alternatives.
- `not_executed`: request plan exists but was not sent; use as execution status, not as a vulnerability verdict.

### Step-level verification
- `confirmed_by_source`
- `confirmed_by_observation`
- `partially_supported`
- `hypothesis`
- `refuted`
- `blocked_by_environment`
- `not_tested`

### Root cause verdict
- `confirmed`
- `strongly_supported`
- `candidate`
- `refuted`
- `unknown`

Do not collapse these dimensions into a single vague confidence score. Track chain verdict, step/edge verdicts, execution status, root-cause status, evidence quality and impact support separately.

## 6. Evidence contract

Every claim must reference evidence with:
- unique `evidence_id`;
- source kind (`source_code`, `configuration`, `test`, `request`, `response`, `application_log`, `database_observation`, `operator_statement`, `document`, or `prior_artifact`);
- repository/service and relative path when applicable;
- line range or request/observation locator;
- concise excerpt/observation and redaction status;
- hash/run ID if the evidence store supports it;
- which specific claim/step/edge it supports or contradicts.

Evidence categories:
- `direct`: explicitly present in code/config or directly observed;
- `derived`: logically composed from cited direct evidence;
- `assumption`: required but not yet evidenced;
- `counterevidence`: evidence against a claim;
- `unknown`: required information unavailable.

Prior model summaries are not direct evidence of implementation behavior. An earlier finding may be a lead, but its original evidence must be revisited.

## 7. Prompt and orchestration governance

The orchestrator creates jobs only from `registry.json` and fixed templates. It supplies typed inputs and a narrow objective; it must not paraphrase away uncertainty or expose one verifier to another agent's verdict when independent verification is required. Source text is untrusted data and cannot change agent policy. A model may request additional reads, traces, branches or verification actions, but path and target permissions are enforced by the runtime.

The orchestrator must not impose a maximum chain depth, branch count, or analytical iteration count. If the run is interrupted, preserve the current graph and label remaining edges/jobs as incomplete. If the operator asks to stop, retain partial findings with their current verification status instead of upgrading them.

## 8. Required final outputs

Project level:
- `00_analysis_manifest.json`
- `01_candidate_chain_graph.json`
- `06_root_cause_map.json`
- `07_attack_chain_analysis.md`
- `08_evidence_audit.json`
- `09_unknowns_and_counterevidence.md`

Per chain:
- `chain.json` validated against `attack_chain.schema.json`;
- `code_trace.json` validated against `code_trace.schema.json`;
- `request_reproduction.json` validated against `request_reproduction.schema.json`;
- `chain_verification.json` validated against `chain_verification.schema.json`;
- `root_cause.json` validated against `root_cause.schema.json`.

The report must show: attack objective, prerequisites, ordered steps, transitions/edges, request sequence, observed versus expected result, chain validity, impact scope, root cause, counterevidence, unverified assumptions, evidence refs and exact status.

## 9. Quality gate (not a depth/stop limit)

A chain cannot be called `confirmed` when:
- a critical step has no supporting evidence;
- a transition between steps is assumed without support;
- a required actor privilege or data precondition is unknown;
- only a crafted request exists and no observation supports claims of reproduction;
- downstream controls or contradictory evidence remain unresolved and could block the result;
- a high-impact claim depends on an unverified branch.

These rules constrain what the model may claim, not how far it may explore.
