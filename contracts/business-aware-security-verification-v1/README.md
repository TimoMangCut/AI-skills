# Business-aware Security Verification — Contract Pack v1.0

This is an implementation-ready contract pack for the post-recon phase of LocalSec AI Manual Pipeline. It is deliberately separate from the v0.2 runtime skill registry: **adding these files does not mean the current `localsec analyze` command executes this phase**. Wire the contract into the orchestrator as a separate phase/command after recon artifacts exist.

## Objective

Determine, with evidence and explicit uncertainty, whether the implementation matches the business intent that can actually be established from available sources; identify mismatches and ambiguity; map security consequences; and actively re-read source to challenge initial interpretations.

## Contents

- `BUSINESS_AWARE_SECURITY_VERIFICATION.md`: normative phase definition, evidence/confidence model, and state machine.
- `orchestration-contract.json`: machine-readable stage order, retry bounds, context isolation, and stop gates.
- `job-contract.schema.json`: per-agent job envelope.
- `registry.json`: skills, prompt/schema references, dependencies, tool permissions, and input/output contracts.
- `prompts/`: immutable prompt mandates for each specialist skill.
- `schemas/`: required JSON output schemas for each skill, job contract, input artifact manifest and phase coverage.
- `IMPLEMENTATION_ACCEPTANCE.md`: acceptance gates that must pass before the phase is called implemented.
- `examples/decision-examples.md`: fictional examples for distinguishing intent ambiguity from a defensible mismatch.

## Runtime assumptions

- The AI, not a parser or scanner, manually explores code, tests, API contracts, business documents, configuration, and cross-service interactions.
- Allowed source tools remain read-only `list_dir` and `read_file`; targeted verification additionally requires an orchestrator-enforced exact-file allow-list.
- The orchestration layer may validate paths, read previously generated JSON/Markdown artifacts, validate schemas, route jobs, enforce budgets, and persist outputs. It must not use AST/IR, grep, SAST, shell, compiler, or other static analysis as a substitute for AI reasoning.
- Business source-of-truth material may be absent. When it is absent, the correct result is `intent_ambiguous` / `not_verified`, not a fabricated business requirement or a declared developer defect.

## Integration sequence

1. Load all per-repository recon dossiers and cross-repository dossiers.
2. Run `business_intent_modeler` in isolated per-repository sessions.
3. Run `business_invariant_challenger` with a deliberately blinded context that excludes previous threat models and findings.
4. Run `implementation_trace_verifier` separately for each repository, manually tracing real paths through authorization, validation, business logic, state changes, persistence, side effects, and audit.
5. Run `intent_implementation_comparator` to distinguish alignment, mismatch, ambiguity, conflict, and unverified behavior.
6. Run `security_consequence_mapper` to create security scenarios without promoting hypotheses to confirmed findings.
7. Run `verification_planner`, then `targeted_verifier` with read permission restricted to the exact candidate paths selected by the orchestrator. Repeat at most the configured number of rounds.
8. Re-run consequence mapping using targeted results, then run `business_aware_synthesizer` and the existing `evidence_auditor`.
9. Publish final reports and coverage/unknowns. Never report a clean security posture merely because the configured workflow completed.

See the contract document before implementing the phase runner.
