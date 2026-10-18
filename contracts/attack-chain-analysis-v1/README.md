# Attack Chain Analysis Contract v1.0

**Purpose:** define the post-recon analysis phase that manually reasons over source code, produces evidence-backed code traces, constructs and validates multi-step attack chains, designs request sequences, verifies outcomes where an approved local test target is available, and maps chains to root causes.

This package is a **contract/prompt/schema pack**. It does not by itself add runtime tools or wire a new phase into the LocalSec orchestrator. See `INTEGRATION.md` for the integration points.

## Governing decision: no system-imposed analytical stop condition

There is **no prescribed maximum attack-chain depth, number of branches, number of verification iterations, or semantic stop condition** in this contract. The model decides whether to continue exploring, ask the operator for missing context, or conclude its current analysis. The operator may redirect, constrain, or end the analysis at any time. A runtime/process interruption is an operational event, not evidence that analysis is complete; incomplete work must remain explicitly incomplete.

This does not mean that an unsupported chain may be presented as verified. Depth is open-ended; evidentiary standards are not.

## Non-negotiable principles

1. **Chain-first, not finding-first.** Single findings are nodes or candidate enablers. The primary analysis unit is a path from attacker-controlled starting conditions to a concrete business/security outcome.
2. **Manually reason over source.** The AI chooses files and traces behavior using the permitted file-reading tools. Do not invoke AST/IR parsers, SAST, grep, compilers, dependency scanners, or other automated source-analysis tools for this phase.
3. **Evidence per step and per edge.** Prove not only each step, but also why state/control/data produced by one step makes the next step possible.
4. **Separate source evidence from runtime evidence.** A code path that appears exploitable is not the same as a reproduced exploit. A request returning `200` is not, by itself, proof of impact.
5. **Maximize credible impact, not rhetoric.** Explore composition, privilege changes, sensitive data paths, transaction-state changes, lateral movement between services, fraud-enabling behavior, audit evasion, and blast radius where the code and environment support them. Never inflate severity beyond the demonstrated or defensibly supported outcome.
6. **Pursue root cause.** Continue beyond the first visible bug to find the flawed invariant, authorization boundary, trust assumption, state machine, data ownership, configuration, or design decision that enables the chain.
7. **Challenge the input.** Prior recon/threat-model outputs are leads, not truth. Re-read source and configuration, search for counterexamples, alternate call paths, guards, compensating controls, and contradictory evidence.
8. **Local/authorized reproduction only.** Send requests only to an explicitly authorized local/test target. Use synthetic identities and disposable data. State-changing, financial, irreversible, destructive, or externally routed actions require explicit operator authorization and an agreed safe fixture; default to plan-only when unavailable.
9. **Unknown is a valid result.** Missing access, missing source, unavailable runtime, or ambiguous business intent must not be silently converted into a claim of exploitability or safety.

## Package contents

- `ATTACK_CHAIN_ANALYSIS.md`: phase contract and detailed reasoning requirements.
- `orchestration-contract.json`: stage contracts and model-directed exploration loop; intentionally contains no `stop_conditions`, `max_depth`, `max_rounds`, or bounded exploration loop.
- `registry.json`: skill identities, inputs/outputs, allowed tools, and prompt references.
- `prompts/`: immutable templates for each specialist role.
- `schemas/`: JSON Schemas for chain, code trace, request reproduction, step verification, root cause, and final session output.
- `examples/`: illustrative chain record and request sequence using fictional endpoints/data.
- `INTEGRATION.md`: how to attach this contract to LocalSec without implying runtime support that is not present.

## Suggested artifacts

```text
documents/_analysis/
  00_analysis_manifest.json
  01_candidate_chain_graph.json
  02_code_traces/
  03_attack_chains/
  04_request_reproductions/
  05_chain_verifications/
  06_root_cause_map.json
  07_attack_chain_analysis.md
  08_evidence_audit.json
  09_unknowns_and_counterevidence.md
```

Prefer one JSON record per chain/request/trace, with a Markdown report for human review. Evidence IDs must refer to an existing evidence index or a newly captured and recorded observation.

## Validation

All JSON files in this package are machine-parseable. JSON Schemas use Draft 2020-12 and deliberately do not set maximum lengths for chains, branches, or iteration histories. The absence of depth/iteration limits is intentional.
