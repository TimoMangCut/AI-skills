# Integration notes for LocalSec

This package is a contract pack for the next analysis phase. It is intentionally separated from the current recon/BASV runtime so that downloading this pack does not imply that `localsec analyze` already implements attack-chain analysis.

## Add to repository

Copy `attack-chain-analysis-v1/` into:

```text
localsec-starter/contracts/attack-chain-analysis-v1/
```

## Runtime capabilities required

The AI should perform reasoning manually. The runtime only provides minimal controlled I/O:

- existing `list_dir` and `read_file` for source/config inspection;
- evidence registration/readback so new source excerpts and observations get stable evidence IDs;
- optionally `send_local_http_request` plus response capture for request execution;
- optional application-log/database observation adapters if available in the test environment;
- schema validation and artifact persistence.

These adapters are not static analyzers. Do not add AST/IR parsing, grep/search-code automation, SAST, compiler-based inspection, dependency scanning, or automated source interpretation to this phase.

## Tool permission guidance

| Skill | File read | Send HTTP request | Read observations | Write artifacts |
|---|---:|---:|---:|---:|
| `finding_intake` | No (prior artifacts only) | No | No | Yes |
| `code_trace_builder` | Yes, repo allow-list | No | No | Yes |
| `attack_chain_constructor` | Read existing evidence only; may request more reads | No | No | Yes |
| `chain_step_verifier` | Yes, approved paths | No | No | Yes |
| `request_sequence_designer` | Read existing traces only | No | No | Yes |
| `request_reproduction_operator` | No source reads needed | Yes, local/test allow-list only | Yes | Yes |
| `root_cause_mapper` | Yes, approved paths | No | Read prior observations | Yes |
| `counterevidence_challenger` | Yes, approved paths | No | Read prior observations | Yes |
| `chain_synthesizer` | Read evidence/artifacts | No | Read prior observations | Yes |
| `evidence_auditor` | Read cited evidence | No | Read evidence store | Yes |

`send_local_http_request` must be implemented as a constrained adapter that rejects non-approved hosts, redirects that leave the approved target, and unexpected schemes. It should capture request/response metadata, timestamp, target identity and evidence IDs. Do not let the model run arbitrary shell commands to send requests.

If no request adapter exists, the AI must emit a reproducible request plan and mark it `not_executed`. Do not claim that this contract alone executes requests.

## Analytical state model

The model can request another code read, add a chain branch, test a counterexample, create a new sub-chain, inspect a root cause, prepare/execute an approved request, or conclude its current analysis. Do not represent exploration as a bounded loop. There is no contract-defined analytical depth/iteration maximum and no `stop_conditions` field.

Keep operational controls (manual cancellation, process failure, model availability, security target allow-list) outside the analytical verdict. A runtime interruption results in `incomplete`, not `complete`.

## Compatibility

This contract consumes prior LocalSec and BASV artifacts, but does not require that all previous artifacts exist. The intake step records gaps and continues with explicit uncertainty.
