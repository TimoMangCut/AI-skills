# Implementation acceptance gates — BASV v1.0

Do not call the phase implemented until these checks pass.

## Orchestrator and prompt control

- [ ] The phase is a separate post-recon command/stage; it does not silently replace the existing recon flow.
- [ ] Every skill/version, prompt template, output schema, allowed tool list, read scope, prerequisite and budget comes from the versioned contract registry.
- [ ] The orchestrator does not allow an LLM to choose arbitrary skills, rewrite system mandates, modify schemas or widen permissions.
- [ ] Every job records run/job/skill IDs, template hash, initial payload hash, input artifact references, model turns, tool calls, status and warnings.
- [ ] Per-repository tasks are isolated sessions; system synthesis does not reuse hidden conversation history from a specialist.

## Manual-only analysis guarantee

- [ ] AI reads source using only the approved read-only file tools.
- [ ] No AST/IR parser, grep, shell, SAST, compiler, runtime execution or code-derived static graph builder is called by this phase.
- [ ] Prior recon artifacts are treated as leads, not as complete or guaranteed-correct input.
- [ ] All source text is treated as untrusted data, not instructions.

## Targeted re-read enforcement

- [ ] Candidate paths from model output are validated by the program as relative, inside the assigned repository, regular non-symlink files and permitted text files.
- [ ] The targeted verifier's actual filesystem tool boundary enforces the exact allow-list. A prompt-only instruction does not pass this gate.
- [ ] If a task has no valid candidate path, it is marked `path_unknown`/`unable_to_verify`; the verifier does not widen scope.
- [ ] Targeted verification receives a neutral question and is blinded to previous mismatch verdict, security impact, exploitability and preferred conclusion.
- [ ] Iterations are bounded (default 2, hard limit 3); duplicate tasks are removed; exhausted tasks remain unresolved.

## Business truth and mismatch gate

- [ ] Each candidate invariant records basis, source authority, evidence IDs and uncertainty.
- [ ] Code alone cannot establish authoritative business intent.
- [ ] A `mismatch` requires authoritative expectation evidence plus directly traced contradictory implementation behavior.
- [ ] An incomplete path or uninspected control becomes `not_verified`, not “missing control”.
- [ ] Inferred business rules become `intent_ambiguous` unless corroborated by authoritative input.
- [ ] Business correctness, security relevance, impact, exploitability, priority and confidence are distinct fields.

## Evidence and output quality

- [ ] All schemas parse and all skill outputs are validated before downstream handoff.
- [ ] Evidence IDs must exist in actual prior artifacts or reads made available to that job; no evidence fabrication.
- [ ] Cross-repository references cite evidence from the relevant participating repositories.
- [ ] The existing evidence auditor is applied to high-priority claims; not-audited items are explicitly listed.
- [ ] Audit verdicts can downgrade status; model confidence cannot override unsupported evidence.
- [ ] Output coverage describes actual jobs and re-read file ranges, not a synthetic percent of the repository.
- [ ] Partial/budget-exhausted runs publish partial results and unknowns, not a false success.
- [ ] A successful workflow never implies the project is secure or that all business rules were discovered.

## Required test suite

- [ ] Happy-path multi-repository run with a mock local model.
- [ ] Missing business requirements results in `intent_ambiguous`, not a confirmed mismatch.
- [ ] Conflicting requirement sources are retained as conflicts and prevent premature confirmation.
- [ ] Targeted verifier is unable to read a path outside its allow-list even if it requests one explicitly.
- [ ] Path traversal, absolute path, symlink and nonexistent paths are rejected.
- [ ] Unsupported or inconclusive evidence-audit results downgrade claims.
- [ ] Budget exhaustion and absent candidate paths produce unresolved status and coverage gaps.
- [ ] Prompt/schema version hashes and job logs are written without exposing absolute repository paths or unredacted secrets.
