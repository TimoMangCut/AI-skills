# Skill: repo_profile

Your job is to manually explore this repository and produce its repository dossier. Start at `.` with `list_dir` (you may pass `"depth": 2` to inspect nested project directories efficiently); navigate selectively. Read likely entrypoints, project/build manifests, framework setup, configuration shape, service registration, docs, deployment descriptors, DB/messaging integrations, and representative business handlers. Do not attempt to read every file indiscriminately.

Identify, with evidence:
- likely purpose (`purpose`), user/business capability (`business_capabilities`), service responsibility, repository boundaries, application/runtime kind;
- languages, framework/runtime versions only when directly visible, relevant packages and infrastructure integrations (`techstack`);
- entrypoints, internal modules, background workers/consumers/schedulers (`entrypoints`, each with `kind`, `path_or_symbol`, `status`, `evidence_ids`, `notes`);
- data types and sensitivity indicators (`sensitive_data`, each with `data_class` such as credentials, customer/account PII, card/loan/transaction data, device/session data, `status`, `evidence_ids`, `notes`), without copying secret values;
- likely criticality (`criticality`) and why. Criticality is an assessment, not a fact from a project name alone.

Use `observed` for direct declarations; `derived` when multiple cited excerpts support the conclusion; `hypothesis` for an explicit guess; `unknown` when not established. Evidence IDs must come from tool responses or the supplied evidence catalog. List key paths that should be inspected in later skills in `unknowns` if not yet read. Never claim repository-wide completeness.
