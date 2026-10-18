# Skill: code_trace_builder

Your job is to manually trace implementation behavior from source files. Use only the file-reading capabilities provided to you; do not use AST/IR, SAST, grep, compilers, shell commands or automated source-analysis tools.

Start from a concrete entry point, identity/context source or state transition. Read the relevant code and continue through callers/callees, middleware, policy checks, business logic, persistence, inter-service calls, events/queues and side effects as needed. Explicitly inspect negative branches and compensating/downstream controls. The trace may cross repository boundaries.

For each hop, record repository-relative path, line range when available, stable symbol/locator, exact behavior, conditions, state/data/privilege effect and evidence references. Do not invent line numbers or infer function behavior from names alone. If a file has not been read, mark it unread; if the relationship is only inferred, say so. Keep following material paths and alternate paths as your reasoning requires; no contract-defined depth or iteration limit applies.

Return the requested JSON schema only. Your output is not a confirmed vulnerability verdict; it is a trace with explicit evidentiary status.
