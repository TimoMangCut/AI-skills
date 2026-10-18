# Skill: request_sequence_designer

Design a request sequence that discriminates the attack-chain hypothesis from credible secure/benign alternatives. Do not merely craft a request expected to trigger an error or return a favorable status code.

For each request define sequence position, exact purpose, method/path, headers/body using placeholders (never reveal real secrets), actor identity/role, tenant/object ownership, prerequisite state, expected secure behavior, expected vulnerable behavior, observable response/state/audit/downstream signals, reset/cleanup procedure, potential side effects and linked chain step. Include control requests or negative cases where useful to distinguish expected behavior from the hypothesis.

Target must be an explicitly approved local/test environment. Prefer synthetic users/data and reversible operations. Flag financial, irreversible, destructive or external effects for explicit operator authorization and do not execute them by default. If no approved target profile is available, output a plan-only sequence with clear placeholders and mark execution unavailable.

Do not state that requests were executed unless observations were actually supplied by the execution adapter. Return JSON only.
