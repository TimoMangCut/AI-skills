from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
BASV_SCHEMA_DIR = ROOT / "contracts" / "business-aware-security-verification-v1" / "schemas"
ACA_SCHEMA_DIR = ROOT / "contracts" / "attack-chain-analysis-v1" / "schemas"

SKILL_SCHEMA = {
    "repo_profile": "repo_profile.schema.json",
    "api_authz": "api_authz.schema.json",
    "dataflow": "dataflow.schema.json",
    "threat_model": "threat_model.schema.json",
    "architecture_review": "architecture_review.schema.json",
    "cross_repo_review": "cross_repo_review.schema.json",
    "evidence_auditor": "evidence_audit.schema.json",
    "diagram_author": "diagrams.schema.json",
    # Phase 2: Business-aware Security Verification (BASV v1.0)
    "business_intent_modeler": "business_intent_model.schema.json",
    "business_invariant_challenger": "business_invariant_challenge.schema.json",
    "implementation_trace_verifier": "implementation_trace.schema.json",
    "intent_implementation_comparator": "intent_implementation_comparison.schema.json",
    "security_consequence_mapper": "security_consequence_map.schema.json",
    "verification_planner": "verification_plan.schema.json",
    "targeted_verifier": "targeted_verification.schema.json",
    "business_aware_synthesizer": "business_aware_synthesis.schema.json",
    "artifact_manifest": "artifact_manifest.schema.json",
    "business_phase_coverage": "business_phase_coverage.schema.json",
    "job_contract": "job-contract.schema.json",
    # Phase 3: Attack Chain Analysis (ACA v1.0)
    "finding_intake": "candidate_claims.schema.json",
    "code_trace_builder": "code_trace.schema.json",
    "attack_chain_constructor": "attack_chain.schema.json",
    "chain_step_verifier": "chain_verification.schema.json",
    "request_sequence_designer": "request_reproduction.schema.json",
    "request_reproduction_operator": "request_reproduction.schema.json",
    "root_cause_mapper": "root_cause.schema.json",
    "counterevidence_challenger": "counterevidence_challenge.schema.json",
    "chain_synthesizer": "chain_synthesis_report.schema.json",
    "aca_evidence_auditor": "chain_verification.schema.json",
    "analysis_session": "analysis_session.schema.json",
    # LocalSec v3.0 skills & artifacts
    "codebase_scout": "__inline_codebase_scout__",
    "extractor_tailor": "__inline_extractor_tailor__",
    "coverage_ledger": "__inline_coverage_ledger__",
    "intent_invariant_modeler": "__inline_intent_invariant_modeler__",
    "unified_surface_mapper": "__inline_unified_surface_mapper__",
    "cross_repo_and_arch_review": "__inline_cross_repo_and_arch_review__",
    "coverage_and_evidence_auditor": "__inline_coverage_and_evidence_auditor__",
    "candidate_intake_planner": "__inline_candidate_intake_planner__",
    "deep_trace_chain_analyst": "__inline_deep_trace_chain_analyst__",
    "blinded_counterevidence_challenger": "__inline_blinded_counterevidence_challenger__",
    "analysis_evidence_gate": "__inline_analysis_evidence_gate__",
    "actor_and_feasibility_assessor": "__inline_actor_and_feasibility_assessor__",
    "beyond_code_control_mapper": "__inline_beyond_code_control_mapper__",
    "sfop_risk_calibrator": "__inline_sfop_risk_calibrator__",
}
ACA_SKILLS = {
    "finding_intake",
    "code_trace_builder",
    "attack_chain_constructor",
    "chain_step_verifier",
    "request_sequence_designer",
    "request_reproduction_operator",
    "root_cause_mapper",
    "counterevidence_challenger",
    "chain_synthesizer",
    "aca_evidence_auditor",
    "analysis_session",
}
V30_SKILLS = {
    "codebase_scout",
    "extractor_tailor",
    "coverage_ledger",
    "intent_invariant_modeler",
    "unified_surface_mapper",
    "cross_repo_and_arch_review",
    "coverage_and_evidence_auditor",
    "candidate_intake_planner",
    "deep_trace_chain_analyst",
    "blinded_counterevidence_challenger",
    "analysis_evidence_gate",
    "actor_and_feasibility_assessor",
    "beyond_code_control_mapper",
    "sfop_risk_calibrator",
}
ALLOWED_STATUSES = {
    "observed",
    "derived",
    "hypothesis",
    "unknown",
    "not_assessed",
    "confirmed",
    "absent",
    "covered_clean",
    "covered_finding",
    "reopened",
    "deferred_out_of_budget",
    "checked_found",
    "checked_not_found",
    "not_applicable",
    "present",
    "missing",
    "partial",
    "refuted",
    "weakened",
    "code_supported",
    "partially_confirmed",
    "hypothesized",
    "confirmed_by_source",
    "confirmed_by_observation",
    "directly_read",
    "inferred_from_context",
    "supported",
    "partially_supported",
    "inconclusive",
    "unsupported",
    "open",
    "resolved",
    "queued_as_candidate",
    "uncovered_gap",
    "yes",
    "no",
    "true",
    "false",
    "satisfied",
    "unsatisfied",
    "impossible",
    "unverified",
    "unassessed",
    "covered_safe",
    "flagged_for_phase_2",
    "deferred",
}
EVIDENCE_ID_KEYS = (
    "evidence_ids",
    "intent_evidence_ids",
    "implementation_evidence_ids",
    "counter_evidence_ids",
    "counterevidence_ids",
    "sample_evidence_ids",
    "representative_deep_read_evidence_ids",
    "caller_evidence_ids",
    "callee_evidence_ids",
    "ownership_evidence_ids",
    "risk_override_evidence_ids",
)
EVIDENCE_REF_KEYS = ("evidence_refs", "counterevidence_refs", "existing_evidence_refs")

IMPACT_RANK: dict[str, int] = {
    "negligible": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "catastrophic": 5,
}

ALLOWED_SEVERITIES = {
    "catastrophic",
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "negligible",
}

IMPACT_LEVELS = {
    "catastrophic",
    "critical",
    "high",
    "medium",
    "low",
    "negligible",
}

VALID_OWNER_ROLES = {
    "dev_team",
    "infra_cloud_sec",
    "iam_platform",
    "ot_safety_engineering",
    "data_privacy_dpo",
    "unassigned_pending_roster",
}

VALID_BLAST_RADIUS = {
    "component",
    "service",
    "domain",
    "cross_domain",
    "platform",
}

VALID_CONTROL_SEARCH_STATUSES = {
    "checked_found",
    "checked_not_found",
    "not_applicable",
}

V30_INLINE_SCHEMAS: dict[str, dict[str, Any]] = {
    "__inline_codebase_scout__": {
        "type": "object",
        "required": ["repo_tier", "product_archetypes", "target_modules", "ignored_modules", "coding_conventions", "sample_evidence_ids"],
        "properties": {
            "repo_tier": {"type": "string", "enum": ["tier_1", "tier_2", "tier_3"]},
            "product_archetypes": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "target_modules": {"type": "array", "minItems": 1},
            "ignored_modules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["path", "reason"],
                    "properties": {
                        "path": {"type": "string", "minLength": 1},
                        "reason": {"type": "string", "minLength": 3},
                    },
                },
            },
            "coding_conventions": {"type": "object"},
            "sample_evidence_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        },
    },
    "__inline_extractor_tailor__": {
        "type": "object",
        "required": ["mode", "rationale", "canary_files", "canary_verified"],
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["USE_STANDARD_EXTRACTOR", "USE_TAILORED_EXTRACTOR", "TAILOR_CUSTOM_EXTRACTOR", "SKIP_EXTRACTOR_DIRECT_READ"],
            },
            "rationale": {"type": "string", "minLength": 3},
            "canary_files": {"type": "array", "items": {"type": "string"}},
            "canary_verified": {"type": "boolean"},
            "script_path": {"type": "string"},
            "patterns_file": {"type": "string"},
            "expected_canary_hits": {"type": "integer", "minimum": 0},
        },
    },
    "__inline_coverage_ledger__": {
        "type": "object",
        "required": ["records", "semantic_clusters"],
        "properties": {
            "records": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["coverage_id", "status", "evidence_ids", "attempts"],
                    "properties": {
                        "coverage_id": {"type": "string", "minLength": 7},
                        "status": {
                            "type": "string",
                            "enum": ["covered_clean", "covered_finding", "reopened", "deferred_out_of_budget"],
                        },
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                        "attempts": {"type": "array", "minItems": 1, "items": {"type": "object"}},
                    },
                },
            },
            "semantic_clusters": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["cluster_id", "representative_deep_read_evidence_ids", "member_endpoints", "outliers"],
                    "properties": {
                        "cluster_id": {"type": "string", "minLength": 1},
                        "shared_control_signature": {"type": "string"},
                        "shared_guard_signature": {"type": "string"},
                        "representative_deep_read_evidence_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                        "member_endpoints": {"type": "array", "minItems": 1},
                        "outliers": {"type": "array"},
                    },
                },
            },
        },
    },
    "__inline_intent_invariant_modeler__": {
        "type": "object",
        "required": ["invariants", "self_challenged_gaps"],
        "properties": {
            "repo_name": {"type": "string"},
            "capabilities": {"type": "array", "items": {"type": "object"}},
            "invariants": {"type": "array", "items": {"type": "object"}},
            "sfop_invariants": {"type": "array", "items": {"type": "object"}},
            "self_challenged_gaps": {"type": "array"},
            "self_review_gaps": {"type": "array"},
            "blinded_challenges": {"type": "array", "items": {"type": "object"}},
            "unknowns": {"type": "array", "items": {"type": "string"}},
        },
    },
    "__inline_unified_surface_mapper__": {
        "type": "object",
        "required": ["surface_checklist", "entrypoints", "semantic_clusters", "invariant_checks", "candidate_queue"],
        "properties": {
            "repo_name": {"type": "string"},
            "entrypoints": {"type": "array", "items": {"type": "object"}},
            "semantic_clusters": {"type": "array", "items": {"type": "object"}},
            "outliers": {"type": "array"},
            "invariant_checks": {"type": "array", "items": {"type": "object"}},
            "surface_checklist": {"type": ["array", "object"]},
            "data_flows": {"type": "array", "items": {"type": "object"}},
            "candidate_queue": {"type": "array", "items": {"type": "object"}},
            "records": {"type": "array", "items": {"type": "object"}},
            "unknowns": {"type": "array", "items": {"type": "string"}},
        },
    },
    "__inline_cross_repo_and_arch_review__": {
        "type": "object",
        "required": ["architecture_findings", "matched_cross_repo_boundaries", "diagrams", "summary"],
        "properties": {
            "repo_name": {"type": "string"},
            "interactions": {"type": "array", "items": {"type": "object"}},
            "trust_assumptions": {"type": "array", "items": {"type": "object"}},
            "architecture_findings": {"type": "array", "items": {"type": "object"}},
            "matched_cross_repo_boundaries": {"type": "array", "items": {"type": "object"}},
            "boundary_mismatches": {"type": "array", "items": {"type": "object"}},
            "architecture_observations": {"type": "array", "items": {"type": "object"}},
            "diagrams": {"type": "array"},
            "mermaid_diagram": {"type": "string"},
            "summary": {"type": "string"},
            "unknowns": {"type": "array", "items": {"type": "string"}},
        },
    },
    "__inline_coverage_and_evidence_auditor__": {
        "type": "object",
        "required": ["visibility_audit_passed", "audited_claims", "downgraded_claims", "summary"],
        "properties": {
            "repo_name": {"type": "string"},
            "visibility_audit_passed": {"type": "boolean"},
            "gate_passed": {"type": "boolean"},
            "audit_status": {"type": "string"},
            "audited_claims": {"type": "array", "items": {"type": "object"}},
            "downgraded_claims": {"type": "array"},
            "visibility_report": {"type": "object"},
            "summary": {"type": "string"},
        },
    },
    "__inline_candidate_intake_planner__": {
        "type": "object",
        "required": ["selected_companions", "deduplicated_batches", "summary"],
        "properties": {
            "repo_name": {"type": "string"},
            "candidates": {"type": "array", "items": {"type": "object"}},
            "selected_companions": {"type": "array"},
            "selected_companion_ids": {"type": "array", "items": {"type": "string"}},
            "deduplicated_batches": {"type": "array", "items": {"type": "object"}},
            "batches": {"type": "array", "items": {"type": "object"}},
            "excluded_companions": {"type": "array", "items": {"type": "object"}},
            "summary": {"type": "string"},
        },
    },
    "__inline_deep_trace_chain_analyst__": {
        "type": "object",
        "required": ["chains", "unexploitable_candidates"],
        "properties": {
            "repo_name": {"type": "string"},
            "chains": {"type": "array", "items": {"type": "object"}},
            "unexploitable_candidates": {"type": "array", "items": {"type": "object"}},
            "root_causes": {"type": "array", "items": {"type": "object"}},
            "unknowns": {"type": "array", "items": {"type": "string"}},
        },
    },
    "__inline_blinded_counterevidence_challenger__": {
        "type": "object",
        "required": ["challenged_chains"],
        "properties": {
            "repo_name": {"type": "string"},
            "challenged_chains": {"type": "array", "items": {"type": "object"}},
            "challenges": {"type": "array", "items": {"type": "object"}},
            "chain_challenges": {"type": "array", "items": {"type": "object"}},
            "control_search_checklist": {"type": ["array", "object"]},
            "empirical_refutations": {"type": "array", "items": {"type": "object"}},
        },
    },
    "__inline_analysis_evidence_gate__": {
        "type": "object",
        "required": ["empirical_refutations_ledger", "confirmed_reachable_chains", "downgraded_or_refuted_chains", "summary"],
        "properties": {
            "repo_name": {"type": "string"},
            "gate_passed": {"type": "boolean"},
            "audit_status": {"type": "string"},
            "audited_claims": {"type": "array", "items": {"type": "object"}},
            "empirical_refutations_ledger": {"type": "array", "items": {"type": "object"}},
            "confirmed_reachable_chains": {"type": "array"},
            "downgraded_or_refuted_chains": {"type": "array"},
            "surviving_chains": {"type": "array", "items": {"type": "string"}},
            "summary": {"type": "string"},
        },
    },
    "__inline_actor_and_feasibility_assessor__": {
        "type": "object",
        "anyOf": [{"required": ["actor_assessments"]}, {"required": ["assessments"]}],
        "properties": {
            "actor_assessments": {"type": "array", "items": {"type": "object"}},
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "finding_id",
                        "minimum_viable_actor",
                        "identity_acquisition_cost",
                        "operational_preconditions",
                        "blocked_by_environment",
                        "evidence_ids",
                    ],
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "chain_id": {"type": "string"},
                        "minimum_viable_actor": {
                            "type": "string",
                            "enum": [
                                "unauthenticated_external",
                                "authenticated_consumer_b2c",
                                "enterprise_partner_dealer",
                                "internal_employee_operator",
                                "compromised_edge_device_tbox_charger_robot",
                                "privileged_admin_devops",
                            ],
                        },
                        "identity_acquisition_cost": {"type": "string", "enum": ["low", "medium", "high"]},
                        "operational_preconditions": {"type": "array"},
                        "blocked_by_environment": {"type": "boolean"},
                        "blocker_details": {"type": "string"},
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
        },
    },
    "__inline_beyond_code_control_mapper__": {
        "type": "object",
        "anyOf": [{"required": ["beyond_code_controls"]}, {"required": ["assessments"]}],
        "properties": {
            "beyond_code_controls": {"type": "array", "items": {"type": "object"}},
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["finding_id", "exposure_tier", "compensating_controls"],
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "chain_id": {"type": "string"},
                        "exposure_tier": {
                            "type": "string",
                            "enum": [
                                "internet_public_behind_cloudflare_waf",
                                "internet_public_bare_alb_direct_ip",
                                "partner_b2b_mtls_vpn",
                                "internal_vpc_rfc1918",
                                "air_gapped_ot_cell_vlan",
                            ],
                        },
                        "compensating_controls": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["layer", "control", "status", "mitigation_effect", "evidence_ids"],
                                "properties": {
                                    "layer": {"type": "string"},
                                    "control": {"type": "string"},
                                    "status": {"type": "string", "enum": ["confirmed", "observed", "hypothesis", "absent", "unknown"]},
                                    "mitigation_effect": {
                                        "type": "string",
                                        "enum": ["blocks_exploit", "reduces_likelihood", "limits_blast_radius", "partial_mitigation", "none"],
                                    },
                                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    "__inline_sfop_risk_calibrator__": {
        "type": "object",
        "required": ["calibrated_findings"],
        "properties": {
            "calibrated_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "finding_id",
                        "impact_axes",
                        "max_impact",
                        "contextual_risk_rating",
                        "risk_owner",
                    ],
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "chain_id": {"type": "string"},
                        "code_verified_severity": {
                            "type": "string",
                            "enum": ["catastrophic", "critical", "high", "medium", "low", "informational", "negligible"],
                        },
                        "exploitability_likelihood": {
                            "type": "string",
                            "enum": ["high", "medium", "low", "theoretical"],
                        },
                        "impact_axes": {
                            "type": "object",
                            "required": ["safety", "financial", "operational", "privacy", "compliance"],
                            "properties": {
                                "safety": {"type": ["string", "object"]},
                                "financial": {"type": ["string", "object"]},
                                "operational": {"type": ["string", "object"]},
                                "privacy": {"type": ["string", "object"]},
                                "compliance": {"type": ["string", "object"]},
                            },
                        },
                        "max_impact": {"type": "string", "enum": ["catastrophic", "critical", "high", "medium", "low", "negligible"]},
                        "contextual_risk_rating": {
                            "type": "string",
                            "enum": ["catastrophic", "critical", "high", "medium", "low", "informational", "negligible"],
                        },
                        "risk_owner": {"type": "string", "minLength": 2},
                        "owner_role": {"type": "string"},
                        "safety_owner": {"type": ["string", "null"]},
                        "blast_radius": {"type": "string"},
                        "sfop_details": {"type": "object"},
                        "rationale": {"type": "string"},
                    },
                },
            }
        },
    },
}


class OutputValidationError(ValueError):
    pass


ValidationError = OutputValidationError


def load_schema(skill_name: str) -> dict[str, Any]:
    """Load JSON schema for skill_name from schemas/v3/<skill_name>.schema.json if present on disk, else fallback to V30_INLINE_SCHEMAS / legacy dirs."""
    clean_skill = skill_name.removeprefix("__inline_").removesuffix("__").removesuffix(".schema.json")
    v3_disk_path = SCHEMA_DIR / "v3" / f"{clean_skill}.schema.json"
    if v3_disk_path.is_file():
        return json.loads(v3_disk_path.read_text(encoding="utf-8"))
    if skill_name in V30_INLINE_SCHEMAS:
        return V30_INLINE_SCHEMAS[skill_name]
    inline_key = f"__inline_{clean_skill}__"
    if inline_key in V30_INLINE_SCHEMAS:
        return V30_INLINE_SCHEMAS[inline_key]
    mapped = SKILL_SCHEMA.get(clean_skill, skill_name)
    if mapped in V30_INLINE_SCHEMAS:
        return V30_INLINE_SCHEMAS[mapped]
    for d in (SCHEMA_DIR / "v3", SCHEMA_DIR, BASV_SCHEMA_DIR, ACA_SCHEMA_DIR):
        p = d / Path(mapped).name
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    raise OutputValidationError(f"Schema file not found: {skill_name}")


def _load_schema_file(schema_name: str) -> dict[str, Any]:
    return load_schema(schema_name)


def _validate_schema(value: Any, schema: dict[str, Any], path: str = "$", issues: list[str] | None = None) -> list[str]:
    issues = issues if issues is not None else []
    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        branch_passed = any(len(_validate_schema(value, sub_s, path, [])) == 0 for sub_s in schema["anyOf"] if isinstance(sub_s, dict))
        if not branch_passed:
            issues.append(f"{path} did not match anyOf schema options")
            return issues
    if "oneOf" in schema and isinstance(schema["oneOf"], list):
        branch_passed = any(len(_validate_schema(value, sub_s, path, [])) == 0 for sub_s in schema["oneOf"] if isinstance(sub_s, dict))
        if not branch_passed:
            issues.append(f"{path} did not match oneOf schema options")
            return issues
    typ = schema.get("type")
    type_ok = {
        "object": lambda x: isinstance(x, dict),
        "array": lambda x: isinstance(x, list),
        "string": lambda x: isinstance(x, str),
        "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
        "number": lambda x: isinstance(x, (int, float)) and not isinstance(x, bool),
        "boolean": lambda x: isinstance(x, bool),
        "null": lambda x: x is None,
    }
    if isinstance(typ, str) and typ in type_ok:
        if not type_ok[typ](value):
            issues.append(f"{path} must be {typ}")
            return issues
    elif isinstance(typ, list):
        if not any(t in type_ok and type_ok[t](value) for t in typ):
            issues.append(f"{path} must be one of types {typ!r}")
            return issues
    if "const" in schema and value != schema["const"]:
        issues.append(f"{path} must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        issues.append(f"{path} must be one of {schema['enum']!r}")
    if isinstance(value, str) and "minLength" in schema and len(value) < schema["minLength"]:
        issues.append(f"{path} must have length >= {schema['minLength']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            issues.append(f"{path} must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            issues.append(f"{path} must be <= {schema['maximum']}")
    if isinstance(value, dict):
        for required in schema.get("required", []):
            if required not in value:
                issues.append(f"{path}.{required} is required")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    issues.append(f"{path}.{key} is not allowed")
        for key, child_schema in props.items():
            if key in value:
                _validate_schema(value[key], child_schema, f"{path}.{key}", issues)
        if isinstance(schema.get("additionalProperties"), dict):
            for key, child in value.items():
                if key not in props:
                    _validate_schema(child, schema["additionalProperties"], f"{path}.{key}", issues)
    elif isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            issues.append(f"{path} must have at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            issues.append(f"{path} must have at most {schema['maxItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                _validate_schema(item, item_schema, f"{path}[{index}]", issues)
    return issues


def _supporting_ref_ids(refs: Any) -> list[str]:
    if not isinstance(refs, list):
        return []
    return [
        str(r["evidence_id"])
        for r in refs
        if isinstance(r, dict)
        and isinstance(r.get("evidence_id"), str)
        and r.get("relation") in {"supports", "derived_from", "context"}
    ]


def _validate_aca_epistemic_gates(skill: str, value: dict[str, Any], issues: list[str]) -> None:
    """Enforce Phase 3 Attack Chain Analysis epistemic gates."""
    chain_verdict = value.get("chain_verdict")
    exec_status = value.get("execution_status")

    # Gate 1: A chain cannot be marked 'confirmed' without observed effect in an authorized test execution.
    if chain_verdict == "confirmed" and exec_status in {
        "request_plan_only",
        "not_executed",
        "execution_blocked",
        "not_applicable",
    }:
        issues.append(
            f"$.chain_verdict cannot be 'confirmed' when execution_status is {exec_status!r} (request_plan_is_not_execution)"
        )

    # Gate 2: In attack_chain_constructor, confirmed/code_supported requires all critical steps, linked edges, and preconditions to be supported.
    if skill == "attack_chain_constructor" and chain_verdict in {"confirmed", "code_supported"}:
        for p_idx, pre in enumerate(value.get("preconditions", [])):
            if isinstance(pre, dict) and pre.get("status") in {"unknown", "refuted"}:
                issues.append(
                    f"$.preconditions[{p_idx}].status is {pre.get('status')!r}; cannot claim chain_verdict={chain_verdict!r} when a precondition is unknown or refuted"
                )
        attacker_model = value.get("attacker_model", {})
        if isinstance(attacker_model, dict):
            for a_idx, assump in enumerate(attacker_model.get("assumptions", [])):
                if isinstance(assump, dict) and assump.get("status") in {"unknown", "refuted"}:
                    issues.append(
                        f"$.attacker_model.assumptions[{a_idx}].status is {assump.get('status')!r}; cannot claim chain_verdict={chain_verdict!r} when an attacker assumption is unknown or refuted"
                    )
        if chain_verdict == "confirmed":
            if value.get("unresolved_questions"):
                issues.append(
                    "$.unresolved_questions must be empty when chain_verdict=='confirmed' (downstream controls or contradictory evidence remain unresolved)"
                )
            for c_idx, cref in enumerate(value.get("counterevidence_refs", [])):
                if isinstance(cref, dict) and cref.get("relation") == "contradicts":
                    issues.append(
                        f"$.counterevidence_refs[{c_idx}] has relation='contradicts'; cannot claim chain_verdict='confirmed' with unreconciled contradicting counterevidence"
                    )
        steps = value.get("steps", [])
        if isinstance(steps, list):
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                for sp_idx, spre in enumerate(step.get("preconditions", [])):
                    if isinstance(spre, dict) and spre.get("status") in {"unknown", "refuted"}:
                        issues.append(
                            f"$.steps[{idx}].preconditions[{sp_idx}].status is {spre.get('status')!r}; cannot claim chain_verdict={chain_verdict!r}"
                        )
                if chain_verdict == "confirmed" and step.get("unresolved_questions"):
                    issues.append(
                        f"$.steps[{idx}].unresolved_questions must be empty when chain_verdict=='confirmed'"
                    )
                v_stat = step.get("verification_status")
                if v_stat not in {"confirmed_by_source", "confirmed_by_observation"}:
                    issues.append(
                        f"$.steps[{idx}].verification_status is {v_stat!r}; cannot claim chain_verdict={chain_verdict!r} with unverified step"
                    )
                if not _supporting_ref_ids(step.get("evidence_refs")):
                    issues.append(
                        f"$.steps[{idx}] requires at least one supporting evidence_ref when chain_verdict={chain_verdict!r}"
                    )
                for e_idx, edge in enumerate(step.get("linked_next_steps", [])):
                    if not isinstance(edge, dict):
                        continue
                    l_stat = edge.get("link_status")
                    if l_stat not in {"confirmed_by_source", "confirmed_by_observation"}:
                        issues.append(
                            f"$.steps[{idx}].linked_next_steps[{e_idx}].link_status is {l_stat!r}; cannot claim chain_verdict={chain_verdict!r} with unverified edge"
                        )
                    if not _supporting_ref_ids(edge.get("evidence_refs")):
                        issues.append(
                            f"$.steps[{idx}].linked_next_steps[{e_idx}] requires supporting evidence_refs when chain_verdict={chain_verdict!r}"
                        )

    # Gate 3: In chain_step_verifier / aca_evidence_auditor, confirmed/code_supported requires all step_results and edge_results to be supported.
    if skill in {"chain_step_verifier", "aca_evidence_auditor"} and chain_verdict in {"confirmed", "code_supported"}:
        for idx, sr in enumerate(value.get("step_results", [])):
            if isinstance(sr, dict):
                if sr.get("result") not in {"confirmed_by_source", "confirmed_by_observation"}:
                    issues.append(
                        f"$.step_results[{idx}].result is {sr.get('result')!r}; incompatible with chain_verdict={chain_verdict!r}"
                    )
                if not _supporting_ref_ids(sr.get("evidence_refs")):
                    issues.append(f"$.step_results[{idx}] requires supporting evidence_refs")
        for idx, er in enumerate(value.get("edge_results", [])):
            if isinstance(er, dict):
                if er.get("status") not in {"confirmed_by_source", "confirmed_by_observation"}:
                    issues.append(
                        f"$.edge_results[{idx}].status is {er.get('status')!r}; incompatible with chain_verdict={chain_verdict!r}"
                    )
                if not _supporting_ref_ids(er.get("evidence_refs")):
                    issues.append(f"$.edge_results[{idx}] requires supporting evidence_refs")
        fe = value.get("final_effect")
        if isinstance(fe, dict):
            if chain_verdict == "confirmed" and fe.get("status") != "demonstrated":
                issues.append("$.final_effect.status must be 'demonstrated' when chain_verdict=='confirmed'")
            elif chain_verdict == "code_supported" and fe.get("status") not in {"code_supported", "demonstrated"}:
                issues.append("$.final_effect.status must be 'code_supported' or 'demonstrated' when chain_verdict=='code_supported'")

    # Gate 4: In request_sequence_designer / request_reproduction_operator, plan_only / not_executed / blocked cannot have executed=true requests.
    if skill in {"request_sequence_designer", "request_reproduction_operator"} and exec_status in {
        "plan_only",
        "not_executed",
        "blocked",
    }:
        for idx, req in enumerate(value.get("requests", [])):
            if isinstance(req, dict) and req.get("executed") is True:
                issues.append(
                    f"$.requests[{idx}].executed cannot be true when top-level execution_status is {exec_status!r}"
                )

    # Gate 5: In code_trace_builder, directly_read hops must cite at least one evidence_ref.
    if skill == "code_trace_builder":
        for idx, hop in enumerate(value.get("hops", [])):
            if isinstance(hop, dict) and hop.get("verification_status") == "directly_read":
                if not _supporting_ref_ids(hop.get("evidence_refs")):
                    issues.append(f"$.hops[{idx}] is marked directly_read but has no supporting evidence_refs")

    # Gate 6: In chain_synthesizer, highest_credible_chains cannot claim confirmed when execution_status is plan-only/not_executed.
    if skill == "chain_synthesizer":
        for idx, ch in enumerate(value.get("highest_credible_chains", [])):
            if isinstance(ch, dict):
                cv = ch.get("chain_verdict")
                es = ch.get("execution_status")
                if cv == "confirmed" and es in {"request_plan_only", "plan_only", "not_executed", "execution_blocked", "not_applicable"}:
                    issues.append(
                        f"$.highest_credible_chains[{idx}].chain_verdict cannot be 'confirmed' when execution_status is {es!r}"
                    )
                if cv in {"confirmed", "code_supported"} and not _supporting_ref_ids(ch.get("evidence_refs")):
                    issues.append(
                        f"$.highest_credible_chains[{idx}] requires supporting evidence_refs for chain_verdict={cv!r}"
                    )


def _get_provenance_kind(eid: str, evidence_catalog: dict[str, dict[str, Any]] | None) -> str:
    if not isinstance(evidence_catalog, dict) or eid not in evidence_catalog:
        return "unknown_source_kind"
    rec = evidence_catalog[eid]
    if not isinstance(rec, dict):
        return "unknown_source_kind"
    if isinstance(rec.get("provenance_kind"), str) and rec["provenance_kind"]:
        return rec["provenance_kind"]
    from .workspace import classify_evidence_provenance
    return classify_evidence_provenance(str(rec.get("path", "")))


def verify_claim_to_excerpt_semantics(
    node: dict[str, Any],
    cited_eids: list[str],
    evidence_catalog: dict[str, dict[str, Any]] | None,
) -> list[str]:
    """
    Deterministic Semantic Claim-to-Excerpt Verifier (Phase 1.6 / Phase 2.6 / Phase 3.4 Gate).
    Detects cases where an LLM attaches a valid evidence_id (ev_...) whose actual source excerpt
    does not contain the claimed code symbols or directly contradicts the claimed mechanism
    (e.g., claiming AuthConfigurer.cs overrides SignatureValidator / SecurityAlgorithms.None / JwtClearToken
    when the excerpt only sets ValidateIssuerSigningKey = true).
    """
    if not isinstance(evidence_catalog, dict) or not cited_eids or not isinstance(node, dict):
        return []
    recs = [evidence_catalog[eid] for eid in cited_eids if eid in evidence_catalog and isinstance(evidence_catalog[eid], dict)]
    if not recs:
        return []
    combined_excerpts = "\n".join(str(r.get("excerpt", "")) for r in recs if r.get("excerpt"))
    if not combined_excerpts.strip():
        return []
    excerpt_lower = combined_excerpts.lower()

    text_fields = (
        "title",
        "scenario",
        "assessment",
        "mechanism",
        "claim",
        "description",
        "observed_behavior",
        "rationale",
        "outcome",
        "authorization_analysis",
        "validation_analysis",
        "state_transition_analysis",
        "observed_logic",
        "notes",
    )
    claim_blob = " ".join(str(node.get(k, "")) for k in text_fields if isinstance(node.get(k), str))
    if not claim_blob.strip():
        return []
    claim_lower = claim_blob.lower()
    contradictions: list[str] = []

    # Rule 1: High-risk JWT alg:none / SignatureValidator / JwtClearToken hallucination guard
    alg_none_markers = (
        "signaturevalidator",
        "securityalgorithms.none",
        "jwtcleartoken",
        "jwtsecuritytoken(token)",
    )
    mentioned_alg_markers = [m for m in alg_none_markers if m in claim_lower]
    if mentioned_alg_markers:
        missing_markers = [m for m in mentioned_alg_markers if m not in excerpt_lower]
        if len(missing_markers) == len(mentioned_alg_markers):
            contradictions.append(
                f"Semantic Claim-to-Excerpt Contradiction: claim asserts {missing_markers} in cited evidence {cited_eids}, "
                f"but none of those symbols exist in the actual source excerpt(s)"
            )

    # Rule 2: Explicit dotted code symbol anchors (e.g., TokenValidationParameters.SignatureValidator)
    import re
    dotted_symbols = re.findall(r"`([A-Z][A-Za-z0-9_]+\.[A-Z][A-Za-z0-9_]+)`", claim_blob)
    for sym in dotted_symbols:
        lhs, rhs = sym.split(".", 1)
        # If the LHS type/object is present in the excerpt (showing we are looking at the right file/block),
        # the claimed RHS member/property must also appear in the cited excerpt.
        if lhs.lower() in excerpt_lower and rhs.lower() not in excerpt_lower:
            contradictions.append(
                f"Semantic Claim-to-Excerpt Contradiction: claim cites `{sym}`, and `{lhs}` is in {cited_eids}, "
                f"but member `{rhs}` does not appear anywhere in the cited excerpt(s)"
            )

    return contradictions


def _normalize_v30_aliases(skill: str, value: dict[str, Any]) -> None:
    """Normalize documented v3 field aliases in-place without relaxing required schema constraints."""
    if not isinstance(value, dict):
        return
    if skill == "actor_and_feasibility_assessor":
        if "actor_assessments" not in value and isinstance(value.get("assessments"), list):
            value["actor_assessments"] = value["assessments"]
        for list_key in ("actor_assessments", "assessments"):
            items = value.get(list_key)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                if "chain_id" not in item and isinstance(item.get("finding_id"), str):
                    item["chain_id"] = item["finding_id"]
                if "finding_id" not in item and isinstance(item.get("chain_id"), str):
                    item["finding_id"] = item["chain_id"]
                if "minimum_actor" not in item and isinstance(item.get("minimum_viable_actor"), str):
                    item["minimum_actor"] = item["minimum_viable_actor"]
                if "minimum_viable_actor" not in item and isinstance(item.get("minimum_actor"), str):
                    item["minimum_viable_actor"] = item["minimum_actor"]
                if "preconditions" not in item and isinstance(item.get("operational_preconditions"), list):
                    item["preconditions"] = [
                        p if isinstance(p, dict) else {"condition": str(p), "precondition": str(p), "status": "unknown", "precondition_status": "unknown"}
                        for p in item["operational_preconditions"]
                    ]
                pre_list = item.get("preconditions")
                if isinstance(pre_list, list):
                    for pre in pre_list:
                        if not isinstance(pre, dict):
                            continue
                        if "condition" not in pre and isinstance(pre.get("precondition"), str):
                            pre["condition"] = pre["precondition"]
                        if "precondition" not in pre and isinstance(pre.get("condition"), str):
                            pre["precondition"] = pre["condition"]
                        raw_st = (
                            pre.get("status")
                            if pre.get("status") is not None
                            else (pre.get("precondition_status") if pre.get("precondition_status") is not None else pre.get("satisfied"))
                        )
                        if raw_st is not None:
                            s_low = str(raw_st).strip().lower()
                            if s_low in {"no", "false", "unsatisfied", "impossible"}:
                                norm_st = "no"
                            elif s_low in {"yes", "true", "satisfied", "confirmed", "observed"}:
                                norm_st = "yes"
                            elif s_low in {"unknown", "unverified", "hypothesis"}:
                                norm_st = "unknown"
                            else:
                                norm_st = str(raw_st)
                            if "status" not in pre or str(pre.get("status")).strip().lower() == s_low:
                                pre["status"] = norm_st
                            if "precondition_status" not in pre or str(pre.get("precondition_status")).strip().lower() == s_low:
                                pre["precondition_status"] = norm_st
    elif skill == "sfop_risk_calibrator":
        findings = value.get("calibrated_findings")
        if isinstance(findings, list):
            for item in findings:
                if not isinstance(item, dict):
                    continue
                if "impact_axes" not in item and isinstance(item.get("sfop_impacts"), dict):
                    item["impact_axes"] = item["sfop_impacts"]
                if "owner_role" not in item:
                    ro_str = str(item.get("risk_owner") or "").strip().lower()
                    matched_role = next((r for r in VALID_OWNER_ROLES if r in ro_str), None)
                    item["owner_role"] = matched_role or "unassigned_pending_roster"
    elif skill == "blinded_counterevidence_challenger":
        if "challenged_chains" not in value:
            for alias in ("challenges", "chain_challenges"):
                if isinstance(value.get(alias), list):
                    value["challenged_chains"] = value[alias]
                    break
        for ch_item in value.get("challenged_chains", []):
            if not isinstance(ch_item, dict):
                continue
            if "challenge_verdict" not in ch_item and isinstance(ch_item.get("challenger_verdict"), str):
                ch_item["challenge_verdict"] = ch_item["challenger_verdict"]
            if "challenger_verdict" not in ch_item and isinstance(ch_item.get("challenge_verdict"), str):
                ch_item["challenger_verdict"] = ch_item["challenge_verdict"]
            if "counter_evidence_ids" not in ch_item and isinstance(ch_item.get("counterevidence_ids"), list):
                ch_item["counter_evidence_ids"] = ch_item["counterevidence_ids"]
            if not ch_item.get("counter_evidence_ids"):
                chk = ch_item.get("control_search_checklist")
                found_eids: list[str] = []
                if isinstance(chk, list):
                    for ce in chk:
                        if isinstance(ce, dict) and ce.get("status") == "checked_found":
                            for e in (ce.get("evidence_ids") or ce.get("counter_evidence_ids") or []):
                                if isinstance(e, str) and e.startswith("ev_") and e not in found_eids:
                                    found_eids.append(e)
                elif isinstance(chk, dict):
                    for ce in chk.values():
                        if isinstance(ce, dict) and ce.get("status") == "checked_found":
                            for e in (ce.get("evidence_ids") or ce.get("counter_evidence_ids") or []):
                                if isinstance(e, str) and e.startswith("ev_") and e not in found_eids:
                                    found_eids.append(e)
                if found_eids:
                    ch_item["counter_evidence_ids"] = found_eids
    elif skill == "intent_invariant_modeler":
        if "invariants" not in value and isinstance(value.get("sfop_invariants"), list):
            norm_invs: list[dict[str, Any]] = []
            for inv in value["sfop_invariants"]:
                if isinstance(inv, dict):
                    cp = dict(inv)
                    if "statement" not in cp and isinstance(cp.get("description"), str):
                        cp["statement"] = cp["description"]
                    if "source_type" not in cp:
                        cp["source_type"] = "authoritative_doc" if cp.get("status") in {"confirmed", "observed"} else "inferred_hypothesis"
                    norm_invs.append(cp)
            value["invariants"] = norm_invs
        if "self_challenged_gaps" not in value and isinstance(value.get("self_review_gaps"), list):
            value["self_challenged_gaps"] = value["self_review_gaps"]
    elif skill == "candidate_intake_planner":
        if "selected_companions" not in value and isinstance(value.get("selected_companion_ids"), list):
            value["selected_companions"] = value["selected_companion_ids"]
        if "deduplicated_batches" not in value and isinstance(value.get("batches"), list):
            norm_batches: list[dict[str, Any]] = []
            for b in value["batches"]:
                if isinstance(b, dict):
                    cp = dict(b)
                    if "rationale" not in cp and ("candidate_ids" in cp or "companion_ids" in cp):
                        cp["rationale"] = f"Grouped batch {cp.get('batch_id', 'B-01')}"
                    norm_batches.append(cp)
            value["deduplicated_batches"] = norm_batches


def validate_agent_output(
    skill: str,
    value: dict[str, Any],
    valid_evidence_ids: set[str],
    *,
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
) -> None:
    if skill not in SKILL_SCHEMA:
        raise OutputValidationError(f"No schema for skill {skill!r}")
    if skill in V30_SKILLS and isinstance(value, dict) and isinstance(value.get("result"), dict) and "status" in value:
        value = value["result"]
    if skill in V30_SKILLS and isinstance(value, dict):
        _normalize_v30_aliases(skill, value)
    schema = load_schema(skill)
    issues = _validate_schema(value, schema)
    is_aca = skill in ACA_SKILLS

    def check_evidence(node: Any, loc: str = "$", parent_status: str | None = None) -> None:
        if isinstance(node, dict):
            status = node.get("status", parent_status)
            if not is_aca and "status" in node and node["status"] not in ALLOWED_STATUSES:
                issues.append(f"{loc}.status has unsupported value {node['status']!r}")
            if node.get("intent_basis") == "implementation_inference" and node.get("authority_assessment") == "authoritative_in_input":
                issues.append(f"{loc} cannot mark implementation_inference as authoritative_in_input")
            if (
                evidence_catalog is not None
                and node.get("authority_assessment") == "authoritative_in_input"
                and node.get("intent_basis") in {"explicit_requirement", "api_or_event_contract", "acceptance_criteria_or_test", "architecture_decision"}
            ):
                node_eids = [x for x in node.get("evidence_ids", []) if isinstance(x, str)]
                if node_eids:
                    kinds = [_get_provenance_kind(eid, evidence_catalog) for eid in node_eids]
                    if all(k == "implementation_code" for k in kinds):
                        issues.append(
                            f"{loc} provenance contamination: cannot claim authoritative_in_input ({node.get('intent_basis')!r}) when all cited evidence_ids are implementation_code"
                        )
            present_id_keys = [k for k in EVIDENCE_ID_KEYS if k in node]
            combined_primary_ids: list[str] = []
            for k in present_id_keys:
                ids = node.get(k)
                if isinstance(ids, list) and all(isinstance(x, str) for x in ids):
                    for eid in ids:
                        if eid not in valid_evidence_ids:
                            issues.append(f"{loc}.{k} references evidence ID not in this job scope: {eid}")
                    if k in {
                        "evidence_ids",
                        "intent_evidence_ids",
                        "implementation_evidence_ids",
                        "sample_evidence_ids",
                        "representative_deep_read_evidence_ids",
                        "caller_evidence_ids",
                        "callee_evidence_ids",
                        "ownership_evidence_ids",
                    }:
                        combined_primary_ids.extend(ids)
            for rk in EVIDENCE_REF_KEYS:
                refs = node.get(rk)
                if isinstance(refs, list):
                    for r_idx, ref_obj in enumerate(refs):
                        if isinstance(ref_obj, dict):
                            eid = ref_obj.get("evidence_id")
                            if isinstance(eid, str) and eid not in valid_evidence_ids:
                                issues.append(f"{loc}.{rk}[{r_idx}].evidence_id references evidence ID not in this job scope: {eid}")
                            if rk in {"evidence_refs", "existing_evidence_refs"} and ref_obj.get("relation") in {"supports", "derived_from", "context"} and isinstance(eid, str):
                                combined_primary_ids.append(eid)
            if not is_aca:
                if present_id_keys:
                    if status in {"observed", "derived", "confirmed", "covered_clean", "covered_finding"} and not combined_primary_ids:
                        issues.append(f"{loc} is {status} but has no supporting evidence IDs")
                    if node.get("comparison_result") == "mismatch" and status in {"observed", "derived"}:
                        intent_ids = [x for x in (node.get("intent_evidence_ids") or []) if isinstance(x, str)]
                        impl_ids = [x for x in (node.get("implementation_evidence_ids") or []) if isinstance(x, str)]
                        if not intent_ids or not impl_ids:
                            issues.append(f"{loc} is an observed/derived mismatch and requires both intent_evidence_ids and implementation_evidence_ids")
                        else:
                            if set(intent_ids) == set(impl_ids):
                                issues.append(
                                    f"{loc} provenance contamination: intent_evidence_ids and implementation_evidence_ids cannot be identical for an observed/derived mismatch"
                                )
                            if evidence_catalog is not None and status == "observed":
                                intent_kinds = [_get_provenance_kind(eid, evidence_catalog) for eid in intent_ids]
                                if all(k == "implementation_code" for k in intent_kinds):
                                    issues.append(
                                        f"{loc} provenance contamination: an 'observed' mismatch cannot cite only implementation_code in intent_evidence_ids; cite an intent_artifact/config_or_manifest or downgrade status to 'derived'/'hypothesis'"
                                    )
                elif status in {"observed", "derived"} and any(
                    k in node
                    for k in ("title", "scenario", "path", "endpoint", "asset", "name", "assessment", "claim", "mechanism", "source_repo", "expected_behavior", "observed_behavior")
                ):
                    issues.append(f"{loc} is {status} but lacks evidence_ids")
            else:
                if "evidence_refs" in node and status in {"confirmed", "confirmed_by_source", "confirmed_by_observation", "code_supported", "demonstrated"} and not combined_primary_ids:
                    issues.append(f"{loc} has status={status!r} but no supporting evidence_refs")
            if (
                evidence_catalog is not None
                and combined_primary_ids
                and status in {"observed", "derived", "confirmed", "confirmed_by_source", "code_supported", "directly_read", "strongly_supported"}
            ):
                sem_issues = verify_claim_to_excerpt_semantics(node, combined_primary_ids, evidence_catalog)
                for si in sem_issues:
                    issues.append(f"{loc}: {si}")
            for key, child in node.items():
                check_evidence(child, f"{loc}.{key}", status)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                check_evidence(child, f"{loc}[{i}]", parent_status)

    check_evidence(value)
    if is_aca and isinstance(value, dict):
        _validate_aca_epistemic_gates(skill, value, issues)
    if skill in V30_SKILLS and isinstance(value, dict):
        _validate_v30_epistemic_gates(
            skill,
            value,
            issues,
            valid_evidence_ids=valid_evidence_ids,
            evidence_catalog=evidence_catalog,
        )
    if issues:
        raise OutputValidationError("; ".join(issues[:40]))


def _extract_anchor_strings(items: Any) -> set[str]:
    out: set[str] = set()
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str) and item.strip():
            out.add(item.strip())
        elif isinstance(item, dict):
            for k in ("id", "endpoint_id", "entrypoint_id", "candidate_id", "path", "route", "endpoint", "handler", "target", "surface"):
                v = item.get(k)
                if isinstance(v, str) and v.strip():
                    out.add(v.strip())
            m = str(item.get("method", "")).strip()
            p = str(item.get("path") or item.get("route") or "").strip()
            if m and p:
                out.add(f"{m} {p}")
    return out


def _validate_v30_epistemic_gates(
    skill: str,
    value: dict[str, Any],
    issues: list[str],
    *,
    valid_evidence_ids: set[str] | None = None,
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Enforce LocalSec v3.0 epistemic gates across Phase 1, Phase 2, and Phase 3."""
    import re

    if skill == "extractor_tailor":
        mode = value.get("mode")
        if mode in {"USE_STANDARD_EXTRACTOR", "USE_TAILORED_EXTRACTOR", "TAILOR_CUSTOM_EXTRACTOR"}:
            if not value.get("canary_verified"):
                issues.append(
                    f"$.canary_verified must be True when mode is {mode!r}; unverified Python extractors are forbidden to prevent SAST anchoring bias"
                )
            if not value.get("canary_files"):
                issues.append(f"$.canary_files must be non-empty when mode is {mode!r}")

    if skill in {"coverage_ledger", "unified_surface_mapper"}:
        cov_re = re.compile(r"^[A-Za-z0-9._~%-]+(::[A-Za-z0-9._~%-]+){3,4}$")
        for idx, rec in enumerate(value.get("records", [])):
            if not isinstance(rec, dict):
                continue
            cid = str(rec.get("coverage_id", ""))
            if not cov_re.match(cid):
                issues.append(
                    f"$.records[{idx}].coverage_id {cid!r} violates RFC 3986 4-or-5 segment format 'surface::boundary::subsystem::attack_class[::lifecycle]'"
                )
            st = rec.get("status")
            attempts = rec.get("attempts", [])
            if st == "reopened" and (not isinstance(attempts, list) or len(attempts) < 2):
                issues.append(
                    f"$.records[{idx}] is marked 'reopened' but attempts[] has fewer than 2 entries (append-only history violation)"
                )

    # ARCH-3F: BOLA/IDOR Clustering Gate in unified_surface_mapper
    if skill == "unified_surface_mapper":
        entrypoints = value.get("entrypoints", [])
        clusters = value.get("semantic_clusters", [])
        if isinstance(entrypoints, list) or isinstance(clusters, list):
            exempt_anchors = _extract_anchor_strings(value.get("outliers", [])) | _extract_anchor_strings(value.get("candidate_queue", []))
            clustered_anchors: set[str] = set()
            if isinstance(clusters, list):
                for cl_idx, cl in enumerate(clusters):
                    if not isinstance(cl, dict):
                        continue
                    cl_outliers = _extract_anchor_strings(cl.get("outliers", []))
                    exempt_anchors |= cl_outliers
                    members = cl.get("member_endpoints") if "member_endpoints" in cl else cl.get("members", [])
                    clustered_anchors |= (_extract_anchor_strings(members) - cl_outliers)
                    if isinstance(members, list):
                        for m_idx, mem in enumerate(members):
                            if isinstance(mem, dict):
                                obj_params = mem.get("object_id_params")
                                if isinstance(obj_params, list) and len(obj_params) > 0:
                                    mem_anchors = _extract_anchor_strings([mem])
                                    if not (mem_anchors & exempt_anchors):
                                        own_chk = mem.get("ownership_check")
                                        own_eids = mem.get("ownership_evidence_ids") or mem.get("evidence_ids") or []
                                        if own_chk != "present" or not own_eids:
                                            issues.append(
                                                f"$.semantic_clusters[{cl_idx}].member_endpoints[{m_idx}] has object_id_params={obj_params!r} and cannot be clustered as an implicit safe member unless ownership_check=='present' with ownership_evidence_ids/evidence_ids, or moved to outliers/candidate_queue (ARCH-3F)"
                                            )
            if isinstance(entrypoints, list):
                for ep_idx, ep in enumerate(entrypoints):
                    if not isinstance(ep, dict):
                        continue
                    obj_params = ep.get("object_id_params")
                    if not isinstance(obj_params, list) or len(obj_params) == 0:
                        continue
                    ep_anchors = _extract_anchor_strings([ep])
                    is_exempt = bool(ep_anchors & exempt_anchors) or bool(ep.get("is_outlier") is True)
                    is_clustered = bool(ep_anchors & clustered_anchors) or bool(ep.get("cluster_id")) or bool(ep.get("clustered_safe") is True)
                    if is_clustered and not is_exempt:
                        own_chk = ep.get("ownership_check")
                        own_eids = ep.get("ownership_evidence_ids") or ep.get("evidence_ids") or []
                        if own_chk != "present" or not own_eids:
                            issues.append(
                                f"$.entrypoints[{ep_idx}] has object_id_params={obj_params!r} and cannot be listed as an unverified member of a cluster unless ownership_check=='present' with non-empty ownership_evidence_ids/evidence_ids, or placed in outliers/candidate_queue (ARCH-3F)"
                            )

    # DEPTH-4.2b & R3-A4 Path 2: Cross-Service Hop Gate & Evidenced unexploitable_candidates in deep_trace_chain_analyst
    if skill == "deep_trace_chain_analyst":
        for u_idx, unexp in enumerate(value.get("unexploitable_candidates", [])):
            if not isinstance(unexp, dict):
                issues.append(
                    f"$.unexploitable_candidates[{u_idx}]: unexploitable_candidates items must be objects with candidate_id, reason (>=10 chars), and non-empty evidence_ids"
                )
                continue
            u_cid = str(unexp.get("candidate_id") or "").strip()
            u_reason = str(unexp.get("reason") or unexp.get("rationale") or "").strip()
            raw_u_eids = [
                str(e).strip()
                for e in (unexp.get("evidence_ids") or [])
                if isinstance(e, str) and str(e).strip().startswith("ev_")
            ]
            valid_u_eids = [e for e in raw_u_eids if valid_evidence_ids is None or e in valid_evidence_ids]
            if not u_cid or len(u_reason) < 10 or not valid_u_eids:
                issues.append(
                    f"$.unexploitable_candidates[{u_idx}]: unexploitable_candidates items must be objects with candidate_id, reason (>=10 chars), and non-empty evidence_ids"
                )
        chains = value.get("chains")
        if not isinstance(chains, list):
            chains = [value] if ("hops" in value or "chain_verdict" in value) else []
        cross_hop_kinds = {"http", "grpc", "message_queue", "zmq_or_ipc"}
        for c_idx, chain in enumerate(chains):
            if not isinstance(chain, dict):
                continue
            verdict = str(chain.get("chain_verdict", ""))
            req_plan = chain.get("request_plan")
            exec_status = req_plan.get("execution_status") if isinstance(req_plan, dict) else chain.get("execution_status")
            if verdict == "confirmed" and exec_status in {"request_plan_only", "plan_only", "not_executed", "blocked", "execution_blocked", "not_applicable"}:
                issues.append(
                    f"$.chains[{c_idx}].chain_verdict cannot be 'confirmed' when execution_status is {exec_status!r} (request_plan_is_not_execution)"
                )
            hops = chain.get("hops") if isinstance(chain.get("hops"), list) else chain.get("steps", [])
            if isinstance(hops, list):
                for h_idx, hop in enumerate(hops):
                    if not isinstance(hop, dict):
                        continue
                    h_kind = str(hop.get("hop_kind", "")).strip().lower()
                    if h_kind in cross_hop_kinds:
                        caller_eids = [x for x in (hop.get("caller_evidence_ids") or []) if isinstance(x, str) and x.strip()]
                        callee_eids = [x for x in (hop.get("callee_evidence_ids") or []) if isinstance(x, str) and x.strip()]
                        generic_eids = [x for x in (hop.get("evidence_ids") or []) if isinstance(x, str) and x.strip()] + _supporting_ref_ids(hop.get("evidence_refs"))
                        all_hop_eids = set(caller_eids) | set(callee_eids) | set(generic_eids)
                        both_evidenced = (len(caller_eids) >= 1 and len(callee_eids) >= 1) or (
                            hop.get("cross_service_verified") is True and len(all_hop_eids) >= 2
                        )
                        if not both_evidenced and verdict in {"confirmed", "code_supported"}:
                            issues.append(
                                f"$.chains[{c_idx}].hops[{h_idx}] has cross-service hop_kind={h_kind!r} lacking caller_evidence_ids + callee_evidence_ids; chain_verdict={verdict!r} is forbidden unless downgraded to 'partially_confirmed' or 'hypothesized' (DEPTH-4.2b)"
                            )

    # DEPTH-4.2d & R3-A4 Paths 1 & 4: 6-Location Control Search Gate & Refutation Evidence Gate in blinded_counterevidence_challenger
    if skill == "blinded_counterevidence_challenger":
        def _resolve_checklist_eids(entry: dict[str, Any], sp_clean: list[str]) -> list[str]:
            explicit = [
                x.strip()
                for x in (entry.get("evidence_ids") or entry.get("counter_evidence_ids") or [])
                if isinstance(x, str) and x.strip()
            ]
            if explicit:
                return explicit
            if "evidence_ids" in entry:
                return []
            if isinstance(evidence_catalog, dict) and evidence_catalog and sp_clean:
                matched_eids: list[str] = []
                for p in sp_clean:
                    p_eids = [
                        eid
                        for eid, rec in evidence_catalog.items()
                        if isinstance(rec, dict)
                        and (str(rec.get("path", "")) == p or str(rec.get("path", "")).endswith("/" + p))
                    ]
                    if not p_eids:
                        return []
                    matched_eids.extend(p_eids)
                if matched_eids:
                    entry["evidence_ids"] = sorted(set(matched_eids))
                    return entry["evidence_ids"]
            return []

        def _check_entry_dict(entry: dict[str, Any], item_loc: str) -> None:
            st = entry.get("status")
            if st not in VALID_CONTROL_SEARCH_STATUSES:
                issues.append(
                    f"{item_loc}.status {st!r} must be one of {sorted(VALID_CONTROL_SEARCH_STATUSES)!r} (DEPTH-4.2d)"
                )
            elif st == "checked_not_found":
                sp = entry.get("searched_paths")
                sp_clean = [p.strip() for p in sp if isinstance(p, str) and p.strip()] if isinstance(sp, list) else []
                eids = _resolve_checklist_eids(entry, sp_clean)
                if not sp_clean or not eids:
                    issues.append(
                        f"{item_loc} has status='checked_not_found' and requires non-empty searched_paths and evidence_ids proving the candidate control files were actually read (DEPTH-4.2d)"
                    )
            elif st == "checked_found":
                sp = entry.get("searched_paths")
                sp_clean = [p.strip() for p in sp if isinstance(p, str) and p.strip()] if isinstance(sp, list) else []
                eids = _resolve_checklist_eids(entry, sp_clean)
                if not eids:
                    issues.append(
                        f"{item_loc} has status='checked_found' and requires non-empty evidence_ids (DEPTH-4.2d)"
                    )
            elif st == "not_applicable":
                reason_str = str(entry.get("reason") or entry.get("notes") or "").strip()
                if len(reason_str) < 20:
                    issues.append(
                        f"{item_loc}: status='not_applicable' requires a reason/notes of at least 20 characters explaining why this control layer does not exist"
                    )

        def _check_control_checklist(chk: Any, loc_prefix: str) -> None:
            if isinstance(chk, list):
                na_count = 0
                for idx, entry in enumerate(chk):
                    if isinstance(entry, dict):
                        if entry.get("status") == "not_applicable":
                            na_count += 1
                        _check_entry_dict(entry, f"{loc_prefix}[{idx}]")
                if (len(chk) >= 6 and na_count == len(chk)) or na_count >= 6:
                    issues.append(
                        f"{loc_prefix}: control_search_checklist cannot mark all 6 control locations as 'not_applicable'; at least one location must be actively searched with evidence_ids"
                    )
            elif isinstance(chk, dict):
                na_count = 0
                for k, entry in chk.items():
                    if isinstance(entry, dict):
                        if entry.get("status") == "not_applicable":
                            na_count += 1
                        _check_entry_dict(entry, f"{loc_prefix}.{k}")
                    elif isinstance(entry, str):
                        if entry == "not_applicable":
                            na_count += 1
                            issues.append(
                                f"{loc_prefix}.{k}: status='not_applicable' requires a reason/notes of at least 20 characters explaining why this control layer does not exist"
                            )
                        elif entry not in VALID_CONTROL_SEARCH_STATUSES:
                            issues.append(
                                f"{loc_prefix}.{k} {entry!r} must be one of {sorted(VALID_CONTROL_SEARCH_STATUSES)!r} (DEPTH-4.2d)"
                            )
                        elif entry in {"checked_not_found", "checked_found"}:
                            issues.append(
                                f"{loc_prefix}.{k} has status={entry!r} and requires an object with non-empty searched_paths and evidence_ids (DEPTH-4.2d)"
                            )
                if (len(chk) >= 6 and na_count == len(chk)) or na_count >= 6:
                    issues.append(
                        f"{loc_prefix}: control_search_checklist cannot mark all 6 control locations as 'not_applicable'; at least one location must be actively searched with evidence_ids"
                    )

        if "control_search_checklist" in value:
            _check_control_checklist(value["control_search_checklist"], "$.control_search_checklist")
        seen_challenge_objs: set[int] = set()
        for list_key in ("challenged_chains", "step_challenges", "challenges", "chain_challenges", "verifications"):
            for c_idx, ch_item in enumerate(value.get(list_key, [])):
                if not isinstance(ch_item, dict) or id(ch_item) in seen_challenge_objs:
                    continue
                seen_challenge_objs.add(id(ch_item))
                if "control_search_checklist" in ch_item:
                    _check_control_checklist(
                        ch_item["control_search_checklist"],
                        f"$.{list_key}[{c_idx}].control_search_checklist",
                    )
                c_verdict = str(
                    ch_item.get("challenge_verdict")
                    or ch_item.get("challenger_verdict")
                    or ch_item.get("verdict")
                    or ""
                ).strip()
                if c_verdict in {"refuted", "mitigated_by_existing_control", "broken_link"}:
                    raw_ceids = [
                        str(e).strip()
                        for e in (ch_item.get("counter_evidence_ids") or ch_item.get("counterevidence_ids") or ch_item.get("evidence_ids") or [])
                        if isinstance(e, str) and str(e).strip().startswith("ev_")
                    ]
                    valid_ceids = [e for e in raw_ceids if valid_evidence_ids is None or e in valid_evidence_ids]
                    has_checked_found_ev = False
                    chk_obj = ch_item.get("control_search_checklist")
                    chk_entries = chk_obj if isinstance(chk_obj, list) else (list(chk_obj.values()) if isinstance(chk_obj, dict) else [])
                    for ce in chk_entries:
                        if isinstance(ce, dict) and ce.get("status") == "checked_found":
                            ce_eids = [
                                str(e).strip()
                                for e in (ce.get("evidence_ids") or ce.get("counter_evidence_ids") or [])
                                if isinstance(e, str) and str(e).strip().startswith("ev_") and (valid_evidence_ids is None or str(e).strip() in valid_evidence_ids)
                            ]
                            if ce_eids:
                                has_checked_found_ev = True
                                break
                    if not valid_ceids and not has_checked_found_ev:
                        issues.append(
                            f"$.{list_key}[{c_idx}]: challenge_verdict in {{'refuted', 'mitigated_by_existing_control', 'broken_link'}} requires non-empty counter_evidence_ids proving the refutation or mitigating control"
                        )

    if skill == "actor_and_feasibility_assessor":
        seen_a_objs: set[int] = set()
        for list_key in ("actor_assessments", "assessments"):
            for a_idx, a_item in enumerate(value.get(list_key, [])):
                if not isinstance(a_item, dict) or id(a_item) in seen_a_objs:
                    continue
                seen_a_objs.add(id(a_item))
                for p_idx, pre in enumerate(a_item.get("preconditions", [])):
                    if not isinstance(pre, dict):
                        continue
                    p_stat = str(
                        pre.get("status")
                        if pre.get("status") is not None
                        else (pre.get("precondition_status") if pre.get("precondition_status") is not None else pre.get("satisfied", ""))
                    ).strip().lower()
                    if p_stat in {"no", "false", "unsatisfied", "impossible"}:
                        raw_eids = [
                            str(e).strip()
                            for e in (pre.get("evidence_ids") or [])
                            if isinstance(e, str) and str(e).strip().startswith("ev_")
                        ]
                        valid_eids = [e for e in raw_eids if valid_evidence_ids is None or e in valid_evidence_ids]
                        raw_sp = [
                            str(p).strip()
                            for p in (pre.get("searched_paths") or [])
                            if isinstance(p, str) and str(p).strip()
                        ]
                        if not valid_eids or not raw_sp:
                            issues.append(
                                f"$.{list_key}[{a_idx}].preconditions[{p_idx}]: precondition with status='no' (unsatisfied) requires non-empty evidence_ids and searched_paths proving the precondition cannot hold"
                            )

    if skill == "beyond_code_control_mapper":
        for idx, ctrl in enumerate(value.get("beyond_code_controls", [])):
            if isinstance(ctrl, dict) and ctrl.get("status") == "hypothesis" and ctrl.get("mitigation_effect") == "blocks_exploit":
                issues.append(
                    f"$.beyond_code_controls[{idx}] has status='hypothesis' and cannot claim mitigation_effect='blocks_exploit' without confirmed config/IaC evidence"
                )
        for idx, item in enumerate(value.get("assessments", [])):
            if not isinstance(item, dict):
                continue
            for c_idx, ctrl in enumerate(item.get("compensating_controls", [])):
                if not isinstance(ctrl, dict):
                    continue
                if ctrl.get("status") == "hypothesis" and ctrl.get("mitigation_effect") == "blocks_exploit":
                    issues.append(
                        f"$.assessments[{idx}].compensating_controls[{c_idx}] has status='hypothesis' and cannot claim mitigation_effect='blocks_exploit' without confirmed config/IaC evidence"
                    )

    if skill == "sfop_risk_calibrator":
        for idx, item in enumerate(value.get("calibrated_findings", [])):
            if not isinstance(item, dict):
                continue
            if "owner_role" in item and item["owner_role"] is not None:
                if item["owner_role"] not in VALID_OWNER_ROLES:
                    issues.append(
                        f"$.calibrated_findings[{idx}].owner_role {item['owner_role']!r} must be one of {sorted(VALID_OWNER_ROLES)!r} (DEPTH-4.4b)"
                    )
            if "risk_owner" in item and not str(item.get("risk_owner") or "").strip():
                issues.append(f"$.calibrated_findings[{idx}].risk_owner must be non-empty")
            if "blast_radius" in item and item["blast_radius"] is not None:
                if item["blast_radius"] not in VALID_BLAST_RADIUS:
                    issues.append(
                        f"$.calibrated_findings[{idx}].blast_radius {item['blast_radius']!r} must be one of {sorted(VALID_BLAST_RADIUS)!r} (DEPTH-4.4d)"
                    )
            sfop_details = item.get("sfop_details")
            if isinstance(sfop_details, dict):
                for ax_k, ax_v in sfop_details.items():
                    if isinstance(ax_v, dict) and "blast_radius" in ax_v and ax_v["blast_radius"] is not None:
                        if ax_v["blast_radius"] not in VALID_BLAST_RADIUS:
                            issues.append(
                                f"$.calibrated_findings[{idx}].sfop_details.{ax_k}.blast_radius {ax_v['blast_radius']!r} must be one of {sorted(VALID_BLAST_RADIUS)!r} (DEPTH-4.4d)"
                            )
            axes = item.get("impact_axes")
            if not isinstance(axes, dict) and isinstance(item.get("sfop_impacts"), dict):
                axes = item["sfop_impacts"]
                item["impact_axes"] = axes
            if not isinstance(axes, dict):
                issues.append(f"$.calibrated_findings[{idx}].impact_axes is required and must be a dict")
                continue
            axis_vals: list[str] = []
            for k in ("safety", "financial", "operational", "privacy", "compliance"):
                if k not in axes:
                    issues.append(f"$.calibrated_findings[{idx}].impact_axes.{k} is required")
                    axis_vals.append("negligible")
                    continue
                raw_ax = axes.get(k, "negligible")
                if isinstance(raw_ax, dict):
                    if "blast_radius" in raw_ax and raw_ax["blast_radius"] is not None:
                        if raw_ax["blast_radius"] not in VALID_BLAST_RADIUS:
                            issues.append(
                                f"$.calibrated_findings[{idx}].impact_axes.{k}.blast_radius {raw_ax['blast_radius']!r} must be one of {sorted(VALID_BLAST_RADIUS)!r} (DEPTH-4.4d)"
                            )
                    if "basis" in raw_ax and not str(raw_ax.get("basis") or "").strip():
                        issues.append(f"$.calibrated_findings[{idx}].impact_axes.{k}.basis must be non-empty")
                    ax_level = str(raw_ax.get("severity") or raw_ax.get("level") or raw_ax.get("impact") or "negligible")
                    if ax_level not in IMPACT_RANK:
                        issues.append(
                            f"$.calibrated_findings[{idx}].impact_axes.{k} level {ax_level!r} must be one of {sorted(IMPACT_RANK.keys())!r}"
                        )
                    axis_vals.append(ax_level)
                else:
                    ax_level = str(raw_ax)
                    if ax_level not in IMPACT_RANK:
                        issues.append(
                            f"$.calibrated_findings[{idx}].impact_axes.{k} {ax_level!r} must be one of {sorted(IMPACT_RANK.keys())!r}"
                        )
                    axis_vals.append(ax_level)
            computed_max_rank = max(IMPACT_RANK.get(v, 0) for v in axis_vals)
            declared_max = str(item.get("max_impact", "negligible"))
            declared_max_rank = IMPACT_RANK.get(declared_max, -1)
            if declared_max_rank != computed_max_rank:
                issues.append(
                    f"$.calibrated_findings[{idx}].max_impact ({declared_max!r}) does not equal the true maximum across the 5 S-F-O-P-C axes ({axis_vals})"
                )
            overall = str(item.get("contextual_risk_rating", "negligible"))
            overall_rank = IMPACT_RANK.get(overall, 99)
            if overall_rank > computed_max_rank:
                issues.append(
                    f"$.calibrated_findings[{idx}].contextual_risk_rating ({overall!r}) exceeds max_impact ({declared_max!r}); hard rule overall_risk <= max_impact violated"
                )
            safety_raw = axes.get("safety", "negligible")
            safety_val = (
                str(safety_raw.get("severity") or safety_raw.get("level") or safety_raw.get("impact") or "negligible")
                if isinstance(safety_raw, dict)
                else str(safety_raw)
            )
            risk_owner = str(item.get("risk_owner") or "").strip()
            safety_owner = str(item.get("safety_owner") or "").strip()
            if safety_val != "negligible":
                if not safety_owner:
                    issues.append(
                        f"$.calibrated_findings[{idx}] has safety impact {safety_val!r} (!= 'negligible') and requires a non-empty $.safety_owner"
                    )
                elif safety_owner.lower() == risk_owner.lower():
                    issues.append(
                        f"$.calibrated_findings[{idx}] violates Safety Owner != Security Risk Owner separation (both set to {risk_owner!r})"
                    )


def validate_v30_epistemic_gates(
    skill_name: str,
    payload: dict[str, Any],
    issues: list[str] | None = None,
    *,
    valid_evidence_ids: set[str] | None = None,
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Public entry point for v3.0 epistemic gates; raises OutputValidationError if called standalone and issues are found."""
    target_issues = issues if issues is not None else []
    if isinstance(payload, dict):
        _normalize_v30_aliases(skill_name, payload)
    _validate_v30_epistemic_gates(
        skill_name,
        payload,
        target_issues,
        valid_evidence_ids=valid_evidence_ids,
        evidence_catalog=evidence_catalog,
    )
    if issues is None and target_issues:
        raise OutputValidationError("; ".join(target_issues[:40]))
    return target_issues


def validate_coverage_ledger(
    ledger: dict[str, Any],
    valid_evidence_ids: set[str],
    visibility_report: dict[str, Any] | None = None,
) -> None:
    """Validate coverage_ledger schema, RFC 3986 coverage_id, and physical Visibility Tracker gate."""
    validate_agent_output("coverage_ledger", ledger, valid_evidence_ids)
    if isinstance(visibility_report, dict):
        unvisited = visibility_report.get("unvisited_target_modules", [])
        grazing = visibility_report.get("shallow_grazing_files", [])
        issues: list[str] = []
        if unvisited:
            issues.append(f"Visibility Tracker gate failed: unvisited_target_modules={unvisited!r}")
        if grazing:
            grazing_paths = [g.get("path") for g in grazing if isinstance(g, dict)]
            issues.append(f"Anti-Grazing gate failed: shallow header grazing (<=8 lines) on files={grazing_paths!r}")
        if issues:
            raise OutputValidationError("; ".join(issues))


def collect_evidence_ids(value: Any) -> set[str]:
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k in EVIDENCE_ID_KEYS:
                ids = node.get(k)
                if isinstance(ids, list):
                    found.update(x for x in ids if isinstance(x, str))
            for rk in EVIDENCE_REF_KEYS:
                refs = node.get(rk)
                if isinstance(refs, list):
                    for r in refs:
                        if isinstance(r, dict) and isinstance(r.get("evidence_id"), str):
                            found.add(r["evidence_id"])
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return found
