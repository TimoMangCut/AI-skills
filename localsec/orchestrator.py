from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .agent import run_skill
from .llm import LocalModelError, OpenAICompatibleLocalClient
from .prompts import load_registry
from .reporting import write_cross_repo_documents, write_repo_documents, write_json
from .workspace import DISALLOWED_EXTENSIONS, ManualWorkspace, WorkspaceError, redact_text

SPECIALIST_ORDER = ["repo_profile", "api_authz", "dataflow", "threat_model", "architecture_review"]
BASV_SPECIALIST_ORDER = [
    "business_intent_modeler",
    "business_invariant_challenger",
    "implementation_trace_verifier",
    "intent_implementation_comparator",
    "security_consequence_mapper",
    "verification_planner",
    "targeted_verifier",
]
ACA_SPECIALIST_ORDER = [
    "finding_intake",
    "code_trace_builder",
    "attack_chain_constructor",
    "chain_step_verifier",
    "request_sequence_designer",
    "request_reproduction_operator",
    "root_cause_mapper",
    "counterevidence_challenger",
]
EVIDENCE_ID_KEYS = ("evidence_ids", "intent_evidence_ids", "implementation_evidence_ids", "counter_evidence_ids")
EVIDENCE_REF_KEYS = ("evidence_refs", "counterevidence_refs", "existing_evidence_refs")

SKILL_AUDIT_PRIORITY = {
    "attack_chain_constructor": 0,
    "chain_step_verifier": 0,
    "root_cause_mapper": 0,
    "chain_synthesizer": 0,
    "code_trace_builder": 1,
    "counterevidence_challenger": 1,
    "request_sequence_designer": 2,
    "finding_intake": 3,
    "security_consequence_mapper": 0,
    "intent_implementation_comparator": 0,
    "business_aware_synthesizer": 0,
    "targeted_verifier": 1,
    "threat_model": 0,
    "architecture_review": 1,
    "implementation_trace_verifier": 2,
    "api_authz": 2,
    "business_intent_modeler": 3,
    "dataflow": 3,
    "repo_profile": 4,
    "business_invariant_challenger": 4,
    "cross_repo_review": 0,
}
STATUS_AUDIT_PRIORITY = {
    "confirmed": 0,
    "confirmed_by_observation": 0,
    "confirmed_by_source": 0,
    "code_supported": 0,
    "directly_read": 0,
    "strongly_supported": 0,
    "observed": 0,
    "derived": 1,
    "partially_supported": 1,
    "partially_confirmed": 1,
    "hypothesis": 2,
    "hypothesized": 2,
    "assumed": 2,
    "candidate": 2,
    "unknown": 3,
    "not_assessed": 4,
}


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return cleaned or "repository"


def _write_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _log_event(path: Path, event: str, **details: Any) -> None:
    _write_jsonl(path, {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **details})


def _walk_evidence_ids(value: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for k in EVIDENCE_ID_KEYS:
            ids = value.get(k)
            if isinstance(ids, list):
                out.update(str(x) for x in ids if isinstance(x, str))
        for rk in EVIDENCE_REF_KEYS:
            refs = value.get(rk)
            if isinstance(refs, list):
                for r in refs:
                    if isinstance(r, dict) and isinstance(r.get("evidence_id"), str):
                        out.add(str(r["evidence_id"]))
        for child in value.values():
            out.update(_walk_evidence_ids(child))
    elif isinstance(value, list):
        for child in value:
            out.update(_walk_evidence_ids(child))
    return out


def _compact(value: Any, *, depth: int = 0, max_depth: int = 8, max_items: int = 45, max_string: int = 1300) -> Any:
    """Bound context passed between specialists without inventing facts."""
    if depth > max_depth:
        return "[context compacted: depth limit]"
    if isinstance(value, str):
        return value if len(value) <= max_string else value[:max_string] + "[TRUNCATED]"
    if isinstance(value, list):
        items = [_compact(x, depth=depth + 1, max_depth=max_depth, max_items=max_items, max_string=max_string) for x in value[:max_items]]
        if len(value) > max_items:
            items.append({"_context_truncated": True, "omitted_items": len(value) - max_items})
        return items
    if isinstance(value, dict):
        return {str(k): _compact(v, depth=depth + 1, max_depth=max_depth, max_items=max_items, max_string=max_string) for k, v in value.items()}
    return value


def _evidence_catalog_for_context(workspace: ManualWorkspace, related: Any, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    related_ids = _walk_evidence_ids(related)
    # Include every cited item first, then recent inspected chunks to allow the next specialist to extend reasoning.
    ordered_ids = [eid for eid in workspace.evidence if eid in related_ids]
    remaining = [eid for eid in workspace.evidence if eid not in related_ids]
    cap = int(cfg.get("analysis", {}).get("max_evidence_context_records", 55))
    if len(ordered_ids) > cap:
        ordered_ids = ordered_ids[-cap:]
        remaining = []
    else:
        remaining = remaining[-(cap - len(ordered_ids)):] if cap > len(ordered_ids) else []
    chosen = set(ordered_ids + remaining)
    return workspace.evidence_catalog(chosen, max_records=cap, excerpt_chars=int(cfg.get("analysis", {}).get("max_evidence_excerpt_chars", 1800)))


def _skill_context(skill: str, ai: dict[str, Any], workspace: ManualWorkspace, coverage: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    upstream = {name: entry for name, entry in ai.items() if entry.get("status") == "ok" and entry.get("result") is not None}
    depends_on = {
        "repo_profile": [],
        "api_authz": ["repo_profile"],
        "dataflow": ["repo_profile", "api_authz"],
        "threat_model": ["repo_profile", "api_authz", "dataflow"],
        "architecture_review": ["repo_profile", "api_authz", "dataflow", "threat_model"],
    }.get(skill, list(upstream))
    previous = {name: upstream[name]["result"] for name in depends_on if name in upstream}
    catalog = _evidence_catalog_for_context(workspace, previous, cfg)
    return {
        "prerequisite_results": _compact(previous),
        "available_evidence": catalog,
        "coverage_so_far": coverage,
        "important_scope_rule": "Read source files manually using the tools. The evidence catalog only shows excerpts previously inspected by an AI skill; you may inspect more files yourself.",
    }


def _claim_text(node: dict[str, Any]) -> str:
    preferred = (
        "title", "scenario", "assessment", "mechanism", "name", "value", "claim",
        "description", "expected_behavior", "observed_behavior", "comparison_result", "rationale",
        "counterexample", "question", "outcome", "authorization_analysis", "validation_analysis",
        "state_transition_analysis", "business_impact", "security_impact",
        "method", "path", "handler", "authn", "authorization", "object_level_authz", "sensitivity",
        "direction", "source", "destination", "identity_context", "kind", "path_or_symbol", "data_class",
        "impact", "notes", "recommendation", "relationship",
    )
    parts = []
    for key in preferred:
        value = node.get(key)
        if isinstance(value, str) and value:
            parts.append(f"{key}: {value}")
        elif isinstance(value, list) and value:
            parts.append(f"{key}: {', '.join(str(x) for x in value[:8])}")
    return "; ".join(parts) or json.dumps({k: v for k, v in node.items() if k not in EVIDENCE_ID_KEYS}, ensure_ascii=False)[:1500]


def _build_proof_obligation_and_challenge(node: dict[str, Any], skill: str) -> tuple[dict[str, str], dict[str, str]]:
    """Construct Popperian falsifiability (proof_obligation) and bounded challenge loop questions for a claim."""
    text = _claim_text(node)
    if skill in {"api_authz", "intent_implementation_comparator", "security_consequence_mapper"}:
        falsify = "Falsified if an upstream middleware, controller guard, SQL constraint, or gateway filter deterministically enforces the missing check on this active route."
        req_cond = "Cited evidence must show both the active route/handler wiring and the absence or bypass of the expected control."
    elif skill in {"attack_chain_constructor", "chain_step_verifier", "code_trace_builder"}:
        falsify = "Falsified if any precondition is unsatisfiable by the attacker actor, if the hop is dead/unwired code, or if state_after is sanitized before the next step."
        req_cond = "Every directly_read hop and linked edge must be bound to an active entrypoint/sink with compatible caller identity and state."
    else:
        falsify = "Falsified if the cited file is dead/unwired code, gated off by a production feature flag, or superseded by a newer migration/contract."
        req_cond = "Cited excerpt must directly govern the active production execution path or authoritative domain contract."
    proof_obligation = {
        "what_would_falsify": str(node.get("what_would_falsify") or falsify),
        "required_supporting_conditions": str(node.get("required_supporting_conditions") or req_cond),
    }
    challenge_questions = {
        "counterexample_question": f"What specific input, caller role, or DB constraint acts as a counterexample that blocks: {text[:140]}?",
        "stronger_alternative_chain_question": "If this specific path is blocked, what adjacent endpoint, background worker, or shared table achieves the same or higher business impact?",
        "overestimated_control_question": "Which existing control on this path is being trusted on paper without verifying its runtime wiring, feature-flag state, or failure mode?",
    }
    return proof_obligation, challenge_questions


def _iter_claims(value: Any, skill: str, path: str = "$", out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    out = out if out is not None else []
    if isinstance(value, dict):
        status = (
            value.get("status")
            or value.get("verification_status")
            or value.get("link_status")
            or value.get("result")
            or value.get("root_cause_status")
            or value.get("chain_verdict")
        )
        present_id_lists = [value.get(k) for k in EVIDENCE_ID_KEYS if isinstance(value.get(k), list)]
        present_ref_lists = [value.get(rk) for rk in EVIDENCE_REF_KEYS if isinstance(value.get(rk), list)]
        if status and (present_id_lists or present_ref_lists):
            merged_ids: list[str] = []
            for id_list in present_id_lists:
                for eid in id_list:
                    if isinstance(eid, str) and eid not in merged_ids:
                        merged_ids.append(eid)
            for ref_list in present_ref_lists:
                for ref_obj in ref_list:
                    if isinstance(ref_obj, dict):
                        eid = ref_obj.get("evidence_id")
                        if isinstance(eid, str) and eid not in merged_ids:
                            merged_ids.append(eid)
            proof_ob, challenge_q = _build_proof_obligation_and_challenge(value, skill)
            out.append({
                "claim_ref": f"{skill}:{path}",
                "source_skill": skill,
                "claim_status": str(status),
                "claim_text": _claim_text(value),
                "cited_evidence_ids": merged_ids,
                "proof_obligation": proof_ob,
                "bounded_challenge_loop": challenge_q,
            })
        for key, child in value.items():
            _iter_claims(child, skill, f"{path}.{key}", out)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _iter_claims(child, skill, f"{path}[{index}]", out)
    return out


def _select_claims_for_audit(all_claims: list[dict[str, Any]], cfg: dict[str, Any]) -> tuple[list[list[dict[str, Any]]], list[str]]:
    """Filter out vacuous unknown/not_assessed claims without evidence, prioritize high-risk skills, and batch."""
    actionable_statuses = {
        "observed",
        "derived",
        "confirmed",
        "confirmed_by_source",
        "confirmed_by_observation",
        "code_supported",
        "directly_read",
        "strongly_supported",
    }
    actionable = [
        c for c in all_claims
        if c["claim_status"] in actionable_statuses or bool(c["cited_evidence_ids"])
    ]
    ordered = sorted(
        actionable,
        key=lambda c: (
            not bool(c["cited_evidence_ids"]),
            STATUS_AUDIT_PRIORITY.get(c["claim_status"], 9),
            SKILL_AUDIT_PRIORITY.get(c["source_skill"], 9),
            c["claim_ref"],
        ),
    )
    analysis_cfg = cfg.get("analysis", {})
    batch_size = max(1, int(analysis_cfg.get("audit_batch_size", 15)))
    max_batches = max(1, int(analysis_cfg.get("max_audit_batches", 6)))
    max_claims = max(1, int(analysis_cfg.get("max_claims_per_audit", batch_size * max_batches)))
    cap = min(len(ordered), max_claims, batch_size * max_batches)
    selected, skipped = ordered[:cap], ordered[cap:]
    batches = [selected[i:i + batch_size] for i in range(0, len(selected), batch_size)]
    return batches, [c["claim_ref"] for c in skipped]


def _run_batched_evidence_audit(
    *,
    client: OpenAICompatibleLocalClient,
    all_claims: list[dict[str, Any]],
    evidence_lookup: dict[str, dict[str, Any]],
    cfg: dict[str, Any],
    run_id: str,
    repo_name: str,
    objective: str,
) -> dict[str, Any]:
    """Run evidence_auditor across bounded claim batches with full-length source excerpts."""
    batches, skipped_refs = _select_claims_for_audit(all_claims, cfg)
    excerpt_cap = int(cfg.get("analysis", {}).get("max_audit_excerpt_chars", 4500))
    if not batches:
        batches = [[]]

    merged_audited: list[dict[str, Any]] = []
    merged_not_audited: list[str] = list(skipped_refs)
    summaries: list[str] = []
    total_tool_calls = 0
    total_model_turns = 0
    total_retries = 0
    seen_eids: set[str] = set()
    warnings: list[str] = []
    batch_statuses: list[str] = []
    first_prompt_sha = ""
    first_payload_sha = ""

    for batch_idx, batch_claims in enumerate(batches):
        batch_eids = {eid for claim in batch_claims for eid in claim["cited_evidence_ids"]}
        cited_catalog = []
        for eid in sorted(batch_eids):
            rec = evidence_lookup.get(eid)
            if rec:
                cited_catalog.append(
                    {k: rec[k] for k in ("evidence_id", "repo_name", "path", "line_start", "line_end", "excerpt_sha256", "redaction_applied") if k in rec}
                    | {"excerpt": rec["excerpt"][:excerpt_cap]}
                )
        not_sent_refs = skipped_refs if batch_idx == 0 else []
        audit_context = {
            "claims_to_audit": batch_claims,
            "cited_evidence_catalog": cited_catalog,
            "not_sent_due_to_audit_budget": len(not_sent_refs),
            "not_sent_claim_refs": not_sent_refs,
            "available_evidence": [],
            "note": "Audit each supplied claim against its actual excerpts in cited_evidence_catalog, not against plausibility.",
        }
        audit_job = {
            "job_id": uuid.uuid4().hex,
            "run_id": run_id,
            "repo_name": repo_name,
            "objective": objective,
            "batch_index": batch_idx + 1,
            "total_batches": len(batches),
            "output_schema": "evidence_audit.schema.json",
            "maximum_tool_calls": 0,
            "read_scope": "none",
        }
        res = run_skill(
            client=client,
            skill="evidence_auditor",
            job_spec=audit_job,
            context=audit_context,
            workspace=None,
            cfg=cfg,
            allowed_context_evidence_ids=batch_eids,
        )
        if not first_prompt_sha:
            first_prompt_sha = res.get("system_prompt_sha256", "")
            first_payload_sha = res.get("initial_payload_sha256", "")
        batch_statuses.append(str(res.get("status", "failed")))
        total_tool_calls += int(res.get("tool_calls", 0))
        total_model_turns += int(res.get("model_turns", 0))
        total_retries += int(res.get("validation_retries", 0))
        seen_eids.update( batch_eids )
        warnings.extend(res.get("warnings", []))
        if res.get("status") == "ok" and isinstance(res.get("result"), dict):
            r_data = res["result"]
            merged_audited.extend(r_data.get("audited_claims", []))
            for na in r_data.get("not_audited", []):
                if na not in merged_not_audited:
                    merged_not_audited.append(na)
            if r_data.get("summary"):
                summaries.append(str(r_data["summary"]))
        else:
            for c in batch_claims:
                if c["claim_ref"] not in merged_not_audited:
                    merged_not_audited.append(c["claim_ref"])

    overall_ok = all(s == "ok" for s in batch_statuses)
    audit_status = "complete" if overall_ok and not merged_not_audited else "partial"
    return {
        "skill": "evidence_auditor",
        "version": "2.1.0",
        "status": "ok" if any(s == "ok" for s in batch_statuses) else "failed",
        "result": {
            "audit_status": audit_status,
            "audited_claims": merged_audited,
            "not_audited": merged_not_audited,
            "summary": " | ".join(summaries) if summaries else "Evidence audit completed.",
        } if any(s == "ok" for s in batch_statuses) else None,
        "tool_calls": total_tool_calls,
        "model_turns": total_model_turns,
        "validation_retries": total_retries,
        "evidence_ids_seen": sorted(seen_eids),
        "evidence_ids_read_during_job": [],
        "tool_trace": [],
        "system_prompt_sha256": first_prompt_sha,
        "initial_payload_sha256": first_payload_sha,
        "warnings": warnings,
    }


def _resolve_path(root: Any, path: str) -> Any:
    if not path.startswith("$"):
        return None
    node = root
    tokens = re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]", path[1:])
    for key, index in tokens:
        try:
            node = node[key] if key else node[int(index)]
        except (KeyError, IndexError, TypeError):
            return None
    return node


def _downgrade_aca_node(target: dict[str, Any], root: dict[str, Any], decision: str) -> None:
    """Downgrade Phase 3 Attack Chain nodes fail-closed when evidence audit rejects or partially supports a claim."""
    if decision in {"unsupported", "inconclusive"}:
        if target.get("verification_status") in {"confirmed_by_source", "confirmed_by_observation"}:
            target["verification_status"] = "hypothesis"
        if target.get("verification_status") == "directly_read":
            target["verification_status"] = "inferred_from_context"
        if target.get("link_status") in {"confirmed_by_source", "confirmed_by_observation"}:
            target["link_status"] = "hypothesis"
        if target.get("result") in {"confirmed_by_source", "confirmed_by_observation"}:
            target["result"] = "hypothesis"
        if target.get("root_cause_status") in {"confirmed", "strongly_supported"}:
            target["root_cause_status"] = "candidate"
        if target.get("status") in {"confirmed", "confirmed_by_source", "confirmed_by_observation", "code_supported", "demonstrated", "strongly_supported"}:
            target["status"] = "unknown" if "condition" in target or "pattern_id" in target or "root_cause_id" in target else "hypothesis"
        if root.get("chain_verdict") in {"confirmed", "code_supported"}:
            root["chain_verdict"] = "hypothesized"
    elif decision == "partially_supported":
        if target.get("verification_status") in {"confirmed_by_source", "confirmed_by_observation"}:
            target["verification_status"] = "partially_supported"
        if target.get("link_status") in {"confirmed_by_source", "confirmed_by_observation"}:
            target["link_status"] = "partially_supported"
        if target.get("result") in {"confirmed_by_source", "confirmed_by_observation"}:
            target["result"] = "partially_supported"
        if root.get("chain_verdict") in {"confirmed", "code_supported"}:
            root["chain_verdict"] = "partially_confirmed"


def _apply_audit(
    ai: dict[str, Any],
    audit: dict[str, Any] | None,
    *,
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
) -> None:
    from .validators import verify_claim_to_excerpt_semantics

    if not isinstance(audit, dict):
        return
    analysis = audit.get("result") if audit.get("status") == "ok" else None
    if not isinstance(analysis, dict):
        return
    verdict_map = {item.get("claim_ref"): item for item in analysis.get("audited_claims", []) if isinstance(item, dict) and item.get("claim_ref")}
    not_audited_set = set(analysis.get("not_audited", []))
    for skill, entry in ai.items():
        result = entry.get("result")
        if not isinstance(result, dict):
            continue
        for claim in _iter_claims(result, skill):
            target = _resolve_path(result, claim["claim_ref"].split(":", 1)[1])
            if not isinstance(target, dict):
                continue
            verdict = verdict_map.get(claim["claim_ref"])
            status = target.get("status")
            sem_contradictions = (
                verify_claim_to_excerpt_semantics(target, claim["cited_evidence_ids"], evidence_catalog)
                if evidence_catalog is not None
                else []
            )
            if sem_contradictions:
                sem_reason = "; ".join(sem_contradictions)
                if verdict is not None:
                    verdict["verdict"] = "unsupported"
                    verdict["reason"] = f"[Semantic Claim-to-Excerpt Verifier: CONTRADICTED] {sem_reason}"
                else:
                    new_verdict = {
                        "claim_ref": claim["claim_ref"],
                        "verdict": "unsupported",
                        "cited_evidence_ids": claim["cited_evidence_ids"],
                        "reason": f"[Semantic Claim-to-Excerpt Verifier: CONTRADICTED] {sem_reason}",
                    }
                    analysis.setdefault("audited_claims", []).append(new_verdict)
                    verdict = new_verdict
            if verdict:
                decision = verdict.get("verdict")
                if decision == "unsupported" and status in {"observed", "derived"}:
                    target["status"] = "unknown"
                    if target.get("comparison_result") == "mismatch":
                        target["comparison_result"] = "not_verified"
                    if target.get("outcome") == "confirmed":
                        target["outcome"] = "inconclusive"
                elif decision in {"partially_supported", "inconclusive"} and status in {"observed", "derived"}:
                    # Preserve inconclusive/partially_supported claims as explicit hypotheses rather than erasing to unknown
                    target["status"] = "hypothesis"
                    target["preserved_hypothesis_lead"] = True
                    if target.get("comparison_result") == "mismatch" and decision == "inconclusive":
                        target["comparison_result"] = "not_verified"
                    if target.get("outcome") == "confirmed":
                        target["outcome"] = "inconclusive"
                _downgrade_aca_node(target, result, str(decision))
                if isinstance(target.get("notes"), str):
                    target["notes"] = (target["notes"] + f" [Evidence audit: {decision}; {verdict.get('reason', '')}]").strip()
            elif claim["claim_ref"] in not_audited_set:
                if status in {"observed", "derived"}:
                    # Fail-closed: any observed/derived claim that was skipped by the auditor is downgraded to hypothesis.
                    target["status"] = "hypothesis"
                    if target.get("comparison_result") == "mismatch":
                        target["comparison_result"] = "not_verified"
                    if isinstance(target.get("notes"), str):
                        target["notes"] = (target["notes"] + " [Evidence audit: not_audited; downgraded fail-closed to hypothesis]").strip()
                _downgrade_aca_node(target, result, "partially_supported")


def evaluate_contextual_evidence_strength(
    evidence_ids: list[str],
    evidence_catalog: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    """Distinguish truly strong contextual evidence from formally valid but contextually weak/stale/isolated evidence, and match against the Negative Corpus of known-false patterns."""
    from .workspace import classify_source_authority_and_role

    if not evidence_ids:
        return {
            "strength_verdict": "no_evidence",
            "is_entrypoint_or_sink_bound": False,
            "is_contract_or_spec_bound": False,
            "best_source_rank": 4,
            "temporal_drift_warning": False,
            "negative_corpus_matches": ["missing_evidence"],
            "deployment_versions": [],
            "context_warnings": ["No evidence IDs supplied."],
        }
    roles: list[str] = []
    provs: list[str] = []
    ranks: list[int] = []
    intent_epochs: list[int] = []
    impl_epochs: list[int] = []
    has_dead_code = False
    has_unverified_dev_note = False
    feature_flags: set[str] = set()
    deployment_versions: set[str] = set()

    for eid in evidence_ids:
        rec = (evidence_catalog or {}).get(eid, {})
        rel = str(rec.get("path", ""))
        excerpt = str(rec.get("excerpt", ""))
        meta = (
            classify_source_authority_and_role(rel, excerpt=excerpt)
            if rel
            else {
                "source_rank": 4,
                "execution_role": "auxiliary_or_helper",
                "provenance_kind": "unknown_source_kind",
                "authority_verified_by": "unverified_dev_note",
                "dead_or_commented_code": False,
                "feature_flag_refs": [],
            }
        )
        role = str(rec.get("execution_role") or meta["execution_role"])
        rank = int(rec.get("source_rank") or meta["source_rank"])
        prov = str(rec.get("provenance_kind") or meta["provenance_kind"])
        verified_by = str(rec.get("authority_verified_by") or meta.get("authority_verified_by", ""))
        mtime = int(rec.get("last_modified_epoch") or 0)
        if rec.get("dead_or_commented_code") or meta.get("dead_or_commented_code"):
            has_dead_code = True
        if verified_by == "unverified_dev_note":
            has_unverified_dev_note = True
        for ff in rec.get("feature_flag_refs") or meta.get("feature_flag_refs") or []:
            feature_flags.add(str(ff))
        branch = str(rec.get("git_branch") or "")
        sha = str(rec.get("git_commit_sha") or "")
        tag = str(rec.get("git_release_tag") or "")
        if branch or sha or tag:
            deployment_versions.add(f"{branch}@{sha or 'unknown'}" + (f" ({tag})" if tag else ""))

        roles.append(role)
        provs.append(prov)
        ranks.append(rank)
        if mtime > 0:
            if prov == "intent_artifact":
                intent_epochs.append(mtime)
            elif prov == "implementation_code":
                impl_epochs.append(mtime)

    is_bound = any(r in {"entrypoint_or_wiring", "domain_service_or_sink", "specification_or_contract"} for r in roles)
    is_spec_bound = any(r == "specification_or_contract" or p == "intent_artifact" for r, p in zip(roles, provs))
    best_rank = min(ranks) if ranks else 4
    temporal_drift_warning = False
    context_warnings: list[str] = []
    negative_corpus_matches: list[str] = []

    if has_dead_code:
        negative_corpus_matches.append("dead_or_commented_code")
        context_warnings.append(
            "Negative corpus match [dead_or_commented_code]: cited evidence consists primarily of commented-out or disabled code."
        )
    if intent_epochs and impl_epochs:
        # If the newest intent doc is > 180 days older than the implementation code, flag potential stale doc authority
        drift_seconds = max(impl_epochs) - max(intent_epochs)
        if drift_seconds > 180 * 86400:
            temporal_drift_warning = True
            negative_corpus_matches.append("stale_doc_plausible_trap")
            context_warnings.append(
                f"Temporal drift warning: cited intent artifact is {drift_seconds // 86400} days older than implementation code."
            )
    if not is_bound:
        negative_corpus_matches.append("unwired_helper_only")
        context_warnings.append(
            "Formally valid but contextually weak: cited evidence consists only of auxiliary_or_helper / informal files without entrypoint, controller, or domain sink binding."
        )
    if best_rank == 4 or (has_unverified_dev_note and best_rank >= 3):
        negative_corpus_matches.append("unverified_dev_note_as_authority")
        context_warnings.append(
            "Low source authority (rank 4 / unverified_dev_note): informal note or README without sign-off cannot serve as primary authoritative specification."
        )
    if feature_flags:
        negative_corpus_matches.append("feature_flag_gated_path")
        context_warnings.append(
            f"Deployment freshness note: execution path depends on runtime feature/config flags {sorted(feature_flags)}."
        )

    if is_bound and best_rank <= 3 and not temporal_drift_warning and not has_dead_code:
        strength_verdict = "contextually_strong"
    elif is_bound and not has_dead_code:
        strength_verdict = "contextually_moderate_with_drift_or_rank_warning"
    else:
        strength_verdict = "contextually_weak_isolated_or_informal"
    return {
        "strength_verdict": strength_verdict,
        "is_entrypoint_or_sink_bound": is_bound,
        "is_contract_or_spec_bound": is_spec_bound,
        "best_source_rank": best_rank,
        "temporal_drift_warning": temporal_drift_warning,
        "negative_corpus_matches": negative_corpus_matches,
        "deployment_versions": sorted(deployment_versions),
        "context_warnings": context_warnings,
    }


def manage_hypothesis_lifecycle(
    hypotheses: list[dict[str, Any]],
    *,
    current_round: int = 1,
    max_stagnant_rounds: int = 2,
    new_evidence_ids: set[str] | None = None,
    new_evidence_repos: set[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Deduplicate hypotheses, apply priority decay / aging, and re-activate dormant/archived hypotheses when new related evidence arrives."""
    decay_map = {"P0": "P1", "P1": "P2", "P2": "P3", "P3": "P3"}
    boost_map = {"P3": "P2", "P2": "P1", "P1": "P0", "P0": "P0"}
    new_eids = new_evidence_ids or set()
    new_repos = new_evidence_repos or set()

    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        item = dict(h)
        repo = str(item.get("repo_name") or (item.get("affected_repos") or [""])[0])
        inv_ref = str(item.get("invariant_ref") or (item.get("invariant_refs") or item.get("related_refs") or [""])[0])
        cat = str(item.get("category") or item.get("title") or item.get("id") or "")
        key = (repo, inv_ref, cat)
        if key in deduped:
            existing = deduped[key]
            merged_eids = sorted(set(existing.get("evidence_ids", [])) | set(item.get("evidence_ids", [])))
            existing["evidence_ids"] = merged_eids
            existing["deduplicated_count"] = int(existing.get("deduplicated_count", 1)) + 1
            continue

        stagnant = int(item.get("rounds_without_new_evidence", 0))
        prio = str(item.get("priority", "P2"))
        item_eids = set(item.get("evidence_ids") or [])
        was_archived = item.get("lifecycle_status") == "archived_requires_operator_or_runtime" or stagnant >= max_stagnant_rounds
        has_fresh_link = bool((item_eids & new_eids) or (repo and repo in new_repos))

        if was_archived and has_fresh_link:
            item["lifecycle_status"] = "active_hypothesis"
            item["reactivated"] = True
            item["rounds_without_new_evidence"] = 0
            item["priority"] = boost_map.get(prio, prio)
        else:
            if stagnant >= 1:
                for _ in range(stagnant):
                    prio = decay_map.get(prio, "P3")
                item["priority"] = prio
            if stagnant >= max_stagnant_rounds:
                item["lifecycle_status"] = "archived_requires_operator_or_runtime"
            else:
                item["lifecycle_status"] = "active_hypothesis"
        item["last_evaluated_round"] = current_round
        deduped[key] = item

    active = [v for v in deduped.values() if v.get("lifecycle_status") == "active_hypothesis"]
    archived = [v for v in deduped.values() if v.get("lifecycle_status") != "active_hypothesis"]
    reactivated = [v for v in active if v.get("reactivated") is True]
    return {
        "active_hypotheses": active,
        "archived_hypotheses": archived,
        "reactivated_hypotheses": reactivated,
    }


def build_cross_artifact_contradiction_graph(
    repo_results: list[dict[str, Any]],
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a 5-axis Cross-Artifact Contradiction Graph across BRD<->Code, Code<->SQL Migration, Code<->Config, API<->Authz Matrix, and Docs<->Observed Behavior."""
    from .workspace import classify_source_authority_and_role

    edges: list[dict[str, Any]] = []
    by_type: dict[str, int] = {
        "brd_vs_code": 0,
        "code_vs_sql_migration": 0,
        "code_vs_runtime_config": 0,
        "api_spec_vs_authz_matrix": 0,
        "doc_vs_observed_request_behavior": 0,
    }
    nodes: set[str] = set()

    for res in repo_results:
        if not isinstance(res, dict):
            continue
        rname = str(res.get("repo_name", "unknown"))
        basv = res.get("basv") or {}
        comp_block = basv.get("intent_implementation_comparator") or {}
        for cmp_item in comp_block.get("comparisons", []):
            if not isinstance(cmp_item, dict):
                continue
            c_res = str(cmp_item.get("comparison_result", ""))
            if c_res not in {"mismatch", "contradictory", "partial"}:
                continue
            intent_eids = cmp_item.get("intent_evidence_ids") or []
            impl_eids = cmp_item.get("implementation_evidence_ids") or []
            intent_paths = [str((evidence_catalog or {}).get(e, {}).get("path", e)) for e in intent_eids]
            impl_paths = [str((evidence_catalog or {}).get(e, {}).get("path", e)) for e in impl_eids]

            joined_intent = " ".join(intent_paths).lower()
            joined_impl = " ".join(impl_paths).lower()
            rationale = str(cmp_item.get("rationale", "") or cmp_item.get("observed_behavior", "")).lower()

            if any(p.endswith(".sql") or "db-pipeline" in p or "migration" in p for p in intent_paths + impl_paths):
                ctype = "code_vs_sql_migration"
            elif any(
                "appsettings" in p or "variable-management" in p or p.endswith((".env", ".yaml", ".yml"))
                for p in intent_paths + impl_paths
            ) or "env_" in rationale:
                ctype = "code_vs_runtime_config"
            elif any(k in rationale for k in ("role", "permission", "authorize", "jwt", "authz", "maker", "checker")):
                ctype = "api_spec_vs_authz_matrix"
            elif any(k in rationale for k in ("request", "response", "status code", "webhook", "callback", "payload")):
                ctype = "doc_vs_observed_request_behavior"
            else:
                ctype = "brd_vs_code"

            by_type[ctype] = by_type.get(ctype, 0) + 1
            src_node = f"{rname}:intent:{cmp_item.get('invariant_ref', 'INV')}"
            dst_node = f"{rname}:impl:{cmp_item.get('id', 'CMP')}"
            nodes.add(src_node)
            nodes.add(dst_node)
            edges.append(
                {
                    "contradiction_type": ctype,
                    "repo_name": rname,
                    "participating_repos": cmp_item.get("repo_names") or [rname],
                    "source_node": src_node,
                    "target_node": dst_node,
                    "invariant_ref": str(cmp_item.get("invariant_ref", "")),
                    "comparison_id": str(cmp_item.get("id", "")),
                    "comparison_result": c_res,
                    "expected_behavior": str(cmp_item.get("expected_behavior", "")),
                    "observed_behavior": str(cmp_item.get("observed_behavior", "")),
                    "intent_evidence_ids": intent_eids,
                    "implementation_evidence_ids": impl_eids,
                    "status": str(cmp_item.get("status", "hypothesis")),
                }
            )

    return {
        "total_contradiction_edges": len(edges),
        "distinct_nodes": len(nodes),
        "by_contradiction_type": by_type,
        "contradiction_edges": edges,
    }


def check_aca_convergence(
    *,
    traces: list[dict[str, Any]],
    previous_evidence_ids: set[str],
    current_evidence_ids: set[str],
    previous_unresolved_questions: list[str],
    current_unresolved_questions: list[str],
    previous_verified_steps_or_edges: int = 0,
    current_verified_steps_or_edges: int = 0,
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
    consecutive_low_gain_rounds: int = 0,
) -> dict[str, Any]:
    """Deterministic convergence, cycle, weighted semantic progress, and operator-review trigger for Phase 3."""
    from .workspace import classify_source_authority_and_role

    seen_hops: set[tuple[str, str, str, str]] = set()
    duplicate_hops: list[dict[str, str]] = []
    for tr in traces:
        if not isinstance(tr, dict):
            continue
        repo = str(tr.get("repo_name", ""))
        question = str(tr.get("trace_question", ""))
        for hop in tr.get("hops", []):
            if not isinstance(hop, dict):
                continue
            hop_repo = str(hop.get("repo_name") or "")
            if not hop_repo and evidence_catalog:
                for ref in hop.get("evidence_refs") or []:
                    if isinstance(ref, dict) and ref.get("evidence_id") in evidence_catalog:
                        ev_rec = evidence_catalog[ref["evidence_id"]]
                        ev_path = str(ev_rec.get("path", ""))
                        if ":" in ev_path:
                            hop_repo = ev_path.split(":", 1)[0]
                        elif ev_rec.get("repo_name") and ev_rec.get("repo_name") != "_analysis":
                            hop_repo = str(ev_rec["repo_name"])
                        break
            effective_repo = hop_repo or repo
            key = (
                effective_repo,
                str(hop.get("relative_file_path", "")),
                str(hop.get("symbol_or_locator", "")),
                question,
            )
            if key in seen_hops:
                duplicate_hops.append(
                    {
                        "repo_name": effective_repo,
                        "relative_file_path": key[1],
                        "symbol_or_locator": key[2],
                        "trace_question": question,
                    }
                )
            else:
                seen_hops.add(key)
    new_evidence_ids = sorted(current_evidence_ids - previous_evidence_ids)
    resolved_questions = sorted(set(previous_unresolved_questions) - set(current_unresolved_questions))
    added_questions = sorted(set(current_unresolved_questions) - set(previous_unresolved_questions))
    verified_delta = max(0, int(current_verified_steps_or_edges) - int(previous_verified_steps_or_edges))

    # Compute weighted semantic progress score (valuing entrypoint/sink evidence & chain state resolution over raw counts)
    evidence_weight = 0.0
    for eid in new_evidence_ids:
        rec = (evidence_catalog or {}).get(eid, {})
        role = rec.get("execution_role")
        if not role and rec.get("path"):
            role = classify_source_authority_and_role(str(rec["path"]))["execution_role"]
        if role in {"entrypoint_or_wiring", "domain_service_or_sink"}:
            evidence_weight += 3.0
        elif role == "specification_or_contract":
            evidence_weight += 2.0
        elif role == "auxiliary_or_helper":
            evidence_weight += 0.4
        else:
            evidence_weight += 1.5

    weighted_epistemic_gain = round(
        evidence_weight
        + (4.0 * verified_delta)
        + (2.5 * len(resolved_questions))
        - (0.5 * len(added_questions) if verified_delta == 0 and len(resolved_questions) == 0 else 0.0),
        2,
    )

    question_runaway_detected = (
        len(added_questions) > len(resolved_questions)
        and len(resolved_questions) == 0
        and verified_delta == 0
        and (len(new_evidence_ids) == 0 or len(added_questions) >= 2)
    )
    low_gain_this_round = weighted_epistemic_gain < 1.5 and verified_delta == 0 and len(resolved_questions) == 0
    updated_low_gain_streak = (consecutive_low_gain_rounds + 1) if low_gain_this_round else 0
    operator_review_triggered = bool(
        duplicate_hops or question_runaway_detected or updated_low_gain_streak >= 2 or (low_gain_this_round and len(added_questions) > 0)
    )
    made_progress = (bool(new_evidence_ids) or bool(resolved_questions) or verified_delta > 0) and not question_runaway_detected and not (updated_low_gain_streak >= 2)
    recommended_action = (
        "conclude_or_request_operator_input"
        if (duplicate_hops or not made_progress or question_runaway_detected or operator_review_triggered)
        else "continue_exploration_permitted"
    )
    return {
        "cycle_detected": bool(duplicate_hops),
        "duplicate_hops": duplicate_hops,
        "question_runaway_detected": question_runaway_detected,
        "weighted_epistemic_gain": weighted_epistemic_gain,
        "consecutive_low_gain_rounds": updated_low_gain_streak,
        "operator_review_triggered": operator_review_triggered,
        "new_evidence_count": len(new_evidence_ids),
        "new_evidence_ids": new_evidence_ids,
        "resolved_question_count": len(resolved_questions),
        "resolved_questions": resolved_questions,
        "added_question_count": len(added_questions),
        "added_questions": added_questions,
        "verified_step_or_edge_delta": verified_delta,
        "made_progress": made_progress,
        "recommended_action": recommended_action,
    }


def build_blinded_challenger_context(
    *,
    intent_model: dict[str, Any],
    repo_profile: dict[str, Any] | None = None,
    api_authz: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    raw_input: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministically strip prior security findings, threat models, and architecture review conclusions."""
    forbidden_keys = {"threat_model", "threats", "architecture_review", "observations", "findings", "cross_repo_review", "security_consequence_map", "scenarios"}
    sanitized_profile = {k: v for k, v in (repo_profile or {}).items() if k not in forbidden_keys}
    sanitized_api = {k: v for k, v in (api_authz or {}).items() if k not in forbidden_keys}
    sanitized_flow = {k: v for k, v in (dataflow or {}).items() if k not in forbidden_keys}
    return {
        "context_blinding_policy": "prior_threat_models, prior_security_findings, and prior_architecture_review_conclusions are strictly excluded",
        "business_intent_model": intent_model,
        "service_and_interface_map": {
            "repo_profile": sanitized_profile,
            "api_inventory": sanitized_api.get("endpoints", []),
            "dataflow": sanitized_flow.get("flows", []),
        },
        "coverage_gaps": (coverage or {}).get("unique_files_read", []),
    }


def build_blinded_targeted_verifier_context(
    *,
    task: dict[str, Any],
    related_invariant_expected_behavior: str = "",
) -> dict[str, Any]:
    """Deterministically strip comparison_result, security_impact, exploitability, and prior conclusions."""
    allowed_task_keys = {
        "task_id",
        "repo_name",
        "question",
        "candidate_paths",
        "expected_evidence",
        "acceptance_criteria",
        "stop_if",
    }
    clean_task = {k: task[k] for k in allowed_task_keys if k in task}
    return {
        "context_blinding_policy": "comparison_result, security_impact, exploitability, and previous_agent_recommended_conclusion are strictly excluded",
        "neutral_verification_task": clean_task,
        "related_invariant_expected_behavior": related_invariant_expected_behavior,
        "allowed_read_paths": list(task.get("candidate_paths", [])),
    }


def build_blinded_chain_verifier_context(
    *,
    attack_chain: dict[str, Any],
    code_traces: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Deterministically strip constructor verdicts (chain_verdict, verification_status, link_status, impact_assessment) for independent chain verification."""
    blinded_steps: list[dict[str, Any]] = []
    for step in attack_chain.get("steps", []):
        if not isinstance(step, dict):
            continue
        blinded_edges = [
            {
                "next_step_id": edge.get("next_step_id"),
                "link_claim": edge.get("link_claim"),
                "evidence_refs": edge.get("evidence_refs", []),
            }
            for edge in step.get("linked_next_steps", [])
            if isinstance(edge, dict)
        ]
        blinded_steps.append(
            {
                "step_id": step.get("step_id"),
                "purpose": step.get("purpose"),
                "actor": step.get("actor"),
                "action": step.get("action"),
                "target_component": step.get("target_component"),
                "preconditions": step.get("preconditions", []),
                "source_or_entry_point": step.get("source_or_entry_point", ""),
                "expected_control": step.get("expected_control", ""),
                "state_before": step.get("state_before", ""),
                "state_after": step.get("state_after", ""),
                "data_or_privilege_delta": step.get("data_or_privilege_delta", ""),
                "linked_next_steps": blinded_edges,
                "evidence_refs": step.get("evidence_refs", []),
            }
        )
    return {
        "context_blinding_policy": (
            "chain_verdict, execution_status, impact_assessment, steps[].verification_status, "
            "steps[].observed_control_behavior, and linked_next_steps[].link_status are strictly excluded "
            "so chain_step_verifier and counterevidence_challenger evaluate steps and edges independently."
        ),
        "candidate_chain_structure": {
            "chain_id": attack_chain.get("chain_id"),
            "title": attack_chain.get("title"),
            "attacker_objective": attack_chain.get("attacker_objective"),
            "business_invariant_at_risk": attack_chain.get("business_invariant_at_risk"),
            "scope": attack_chain.get("scope"),
            "attacker_model": attack_chain.get("attacker_model"),
            "entry_point": attack_chain.get("entry_point"),
            "preconditions": attack_chain.get("preconditions", []),
            "steps": blinded_steps,
        },
        "code_traces": code_traces or [],
    }


def execute_constrained_local_request(
    *,
    request_plan: dict[str, Any],
    target_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Constrained local HTTP request adapter that defaults fail-closed to not_executed unless an operator-approved local target profile is provided."""
    updated = json.loads(json.dumps(request_plan))
    allow_urls = [
        str(u).rstrip("/")
        for u in (target_profile or {}).get("allow_listed_base_urls", [])
        if isinstance(u, str) and (u.startswith("http://127.0.0.1") or u.startswith("http://localhost"))
    ]
    operator_approved = bool((target_profile or {}).get("operator_approved") is True and allow_urls)
    if not operator_approved:
        updated["execution_status"] = "not_executed"
        for req in updated.get("requests", []):
            if isinstance(req, dict):
                req["executed"] = False
                req["observation"] = None
        updated["blocked_reason"] = (
            "No operator-approved allow-listed localhost target profile configured; "
            "preserving request sequence as plan_only / not_executed."
        )
        return updated

    allow_state_change = bool((target_profile or {}).get("allow_state_change") is True)
    for req in updated.get("requests", []):
        if not isinstance(req, dict):
            continue
        method = str(req.get("method", "GET")).upper()
        url = str(req.get("url_or_path", ""))
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not allow_state_change:
            req["executed"] = False
            req["observation"] = None
            updated["execution_status"] = "blocked"
            updated["blocked_reason"] = f"State-changing method {method} blocked because allow_state_change is False."
            return updated
        if url.startswith("http://") or url.startswith("https://"):
            if not any(url.startswith(base) for base in allow_urls):
                req["executed"] = False
                req["observation"] = None
                updated["execution_status"] = "blocked"
                updated["blocked_reason"] = f"Target URL {url!r} is outside allow_listed_base_urls."
                return updated
    return updated


def _select_cross_repo_evidence(repo_results: list[dict[str, Any]], sys_evidence: dict[str, dict[str, Any]], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Select cited evidence Round-Robin across all repositories so early repos are never starved by later repos."""
    per_repo_queues: list[list[str]] = []
    for result in repo_results:
        ai = result.get("ai", {})
        # Prioritize boundary-relevant skills (dataflow & api_authz) first, then threat_model, architecture_review, repo_profile.
        priority_ids: list[str] = []
        seen: set[str] = set()
        for skill in ("dataflow", "api_authz", "threat_model", "architecture_review", "repo_profile"):
            skill_res = ai.get(skill, {}).get("result")
            for eid in sorted(_walk_evidence_ids(skill_res)):
                if eid in sys_evidence and eid not in seen:
                    seen.add(eid)
                    priority_ids.append(eid)
        if priority_ids:
            per_repo_queues.append(priority_ids)

    analysis_cfg = cfg.get("analysis", {})
    base_cap = int(analysis_cfg.get("max_evidence_context_records", 55))
    sys_cap = int(analysis_cfg.get("max_system_evidence_records", max(base_cap, min(len(repo_results) * 4, 165))))
    excerpt_chars = int(analysis_cfg.get("max_evidence_excerpt_chars", 1800))

    selected_ids: list[str] = []
    idx = 0
    while len(selected_ids) < sys_cap and any(idx < len(q) for q in per_repo_queues):
        for q in per_repo_queues:
            if idx < len(q) and len(selected_ids) < sys_cap:
                selected_ids.append(q[idx])
        idx += 1

    sys_catalog = []
    for eid in selected_ids:
        rec = sys_evidence[eid]
        sys_catalog.append(
            {k: rec[k] for k in ("evidence_id", "repo_name", "path", "line_start", "line_end", "excerpt_sha256", "redaction_applied")}
            | {"excerpt": rec["excerpt"][:excerpt_chars]}
        )
    return sys_catalog


def analyze_repositories(repos: list[str | Path], *, cfg: dict[str, Any], output_dir: str | Path | None = None, work_dir: str | Path | None = None, use_llm: bool = True) -> dict[str, Any]:
    if not use_llm:
        raise ValueError("AI-only mode requires a local model; static-only analysis has been deliberately removed")
    output_root = Path(output_dir or cfg.get("analysis", {}).get("output_dir", "documents")).expanduser().resolve()
    work_root = Path(work_dir or cfg.get("analysis", {}).get("work_dir", ".localsec")).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
    run_root = work_root / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    run_log = run_root / "run_log.jsonl"

    llm_config = dict(cfg.get("llm", {}))
    client = OpenAICompatibleLocalClient(llm_config)
    ok, message = client.probe()
    if not ok:
        raise LocalModelError(f"Configured local model endpoint is not available: {message}")

    registry = load_registry()
    repo_results: list[dict[str, Any]] = []
    used_names: set[str] = set()
    _log_event(run_log, "run_started", run_id=run_id, analysis_mode="ai_manual_file_reading", repo_count=len(repos), model=client.model)

    for repo_arg in repos:
        repo_path = Path(repo_arg).expanduser().resolve(strict=True)
        if not repo_path.is_dir():
            raise ValueError(f"Repository is not a directory: {repo_path}")
        repo_name = repo_path.name
        safe_name = _safe_name(repo_name)
        if safe_name in used_names:
            raise ValueError(f"Repository output name collision for {repo_name!r}; pass uniquely named directories")
        used_names.add(safe_name)
        workspace = ManualWorkspace(repo_path, safe_name, cfg.get("analysis", {}), run_id)
        repo_run_dir = run_root / safe_name
        repo_run_dir.mkdir(parents=True, exist_ok=True)
        ai: dict[str, Any] = {}
        _log_event(run_log, "repo_started", run_id=run_id, repo_name=safe_name)

        for skill in SPECIALIST_ORDER:
            context = _skill_context(skill, ai, workspace, workspace.coverage(), cfg)
            spec = registry["skills"][skill]
            job_spec = {
                "job_id": uuid.uuid4().hex,
                "run_id": run_id,
                "repo_name": safe_name,
                "objective": spec["purpose"],
                "fixed_skill_order": registry["orchestration_policy"]["workflow_order"],
                "repository_path_exposure": "relative paths only; absolute path is withheld from the model",
                "read_scope": spec["read_scope"],
                "maximum_tool_calls": int(cfg.get("analysis", {}).get("max_total_tool_calls_per_skill", 40)),
                "output_schema": spec["schema"],
                "evidence_policy": "observed/derived claims require valid evidence IDs from excerpts actually returned to this session",
            }
            _log_event(run_log, "skill_started", run_id=run_id, repo_name=safe_name, skill=skill, job_id=job_spec["job_id"])
            result = run_skill(
                client=client,
                skill=skill,
                job_spec=job_spec,
                context=context,
                workspace=workspace,
                cfg=cfg,
                allowed_context_evidence_ids={entry["evidence_id"] for entry in context.get("available_evidence", [])},
            )
            ai[skill] = result
            write_json(repo_run_dir / f"{skill}.json", result)
            _log_event(run_log, "skill_finished", run_id=run_id, repo_name=safe_name, skill=skill, status=result["status"], tool_calls=result["tool_calls"], model_turns=result["model_turns"], warning_count=len(result["warnings"]), system_prompt_sha256=result.get("system_prompt_sha256"), initial_payload_sha256=result.get("initial_payload_sha256"))

        all_repo_claims: list[dict[str, Any]] = []
        for skill in SPECIALIST_ORDER:
            entry = ai.get(skill, {})
            if entry.get("status") == "ok" and isinstance(entry.get("result"), dict):
                all_repo_claims.extend(_iter_claims(entry["result"], skill))

        audit_result = _run_batched_evidence_audit(
            client=client,
            all_claims=all_repo_claims,
            evidence_lookup=workspace.evidence,
            cfg=cfg,
            run_id=run_id,
            repo_name=safe_name,
            objective=registry["skills"]["evidence_auditor"]["purpose"],
        )
        ai["evidence_auditor"] = audit_result
        write_json(repo_run_dir / "evidence_auditor.json", audit_result)
        _log_event(run_log, "skill_finished", run_id=run_id, repo_name=safe_name, skill="evidence_auditor", status=audit_result.get("status"), tool_calls=audit_result.get("tool_calls"), model_turns=audit_result.get("model_turns"), system_prompt_sha256=audit_result.get("system_prompt_sha256"), initial_payload_sha256=audit_result.get("initial_payload_sha256"))
        if audit_result.get("status") == "ok" and isinstance(audit_result.get("result"), dict):
            _apply_audit(ai, audit_result)

        coverage = workspace.coverage()
        coverage["skills"] = {name: {"status": item.get("status"), "tool_calls": item.get("tool_calls"), "model_turns": item.get("model_turns"), "warnings": item.get("warnings", [])} for name, item in ai.items()}
        coverage["budget_exhaustions"] = [f"{name}: {warning}" for name, item in ai.items() for warning in item.get("warnings", []) if "budget_exhausted" in warning]
        coverage["workflow_status"] = "completed" if all(ai.get(name, {}).get("status") == "ok" for name in SPECIALIST_ORDER + ["evidence_auditor"]) else "partial"
        coverage["security_posture"] = "undetermined_by_design"
        coverage["important_limitations"] = [
            "AI chose which paths and line ranges to read; unvisited code may contain relevant behavior.",
            "No AST/IR, parser, grep, SAST, compiler, shell or runtime analysis was used.",
            "Evidence auditing is an independent AI critique, not formal proof.",
            "Deployment, gateway, IAM, runtime service discovery and external contracts may be outside this repo.",
        ]
        repo_result = {"repo_name": safe_name, "run_id": run_id, "ai": ai, "coverage": coverage, "evidence": list(workspace.evidence.values()), "workspace_tool_log": workspace.tool_log}
        repo_results.append(repo_result)
        write_repo_documents(output_root / safe_name, repo_run_dir, repo_result)
        write_json(repo_run_dir / "evidence_index.json", list(workspace.evidence.values()))
        write_json(repo_run_dir / "coverage.json", coverage)
        write_json(repo_run_dir / "workspace_tool_log.json", workspace.tool_log)
        _log_event(run_log, "repo_finished", run_id=run_id, repo_name=safe_name, status=coverage["workflow_status"], inspected_files=coverage["unique_files_read"], evidence_count=coverage["evidence_count"])

    # System synthesis uses Boundary Projection (omitting raw per-claim audit logs since _apply_audit already updated statuses in place).
    system_context_base = {
        "repositories": [
            {
                "repo_name": result["repo_name"],
                "coverage": {
                    "workflow_status": result["coverage"].get("workflow_status"),
                    "unique_files_read_count": len(result["coverage"].get("unique_files_read", [])),
                    "evidence_count": result["coverage"].get("evidence_count", 0),
                },
                "profile": result["ai"].get("repo_profile", {}).get("result"),
                "api_authz": result["ai"].get("api_authz", {}).get("result"),
                "dataflow": result["ai"].get("dataflow", {}).get("result"),
                "threat_model": result["ai"].get("threat_model", {}).get("result"),
                "architecture_review": result["ai"].get("architecture_review", {}).get("result"),
            }
            for result in repo_results
        ],
        "coverage_note": "Each repo was reviewed by model-guided, manually selected file reads. Treat unvisited files and non-repository config as unknown.",
    }
    sys_evidence: dict[str, dict[str, Any]] = {}
    for result in repo_results:
        for record in result["evidence"]:
            sys_evidence[record["evidence_id"]] = record

    sys_catalog = _select_cross_repo_evidence(repo_results, sys_evidence, cfg)
    system_context = {"system_review_input": _compact(system_context_base), "available_evidence": sys_catalog}
    cross_job = {"job_id": uuid.uuid4().hex, "run_id": run_id, "repo_name": "_system", "objective": registry["skills"]["cross_repo_review"]["purpose"], "output_schema": "cross_repo_review.schema.json", "maximum_tool_calls": 0, "read_scope": "none"}
    cross = run_skill(client=client, skill="cross_repo_review", job_spec=cross_job, context=system_context, workspace=None, cfg=cfg, allowed_context_evidence_ids={r["evidence_id"] for r in sys_catalog})

    all_sys_audit_claims = _iter_claims(cross.get("result") or {}, "cross_repo_review") if cross.get("status") == "ok" else []
    sys_audit = _run_batched_evidence_audit(
        client=client,
        all_claims=all_sys_audit_claims,
        evidence_lookup=sys_evidence,
        cfg=cfg,
        run_id=run_id,
        repo_name="_system",
        objective="Audit the cross-repository review claims",
    )
    if sys_audit.get("status") == "ok" and isinstance(cross.get("result"), dict):
        temporary = {"cross_repo_review": cross}
        _apply_audit(temporary, sys_audit)
        cross = temporary["cross_repo_review"]

    diagram_input = {"repositories": [{"repo_name": r["repo_name"], "profile": r["ai"].get("repo_profile", {}).get("result"), "dataflow": r["ai"].get("dataflow", {}).get("result")} for r in repo_results], "cross_repo_review": cross.get("result"), "available_evidence": sys_catalog}
    diagrams = run_skill(client=client, skill="diagram_author", job_spec={"job_id": uuid.uuid4().hex, "run_id": run_id, "repo_name": "_system", "objective": registry["skills"]["diagram_author"]["purpose"], "output_schema": "diagrams.schema.json", "maximum_tool_calls": 0, "read_scope": "none"}, context=diagram_input, workspace=None, cfg=cfg, allowed_context_evidence_ids={r["evidence_id"] for r in sys_catalog})

    write_cross_repo_documents(output_root / "_system", cross, sys_audit, diagrams, repo_results)
    write_json(run_root / "cross_repo_review.json", cross)
    write_json(run_root / "cross_repo_evidence_audit.json", sys_audit)
    write_json(run_root / "diagrams.json", diagrams)
    write_json(run_root / "system_evidence_index.json", sys_catalog)

    required_system_jobs = [cross, sys_audit, diagrams]
    workflow_status = "completed" if all(x.get("status") == "ok" for x in required_system_jobs) and all(r["coverage"]["workflow_status"] == "completed" for r in repo_results) else "partial"
    system_coverage = {
        "run_id": run_id,
        "analysis_mode": "ai_manual_file_reading",
        "workflow_status": workflow_status,
        "coverage_status": "bounded_manual_review",
        "security_posture": "undetermined_by_design",
        "exhaustive_repository_scan": False,
        "llm": {"model": client.model, "endpoint_kind": "loopback_or_explicitly_allowed", "probe": message},
        "repos": [{"repo_name": r["repo_name"], "workflow_status": r["coverage"]["workflow_status"], "unique_files_read": len(r["coverage"]["unique_files_read"]), "evidence_count": r["coverage"]["evidence_count"], "skill_status": {k: v.get("status") for k, v in r["ai"].items()}} for r in repo_results],
        "cross_repo_review_status": cross.get("status"),
        "cross_repo_evidence_audit_status": sys_audit.get("status"),
        "diagram_author_status": diagrams.get("status"),
        "limitations": ["The AI-selected file reads are not exhaustive.", "No static analysis tools, AST/IR parsing, shell commands, builds, or runtime tests were used.", "A completed workflow is not a security clearance or confirmation that there are no vulnerabilities."],
    }
    write_json(output_root / "_system" / "04_system_coverage.json", system_coverage)
    write_json(run_root / "system_coverage.json", system_coverage)
    _log_event(run_log, "run_finished", run_id=run_id, workflow_status=workflow_status, cross_repo_status=cross.get("status"), evidence_audit_status=sys_audit.get("status"), diagram_status=diagrams.get("status"))
    return {"run_id": run_id, "output_dir": str(output_root), "work_dir": str(work_root), "system_coverage": system_coverage}


def build_coverage_id(
    surface: str,
    boundary: str,
    subsystem: str,
    attack_class: str,
    lifecycle: str | None = None,
) -> str:
    """Build canonical RFC 3986 percent-encoded 4-or-5 segment coverage_id."""
    from urllib.parse import quote

    parts = [surface, boundary, subsystem, attack_class]
    if lifecycle is not None and str(lifecycle).strip():
        parts.append(str(lifecycle))
    encoded: list[str] = []
    for p in parts:
        clean = str(p).strip()
        if not clean:
            raise ValueError("coverage_id segment cannot be empty")
        encoded.append(quote(clean, safe="-._~"))
    return "::".join(encoded)


def run_tailored_extractor_safely(
    *,
    repo_root: Path,
    mode: str = "USE_STANDARD_EXTRACTOR",
    canary_files: list[str] | None = None,
    custom_patterns: list[dict[str, str]] | None = None,
    patterns_file: str | Path | None = None,
    expected_canary_hits: int = 1,
    target_modules: list[str] | None = None,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    """Phase 1.2 (phase-1-extractor-tailor) helper:
    Runs standard or AI-tailored structural regex/route hints ONLY after verifying against canary_files.
    Enforces ManualWorkspace path, symlink, extension, redaction, and sanitization invariants (BUG-05)
    and scans target_modules once canary verification succeeds (BUG-06).
    Never acts as a standalone SAST tool or ground-truth denominator.
    """
    repo_root = Path(repo_root).expanduser().resolve()
    if mode == "SKIP_EXTRACTOR_DIRECT_READ":
        return {
            "mode": mode,
            "canary_files": canary_files or [],
            "canary_verified": True,
            "extracted_hints": [],
            "target_module_hints": [],
            "target_module_hits_count": 0,
            "note": "Extractor intentionally skipped; AI will perform 100% direct manual reading.",
        }

    canary_list = [c.strip() for c in (canary_files or []) if isinstance(c, str) and c.strip()]
    if not canary_list:
        return {
            "mode": mode,
            "canary_files": [],
            "canary_verified": False,
            "extracted_hints": [],
            "target_module_hints": [],
            "target_module_hits_count": 0,
            "error": "canary_files must be non-empty when running a standard or tailored extractor",
        }

    loaded_patterns: list[dict[str, str]] = list(custom_patterns or [])
    if patterns_file is not None:
        pf = Path(patterns_file).expanduser()
        if not pf.is_file():
            return {
                "mode": mode,
                "canary_files": canary_list,
                "canary_verified": False,
                "extracted_hints": [],
                "target_module_hints": [],
                "target_module_hits_count": 0,
                "error": f"patterns_file does not exist: {patterns_file}",
            }
        try:
            raw_pf = json.loads(pf.read_text(encoding="utf-8", errors="replace"))
            if isinstance(raw_pf, list):
                loaded_patterns = [p for p in raw_pf if isinstance(p, dict) and "regex" in p]
            elif isinstance(raw_pf, dict):
                cand_list = raw_pf.get("patterns") or raw_pf.get("custom_patterns") or []
                if isinstance(cand_list, list):
                    loaded_patterns = [p for p in cand_list if isinstance(p, dict) and "regex" in p]
        except Exception as exc:
            return {
                "mode": mode,
                "canary_files": canary_list,
                "canary_verified": False,
                "extracted_hints": [],
                "target_module_hints": [],
                "target_module_hits_count": 0,
                "error": f"failed to parse patterns_file: {exc}",
            }

    default_patterns = [
        {"name": "decorator_route", "regex": r"@(?:app|router|api|bp|GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|HttpGet|HttpPost|Get|Post|Put|Delete|on\(Action\.)[^\n]*"},
        {"name": "express_or_gin_route", "regex": r"\b(?:app|router|r|group|v1|v2)\.(?:get|post|put|delete|patch|use|handle|HandleFunc|POST|GET|PUT|DELETE)\s*\([^\n]*"},
        {"name": "grpc_or_mq_consumer", "regex": r"\b(?:rpc\s+\w+|@KafkaListener|@RabbitListener|zmq_recv|on_message|subscribe)\b[^\n]*"},
    ]
    active_patterns = loaded_patterns if (loaded_patterns and (mode == "TAILOR_CUSTOM_EXTRACTOR" or patterns_file is not None)) else default_patterns
    compiled = [(p.get("name", "hint"), re.compile(p["regex"])) for p in active_patterns if "regex" in p]

    max_file_bytes = 2_000_000

    def _safe_resolve_and_check(rel_path: str) -> tuple[str, Path] | None:
        clean_rel = ManualWorkspace._clean_relative(rel_path)
        if clean_rel == ".":
            return None
        cur = repo_root
        for part in clean_rel.split("/"):
            cur = cur / part
            if ManualWorkspace._is_symlink_or_junction(cur):
                raise WorkspaceError(f"symlink/reparse paths are not readable: {rel_path}")
        try:
            resolved = cur.resolve(strict=True)
        except OSError:
            return None
        if not resolved.is_relative_to(repo_root):
            raise WorkspaceError(f"path escapes repository root: {rel_path}")
        if not resolved.is_file():
            return None
        if resolved.suffix.lower() in DISALLOWED_EXTENSIONS or ManualWorkspace._is_cert_or_key(resolved):
            raise WorkspaceError(f"disallowed binary/certificate/secret file extension: {rel_path}")
        if ManualWorkspace._is_generated_or_lockfile(resolved) or not ManualWorkspace._is_text_candidate(resolved):
            return None
        try:
            if resolved.stat().st_size > max_file_bytes:
                return None
        except OSError:
            return None
        return clean_rel, resolved

    def _scan_file(rel_path: str, strict_security: bool = False) -> list[dict[str, Any]]:
        try:
            checked = _safe_resolve_and_check(rel_path)
        except WorkspaceError:
            if strict_security:
                raise
            return []
        if checked is None:
            return []
        clean_rel, fpath = checked
        try:
            raw_bytes = fpath.read_bytes()
            if b"\x00" in raw_bytes[:8192]:
                return []
            text = raw_bytes.decode("utf-8", errors="replace")
        except OSError:
            return []
        hits: list[dict[str, Any]] = []
        raw_lines = text.splitlines()
        sanitized_lines = ManualWorkspace._sanitize_untrusted_source_lines(raw_lines)
        redacted_lines = ManualWorkspace._redact_text_lines(sanitized_lines)
        for line_no, (orig_line, safe_line) in enumerate(zip(raw_lines, redacted_lines), 1):
            for pat_name, creg in compiled:
                if creg.search(orig_line):
                    hits.append({
                        "path": clean_rel,
                        "line": line_no,
                        "pattern": pat_name,
                        "snippet": str(safe_line).strip()[:180],
                    })
        return hits

    canary_hits: list[dict[str, Any]] = []
    for cfile in canary_list:
        canary_hits.extend(_scan_file(cfile, strict_security=True))

    min_hits = max(1, int(expected_canary_hits or 1))
    if len(canary_hits) < min_hits:
        err_msg = (
            "Extractor returned 0 matches on canary_files; refusing to run on repo to prevent SAST false-negative anchoring bias. Tailor patterns or use SKIP_EXTRACTOR_DIRECT_READ."
            if len(canary_hits) == 0
            else f"Extractor returned {len(canary_hits)} matches on canary_files (expected >= {min_hits}, 0 matches on canary_files threshold not met); refusing to run on repo."
        )
        return {
            "mode": mode,
            "canary_files": canary_list,
            "canary_verified": False,
            "canary_hit_count": len(canary_hits),
            "expected_canary_hits": min_hits,
            "extracted_hints": [],
            "target_module_hints": [],
            "target_module_hits_count": 0,
            "error": err_msg,
        }

    # Resolve target_modules from argument or run_dir/codebase_scout.json
    effective_target_modules: list[str] = []
    if target_modules:
        effective_target_modules = [str(m).strip().strip("/") for m in target_modules if str(m).strip()]
    elif run_dir is not None and (Path(run_dir) / "codebase_scout.json").is_file():
        try:
            scout_payload = json.loads((Path(run_dir) / "codebase_scout.json").read_text(encoding="utf-8", errors="replace"))
            scout_res = scout_payload.get("result", scout_payload) if isinstance(scout_payload, dict) else {}
            for item in scout_res.get("target_modules", []):
                if isinstance(item, str) and item.strip():
                    effective_target_modules.append(item.strip().strip("/"))
                elif isinstance(item, dict) and str(item.get("path", "")).strip():
                    effective_target_modules.append(str(item["path"]).strip().strip("/"))
        except Exception:
            effective_target_modules = []

    ignored_dir_names = {
        ".git", ".hg", ".svn", ".localsec", ".venv", "venv", "node_modules", "vendor",
        "dist", "build", "target", "bin", "obj", "__pycache__", ".pytest_cache", ".mypy_cache",
    }
    target_module_hints: list[dict[str, Any]] = []
    seen_files: set[str] = set()

    def _walk_dir(base_dir: Path) -> None:
        if not base_dir.exists():
            return
        if base_dir.is_file():
            try:
                rel_p = base_dir.relative_to(repo_root).as_posix()
            except ValueError:
                return
            if rel_p not in seen_files:
                seen_files.add(rel_p)
                target_module_hints.extend(_scan_file(rel_p, strict_security=False))
            return
        for child in sorted(base_dir.rglob("*")):
            try:
                rel_parts = child.relative_to(repo_root).parts
            except ValueError:
                continue
            if any(part in ignored_dir_names for part in rel_parts):
                continue
            if child.is_symlink() or not child.is_file():
                continue
            rel_p = child.relative_to(repo_root).as_posix()
            if rel_p in seen_files:
                continue
            seen_files.add(rel_p)
            target_module_hints.extend(_scan_file(rel_p, strict_security=False))

    if effective_target_modules:
        for mod in effective_target_modules:
            try:
                clean_mod = ManualWorkspace._clean_relative(mod)
            except WorkspaceError:
                continue
            _walk_dir(repo_root if clean_mod == "." else (repo_root / clean_mod))
    else:
        _walk_dir(repo_root)

    # Combine canary hits first (preserving order for existing callers) with deduplicated target module hits
    combined_hints: list[dict[str, Any]] = list(canary_hits)
    seen_hit_keys = {(h["path"], h["line"], h["pattern"]) for h in canary_hits}
    for th in target_module_hints:
        key = (th["path"], th["line"], th["pattern"])
        if key not in seen_hit_keys:
            seen_hit_keys.add(key)
            combined_hints.append(th)

    return {
        "mode": mode,
        "canary_files": canary_list,
        "canary_verified": True,
        "canary_hit_count": len(canary_hits),
        "expected_canary_hits": min_hits,
        "target_modules_scanned": effective_target_modules,
        "target_module_hits_count": len(target_module_hints),
        "target_module_hints": target_module_hints,
        "extracted_hints": combined_hints,
    }


VALID_IGNORED_MODULE_REASONS = {
    "test_or_mock",
    "generated_code",
    "third_party_vendor",
    "deprecated_dead_code",
    "docs_or_assets",
}

HIGH_ENTROPY_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|client_secret|api[_-]?key|access[_-]?token|private[_-]?key|jwt[_-]?secret|signing[_-]?key)\b"
    r"\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-!@#$%^&*]{12,})[\"']"
)
RAW_TOKEN_LEAD_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{12,})\b"
)
PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

DEPENDENCY_MANIFEST_NAMES = {
    "package.json": "npm",
    "go.mod": "golang",
    "requirements.txt": "pypi",
    "pyproject.toml": "pypi",
    "pipfile": "pypi",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "cargo.toml": "cargo",
    "composer.json": "composer",
    "gemfile": "rubygems",
    "pubspec.yaml": "pub",
}


CONTENT_ENTRYPOINT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("decorator_route", re.compile(r"@(?:app|router|api|bp|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|HttpGet|HttpPost|HttpPut|HttpDelete|GrpcService|Mutation|Query)\b")),
    ("nestjs_controller_or_route", re.compile(r"@Controller\s*\(|@(?:Get|Post|Put|Delete|Patch)\s*\(")),
    ("go_http_router", re.compile(r"\b(?:r|router|group|e|mux)\.(?:GET|POST|PUT|DELETE|PATCH|Use)\s*\(")),
    ("dotnet_endpoint", re.compile(r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\b|\bMap(?:Get|Post|Put|Delete|Patch|GrpcService)\s*\(")),
    ("queue_consumer", re.compile(r"@(?:KafkaListener|RabbitListener|SqsListener|EventPattern|MessagePattern)\s*\(|\b(?:celery\.task|shared_task)\b")),
    ("scheduler_or_cron", re.compile(r"@(?:Scheduled|Cron)\s*\(|\b(?:cron\.schedule|APScheduler|BackgroundScheduler)\b")),
    ("spring_scheduled_or_listener", re.compile(r"@Scheduled\s*\(|@KafkaListener\s*\(|@RabbitListener\s*\(")),
    ("webhook_handler", re.compile(r"['\"][^'\"]*webhook[^'\"]*['\"]|\b(?:handle_webhook|verify_webhook|webhook_receiver)\b", re.IGNORECASE)),
    ("aws_lambda_handler", re.compile(r"def\s+lambda_handler\s*\(|exports\.handler\s*=|@click\.command|\bargparse\.ArgumentParser\b|\bcobra\.Command\b")),
    ("ocpp_action", re.compile(r"@on\(\s*Action\.|\bon_(?:boot_notification|remote_start_transaction|remote_stop_transaction|start_transaction|stop_transaction|authorize|meter_values)\b")),
    ("router_call", re.compile(r"\b(?:router|app|r|mux|server)\.(?:get|post|put|delete|patch|use|HandleFunc|Register\w*Server)\s*\(")),
    ("zmq_or_ipc", re.compile(r"#include\s*<zmq\.h>|\bzmq_(?:recv|msg_recv|bind|connect)\b|\bhandle_zmq_frame\b")),
    ("ros2_node", re.compile(r"\b(?:create_subscription|create_service|create_action_server)\b")),
    ("mobile_bridge", re.compile(r"\bMethodChannel\s*\(|\bCFBundleURLSchemes\b|android:exported\s*=\s*\"true\"|<intent-filter")),
    ("enterprise_ot_listener", re.compile(r"\bFUNCTION\s+Z\w+|\bRFC_\w+|<http:listener|\b(?:modbus|opcua|iec61850|dnp3)\b", re.IGNORECASE)),
    # MCP / LLM tool handlers: arguments are chosen by the model (and by prompt injection), so each tool is an entrypoint
    ("mcp_or_llm_tool", re.compile(r"\.register(?:Tool|Resource|Prompt)\s*\(|\bserver\.tool\s*\(|setRequestHandler\s*\(\s*(?:CallToolRequestSchema|ReadResourceRequestSchema)|@mcp\.(?:tool|resource)\b|\bFastMCP\s*\(")),
    ("js_route_handler_export", re.compile(r"\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\(|\bexport\s+default\s+(?:async\s+)?function\s+handler\s*\(")),
    ("js_queue_worker", re.compile(r"\bnew\s+Worker\s*\(\s*['\"]|\bchannel\.consume\s*\(|\bconsumer\.run\s*\(|\.subscribe\s*\(\s*\{\s*topic")),
]

CONTENT_SECURITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jwt_or_token_verify", re.compile(r"\b(?:jwt\.decode|jwt\.verify|verify_token|require_jwt|validate_token|parse_token|Bearer\s)\b")),
    ("authz_guard", re.compile(r"\b(?:authorize|check_permission|has_permission|require_role|UseGuards|SecurityFilterChain|PreAuthorize|CanActivate|Depends\s*\(\s*(?:get_current_user|require_))\b|@(?:require_role|UseGuards|PreAuthorize|RolesAllowed|InternalServiceOnly)\b")),
    ("framework_auth_decorator", re.compile(r"@UseGuards\s*\(|\[Authorize\b|\[AllowAnonymous\b")),
    ("crypto_or_hmac", re.compile(r"\b(?:hmac\.new|hmac\.compare_digest|crypto\.createHmac|bcrypt\.|argon2\.| pbkdf2)\b")),
    ("safety_interlock", re.compile(r"\b(?:check_interlock|safety_interlock|emergency_stop|verify_contactor_safe)\b")),
]

GENERIC_NON_SIGNAL_STEMS = {
    "main", "app", "server", "program", "startup", "index",
    "session", "token", "policy", "config", "settings", "utils", "helpers", "common", "types",
}


def _is_test_or_generated_path(rel_path: str, stem: str, suffix: str, parts_lower: list[str]) -> bool:
    lower_rel = rel_path.lower()
    if any(
        p in {
            "tests", "test", "__tests__", "spec", "specs", "mocks", "mock",
            "fixtures", "vendor", "node_modules", "third_party", "generated", "gen",
        }
        for p in parts_lower
    ):
        return True
    if (
        stem.startswith("test_")
        or stem.endswith(("_test", ".test", ".spec", "_spec", "_mock", ".mock", "_pb2", "_pb2_grpc"))
        or lower_rel.endswith((".spec.ts", ".test.ts", ".spec.js", ".test.js", ".pb.go", ".g.dart", ".freezed.dart"))
    ):
        return True
    return False


def _classify_inventory_file_with_signals(
    rel_path: str,
    stem: str,
    suffix: str,
    parts_lower: list[str],
    sample_text: str,
) -> tuple[list[str], list[str]]:
    """Classify a file into mandatory inventory buckets using content signals first, returning (categories, matched_signals[:3])."""
    categories: list[str] = []
    signals: list[str] = []
    lower_rel = rel_path.lower()
    lower_sample = sample_text.lower()

    # 1. Entrypoint: require content signals or explicit controller/router/handler/ocpp/vla/ros2 path/stem (never generic main/app/server/program alone)
    ep_signals: list[str] = []
    for sig_name, pat in CONTENT_ENTRYPOINT_PATTERNS:
        m = pat.search(sample_text)
        if m:
            snippet = m.group(0).strip()[:60]
            ep_signals.append(f"content:{sig_name}:{snippet}")
            if len(ep_signals) >= 3:
                break
    specific_ep_stem = any(
        tok in stem
        for tok in ("controller", "router", "route", "handler", "consumer", "endpoint", "webhook", "zmq_bridge")
    ) and stem not in GENERIC_NON_SIGNAL_STEMS
    specific_ep_dir = any(
        p in {"controllers", "controller", "routes", "routers", "handlers", "consumers", "endpoints", "webhooks", "ocpp", "vla", "ros2"}
        for p in parts_lower
    ) and stem not in GENERIC_NON_SIGNAL_STEMS
    if (ep_signals or specific_ep_stem or specific_ep_dir or lower_rel.endswith((".launch.py", ".launch.xml", "androidmanifest.xml", "info.plist"))) and (
        suffix not in {".md", ".txt", ".json", ".yaml", ".yml", ".lock"}
        or lower_rel.endswith(("androidmanifest.xml", "info.plist", ".launch.xml"))
    ):
        categories.append("entrypoint")
        if ep_signals:
            signals.extend(ep_signals[:3])
        else:
            signals.append(f"structural_entrypoint:{rel_path}")

    # 2. Security: require content signals or explicit auth/guard/rbac/security/interlock stem/dir (never generic session/token/policy alone)
    sec_signals: list[str] = []
    for sig_name, pat in CONTENT_SECURITY_PATTERNS:
        m = pat.search(sample_text)
        if m:
            snippet = m.group(0).strip()[:60]
            sec_signals.append(f"content:{sig_name}:{snippet}")
            if len(sec_signals) >= 3:
                break
    specific_sec_stem = any(
        tok in stem
        for tok in ("auth", "authn", "authz", "jwt", "guard", "middleware", "rbac", "permission", "crypto", "cipher", "signature", "hmac", "oauth", "acl", "security", "interlock", "safety")
    ) and stem not in GENERIC_NON_SIGNAL_STEMS
    specific_sec_dir = any(
        p in {"auth", "authn", "authz", "security", "guards", "guard", "middlewares", "middleware", "rbac", "acl", "crypto", "jwt", "oauth", "permissions"}
        for p in parts_lower
    ) and stem not in GENERIC_NON_SIGNAL_STEMS
    if (sec_signals or specific_sec_stem or specific_sec_dir) and suffix not in {".md", ".txt"}:
        categories.append("security")
        for s in (sec_signals or [f"structural_security:{rel_path}"]):
            if len(signals) < 3 and s not in signals:
                signals.append(s)

    # 3. Wiring / Config: narrow .yaml/.yml/.toml/.ini/.properties to files whose path or content indicates app/infra wiring
    wiring_path_tokens = (
        "docker", "compose", "dockerfile", "k8s", "kubernetes", "helm", "ingress",
        "gateway", "kong", "krakend", "nginx", "envoy", "appsettings", "application.",
        "config", "settings", "localsec", "manifest", "androidmanifest", "info.plist",
        "cors", "auth", "security",
    )
    wiring_content_tokens = (
        "server:", "spring:", "services:", "ingress:", "routes:", "endpoints:",
        "upstreams:", "plugins:", "cors", "jwt", "auth", "security", "listen ",
        "proxy_pass", "apiversion:",
    )
    if suffix in {".tf", ".hcl", ".conf", ".plist", ".entitlements", ".csproj"}:
        is_wiring = True
    elif suffix in {".yaml", ".yml", ".toml", ".ini", ".properties"}:
        is_wiring = (
            any(tok in lower_rel for tok in wiring_path_tokens)
            or any(tok in lower_sample for tok in wiring_content_tokens)
        )
    else:
        is_wiring = any(
            tok in lower_rel
            for tok in (
                "docker-compose", "dockerfile", "helm", "k8s", "kubernetes", "ingress",
                "gateway", "krakend", "kong", "nginx", "envoy", "appsettings",
                "androidmanifest", "info.plist", "cors",
            )
        )
    if is_wiring:
        categories.append("wiring_config")
        if len(signals) < 3:
            signals.append(f"wiring_config:{suffix or lower_rel}")

    # 4. Outbound
    is_outbound = (
        any(p in {"clients", "client", "adapters", "integrations", "producers", "publishers", "outbound"} for p in parts_lower)
        or any(tok in stem for tok in ("client", "producer", "publisher", "sender", "dispatcher", "gateway_client", "http_client", "webhook_sender"))
        or any(tok in lower_sample for tok in ("requests.post", "requests.get", "httpx.", "axios.", "fetch(", "http.newrequest", "grpc.dial", "kafka.producer", "publish("))
    )
    if is_outbound and suffix not in {".md", ".txt"}:
        categories.append("outbound")
        if len(signals) < 3:
            signals.append("outbound_call_or_client")

    # 5. Data Access: require SQL/ORM/DB content signals OR .sql/.prisma suffix OR migrations directory
    data_content_signals = (
        "select ", "insert ", "update ", "delete from", "create table",
        "@entity", "@table", "prisma.", "gorm.", "db.", "session.query",
        "repository<", "dbcontext", "redis.", "mongo", ".execute(",
        "sqlalchemy", "typeorm", "sequelize", "mongoose",
    )
    is_data = (
        suffix in {".sql", ".prisma"}
        or "migrations" in parts_lower
        or any(tok in lower_sample for tok in data_content_signals)
    )
    if is_data and suffix not in {".md", ".txt"}:
        categories.append("data_access")
        if len(signals) < 3:
            signals.append("data_access_or_schema")

    return categories, signals[:3]


def _classify_inventory_file(rel_path: str, stem: str, suffix: str, parts_lower: list[str], sample_text: str) -> list[str]:
    """Classify a file into mandatory inventory buckets: entrypoint, security, wiring_config, outbound, data_access."""
    cats, _ = _classify_inventory_file_with_signals(rel_path, stem, suffix, parts_lower, sample_text)
    return cats


def _redact_secret_preview(line: str) -> str:
    """Create a strictly redacted preview that never exposes raw secret values."""
    redacted = redact_text(line.strip())
    redacted = HIGH_ENTROPY_SECRET_RE.sub(r"\1=[REDACTED_SECRET_LEAD]", redacted)
    redacted = RAW_TOKEN_LEAD_RE.sub("[REDACTED_TOKEN_LEAD]", redacted)
    if PRIVATE_KEY_HEADER_RE.search(redacted):
        return "[REDACTED_PRIVATE_KEY_HEADER]"
    # Also redact any quoted string >= 10 chars after = or :
    redacted = re.sub(r"([:=]\s*[\"'])[^\"']{8,}([\"'])", r"\1[REDACTED]\2", redacted)
    return redacted[:160]


def _scan_external_tool_reports_detailed(
    project_root: Path,
    repo_root: Path,
    repo_name: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str], list[dict[str, Any]]]:
    """R3-A6 & R4-C5: Scan <project_root>/reports/ and <repo_root>/reports/ for *.sarif, *trivy*.json, *gitleaks*.json.
    Filters project-level reports by repo_name, extracts severity, groups CRITICAL/HIGH findings into
    external_tool_leads, places MEDIUM/LOW/INFO findings into deferred_external_tool_findings,
    and preserves project-level findings whose target cannot be mapped to any repo in unassigned_project_findings.
    Returns (external_tool_leads, deferred_external_tool_findings, flagged_manifest_paths, unassigned_project_findings).
    """
    eff_repo_name = (repo_name or repo_root.name).strip()
    other_repo_names: set[str] = set()
    if project_root != repo_root and project_root.is_dir():
        try:
            for d in project_root.iterdir():
                if (
                    d.is_dir()
                    and not d.name.startswith((".", "_"))
                    and d.name not in {"reports", "documents", "localsec", "schemas", "contracts", "tests"}
                    and d.name != eff_repo_name
                ):
                    other_repo_names.add(d.name)
        except OSError:
            pass

    def _classify_uri_for_repo(raw_uri: str, is_project_report: bool) -> tuple[str | None, bool]:
        """Return (resolved_uri_for_this_repo, is_unassigned_across_all_repos)."""
        loc_uri = raw_uri.strip().replace("\\", "/")
        if loc_uri.startswith("file://"):
            loc_uri = loc_uri[7:]
        loc_uri = loc_uri.lstrip("./")
        if eff_repo_name and loc_uri.startswith(f"{eff_repo_name}/"):
            return loc_uri[len(eff_repo_name) + 1:], False
        if not is_project_report:
            return loc_uri, False
        if not loc_uri:
            if not other_repo_names:
                return loc_uri, False
            return None, True
        if (repo_root / loc_uri).exists():
            return loc_uri, False
        first_seg = loc_uri.split("/", 1)[0]
        if first_seg in other_repo_names:
            return None, False
        for o_repo in other_repo_names:
            if (project_root / o_repo / loc_uri).exists():
                return None, False
        if ":" in loc_uri or "/" in loc_uri:
            if not (repo_root / first_seg).exists():
                return None, True
        if other_repo_names:
            return None, True
        return loc_uri, False

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    grouped_leads: dict[str, dict[str, Any]] = {}
    deferred_findings: list[dict[str, Any]] = []
    unassigned_findings: list[dict[str, Any]] = []
    flagged_manifests: set[str] = set()

    def _record_finding(
        *,
        tool: str,
        rule_id: str,
        title: str,
        path: str,
        line: int,
        report_file: str,
        severity: str,
        group_key: str,
        unassigned: bool = False,
    ) -> None:
        sev_u = severity.upper() if severity.upper() in sev_rank else "HIGH"
        if unassigned:
            unassigned_findings.append({
                "tool": tool,
                "rule_id": rule_id,
                "title": title[:200],
                "target": path,
                "line": line,
                "report_file": report_file,
                "severity": sev_u,
                "group_key": group_key,
            })
            return
        if tool in {"trivy", "sarif"} and path:
            flagged_manifests.add(path)
        if tool == "gitleaks" or sev_u in {"CRITICAL", "HIGH"}:
            if group_key not in grouped_leads:
                grouped_leads[group_key] = {
                    "tool": tool,
                    "rule_id": rule_id,
                    "title": title[:200],
                    "path": path,
                    "line": line,
                    "report_file": report_file,
                    "severity": sev_u,
                    "group_key": group_key,
                    "finding_count": 1,
                    "cve_ids": [rule_id] if rule_id else [],
                }
            else:
                grp = grouped_leads[group_key]
                grp["finding_count"] = int(grp.get("finding_count", 1)) + 1
                if rule_id and rule_id not in grp["cve_ids"]:
                    grp["cve_ids"].append(rule_id)
                if sev_rank.get(sev_u, 0) > sev_rank.get(str(grp.get("severity", "HIGH")), 0):
                    grp["severity"] = sev_u
        else:
            deferred_findings.append({
                "tool": tool,
                "rule_id": rule_id,
                "title": title[:200],
                "path": path,
                "line": line,
                "report_file": report_file,
                "severity": sev_u,
                "group_key": group_key,
            })

    report_dirs: list[tuple[Path, bool]] = []
    proj_reports = project_root / "reports"
    repo_reports = repo_root / "reports"
    if proj_reports.is_dir():
        report_dirs.append((proj_reports, proj_reports.resolve() != repo_reports.resolve()))
    if repo_reports.is_dir() and all(repo_reports.resolve() != d.resolve() for d, _ in report_dirs):
        report_dirs.append((repo_reports, False))

    for rdir, is_proj_report in report_dirs:
        try:
            files = sorted(rdir.rglob("*"))
        except OSError:
            continue
        for f in files:
            if not f.is_file():
                continue
            lname = f.name.lower()
            if not (lname.endswith(".sarif") or ("trivy" in lname and lname.endswith(".json")) or ("gitleaks" in lname and lname.endswith(".json"))):
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if lname.endswith(".sarif") and isinstance(data, dict):
                for run in data.get("runs", []):
                    if not isinstance(run, dict):
                        continue
                    rule_sev_map: dict[str, str] = {}
                    driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
                    if isinstance(driver, dict):
                        for r_def in driver.get("rules", []):
                            if isinstance(r_def, dict) and r_def.get("id"):
                                r_id_k = str(r_def["id"])
                                r_props = r_def.get("properties", {}) if isinstance(r_def.get("properties"), dict) else {}
                                r_def_cfg = r_def.get("defaultConfiguration", {}) if isinstance(r_def.get("defaultConfiguration"), dict) else {}
                                if r_props.get("security-severity") is not None:
                                    try:
                                        ss = float(r_props["security-severity"])
                                        rule_sev_map[r_id_k] = "CRITICAL" if ss >= 9.0 else ("HIGH" if ss >= 7.0 else ("MEDIUM" if ss >= 4.0 else "LOW"))
                                    except (ValueError, TypeError):
                                        pass
                                elif r_def_cfg.get("level"):
                                    lvl_s = str(r_def_cfg["level"]).lower()
                                    rule_sev_map[r_id_k] = "HIGH" if lvl_s == "error" else ("MEDIUM" if lvl_s == "warning" else "LOW")
                    for res in run.get("results", []):
                        if not isinstance(res, dict):
                            continue
                        rule_id = str(res.get("ruleId") or "SARIF_RULE")
                        msg = res.get("message", {})
                        text = str(msg.get("text") if isinstance(msg, dict) else msg or rule_id)
                        loc_uri = ""
                        start_line = 1
                        locs = res.get("locations", [])
                        if isinstance(locs, list) and locs and isinstance(locs[0], dict):
                            phys = locs[0].get("physicalLocation", {})
                            if isinstance(phys, dict):
                                art = phys.get("artifactLocation", {})
                                reg = phys.get("region", {})
                                if isinstance(art, dict):
                                    loc_uri = str(art.get("uri") or "")
                                if isinstance(reg, dict) and reg.get("startLine"):
                                    start_line = int(reg["startLine"])
                        resolved_uri, is_unassigned = _classify_uri_for_repo(loc_uri, is_proj_report)
                        if resolved_uri is None and not is_unassigned:
                            continue
                        props = res.get("properties", {}) if isinstance(res.get("properties"), dict) else {}
                        sarif_sev = ""
                        if props.get("security-severity") is not None:
                            try:
                                ss = float(props["security-severity"])
                                sarif_sev = "CRITICAL" if ss >= 9.0 else ("HIGH" if ss >= 7.0 else ("MEDIUM" if ss >= 4.0 else "LOW"))
                            except (ValueError, TypeError):
                                sarif_sev = ""
                        if not sarif_sev and str(props.get("severity") or res.get("severity") or "").upper() in sev_rank:
                            sarif_sev = str(props.get("severity") or res.get("severity")).upper()
                        if not sarif_sev and res.get("level"):
                            lvl = str(res.get("level")).strip().lower()
                            sarif_sev = "HIGH" if lvl == "error" else ("MEDIUM" if lvl == "warning" else ("LOW" if lvl == "note" else "INFO"))
                        if not sarif_sev:
                            sarif_sev = rule_sev_map.get(rule_id, "HIGH")
                        eff_path = resolved_uri if resolved_uri is not None else loc_uri
                        module_dir = "/".join(eff_path.split("/")[:-1]) if "/" in eff_path else "."
                        g_key = f"sarif:{rule_id}:{module_dir}"
                        _record_finding(
                            tool="sarif",
                            rule_id=rule_id,
                            title=text,
                            path=eff_path,
                            line=start_line,
                            report_file=f.name,
                            severity=sarif_sev,
                            group_key=g_key,
                            unassigned=is_unassigned,
                        )
            elif "trivy" in lname and isinstance(data, dict):
                for r_item in data.get("Results", data.get("results", [])):
                    if not isinstance(r_item, dict):
                        continue
                    target = str(r_item.get("Target") or r_item.get("target") or "")
                    resolved_target, is_unassigned = _classify_uri_for_repo(target, is_proj_report)
                    if resolved_target is None and not is_unassigned:
                        continue
                    eff_target = resolved_target if resolved_target is not None else target
                    for vuln in list(r_item.get("Vulnerabilities") or []) + list(r_item.get("Misconfigurations") or []):
                        if not isinstance(vuln, dict):
                            continue
                        vid = str(vuln.get("VulnerabilityID") or vuln.get("ID") or "TRIVY_FINDING")
                        vtitle = str(vuln.get("Title") or vuln.get("PkgName") or vid)
                        raw_sev = str(vuln.get("Severity") or vuln.get("severity") or "HIGH").strip().upper()
                        vsev = raw_sev if raw_sev in sev_rank else ("LOW" if raw_sev == "UNKNOWN" else "HIGH")
                        pkg_name = str(vuln.get("PkgName") or vuln.get("pkgName") or vuln.get("Type") or vid).strip()
                        installed_ver = str(vuln.get("InstalledVersion") or vuln.get("installedVersion") or "").strip()
                        g_key = f"trivy:{eff_target}:{pkg_name}@{installed_ver}"
                        _record_finding(
                            tool="trivy",
                            rule_id=vid,
                            title=vtitle,
                            path=eff_target,
                            line=1,
                            report_file=f.name,
                            severity=vsev,
                            group_key=g_key,
                            unassigned=is_unassigned,
                        )
            elif "gitleaks" in lname:
                items = data if isinstance(data, list) else (data.get("findings", []) if isinstance(data, dict) else [])
                if isinstance(items, list):
                    for g_idx, g_item in enumerate(items):
                        if not isinstance(g_item, dict):
                            continue
                        rid = str(g_item.get("RuleID") or g_item.get("rule_id") or "GITLEAKS_RULE")
                        desc = str(g_item.get("Description") or g_item.get("description") or rid)
                        gfile = str(g_item.get("File") or g_item.get("file") or "")
                        resolved_gfile, is_unassigned = _classify_uri_for_repo(gfile, is_proj_report)
                        if resolved_gfile is None and not is_unassigned:
                            continue
                        eff_gfile = resolved_gfile if resolved_gfile is not None else gfile
                        gline = int(g_item.get("StartLine") or g_item.get("line") or 1)
                        _record_finding(
                            tool="gitleaks",
                            rule_id=rid,
                            title=desc,
                            path=eff_gfile,
                            line=gline,
                            report_file=f.name,
                            severity="HIGH",
                            group_key=f"gitleaks:{rid}:{eff_gfile}:{gline}:{g_idx}",
                            unassigned=is_unassigned,
                        )
    return list(grouped_leads.values()), deferred_findings, flagged_manifests, unassigned_findings


def _scan_external_tool_reports(project_root: Path, repo_root: Path, repo_name: str = "") -> list[dict[str, Any]]:
    """Scan <project_root>/reports/ and <repo_root>/reports/ for *.sarif, *trivy*.json, *gitleaks*.json."""
    leads, _, _, _ = _scan_external_tool_reports_detailed(project_root, repo_root, repo_name=repo_name)
    return leads


def inventory_repo(
    project_root: Path,
    repo_name: str,
    run_id: str = "default",
    operator_tier: str | int | None = None,
) -> dict[str, Any]:
    """ARCH-3C, DEPTH-4.1e, DEPTH-4.3d, DEPTH-4.7:
    Deterministic pre-scout file tree & mandatory surface inventory.
    Walks repo_root respecting IGNORED_DIRS, DISALLOWED_EXTENSIONS, and MAX_FILE_BYTES,
    classifies mandatory_files (excluding test/mock/generated/vendor files),
    records mandatory_file_signals (<=3 snippets per file) and external_tool_leads,
    scans redacted secret leads & dependency manifests,
    and computes recommended_tier and tier_mismatch_warning.
    """
    project_root = Path(project_root).expanduser().resolve()
    candidate_repo = project_root / repo_name
    if candidate_repo.is_dir():
        repo_root = candidate_repo.resolve()
    elif project_root.name == repo_name and project_root.is_dir():
        repo_root = project_root
        project_root = repo_root.parent
    else:
        raise WorkspaceError(f"Repository directory not found for {repo_name!r} under {project_root}")

    ignored_dirs = {
        ".git", ".hg", ".svn", ".localsec", ".venv", "venv", "node_modules", "vendor",
        "dist", "build", "target", "bin", "obj", ".idea", ".vscode", "__pycache__",
        ".pytest_cache", ".mypy_cache", "coverage", ".next", ".nuxt",
    }
    max_file_bytes = 2_000_000

    mandatory_files: dict[str, list[str]] = {
        "entrypoint": [],
        "security": [],
        "wiring_config": [],
        "outbound": [],
        "data_access": [],
    }
    mandatory_file_signals: dict[str, list[str]] = {}
    excluded_test_or_generated_files: list[str] = []
    all_eligible_files: list[str] = []
    module_Readiness: dict[str, dict[str, Any]] = {}
    secret_leads: list[dict[str, Any]] = []
    dependency_manifests: list[dict[str, Any]] = []
    dependency_leads: list[dict[str, Any]] = []

    def _walk(curr_dir: Path) -> None:
        try:
            children = sorted(curr_dir.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            return
        for child in children:
            if ManualWorkspace._is_symlink_or_junction(child):
                continue
            if child.is_dir():
                if child.name in ignored_dirs:
                    continue
                _walk(child)
                continue
            if not child.is_file():
                continue
            try:
                rel_path = child.relative_to(repo_root).as_posix()
                fsize = child.stat().st_size
            except (OSError, ValueError):
                continue
            if fsize > max_file_bytes:
                continue
            lower_name = child.name.lower()
            suffix = child.suffix.lower()
            if suffix in DISALLOWED_EXTENSIONS or ManualWorkspace._is_cert_or_key(child):
                continue

            # Check dependency manifests before skipping lockfiles
            if lower_name in DEPENDENCY_MANIFEST_NAMES or suffix == ".csproj":
                ecosystem = DEPENDENCY_MANIFEST_NAMES.get(lower_name, "nuget" if suffix == ".csproj" else "unknown")
                dep_entry: dict[str, Any] = {
                    "path": rel_path,
                    "ecosystem": ecosystem,
                    "size_bytes": fsize,
                }
                dependency_manifests.append(dep_entry)
                dependency_leads.append({
                    "path": rel_path,
                    "line": 1,
                    "lead_type": f"dependency_manifest:{ecosystem}",
                    "ecosystem": ecosystem,
                })

            if ManualWorkspace._is_generated_or_lockfile(child):
                excluded_test_or_generated_files.append(rel_path)
                continue
            if not ManualWorkspace._is_text_candidate(child):
                continue

            parts = rel_path.split("/")
            parts_lower = [p.lower() for p in parts[:-1]]
            stem_lower = child.stem.lower()
            if _is_test_or_generated_path(rel_path, stem_lower, suffix, parts_lower):
                excluded_test_or_generated_files.append(rel_path)
                continue

            all_eligible_files.append(rel_path)
            top_mod = "/".join(parts[:-1]) if len(parts) > 1 else "."
            mod_entry = module_Readiness.setdefault(top_mod, {"path": top_mod, "file_count": 0, "entrypoint_count": 0, "security_count": 0})
            mod_entry["file_count"] += 1

            sample_text = ""
            try:
                raw_bytes = child.read_bytes()
                if b"\x00" not in raw_bytes[:4096]:
                    sample_text = raw_bytes[:32768].decode("utf-8", errors="replace")
            except OSError:
                sample_text = ""

            cats, sigs = _classify_inventory_file_with_signals(rel_path, stem_lower, suffix, parts_lower, sample_text)
            if cats:
                mandatory_file_signals[rel_path] = sigs[:3]
            for c in cats:
                mandatory_files[c].append(rel_path)
            if "entrypoint" in cats:
                mod_entry["entrypoint_count"] += 1
            if "security" in cats:
                mod_entry["security_count"] += 1

            # Scan for secret candidate leads (never emit raw secrets)
            if sample_text:
                is_test_or_doc = any(p in {"tests", "test", "docs", "doc", "__tests__", "fixtures", "mocks"} for p in parts_lower) or suffix in {".md", ".txt"}
                if not is_test_or_doc:
                    for line_no, line in enumerate(sample_text.splitlines(), 1):
                        lead_type: str | None = None
                        if PRIVATE_KEY_HEADER_RE.search(line):
                            lead_type = "private_key_block_header"
                        elif RAW_TOKEN_LEAD_RE.search(line):
                            lead_type = "hardcoded_provider_token_pattern"
                        elif HIGH_ENTROPY_SECRET_RE.search(line):
                            m = HIGH_ENTROPY_SECRET_RE.search(line)
                            val = m.group(2) if m else ""
                            if val.lower() not in {"changeme", "password", " password123", "your_secret_here", "secret_key_here", "dummy_secret", "placeholder"} and not val.startswith("${"):
                                lead_type = "hardcoded_credential_assignment"
                        if lead_type:
                            secret_leads.append({
                                "path": rel_path,
                                "line": line_no,
                                "lead_type": lead_type,
                                "redacted_preview": _redact_secret_preview(line),
                            })

    _walk(repo_root)
    external_tool_leads, deferred_external_tool_findings, flagged_manifests, unassigned_project_findings = _scan_external_tool_reports_detailed(
        project_root,
        repo_root,
        repo_name=repo_name,
    )
    flagged_manifest_dirs = {str(Path(p).parent.as_posix()) for p in flagged_manifests if p}
    for d_lead in dependency_leads:
        if isinstance(d_lead, dict):
            d_path = str(d_lead.get("path") or "")
            d_dir = str(Path(d_path).parent.as_posix()) if d_path else ""
            if d_path in flagged_manifests or (d_dir and d_dir in flagged_manifest_dirs):
                d_lead["vulnerable_or_flagged"] = True

    has_entrypoints = len(mandatory_files["entrypoint"]) > 0
    has_security = len(mandatory_files["security"]) > 0
    has_outbound_or_data = len(mandatory_files["outbound"]) > 0 or len(mandatory_files["data_access"]) > 0

    if has_entrypoints or has_security:
        recommended_tier = "tier_1"
        recommended_tier_num = 1
    elif has_outbound_or_data or len(mandatory_files["wiring_config"]) > 0:
        recommended_tier = "tier_2"
        recommended_tier_num = 2
    else:
        recommended_tier = "tier_3"
        recommended_tier_num = 3

    norm_op_tier: str | None = None
    if operator_tier is not None:
        s_tier = str(operator_tier).strip().lower()
        if s_tier in {"1", "tier_1", "tier1"}:
            norm_op_tier = "tier_1"
        elif s_tier in {"2", "tier_2", "tier2"}:
            norm_op_tier = "tier_2"
        elif s_tier in {"3", "tier_3", "tier3"}:
            norm_op_tier = "tier_3"
        else:
            norm_op_tier = s_tier

    tier_mismatch_warning: str | None = None
    if norm_op_tier == "tier_3" and (has_entrypoints or has_security):
        tier_mismatch_warning = (
            f"Operator assigned {norm_op_tier}, but inventory_repo discovered "
            f"{len(mandatory_files['entrypoint'])} entrypoint file(s) and {len(mandatory_files['security'])} security file(s). "
            f"Recommended tier is {recommended_tier}."
        )
    elif norm_op_tier == "tier_2" and has_entrypoints and has_security:
        tier_mismatch_warning = (
            f"Operator assigned {norm_op_tier}, but repository contains both active entrypoints "
            f"({len(mandatory_files['entrypoint'])}) and security controls ({len(mandatory_files['security'])}). "
            f"Recommended tier is {recommended_tier}."
        )

    mandatory_directories = sorted({
        ("/".join(p.split("/")[:-1]) if "/" in p else ".")
        for p in (mandatory_files["entrypoint"] + mandatory_files["security"])
    })

    result = {
        "repo_name": repo_name,
        "run_id": run_id,
        "total_eligible_files": len(all_eligible_files),
        "eligible_files": all_eligible_files,
        "excluded_test_or_generated_files": sorted(set(excluded_test_or_generated_files)),
        "mandatory_files": mandatory_files,
        "mandatory_file_signals": mandatory_file_signals,
        "mandatory_directories": mandatory_directories,
        "discovered_modules": sorted(module_Readiness.values(), key=lambda x: x["path"]),
        "secret_leads": secret_leads,
        "dependency_manifests": dependency_manifests,
        "dependency_leads": dependency_leads,
        "external_tool_leads": external_tool_leads,
        "deferred_external_tool_findings": deferred_external_tool_findings,
        "deferred_external_tool_findings_count": len(deferred_external_tool_findings),
        "unassigned_project_external_findings": unassigned_project_findings,
        "unassigned_project_external_findings_count": len(unassigned_project_findings),
        "recommended_tier": recommended_tier,
        "recommended_tier_number": recommended_tier_num,
        "operator_tier": norm_op_tier,
        "tier_mismatch_warning": tier_mismatch_warning,
    }

    run_dir = project_root / ".localsec" / "runs" / run_id / repo_name
    write_json(run_dir / "inventory_repo.json", result)
    if unassigned_project_findings:
        analysis_dir = project_root / ".localsec" / "runs" / run_id / "_analysis"
        write_json(
            analysis_dir / "unassigned_external_tool_findings.json",
            {
                "run_id": run_id,
                "unassigned_findings_count": len(unassigned_project_findings),
                "unassigned_findings": unassigned_project_findings,
            },
        )
    return result


def validate_scout_map_against_inventory(
    scout_map: dict[str, Any],
    inventory: dict[str, Any] | None,
) -> dict[str, Any]:
    """ARCH-3C: Cross-check codebase_scout.json against inventory_repo.json.
    Every directory containing an entrypoint or security file in inventory_repo.json
    must be either in target_modules or in ignored_modules with a valid reason.
    """
    if not isinstance(inventory, dict):
        return {"valid": True, "unaccounted_mandatory_directories": [], "invalid_ignored_modules": [], "tier_mismatch_warning": None}

    raw_targets = scout_map.get("target_modules", [])
    target_mods: list[str] = []
    for item in raw_targets:
        if isinstance(item, str) and item.strip():
            target_mods.append(item.strip().strip("/") or ".")
        elif isinstance(item, dict) and str(item.get("path", "")).strip():
            target_mods.append(str(item["path"]).strip().strip("/") or ".")

    raw_ignored = scout_map.get("ignored_modules", [])
    ignored_mods: dict[str, str] = {}
    invalid_ignored_modules: list[dict[str, Any]] = []
    if isinstance(raw_ignored, list):
        for item in raw_ignored:
            if isinstance(item, dict):
                mpath = str(item.get("path") or item.get("module") or "").strip().strip("/") or "."
                reason = str(item.get("reason") or "").strip()
                ignored_mods[mpath] = reason
                if reason not in VALID_IGNORED_MODULE_REASONS:
                    invalid_ignored_modules.append({"path": mpath, "reason": reason, "allowed_reasons": sorted(VALID_IGNORED_MODULE_REASONS)})

    mandatory_files = inventory.get("mandatory_files", {})
    ep_and_sec = list(mandatory_files.get("entrypoint", [])) + list(mandatory_files.get("security", []))
    mandatory_dirs = sorted({("/".join(p.split("/")[:-1]) if "/" in p else ".") for p in ep_and_sec})

    unaccounted_dirs: list[str] = []
    for mdir in mandatory_dirs:
        in_target = any(
            t == "." or mdir == t or mdir.startswith(t + "/") or t.startswith(mdir + "/")
            for t in target_mods
        )
        in_ignored = any(
            ig == "." or mdir == ig or mdir.startswith(ig + "/")
            for ig, rsn in ignored_mods.items()
            if rsn in VALID_IGNORED_MODULE_REASONS
        )
        if not in_target and not in_ignored:
            unaccounted_dirs.append(mdir)

    scout_tier = str(scout_map.get("repo_tier", "")).strip().lower()
    tier_warning = inventory.get("tier_mismatch_warning")
    if scout_tier in {"3", "tier_3", "tier3"} and ep_and_sec:
        tier_warning = (
            f"codebase_scout assigned repo_tier={scout_map.get('repo_tier')!r}, but inventory_repo found "
            f"{len(mandatory_files.get('entrypoint', []))} entrypoint and {len(mandatory_files.get('security', []))} security files."
        )

    return {
        "valid": len(unaccounted_dirs) == 0 and len(invalid_ignored_modules) == 0,
        "unaccounted_mandatory_directories": unaccounted_dirs,
        "invalid_ignored_modules": invalid_ignored_modules,
        "tier_mismatch_warning": tier_warning,
    }


_HANDLER_SIG_RE = re.compile(
    r"^\s*(?:"
    r"(?:async\s+)?def\s+\w+"                                   # Python
    r"|func\s*(?:\([^)]*\)\s*)?\w*\s*\("                     # Go (incl. methods / closures)
    r"|(?:export\s+)?(?:async\s+)?function\b"                  # JS/TS function
    r"|(?:(?:public|private|protected|internal|static|async|override|virtual|final|synchronized)\s+)+[\w<>\[\],?\s]*\w+\s*\("  # Java/C#/TS methods
    r"|(?:async\s+)?\w+\s*\([^;]*\)\s*(?::\s*[\w<>\[\], ]+)?\s*\{"  # TS/JS class method `name(...) {`
    r"|.*=>\s*\{?"                                              # arrow handler: r.get('/x', (req, res) => {
    r")"
)


def _derive_handler_end(lines: list[str], line_start: int, max_scan: int = 400) -> int | None:
    """C3: derive where a handler body ends from the source itself, instead of trusting the mapper's line_end.

    Starts at the route/decorator line, finds the handler signature within the next 15 lines, then follows
    indentation (Python) or brace depth (C-family) to the end of the body. Returns a 1-based line or None.
    """
    n = len(lines)
    if line_start < 1 or line_start > n:
        return None
    sig = None
    for i in range(line_start - 1, min(n, line_start + 15)):
        if _HANDLER_SIG_RE.match(lines[i]):
            sig = i
            break
    if sig is None:
        return None
    sig_line = lines[sig]
    if re.match(r"^\s*(?:async\s+)?def\s", sig_line):
        indent = len(sig_line) - len(sig_line.lstrip())
        end = sig
        for j in range(sig + 1, min(n, sig + max_scan)):
            txt = lines[j]
            if not txt.strip():
                continue
            if len(txt) - len(txt.lstrip()) <= indent:
                break
            end = j
        return end + 1
    depth = 0
    opened = False
    for j in range(sig, min(n, sig + max_scan)):
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}" and opened:
                depth -= 1
                if depth == 0:
                    return j + 1
    return None


def audit_visibility_and_coverage(
    *,
    workspace: ManualWorkspace,
    scout_map: dict[str, Any] | None = None,
    coverage_ledger: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    surface_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Phase 1.6 deterministic Visibility Tracker & Coverage Ledger audit gate.
    Enhanced with ARCH-3C file-level mandatory coverage and DEPTH-4.2a cluster spot-checks.
    """
    from .validators import OutputValidationError, validate_coverage_ledger

    vis = workspace.compute_visibility_report(scout_map)
    visited_set = {p.split(":", 1)[1] if ":" in p else p for p in vis.get("visited_files", [])}

    # Build endpoint -> file and endpoint -> line span / evidence_ids lookup from surface_map.entrypoints[]
    ep_to_file: dict[str, str] = {}
    ep_to_span: dict[str, tuple[str, int, int]] = {}
    ep_to_eids: dict[str, list[str]] = {}
    all_clusters: list[dict[str, Any]] = []
    if isinstance(surface_map, dict):
        s_res = surface_map.get("result", surface_map) if isinstance(surface_map.get("result"), dict) else surface_map
        if isinstance(s_res, dict):
            for ep in s_res.get("entrypoints", []):
                if not isinstance(ep, dict):
                    continue
                ep_file = str(ep.get("file") or ep.get("source_file") or "").strip().lstrip("./")
                if not ep_file:
                    continue
                raw_ls = ep.get("line_start") or ep.get("line")
                raw_le = ep.get("line_end") or raw_ls
                span_tuple: tuple[str, int, int] | None = None
                if isinstance(raw_ls, int) and raw_ls >= 1:
                    span_tuple = (ep_file, int(raw_ls), max(int(raw_ls), int(raw_le) if isinstance(raw_le, int) else int(raw_ls)))
                ep_eids = [str(e) for e in (ep.get("evidence_ids") or []) if isinstance(e, str) and e.startswith("ev_")]
                keys_for_ep: list[str] = []
                for k in ("id", "path", "route", "endpoint"):
                    val = str(ep.get(k) or "").strip()
                    if val:
                        keys_for_ep.append(val)
                method_path = f"{str(ep.get('method') or '').strip()} {str(ep.get('path') or ep.get('route') or '').strip()}".strip()
                if method_path:
                    keys_for_ep.append(method_path)
                for kval in keys_for_ep:
                    ep_to_file[kval] = ep_file
                    if span_tuple is not None:
                        ep_to_span[kval] = span_tuple
                    if ep_eids:
                        ep_to_eids[kval] = ep_eids
            for cl in (s_res.get("semantic_clusters") or s_res.get("equivalence_clusters") or []):
                if isinstance(cl, dict):
                    all_clusters.append(cl)
    if isinstance(coverage_ledger, dict):
        c_res = coverage_ledger.get("result", coverage_ledger) if isinstance(coverage_ledger.get("result"), dict) else coverage_ledger
        if isinstance(c_res, dict) and not all_clusters:
            for cl in (c_res.get("semantic_clusters") or c_res.get("equivalence_clusters") or []):
                if isinstance(cl, dict):
                    all_clusters.append(cl)

    def _resolve_cluster_ref_to_file(ref: str) -> str:
        ref = ref.strip()
        if not ref:
            return ""
        if ref in ep_to_file:
            return ep_to_file[ref]
        cand_rel = ref.lstrip("./")
        if not cand_rel.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "OCPP:", "HTTP")):
            if Path(cand_rel).suffix != "" or (workspace.root / cand_rel).is_file():
                return cand_rel
        return ""

    clustered_files: set[str] = set()
    spot_check_clusters: list[dict[str, Any]] = []
    spot_check_violations: list[str] = []
    for idx, cl in enumerate(all_clusters):
        cid = str(cl.get("cluster_id") or f"cluster_{idx + 1}")
        raw_rep_ep = str(
            cl.get("representative_endpoint")
            or cl.get("representative_file")
            or cl.get("representative_path")
            or ""
        ).strip()
        raw_rep = str(
            cl.get("representative_file")
            or cl.get("representative_path")
            or cl.get("representative_endpoint")
            or ""
        ).strip()
        rep = _resolve_cluster_ref_to_file(raw_rep)
        rep_eids_list = [
            str(e) for e in (cl.get("representative_deep_read_evidence_ids") or [])
            if isinstance(e, str) and e.startswith("ev_")
        ]
        if not rep:
            for eid in rep_eids_list:
                rec = workspace.evidence.get(str(eid))
                if isinstance(rec, dict) and rec.get("path"):
                    rep = str(rec["path"]).strip()
                    break
        raw_members = (
            cl.get("member_endpoints")
            or cl.get("members")
            or cl.get("member_files")
            or []
        )
        raw_member_files_only = cl.get("member_files") or []
        raw_member_count = max(
            len(raw_members) if isinstance(raw_members, list) else 0,
            len(raw_member_files_only) if isinstance(raw_member_files_only, list) else 0,
        )
        members: list[str] = []
        member_refs: list[str] = []
        for src_list in (raw_members, raw_member_files_only):
            if isinstance(src_list, list):
                for m in src_list:
                    m_ref = ""
                    m_str = ""
                    if isinstance(m, str) and m.strip():
                        m_ref = m.strip()
                        m_str = _resolve_cluster_ref_to_file(m_ref)
                    elif isinstance(m, dict):
                        m_ref = str(m.get("endpoint") or m.get("id") or m.get("path") or m.get("file") or "").strip()
                        m_str = _resolve_cluster_ref_to_file(str(m.get("path") or m.get("file") or m.get("endpoint") or ""))
                    if m_ref and m_ref not in member_refs:
                        member_refs.append(m_ref)
                    if m_str and m_str not in members:
                        members.append(m_str)
        for m in members:
            if not rep or rep in visited_set:
                clustered_files.add(m)
        effective_member_count = max(len(members), len(member_refs), raw_member_count)
        if effective_member_count >= 5:
            non_rep_files = sorted(m for m in members if m != rep)
            non_rep_refs = sorted(
                r for r in member_refs
                if r not in {raw_rep, raw_rep_ep, rep}
            )
            spot_ep = ""
            spot_file = ""
            if non_rep_refs:
                pick_ep_idx = int(hashlib.sha256(cid.encode("utf-8")).hexdigest(), 16) % len(non_rep_refs)
                spot_ep = non_rep_refs[pick_ep_idx]
                spot_file = _resolve_cluster_ref_to_file(spot_ep)
            if not spot_file:
                if non_rep_files:
                    pick_idx = int(hashlib.sha256(cid.encode("utf-8")).hexdigest(), 16) % len(non_rep_files)
                    spot_file = non_rep_files[pick_idx]
                elif rep:
                    spot_file = rep
            if not spot_ep:
                spot_ep = spot_file

            if spot_file or spot_ep:
                # C3: Verify full handler-span spot-check!
                # Merge overlapping/adjacent read ranges first so multi-read spans are evaluated accurately.
                def _merge_ranges(raw_rngs: list[tuple[int, int]]) -> list[tuple[int, int]]:
                    pts = sorted((int(a), int(b)) for a, b in raw_rngs if int(b) >= int(a))
                    if not pts:
                        return []
                    merged: list[tuple[int, int]] = [pts[0]]
                    for s, e in pts[1:]:
                        prev_s, prev_e = merged[-1]
                        if s <= prev_e + 1:
                            merged[-1] = (prev_s, max(prev_e, e))
                        else:
                            merged.append((s, e))
                    return merged

                file_ranges = workspace.read_ranges.get(spot_file, []) if spot_file else []
                span_info = ep_to_span.get(spot_ep)
                if span_info is not None:
                    sf, l_start, l_end = span_info
                    eff_ranges = _merge_ranges(workspace.read_ranges.get(sf, file_ranges))
                    sf_lines: list[str] = []
                    sf_disk = workspace.root / sf
                    if sf_disk.is_file():
                        try:
                            sf_lines = sf_disk.read_text(encoding="utf-8", errors="replace").splitlines()
                        except Exception:
                            sf_lines = []
                    sf_total_lines = len(sf_lines)
                    # C3: the handler end comes from the source (brace/indent walk), never only from the mapper's claim;
                    # a short self-declared line_end cannot shrink the span that must be read.
                    derived_end = _derive_handler_end(sf_lines, l_start) if sf_lines else None
                    if derived_end is not None:
                        req_end = max(derived_end, l_end)
                    elif l_end > l_start:
                        req_end = l_end
                    else:
                        req_end = l_start + 8
                    if sf_total_lines > 0:
                        req_end = min(sf_total_lines, req_end)
                    spot_read = any(r_s <= l_start and r_e >= req_end for r_s, r_e in eff_ranges)
                elif spot_file and spot_file != rep:
                    spot_read = spot_file in visited_set
                else:
                    # Single-file multi-endpoint cluster without line_start on spot_ep:
                    # Require spot_ep to have its own distinct valid evidence_id in workspace.evidence covering >=3 lines
                    ep_specific_eids = []
                    for e in ep_to_eids.get(spot_ep, []):
                        if e in workspace.evidence and e not in set(rep_eids_list):
                            rec = workspace.evidence.get(e, {})
                            # C3: the distinct evidence must come from the spot-check file itself
                            if spot_file and str(rec.get("path") or "").lstrip("./") != spot_file:
                                continue
                            span_len = int(rec.get("line_end", 0)) - int(rec.get("line_start", 0)) + 1
                            if span_len >= 3:
                                ep_specific_eids.append(e)
                    spot_read = len(ep_specific_eids) > 0

                spot_check_clusters.append({
                    "cluster_id": cid,
                    "member_count": effective_member_count,
                    "representative_file": rep,
                    "representative_endpoint": raw_rep_ep or rep,
                    "required_spot_check_endpoint": spot_ep,
                    "required_spot_check_file": spot_file,
                    "spot_check_read": spot_read,
                })
                if not spot_read:
                    spot_check_violations.append(
                        f"Cluster {cid!r} has {effective_member_count} members (>=5); spot-check handler/endpoint "
                        f"{spot_ep!r} (file {spot_file!r}) must be directly read across its full handler body span"
                    )

    # Check ignored/waived modules from scout_map
    waived_prefixes: list[str] = []
    if isinstance(scout_map, dict):
        for ig in scout_map.get("ignored_modules", []):
            if isinstance(ig, dict) and str(ig.get("reason", "")) in VALID_IGNORED_MODULE_REASONS:
                p = str(ig.get("path") or ig.get("module") or "").strip().strip("/")
                if p:
                    waived_prefixes.append(p)

    # File-level mandatory coverage (ARCH-3C), measured in LINES: opening a file is not reading it.
    # A mandatory file counts as DIRECT_READ only when the merged read ranges cover >= min_pct of its lines.
    min_pct = float(workspace.cfg.get("mandatory_min_line_coverage", 0.9))

    def _line_cov(fpath: str) -> tuple[int, int]:
        disk = workspace.root / fpath
        try:
            total = len(disk.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            return 0, 0
        pts = sorted((int(a), int(b)) for a, b in workspace.read_ranges.get(fpath, []) if int(b) >= int(a))
        covered, cur_s, cur_e = 0, None, None
        for s, e in pts:
            s, e = max(1, s), min(total, e)
            if s > e:
                continue
            if cur_e is not None and s <= cur_e + 1:
                cur_e = max(cur_e, e)
            else:
                if cur_e is not None:
                    covered += cur_e - cur_s + 1
                cur_s, cur_e = s, e
        if cur_e is not None:
            covered += cur_e - cur_s + 1
        return covered, total

    mandatory_file_status: dict[str, dict[str, str]] = {"entrypoint": {}, "security": {}}
    mandatory_line_coverage: dict[str, dict[str, Any]] = {}
    unvisited_mandatory_files: list[str] = []
    partially_read_mandatory_files: list[str] = []
    if isinstance(inventory, dict):
        mfiles = inventory.get("mandatory_files", {})
        for bucket in ("entrypoint", "security"):
            for fpath in mfiles.get(bucket, []):
                covered, total = _line_cov(fpath)
                pct = round(covered / total, 4) if total else 1.0
                mandatory_line_coverage[fpath] = {"lines_read": covered, "lines_total": total, "pct": pct}
                if fpath in visited_set and pct >= min_pct:
                    mandatory_file_status[bucket][fpath] = "DIRECT_READ"
                elif fpath in visited_set:
                    mandatory_file_status[bucket][fpath] = "PARTIAL_READ"
                    partially_read_mandatory_files.append(f"{bucket}:{fpath} ({covered}/{total} lines)")
                elif fpath in clustered_files:
                    mandatory_file_status[bucket][fpath] = "CLUSTERED_SAFE"
                elif any(fpath == wp or fpath.startswith(wp + "/") for wp in waived_prefixes):
                    mandatory_file_status[bucket][fpath] = "WAIVED"
                else:
                    mandatory_file_status[bucket][fpath] = "UNVISITED"
                    unvisited_mandatory_files.append(f"{bucket}:{fpath}")

    # Per target module: share of lines read across non-test source files (reported, so "visited" is not mistaken for "read")
    module_line_coverage: dict[str, dict[str, Any]] = {}
    src_suffixes = {".py", ".ts", ".tsx", ".js", ".mjs", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs", ".c", ".cpp", ".h", ".swift", ".dart"}
    for mod in (scout_map or {}).get("target_modules", []) if isinstance(scout_map, dict) else []:
        mod_p = str(mod.get("path") if isinstance(mod, dict) else mod).strip().strip("/")
        base = workspace.root / mod_p if mod_p not in {"", "."} else workspace.root
        if not base.is_dir():
            continue
        lines_total = lines_read = 0
        for fp in base.rglob("*"):
            if not fp.is_file() or fp.suffix.lower() not in src_suffixes:
                continue
            rel_fp = fp.relative_to(workspace.root).as_posix()
            parts = [x.lower() for x in fp.relative_to(workspace.root).parts]
            if "node_modules" in parts or _is_test_or_generated_path(rel_fp, fp.stem.lower(), fp.suffix.lower(), parts):
                continue
            c, t = _line_cov(rel_fp)
            lines_total += t
            lines_read += c
        module_line_coverage[mod_p or "."] = {
            "lines_read": lines_read,
            "lines_total": lines_total,
            "pct": round(lines_read / lines_total, 4) if lines_total else None,
        }

    # V20: the rest of each target module is gated too, by share of non-test source lines read. Before this only the
    # mandatory files were forced, and the agent stopped at 26-35% of module lines in the vinfast-mcp runs.
    min_mod_pct = float(workspace.cfg.get("target_module_min_line_coverage", 0.5))
    under_read_target_modules: list[str] = []
    for mod_key, mc in module_line_coverage.items():
        if any(mod_key == wp or mod_key.startswith(wp + "/") for wp in waived_prefixes):
            continue
        pct = mc.get("pct")
        if pct is not None and mc.get("lines_total", 0) > 0 and pct < min_mod_pct:
            under_read_target_modules.append(
                f"{mod_key} ({mc['lines_read']}/{mc['lines_total']} lines = {pct:.0%}, need {min_mod_pct:.0%}; "
                f"use `read_files <repo> --module {mod_key} --until-pct {int(min_mod_pct * 100)}`)"
            )

    vis["mandatory_file_coverage"] = mandatory_file_status
    vis["mandatory_line_coverage"] = mandatory_line_coverage
    vis["target_module_min_line_coverage"] = min_mod_pct
    vis["under_read_target_modules"] = under_read_target_modules
    vis["mandatory_min_line_coverage"] = min_pct
    vis["unvisited_mandatory_files"] = unvisited_mandatory_files
    vis["partially_read_mandatory_files"] = partially_read_mandatory_files
    vis["target_module_line_coverage"] = module_line_coverage
    vis["spot_check_clusters"] = spot_check_clusters
    vis["spot_check_violations"] = spot_check_violations
    if unvisited_mandatory_files or partially_read_mandatory_files or under_read_target_modules or spot_check_violations:
        vis["gate_passed"] = False

    ledger_issues: list[str] = []
    if coverage_ledger is not None:
        try:
            validate_coverage_ledger(coverage_ledger, set(workspace.evidence.keys()), visibility_report=vis)
        except OutputValidationError as exc:
            ledger_issues.append(str(exc))
    else:
        if not vis.get("gate_passed", False):
            ledger_issues.append("Visibility Tracker gate failed (unvisited_target_modules, shallow_grazing_files, unvisited_mandatory_files or partially_read_mandatory_files present)")
    for v in spot_check_violations:
        if v not in ledger_issues:
            ledger_issues.append(v)

    return {
        "gate_passed": bool(vis.get("gate_passed", False) and not ledger_issues),
        "visibility_report": vis,
        "ledger_validation_issues": ledger_issues,
    }


def select_attack_companions_for_repo(
    *,
    run_dir: Path,
    archetypes: list[str] | None = None,
    candidate_classes: list[str] | None = None,
    max_companions: int = 3,
) -> dict[str, Any]:
    """ARCH-3B: Select and persist attack-class companion blocks into run_dir/selected_attack_companions.json."""
    from .prompts import select_companion_blocks

    run_dir = Path(run_dir)
    eff_archetypes = list(archetypes or [])
    eff_classes = list(candidate_classes or [])

    if not eff_archetypes and (run_dir / "codebase_scout.json").is_file():
        try:
            scout_raw = json.loads((run_dir / "codebase_scout.json").read_text(encoding="utf-8", errors="replace"))
            scout_res = scout_raw.get("result", scout_raw) if isinstance(scout_raw, dict) else {}
            eff_archetypes = [str(a) for a in scout_res.get("detected_archetypes", []) if str(a).strip()]
        except Exception:
            pass

    if not eff_classes and (run_dir / "candidate_queue.json").is_file():
        try:
            cq_raw = json.loads((run_dir / "candidate_queue.json").read_text(encoding="utf-8", errors="replace"))
            for c in cq_raw.get("candidates", []):
                if isinstance(c, dict) and c.get("attack_class"):
                    eff_classes.append(str(c["attack_class"]))
        except Exception:
            pass

    return select_companion_blocks(
        archetypes=eff_archetypes,
        candidate_classes=eff_classes,
        max_companions=max_companions,
        run_dir=run_dir,
    )


def generate_coverage_matrix(run_dir: Path, repo_name: str) -> dict[str, Any]:
    """DEPTH-4.3a: Deterministic Coverage Matrix Generator.
    Combines inventory_repo.json, codebase_scout.json, unified_surface_mapper.json, and intent_invariant_modeler.json
    to emit coverage_matrix.json with records[] covering each target module/entrypoint across applicable attack classes.
    Never fabricates 'verified_safe' or placeholder evidence IDs; defaults unassessed cells to 'unassessed' with [].
    """
    run_dir = Path(run_dir)

    def _read_opt(fname: str) -> dict[str, Any]:
        fp = run_dir / fname
        if fp.is_file():
            try:
                raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw, dict):
                    return raw.get("result", raw) if isinstance(raw.get("result"), dict) else raw
            except Exception:
                pass
        return {}

    inv = _read_opt("inventory_repo.json")
    scout = _read_opt("codebase_scout.json")
    surf = _read_opt("unified_surface_mapper.json")
    intent = _read_opt("intent_invariant_modeler.json")
    existing_ledger = _read_opt("coverage_ledger.json")

    ws_evidence: dict[str, dict[str, Any]] = {}
    deferred_files: set[str] = set()
    ws_path = run_dir / "workspace_state.json"
    if ws_path.is_file():
        try:
            ws_data = json.loads(ws_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(ws_data.get("evidence"), dict):
                ws_evidence = ws_data["evidence"]
            for df in ws_data.get("deferred_out_of_budget", []):
                if isinstance(df, str) and df.strip():
                    deferred_files.add(df.strip())
        except Exception:
            ws_evidence = {}

    def _filter_module_eids(raw_eids: list[Any], mod: str) -> list[str]:
        valid: list[str] = []
        for e in raw_eids:
            es = str(e).strip()
            if not es.startswith("ev_") or es == "ev_000000000000000000":
                continue
            if ws_evidence:
                rec = ws_evidence.get(es)
                if not isinstance(rec, dict):
                    continue
                rpath = str(rec.get("path") or "").strip().lstrip("./")
                if mod != "." and not (rpath == mod or rpath.startswith(mod + "/")):
                    continue
            if es not in valid:
                valid.append(es)
        return valid

    target_mods: list[str] = []
    for item in scout.get("target_modules", []):
        if isinstance(item, str) and item.strip():
            target_mods.append(item.strip().strip("/"))
        elif isinstance(item, dict) and str(item.get("path", "")).strip():
            target_mods.append(str(item["path"]).strip().strip("/"))
    if not target_mods:
        target_mods = list(inv.get("mandatory_directories", [])) or ["src"]

    attack_classes = ["BOLA_IDOR", "AUTH_BYPASS", "INJECTION", "SSRF_OUTBOUND", "STATE_RACE"]
    if intent.get("safety_invariants") or intent.get("sfop_invariants") or intent.get("invariants"):
        attack_classes.append("SAFETY_INVARIANT")

    # Index explicit surface anomalies / candidates / entrypoints per (mod, aclass)
    flagged_evidence_by_cell: dict[tuple[str, str], list[str]] = {}
    flagged_cells: set[tuple[str, str]] = set()
    safe_evidence_by_cell: dict[tuple[str, str], list[str]] = {}

    def _match_attack_class(raw_cls: str) -> str:
        u = raw_cls.upper()
        if any(k in u for k in ("BOLA", "IDOR", "BFLA", "OBJECT", "TENANT")):
            return "BOLA_IDOR"
        if any(k in u for k in ("AUTH", "JWT", "TOKEN", "SESSION", "OCPP")):
            return "AUTH_BYPASS"
        if any(k in u for k in ("INJECT", "SQL", "CMD", "XSS", "DESERIAL")):
            return "INJECTION"
        if any(k in u for k in ("SSRF", "OUTBOUND", "WEBHOOK")):
            return "SSRF_OUTBOUND"
        if any(k in u for k in ("RACE", "STATE", "IDEMPOTEN", "BOPLA", "MASS")):
            return "STATE_RACE"
        if any(k in u for k in ("SAFETY", "INVARIANT", "ACTUATOR", "INTERLOCK")):
            return "SAFETY_INVARIANT"
        return ""

    for anom in (
        list(surf.get("anomalies", []))
        + list(surf.get("intent_vs_code_gaps", []))
        + list(surf.get("candidate_queue", []))
        + list(surf.get("candidates", []))
    ):
        if not isinstance(anom, dict):
            continue
        ap = str(
            anom.get("path")
            or anom.get("file")
            or anom.get("endpoint")
            or ((anom.get("target_paths") or [""])[0] if isinstance(anom.get("target_paths"), list) else "")
        ).strip()
        raw_ac = str(
            anom.get("attack_class")
            or ((anom.get("attack_classes") or [""])[0] if isinstance(anom.get("attack_classes"), list) else "")
            or ""
        )
        mapped_ac = _match_attack_class(raw_ac)
        if not mapped_ac:
            continue
        raw_eids = list(anom.get("evidence_ids") or [])
        for mod in target_mods:
            if mod == "." or (ap and (ap == mod or ap.startswith(mod + "/") or mod in ap)):
                flagged_cells.add((mod, mapped_ac))
            mod_eids = _filter_module_eids(raw_eids, mod)
            if mod_eids and (mod == "." or mod in ap or not ap):
                flagged_cells.add((mod, mapped_ac))
                cell = flagged_evidence_by_cell.setdefault((mod, mapped_ac), [])
                for e in mod_eids:
                    if e not in cell:
                        cell.append(e)

    for ic in surf.get("invariant_checks", []):
        if isinstance(ic, dict) and str(ic.get("enforcement_status") or ic.get("status") or "").lower() in {"missing", "partial"}:
            raw_eids = list(ic.get("implementation_evidence_ids") or ic.get("evidence_ids") or [])
            ic_ac = "SAFETY_INVARIANT" if "SAFETY_INVARIANT" in attack_classes else "STATE_RACE"
            for mod in target_mods:
                mod_eids = _filter_module_eids(raw_eids, mod)
                if mod_eids:
                    flagged_cells.add((mod, ic_ac))
                    cell = flagged_evidence_by_cell.setdefault((mod, ic_ac), [])
                    for e in mod_eids:
                        if e not in cell:
                            cell.append(e)

    for ep in surf.get("entrypoints", []):
        if not isinstance(ep, dict):
            continue
        ep_file = str(ep.get("file") or ep.get("path") or "").strip().lstrip("./")
        raw_eids = list(ep.get("ownership_evidence_ids") or ep.get("evidence_ids") or [])
        for mod in target_mods:
            if mod != "." and not (ep_file == mod or ep_file.startswith(mod + "/")):
                continue
            is_bola_flagged = bool(
                ep.get("ownership_check") == "missing"
                or (ep.get("object_id_params") and ep.get("ownership_check") != "present")
            )
            if is_bola_flagged:
                flagged_cells.add((mod, "BOLA_IDOR"))
            mod_eids = _filter_module_eids(raw_eids, mod)
            if not mod_eids:
                continue
            if is_bola_flagged:
                cell = flagged_evidence_by_cell.setdefault((mod, "BOLA_IDOR"), [])
                for e in mod_eids:
                    if e not in cell:
                        cell.append(e)
            elif ep.get("ownership_check") == "present":
                cell = safe_evidence_by_cell.setdefault((mod, "BOLA_IDOR"), [])
                for e in mod_eids:
                    if e not in cell:
                        cell.append(e)

    records: list[dict[str, Any]] = []
    seen_cids: set[str] = set()

    # Preserve existing coverage_ledger records only when they cite valid non-placeholder evidence IDs and do not contradict flagged cells
    for rec in existing_ledger.get("records", []):
        if isinstance(rec, dict) and rec.get("coverage_id"):
            cid_str = str(rec["coverage_id"])
            rec_mod = str(rec.get("target_module") or ".")
            rec_ac = str(rec.get("attack_class") or "")
            valid_rec_eids = _filter_module_eids(list(rec.get("evidence_ids") or []), rec_mod)
            rec_copy = dict(rec)
            raw_st = str(rec_copy.get("status") or "unassessed")
            cell_flagged_eids = flagged_evidence_by_cell.get((rec_mod, rec_ac), [])
            cell_is_flagged = bool(cell_flagged_eids or (rec_mod, rec_ac) in flagged_cells)
            if raw_st in {"verified_safe", "covered_safe"}:
                if cell_is_flagged:
                    rec_copy["status"] = "flagged_for_phase_2"
                    rec_copy["evidence_ids"] = cell_flagged_eids or valid_rec_eids
                else:
                    rec_copy["status"] = "covered_safe" if valid_rec_eids else "unassessed"
                    rec_copy["evidence_ids"] = valid_rec_eids
            elif raw_st in {"covered_finding", "flagged_for_phase_2"}:
                rec_copy["status"] = "flagged_for_phase_2" if (valid_rec_eids or cell_is_flagged) else "unassessed"
                rec_copy["evidence_ids"] = valid_rec_eids or cell_flagged_eids
            else:
                rec_copy["evidence_ids"] = valid_rec_eids
            seen_cids.add(cid_str)
            records.append(rec_copy)

    for mod in target_mods:
        mod_is_deferred = any(df == mod or df.startswith(mod + "/") for df in deferred_files)
        for aclass in attack_classes:
            cid = build_coverage_id(mod, "repo_boundary", repo_name, aclass)
            if cid in seen_cids:
                continue
            seen_cids.add(cid)
            flagged_eids = flagged_evidence_by_cell.get((mod, aclass), [])
            safe_eids = safe_evidence_by_cell.get((mod, aclass), [])
            if flagged_eids:
                status = "flagged_for_phase_2"
                cell_eids = flagged_eids
            elif safe_eids:
                status = "covered_safe"
                cell_eids = safe_eids
            elif mod_is_deferred:
                status = "deferred"
                cell_eids = []
            else:
                status = "unassessed"
                cell_eids = []
            records.append({
                "coverage_id": cid,
                "target_module": mod,
                "attack_class": aclass,
                "status": status,
                "evidence_ids": cell_eids,
                "attempts": (
                    [
                        {
                            "attempt_number": 1,
                            "action": "evidence_backed_surface_assessment",
                            "evidence_ids": cell_eids,
                        }
                    ]
                    if cell_eids
                    else []
                ),
            })

    status_counts: dict[str, int] = {
        "covered_safe": 0,
        "flagged_for_phase_2": 0,
        "unassessed": 0,
        "deferred": 0,
    }
    for r in records:
        st = str(r.get("status") or "unassessed")
        if st in status_counts:
            status_counts[st] += 1
        elif st in {"verified_safe"}:
            status_counts["covered_safe"] += 1
        elif st in {"covered_finding"}:
            status_counts["flagged_for_phase_2"] += 1
        else:
            status_counts["unassessed"] += 1

    matrix_payload = {
        "repo_name": repo_name,
        "generated_by": "generate_coverage_matrix",
        "target_modules": target_mods,
        "attack_classes": attack_classes,
        "record_count": len(records),
        "status_counts": status_counts,
        "records": records,
    }
    write_json(run_dir / "coverage_matrix.json", matrix_payload)
    return matrix_payload


def build_v3_candidate_queue(run_dir: Path, repo_name: str) -> dict[str, Any]:
    """ARCH-3G & DEPTH-4.2a: Comprehensive Phase 1 -> Phase 2 Candidate Collector.
    Collects candidates from all 7+ sources, deduplicates, assigns stable cand_<12-hex> IDs,
    and writes run_dir/candidate_queue.json.
    """
    run_dir = Path(run_dir)

    def _load_json_dict(path: Path) -> dict[str, Any]:
        if path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw, dict):
                    return raw.get("result", raw) if isinstance(raw.get("result"), dict) else raw
            except Exception:
                pass
        return {}

    surf = _load_json_dict(run_dir / "unified_surface_mapper.json")
    intent = _load_json_dict(run_dir / "intent_invariant_modeler.json")
    arch = _load_json_dict(run_dir / "cross_repo_and_arch_review.json")
    if not arch and (run_dir.parent / "_analysis" / "cross_repo_and_arch_review.json").is_file():
        arch = _load_json_dict(run_dir.parent / "_analysis" / "cross_repo_and_arch_review.json")
    ledger = _load_json_dict(run_dir / "coverage_ledger.json")
    matrix = _load_json_dict(run_dir / "coverage_matrix.json")
    inv = _load_json_dict(run_dir / "inventory_repo.json")

    candidates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    sources_summary: dict[str, int] = {
        "surface_anomalies": 0,
        "intent_vs_code_gaps": 0,
        "blinded_challenger_new_invariants": 0,
        "trust_boundary_mismatches": 0,
        "contract_drift_findings": 0,
        "coverage_ledger_flagged": 0,
        "inventory_leads": 0,
        "external_tool_leads": 0,
        "stride_review": 0,
        "pattern_checklist": 0,
    }

    def _norm_rc(v: Any) -> str:
        t = re.sub(r"[^A-Za-z0-9]+", "-", str(v or "").strip()).strip("-").upper()
        return t if len(t) >= 4 else ""

    def _add_candidate(
        source_kind: str,
        title: str,
        attack_class: str,
        target_path: str,
        evidence_ids: list[str],
        raw_item: dict[str, Any],
    ) -> None:
        identity = f"{repo_name}|{source_kind}|{attack_class}|{target_path}|{title}"
        cid = str(raw_item.get("candidate_id") or "")
        if not re.match(r"^cand_[a-f0-9]{12}$", cid):
            cid = "cand_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        if cid in seen_ids:
            return
        seen_ids.add(cid)
        sources_summary[source_kind] = sources_summary.get(source_kind, 0) + 1
        candidates.append({
            "candidate_id": cid,
            "repo_name": repo_name,
            "source_kind": source_kind,
            "title": title,
            "attack_class": attack_class,
            "target_path": target_path,
            "evidence_ids": [str(e) for e in evidence_ids if str(e).startswith("ev_")],
            "status": "queued_for_phase_2",
            "source_detail": raw_item,
            # V1: root-cause hint declared by the Phase 1 step that produced the item (shared across sources)
            "root_cause_hint": _norm_rc(raw_item.get("root_cause_hint") or raw_item.get("root_cause_cluster_id") or ""),
        })

    # 1a. unified_surface_mapper.json -> explicit candidate_queue[] / candidates[] and semantic_clusters[].outliers[]
    for item in list(surf.get("candidate_queue", [])) + list(surf.get("candidates", [])):
        if isinstance(item, dict):
            _add_candidate(
                "surface_anomalies",
                str(item.get("title") or item.get("description") or item.get("candidate_id") or "Queued Surface Candidate"),
                str((item.get("attack_classes") or [item.get("attack_class") or "BOLA_IDOR"])[0]),
                str((item.get("target_paths") or [item.get("target_path") or item.get("path") or item.get("file") or ""])[0]),
                list(item.get("evidence_ids", [])),
                item,
            )
    for cl in surf.get("semantic_clusters", []):
        if isinstance(cl, dict):
            for out_ep in cl.get("outliers", []):
                if isinstance(out_ep, str) and out_ep.strip():
                    _add_candidate(
                        "surface_anomalies",
                        f"Cluster Outlier Endpoint: {out_ep.strip()}",
                        "CLUSTER_OUTLIER_REVIEW",
                        out_ep.strip(),
                        list(cl.get("representative_deep_read_evidence_ids", [])),
                        {"cluster_id": cl.get("cluster_id"), "outlier": out_ep.strip()},
                    )
                elif isinstance(out_ep, dict):
                    _add_candidate(
                        "surface_anomalies",
                        str(out_ep.get("title") or out_ep.get("path") or out_ep.get("endpoint") or "Cluster Outlier"),
                        str(out_ep.get("attack_class") or "CLUSTER_OUTLIER_REVIEW"),
                        str(out_ep.get("path") or out_ep.get("file") or out_ep.get("endpoint") or ""),
                        list(out_ep.get("evidence_ids") or cl.get("representative_deep_read_evidence_ids", [])),
                        out_ep,
                    )

    # 1b. unified_surface_mapper.json -> entrypoints[] with BOLA (object_id_params without ownership_check=='present') or BOPLA (raw_entity_or_map)
    for ep in surf.get("entrypoints", []):
        if isinstance(ep, dict):
            ep_path = str(ep.get("file") or ep.get("path") or ep.get("route") or "")
            obj_params = ep.get("object_id_params")
            if isinstance(obj_params, list) and len(obj_params) > 0 and ep.get("ownership_check") != "present":
                _add_candidate(
                    "surface_anomalies",
                    f"BOLA/IDOR Candidate on {ep.get('method', 'HTTP')} {ep.get('path', ep_path)} (object_id_params={obj_params}, ownership_check={ep.get('ownership_check', 'unknown')})",
                    "BOLA_IDOR",
                    ep_path,
                    list(ep.get("ownership_evidence_ids") or ep.get("evidence_ids") or []),
                    ep,
                )
            if ep.get("input_binding") == "raw_entity_or_map":
                _add_candidate(
                    "surface_anomalies",
                    f"BOPLA/Mass-Assignment Candidate on {ep.get('method', 'HTTP')} {ep.get('path', ep_path)} (input_binding=raw_entity_or_map)",
                    "BOPLA_MASS_ASSIGNMENT",
                    ep_path,
                    list(ep.get("evidence_ids") or []),
                    ep,
                )

    # 1c. unified_surface_mapper.json -> surface_checklist unknown items or 'absent' items contradicted by inventory_repo signals
    inv_signals = inv.get("mandatory_file_signals", {}) if isinstance(inv.get("mandatory_file_signals"), dict) else {}
    inv_mfiles = inv.get("mandatory_files", {}) if isinstance(inv.get("mandatory_files"), dict) else {}
    all_inv_files = list(inv_mfiles.get("entrypoint", [])) + list(inv_mfiles.get("security", []))

    def _contradicting_inventory_files(stype_name: str) -> list[str]:
        st_low = stype_name.strip().lower()
        matched_files: list[str] = []
        signal_keywords: tuple[str, ...] = ()
        path_keywords: tuple[str, ...] = ()
        http_route_signals = (
            "decorator_route",
            "nestjs_controller_or_route",
            "go_http_router",
            "dotnet_endpoint",
            "router_call",
            "mulesoft_http_listener",
            "sap_abap_rfc",
        )
        if st_low == "public_http":
            signal_keywords = http_route_signals
            path_keywords = ("controller", "router", "routes", "endpoint")
        elif st_low == "internal_or_admin_http":
            signal_keywords = ("sap_abap_rfc", "mulesoft_http_listener", "grpc_service")
            path_keywords = ("admin", "internal", "backoffice", "management", "rfc_")
        elif st_low == "queue_or_event_consumer":
            signal_keywords = ("queue_consumer", "kafkalistener", "rabbitlistener", "sqslistener", "celery", "shared_task", "nats", "pubsub")
            path_keywords = ("consumer", "subscriber", "kafka", "rabbit", "sqs", "event_handler")
        elif st_low == "scheduler_or_batch":
            signal_keywords = ("scheduler_or_cron", "@scheduled", "@cron", "cron.schedule", "apscheduler", "quartz")
            path_keywords = ("cron", "scheduler", "scheduled", "batch_job")
        elif st_low == "webhook_or_callback":
            signal_keywords = ("webhook_handler", "webhook", "callback")
            path_keywords = ("webhook", "callback")
        elif st_low == "websocket_mqtt_ocpp":
            signal_keywords = ("ocpp", "mqtt", "zmq", "websocket")
            path_keywords = ("ocpp", "mqtt", "websocket", "ws_")
        elif st_low == "cli_or_maintenance_job":
            signal_keywords = ("aws_lambda_handler", "lambda_handler", "click.command", "argumentparser", "cobra.command", "typer")
            path_keywords = ("cli", "command", "lambda_handler", "manage.py")
        elif st_low == "mobile_deeplink_or_exported_component":
            signal_keywords = ("mobile_bridge", "mobile_manifest", "flutter_method_channel", "methodchannel", "deeplink")
            path_keywords = ("androidmanifest.xml", "info.plist", "deeplink", "method_channel")
        elif st_low == "ble_or_hardware_bus":
            signal_keywords = ("ros2", "modbus", "opcua", "iec61850", "dnp3", "canbus", "ble")
            path_keywords = ("ros2", "modbus", "opcua", "canbus", "ble")
        if not signal_keywords and not path_keywords:
            return []
        for fpath, sigs in inv_signals.items():
            sig_list = [str(s).lower() for s in (sigs if isinstance(sigs, list) else [sigs])]
            fl = str(fpath).lower()
            if st_low == "public_http":
                # Exclude files that are purely internal/admin if internal_or_admin_http covers them
                if any(k in fl for k in ("admin", "internal", "backoffice")):
                    continue
            if any(any(k in s for k in signal_keywords) for s in sig_list) or any(pk in fl for pk in path_keywords):
                if str(fpath) not in matched_files:
                    matched_files.append(str(fpath))
        for fpath in all_inv_files:
            fl = str(fpath).lower()
            if st_low == "public_http" and any(k in fl for k in ("admin", "internal", "backoffice")):
                continue
            if any(pk in fl for pk in path_keywords) and str(fpath) not in matched_files:
                matched_files.append(str(fpath))
        return matched_files

    s_chk = surf.get("surface_checklist")
    if isinstance(s_chk, dict):
        for stype, sinfo in s_chk.items():
            is_unk = False
            is_abs = False
            if sinfo is None:
                is_unk = True
            elif isinstance(sinfo, dict):
                st_str = str(sinfo.get("status", "")).lower()
                if st_str == "unknown" or ("present" in sinfo and sinfo.get("present") is None):
                    is_unk = True
                elif st_str == "absent" or sinfo.get("present") is False:
                    is_abs = True
            elif str(sinfo).lower() == "unknown":
                is_unk = True
            elif str(sinfo).lower() in {"absent", "false"}:
                is_abs = True
            if is_unk:
                _add_candidate(
                    "surface_anomalies",
                    f"Unknown Surface Type Requires Verification: {stype}",
                    "UNVERIFIED_SURFACE",
                    stype,
                    list(sinfo.get("evidence_ids", [])) if isinstance(sinfo, dict) else [],
                    {"surface_type": stype, "status": "unknown"},
                )
            elif is_abs:
                contra_files = _contradicting_inventory_files(str(stype))
                if contra_files:
                    _add_candidate(
                        "surface_anomalies",
                        f"Contradicted Surface Checklist ('absent' vs inventory_repo signals): {stype} ({', '.join(contra_files[:3])})",
                        "UNVERIFIED_SURFACE",
                        contra_files[0],
                        list(sinfo.get("evidence_ids", [])) if isinstance(sinfo, dict) else [],
                        {"surface_type": stype, "status": "absent_contradicted_by_inventory", "contradicting_files": contra_files},
                    )
    elif isinstance(s_chk, list):
        for sinfo in s_chk:
            if not isinstance(sinfo, dict):
                continue
            stype = str(sinfo.get("surface_type") or sinfo.get("type") or "surface")
            st_str = str(sinfo.get("status", "")).lower()
            if st_str == "unknown" or ("present" in sinfo and sinfo.get("present") is None):
                _add_candidate(
                    "surface_anomalies",
                    f"Unknown Surface Type Requires Verification: {stype}",
                    "UNVERIFIED_SURFACE",
                    stype,
                    list(sinfo.get("evidence_ids", [])),
                    sinfo,
                )
            elif st_str == "absent" or sinfo.get("present") is False:
                contra_files = _contradicting_inventory_files(stype)
                if contra_files:
                    _add_candidate(
                        "surface_anomalies",
                        f"Contradicted Surface Checklist ('absent' vs inventory_repo signals): {stype} ({', '.join(contra_files[:3])})",
                        "UNVERIFIED_SURFACE",
                        contra_files[0],
                        list(sinfo.get("evidence_ids", [])),
                        {**sinfo, "status": "absent_contradicted_by_inventory", "contradicting_files": contra_files},
                    )

    # 1d. unified_surface_mapper.json -> anomalies[]
    for item in surf.get("anomalies", []):
        if isinstance(item, dict):
            _add_candidate(
                "surface_anomalies",
                str(item.get("title") or item.get("description") or item.get("anomaly_id") or "Surface Anomaly"),
                str(item.get("attack_class") or item.get("category") or "BOLA_IDOR"),
                str(item.get("path") or item.get("file") or item.get("endpoint") or ""),
                list(item.get("evidence_ids", [])),
                item,
            )

    # 2. unified_surface_mapper.json -> intent_vs_code_gaps[] and invariant_checks[]
    for item in surf.get("intent_vs_code_gaps", []):
        if isinstance(item, dict):
            _add_candidate(
                "intent_vs_code_gaps",
                str(item.get("title") or item.get("gap_description") or item.get("invariant_id") or "Intent vs Code Gap"),
                str(item.get("attack_class") or "BUSINESS_LOGIC_BYPASS"),
                str(item.get("path") or item.get("file") or ""),
                list(item.get("evidence_ids", [])),
                item,
            )
    for item in surf.get("invariant_checks", []):
        if isinstance(item, dict) and str(item.get("enforcement_status") or item.get("status") or "").lower() in {"missing", "partial", "unknown"}:
            _add_candidate(
                "intent_vs_code_gaps",
                f"Invariant {item.get('invariant_id', 'INV')} Enforcement {item.get('enforcement_status') or item.get('status')}",
                "BUSINESS_LOGIC_BYPASS",
                str(item.get("file") or item.get("path") or item.get("invariant_id") or ""),
                list(item.get("implementation_evidence_ids") or item.get("intent_evidence_ids") or item.get("evidence_ids") or []),
                item,
            )

    # 3. intent_invariant_modeler.json -> blinded_challenger_new_invariants[], self_challenged_gaps[], and self_review_gaps[]
    for item in (
        list(intent.get("blinded_challenger_new_invariants", []))
        + list(intent.get("self_challenged_gaps", []))
        + list(intent.get("self_review_gaps", []))
    ):
        if isinstance(item, str) and item.strip():
            _add_candidate(
                "blinded_challenger_new_invariants",
                f"Self-Review Invariant Gap: {item.strip()}",
                "INVARIANT_VIOLATION",
                "",
                [],
                {"gap": item.strip()},
            )
        elif isinstance(item, dict):
            if str(item.get("verification_status", "unverified")).lower() not in {"verified_enforced", "confirmed_safe"}:
                _add_candidate(
                    "blinded_challenger_new_invariants",
                    str(item.get("title") or item.get("invariant") or item.get("description") or item.get("gap_id") or "Unverified Safety/Business Invariant"),
                    str(item.get("attack_class") or item.get("sfop_axis") or item.get("axis") or "INVARIANT_VIOLATION"),
                    str(item.get("target_module") or item.get("path") or ""),
                    list(item.get("evidence_ids", [])),
                    item,
                )

    # 4. cross_repo_and_arch_review.json -> trust_boundary_mismatches[]
    for item in arch.get("trust_boundary_mismatches", []):
        if isinstance(item, dict):
            _add_candidate(
                "trust_boundary_mismatches",
                str(item.get("title") or item.get("description") or item.get("mismatch_id") or "Trust Boundary Mismatch"),
                str(item.get("attack_class") or "CROSS_SERVICE_TRUST_MISMATCH"),
                str(item.get("consumer_path") or item.get("producer_path") or item.get("path") or ""),
                list(item.get("evidence_ids", [])),
                item,
            )

    # 4b. cross_repo_and_arch_review.json -> stride_review (E7) and pattern_checklist (V16) issues
    for block, prefix in (("stride_review", "STRIDE"), ("pattern_checklist", "PATTERN")):
        review = arch.get(block) if isinstance(arch.get(block), dict) else {}
        for s_key, s_item in review.items():
            if isinstance(s_item, dict) and str(s_item.get("review_status")) == "issue_found":
                for iss in s_item.get("issues") or []:
                    if isinstance(iss, dict):
                        _add_candidate(
                            block,
                            str(iss.get("title") or s_key),
                            f"{prefix}_{str(s_key).upper()}",
                            str(iss.get("target_path") or iss.get("path") or ""),
                            list(iss.get("evidence_ids", [])),
                            iss,
                        )

    # 5. cross_repo_and_arch_review.json -> contract_drift_findings[]
    for item in arch.get("contract_drift_findings", []):
        if isinstance(item, dict):
            _add_candidate(
                "contract_drift_findings",
                str(item.get("title") or item.get("description") or "Contract Drift Finding"),
                str(item.get("attack_class") or "CONTRACT_DRIFT"),
                str(item.get("path") or item.get("endpoint") or ""),
                list(item.get("evidence_ids", [])),
                item,
            )

    # 6. coverage_ledger.json / coverage_matrix.json -> flagged records
    combined_records = list(ledger.get("records", [])) + list(matrix.get("records", []))
    for rec in combined_records:
        if isinstance(rec, dict) and str(rec.get("status", "")) in {"flagged_for_phase_2", "reopened", "failed_hypothesis"}:
            cid_str = str(rec.get("coverage_id") or "")
            _add_candidate(
                "coverage_ledger_flagged",
                f"Flagged Coverage Record: {cid_str}",
                str(rec.get("attack_class") or "COVERAGE_FLAGGED"),
                str(rec.get("target_module") or cid_str),
                list(rec.get("evidence_ids", [])),
                rec,
            )

    # 7. inventory_repo.json -> secret_leads[], dependency_leads[], and external_tool_leads[]
    for s_lead in inv.get("secret_leads", []):
        if isinstance(s_lead, dict):
            _add_candidate(
                "inventory_leads",
                f"Secret Candidate Lead ({s_lead.get('lead_type', 'secret')}) at {s_lead.get('path', '')}:{s_lead.get('line', 1)}",
                "HARDCODED_SECRET_LEAD",
                f"{s_lead.get('path', '')}:{s_lead.get('line', 1)}",
                [],
                s_lead,
            )
    for d_lead in inv.get("dependency_leads", []):
        if isinstance(d_lead, dict) and d_lead.get("vulnerable_or_flagged"):
            _add_candidate(
                "inventory_leads",
                f"Dependency Lead ({d_lead.get('ecosystem', 'dep')}) in {d_lead.get('path', '')}",
                "DEPENDENCY_RISK_LEAD",
                str(d_lead.get("path", "")),
                [],
                d_lead,
            )
    for ext_lead in inv.get("external_tool_leads", []):
        if isinstance(ext_lead, dict):
            _add_candidate(
                "external_tool_leads",
                f"External Tool Lead ({ext_lead.get('tool', 'scanner')}:{ext_lead.get('rule_id', 'rule')}): {ext_lead.get('title', '')}",
                str(ext_lead.get("rule_id") or "EXTERNAL_SCANNER_LEAD"),
                f"{ext_lead.get('path', '')}:{ext_lead.get('line', 1)}",
                [],
                ext_lead,
            )

    # E6: the same issue arrives from up to 5 sources (vinfast-mcp trial: 49 candidates, ~12 issues). Keep every
    # candidate for accountability, but link likely duplicates so 2.1 batches by group instead of re-deriving it by hand:
    # mostly the same evidence ids, OR the same source file (a path with an extension), OR the same directory-level
    # target with the same attack class. Sources label classes differently (BOLA_IDOR vs CROSS_SERVICE_TRUST_MISMATCH vs
    # privacy) for the same issue, so evidence and file are the stronger signals.
    # V1: in the vinfast-mcp run 2 these rules produced one group of 48/72 candidates: "generic" source labels
    # (cluster outliers, flagged coverage records) matched every class in the same file and bridged unrelated issues.
    # Now only specific candidates link to each other; each generic one is attached afterwards to the single closest
    # group without merging groups, and a group above MAX_GROUP is split back by attack class.
    generic_classes = {"CLUSTER_OUTLIER_REVIEW", "COVERAGE_FLAGGED", "UNVERIFIED_SURFACE", "BOLA_IDOR_FLAGGED"}
    MAX_GROUP = 12
    parent = list(range(len(candidates)))

    def _find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def _file_of(c: dict[str, Any]) -> str:
        return str(c.get("target_path") or "").split(":", 1)[0].strip().lstrip("./")

    def _is_generic(c: dict[str, Any]) -> bool:
        title = str(c.get("title") or "")
        return c["attack_class"] in generic_classes or title.startswith(("Flagged Coverage Record", "Cluster Outlier", "Contradicted Surface"))

    def _jaccard(a: dict[str, Any], b: dict[str, Any]) -> float:
        ea, eb = set(a["evidence_ids"]), set(b["evidence_ids"])
        return len(ea & eb) / len(ea | eb) if ea and eb else 0.0

    specific = [i for i, c in enumerate(candidates) if not _is_generic(c)]
    for x, i in enumerate(specific):
        for j in specific[x + 1:]:
            a, b = candidates[i], candidates[j]
            fa, fb = _file_of(a), _file_of(b)
            same_file_class = bool(fa) and fa == fb and a["attack_class"] == b["attack_class"]
            ha, hb = a.get("root_cause_hint") or "", b.get("root_cause_hint") or ""
            if ha and hb and ha != hb:
                continue  # two different declared root causes are never merged by heuristics
            if same_file_class or _jaccard(a, b) >= 0.5:
                parent[_find(i)] = _find(j)
    for i, c in enumerate(candidates):
        if i in specific:
            continue
        best, best_score = None, 0.0
        for j in specific:
            score = _jaccard(c, candidates[j]) + (0.5 if _file_of(c) and _file_of(c) == _file_of(candidates[j]) else 0.0)
            if score > best_score:
                best, best_score = j, score
        if best is not None and best_score >= 0.5:
            parent[i] = _find(best)
    # V1: candidates whose Phase 1 step declared the same root_cause_hint belong together whatever their file or class
    # (vinfast-mcp run 3: ~14 groups were all the unsigned-identity-header root cause under different labels).
    by_hint: dict[str, int] = {}
    for i, c in enumerate(candidates):
        h = c.get("root_cause_hint") or ""
        if not h:
            continue
        if h in by_hint:
            parent[_find(i)] = _find(by_hint[h])
        else:
            by_hint[h] = i
    groups: dict[int, list[dict[str, Any]]] = {}
    for i, c in enumerate(candidates):
        groups.setdefault(_find(i), []).append(c)
    # Split only heuristic groups; a group held together by one declared root cause stays whole
    oversized = [
        k for k, m in groups.items()
        if len(m) > MAX_GROUP and len({c.get("root_cause_hint") for c in m if c.get("root_cause_hint")}) != 1
    ]
    for k in oversized:
        members = groups.pop(k)
        # Split by declared root cause first; only hint-less members fall back to attack class
        by_key: dict[str, list[dict[str, Any]]] = {}
        for c in members:
            key = ("hint:" + c["root_cause_hint"]) if c.get("root_cause_hint") else ("class:" + c["attack_class"])
            by_key.setdefault(key, []).append(c)
        for idx, sub in enumerate(by_key.values()):
            groups[-(k * 1000 + idx + 1)] = sub
    duplicate_groups: list[dict[str, Any]] = []
    for members in sorted(groups.values(), key=lambda m: m[0]["candidate_id"]):
        gid = "grp_" + hashlib.sha256("|".join(sorted(c["candidate_id"] for c in members)).encode("utf-8")).hexdigest()[:10]
        for c in members:
            c["duplicate_group_id"] = gid
            c["duplicate_group_size"] = len(members)
        duplicate_groups.append({
            "duplicate_group_id": gid,
            "attack_class": members[0]["attack_class"],
            "target_files": sorted({_file_of(c) for c in members if _file_of(c)}),
            "candidate_ids": [c["candidate_id"] for c in members],
            "titles": [c["title"] for c in members][:6],
            "root_cause_hints": sorted({c["root_cause_hint"] for c in members if c.get("root_cause_hint")}),
        })

    payload = {
        "repo_name": repo_name,
        "candidate_count": len(candidates),
        "duplicate_group_count": len(duplicate_groups),
        "sources_summary": sources_summary,
        "duplicate_groups": duplicate_groups,
        "candidates": candidates,
    }
    write_json(run_dir / "candidate_queue.json", payload)
    return payload


def _normalize_boundary_target(raw_target: str, explicit_service: str = "") -> tuple[str, str, list[str]]:
    """Normalize URL/route/topic target into (service_or_host, normalized_path, non_empty_segments).
    Replaces path params (:id, {id}, <id>) with {param} and never matches bare '/' via endswith.
    """
    s = raw_target.strip()
    # Strip HTTP method prefix if present (e.g. 'POST /api/v1/orders')
    s = re.sub(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|RPC|GRPC|OCPP)\s+", "", s, flags=re.IGNORECASE).strip()
    host = explicit_service.strip().lower()
    if "://" in s:
        _, rest = s.split("://", 1)
        if "/" in rest:
            raw_host, path_part = rest.split("/", 1)
            path_part = "/" + path_part
        else:
            raw_host, path_part = rest, ""
        raw_host = raw_host.split(":", 1)[0].strip().lower()
        if raw_host and raw_host not in {"localhost", "127.0.0.1", "0.0.0.0"} and not host:
            host = raw_host
        s = path_part
    s = s.split("?", 1)[0].split("#", 1)[0].strip()
    raw_segments = [seg.strip() for seg in s.strip("/").split("/") if seg.strip()]
    norm_segments: list[str] = []
    for seg in raw_segments:
        if (
            seg.startswith(":")
            or (seg.startswith("{") and seg.endswith("}"))
            or (seg.startswith("<") and seg.endswith(">"))
        ):
            norm_segments.append("{param}")
        else:
            norm_segments.append(seg.lower())
    norm_path = "/" + "/".join(norm_segments) if norm_segments else ""
    return host, norm_path, norm_segments


def _extract_boundary_http_method(raw_target: str, explicit_method: str = "") -> str:
    m = explicit_method.strip().upper()
    if m in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        return m
    mt = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", raw_target.strip(), flags=re.IGNORECASE)
    return mt.group(1).upper() if mt else ""


def match_cross_repo_boundaries(project_root: Path, run_id: str = "default") -> dict[str, Any]:
    """DEPTH-4.1f: Deterministic Cross-Repo Producer/Consumer Boundary Matcher.
    Reads all <repo>/unified_surface_mapper.json and <repo>/inventory_repo.json across .localsec/runs/<run_id>/*,
    normalizes paths/hosts/parameters, matches outbound calls/producers/data_flows against inbound entrypoints/consumers,
    and flags unmatched_producers, unmatched_consumers, and auth_propagation_gaps.
    """
    project_root = Path(project_root).expanduser().resolve()
    runs_root = project_root / ".localsec" / "runs" / run_id
    producers: list[dict[str, Any]] = []
    consumers: list[dict[str, Any]] = []
    repos_scanned: list[str] = []

    if runs_root.is_dir():
        for repo_dir in sorted(runs_root.iterdir(), key=lambda p: p.name):
            if not repo_dir.is_dir() or repo_dir.name.startswith("_"):
                continue
            rname = repo_dir.name
            repos_scanned.append(rname)
            surf_file = repo_dir / "unified_surface_mapper.json"
            if surf_file.is_file():
                try:
                    raw = json.loads(surf_file.read_text(encoding="utf-8", errors="replace"))
                    surf = raw.get("result", raw) if isinstance(raw, dict) else {}
                except Exception:
                    surf = {}
                raw_out = (
                    list(surf.get("outbound_surfaces", []))
                    + list(surf.get("producers", []))
                    + list(surf.get("outbound_calls", []))
                    + list(surf.get("data_flows", []))
                )
                for out_item in raw_out:
                    if isinstance(out_item, dict):
                        target_val = str(
                            out_item.get("target")
                            or out_item.get("destination")
                            or out_item.get("route")
                            or out_item.get("topic")
                            or out_item.get("channel")
                            or ""
                        ).strip()
                        if not target_val:
                            continue
                        raw_id_prop = out_item.get("identity_forwarding") or out_item.get("identity_propagation")
                        has_explicit_auth = (
                            raw_id_prop is not None
                            or "forwards_auth" in out_item
                            or "auth_forwarded" in out_item
                        )
                        if not has_explicit_auth:
                            id_prop = "unknown"
                            fw_auth = False
                        else:
                            id_prop = str(raw_id_prop or "").strip().lower()
                            if "forwards_auth" in out_item:
                                fw_auth = bool(out_item["forwards_auth"])
                            elif "auth_forwarded" in out_item:
                                fw_auth = bool(out_item["auth_forwarded"])
                            else:
                                fw_auth = id_prop not in {"none", "stripped", "absent", "false", "unknown", ""}
                        producers.append({
                            "repo_name": rname,
                            "target": target_val,
                            "method": _extract_boundary_http_method(target_val, str(out_item.get("method") or "")),
                            "target_service": str(out_item.get("target_service") or out_item.get("service") or "").strip().lower(),
                            "protocol": str(out_item.get("protocol") or "http").lower(),
                            "identity_forwarding": id_prop or ("forwarded" if fw_auth else "none"),
                            "forwards_auth": fw_auth,
                            "path": str(out_item.get("path") or out_item.get("source") or ""),
                            "evidence_ids": list(out_item.get("evidence_ids", [])),
                        })
                for in_item in list(surf.get("entrypoints", [])) + list(surf.get("inbound_surfaces", [])) + list(surf.get("consumers", [])):
                    if isinstance(in_item, dict):
                        target_val = str(
                            in_item.get("route")
                            or in_item.get("path")
                            or in_item.get("target")
                            or in_item.get("topic")
                            or in_item.get("channel")
                            or in_item.get("endpoint")
                            or ""
                        ).strip()
                        if not target_val:
                            continue
                        authn_str = str(in_item.get("authn", "")).lower()
                        expects_auth = bool(in_item.get("expects_auth", in_item.get("requires_auth", authn_str not in {"none", "public", "anonymous"})))
                        consumers.append({
                            "repo_name": rname,
                            "target": target_val,
                            "method": _extract_boundary_http_method(target_val, str(in_item.get("method") or "")),
                            "protocol": str(in_item.get("protocol") or "http").lower(),
                            "expects_auth": expects_auth,
                            "assumes_upstream_auth": bool(in_item.get("assumes_upstream_auth", "upstream" in authn_str or "gateway_trusted" in authn_str)),
                            "path": str(in_item.get("file") or in_item.get("path") or ""),
                            "evidence_ids": list(in_item.get("evidence_ids", [])),
                        })

    matched_edges: list[dict[str, Any]] = []
    unmatched_producers: list[dict[str, Any]] = []
    unmatched_consumers: list[dict[str, Any]] = []
    auth_propagation_gaps: list[dict[str, Any]] = []
    matched_consumer_indices: set[int] = set()

    for prod in producers:
        ptarget = prod["target"]
        pmethod = prod.get("method", "")
        phost, pnorm, psegs = _normalize_boundary_target(ptarget, prod.get("target_service", ""))
        candidates_for_prod: list[tuple[int, str]] = []
        for c_idx, cons in enumerate(consumers):
            if cons["repo_name"] == prod["repo_name"]:
                continue
            cmethod = cons.get("method", "")
            if pmethod and cmethod and pmethod != cmethod:
                continue
            ctarget = cons["target"]
            chost, cnorm, csegs = _normalize_boundary_target(ctarget)
            if not pnorm or not cnorm:
                continue
            if phost and chost and phost != chost and phost != cons["repo_name"].lower():
                continue
            if phost and not chost and phost not in {cons["repo_name"].lower(), _safe_name(cons["repo_name"]).lower()} and len(repos_scanned) > 2:
                # If producer explicitly named another repo/service host, require consumer repo match when possible
                if any(phost == r.lower() or phost == _safe_name(r).lower() for r in repos_scanned):
                    continue
            literal_generic = {"api", "v1", "v2", "v3", "internal", "public", "private", "admin", "{param}"}
            if pnorm == cnorm:
                candidates_for_prod.append((c_idx, "exact"))
            else:
                shorter_segs = psegs if len(psegs) <= len(csegs) else csegs
                longer_segs = csegs if len(psegs) <= len(csegs) else psegs
                # D5: a suffix match needs >= 2 specific literal segments (not params or api/v1-style prefixes),
                # otherwise `users/{param}` matches every service that has a users resource.
                specific = [sg for sg in shorter_segs if sg not in literal_generic]
                if len(shorter_segs) >= 2 and longer_segs[-len(shorter_segs):] == shorter_segs and len(specific) >= 2:
                    candidates_for_prod.append((c_idx, "suffix"))

        exact = [c for c in candidates_for_prod if c[1] == "exact"]
        chosen = exact or candidates_for_prod
        # D5: suffix-only matches into more than one consumer repo are ambiguous: keep them visible, but no auth gap
        ambiguous = not exact and len({consumers[ci]["repo_name"] for ci, _ in chosen}) > 1
        for c_idx, kind in chosen:
            cons = consumers[c_idx]
            matched_consumer_indices.add(c_idx)
            cnorm = _normalize_boundary_target(cons["target"])[1]
            edge = {
                "producer_repo": prod["repo_name"],
                "consumer_repo": cons["repo_name"],
                "target": ptarget,
                "normalized_target": cnorm,
                "protocol": prod["protocol"],
                "method": pmethod or cons.get("method", ""),
                "match_kind": kind,
                "ambiguous": ambiguous,
                "producer_path": prod["path"],
                "consumer_path": cons["path"],
                "producer_evidence_ids": prod["evidence_ids"],
                "consumer_evidence_ids": cons["evidence_ids"],
            }
            matched_edges.append(edge)
            if ambiguous:
                continue
            if (not prod["forwards_auth"] and cons["expects_auth"]) or cons["assumes_upstream_auth"]:
                if cons["assumes_upstream_auth"]:
                    gap_reason = "Consumer assumes upstream auth without local verification"
                elif prod.get("identity_forwarding") == "unknown":
                    gap_reason = "Producer identity_forwarding is unspecified ('unknown') while consumer requires authentication"
                else:
                    gap_reason = "Producer does not forward auth context required by consumer"
                auth_propagation_gaps.append({
                    **edge,
                    "gap_reason": gap_reason,
                })
        if not chosen and ptarget:
            unmatched_producers.append(prod)

    for c_idx, cons in enumerate(consumers):
        if c_idx not in matched_consumer_indices and cons["target"]:
            unmatched_consumers.append(cons)

    result = {
        "run_id": run_id,
        "repos_scanned": repos_scanned,
        "matched_edges": matched_edges,
        "unmatched_producers": unmatched_producers,
        "unmatched_consumers": unmatched_consumers,
        "auth_propagation_gaps": auth_propagation_gaps,
    }
    analysis_dir = runs_root / "_analysis"
    write_json(analysis_dir / "matched_cross_repo_boundaries.json", result)
    return result


def finalize_v3_phase1(project_root: Path, repo_name: str, run_id: str = "default") -> dict[str, Any]:
    """ARCH-3D & ARCH-3G: Script-enforced Phase 1 Finalizer.
    Runs/loads inventory_repo, generate_coverage_matrix, audit_visibility_and_coverage,
    semantic claim verification with fail-closed downgrade, and build_v3_candidate_queue,
    validates/generates coverage_and_evidence_auditor.json, and writes phase1_gate_Certificate.json + phase1_gate_receipt.json.
    """
    from .config import load_config
    from .validators import OutputValidationError, validate_agent_output, verify_claim_to_excerpt_semantics

    project_root = Path(project_root).expanduser().resolve()
    run_dir = project_root / ".localsec" / "runs" / run_id / repo_name
    run_dir.mkdir(parents=True, exist_ok=True)

    inv_path = run_dir / "inventory_repo.json"
    if inv_path.is_file():
        inventory = json.loads(inv_path.read_text(encoding="utf-8", errors="replace"))
    else:
        inventory = inventory_repo(project_root, repo_name, run_id=run_id)

    scout_map: dict[str, Any] = {}
    if (run_dir / "codebase_scout.json").is_file():
        raw_scout = json.loads((run_dir / "codebase_scout.json").read_text(encoding="utf-8", errors="replace"))
        scout_map = raw_scout.get("result", raw_scout) if isinstance(raw_scout, dict) else {}

    scout_validation = validate_scout_map_against_inventory(scout_map, inventory)

    repo_root = (project_root / repo_name) if (project_root / repo_name).is_dir() else project_root
    cfg = load_config(None)["analysis"]
    ws = ManualWorkspace(repo_root, repo_name, cfg, run_id, project_root=project_root)
    ws_state_file = run_dir / "workspace_state.json"
    if ws_state_file.is_file():
        try:
            ws_state = json.loads(ws_state_file.read_text(encoding="utf-8", errors="replace"))
            ws.evidence = ws_state.get("evidence", {})
            ws.tool_log = ws_state.get("tool_log", [])
            ws.read_ranges = {
                k: [tuple(pair) for pair in v]
                for k, v in ws_state.get("read_ranges", {}).items()
            }
            ws.deferred_out_of_budget = list(ws_state.get("deferred_out_of_budget", []))
        except Exception:
            pass

    auditor_errors: list[str] = []
    auditor_path = run_dir / "coverage_and_evidence_auditor.json"
    existing_aud_payload: dict[str, Any] = {}
    if auditor_path.is_file():
        try:
            raw_aud = json.loads(auditor_path.read_text(encoding="utf-8", errors="replace"))
            existing_aud_payload = raw_aud.get("result", raw_aud) if isinstance(raw_aud, dict) else raw_aud
            validate_agent_output("coverage_and_evidence_auditor", existing_aud_payload, set(ws.evidence.keys()) or None)
        except OutputValidationError as exc:
            auditor_errors.append(str(exc))
        except Exception as exc:
            auditor_errors.append(str(exc))

    # ARCH-3D: Run deterministic semantic claim verifier on Phase 1 outputs and automatically downgrade contradicted claims fail-closed
    semantic_downgrades: list[dict[str, Any]] = []
    for p1_skill in ("intent_invariant_modeler", "unified_surface_mapper", "cross_repo_and_arch_review"):
        sf = run_dir / f"{p1_skill}.json"
        if not sf.is_file():
            continue
        try:
            raw_s = json.loads(sf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        res_obj = raw_s.get("result") if isinstance(raw_s.get("result"), dict) else raw_s
        if not isinstance(res_obj, dict):
            continue
        modified = False
        for list_key in ("invariants", "anomalies", "intent_vs_code_gaps", "invariant_checks", "entrypoints", "trust_boundary_mismatches"):
            items = res_obj.get(list_key)
            if not isinstance(items, list):
                continue
            for idx, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                eids = [str(e) for e in (item.get("evidence_ids") or item.get("implementation_evidence_ids") or []) if str(e).startswith("ev_")]
                if eids:
                    contradictions = verify_claim_to_excerpt_semantics(item, eids, ws.evidence)
                    if contradictions:
                        old_status = item.get("status", "observed")
                        item["status"] = "hypothesis"
                        item["confidence"] = "low"
                        item["downgraded_by_semantic_gate"] = True
                        item["semantic_contradictions"] = contradictions
                        modified = True
                        semantic_downgrades.append({
                            "claim_ref": f"{p1_skill}:{list_key}[{idx}]",
                            "previous_status": old_status,
                            "new_status": "hypothesis",
                            "contradictions": contradictions,
                        })
        if modified:
            write_json(sf, raw_s)

    if isinstance(existing_aud_payload, dict):
        for ca in existing_aud_payload.get("claim_audits", []):
            if isinstance(ca, dict) and str(ca.get("verdict") or "").lower() in {"unsupported", "partially_supported"}:
                semantic_downgrades.append({
                    "claim_ref": str(ca.get("claim_id") or ca.get("claim_ref") or "audited_claim"),
                    "previous_status": "observed",
                    "new_status": "hypothesis",
                    "contradictions": [str(ca.get("notes") or ca.get("verdict") or "Unsupported claim flagged by auditor")],
                })

    surface_map: dict[str, Any] = {}
    if (run_dir / "unified_surface_mapper.json").is_file():
        surface_map = json.loads((run_dir / "unified_surface_mapper.json").read_text(encoding="utf-8", errors="replace"))

    matrix = generate_coverage_matrix(run_dir, repo_name)
    cand_queue = build_v3_candidate_queue(run_dir, repo_name)

    ledger_data: dict[str, Any] | None = None
    if (run_dir / "coverage_ledger.json").is_file():
        try:
            ledger_data = json.loads((run_dir / "coverage_ledger.json").read_text(encoding="utf-8", errors="replace"))
        except Exception:
            ledger_data = None

    vis_audit = audit_visibility_and_coverage(
        workspace=ws,
        scout_map=scout_map or None,
        coverage_ledger=ledger_data,
        inventory=inventory,
        surface_map=surface_map or None,
    )

    arch_for_stride: dict[str, Any] = {}
    arch_fp = run_dir / "cross_repo_and_arch_review.json"
    if arch_fp.is_file():
        try:
            raw_arch = json.loads(arch_fp.read_text(encoding="utf-8", errors="replace"))
            arch_for_stride = raw_arch.get("result", raw_arch) if isinstance(raw_arch, dict) else {}
        except Exception:
            arch_for_stride = {}
    stride_errors = check_stride_review(arch_for_stride, set(ws.evidence.keys()) or None)
    stride_errors += check_pattern_checklist(arch_for_stride, set(ws.evidence.keys()) or None)

    gate_passed = bool(
        scout_validation.get("valid", True)
        and vis_audit.get("gate_passed", False)
        and not auditor_errors
        and not stride_errors
    )

    authoritative_auditor = {
        "skill": "coverage_and_evidence_auditor",
        "version": "3.0.0",
        "status": "ok",
        "result": {
            "repo_name": repo_name,
            "gate_passed": gate_passed,
            "visibility_audit_passed": bool(vis_audit.get("gate_passed", False)),
            "evidence_audit_passed": len(auditor_errors) == 0,
            "visibility_report": vis_audit.get("visibility_report", {}),
            "downgraded_claims": semantic_downgrades,
            "claim_audits": existing_aud_payload.get("claim_audits", []) if isinstance(existing_aud_payload, dict) else [],
            "blocker_reasons": (
                list(vis_audit.get("visibility_report", {}).get("unvisited_target_modules", []))
                + list(vis_audit.get("visibility_report", {}).get("grazed_files", []))
                + list(vis_audit.get("visibility_report", {}).get("partially_read_mandatory_files", []))
                + list(vis_audit.get("visibility_report", {}).get("under_read_target_modules", []))
                + auditor_errors
                + stride_errors
            ),
            "summary": (
                f"Authoritative Phase 1 audit finalized (gate_passed={gate_passed}, "
                f"downgrades={len(semantic_downgrades)}, candidates={cand_queue.get('candidate_count', 0)})."
            ),
        },
    }
    write_json(auditor_path, authoritative_auditor)

    cert = {
        "phase": "phase_1",
        "repo_name": repo_name,
        "run_id": run_id,
        "gate_passed": gate_passed,
        "scout_inventory_validation": scout_validation,
        "visibility_audit": vis_audit,
        "semantic_downgrades": semantic_downgrades,
        "coverage_matrix_records": matrix.get("record_count", 0),
        "candidate_queue_count": cand_queue.get("candidate_count", 0),
        "auditor_validation_errors": auditor_errors,
        "stride_review_errors": stride_errors,
    }
    write_json(run_dir / "phase1_gate_Certificate.json", cert)
    write_json(run_dir / "phase1_gate_receipt.json", cert)
    return cert


# E7: a STRIDE + hardening pass in step 1.5. The vinfast-mcp trial missed exactly the classes the attack-class
# companions do not cover (client-side supply chain / SRI, DoS by design, audit gaps, one service credential for all users).
STRIDE_REVIEW_KEYS = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
    "client_side_supply_chain",
    "shared_service_credentials",
)


# V16: fixed checklist of recurring weakness patterns. Run-to-run variance in the vinfast-mcp trials came from Phase 1
# candidate generation (run 2 never raised "booking state kept in process memory" that run 1 found); a fixed list makes
# every run look at the same places.
PATTERN_CHECKLIST_KEYS = (
    "process_local_state_multi_replica",
    "client_asserted_identity_or_ownership",
    "client_controlled_state_or_flags",
    "ownership_check_on_every_object_access",
    "replay_and_idempotency",
    "llm_or_tool_argument_trust",
    "outbound_url_fetch",
    "environment_gated_controls",
    "debug_error_and_metadata_exposure",
    "secrets_in_code_or_config",
)


def check_stride_review(arch: dict[str, Any] | None, valid_evidence_ids: set[str] | None = None) -> list[str]:
    """Return gate errors for cross_repo_and_arch_review.stride_review (empty list = complete)."""
    return _check_review_block(arch, "stride_review", STRIDE_REVIEW_KEYS, valid_evidence_ids)


def check_pattern_checklist(arch: dict[str, Any] | None, valid_evidence_ids: set[str] | None = None) -> list[str]:
    """Return gate errors for cross_repo_and_arch_review.pattern_checklist (empty list = complete)."""
    return _check_review_block(arch, "pattern_checklist", PATTERN_CHECKLIST_KEYS, valid_evidence_ids)


def _check_review_block(
    arch: dict[str, Any] | None,
    field: str,
    keys: tuple[str, ...],
    valid_evidence_ids: set[str] | None = None,
) -> list[str]:
    review = arch.get(field) if isinstance(arch, dict) else None
    if not isinstance(review, dict):
        return [f"{field} missing in cross_repo_and_arch_review (step 1.5 must cover " + ", ".join(keys) + ")"]
    errors: list[str] = []

    def _ev_ok(ids: Any) -> bool:
        vals = [str(e) for e in (ids or []) if str(e).startswith("ev_")]
        return bool(vals) and (not valid_evidence_ids or all(v in valid_evidence_ids for v in vals))

    for key in keys:
        item = review.get(key)
        if not isinstance(item, dict):
            errors.append(f"{field}.{key} missing")
            continue
        st = str(item.get("review_status") or "")
        if st == "not_applicable":
            if len(str(item.get("reason") or "").strip()) < 20:
                errors.append(f"{field}.{key}: not_applicable needs a reason of >= 20 characters")
        elif st == "checked_none":
            if not item.get("checked_paths") or not _ev_ok(item.get("evidence_ids")):
                errors.append(f"{field}.{key}: checked_none needs checked_paths and real ev_ evidence_ids")
        elif st == "issue_found":
            issues = [i for i in (item.get("issues") or []) if isinstance(i, dict)]
            if not issues or any(not str(i.get("title") or "").strip() or not _ev_ok(i.get("evidence_ids")) for i in issues):
                errors.append(f"{field}.{key}: issue_found needs issues[] each with title and real ev_ evidence_ids")
        else:
            errors.append(f"{field}.{key}.review_status must be issue_found | checked_none | not_applicable")
    return errors


CHALLENGER_RECONCILIATION_MATRIX = {
    "confirmed_exploit_chain": "REACHABLE_VULNERABILITY",
    "sustained": "REACHABLE_VULNERABILITY",
    "upheld": "REACHABLE_VULNERABILITY",
    "mitigated_by_existing_control": "REFUTED_FALSE_POSITIVE",
    "refuted": "REFUTED_FALSE_POSITIVE",
    "broken_link": "REFUTED_FALSE_POSITIVE",
    "needs_runtime_verification": "HYPOTHESIS_ONLY_UNVERIFIED",
    # Code path exists and a control covers only part of it: residual risk is real, so it stays in Phase 3 scope
    # (was HYPOTHESIS_ONLY_UNVERIFIED, which dropped the highest-severity chain of the vinfast-mcp trial out of Phase 3).
    "partially_mitigated": "REACHABLE_PARTIALLY_MITIGATED",
}

SURVIVING_RECONCILED_STATUSES = {"REACHABLE_VULNERABILITY", "REACHABLE_PARTIALLY_MITIGATED"}


def chains_fingerprint(deep_trace: dict[str, Any] | None) -> str:
    """V18: content fingerprint of what the blinded challenger must challenge (chain ids + hop locations).
    prepare_blinded_chain_verifier writes it into the package, the challenger copies it into its output, and
    finalize_v3_phase2 compares it with the current 2.2 chains instead of comparing file timestamps."""
    raw = (deep_trace or {}).get("chains") or (deep_trace or {}).get("verified_chains") or []
    canon = []
    for ch in raw:
        if not isinstance(ch, dict):
            continue
        hops = [
            (str(h.get("file") or h.get("path") or ""), int(h.get("line_start") or 0), int(h.get("line_end") or 0))
            for h in (ch.get("hops") or [])
            if isinstance(h, dict)
        ]
        canon.append((str(ch.get("chain_id") or ""), sorted(str(c) for c in (ch.get("candidate_ids") or [])), hops))
    canon.sort()
    return "sha256:" + hashlib.sha256(json.dumps(canon, ensure_ascii=False).encode("utf-8")).hexdigest()


def finalize_v3_phase2(project_root: Path, repo_name: str, run_id: str = "default") -> dict[str, Any]:
    """ARCH-3D, ARCH-3G, ARCH-3H: Script-enforced Phase 2 Finalizer.
    Verifies every candidate in candidate_queue.json is accounted for, verifies blinded_counterevidence_challenger
    is fresh and complete (all chains challenged + 6-location checklist), enforces request_plan_is_not_execution
    and the Challenger Reconciliation Matrix (fail-closed), and writes phase2_gate_Certificate.json,
    phase2_gate_receipt.json, analysis_evidence_gate.json, and phase3_verified_queue.json.
    """
    project_root = Path(project_root).expanduser().resolve()
    run_dir = project_root / ".localsec" / "runs" / run_id / repo_name
    run_dir.mkdir(parents=True, exist_ok=True)

    dt_file = run_dir / "deep_trace_chain_analyst.json"
    ch_file = run_dir / "blinded_counterevidence_challenger.json"
    dt_mtime = dt_file.stat().st_mtime if dt_file.is_file() else 0.0
    ch_mtime = ch_file.stat().st_mtime if ch_file.is_file() else 0.0
    stale_challenger = bool(dt_mtime and ch_mtime and ch_mtime + 0.001 < dt_mtime)
    # V18: when the challenger output carries the package fingerprint, freshness is decided by content: a 2.2
    # resubmit with unchanged chains is not stale, and an old 2.3 output resubmitted after the chains changed is.
    challenger_fingerprint = ""
    if ch_file.is_file():
        try:
            raw_ch = json.loads(ch_file.read_text(encoding="utf-8", errors="replace"))
            raw_ch = raw_ch.get("result", raw_ch) if isinstance(raw_ch, dict) and isinstance(raw_ch.get("result"), dict) else raw_ch
            challenger_fingerprint = str((raw_ch or {}).get("blinded_package_fingerprint") or "")
        except Exception:
            challenger_fingerprint = ""
    current_fingerprint = ""
    if dt_file.is_file():
        try:
            raw_dt_fp = json.loads(dt_file.read_text(encoding="utf-8", errors="replace"))
            raw_dt_fp = raw_dt_fp.get("result", raw_dt_fp) if isinstance(raw_dt_fp, dict) and isinstance(raw_dt_fp.get("result"), dict) else raw_dt_fp
            current_fingerprint = chains_fingerprint(raw_dt_fp if isinstance(raw_dt_fp, dict) else {})
        except Exception:
            current_fingerprint = ""
    if challenger_fingerprint:
        stale_challenger = challenger_fingerprint != current_fingerprint

    def _load(fname: str) -> dict[str, Any]:
        fp = run_dir / fname
        if fp.is_file():
            try:
                raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw, dict):
                    return raw.get("result", raw) if isinstance(raw.get("result"), dict) else raw
            except Exception:
                pass
        return {}

    cand_queue = _load("candidate_queue.json")
    deep_trace = _load("deep_trace_chain_analyst.json")
    challenger = _load("blinded_counterevidence_challenger.json")
    ev_gate = _load("analysis_evidence_gate.json")

    ws_evidence_ids: set[str] = set()
    for ev_fname in ("workspace_state.json", "evidence.json"):
        ev_fp = run_dir / ev_fname
        if ev_fp.is_file():
            try:
                ev_raw = json.loads(ev_fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(ev_raw, dict):
                    ev_map = ev_raw.get("evidence", ev_raw)
                    if isinstance(ev_map, dict):
                        ws_evidence_ids.update(str(k) for k in ev_map.keys() if str(k).startswith("ev_"))
            except Exception:
                pass

    challenger_by_id: dict[str, dict[str, Any]] = {}
    raw_challenges = (
        challenger.get("challenged_chains")
        or challenger.get("step_challenges")
        or challenger.get("challenges")
        or challenger.get("chain_challenges")
        or []
    )
    for ch in raw_challenges:
        if isinstance(ch, dict):
            for k in ("chain_id", "candidate_id", "finding_id"):
                cid = str(ch.get(k) or "").strip()
                if cid:
                    challenger_by_id[cid] = ch

    verified_phase3_findings: list[dict[str, Any]] = []
    refuted_ledger: list[dict[str, Any]] = []
    hypothesis_only: list[dict[str, Any]] = []
    # V17: a chain refuted as broken_link only proves the hops do not connect, not that each weakness is false
    broken_link_splits: list[dict[str, Any]] = []
    reconciliation_log: list[dict[str, Any]] = []
    accounted_candidate_ids: set[str] = set()
    unchallenged_chains: list[str] = []
    incomplete_checklist_chains: list[str] = []

    required_6_locations = {
        "global_middleware_or_filter",
        "gateway_or_ingress_config",
        "service_or_domain_guard",
        "orm_global_filter_or_scoped_query",
        "db_constraint_rls_or_trigger",
        "upstream_caller_validation",
    }

    for unexp in deep_trace.get("unexploitable_candidates", []):
        if isinstance(unexp, dict):
            unexp_eids = [
                str(e)
                for e in (unexp.get("evidence_ids") or [])
                if str(e).startswith("ev_") and bool(ws_evidence_ids and str(e) in ws_evidence_ids)
            ]
            unexp_reason = str(unexp.get("reason") or unexp.get("rationale") or "").strip()
            if unexp_eids and len(unexp_reason) >= 10:
                for k in ("candidate_id", "id", "chain_id"):
                    if unexp.get(k):
                        accounted_candidate_ids.add(str(unexp[k]))
                refuted_ledger.append({
                    "candidate_id": str(unexp.get("candidate_id") or unexp.get("id") or ""),
                    "refutation_reason": unexp_reason,
                    "counterevidence_ids": unexp_eids,
                })

    chains = list(deep_trace.get("chains") or deep_trace.get("verified_chains") or [])
    if not chains and ev_gate.get("verified_phase2_findings"):
        chains = list(ev_gate.get("verified_phase2_findings", []))

    dt_modified = False
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        chain_id = str(chain.get("chain_id") or chain.get("candidate_id") or chain.get("finding_id") or "")
        cand_id = str(chain.get("candidate_id") or chain_id)
        if cand_id:
            accounted_candidate_ids.add(cand_id)
        if chain_id:
            accounted_candidate_ids.add(chain_id)
        for cid_item in list(chain.get("candidate_ids") or []) + list(chain.get("source_candidate_ids") or []):
            if cid_item:
                accounted_candidate_ids.add(str(cid_item))

        # ARCH-3D: Enforce request_plan_is_not_execution (cap unexecuted 'confirmed' chains to 'code_supported')
        rplan = chain.get("request_plan") or chain.get("request_sequence_plan") or {}
        exec_status = rplan.get("execution_status") if isinstance(rplan, dict) else chain.get("execution_status", "not_executed")
        effective_chain_verdict = str(chain.get("chain_verdict") or "code_supported")
        if effective_chain_verdict == "confirmed" and exec_status != "executed":
            effective_chain_verdict = "code_supported"
            chain["chain_verdict"] = "code_supported"
            dt_modified = True

        ch_entry = challenger_by_id.get(chain_id) or challenger_by_id.get(cand_id)
        if not ch_entry:
            for cid_item in list(chain.get("candidate_ids") or []) + list(chain.get("source_candidate_ids") or []):
                if str(cid_item) in challenger_by_id:
                    ch_entry = challenger_by_id[str(cid_item)]
                    break

        if not ch_entry:
            ch_verdict = "unchallenged"
            reconciled_status = "UNCHALLENGED_BLOCKED"
            unchallenged_chains.append(chain_id or cand_id)
        else:
            raw_verdict = str(
                ch_entry.get("challenge_verdict")
                or ch_entry.get("challenger_verdict")
                or ch_entry.get("verdict")
                or ch_entry.get("overall_challenge_outcome")
                or ""
            ).strip()
            if raw_verdict not in CHALLENGER_RECONCILIATION_MATRIX:
                ch_verdict = raw_verdict or "unchallenged"
                reconciled_status = "UNCHALLENGED_BLOCKED"
                unchallenged_chains.append(chain_id or cand_id)
            else:
                ch_verdict = raw_verdict
                reconciled_status = CHALLENGER_RECONCILIATION_MATRIX[ch_verdict]

            checklist = ch_entry.get("control_search_checklist")
            checklist_entries: list[dict[str, Any]] = []
            if isinstance(checklist, list):
                seen_locs = {
                    str(c.get("location") or c.get("control_location") or "").strip()
                    for c in checklist
                    if isinstance(c, dict)
                }
                checklist_entries = [c for c in checklist if isinstance(c, dict)]
                if not required_6_locations.issubset(seen_locs):
                    incomplete_checklist_chains.append(chain_id or cand_id)
            elif isinstance(checklist, dict):
                seen_locs = {str(k).strip() for k in checklist.keys()}
                checklist_entries = [v for v in checklist.values() if isinstance(v, dict)]
                if not required_6_locations.issubset(seen_locs):
                    incomplete_checklist_chains.append(chain_id or cand_id)
            elif "control_search_checklist" in ch_entry:
                incomplete_checklist_chains.append(chain_id or cand_id)

            if checklist_entries:
                na_count = 0
                checklist_invalid = False
                for c_item in checklist_entries:
                    cst = str(c_item.get("status") or "").strip().lower()
                    if cst == "not_applicable":
                        na_count += 1
                        na_reason = str(c_item.get("reason") or c_item.get("rationale") or c_item.get("notes") or "").strip()
                        if len(na_reason) < 20:
                            checklist_invalid = True
                    elif cst in {"checked_found", "checked_not_found"}:
                        c_eids = [
                            str(e)
                            for e in (c_item.get("evidence_ids") or [])
                            if str(e).startswith("ev_") and bool(ws_evidence_ids and str(e) in ws_evidence_ids)
                        ]
                        if not c_eids:
                            checklist_invalid = True
                if na_count >= len(required_6_locations) or checklist_invalid:
                    if (chain_id or cand_id) not in incomplete_checklist_chains:
                        incomplete_checklist_chains.append(chain_id or cand_id)

            # C8: Re-verify refutation counterevidence directly in finalize_v3_phase2 (never fall back to chain.evidence_ids)
            if reconciled_status == "REFUTED_FALSE_POSITIVE":
                raw_counter_eids = list(
                    ch_entry.get("counter_evidence_ids")
                    or ch_entry.get("counterevidence_ids")
                    or []
                )
                for c_item in checklist_entries:
                    if str(c_item.get("status") or "").strip().lower() == "checked_found":
                        raw_counter_eids.extend(c_item.get("evidence_ids") or [])
                valid_counter_eids = [
                    str(e)
                    for e in raw_counter_eids
                    if isinstance(e, str) and str(e).startswith("ev_") and bool(ws_evidence_ids and str(e) in ws_evidence_ids)
                ]
                if not valid_counter_eids or (chain_id or cand_id) in incomplete_checklist_chains:
                    reconciled_status = "UNCHALLENGED_BLOCKED"
                    if (chain_id or cand_id) not in unchallenged_chains:
                        unchallenged_chains.append(chain_id or cand_id)

        reconciled_item = {
            **chain,
            "chain_id": chain_id or cand_id,
            "candidate_id": cand_id or chain_id,
            "chain_verdict": effective_chain_verdict,
            "challenger_verdict": ch_verdict,
            "challenge_verdict": ch_verdict,
            "reconciled_status": reconciled_status,
        }
        if ch_entry:
            # Carry the challenger's own reasoning forward (residual risk / existing controls), not just the verdict label
            reconciled_item["challenger_notes"] = str(
                ch_entry.get("notes") or ch_entry.get("rationale") or ch_entry.get("summary") or ch_entry.get("reason") or ""
            )
        reconciliation_log.append({
            "chain_id": chain_id or cand_id,
            "chain_verdict": effective_chain_verdict,
            "challenger_verdict": ch_verdict,
            "challenge_verdict": ch_verdict,
            "reconciled_status": reconciled_status,
        })

        if reconciled_status in SURVIVING_RECONCILED_STATUSES:
            verified_phase3_findings.append(reconciled_item)
        elif reconciled_status == "REFUTED_FALSE_POSITIVE":
            if str(ch_verdict).strip().lower() == "broken_link":
                broken_link_splits.append({
                    "chain_id": chain_id or cand_id,
                    "candidate_ids": [str(x) for x in (chain.get("candidate_ids") or chain.get("source_candidate_ids") or []) if x],
                    "hop_files": sorted({str(h.get("file") or h.get("path") or "") for h in (chain.get("hops") or []) if isinstance(h, dict)} - {""}),
                    "challenger_notes": str((ch_entry or {}).get("notes") or (ch_entry or {}).get("rationale") or ""),
                    "required_action": "assess each candidate on its own path; the broken_link verdict is not counter-evidence for them",
                })
            ch_reason = str((ch_entry or {}).get("notes") or (ch_entry or {}).get("rationale") or (ch_entry or {}).get("reason") or "").strip()
            refuted_ledger.append({
                "candidate_id": cand_id or chain_id,
                "chain_id": chain_id or cand_id,
                "refutation_reason": f"Refuted by blinded_counterevidence_challenger ({ch_verdict})" + (f": {ch_reason}" if ch_reason else ""),
                "counterevidence_ids": list(
                    (ch_entry or {}).get("counter_evidence_ids")
                    or (ch_entry or {}).get("counterevidence_ids")
                    or []
                ),
            })
        elif reconciled_status == "HYPOTHESIS_ONLY_UNVERIFIED":
            hypothesis_only.append(reconciled_item)

    if dt_modified and dt_file.is_file():
        try:
            raw_dt = json.loads(dt_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(raw_dt, dict) and isinstance(raw_dt.get("result"), dict):
                raw_dt["result"] = deep_trace
                write_json(dt_file, raw_dt)
            else:
                write_json(dt_file, deep_trace)
        except Exception:
            pass

    queued_ids = [
        str(c.get("candidate_id"))
        for c in cand_queue.get("candidates", [])
        if isinstance(c, dict) and c.get("candidate_id")
    ]
    unaccounted_candidates = [cid for cid in queued_ids if cid not in accounted_candidate_ids]

    blinded_artifact_path = project_root / ".localsec" / "tmp" / f"blinded_chains_{repo_name}.json"
    blinded_challenger_verified = bool(
        (
            ch_file.is_file()
            and not stale_challenger
            and len(unchallenged_chains) == 0
            and len(incomplete_checklist_chains) == 0
        )
        or len(chains) == 0
    )

    gate_passed = len(unaccounted_candidates) == 0 and blinded_challenger_verified

    phase3_queue = {
        "repo_name": repo_name,
        "run_id": run_id,
        "verified_findings_count": len(verified_phase3_findings),
        "verified_findings": verified_phase3_findings,
        "hypothesis_only_findings": hypothesis_only,
        "empirical_refutations_ledger": refuted_ledger,
        "broken_link_splits": broken_link_splits,
        "reconciliation_log": reconciliation_log,
    }
    write_json(run_dir / "phase3_verified_queue.json", phase3_queue)
    write_json(
        run_dir / "analysis_evidence_gate.json",
        {
            "skill": "analysis_evidence_gate",
            "version": "3.0.0",
            "status": "ok",
            "result": {
                "repo_name": repo_name,
                "gate_passed": gate_passed,
                "confirmed_reachable_chains": [f.get("chain_id") for f in verified_phase3_findings],
                "downgraded_or_refuted_chains": [r.get("chain_id") or r.get("candidate_id") for r in refuted_ledger],
                "hypothesis_only_chains": [h.get("chain_id") for h in hypothesis_only],
                "unchallenged_chains": unchallenged_chains,
                "incomplete_checklist_chains": incomplete_checklist_chains,
                "stale_challenger": stale_challenger,
                "challenger_fingerprint": challenger_fingerprint or None,
                "current_chains_fingerprint": current_fingerprint or None,
                "empirical_refutations_ledger": refuted_ledger,
                "reconciliation_log": reconciliation_log,
                "summary": (
                    f"Phase 2 gate finalized (gate_passed={gate_passed}, "
                    f"{len(verified_phase3_findings)} reachable, {len(refuted_ledger)} refuted, "
                    f"{len(unchallenged_chains)} unchallenged)."
                ),
            },
        },
    )

    cert = {
        "phase": "phase_2",
        "repo_name": repo_name,
        "run_id": run_id,
        "gate_passed": gate_passed,
        "blinded_artifact_present": blinded_artifact_path.is_file(),
        "blinded_challenger_verified": blinded_challenger_verified,
        "stale_challenger": stale_challenger,
        "chains_fingerprint": current_fingerprint or None,
        "blinded_package_fingerprint": challenger_fingerprint or None,
        "unchallenged_chains": unchallenged_chains,
        "incomplete_checklist_chains": incomplete_checklist_chains,
        "total_candidates": len(queued_ids),
        "accounted_candidates_count": len(queued_ids) - len(unaccounted_candidates),
        "unaccounted_candidates": unaccounted_candidates,
        "reachable_vulnerabilities_count": len(verified_phase3_findings),
        "refuted_false_positives_count": len(refuted_ledger),
        "hypothesis_only_count": len(hypothesis_only),
        "reconciliation_log": reconciliation_log,
    }
    write_json(run_dir / "phase2_gate_Certificate.json", cert)
    write_json(run_dir / "phase2_gate_receipt.json", cert)
    return cert


def ingest_runtime_facts(
    project_root: Path,
    repo_name: str,
    facts_path: Path | str,
    run_id: str = "default",
) -> dict[str, Any]:
    """DEPTH-4.4a: Validate and ingest operator-supplied runtime_environment_facts.json,
    and automatically recalculate Phase 3 risk with zero LLM tokens if Phase 3 artifacts exist.
    """
    project_root = Path(project_root).expanduser().resolve()
    src = Path(facts_path).expanduser().resolve()
    if not src.is_file():
        raise WorkspaceError(f"runtime facts file not found: {facts_path}")
    raw = json.loads(src.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(raw, dict):
        raise WorkspaceError("runtime_environment_facts.json must be a JSON object")

    run_dir = project_root / ".localsec" / "runs" / run_id / repo_name
    dest = run_dir / "runtime_environment_facts.json"
    normalized = {
        "repo_name": repo_name,
        "run_id": run_id,
        "ingested_from": str(src),
        "controls": raw.get("controls", raw.get("runtime_controls", [])),
        "answers": raw.get("answers", {}),
        "environment": raw.get("environment", "production"),
        "raw_facts": raw,
    }
    write_json(dest, normalized)
    recalc = None
    if (run_dir / "sfop_risk_calibrator.json").is_file() or (run_dir / "beyond_code_control_mapper.json").is_file():
        recalc = finalize_v3_phase3(project_root, repo_name, run_id=run_id)
    return {"ok": True, "repo_name": repo_name, "saved_to": str(dest), "facts": normalized, "recalculated_phase3": recalc}


def finalize_v3_phase3(project_root: Path, repo_name: str, run_id: str = "default") -> dict[str, Any]:
    """ARCH-3D, ARCH-3G, ARCH-3H & DEPTH-4.4a: Script-enforced Phase 3 Finalizer.
    Verifies surviving chain_ids from Phase 2 are accounted for, derives feasibility_derived & key_questions.json
    (including preconditions from 3.1 and beyond-code controls from 3.2 with outcome_if_yes/outcome_if_no),
    computes derived_risk_rating, cross-checks beyond_code_control_mapper.json against repo evidence and
    runtime_environment_facts.json, validates sfop_risk_calibrator.json against the 3 hard laws,
    and writes phase3_gate_Certificate.json + phase3_gate_receipt.json.
    """
    from .validators import OutputValidationError, validate_v30_epistemic_gates

    project_root = Path(project_root).expanduser().resolve()
    run_dir = project_root / ".localsec" / "runs" / run_id / repo_name
    run_dir.mkdir(parents=True, exist_ok=True)

    def _load(fname: str) -> dict[str, Any]:
        fp = run_dir / fname
        if fp.is_file():
            try:
                raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw, dict):
                    return raw.get("result", raw) if isinstance(raw.get("result"), dict) else raw
            except Exception:
                pass
        return {}

    p3_queue = _load("phase3_verified_queue.json")
    actor_map = _load("actor_and_feasibility_assessor.json")
    beyond_code = _load("beyond_code_control_mapper.json")
    runtime_facts = _load("runtime_environment_facts.json")
    sfop = _load("sfop_risk_calibrator.json")

    ws_evidence_ids: set[str] = set()
    for ev_fname in ("workspace_state.json", "evidence.json"):
        ev_fp = run_dir / ev_fname
        if ev_fp.is_file():
            try:
                ev_raw = json.loads(ev_fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(ev_raw, dict):
                    ev_map = ev_raw.get("evidence", ev_raw)
                    if isinstance(ev_map, dict):
                        ws_evidence_ids.update(str(k) for k in ev_map.keys() if str(k).startswith("ev_"))
            except Exception:
                pass

    confirmed_runtime_controls: set[str] = set()
    blocked_by_runtime_controls: set[str] = set()
    runtime_answers = runtime_facts.get("answers", {}) if isinstance(runtime_facts.get("answers"), dict) else {}
    for ctrl in runtime_facts.get("controls", []):
        if isinstance(ctrl, dict):
            st = str(ctrl.get("status", "enforced")).lower()
            if st in {"enforced", "confirmed", "confirmed_enforced", "active", "blocks_exploit"}:
                for k in ("control_id", "name", "type", "layer", "chain_id", "finding_id"):
                    if ctrl.get(k):
                        confirmed_runtime_controls.add(str(ctrl[k]).lower())
                if ctrl.get("mitigation_effect") == "blocks_exploit" or st == "blocks_exploit":
                    for k in ("chain_id", "finding_id", "control_id", "name"):
                        if ctrl.get(k):
                            blocked_by_runtime_controls.add(str(ctrl[k]).lower())

    def _pre_status(pre: dict[str, Any]) -> str:
        raw_st = str(
            pre.get("status")
            or pre.get("precondition_status")
            or pre.get("satisfied")
            or ""
        ).strip().lower()
        if raw_st in {"yes", "true", "satisfied", "confirmed", "observed"}:
            return "yes"
        if raw_st in {"no", "false", "unsatisfied", "impossible"}:
            return "no"
        if raw_st in {"unknown", "unverified", "hypothesis"}:
            return "unknown"
        return raw_st

    downgraded_controls: list[dict[str, Any]] = []
    key_questions: list[dict[str, Any]] = []

    # Index 3.1 actor assessments by chain_id / finding_id
    actor_by_id: dict[str, dict[str, Any]] = {}
    for a_entry in list(actor_map.get("actor_assessments") or []) + list(actor_map.get("assessments") or []):
        if isinstance(a_entry, dict):
            aid = str(a_entry.get("chain_id") or a_entry.get("finding_id") or a_entry.get("candidate_id") or "").strip()
            if aid:
                actor_by_id[aid] = a_entry
            for pre in a_entry.get("preconditions", []):
                if not isinstance(pre, dict):
                    continue
                pst = _pre_status(pre)
                cond_desc = str(pre.get("condition") or pre.get("description") or pre.get("precondition") or "unknown precondition")
                if pst == "unknown":
                    # V12: a precondition is attainable when 3.1 itself names a holder who attains it with real repo
                    # evidence (e.g. "chat-be workload holds AGENT_PLATFORM_KEY"). Leaving it 'unknown' made every chain
                    # provisional, while reporting/risk.py — given the same holders — concluded the chain is feasible.
                    chain_actor = str(a_entry.get("minimum_actor") or a_entry.get("minimum_viable_actor") or "").strip()
                    holder_hit = next(
                        (
                            h for h in (pre.get("holders") or [])
                            if isinstance(h, dict)
                            and str(h.get("attainable") or "").strip().lower() == "yes"
                            # V19: a holder counts for the chain's own attacker type only
                            and (not h.get("actor_type") or not chain_actor or str(h.get("actor_type")) == chain_actor)
                            and any(
                                str(e).startswith("ev_") and bool(ws_evidence_ids and str(e) in ws_evidence_ids)
                                for e in (h.get("evidence_ids") or [])
                            )
                        ),
                        None,
                    )
                    if holder_hit is not None:
                        pst = "yes"
                        pre["status"] = "yes"
                        pre["precondition_status"] = "yes"
                        pre["attained_via_holder"] = str(holder_hit.get("who") or "")
                if pst == "no":
                    # C8: Require non-empty ws_evidence_ids and membership in ws_evidence_ids for repo-evidenced 'no' preconditions
                    pre_eids = [
                        str(e)
                        for e in (pre.get("evidence_ids") or [])
                        if str(e).startswith("ev_") and bool(ws_evidence_ids and str(e) in ws_evidence_ids)
                    ]
                    ans_val = str(runtime_answers.get(cond_desc) or runtime_answers.get(aid) or "").strip().lower()
                    has_no_fact = ans_val in {"no", "false", "unsatisfied", "impossible"}
                    if not pre_eids and not has_no_fact:
                        pst = "unknown"
                        pre["status"] = "unknown"
                        pre["precondition_status"] = "unknown"
                if pst == "unknown":
                    key_questions.append({
                        "question_id": f"KQ-{len(key_questions) + 1:02d}",
                        "chain_id": aid or "repo_wide",
                        "question_kind": "precondition",
                        "target_team": "appsec_architecture",
                        "question": f"Does runtime precondition '{cond_desc}' hold for {aid or repo_name}?",
                        "searched_paths": list(pre.get("searched_paths", [])),
                        "outcome_if_yes": "Feasibility becomes 'feasible'; contextual risk resolves to full S-F-O-P-C impact.",
                        "outcome_if_no": "Feasibility becomes 'infeasible'; contextual risk downgrades to 'low'.",
                        "status": "pending_operator",
                    })

    controls_list = list(beyond_code.get("beyond_code_controls", []))
    for a_item in beyond_code.get("assessments", []):
        if isinstance(a_item, dict):
            for c_item in a_item.get("compensating_controls", []):
                if isinstance(c_item, dict):
                    controls_list.append({**c_item, "finding_id": a_item.get("finding_id") or a_item.get("chain_id")})

    for ctrl in controls_list:
        if not isinstance(ctrl, dict):
            continue
        status = str(ctrl.get("enforcement_status") or ctrl.get("status") or "").upper()
        cname = str(ctrl.get("control_id") or ctrl.get("name") or ctrl.get("control") or ctrl.get("layer") or "beyond_code_control")
        cid_ref = str(ctrl.get("chain_id") or ctrl.get("finding_id") or "")
        if status in {"CONFIRMED_ENFORCED", "CONFIRMED", "OBSERVED"}:
            ev_ids = [str(e) for e in ctrl.get("evidence_ids", []) if str(e).startswith("ev_")]
            has_repo_ev = bool(ev_ids and ws_evidence_ids and any(e in ws_evidence_ids for e in ev_ids))
            has_runtime_fact = (
                bool(cname and cname.lower() in confirmed_runtime_controls)
                or bool(cid_ref and cid_ref.lower() in confirmed_runtime_controls)
                or bool(ctrl.get("runtime_fact_verified"))
            )
            if not has_repo_ev and not has_runtime_fact:
                ctrl["enforcement_status"] = "ASSUMED_UNVERIFIED"
                ctrl["status"] = "hypothesis"
                if ctrl.get("mitigation_effect") == "blocks_exploit":
                    ctrl["mitigation_effect"] = "reduces_likelihood"
                    ctrl["claimed_blocks_exploit"] = True
                downgraded_controls.append({
                    "control": cname,
                    "previous_status": status,
                    "new_status": "ASSUMED_UNVERIFIED",
                    "reason": "No repo ev_... evidence or runtime_environment_facts.json confirmation found",
                })
            elif ctrl.get("mitigation_effect") == "blocks_exploit" and cid_ref:
                blocked_by_runtime_controls.add(cid_ref.lower())
        if (
            str(ctrl.get("status", "")).lower() in {"hypothesis", "unknown", "assumed_unverified"}
            or str(ctrl.get("enforcement_status", "")).upper() == "ASSUMED_UNVERIFIED"
            or str(ctrl.get("present", "")).lower() == "unknown"
        ):
            key_questions.append({
                "question_id": f"KQ-{len(key_questions) + 1:02d}",
                "chain_id": cid_ref or "repo_wide",
                "question_kind": "beyond_code_control",
                "target_team": "infra_cloud_sec",
                # V12: only a control that would block the exploit if confirmed keeps the chain provisional
                "could_block_exploit": bool(ctrl.get("mitigation_effect") == "blocks_exploit" or ctrl.get("claimed_blocks_exploit")),
                "question": f"Is control '{cname}' actively enforced in production for {cid_ref or repo_name}?",
                "searched_paths": list(ctrl.get("searched_paths", [])),
                "outcome_if_yes": "Control is confirmed enforced; if mitigation_effect=='blocks_exploit', feasibility becomes 'infeasible' and contextual_risk_rating downgrades to 'low'.",
                "outcome_if_no": "Control is absent; feasibility becomes 'feasible' and contextual_risk_rating resolves to full S-F-O-P-C impact.",
                "status": "answered" if (cname.lower() in confirmed_runtime_controls or cid_ref.lower() in confirmed_runtime_controls) else "pending_operator",
            })

    if downgraded_controls:
        write_json(run_dir / "beyond_code_control_mapper.json", beyond_code)

    # ARCH-3H & R3-A5: Derive feasibility_derived, derived_risk_rating, dynamic key_questions outcomes, and Safety HSE handoff questions
    # Hypothesis-only chains (Phase 2 could not confirm the path) stay provisional whatever 3.1 says
    hypothesis_only_ids = {
        str(h.get("chain_id") or h.get("candidate_id") or "")
        for h in p3_queue.get("hypothesis_only_findings", [])
        if isinstance(h, dict)
    }
    calibrated_list = sfop.get("calibrated_findings", []) if isinstance(sfop, dict) else []
    accounted_chain_ids: set[str] = set()
    rank_map = {"none": 0, "negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "catastrophic": 5}
    inv_rank = {0: "negligible", 1: "low", 2: "medium", 3: "high", 4: "critical", 5: "catastrophic"}

    for cf in calibrated_list:
        if not isinstance(cf, dict):
            continue
        fid = str(cf.get("chain_id") or cf.get("finding_id") or "")
        if fid:
            accounted_chain_ids.add(fid)

        # Compute max S-F-O-P-C impact
        axes = cf.get("impact_axes") or cf.get("sfop_impacts") or {}
        max_axis_rank = 0
        for ax in ("safety", "financial", "operational", "privacy", "compliance"):
            ax_obj = axes.get(ax) if isinstance(axes, dict) and ax in axes else cf.get(f"{ax}_impact")
            lvl = str(ax_obj.get("level") if isinstance(ax_obj, dict) else (ax_obj or "negligible")).lower()
            max_axis_rank = max(max_axis_rank, rank_map.get(lvl, 0))
        max_impact_str = inv_rank.get(max_axis_rank, "medium")
        infeasible_risk_str = "low" if max_axis_rank >= 1 else "negligible"

        # Check 3.1 preconditions for this finding
        a_info = actor_by_id.get(fid, {})
        pre_list = a_info.get("preconditions", []) if isinstance(a_info, dict) else []
        has_false_precondition = any(
            isinstance(p, dict) and _pre_status(p) == "no"
            for p in pre_list
        )
        unk_pre_count = sum(
            1 for p in pre_list if isinstance(p, dict) and _pre_status(p) == "unknown"
        )
        has_unknown_precondition = unk_pre_count > 0
        pending_chain_questions = [
            q for q in key_questions
            if q.get("chain_id") == fid and q.get("status") == "pending_operator"
        ]
        total_unknowns = len(pending_chain_questions)
        for q in pending_chain_questions:
            qkind = q.get("question_kind", "")
            if qkind == "precondition":
                if total_unknowns <= 1:
                    q["outcome_if_yes"] = (
                        f"All preconditions satisfied; feasibility becomes 'feasible' and contextual_risk_rating resolves to '{max_impact_str}' (max S-F-O-P-C impact)."
                    )
                else:
                    q["outcome_if_yes"] = (
                        f"Precondition satisfied, but {total_unknowns - 1} other unknown(s) remain pending for {fid}; "
                        f"feasibility stays 'provisional_unknown' until all are resolved (max S-F-O-P-C impact='{max_impact_str}')."
                    )
                q["outcome_if_no"] = (
                    f"Precondition falsified; feasibility becomes 'infeasible' and contextual_risk_rating downgrades to '{infeasible_risk_str}'."
                )
            elif qkind == "beyond_code_control":
                q["outcome_if_yes"] = (
                    f"Control is confirmed enforced; if mitigation_effect=='blocks_exploit', feasibility becomes 'infeasible' and contextual_risk_rating downgrades to '{infeasible_risk_str}'."
                )
                if total_unknowns <= 1:
                    q["outcome_if_no"] = (
                        f"Control is absent; feasibility becomes 'feasible' and contextual_risk_rating resolves to '{max_impact_str}' (max S-F-O-P-C impact)."
                    )
                else:
                    q["outcome_if_no"] = (
                        f"Control is absent, but {total_unknowns - 1} other unknown(s) remain pending for {fid}; "
                        f"feasibility stays 'provisional_unknown' until all are resolved (max S-F-O-P-C impact='{max_impact_str}')."
                    )

        if fid.lower() in blocked_by_runtime_controls or has_false_precondition:
            cf["feasibility_derived"] = "infeasible"
            derived_risk = infeasible_risk_str
            cf["derived_risk_rating"] = derived_risk
            cf["contextual_risk_rating"] = derived_risk
            cf["provisional"] = False
        elif has_unknown_precondition or fid in hypothesis_only_ids or any(
            q.get("question_kind") != "beyond_code_control" or q.get("could_block_exploit") for q in pending_chain_questions
        ):
            cf["feasibility_derived"] = "provisional_unknown"
            cf["derived_risk_rating"] = max_impact_str
            cf["provisional"] = True
        else:
            # Script-derived: never keep a model-written 'provisional_unknown' once every precondition is attained
            cf["feasibility_derived"] = "feasible"
            cf["derived_risk_rating"] = max_impact_str
            cf["provisional"] = False

        # Deterministic contextual_risk_rating enforcement (R3-A5 & C6):
        # contextual_risk_rating == derived_risk_rating unless risk_override_rationale (>=80 chars) + valid risk_override_evidence_ids
        derived_rank = rank_map.get(str(cf["derived_risk_rating"]).lower(), max_axis_rank)
        override_rationale = str(cf.get("risk_override_rationale") or "").strip()
        override_eids = [
            str(e)
            for e in (cf.get("risk_override_evidence_ids") or [])
            if str(e).startswith("ev_") and ws_evidence_ids and str(e) in ws_evidence_ids
        ]
        has_valid_override = len(override_rationale) >= 80 and len(override_eids) > 0
        cur_risk = str(cf.get("contextual_risk_rating") or cf.get("overall_risk") or cf["derived_risk_rating"]).lower()
        cur_rank = rank_map.get(cur_risk, derived_rank)
        if not has_valid_override:
            cf["contextual_risk_rating"] = cf["derived_risk_rating"]
            cf["risk_override_applied"] = False
        else:
            min_allowed_rank = max(0, derived_rank - 1)
            clamped_rank = min(derived_rank, max(min_allowed_rank, cur_rank))
            cf["contextual_risk_rating"] = inv_rank.get(clamped_rank, cf["derived_risk_rating"])
            cf["risk_override_applied"] = bool(cf["contextual_risk_rating"] != cf["derived_risk_rating"])

        # C2: Default missing owner_role to 'unassigned_pending_roster' (never 'dev_team') and emit KQ-OWNER question
        owner_role_val = str(cf.get("owner_role") or "").strip()
        if not owner_role_val or owner_role_val == "unassigned_pending_roster":
            cf["owner_role"] = "unassigned_pending_roster"
            key_questions.append({
                "question_id": f"KQ-OWNER-{len(key_questions) + 1:02d}",
                "chain_id": fid or "repo_wide",
                "question_kind": "owner_assignment",
                "target_team": "security_governance",
                "question": f"Assign concrete remediation owner_role from project roster for {fid or repo_name} (currently 'unassigned_pending_roster').",
                "searched_paths": [],
                "outcome_if_yes": "Remediation owner_role assigned from project roster and SLA tracking activated.",
                "outcome_if_no": "Finding remains 'unassigned_pending_roster' and blocks final governance sign-off.",
                "status": "pending_operator",
            })

        # Check Safety axis for HSE/Functional Safety handoff question (DEPTH-4.4b)
        s_axis = axes.get("safety") if isinstance(axes, dict) else None
        s_level = (s_axis.get("level") if isinstance(s_axis, dict) else s_axis) or cf.get("safety_impact") or "negligible"
        if str(s_level).lower() not in {"negligible", "none", ""}:
            key_questions.append({
                "question_id": f"KQ-SAFETY-{len(key_questions) + 1:02d}",
                "chain_id": fid or "repo_wide",
                "target_team": "ot_safety_engineering",
                "question": f"Confirm hardware/firmware safety interlock outside software repo for {fid} (actuator_command_path_without_interlock={s_axis.get('actuator_command_path_without_interlock', 'unknown') if isinstance(s_axis, dict) else 'unknown'}).",
                "outcome_if_yes": "Hardware interlock confirmed outside software; safety risk mitigated at physical layer.",
                "outcome_if_no": "No hardware interlock; software path can directly actuate physical state — Gate 0 Emergency Brake remains active.",
                "status": "pending_safety_owner",
            })

    # R3-A3: Forward hypothesis_only_findings from phase3_verified_queue.json into key_questions.json so they are never silently dropped
    hypothesis_only_chain_ids: list[str] = []
    for h_ch in p3_queue.get("hypothesis_only_findings", []):
        if not isinstance(h_ch, dict):
            continue
        h_id = str(h_ch.get("chain_id") or h_ch.get("candidate_id") or "").strip()
        if h_id:
            hypothesis_only_chain_ids.append(h_id)
        h_verdict = str(h_ch.get("challenger_verdict") or h_ch.get("challenge_verdict") or "needs_runtime_verification")
        h_sev = str(h_ch.get("code_verified_severity") or h_ch.get("severity") or "unknown")
        h_paths = sorted({
            str(hp.get("file") or hp.get("path") or "")
            for hp in (h_ch.get("hops") or [])
            if isinstance(hp, dict) and (hp.get("file") or hp.get("path"))
        } | ({str(h_ch["target_path"])} if h_ch.get("target_path") else set()))
        key_questions.append({
            "question_id": f"KQ-HYP-{len(key_questions) + 1:02d}",
            "chain_id": h_id or "repo_wide",
            "question_kind": "hypothesis_runtime_verification",
            "target_team": "appsec_pentest_qa",
            "severity": h_sev,
            "question": f"Execute runtime verification request_plan for hypothesis-only chain {h_id or repo_name} (severity {h_sev}, {h_verdict}).",
            "searched_paths": h_paths,
            "outcome_if_yes": "Exploit chain confirmed reproducible at runtime; promote to Confirmed Finding and calibrate S-F-O-P-C risk.",
            "outcome_if_no": "Exploit chain blocked at runtime; move to Empirical Refutations Ledger with runtime evidence.",
            "status": "pending_runtime_verification",
        })

    if calibrated_list:
        write_json(run_dir / "sfop_risk_calibrator.json", sfop)

    write_json(
        run_dir / "key_questions.json",
        {
            "repo_name": repo_name,
            "run_id": run_id,
            "question_count": len(key_questions),
            "questions": key_questions,
        },
    )

    # Phase 3 must assess hypothesis-only chains too (provisional): a chain that still needs runtime proof can be the
    # most severe one, and a bare KQ-HYP question leaves it without actor/control/impact assessment or a rating.
    surviving_p2_ids = [
        str(f.get("chain_id") or f.get("finding_id") or "")
        for f in list(p3_queue.get("verified_findings", [])) + list(p3_queue.get("hypothesis_only_findings", []))
        if isinstance(f, dict) and (f.get("chain_id") or f.get("finding_id"))
    ]
    unaccounted_p3_chains = [cid for cid in surviving_p2_ids if cid not in accounted_chain_ids]

    sfop_validation_errors: list[str] = []
    if sfop:
        try:
            validate_v30_epistemic_gates("sfop_risk_calibrator", sfop)
        except OutputValidationError as exc:
            sfop_validation_errors.append(str(exc))
    else:
        sfop_validation_errors.append("sfop_risk_calibrator.json is missing or empty")

    gate_passed = len(sfop_validation_errors) == 0 and len(unaccounted_p3_chains) == 0
    cert = {
        "phase": "phase_3",
        "repo_name": repo_name,
        "run_id": run_id,
        "gate_passed": gate_passed,
        "unaccounted_phase2_chains": unaccounted_p3_chains,
        "hypothesis_only_chain_ids": hypothesis_only_chain_ids,
        "downgraded_beyond_code_controls": downgraded_controls,
        "key_questions_count": len(key_questions),
        "sfop_validation_errors": sfop_validation_errors,
    }
    write_json(run_dir / "phase3_gate_Certificate.json", cert)
    write_json(run_dir / "phase3_gate_receipt.json", cert)
    return cert


def diff_prior_run(
    *,
    current_scout_map: dict[str, Any],
    prior_coverage_ledger: dict[str, Any],
    changed_files: list[str],
) -> dict[str, Any]:
    """Incremental Delta-Recon (--prior-run-id): invalidate coverage_ledger entries touching changed_files or their target modules."""
    norm_changed = [c.strip().strip("/") for c in changed_files if isinstance(c, str) and c.strip()]
    target_mods = [
        (m.strip().strip("/") if isinstance(m, str) else str(m.get("path", "")).strip().strip("/"))
        for m in current_scout_map.get("target_modules", [])
        if (isinstance(m, str) and m.strip()) or (isinstance(m, dict) and m.get("path"))
    ]
    affected_modules = sorted({
        mod for mod in target_mods
        if any(cf == mod or cf.startswith(mod + "/") for cf in norm_changed)
    })

    from urllib.parse import unquote

    reopened_records: list[dict[str, Any]] = []
    preserved_records: list[dict[str, Any]] = []
    for rec in prior_coverage_ledger.get("records", []):
        if not isinstance(rec, dict):
            continue
        cid = str(rec.get("coverage_id", ""))
        decoded_cid = unquote(cid)
        item = json.loads(json.dumps(rec))
        is_hit = (
            any(mod in cid or mod in decoded_cid for mod in affected_modules)
            or any(cf in cid or cf in decoded_cid for cf in norm_changed)
        )
        if is_hit:
            item["status"] = "reopened"
            attempts = list(item.get("attempts", []))
            attempts.append({
                "attempt_number": len(attempts) + 1,
                "action": "reopened_by_delta_diff",
                "changed_files": norm_changed,
            })
            item["attempts"] = attempts
            reopened_records.append(item)
        else:
            preserved_records.append(item)

    return {
        "changed_files": norm_changed,
        "affected_target_modules": affected_modules,
        "reopened_count": len(reopened_records),
        "preserved_count": len(preserved_records),
        "reopened_records": reopened_records,
        "preserved_records": preserved_records,
    }

