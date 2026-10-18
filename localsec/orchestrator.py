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
from .workspace import ManualWorkspace, WorkspaceError

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
