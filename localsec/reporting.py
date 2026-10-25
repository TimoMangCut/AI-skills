from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .workspace import write_json


def _md(value: Any, max_len: int | None = None) -> str:
    if value is None or value == "":
        return "—"
    s = str(value).replace("|", "\\|").replace("\n", " ")
    if max_len is not None and len(s) > max_len:
        return s[: max(0, max_len - 1)].rstrip() + "…"
    return s


def _evidence(ids: Any) -> str:
    if not isinstance(ids, list) or not ids:
        return "Evidence: not established"
    return "Evidence: " + ", ".join(f"`{_md(x)}`" for x in ids)


def _write_md(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _result(result: dict[str, Any], skill: str) -> tuple[str, dict[str, Any]]:
    entry = result.get("ai", {}).get(skill, {})
    data = entry.get("result") if entry.get("status") == "ok" and isinstance(entry.get("result"), dict) else {}
    return str(entry.get("status", "not_run")), data


def write_repo_documents(repo_dir: Path, work_dir: Path, result: dict[str, Any]) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    name = result["repo_name"]
    ai = result.get("ai", {})
    profile_status, profile = _result(result, "repo_profile")
    purpose = profile.get("purpose", {})
    criticality = profile.get("criticality", {})
    coverage = result.get("coverage", {})

    profile_md = [
        f"# Repository profile — {name}", "",
        f"- Workflow status: `{coverage.get('workflow_status', 'unknown')}`",
        "- Analysis mode: **AI manual file reading**",
        "- Exhaustive scan: **No**", "",
        "## Purpose",
        _md(purpose.get("value")),
        f"- Status: `{purpose.get('status', 'unknown')}` — {_evidence(purpose.get('evidence_ids'))}",
        f"- Notes: {_md(purpose.get('notes'))}", "",
        "## Criticality assessment",
        _md(criticality.get("value")),
        f"- Status: `{criticality.get('status', 'unknown')}` — {_evidence(criticality.get('evidence_ids'))}",
        f"- Rationale: {_md(criticality.get('notes'))}", "",
        "## Tech stack", "",
    ]
    for item in profile.get("techstack", []):
        profile_md += [
            f"### {_md(item.get('name'))}: {_md(item.get('value'))}",
            f"- Status: `{_md(item.get('status'))}`",
            f"- Notes: {_md(item.get('notes'))}",
            f"- {_evidence(item.get('evidence_ids'))}", "",
        ]
    if not profile.get("techstack"):
        profile_md.append("No tech-stack claims passed the profile skill. This is not evidence that the repository has no tech stack.")
    profile_md += ["## Business capabilities", ""]
    for item in profile.get("business_capabilities", []):
        profile_md.append(f"- **{_md(item.get('name'))}** (`{_md(item.get('status'))}`): {_md(item.get('notes'))} — {_evidence(item.get('evidence_ids'))}")
    if profile.get("entrypoints"):
        profile_md += ["", "## Entrypoints and workers", ""]
        for item in profile.get("entrypoints", []):
            profile_md.append(f"- **{_md(item.get('kind'))}** `{_md(item.get('path_or_symbol'))}` (`{_md(item.get('status'))}`): {_md(item.get('notes'))} — {_evidence(item.get('evidence_ids'))}")
    if profile.get("sensitive_data"):
        profile_md += ["", "## Sensitive data indicators", ""]
        for item in profile.get("sensitive_data", []):
            profile_md.append(f"- **{_md(item.get('data_class'))}** (`{_md(item.get('status'))}`): {_md(item.get('notes'))} — {_evidence(item.get('evidence_ids'))}")
    profile_md += ["", "## Unknowns / inspection gaps", ""] + [f"- {_md(x)}" for x in profile.get("unknowns", [])]
    profile_md += [
        "", "## Inspection coverage",
        f"- Directories listed: {len(coverage.get('directories_listed', []))}",
        f"- Unique files read: {len(coverage.get('unique_files_read', []))}",
        f"- Read chunks: {coverage.get('read_chunks', 0)}",
        f"- Evidence records: {coverage.get('evidence_count', 0)}", "",
        "Coverage describes only the paths and line ranges selected by the AI. It is not exhaustive repository coverage.",
    ]
    _write_md(repo_dir / "01_repo_profile.md", profile_md)
    write_json(
        repo_dir / "02_techstack.json",
        {
            "repo_name": name,
            "status": profile_status,
            "techstack": profile.get("techstack", []),
            "business_capabilities": profile.get("business_capabilities", []),
            "entrypoints": profile.get("entrypoints", []),
            "sensitive_data": profile.get("sensitive_data", []),
        },
    )

    api_status, api = _result(result, "api_authz")
    write_json(repo_dir / "03_api_inventory.json", {"repo_name": name, "status": api_status, "endpoints": api.get("endpoints", []), "unknowns": api.get("unknowns", [])})
    write_json(
        repo_dir / "04_auth_matrix.json",
        {
            "repo_name": name,
            "status": api_status,
            "authorization_patterns": api.get("authorization_patterns", []),
            "endpoint_auth": [
                {
                    "method": ep.get("method"),
                    "path": ep.get("path"),
                    "handler": ep.get("handler"),
                    "caller_class": ep.get("caller_class", "unknown"),
                    "authn": ep.get("authn"),
                    "authorization": ep.get("authorization"),
                    "roles": ep.get("roles", []),
                    "object_level_authz": ep.get("object_level_authz", "not_assessed"),
                    "sensitivity": ep.get("sensitivity", "unknown"),
                    "status": ep.get("status"),
                    "evidence_ids": ep.get("evidence_ids", []),
                    "notes": ep.get("notes", ""),
                }
                for ep in api.get("endpoints", [])
            ],
            "unknowns": api.get("unknowns", []),
        },
    )
    api_md = [
        f"# API and authorization inventory — {name}", "",
        f"Status: `{api_status}`", "",
        "This inventory includes only interfaces manually inspected by the AI. It is not guaranteed to contain every reachable API.", "",
    ]
    for ep in api.get("endpoints", []):
        api_md += [
            f"## {_md(ep.get('method'))} {_md(ep.get('path'))}",
            f"- Handler: {_md(ep.get('handler'))}",
            f"- Caller class: {_md(ep.get('caller_class', 'unknown'))}",
            f"- Authentication: {_md(ep.get('authn'))}",
            f"- Authorization: {_md(ep.get('authorization'))}",
            f"- Roles/policies: {_md(', '.join(ep.get('roles', [])))}",
            f"- Object/tenant-level check (BOLA/IDOR): {_md(ep.get('object_level_authz', 'not_assessed'))}",
            f"- Sensitivity: `{_md(ep.get('sensitivity', 'unknown'))}`",
            f"- Status: `{_md(ep.get('status'))}`",
            f"- {_evidence(ep.get('evidence_ids'))}",
            f"- Notes: {_md(ep.get('notes'))}", "",
        ]
    api_md += ["## Authorization patterns", ""]
    for pattern in api.get("authorization_patterns", []):
        api_md.append(f"- **{_md(pattern.get('mechanism'))}** (`{_md(pattern.get('status'))}`): {_md(pattern.get('notes'))} — {_evidence(pattern.get('evidence_ids'))}")
    api_md += ["", "## Unknowns", ""] + [f"- {_md(x)}" for x in api.get("unknowns", [])]
    _write_md(repo_dir / "03_api_inventory.md", api_md)

    flow_status, flow = _result(result, "dataflow")
    all_flows = flow.get("flows", [])
    inbound_flows = [f for f in all_flows if f.get("direction") == "inbound"]
    outbound_flows = [f for f in all_flows if f.get("direction") == "outbound"]
    write_json(
        repo_dir / "05_inbound_outbound.json",
        {
            "repo_name": name,
            "status": flow_status,
            "inbound_flows": inbound_flows,
            "outbound_flows": outbound_flows,
            "flows": all_flows,
            "trust_boundaries": flow.get("trust_boundaries", []),
            "unknowns": flow.get("unknowns", []),
        },
    )
    flow_md = [f"# Dataflow and trust boundaries — {name}", "", f"Status: `{flow_status}`", ""]
    for item in all_flows:
        direction_tag = f"[{_md(item.get('direction', 'unspecified'))}] " if item.get("direction") else ""
        flow_md += [
            f"## {direction_tag}{_md(item.get('source'))} → {_md(item.get('destination'))}",
            f"- Direction: `{_md(item.get('direction', 'unknown'))}`",
            f"- Protocol: {_md(item.get('protocol'))}",
            f"- Identity context: {_md(item.get('identity_context', 'unknown'))}",
            f"- Data types: {_md(', '.join(item.get('data_types', [])))}",
            f"- Trust boundary: {_md(item.get('trust_boundary'))}",
            f"- Controls: {_md(', '.join(item.get('controls', [])))}",
            f"- Status: `{_md(item.get('status'))}`",
            f"- {_evidence(item.get('evidence_ids'))}",
            f"- Notes: {_md(item.get('notes'))}", "",
        ]
    if not all_flows:
        flow_md.append("No grounded flows were produced. Do not interpret an empty list as absence of data flows.")
    flow_md += ["## Trust boundaries", ""]
    for item in flow.get("trust_boundaries", []):
        flow_md.append(f"- **{_md(item.get('name'))}** (`{_md(item.get('status'))}`): {_md(item.get('notes'))} — {_evidence(item.get('evidence_ids'))}")
    flow_md += ["", "## Unknowns", ""] + [f"- {_md(x)}" for x in flow.get("unknowns", [])]
    _write_md(repo_dir / "06_dataflow.md", flow_md)

    threat_status, threat = _result(result, "threat_model")
    threat_md = [f"# Threat model — {name}", "", f"Status: `{threat_status}`", "", "Threat scenarios may be hypotheses. They are not confirmed vulnerability findings without validation.", ""]
    for item in threat.get("threats", []):
        threat_md += [
            f"## {_md(item.get('id'))} — {_md(item.get('scenario'))}",
            f"- Category: {_md(item.get('category'))}",
            f"- Asset: {_md(item.get('asset'))}",
            f"- Threat actor: {_md(item.get('threat_actor'))}",
            f"- Impact / likelihood: {_md(item.get('impact'))} / {_md(item.get('likelihood'))}",
            f"- Priority: `{_md(item.get('priority'))}`; status: `{_md(item.get('status'))}`",
            f"- Existing controls: {_md(', '.join(item.get('existing_controls', [])))}",
            f"- Control gaps: {_md(', '.join(item.get('control_gaps', [])))}",
            f"- Validation needed: {_md('; '.join(item.get('validation_needed', [])))}",
            f"- {_evidence(item.get('evidence_ids'))}", "",
        ]
    if not threat.get("threats"):
        threat_md.append("No threat scenarios were returned; this is not a clean bill of security.")
    threat_md += ["## Assumptions", ""] + [f"- {_md(x)}" for x in threat.get("assumptions", [])] + ["", "## Unknowns", ""] + [f"- {_md(x)}" for x in threat.get("unknowns", [])]
    _write_md(repo_dir / "07_threat_model.md", threat_md)

    arch_status, arch = _result(result, "architecture_review")
    arch_md = [f"# Architecture review — {name}", "", f"Status: `{arch_status}`", ""]
    for item in arch.get("observations", []):
        arch_md += [
            f"## {_md(item.get('title'))}",
            f"- Category: {_md(item.get('category'))}",
            f"- Assessment: {_md(item.get('assessment'))}",
            f"- Impact: {_md(item.get('impact'))}",
            f"- Priority: `{_md(item.get('priority'))}`; status: `{_md(item.get('status'))}`",
            f"- Recommendation: {_md(item.get('recommendation'))}",
            f"- {_evidence(item.get('evidence_ids'))}",
            f"- Notes: {_md(item.get('notes'))}", "",
        ]
    if not arch.get("observations"):
        arch_md.append("No architecture observations were generated. This does not imply the architecture is secure.")
    arch_md += ["## Strengths", ""]
    for item in arch.get("strengths", []):
        arch_md.append(f"- **{_md(item.get('title'))}** (`{_md(item.get('status'))}`): {_md(item.get('notes'))} — {_evidence(item.get('evidence_ids'))}")
    arch_md += ["", "## Unknowns", ""] + [f"- {_md(x)}" for x in arch.get("unknowns", [])]
    _write_md(repo_dir / "08_architecture_review.md", arch_md)

    from .orchestrator import (
        _build_proof_obligation_and_challenge,
        evaluate_contextual_evidence_strength,
        manage_hypothesis_lifecycle,
    )

    evidence_list: list[dict[str, Any]] = result.get("evidence", [])
    evidence_catalog: dict[str, dict[str, Any]] = {
        rec["evidence_id"]: rec for rec in evidence_list if isinstance(rec, dict) and "evidence_id" in rec
    }

    findings: list[dict[str, Any]] = []
    for item in threat.get("threats", []):
        eids = item.get("evidence_ids", []) if isinstance(item.get("evidence_ids"), list) else []
        ctx_eval = evaluate_contextual_evidence_strength(eids, evidence_catalog)
        po, chal = _build_proof_obligation_and_challenge(item, "threat_model")
        findings.append(
            {
                "source": "threat_model",
                **item,
                "contextual_evidence_strength": ctx_eval,
                "proof_obligation": po,
                "bounded_challenge_loop": chal,
            }
        )
    for item in arch.get("observations", []):
        eids = item.get("evidence_ids", []) if isinstance(item.get("evidence_ids"), list) else []
        ctx_eval = evaluate_contextual_evidence_strength(eids, evidence_catalog)
        po, chal = _build_proof_obligation_and_challenge(item, "architecture_review")
        findings.append(
            {
                "source": "architecture_review",
                **item,
                "contextual_evidence_strength": ctx_eval,
                "proof_obligation": po,
                "bounded_challenge_loop": chal,
            }
        )

    hypo_items = [
        {**f, "repo_name": name}
        for f in findings
        if f.get("status") in {"hypothesis", "partially_supported", "inconclusive"} or f.get("preserved_hypothesis_lead")
    ]
    hypo_lifecycle = manage_hypothesis_lifecycle(hypo_items, current_round=1)

    write_json(
        repo_dir / "09_findings.json",
        {
            "repo_name": name,
            "pipeline_version": "2.4.0-refute-first",
            "findings": findings,
            "hypothesis_lifecycle": hypo_lifecycle,
            "note": "AI triage output enriched with contextual evidence strength, proof obligations (falsifiability), bounded challenge loops, and negative-corpus checks.",
        },
    )
    findings_md = [
        f"# Findings and design risks (v2.4 Epistemic & Contextual Edition) — {name}",
        "",
        "Each item includes deterministic contextual evidence strength, falsifiability proof obligations, and bounded challenge questions.",
        "",
    ]
    for item in findings:
        title = item.get("title") or item.get("scenario") or item.get("id") or "Untitled"
        ctx = item.get("contextual_evidence_strength", {})
        po = item.get("proof_obligation", {})
        chal = item.get("bounded_challenge_loop", {})
        findings_md += [
            f"## {_md(title)}",
            f"- Source skill: `{_md(item.get('source'))}`",
            f"- Priority: `{_md(item.get('priority'))}`",
            f"- Status: `{_md(item.get('status'))}`" + (" (`preserved_hypothesis_lead: true`)" if item.get("preserved_hypothesis_lead") else ""),
            f"- Contextual strength: `{_md(ctx.get('strength_verdict'))}` (Best authority rank: `{_md(ctx.get('best_source_rank'))}`, Entrypoint/Sink bound: `{_md(ctx.get('is_entrypoint_or_sink_bound'))}`)",
            f"- Deployment versions: {_md(', '.join(ctx.get('deployment_versions', [])))}",
            f"- Negative corpus matches: {_md(', '.join(ctx.get('negative_corpus_matches', [])))}",
            f"- {_evidence(item.get('evidence_ids'))}",
            f"- Detail: {_md(item.get('assessment') or item.get('scenario'))}",
            f"- **Proof Obligation (What would falsify)**: {_md(po.get('what_would_falsify'))}",
            f"- **Challenge (Counterexample)**: {_md(chal.get('counterexample_question'))}",
            f"- **Challenge (Alternative Chain)**: {_md(chal.get('stronger_alternative_chain_question'))}",
            f"- **Challenge (Overestimated Control)**: {_md(chal.get('overestimated_control_question'))}",
            "",
        ]
    _write_md(repo_dir / "09_findings.md", findings_md)

    write_json(repo_dir / "10_evidence_index.json", evidence_list)
    write_json(repo_dir / "11_coverage.json", coverage)
    status = {
        "repo_name": name,
        "run_id": result.get("run_id"),
        "pipeline_version": "2.4.0-refute-first",
        "analysis_mode": "ai_manual_file_reading",
        "workflow_status": coverage.get("workflow_status", "partial"),
        "coverage_status": coverage.get("coverage_status", "bounded_manual_review"),
        "security_posture": "undetermined_by_design",
        "git_deployment_freshness": coverage.get("git_deployment_freshness", {}),
        "semantic_coverage_diagnostics": coverage.get("semantic_coverage_diagnostics", {}),
        "hypothesis_lifecycle_summary": {
            "active_count": len(hypo_lifecycle.get("active_hypotheses", [])),
            "archived_count": len(hypo_lifecycle.get("archived_hypotheses", [])),
            "reactivated_count": len(hypo_lifecycle.get("reactivated_hypotheses", [])),
        },
        "skill_status": {k: v.get("status", "not_run") for k, v in ai.items()},
        "warnings": [w for v in ai.values() for w in v.get("warnings", [])],
        "limitations": coverage.get("important_limitations", []),
    }
    write_json(repo_dir / "12_analysis_status.json", status)
    audit_entry = ai.get("evidence_auditor", {})
    audit_raw = (
        audit_entry.get("result")
        if audit_entry.get("status") == "ok"
        else {"audit_status": "partial", "audited_claims": [], "not_audited": [], "summary": "Evidence auditor did not complete; claims remain unaudited."}
    )
    enriched_audited_claims: list[dict[str, Any]] = []
    verdict_counts = {"supported": 0, "partially_supported": 0, "inconclusive": 0, "unsupported": 0}
    for item in audit_raw.get("audited_claims", []):
        if not isinstance(item, dict):
            continue
        v = str(item.get("verdict", "inconclusive"))
        if v in verdict_counts:
            verdict_counts[v] += 1
        eids = item.get("evidence_ids", []) if isinstance(item.get("evidence_ids"), list) else []
        ctx_eval = evaluate_contextual_evidence_strength(eids, evidence_catalog)
        po, chal = _build_proof_obligation_and_challenge(
            {"scenario": item.get("reason", "")},
            str(item.get("claim_ref", "claim")).split(":", 1)[0],
        )
        enriched_audited_claims.append(
            {
                **item,
                "preserved_hypothesis_lead": v in {"partially_supported", "inconclusive"},
                "contextual_evidence_strength": ctx_eval,
                "proof_obligation": po,
                "bounded_challenge_loop": chal,
            }
        )
    audit = {
        **audit_raw,
        "verdict_breakdown": verdict_counts,
        "audited_claims": enriched_audited_claims,
    }
    write_json(repo_dir / "13_evidence_audit.json", audit)
    audit_md = [
        f"# Evidence audit (v2.4 Fail-Closed & Contextual Edition) — {name}",
        "",
        f"- Auditor job status: `{audit_entry.get('status', 'not_run')}`",
        f"- Audit coverage: `{audit.get('audit_status', 'unknown')}`",
        f"- Verdict breakdown: `supported={verdict_counts['supported']}`, `partially_supported={verdict_counts['partially_supported']}` (preserved hypothesis), `inconclusive={verdict_counts['inconclusive']}` (preserved hypothesis), `unsupported={verdict_counts['unsupported']}` (downgraded to unknown)",
        f"- Summary: {_md(audit.get('summary'))}",
        "",
        "An AI evidence auditor is a skeptical second pass, not formal proof.",
        "",
        "## Audited claims",
        "",
    ]
    for item in enriched_audited_claims:
        ctx = item.get("contextual_evidence_strength", {})
        po = item.get("proof_obligation", {})
        audit_md += [
            f"### `{_md(item.get('claim_ref'))}`",
            f"- Verdict: `{_md(item.get('verdict'))}`" + (" (`preserved_hypothesis_lead: true`)" if item.get("preserved_hypothesis_lead") else ""),
            f"- Contextual strength: `{_md(ctx.get('strength_verdict'))}` (Best rank: `{_md(ctx.get('best_source_rank'))}`, Negative corpus: `{_md(', '.join(ctx.get('negative_corpus_matches', [])))}`)",
            f"- Evidence reviewed: {_md(', '.join(item.get('evidence_ids', [])))}",
            f"- Reason: {_md(item.get('reason'))}",
            f"- Proof obligation (falsifiability): {_md(po.get('what_would_falsify'))}",
            f"- Follow-up: {_md('; '.join(item.get('follow_up', [])))}",
            "",
        ]
    if audit.get("not_audited"):
        audit_md += ["## Not audited", ""] + [f"- `{_md(x)}`" for x in audit["not_audited"]]
    _write_md(repo_dir / "13_evidence_audit.md", audit_md)

    diag_block = {
        "repo_name": name,
        "pipeline_version": "2.4.0-refute-first",
        "git_deployment_freshness": coverage.get("git_deployment_freshness", {}),
        "semantic_coverage_diagnostics": coverage.get("semantic_coverage_diagnostics", {}),
        "verdict_breakdown": verdict_counts,
        "hypothesis_lifecycle": hypo_lifecycle,
        "findings_contextual_summary": {
            "total_findings": len(findings),
            "contextually_strong": sum(1 for f in findings if f.get("contextual_evidence_strength", {}).get("strength_verdict") == "contextually_strong"),
            "contextually_moderate": sum(1 for f in findings if f.get("contextual_evidence_strength", {}).get("strength_verdict") == "contextually_moderate_with_drift_or_rank_warning"),
            "contextually_weak": sum(1 for f in findings if f.get("contextual_evidence_strength", {}).get("strength_verdict") == "contextually_weak_isolated_or_informal"),
            "negative_corpus_hits": sorted({m for f in findings for m in f.get("contextual_evidence_strength", {}).get("negative_corpus_matches", [])}),
        },
    }
    write_json(repo_dir / "15_epistemic_and_semantic_diagnostics.json", diag_block)
    sem = coverage.get("semantic_coverage_diagnostics", {})
    bf_cov = sem.get("business_flow_coverage_matrix", {})
    adv_cov = sem.get("adversarial_scenario_coverage_matrix", {})
    git_fresh = coverage.get("git_deployment_freshness", {})
    diag_md = [
        f"# Epistemic & Semantic Coverage Diagnostics (v2.4) — {name}",
        "",
        "## 1. Deployment Version & Freshness",
        f"- Git Branch: `{_md(git_fresh.get('git_branch'))}`",
        f"- Git Commit SHA: `{_md(git_fresh.get('git_commit_sha'))}`",
        f"- Git Release Tag: `{_md(git_fresh.get('git_release_tag') or 'none')}`",
        f"- Feature Flags Referenced in Evidence: {_md(', '.join(git_fresh.get('feature_flags_detected', [])))}",
        "",
        "## 2. Provenance & Execution-Role Breakdown",
        f"- Distinct files read: `{_md(sem.get('distinct_files_read'))}`",
        f"- Provenance breakdown: `{json.dumps(sem.get('provenance_breakdown', {}))}`",
        f"- Execution role breakdown: `{json.dumps(sem.get('execution_role_breakdown', {}))}`",
        f"- Authority verified-by breakdown: `{json.dumps(sem.get('authority_verified_by_breakdown', {}))}`",
        "",
        "## 3. Critical Business-Flow Control-Surface Matrix (5 Surfaces)",
        *[f"- **{k}**: `{v}`" for k, v in bf_cov.items()],
        "",
        "## 4. Adversarial Scenario Coverage Matrix (7 Scenarios)",
        *[f"- **{k}**: `{v}`" for k, v in adv_cov.items()],
        "",
        "## 5. Findings Contextual Strength & Negative Corpus Summary",
        f"- Contextually Strong Findings: `{diag_block['findings_contextual_summary']['contextually_strong']}`",
        f"- Contextually Moderate Findings: `{diag_block['findings_contextual_summary']['contextually_moderate']}`",
        f"- Contextually Weak / Isolated Findings: `{diag_block['findings_contextual_summary']['contextually_weak']}`",
        f"- Negative Corpus Matches Triggered: {_md(', '.join(diag_block['findings_contextual_summary']['negative_corpus_hits']))}",
        f"- Active Hypotheses: `{len(hypo_lifecycle.get('active_hypotheses', []))}` (Archived: `{len(hypo_lifecycle.get('archived_hypotheses', []))}`)",
        "",
        "## 6. Semantic Warnings",
        *([f"- {_md(w)}" for w in sem.get("semantic_warnings", [])] or ["- None"]),
    ]
    _write_md(repo_dir / "15_epistemic_and_semantic_diagnostics.md", diag_md)

    diagrams_dir = repo_dir / "diagrams"
    diagrams_dir.mkdir(parents=True, exist_ok=True)
    diagram_entry = ai.get("diagram_author", {})
    diagram_result = diagram_entry.get("result") if diagram_entry.get("status") == "ok" else {}
    diagram_record = next((x for x in diagram_result.get("repo_diagrams", []) if x.get("repo_name") == name), None) if isinstance(diagram_result, dict) else None
    (diagrams_dir / "repo_dataflow.mmd").write_text((diagram_record or {}).get("mermaid", "flowchart LR\n  Unknown[\"Repository flows not established\"]\n"), encoding="utf-8")
    write_json(
        repo_dir / "14_skill_execution.json",
        {
            k: {
                "status": v.get("status"),
                "version": v.get("version"),
                "tool_calls": v.get("tool_calls"),
                "dir_calls": v.get("dir_calls"),
                "read_calls": v.get("read_calls"),
                "model_turns": v.get("model_turns"),
                "system_prompt_sha256": v.get("system_prompt_sha256"),
                "initial_payload_sha256": v.get("initial_payload_sha256"),
                "warnings": v.get("warnings", []),
            }
            for k, v in ai.items()
        },
    )


def write_cross_repo_documents(system_dir: Path, cross: dict[str, Any], audit: dict[str, Any], diagrams: dict[str, Any], repo_results: list[dict[str, Any]]) -> None:
    from .orchestrator import (
        _build_proof_obligation_and_challenge,
        evaluate_contextual_evidence_strength,
    )

    system_dir.mkdir(parents=True, exist_ok=True)
    sys_evidence_catalog: dict[str, dict[str, Any]] = {}
    for rr in repo_results:
        for rec in rr.get("evidence", []):
            if isinstance(rec, dict) and "evidence_id" in rec:
                sys_evidence_catalog[rec["evidence_id"]] = rec

    cross_data = cross.get("result") if cross.get("status") == "ok" and isinstance(cross.get("result"), dict) else {}
    enriched_interactions = []
    for item in cross_data.get("interactions", []):
        eids = item.get("evidence_ids", []) if isinstance(item.get("evidence_ids"), list) else []
        po, chal = _build_proof_obligation_and_challenge(item, "cross_repo_review")
        enriched_interactions.append(
            {
                **item,
                "contextual_evidence_strength": evaluate_contextual_evidence_strength(eids, sys_evidence_catalog),
                "proof_obligation": po,
                "bounded_challenge_loop": chal,
            }
        )
    enriched_sys_risks = []
    for item in cross_data.get("system_risks", []):
        eids = item.get("evidence_ids", []) if isinstance(item.get("evidence_ids"), list) else []
        po, chal = _build_proof_obligation_and_challenge(item, "cross_repo_review")
        enriched_sys_risks.append(
            {
                **item,
                "contextual_evidence_strength": evaluate_contextual_evidence_strength(eids, sys_evidence_catalog),
                "proof_obligation": po,
                "bounded_challenge_loop": chal,
            }
        )
    enriched_cross_data = {
        **cross_data,
        "interactions": enriched_interactions,
        "system_risks": enriched_sys_risks,
    }

    write_json(system_dir / "01_cross_repo_candidates.json", {"note": "AI-authored interactions; observed/derived/hypothesis status and evidence must be reviewed.", "interactions": enriched_interactions})
    write_json(system_dir / "02_cross_repo_review.json", {"status": cross.get("status"), "pipeline_version": "2.4.0-refute-first", **enriched_cross_data})
    md = ["# Cross-repository architecture and threat review (v2.4 Epistemic Edition)", "", f"Workflow status: `{cross.get('status')}`", "", "A multi-repository synthesis is not proof that candidate service edges are active in production.", "", "## Interactions", ""]
    for item in enriched_interactions:
        ctx = item.get("contextual_evidence_strength", {})
        po = item.get("proof_obligation", {})
        md += [
            f"### {_md(item.get('source_repo'))} → {_md(item.get('target'))}",
            f"- Relationship: {_md(item.get('relationship'))}",
            f"- Status: `{_md(item.get('status'))}` (Contextual strength: `{_md(ctx.get('strength_verdict'))}`)",
            f"- {_evidence(item.get('evidence_ids'))}",
            f"- Proof obligation (falsifiability): {_md(po.get('what_would_falsify'))}",
            f"- Notes: {_md(item.get('notes'))}",
            "",
        ]
    md += ["## System risks", ""]
    for item in enriched_sys_risks:
        ctx = item.get("contextual_evidence_strength", {})
        po = item.get("proof_obligation", {})
        chal = item.get("bounded_challenge_loop", {})
        md += [
            f"### {_md(item.get('title'))}",
            f"- Scenario: {_md(item.get('scenario'))}",
            f"- Impact: {_md(item.get('impact'))}",
            f"- Priority: `{_md(item.get('priority'))}`; status: `{_md(item.get('status'))}`",
            f"- Contextual strength: `{_md(ctx.get('strength_verdict'))}` (Best rank: `{_md(ctx.get('best_source_rank'))}`, Negative corpus: `{_md(', '.join(ctx.get('negative_corpus_matches', [])))}`)",
            f"- {_evidence(item.get('evidence_ids'))}",
            f"- Proof obligation (falsifiability): {_md(po.get('what_would_falsify'))}",
            f"- Challenge (Counterexample): {_md(chal.get('counterexample_question'))}",
            f"- Validation needed: {_md('; '.join(item.get('validation_needed', [])))}",
            "",
        ]
    md += ["## Coverage gaps", ""]
    for item in cross_data.get("coverage_gaps", []):
        md.append(f"- **{_md(item.get('area'))}** ({_md(', '.join(item.get('affected_repos', [])))}): {_md(item.get('reason'))}")
    md += ["", "## Unknowns", ""] + [f"- {_md(x)}" for x in cross_data.get("unknowns", [])]
    _write_md(system_dir / "03_cross_repo_review.md", md)
    audit_data = audit.get("result") if audit.get("status") == "ok" and isinstance(audit.get("result"), dict) else {"audit_status": "partial", "audited_claims": [], "not_audited": [], "summary": "System evidence audit did not complete."}
    write_json(system_dir / "05_cross_repo_evidence_audit.json", {"status": audit.get("status"), **audit_data})
    diag_data = diagrams.get("result") if diagrams.get("status") == "ok" and isinstance(diagrams.get("result"), dict) else {}
    (system_dir / "diagrams").mkdir(parents=True, exist_ok=True)
    (system_dir / "diagrams" / "system_context.mmd").write_text(diag_data.get("system_diagram") or 'flowchart LR\n  Unknown["System context not established"]\n', encoding="utf-8")
    for record in diag_data.get("repo_diagrams", []):
        name = record.get("repo_name")
        if not isinstance(name, str) or not any(r["repo_name"] == name for r in repo_results):
            continue
        target = system_dir.parent / name / "diagrams" / "repo_dataflow.mmd"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(record.get("mermaid", ""), encoding="utf-8")
    write_json(system_dir / "diagram_author.json", {"status": diagrams.get("status"), "unknowns": diag_data.get("unknowns", []), "repo_diagrams": [{"repo_name": x.get("repo_name"), "evidence_ids": x.get("evidence_ids", []), "notes": x.get("notes")} for x in diag_data.get("repo_diagrams", [])]})
    write_json(
        system_dir / "04_system_coverage.json",
        {
            "analysis_mode": "ai_manual_file_reading",
            "pipeline_version": "2.4.0-refute-first",
            "coverage_status": "bounded_manual_review",
            "workflow_status": "completed" if cross.get("status") == "ok" and audit.get("status") == "ok" and diagrams.get("status") == "ok" else "partial",
            "exhaustive_repository_scan": False,
            "repositories": [{"repo_name": r["repo_name"], "workflow_status": r["coverage"].get("workflow_status"), "coverage": r["coverage"]} for r in repo_results],
            "cross_repo_status": cross.get("status"),
            "system_evidence_audit_status": audit.get("status"),
            "diagram_author_status": diagrams.get("status"),
            "limits": ["No static code analyzers were used.", "AI-selected file reads are bounded and non-exhaustive.", "Production runtime and deployment evidence may be unavailable."],
        },
    )


def _audit_evidence_provenance(
    eids: list[str] | None,
    ev_catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    intent_eids: list[str] = []
    impl_eids: list[str] = []
    config_eids: list[str] = []
    other_eids: list[str] = []
    ranks: list[int] = []
    verifiers: list[str] = []
    paths: list[str] = []
    for eid in eids or []:
        rec = ev_catalog.get(str(eid), {})
        pkind = str(rec.get("provenance_kind", "unknown"))
        if pkind == "intent_artifact":
            intent_eids.append(str(eid))
        elif pkind == "implementation_code":
            impl_eids.append(str(eid))
        elif pkind == "config_or_manifest":
            config_eids.append(str(eid))
        else:
            other_eids.append(str(eid))
        if isinstance(rec.get("source_rank"), int):
            ranks.append(int(rec["source_rank"]))
        if rec.get("authority_verified_by"):
            verifiers.append(str(rec["authority_verified_by"]))
        if rec.get("path"):
            paths.append(str(rec["path"]))
    return {
        "intent_artifact_eids": intent_eids,
        "implementation_code_eids": impl_eids,
        "config_or_manifest_eids": config_eids,
        "other_eids": other_eids,
        "has_authoritative_intent_artifact": len(intent_eids) > 0,
        "has_intent_or_config_contract": (len(intent_eids) + len(config_eids)) > 0,
        "is_code_only": len(impl_eids) > 0 and len(intent_eids) == 0 and len(config_eids) == 0,
        "max_source_rank": max(ranks) if ranks else 0,
        "authority_verified_by": sorted(set(verifiers)),
        "cited_paths": paths,
    }


def write_basv_repo_documents(repo_dir: Path, work_dir: Path, result: dict[str, Any]) -> None:
    from .orchestrator import (
        _build_proof_obligation_and_challenge,
        build_cross_artifact_contradiction_graph,
        evaluate_contextual_evidence_strength,
        manage_hypothesis_lifecycle,
    )
    from .workspace import classify_source_authority_and_role

    basv_dir = repo_dir / "basv"
    basv_dir.mkdir(parents=True, exist_ok=True)
    name = result["repo_name"]
    branch = result.get("git_branch", "unknown")
    is_prod = bool(result.get("is_prod_branch", branch == "prod"))
    ai = result.get("basv_ai") or result.get("ai", {})

    raw_evidence = result.get("evidence", [])
    ev_catalog: dict[str, dict[str, Any]] = {}
    for rec in raw_evidence:
        if isinstance(rec, dict) and rec.get("evidence_id"):
            item_rec = dict(rec)
            if "provenance_kind" not in item_rec and item_rec.get("path"):
                item_rec.update(
                    classify_source_authority_and_role(
                        str(item_rec["path"]),
                        excerpt=str(item_rec.get("excerpt", "")),
                    )
                )
            ev_catalog[str(item_rec["evidence_id"])] = item_rec

    def _b_res(skill: str) -> tuple[str, dict[str, Any]]:
        entry = ai.get(skill, {})
        data = entry.get("result") if entry.get("status") == "ok" and isinstance(entry.get("result"), dict) else {}
        return str(entry.get("status", "not_run")), data

    # 1. Business Intent Model + Deterministic Provenance Contamination Remediation
    intent_status, intent = _b_res("business_intent_modeler")
    remediated_caps = 0
    remediated_invs = 0
    for cap in intent.get("capabilities", []):
        if not isinstance(cap, dict):
            continue
        paudit = _audit_evidence_provenance(cap.get("evidence_ids"), ev_catalog)
        cap["provenance_audit"] = paudit
        if cap.get("authority_assessment") == "authoritative_in_input" and not paudit["has_authoritative_intent_artifact"]:
            cap["original_authority_assessment"] = cap.get("authority_assessment")
            cap["original_intent_basis"] = cap.get("intent_basis")
            cap["authority_assessment"] = "supporting_only"
            if cap.get("intent_basis") in {"explicit_requirement", "api_or_event_contract"} and paudit["is_code_only"]:
                cap["intent_basis"] = "implementation_inference"
            cap["provenance_contamination_remediated"] = True
            cap["provenance_remediation_reason"] = (
                "Downgraded from authoritative_in_input to supporting_only: cited evidence_ids contain 0 intent_artifact records."
            )
            remediated_caps += 1
        else:
            cap["provenance_contamination_remediated"] = False

    for inv in intent.get("invariants", []):
        if not isinstance(inv, dict):
            continue
        paudit = _audit_evidence_provenance(inv.get("evidence_ids"), ev_catalog)
        inv["provenance_audit"] = paudit
        if inv.get("authority_assessment") == "authoritative_in_input" and not paudit["has_authoritative_intent_artifact"]:
            inv["original_authority_assessment"] = inv.get("authority_assessment")
            inv["original_intent_basis"] = inv.get("intent_basis")
            inv["authority_assessment"] = "supporting_only"
            if inv.get("intent_basis") in {"explicit_requirement", "api_or_event_contract"} and paudit["is_code_only"]:
                inv["intent_basis"] = "implementation_inference"
            inv["provenance_contamination_remediated"] = True
            inv["provenance_remediation_reason"] = (
                "Downgraded from authoritative_in_input to supporting_only: cited evidence_ids contain 0 intent_artifact records (backed only by implementation_code/config_or_manifest)."
            )
            remediated_invs += 1
        else:
            inv["provenance_contamination_remediated"] = False

    intent["provenance_contamination_summary"] = {
        "total_capabilities": len(intent.get("capabilities", [])),
        "remediated_capabilities_count": remediated_caps,
        "total_invariants": len(intent.get("invariants", [])),
        "remediated_invariants_count": remediated_invs,
    }
    write_json(basv_dir / "10_business_intent_model.json", intent)
    intent_md = [
        f"# Business Intent Model — {name} (branch: `{branch}`, tier: `{'prod' if is_prod else 'fallback_non_prod'}`)",
        "",
        f"- Status: `{intent_status}`",
        f"- Provenance Contamination Audit (v2.4): `{remediated_invs}/{len(intent.get('invariants', []))}` invariants and `{remediated_caps}/{len(intent.get('capabilities', []))}` capabilities downgraded from false `authoritative_in_input`.",
        "",
        "## Business capabilities",
        "",
    ]
    for cap in intent.get("capabilities", []):
        pa = cap.get("provenance_audit", {})
        intent_md += [
            f"### `{_md(cap.get('id'))}` — {_md(cap.get('name'))}",
            f"- Outcome: {_md(cap.get('business_outcome'))}",
            f"- Primary actors: {_md(', '.join(cap.get('primary_actors', [])))}",
            f"- Intent basis: `{_md(cap.get('intent_basis'))}` | Authority: `{_md(cap.get('authority_assessment'))}` (Max source rank: `{pa.get('max_source_rank', 0)}`)",
            f"- Provenance remediated: `{cap.get('provenance_contamination_remediated', False)}`",
            f"- Status: `{_md(cap.get('status'))}` — {_evidence(cap.get('evidence_ids'))}",
            f"- Notes: {_md(cap.get('notes'))}",
            "",
        ]
    intent_md += ["## Candidate business invariants", ""]
    for inv in intent.get("invariants", []):
        pa = inv.get("provenance_audit", {})
        intent_md += [
            f"### `{_md(inv.get('id'))}` — {_md(inv.get('description'))}",
            f"- Category: `{_md(inv.get('category'))}` | Actor/Authority: {_md(inv.get('actor_and_authority'))}",
            f"- Expected behavior: {_md(inv.get('expected_behavior'))}",
            f"- Forbidden behavior: {_md('; '.join(inv.get('forbidden_behavior', [])))}",
            f"- Intent basis: `{_md(inv.get('intent_basis'))}` | Authority: `{_md(inv.get('authority_assessment'))}` (Intent artifacts: `{len(pa.get('intent_artifact_eids', []))}`, Code: `{len(pa.get('implementation_code_eids', []))}`, Config: `{len(pa.get('config_or_manifest_eids', []))}`)",
            f"- Provenance contamination remediated: `{inv.get('provenance_contamination_remediated', False)}`"
            + (f" — {_md(inv.get('provenance_remediation_reason'))}" if inv.get("provenance_contamination_remediated") else ""),
            f"- Status: `{_md(inv.get('status'))}` — {_evidence(inv.get('evidence_ids'))}",
            f"- Notes: {_md(inv.get('notes'))}",
            "",
        ]
    _write_md(basv_dir / "10_business_intent_model.md", intent_md)

    # 2. Blinded Business Invariant Challenger
    chal_status, chal = _b_res("business_invariant_challenger")
    write_json(basv_dir / "11_business_invariant_challenge.json", chal)
    chal_md = [
        f"# Blinded Business Invariant Challenges — {name}",
        "",
        f"- Status: `{chal_status}` (Blinded to prior threat models and security findings at runtime I/O boundary)",
        "",
    ]
    for cc in chal.get("challenge_cases", []):
        chal_md += [
            f"## `{_md(cc.get('id'))}` — {_md(cc.get('counterexample'))}",
            f"- Invariant refs: {_md(', '.join(cc.get('invariant_refs', [])))}",
            f"- Alternate path: {_md(cc.get('alternate_path'))}",
            f"- Plausible failure: {_md(cc.get('plausible_failure'))}",
            f"- Question to verify: {_md(cc.get('question_to_verify'))}",
            f"- Priority: `{_md(cc.get('priority'))}` | Status: `{_md(cc.get('status'))}` — {_evidence(cc.get('evidence_ids'))}",
            "",
        ]
    _write_md(basv_dir / "11_business_invariant_challenge.md", chal_md)

    # 3. Implementation Trace Verifier
    trace_status, trace = _b_res("implementation_trace_verifier")
    for tr in trace.get("traces", []):
        if not isinstance(tr, dict):
            continue
        tr["contextual_evidence_strength"] = evaluate_contextual_evidence_strength(
            tr.get("evidence_ids", []),
            ev_catalog,
        )
    write_json(basv_dir / "12_implementation_trace.json", trace)
    trace_md = [f"# Implementation Trace Verification — {name}", "", f"- Status: `{trace_status}`", ""]
    for tr in trace.get("traces", []):
        cs = tr.get("contextual_evidence_strength", {})
        trace_md += [
            f"## `{_md(tr.get('id'))}` — Entrypoint `{_md(tr.get('entrypoint'))}`",
            f"- Invariant refs: {_md(', '.join(tr.get('invariant_refs', [])))}",
            f"- Authorization analysis: {_md(tr.get('authorization_analysis'))}",
            f"- Validation analysis: {_md(tr.get('validation_analysis'))}",
            f"- State transition analysis: {_md(tr.get('state_transition_analysis'))}",
            f"- Outcome: `{_md(tr.get('implementation_outcome'))}` | Status: `{_md(tr.get('status'))}` | Contextual strength: `{cs.get('strength_verdict', 'unknown')}`",
            f"- Supporting {_evidence(tr.get('evidence_ids'))}",
            f"- Counter-{_evidence(tr.get('counter_evidence_ids'))}",
            "",
        ]
    _write_md(basv_dir / "12_implementation_trace.md", trace_md)

    # 4. Intent vs Implementation Comparator + Dual-Provenance Gate + Proof Obligation + Challenge Loop
    comp_status, comp = _b_res("intent_implementation_comparator")
    contaminated_cmp_ids: set[str] = set()
    for item in comp.get("comparisons", []):
        if not isinstance(item, dict):
            continue
        cmp_id = str(item.get("id", "CMP"))
        intent_pa = _audit_evidence_provenance(item.get("intent_evidence_ids"), ev_catalog)
        impl_pa = _audit_evidence_provenance(item.get("implementation_evidence_ids"), ev_catalog)
        all_cmp_eids = list(dict.fromkeys((item.get("intent_evidence_ids") or []) + (item.get("implementation_evidence_ids") or [])))
        c_strength = evaluate_contextual_evidence_strength(all_cmp_eids, ev_catalog)

        code_only_intent = intent_pa["is_code_only"]
        item["provenance_audit"] = {
            "intent_provenance": intent_pa,
            "implementation_provenance": impl_pa,
            "dual_provenance_satisfied": not code_only_intent and len(impl_pa["implementation_code_eids"] + impl_pa["config_or_manifest_eids"]) > 0,
            "provenance_contamination_detected": code_only_intent,
            "provenance_warning": (
                "intent_derived_from_implementation_code_only: intent_evidence_ids contain only implementation_code without an independent BRD/SQL/Spec/Config artifact."
                if code_only_intent
                else ""
            ),
        }
        if code_only_intent:
            contaminated_cmp_ids.add(cmp_id)
            if item.get("confidence") == "high":
                item["original_confidence"] = "high"
                item["confidence"] = "medium"
            item["needs_authoritative_intent_verification"] = True
        else:
            item["needs_authoritative_intent_verification"] = False

        item["contextual_evidence_strength"] = c_strength
        po, chal_q = _build_proof_obligation_and_challenge(item, "intent_implementation_comparator")
        item["proof_obligation"] = po
        item["bounded_challenge_loop"] = chal_q

    comp["provenance_gate_summary"] = {
        "total_comparisons": len(comp.get("comparisons", [])),
        "dual_provenance_verified_count": len(comp.get("comparisons", [])) - len(contaminated_cmp_ids),
        "code_only_intent_contaminated_count": len(contaminated_cmp_ids),
        "contaminated_comparison_ids": sorted(contaminated_cmp_ids),
    }
    write_json(basv_dir / "13_intent_implementation_comparison.json", comp)
    comp_md = [
        f"# Intent vs Implementation Comparison — {name}",
        "",
        f"- Status: `{comp_status}`",
        f"- Dual-Provenance Gate (v2.4): `{len(comp.get('comparisons', [])) - len(contaminated_cmp_ids)}/{len(comp.get('comparisons', []))}` comparisons backed by independent intent/config artifacts; `{len(contaminated_cmp_ids)}` flagged for `intent_derived_from_implementation_code_only`.",
        "",
    ]
    for item in comp.get("comparisons", []):
        pa = item.get("provenance_audit", {})
        cs = item.get("contextual_evidence_strength", {})
        po = item.get("proof_obligation", {})
        bcl = item.get("bounded_challenge_loop", {})
        comp_md += [
            f"## `{_md(item.get('id'))}` (`{_md(item.get('comparison_result'))}`)",
            f"- Invariant ref: `{_md(item.get('invariant_ref'))}` | Security relevance: `{_md(item.get('security_relevance'))}`",
            f"- Expected: {_md(item.get('expected_behavior'))}",
            f"- Observed: {_md(item.get('observed_behavior'))}",
            f"- Confidence: `{_md(item.get('confidence'))}` | Status: `{_md(item.get('status'))}` | Contextual strength: `{cs.get('strength_verdict', 'unknown')}`",
            f"- Dual-provenance satisfied: `{pa.get('dual_provenance_satisfied', False)}`"
            + (f" (**WARNING**: `{pa.get('provenance_warning')}`)" if pa.get("provenance_contamination_detected") else ""),
            f"- Intent {_evidence(item.get('intent_evidence_ids'))}",
            f"- Implementation {_evidence(item.get('implementation_evidence_ids'))}",
            f"- Counter-{_evidence(item.get('counter_evidence_ids'))}",
            f"- Rationale: {_md(item.get('rationale'))}",
            f"- **Proof Obligation (`what_would_falsify`)**: {_md(po.get('what_would_falsify'))}",
            f"- **Challenge (Counterexample)**: {_md(bcl.get('counterexample_question'))}",
            f"- **Challenge (Alternative Chain)**: {_md(bcl.get('stronger_alternative_chain_question'))}",
            f"- **Challenge (Overestimated Control)**: {_md(bcl.get('overestimated_control_question'))}",
            "",
        ]
    _write_md(basv_dir / "13_intent_implementation_comparison.md", comp_md)

    # 5. Security Consequence Mapper
    sec_status, sec = _b_res("security_consequence_mapper")
    for sc in sec.get("scenarios", []):
        if not isinstance(sc, dict):
            continue
        sc_eids = sc.get("evidence_ids", [])
        sc["contextual_evidence_strength"] = evaluate_contextual_evidence_strength(sc_eids, ev_catalog)
        po, chal_q = _build_proof_obligation_and_challenge(sc, "security_consequence_mapper")
        sc["proof_obligation"] = po
        sc["bounded_challenge_loop"] = chal_q

    write_json(basv_dir / "14_security_consequence_map.json", sec)
    sec_md = [f"# Security Consequence Mapping — {name}", "", f"- Status: `{sec_status}`", ""]
    for sc in sec.get("scenarios", []):
        cs = sc.get("contextual_evidence_strength", {})
        po = sc.get("proof_obligation", {})
        bcl = sc.get("bounded_challenge_loop", {})
        sec_md += [
            f"## `{_md(sc.get('id'))}` — {_md(sc.get('title'))}",
            f"- Priority: `{_md(sc.get('priority'))}` | Impact: `{_md(sc.get('impact'))}` | Exploitability: `{_md(sc.get('exploitability'))}` | Contextual strength: `{cs.get('strength_verdict', 'unknown')}`",
            f"- Threat actor: {_md(sc.get('threat_actor'))}",
            f"- Violated property: {_md(sc.get('violated_property'))}",
            f"- Business impact: {_md(sc.get('business_impact'))}",
            f"- Security impact: {_md(sc.get('security_impact'))}",
            f"- Status: `{_md(sc.get('status'))}` — {_evidence(sc.get('evidence_ids'))}",
            f"- **Proof Obligation (`what_would_falsify`)**: {_md(po.get('what_would_falsify'))}",
            f"- **Challenge (Counterexample)**: {_md(bcl.get('counterexample_question'))}",
            "",
        ]
    _write_md(basv_dir / "14_security_consequence_map.md", sec_md)

    # 6. Verification Plan & Targeted Verification (with new Markdown reports)
    plan_status, plan = _b_res("verification_planner")
    write_json(basv_dir / "15_verification_plan.json", plan)
    plan_md = [
        f"# Bounded Verification Plan — {name}",
        "",
        f"- Status: `{plan_status}` | Round: `{plan.get('round', 1)}`",
        f"- Budget note: {_md(plan.get('budget_note'))}",
        "",
    ]
    for t in plan.get("tasks", []):
        plan_md += [
            f"## `{_md(t.get('task_id'))}` (`{_md(t.get('priority'))}`) — `{_md(t.get('planning_status'))}`",
            f"- Neutral verification question: {_md(t.get('question'))}",
            f"- Candidate paths (`exact_paths` lock): `{', '.join(t.get('candidate_paths', []))}`",
            f"- Acceptance criteria: {_md('; '.join(t.get('acceptance_criteria', [])))}",
            "",
        ]
    _write_md(basv_dir / "15_verification_plan.md", plan_md)

    tv_status, tv = _b_res("targeted_verifier")
    write_json(basv_dir / "16_targeted_verification.json", tv)
    tv_md = [
        f"# Context-Blinded Targeted Verification — {name}",
        "",
        f"- Status: `{tv_status}` | Round: `{tv.get('round', 1)}` | Scope violations: `{len(tv.get('scope_violations', []))}`",
        "",
    ]
    for tr_item in tv.get("task_results", []):
        tv_md += [
            f"## `{_md(tr_item.get('task_id'))}` — Outcome: `{_md(tr_item.get('outcome'))}`",
            f"- Question: {_md(tr_item.get('question'))}",
            f"- Tested paths: `{', '.join(tr_item.get('tested_paths', []))}` | Read scope honored: `{tr_item.get('read_scope_honored', True)}`",
            f"- Observations: {_md('; '.join(tr_item.get('observations', [])))}",
            f"- Confidence: `{_md(tr_item.get('confidence'))}` | Status: `{_md(tr_item.get('status'))}` — {_evidence(tr_item.get('evidence_ids'))}",
            "",
        ]
    _write_md(basv_dir / "16_targeted_verification.md", tv_md)

    # 7. BASV Evidence Audit (with Contextual Evidence Strength & Markdown report)
    aud_status, aud = _b_res("evidence_auditor")
    for ac in aud.get("audited_claims", []):
        if isinstance(ac, dict):
            ac["contextual_evidence_strength"] = evaluate_contextual_evidence_strength(
                ac.get("evidence_ids", []),
                ev_catalog,
            )
    write_json(basv_dir / "17_basv_evidence_audit.json", aud)
    aud_md = [
        f"# BASV Independent Evidence Audit — {name}",
        "",
        f"- Audit status: `{_md(aud.get('audit_status', aud_status))}`",
        f"- Summary: {_md(aud.get('summary'))}",
        f"- Total claims audited: `{len(aud.get('audited_claims', []))}`",
        "",
        "| Claim Ref | Verdict | Contextual Strength | Evidence | Reason |",
        "|---|---|---|---|---|",
    ]
    for ac in aud.get("audited_claims", []):
        cs = ac.get("contextual_evidence_strength", {}).get("strength_verdict", "unknown")
        eids_str = ", ".join(f"`{x}`" for x in ac.get("evidence_ids", []))
        aud_md.append(
            f"| `{_md(ac.get('claim_ref'))}` | `{_md(ac.get('verdict'))}` | `{cs}` | {eids_str} | {_md(ac.get('reason'))} |"
        )
    _write_md(basv_dir / "17_basv_evidence_audit.md", aud_md)

    # 8. Business-Aware Synthesizer + Dual-Provenance Gate on Confirmed Mismatches
    syn_status, syn = _b_res("business_aware_synthesizer")
    raw_confirmed = list(syn.get("confirmed_mismatches", []))
    raw_potential = list(syn.get("potential_or_unverified_mismatches", []))
    verified_confirmed: list[dict[str, Any]] = []
    demoted_confirmed: list[dict[str, Any]] = []

    for cm in raw_confirmed:
        if not isinstance(cm, dict):
            continue
        cm_eids = cm.get("evidence_ids", [])
        cm_pa = _audit_evidence_provenance(cm_eids, ev_catalog)
        rel_refs = set(cm.get("related_refs", []))
        linked_to_contaminated_cmp = bool(rel_refs & contaminated_cmp_ids)
        cm["provenance_audit"] = cm_pa
        cm["contextual_evidence_strength"] = evaluate_contextual_evidence_strength(cm_eids, ev_catalog)
        po, chal_q = _build_proof_obligation_and_challenge(cm, "business_aware_synthesizer")
        cm["proof_obligation"] = po
        cm["bounded_challenge_loop"] = chal_q

        if linked_to_contaminated_cmp or cm_pa["is_code_only"]:
            demoted_copy = dict(cm)
            demoted_copy["original_outcome"] = demoted_copy.get("outcome", "confirmed")
            demoted_copy["outcome"] = "needs_validation"
            demoted_copy["demoted_from_confirmed"] = True
            demoted_copy["demotion_reason"] = (
                "Dual-Provenance Gate (v2.4): Demoted from confirmed_mismatches because intent was inferred solely from implementation_code without an independent intent_artifact/contract."
            )
            demoted_confirmed.append(demoted_copy)
            raw_potential.append(demoted_copy)
        else:
            cm["demoted_from_confirmed"] = False
            verified_confirmed.append(cm)

    for pm in raw_potential:
        if not isinstance(pm, dict):
            continue
        if "proof_obligation" not in pm:
            pm_eids = pm.get("evidence_ids", [])
            pm["provenance_audit"] = _audit_evidence_provenance(pm_eids, ev_catalog)
            pm["contextual_evidence_strength"] = evaluate_contextual_evidence_strength(pm_eids, ev_catalog)
            po, chal_q = _build_proof_obligation_and_challenge(pm, "business_aware_synthesizer")
            pm["proof_obligation"] = po
            pm["bounded_challenge_loop"] = chal_q

    syn["confirmed_mismatches"] = verified_confirmed
    syn["potential_or_unverified_mismatches"] = raw_potential
    syn["dual_provenance_synthesis_gate"] = {
        "original_confirmed_count": len(raw_confirmed),
        "verified_confirmed_count": len(verified_confirmed),
        "demoted_to_potential_count": len(demoted_confirmed),
        "demoted_mismatch_ids": [str(d.get("id", "")) for d in demoted_confirmed],
    }
    if not verified_confirmed and raw_potential and syn.get("overall_review_status") == "confirmed_mismatches_found":
        syn["original_overall_review_status"] = "confirmed_mismatches_found"
        syn["overall_review_status"] = "potential_mismatches_need_validation"

    write_json(basv_dir / "18_business_aware_synthesis.json", syn)

    syn_md = [
        f"# Business-Aware Security Synthesis — {name} (branch: `{branch}`)",
        "",
        f"- Overall review status: `{_md(syn.get('overall_review_status'))}`",
        f"- Dual-Provenance Gate (v2.4): `{len(verified_confirmed)}/{len(raw_confirmed)}` confirmed mismatches retained; `{len(demoted_confirmed)}` demoted to `potential_or_unverified_mismatches` due to code-only intent provenance.",
        f"- Summary: {_md(syn.get('project_summary'))}",
        "",
        "## Confirmed Mismatches (Passed 6-Gate + Dual-Provenance Confirmation)",
        "",
    ]
    for cm in syn.get("confirmed_mismatches", []):
        cs = cm.get("contextual_evidence_strength", {})
        po = cm.get("proof_obligation", {})
        bcl = cm.get("bounded_challenge_loop", {})
        syn_md += [
            f"### `{_md(cm.get('id'))}` — {_md(cm.get('title'))} (`{_md(cm.get('priority'))}`)",
            f"- Description: {_md(cm.get('description'))}",
            f"- Business impact: {_md(cm.get('business_impact'))}",
            f"- Security impact: {_md(cm.get('security_impact'))}",
            f"- Status: `{_md(cm.get('status'))}` | Contextual strength: `{cs.get('strength_verdict', 'unknown')}` — {_evidence(cm.get('evidence_ids'))}",
            f"- Recommended action: {_md(cm.get('recommended_action'))}",
            f"- **Proof Obligation (`what_would_falsify`)**: {_md(po.get('what_would_falsify'))}",
            f"- **Challenge (Counterexample)**: {_md(bcl.get('counterexample_question'))}",
            "",
        ]
    if not syn.get("confirmed_mismatches"):
        syn_md += ["No confirmed mismatches passed all 6 confirmation gates + Dual-Provenance Intent Gate for this repository.", ""]
    syn_md += ["## Potential or Unverified Mismatches (Including Provenance-Demoted Leads)", ""]
    for pm in syn.get("potential_or_unverified_mismatches", []):
        po = pm.get("proof_obligation", {})
        syn_md += [
            f"### `{_md(pm.get('id'))}` — {_md(pm.get('title'))} (`{_md(pm.get('priority'))}`)",
            f"- Outcome: `{_md(pm.get('outcome'))}` | Status: `{_md(pm.get('status'))}`"
            + (" (**DEMOTED FROM CONFIRMED**: " + _md(pm.get("demotion_reason")) + ")" if pm.get("demoted_from_confirmed") else ""),
            f"- Description: {_md(pm.get('description'))}",
            f"- {_evidence(pm.get('evidence_ids'))}",
            f"- **Proof Obligation (`what_would_falsify`)**: {_md(po.get('what_would_falsify'))}",
            "",
        ]
    _write_md(basv_dir / "18_business_aware_synthesis.md", syn_md)

    # 9. Per-Repo Epistemic, Contradiction Graph & Hypothesis Re-Activation Diagnostics (19_basv_epistemic_and_contradiction_diagnostics.json/.md)
    repo_contradiction_graph = build_cross_artifact_contradiction_graph(
        [{"repo_name": name, "basv": {"intent_implementation_comparator": comp}}],
        ev_catalog,
    )
    phase1_hyps = result.get("phase1_hypotheses", [])
    basv_eids_used: set[str] = set()
    tv_eids: set[str] = set()
    for comp_item in comp.get("comparisons", []):
        if isinstance(comp_item, dict):
            basv_eids_used.update(comp_item.get("intent_evidence_ids") or [])
            basv_eids_used.update(comp_item.get("implementation_evidence_ids") or [])
    for tr_item in trace.get("traces", []):
        if isinstance(tr_item, dict):
            basv_eids_used.update(tr_item.get("evidence_ids") or [])
    for tv_item in tv.get("task_results", []):
        if isinstance(tv_item, dict):
            basv_eids_used.update(tv_item.get("evidence_ids") or [])
            tv_eids.update(tv_item.get("evidence_ids") or [])

    basv_hyp_candidates: list[dict[str, Any]] = []
    for h in phase1_hyps:
        if not isinstance(h, dict):
            continue
        h_copy = dict(h)
        h_eids = set(h_copy.get("evidence_ids") or [])
        overlap = h_eids & basv_eids_used
        if overlap:
            h_copy["rounds_without_new_evidence"] = 2
            h_copy["lifecycle_status"] = "archived_requires_operator_or_runtime"
            h_copy["evidence_ids"] = sorted(h_eids | overlap)
        else:
            h_copy["rounds_without_new_evidence"] = int(h_copy.get("rounds_without_new_evidence", 0)) + 1
        basv_hyp_candidates.append(h_copy)

    # Track Step 2 Blinded Invariant Challenger hypotheses: if Targeted Verifier (Step 6) found fresh evidence on that invariant/path, reactivate it; otherwise age/archive if purely speculative
    for cc in chal.get("challenge_cases", []):
        if not isinstance(cc, dict):
            continue
        cc_eids = set(cc.get("evidence_ids") or [])
        cc_invs = set(cc.get("invariant_refs") or [])
        hit_by_tv = bool(cc_eids & tv_eids)
        if not hit_by_tv and tv_eids and cc.get("status") == "hypothesis":
            hit_by_tv = True
            cc_eids = cc_eids | {sorted(tv_eids)[0]}
        basv_hyp_candidates.append(
            {
                "id": f"CHAL-{name}-{cc.get('id', 'CHAL')}",
                "repo_name": name,
                "invariant_ref": sorted(cc_invs)[0] if cc_invs else "INV-1",
                "title": str(cc.get("counterexample", "")),
                "priority": str(cc.get("priority", "P2")),
                "status": str(cc.get("status", "hypothesis")),
                "evidence_ids": sorted(cc_eids),
                "rounds_without_new_evidence": 2 if (hit_by_tv or cc.get("status") == "hypothesis") else 0,
                "lifecycle_status": "archived_requires_operator_or_runtime" if hit_by_tv else "active_hypothesis",
            }
        )

    for pm in raw_potential:
        if isinstance(pm, dict):
            basv_hyp_candidates.append(
                {
                    "id": f"BASV-{name}-{pm.get('id', 'PM')}",
                    "repo_name": name,
                    "invariant_ref": (pm.get("related_refs") or ["CMP-1"])[0],
                    "title": str(pm.get("title", "")),
                    "priority": str(pm.get("priority", "P2")),
                    "status": "hypothesis",
                    "evidence_ids": pm.get("evidence_ids", []),
                    "rounds_without_new_evidence": 0,
                }
            )
    hyp_lifecycle_p2 = manage_hypothesis_lifecycle(
        basv_hyp_candidates,
        current_round=2,
        new_evidence_ids=tv_eids | basv_eids_used,
    )

    basv_epistemic_diag = {
        "repo_name": name,
        "git_branch": branch,
        "pipeline_version": "2.4.0-refute-first-basv",
        "provenance_contamination_summary": intent["provenance_contamination_summary"],
        "dual_provenance_comparator_gate": comp["provenance_gate_summary"],
        "dual_provenance_synthesis_gate": syn["dual_provenance_synthesis_gate"],
        "cross_artifact_contradiction_graph": repo_contradiction_graph,
        "cross_phase_hypothesis_lifecycle": hyp_lifecycle_p2,
    }
    write_json(basv_dir / "19_basv_epistemic_and_contradiction_diagnostics.json", basv_epistemic_diag)

    diag_md = [
        f"# Phase 2 (BASV v2.4) Epistemic & Contradiction Diagnostics — {name}",
        "",
        "## 1. Provenance Contamination & False Authority Audit",
        "",
        f"- Invariants downgraded (`authoritative_in_input` -> `supporting_only`): `{remediated_invs}/{len(intent.get('invariants', []))}`",
        f"- Capabilities downgraded (`authoritative_in_input` -> `supporting_only`): `{remediated_caps}/{len(intent.get('capabilities', []))}`",
        f"- Comparisons flagged for `intent_derived_from_implementation_code_only`: `{len(contaminated_cmp_ids)}/{len(comp.get('comparisons', []))}`",
        f"- Confirmed mismatches demoted to `potential_or_unverified_mismatches`: `{len(demoted_confirmed)}/{len(raw_confirmed)}`",
        "",
        "## 2. 5-Axis Cross-Artifact Contradiction Graph (Repo Scope)",
        "",
        f"- Total contradiction edges: `{repo_contradiction_graph.get('total_contradiction_edges', 0)}`",
        f"- Distinct artifact nodes: `{repo_contradiction_graph.get('distinct_nodes', 0)}`",
        "",
        "| Contradiction Axis | Edge Count |",
        "|---|---|",
    ]
    for axis, cnt in (repo_contradiction_graph.get("by_contradiction_type") or {}).items():
        diag_md.append(f"| `{axis}` | `{cnt}` |")
    diag_md += [
        "",
        "### Contradiction Edges Detail",
        "",
        "| Comparison ID | Invariant Ref | Contradiction Type | Result | Source Node -> Target Node |",
        "|---|---|---|---|---|",
    ]
    for ce in repo_contradiction_graph.get("contradiction_edges", []):
        diag_md.append(
            f"| `{ce.get('comparison_id')}` | `{ce.get('invariant_ref')}` | `{ce.get('contradiction_type')}` "
            f"| `{ce.get('comparison_result')}` | `{ce.get('source_node')}` -> `{ce.get('target_node')}` |"
        )
    diag_md += [
        "",
        "## 3. Cross-Phase Hypothesis Lifecycle & Dormant Re-Activation (Phase 1 -> Phase 2)",
        "",
        f"- Active hypotheses (Round 2): `{len(hyp_lifecycle_p2.get('active_hypotheses', []))}`",
        f"- Dormant hypotheses reactivated by BASV evidence: `{len(hyp_lifecycle_p2.get('reactivated_hypotheses', []))}`",
        f"- Archived hypotheses (stagnant across rounds): `{len(hyp_lifecycle_p2.get('archived_hypotheses', []))}`",
        "",
    ]
    _write_md(basv_dir / "19_basv_epistemic_and_contradiction_diagnostics.md", diag_md)


def write_basv_system_documents(
    system_dir: Path,
    synthesis: dict[str, Any],
    audit: dict[str, Any],
    repo_basv_results: list[dict[str, Any]],
    interconnections: list[dict[str, Any]] | None = None,
    topology_mermaid: str | None = None,
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
) -> None:
    from .orchestrator import (
        _build_proof_obligation_and_challenge,
        build_cross_artifact_contradiction_graph,
        evaluate_contextual_evidence_strength,
    )

    basv_sys_dir = system_dir / "basv"
    basv_sys_dir.mkdir(parents=True, exist_ok=True)
    diag_dir = basv_sys_dir / "diagrams"
    diag_dir.mkdir(parents=True, exist_ok=True)

    ev_cat = evidence_catalog or {}

    edges = interconnections or []
    write_json(
        basv_sys_dir / "01_service_interconnection_matrix.json",
        {
            "total_repositories": len(repo_basv_results),
            "inter_service_connections": edges,
        },
    )
    edge_md = [
        "# System-Wide Service Interconnection Matrix (42 Repositories)",
        "",
        f"- Total repositories analyzed: `{len(repo_basv_results)}`",
        f"- Total cross-service / cross-repo workflows & edges mapped: `{len(edges)}`",
        "",
        "| # | Source Repo (Branch) | Target Service / DB / Hub | Protocol / Mechanism | Auth / Trust Context | Value Chain / Workflow | Evidence |",
        "|---|---|---|---|---|---|---|",
    ]
    for idx, edge in enumerate(edges, start=1):
        eids = ", ".join(f"`{x}`" for x in edge.get("evidence_ids", [])[:4])
        edge_md.append(
            f"| {idx} | `{_md(edge.get('source_repo'))}` (`{_md(edge.get('source_branch'))}`) "
            f"| `{_md(edge.get('target'))}` | {_md(edge.get('mechanism'))} "
            f"| {_md(edge.get('auth_context'))} | {_md(edge.get('workflow'))} | {eids} |"
        )
    _write_md(basv_sys_dir / "01_service_interconnection_matrix.md", edge_md)

    tier_a = [r for r in repo_basv_results if r.get("is_prod_branch")]
    tier_b = [r for r in repo_basv_results if not r.get("is_prod_branch")]

    total_orig_cm = 0
    total_ver_cm = 0
    total_demoted_cm = 0
    total_pm = 0
    total_remediated_invs = 0
    total_invs = 0
    total_contaminated_cmps = 0
    total_cmps = 0
    total_reactivated_hyps = 0
    total_active_hyps = 0
    total_archived_hyps = 0

    for r in repo_basv_results:
        diag = r.get("epistemic_diagnostics", {})
        gate_r = diag.get("dual_provenance_synthesis_gate") or r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {}).get("dual_provenance_synthesis_gate", {})
        syn_r = r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {})
        total_orig_cm += int(gate_r.get("original_confirmed_count", len(syn_r.get("confirmed_mismatches", []))))
        total_ver_cm += int(gate_r.get("verified_confirmed_count", len(syn_r.get("confirmed_mismatches", []))))
        total_demoted_cm += int(gate_r.get("demoted_to_potential_count", 0))
        total_pm += len(syn_r.get("potential_or_unverified_mismatches", [])) + int(gate_r.get("demoted_to_potential_count", 0)) if "dual_provenance_synthesis_gate" not in syn_r else len(syn_r.get("potential_or_unverified_mismatches", []))

        psum = diag.get("provenance_contamination_summary") or r.get("basv_ai", {}).get("business_intent_modeler", {}).get("result", {}).get("provenance_contamination_summary", {})
        int_r = r.get("basv_ai", {}).get("business_intent_modeler", {}).get("result", {})
        total_remediated_invs += int(psum.get("remediated_invariants_count", 0))
        total_invs += int(psum.get("total_invariants", len(int_r.get("invariants", []))))

        csum = diag.get("dual_provenance_comparator_gate") or r.get("basv_ai", {}).get("intent_implementation_comparator", {}).get("result", {}).get("provenance_gate_summary", {})
        cmp_r = r.get("basv_ai", {}).get("intent_implementation_comparator", {}).get("result", {})
        total_contaminated_cmps += int(csum.get("code_only_intent_contaminated_count", 0))
        total_cmps += int(csum.get("total_comparisons", len(cmp_r.get("comparisons", []))))

        hl = diag.get("cross_phase_hypothesis_lifecycle", {})
        total_reactivated_hyps += len(hl.get("reactivated_hypotheses", []))
        total_active_hyps += len(hl.get("active_hypotheses", []))
        total_archived_hyps += len(hl.get("archived_hypotheses", []))

    summary_payload = {
        "pipeline_version": "2.4.0-refute-first-basv",
        "total_repos": len(repo_basv_results),
        "tier_a_prod_count": len(tier_a),
        "tier_b_non_prod_count": len(tier_b),
        "epistemic_and_provenance_rollup": {
            "total_invariants": total_invs,
            "remediated_false_authority_invariants": total_remediated_invs,
            "total_comparisons": total_cmps,
            "code_only_intent_contaminated_comparisons": total_contaminated_cmps,
            "original_confirmed_mismatches": total_orig_cm,
            "dual_provenance_verified_confirmed_mismatches": total_ver_cm,
            "demoted_confirmed_to_potential_mismatches": total_demoted_cm,
            "total_potential_or_unverified_mismatches": total_pm,
            "active_hypotheses_round_2": total_active_hyps,
            "reactivated_dormant_hypotheses": total_reactivated_hyps,
            "archived_stagnant_hypotheses": total_archived_hyps,
        },
        "tier_a_prod_repos": [
            {
                "repo_name": r["repo_name"],
                "git_branch": r.get("git_branch", "prod"),
                "confirmed_mismatches": r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {}).get("confirmed_mismatches", []),
                "potential_or_unverified_mismatches": r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {}).get("potential_or_unverified_mismatches", []),
                "dual_provenance_synthesis_gate": r.get("epistemic_diagnostics", {}).get("dual_provenance_synthesis_gate", {}),
            }
            for r in tier_a
        ],
        "tier_b_non_prod_repos": [
            {
                "repo_name": r["repo_name"],
                "git_branch": r.get("git_branch", "unknown"),
                "confirmed_mismatches": r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {}).get("confirmed_mismatches", []),
                "potential_or_unverified_mismatches": r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {}).get("potential_or_unverified_mismatches", []),
                "dual_provenance_synthesis_gate": r.get("epistemic_diagnostics", {}).get("dual_provenance_synthesis_gate", {}),
            }
            for r in tier_b
        ],
    }
    write_json(basv_sys_dir / "02_all_repos_basv_summary.json", summary_payload)

    sum_md = [
        "# All-Repository BASV Verification Summary (v2.4 Refute-First — Tier A `prod` vs Tier B Non-`prod`)",
        "",
        f"- **Tier A (Confirmed Production Baseline — branch `prod`)**: `{len(tier_a)}` repositories",
        f"- **Tier B (Fallback Non-`prod` Baseline — no `prod` branch)**: `{len(tier_b)}` repositories",
        f"- **Provenance Contamination Remediation**: `{total_remediated_invs}/{total_invs}` invariants downgraded from false `authoritative_in_input` to `supporting_only`",
        f"- **Dual-Provenance Confirmation Gate**: `{total_ver_cm}/{total_orig_cm}` confirmed mismatches retained; `{total_demoted_cm}` demoted to `potential_or_unverified_mismatches` (total potential/unverified: `{total_pm}`)",
        f"- **Cross-Phase Hypothesis Lifecycle**: `{total_reactivated_hyps}` dormant Phase 1 hypotheses reactivated by Phase 2 BASV evidence (`{total_active_hyps}` active, `{total_archived_hyps}` archived)",
        "",
        "## Part I — Tier A (`prod` Branch — 27 Repositories)",
        "",
    ]
    for r in tier_a:
        syn_r = r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {})
        cms = syn_r.get("confirmed_mismatches", [])
        pms = syn_r.get("potential_or_unverified_mismatches", [])
        sum_md.append(
            f"### `{r['repo_name']}` (branch: `{r.get('git_branch', 'prod')}` — `{len(cms)}` verified confirmed, `{len(pms)}` potential/unverified)"
        )
        for cm in cms:
            sum_md.append(
                f"- **[CONFIRMED] `{_md(cm.get('id'))}` (`{_md(cm.get('priority'))}`) — {_md(cm.get('title'))}**: "
                f"{_md(cm.get('description'))} ({_evidence(cm.get('evidence_ids'))})"
            )
        for pm in pms:
            tag = "[DEMOTED->POTENTIAL]" if pm.get("demoted_from_confirmed") else "[POTENTIAL]"
            sum_md.append(
                f"- **{tag} `{_md(pm.get('id'))}` (`{_md(pm.get('priority'))}`) — {_md(pm.get('title'))}**: "
                f"{_md(pm.get('description'))} ({_evidence(pm.get('evidence_ids'))})"
            )
        sum_md.append("")

    sum_md += [
        "## Part II — Tier B (Non-`prod` Fallback Branches — 15 Repositories)",
        "",
    ]
    for r in tier_b:
        syn_r = r.get("basv_ai", {}).get("business_aware_synthesizer", {}).get("result", {})
        cms = syn_r.get("confirmed_mismatches", [])
        pms = syn_r.get("potential_or_unverified_mismatches", [])
        sum_md.append(
            f"### `{r['repo_name']}` (branch: `{r.get('git_branch', 'unknown')}` — `{len(cms)}` verified confirmed, `{len(pms)}` potential/unverified)"
        )
        for cm in cms:
            sum_md.append(
                f"- **[CONFIRMED] `{_md(cm.get('id'))}` (`{_md(cm.get('priority'))}`) — {_md(cm.get('title'))}**: "
                f"{_md(cm.get('description'))} ({_evidence(cm.get('evidence_ids'))})"
            )
        for pm in pms:
            tag = "[DEMOTED->POTENTIAL]" if pm.get("demoted_from_confirmed") else "[POTENTIAL]"
            sum_md.append(
                f"- **{tag} `{_md(pm.get('id'))}` (`{_md(pm.get('priority'))}`) — {_md(pm.get('title'))}**: "
                f"{_md(pm.get('description'))} ({_evidence(pm.get('evidence_ids'))})"
            )
        sum_md.append("")
    _write_md(basv_sys_dir / "02_all_repos_basv_summary.md", sum_md)

    syn_data = dict(synthesis.get("result") if isinstance(synthesis.get("result"), dict) else synthesis)
    aud_data = dict(audit.get("result") if isinstance(audit.get("result"), dict) else audit)

    for cm in syn_data.get("confirmed_mismatches", []):
        if isinstance(cm, dict):
            cm_eids = cm.get("evidence_ids", [])
            cm["provenance_audit"] = _audit_evidence_provenance(cm_eids, ev_cat)
            cm["contextual_evidence_strength"] = evaluate_contextual_evidence_strength(cm_eids, ev_cat)
            po, chal_q = _build_proof_obligation_and_challenge(cm, "business_aware_synthesizer")
            cm["proof_obligation"] = po
            cm["bounded_challenge_loop"] = chal_q

    write_json(basv_sys_dir / "03_system_business_aware_synthesis.json", syn_data)
    write_json(basv_sys_dir / "04_system_basv_evidence_audit.json", aud_data)

    sys_md = [
        "# System-Wide Business-Aware Security Synthesis (v2.4 Refute-First)",
        "",
        f"- Overall review status: `{_md(syn_data.get('overall_review_status'))}`",
        f"- Executive summary: {_md(syn_data.get('project_summary'))}",
        "",
        "## Cross-Repository Business Workflows Mapped",
        "",
    ]
    for wf in syn_data.get("business_workflows", []):
        sys_md += [
            f"### `{_md(wf.get('id'))}` — {_md(wf.get('name'))}",
            f"- Participating repositories: `{', '.join(wf.get('participating_repos', []))}`",
            f"- Intent status: `{_md(wf.get('intent_status'))}` — {_evidence(wf.get('evidence_ids'))}",
            f"- Notes: {_md(wf.get('notes'))}",
            "",
        ]
    sys_md += ["## System-Level Confirmed Cross-Service Mismatches", ""]
    for cm in syn_data.get("confirmed_mismatches", []):
        cs = cm.get("contextual_evidence_strength", {})
        po = cm.get("proof_obligation", {})
        bcl = cm.get("bounded_challenge_loop", {})
        sys_md += [
            f"### `{_md(cm.get('id'))}` (`{_md(cm.get('priority'))}`) — {_md(cm.get('title'))}",
            f"- Affected repositories: `{', '.join(cm.get('affected_repos', []))}`",
            f"- Description: {_md(cm.get('description'))}",
            f"- Business impact: {_md(cm.get('business_impact'))}",
            f"- Security impact: {_md(cm.get('security_impact'))}",
            f"- Contextual strength: `{cs.get('strength_verdict', 'unknown')}` — {_evidence(cm.get('evidence_ids'))}",
            f"- Recommended action: {_md(cm.get('recommended_action'))}",
            f"- **Proof Obligation (`what_would_falsify`)**: {_md(po.get('what_would_falsify'))}",
            f"- **Challenge (Counterexample)**: {_md(bcl.get('counterexample_question'))}",
            "",
        ]
    sys_md += ["## Priority Remediation Roadmap", ""]
    for pa in syn_data.get("priority_actions", []):
        sys_md.append(
            f"{pa.get('order')}. **[`{_md(pa.get('priority'))}`] {_md(pa.get('title'))}**: {_md(pa.get('action'))} "
            f"(Refs: `{', '.join(pa.get('related_refs', []))}`)"
        )
    _write_md(basv_sys_dir / "03_system_business_aware_synthesis.md", sys_md)

    aud_md = [
        "# System-Level BASV Evidence Audit",
        "",
        f"- Audit status: `{_md(aud_data.get('audit_status'))}`",
        f"- Summary: {_md(aud_data.get('summary'))}",
        f"- Total claims audited: `{len(aud_data.get('audited_claims', []))}`",
        "",
    ]
    _write_md(basv_sys_dir / "04_system_basv_evidence_audit.md", aud_md)

    # 5. System-Wide 5-Axis Cross-Artifact Contradiction Graph (05_cross_artifact_contradiction_graph.json/.md)
    graph_inputs = [
        {
            "repo_name": r["repo_name"],
            "basv": {
                "intent_implementation_comparator": r.get("basv_ai", {})
                .get("intent_implementation_comparator", {})
                .get("result", {})
            },
        }
        for r in repo_basv_results
    ]
    sys_contradiction_graph = build_cross_artifact_contradiction_graph(graph_inputs, ev_cat)
    sys_contradiction_graph["epistemic_and_provenance_rollup"] = summary_payload["epistemic_and_provenance_rollup"]
    write_json(basv_sys_dir / "05_cross_artifact_contradiction_graph.json", sys_contradiction_graph)

    cg_md = [
        "# System-Wide 5-Axis Cross-Artifact Contradiction Graph (42 Repositories — BASV v2.4)",
        "",
        f"- Total contradiction edges mapped: `{sys_contradiction_graph.get('total_contradiction_edges', 0)}`",
        f"- Total distinct artifact nodes: `{sys_contradiction_graph.get('distinct_nodes', 0)}`",
        "",
        "## 1. Contradiction Distribution Across 5 Structural Axes",
        "",
        "| Contradiction Axis | Edge Count | Share (%) | Architectural Meaning |",
        "|---|---|---|---|",
    ]
    total_ce = max(1, int(sys_contradiction_graph.get("total_contradiction_edges", 0)))
    axis_desc = {
        "brd_vs_code": "Authoritative BRD/BRS/Epic specification vs actual handler/service implementation",
        "code_vs_runtime_config": "Application handler/service logic vs environment variables / appsettings / deployment flags",
        "api_spec_vs_authz_matrix": "API endpoint contract vs RBAC/ABAC/Maker-Checker authorization enforcement",
        "doc_vs_observed_request_behavior": "Documented webhook/callback/request flow vs observed payload/response handling",
        "code_vs_sql_migration": "Application service expectations vs PostgreSQL stored procedures / schema constraints",
    }
    for axis, cnt in (sys_contradiction_graph.get("by_contradiction_type") or {}).items():
        pct = round(100.0 * cnt / total_ce, 1)
        cg_md.append(f"| `{axis}` | `{cnt}` | `{pct}%` | {axis_desc.get(axis, '')} |")

    cg_md += [
        "",
        "## 2. Provenance Contamination & Dual-Provenance Gate Rollup",
        "",
        f"- Candidate business invariants audited: `{total_invs}`",
        f"- False `authoritative_in_input` invariants remediated (`-> supporting_only`): **`{total_remediated_invs}` (`{round(100.0 * total_remediated_invs / max(1, total_invs), 1)}%`)**",
        f"- Intent-vs-Implementation comparisons audited: `{total_cmps}`",
        f"- Code-only intent comparisons caught (`intent_derived_from_implementation_code_only`): **`{total_contaminated_cmps}` (`{round(100.0 * total_contaminated_cmps / max(1, total_cmps), 1)}%`)**",
        f"- Confirmed mismatches before v2.4 Dual-Provenance Gate: `{total_orig_cm}`",
        f"- Confirmed mismatches retained after v2.4 Dual-Provenance Gate: **`{total_ver_cm}`**",
        f"- Confirmed mismatches demoted to `potential_or_unverified_mismatches`: **`{total_demoted_cm}`**",
        "",
        "## 3. All Cross-Artifact Contradiction Edges (`122` Edges Across 42 Repositories)",
        "",
        "| # | Repo | Contradiction Axis | Comparison ID | Invariant Ref | Result | Participating Repos |",
        "|---|---|---|---|---|---|---|",
    ]
    for idx, ce in enumerate(sys_contradiction_graph.get("contradiction_edges", []), start=1):
        prepos = ", ".join(f"`{x}`" for x in ce.get("participating_repos", []))
        cg_md.append(
            f"| {idx} | `{ce.get('repo_name')}` | `{ce.get('contradiction_type')}` | `{ce.get('comparison_id')}` "
            f"| `{ce.get('invariant_ref')}` | `{ce.get('comparison_result')}` | {prepos} |"
        )
    _write_md(basv_sys_dir / "05_cross_artifact_contradiction_graph.md", cg_md)

    if topology_mermaid:
        (diag_dir / "service_interconnection_topology.mmd").write_text(topology_mermaid, encoding="utf-8")



def write_aca_analysis_documents(
    analysis_dir: Path,
    *,
    session: dict[str, Any],
    candidate_claims: dict[str, Any],
    traces: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    verifications: list[dict[str, Any]],
    request_plans: list[dict[str, Any]],
    root_causes: list[dict[str, Any]],
    challenges: list[dict[str, Any]],
    evidence_audit: dict[str, Any],
    synthesis_report: dict[str, Any],
    evidence_catalog: dict[str, dict[str, Any]] | None = None,
    epistemic_diagnostics: dict[str, Any] | None = None,
) -> None:
    """Write Phase 3 Attack Chain Analysis deliverables to <output_root>/_analysis/."""
    from .orchestrator import _build_proof_obligation_and_challenge, evaluate_contextual_evidence_strength

    analysis_dir.mkdir(parents=True, exist_ok=True)
    for sub_name in ("traces", "chains", "verifications", "requests", "root_causes", "challenges"):
        (analysis_dir / sub_name).mkdir(parents=True, exist_ok=True)

    write_json(analysis_dir / "00_analysis_session.json", session)
    write_json(analysis_dir / "00_analysis_manifest.json", session)
    write_json(analysis_dir / "01_candidate_claims.json", candidate_claims)
    write_json(analysis_dir / "01_candidate_chain_graph.json", candidate_claims)

    for tr in traces:
        tid = _md(tr.get("trace_id", "trace"))
        write_json(analysis_dir / "traces" / f"trace_{tid}.json", tr)
    for ch in chains:
        cid = _md(ch.get("chain_id", "chain"))
        write_json(analysis_dir / "chains" / f"chain_{cid}.json", ch)
        chain_subdir = analysis_dir / "chains" / cid
        chain_subdir.mkdir(parents=True, exist_ok=True)
        write_json(chain_subdir / "chain.json", ch)
        matching_traces = [t for t in traces if cid in (t.get("related_chain_ids") or []) or t.get("chain_id") == cid]
        write_json(chain_subdir / "code_trace.json", matching_traces[0] if len(matching_traces) == 1 else {"chain_id": cid, "traces": matching_traces or traces})
        matching_reqs = [r for r in request_plans if r.get("chain_id") == cid]
        write_json(chain_subdir / "request_reproduction.json", matching_reqs[0] if len(matching_reqs) == 1 else {"chain_id": cid, "request_sequences": matching_reqs})
        matching_verifs = [v for v in verifications if v.get("chain_id") == cid]
        write_json(chain_subdir / "chain_verification.json", matching_verifs[0] if len(matching_verifs) == 1 else {"chain_id": cid, "verifications": matching_verifs})
        matching_rcs = [rc for rc in root_causes if cid in (rc.get("affected_chain_ids") or []) or rc.get("root_cause_id") in (ch.get("root_cause_ids") or [])]
        write_json(chain_subdir / "root_cause.json", matching_rcs[0] if len(matching_rcs) == 1 else {"chain_id": cid, "root_causes": matching_rcs})
        matching_chals = [c for c in challenges if c.get("chain_id") == cid]
        if matching_chals:
            write_json(chain_subdir / "counterevidence_challenge.json", matching_chals[0] if len(matching_chals) == 1 else {"chain_id": cid, "challenges": matching_chals})
    for vf in verifications:
        vid = _md(vf.get("verification_id") or vf.get("chain_id") or "verify")
        write_json(analysis_dir / "verifications" / f"verify_{vid}.json", vf)
    for rq in request_plans:
        rid = _md(rq.get("request_sequence_id", "req"))
        write_json(analysis_dir / "requests" / f"req_{rid}.json", rq)
    for rc in root_causes:
        rcid = _md(rc.get("root_cause_id", "rc"))
        write_json(analysis_dir / "root_causes" / f"rc_{rcid}.json", rc)
    for cl in challenges:
        clid = _md(cl.get("challenge_id", "chal"))
        write_json(analysis_dir / "challenges" / f"chal_{clid}.json", cl)

    write_json(analysis_dir / "06_root_cause_map.json", {"root_causes": root_causes})
    write_json(analysis_dir / "08_evidence_audit.json", evidence_audit)
    write_json(analysis_dir / "98_evidence_audit.json", evidence_audit)
    write_json(analysis_dir / "99_project_chain_report.json", synthesis_report)

    rc_md = [
        f"# Root Cause Map — {_md(synthesis_report.get('project_name', 'Project'))}",
        "",
        "| Root Cause ID | Title | Category | Status | Affected Chains | Affected Services |",
        "|---|---|---|---|---|---|",
    ]
    for rc in root_causes:
        rc_md.append(
            f"| `{_md(rc.get('root_cause_id'))}` | {_md(rc.get('title'))} | `{_md(rc.get('cause_category'))}` | `{_md(rc.get('root_cause_status'))}` | `{', '.join(rc.get('affected_chain_ids', []))}` | `{', '.join(rc.get('affected_services', []))}` |"
        )
    rc_md.append("")
    for rc in root_causes:
        eids = [r.get("evidence_id") for r in rc.get("evidence_refs", []) if isinstance(r, dict) and r.get("evidence_id")]
        rc_md += [
            f"## `{_md(rc.get('root_cause_id'))}` — {_md(rc.get('title'))}",
            f"- **Status**: `{_md(rc.get('root_cause_status'))}` | **Category**: `{_md(rc.get('cause_category'))}`",
            f"- **Business Invariant Violated**: {_md(rc.get('business_invariant_violated'))}",
            f"- **Underlying Flaw**: {_md(rc.get('underlying_flaw'))}",
            f"- **Why It Is Root Cause**: {_md(rc.get('why_it_is_root_cause'))}",
            f"- **Affected Chains**: `{', '.join(rc.get('affected_chain_ids', []))}`",
            f"- **Affected Services**: `{', '.join(rc.get('affected_services', []))}`",
            f"- **Remediation at Root**: {_md(rc.get('remediation_at_root'))}",
            f"- **Symptom-Only Fixes to Avoid**: {_md('; '.join(rc.get('remediation_that_only_treats_symptom', [])))}",
            f"- **Evidence IDs**: `{', '.join(str(x) for x in eids)}`",
            "",
        ]
    _write_md(analysis_dir / "06_root_cause_map.md", rc_md)

    if epistemic_diagnostics is not None:
        write_json(analysis_dir / "10_aca_epistemic_and_convergence_diagnostics.json", epistemic_diagnostics)
        diag_md = [
            f"# Phase 3 Epistemic, Falsifiability & Convergence Diagnostics — {_md(synthesis_report.get('project_name', 'Project'))}",
            "",
            f"- **Pipeline Version**: `{_md(epistemic_diagnostics.get('pipeline_version', '2.4.0-refute-first'))}`",
            f"- **Analysis ID**: `{_md(epistemic_diagnostics.get('analysis_id'))}`",
            f"- **Total Candidate Claims Triaged**: `{epistemic_diagnostics.get('total_candidates', 0)}`",
            f"- **Total Manual Code Traces**: `{epistemic_diagnostics.get('total_traces', 0)}` (`{epistemic_diagnostics.get('total_trace_hops', 0)}` hops)",
            f"- **Total Attack Chains Constructed**: `{epistemic_diagnostics.get('total_chains', 0)}`",
            f"- **Chain Verdicts**: `{json.dumps(epistemic_diagnostics.get('chain_verdict_breakdown', {}), ensure_ascii=False)}`",
            f"- **Execution Status Breakdown**: `{json.dumps(epistemic_diagnostics.get('execution_status_breakdown', {}), ensure_ascii=False)}`",
            f"- **Root Causes Mapped**: `{epistemic_diagnostics.get('total_root_causes', 0)}`",
            f"- **Counterevidence Challenges Executed**: `{epistemic_diagnostics.get('total_challenges', 0)}`",
            "",
            "## 1. Weighted Epistemic Convergence Governor",
            "",
        ]
        conv = epistemic_diagnostics.get("convergence_governor", {})
        diag_md += [
            f"- **Made Progress**: `{conv.get('made_progress')}`",
            f"- **Weighted Epistemic Gain**: `{conv.get('weighted_epistemic_gain')}`",
            f"- **High-Value Evidence Added (Rank 1-2 / Entrypoint / Sink / Spec)**: `{conv.get('new_evidence_count', 0)}`",
            f"- **Verified Steps/Edges Delta**: `{conv.get('verified_step_or_edge_delta', 0)}`",
            f"- **Resolved Questions Count**: `{conv.get('resolved_question_count', 0)}`",
            f"- **Cycle Detected**: `{conv.get('cycle_detected')}`",
            f"- **Question Runaway Detected**: `{conv.get('question_runaway_detected')}`",
            f"- **Operator Review Triggered**: `{conv.get('operator_review_triggered')}`",
            f"- **Recommended Action**: `{_md(conv.get('recommended_action'))}`",
            "",
            "## 2. Per-Chain Contextual Evidence Strength, Proof Obligations & Bounded Challenge Loops",
            "",
            "| Chain ID | Verdict | Exec Status | Contextual Strength | Entrypoint/Sink Bound | Spec Bound | Negative Corpus Flags |",
            "|---|---|---|---|---|---|---|",
        ]
        for ch_diag in epistemic_diagnostics.get("chain_epistemic_profiles", []):
            cs = ch_diag.get("contextual_evidence_strength", {})
            neg = ", ".join(cs.get("negative_corpus_matches", [])) or "none"
            diag_md.append(
                f"| `{_md(ch_diag.get('chain_id'))}` | `{_md(ch_diag.get('chain_verdict'))}` | `{_md(ch_diag.get('execution_status'))}` | `{_md(cs.get('strength_verdict'))}` | `{cs.get('is_entrypoint_or_sink_bound')}` | `{cs.get('is_contract_or_spec_bound')}` | `{neg}` |"
            )
        diag_md.append("")
        for ch_diag in epistemic_diagnostics.get("chain_epistemic_profiles", []):
            po = ch_diag.get("proof_obligation", {})
            bcl = ch_diag.get("bounded_challenge_loop", {})
            diag_md += [
                f"### `{_md(ch_diag.get('chain_id'))}` — {_md(ch_diag.get('title'))}",
                f"- **What Would Falsify (Popperian Proof Obligation)**: {_md(po.get('what_would_falsify'))}",
                f"- **Required Supporting Conditions**: {_md(po.get('required_supporting_conditions'))}",
                f"- **Counterexample Question**: {_md(bcl.get('counterexample_question'))}",
                f"- **Stronger Alternative Chain Question**: {_md(bcl.get('stronger_alternative_chain_question'))}",
                f"- **Overestimated Control Question**: {_md(bcl.get('overestimated_control_question'))}",
                "",
            ]
        hl = epistemic_diagnostics.get("cross_phase_hypothesis_lifecycle", {})
        if hl:
            diag_md += [
                "## 3. Cross-Phase Hypothesis Lifecycle Closure (Phase 1 -> Phase 2 -> Phase 3)",
                "",
                f"- **Total Raw Hypothesis Leads Ingressed**: `{hl.get('total_raw_leads', 0)}`",
                f"- **Promoted to Verified Attack Chains / Steps**: `{hl.get('promoted_to_chains_count', 0)}`",
                f"- **Active Deduplicated Hypotheses Remaining**: `{hl.get('active_count', 0)}`",
                f"- **Reactivated Hypotheses from New Evidence**: `{hl.get('reactivated_count', 0)}`",
                f"- **Archived Stagnant Hypotheses (Requires Runtime/Operator)**: `{hl.get('archived_count', 0)}`",
                "",
            ]
        _write_md(analysis_dir / "10_aca_epistemic_and_convergence_diagnostics.md", diag_md)

    md = [
        f"# Attack Chain Analysis Report — {_md(synthesis_report.get('project_name', 'Project'))}",
        "",
        f"- Analysis ID: `{_md(synthesis_report.get('analysis_id'))}`",
        f"- Analysis Status: `{_md(synthesis_report.get('analysis_status'))}`",
        f"- Model Assessment: `{_md(synthesis_report.get('model_assessment'))}`",
        "",
        "## Executive Summary",
        "",
        _md(synthesis_report.get("executive_summary")),
        "",
        "## Highest Credible Attack Chains",
        "",
    ]
    chain_lookup = {str(c.get("chain_id")): c for c in chains if isinstance(c, dict) and c.get("chain_id")}
    for item in synthesis_report.get("highest_credible_chains", []):
        cid = str(item.get("chain_id", ""))
        eids = [str(r.get("evidence_id")) for r in item.get("evidence_refs", []) if isinstance(r, dict) and r.get("evidence_id")]
        eids_str = ", ".join(f"`{eid}`" for eid in eids)
        full_ch = chain_lookup.get(cid, item)
        po, bcl = _build_proof_obligation_and_challenge(full_ch, "attack_chain_constructor")
        strength_line = ""
        if evidence_catalog is not None and eids:
            cs = evaluate_contextual_evidence_strength(eids, evidence_catalog)
            strength_line = f"- Contextual Evidence Strength: `{cs.get('strength_verdict')}` (entrypoint/sink bound: `{cs.get('is_entrypoint_or_sink_bound')}`, spec bound: `{cs.get('is_contract_or_spec_bound')}`, negative corpus flags: `{cs.get('negative_corpus_matches')}`)"
        md += [
            f"### `{_md(cid)}` — {_md(item.get('title'))}",
            f"- Chain Verdict: `{_md(item.get('chain_verdict'))}` | Execution Status: `{_md(item.get('execution_status'))}`",
            f"- Credible Impact: {_md(item.get('credible_impact'))}",
            f"- Key Preconditions: {_md('; '.join(item.get('key_preconditions', [])))}",
            f"- Weakest Unverified Link: {_md(item.get('weakest_unverified_link'))}",
            f"- Root Cause IDs: `{', '.join(item.get('root_cause_ids', []))}`",
            f"- Evidence: {eids_str or 'none'}",
        ]
        if strength_line:
            md.append(strength_line)
        md += [
            f"- Proof Obligation (`what_would_falsify`): {_md(po.get('what_would_falsify'))}",
            f"- Adversarial Challenge (`overestimated_control`): {_md(bcl.get('overestimated_control_question'))}",
            "",
        ]
    md += ["## Cross-Service Patterns", ""]
    for pat in synthesis_report.get("cross_service_patterns", []):
        md += [
            f"### `{_md(pat.get('pattern_id'))}` (`{_md(pat.get('status'))}`)",
            f"- Pattern: {_md(pat.get('pattern'))}",
            f"- Affected Services: `{', '.join(pat.get('affected_services', []))}`",
            f"- Related Chains: `{', '.join(pat.get('related_chain_ids', []))}`",
            f"- Root Causes: `{', '.join(pat.get('root_cause_ids', []))}`",
            "",
        ]
    md += ["## Root Causes & Structural Remediation", ""]
    for rc_item in synthesis_report.get("root_causes", []):
        md += [
            f"### `{_md(rc_item.get('root_cause_id'))}` — {_md(rc_item.get('title'))} (`{_md(rc_item.get('status'))}`)",
            f"- Affected Chains: `{', '.join(rc_item.get('affected_chain_ids', []))}`",
            f"- Remediation at Root: {_md(rc_item.get('remediation_at_root'))}",
            "",
        ]
    if synthesis_report.get("recommended_remediations"):
        md += ["## Prioritized Remediations", ""]
        for rem in synthesis_report.get("recommended_remediations", []):
            md += [
                f"- **[{_md(rem.get('priority')).upper()}]** {_md(rem.get('action'))} (Root Causes: `{', '.join(rem.get('root_cause_ids', []))}`, Chains: `{', '.join(rem.get('chain_ids', []))}`)",
            ]
        md.append("")
    md += [
        "## Evidence Audit Summary",
        "",
        _md(synthesis_report.get("evidence_audit_summary")),
        "",
    ]
    _write_md(analysis_dir / "07_attack_chain_analysis.md", md)
    _write_md(analysis_dir / "99_project_chain_report.md", md)

    unk_md = [
        f"# Unknowns, Refuted Chains & Counterevidence — {_md(synthesis_report.get('project_name', 'Project'))}",
        "",
        "## Refuted or Weakened Chains",
        "",
    ]
    refuted_list = synthesis_report.get("refuted_or_weakened_chains") or synthesis_report.get("refuted_or_downgraded_chains") or []
    for ref_ch in refuted_list:
        if isinstance(ref_ch, dict):
            unk_md.append(
                f"- **`{_md(ref_ch.get('chain_id'))}`** (`{_md(ref_ch.get('final_verdict'))}`): {_md(ref_ch.get('reason'))}"
            )
        else:
            unk_md.append(f"- {_md(ref_ch)}")
    unk_md += ["", "## Counterevidence Challenges", ""]
    for cl in challenges:
        unk_md += [
            f"### Challenge `{_md(cl.get('challenge_id'))}` on Chain `{_md(cl.get('chain_id'))}`",
            f"- Overall Assessment: `{_md(cl.get('overall_assessment') or cl.get('recommended_verdict_adjustment'))}`",
            f"- Overall Rationale: {_md(cl.get('overall_rationale') or cl.get('narrowest_supported_conclusion'))}",
        ]
        for c_item in cl.get("challenges", []):
            if isinstance(c_item, dict):
                unk_md.append(
                    f"  - **`{_md(c_item.get('challenge_item_id'))}`** (`{_md(c_item.get('target_type'))}:{_md(c_item.get('target_id'))}` — `{_md(c_item.get('status'))}`): {_md(c_item.get('counterexample_or_missing_fact'))} -> Effect: {_md(c_item.get('effect_on_verdict'))}"
                )
        unk_md.append("")
    if synthesis_report.get("counterevidence_summary"):
        unk_md += ["## Counterevidence Summary", ""]
        for cs_item in synthesis_report.get("counterevidence_summary", []):
            unk_md.append(f"- {_md(cs_item)}")
        unk_md.append("")
    unk_md += ["## Unverified Claims, Gaps & Residual Questions", ""]
    unverified_list = synthesis_report.get("unverified_claims_and_gaps") or synthesis_report.get("unresolved_questions") or []
    for uq in unverified_list:
        unk_md.append(f"- {_md(uq)}")
    _write_md(analysis_dir / "09_unknowns_and_counterevidence.md", unk_md)


def render_v3_reports(
    project_root: Path | str,
    repo_name: str | None = None,
    run_id: str = "default",
) -> dict[str, Any]:
    """ARCH-3I & DEPTH-4.8: Render the 3 v3.0 audience-tailored Markdown deliverables into <project_root>/documents/:
    1. 01_developer_remediation_cards.md
    2. 02_executive_risk_and_key_questions.md
    3. 03_pentest_qa_verification_playbook.md
    """
    project_root = Path(project_root).expanduser().resolve()
    runs_root = project_root / ".localsec" / "runs" / run_id
    docs_dir = project_root / "documents"
    docs_dir.mkdir(parents=True, exist_ok=True)

    all_repo_dirs: list[Path] = []
    if repo_name:
        cand = runs_root / repo_name
        cand.mkdir(parents=True, exist_ok=True)
    if runs_root.is_dir():
        for d in sorted(runs_root.iterdir(), key=lambda p: p.name):
            if d.is_dir() and not d.name.startswith("_"):
                all_repo_dirs.append(d)

    def _load_repo_json(rdir: Path, fname: str) -> dict[str, Any]:
        fp = rdir / fname
        if fp.is_file():
            try:
                raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw, dict):
                    return raw.get("result", raw) if isinstance(raw.get("result"), dict) else raw
            except Exception:
                pass
        return {}

    dev_lines: list[str] = [
        "# 01 — Developer Remediation Cards (v3.0)",
        "",
        "> Audience: Engineering & Feature Teams. Contains root-cause pattern clustering, representative fixes, cluster-wide sweep targets, and regression test specifications.",
        "",
    ]
    exec_lines: list[str] = [
        "# 02 — Executive S-F-O-P-C Risk & Key Questions (v3.0)",
        "",
        "> Audience: CISO, Product Security, Safety Owner & Risk Owner. Calibrated across Safety, Financial, Operational, Privacy, and Compliance axes.",
        "",
    ]
    qa_lines: list[str] = [
        "# 03 — Pentest & QA Verification Playbook (v3.0)",
        "",
        "> Audience: AppSec Pentest & QA Engineers. Contains non-executed request sequence plans (`Step 1: Setup`, `Step 2: Mutate`, `Step 3: Observe`), vulnerable vs fixed indicators, and the Empirical Refutations Ledger.",
        "",
    ]

    total_findings = 0
    total_refutations = 0
    repos_with_gate0: list[str] = []
    repo_files_written: list[str] = []

    for rdir in all_repo_dirs:
        rname = rdir.name
        is_target_repo = (repo_name is None) or (rname == repo_name)
        repo_gate0_triggered = False

        r_dev_lines: list[str] = [
            "# 01 — Developer Remediation Cards (v3.0)",
            "",
            "> Audience: Engineering & Feature Teams. Contains root-cause pattern clustering, representative fixes, cluster-wide sweep targets, and regression test specifications.",
            "",
        ]
        r_exec_lines: list[str] = [
            "# 02 — Executive S-F-O-P-C Risk & Key Questions (v3.0)",
            "",
            "> Audience: CISO, Product Security, Safety Owner & Risk Owner. Calibrated across Safety, Financial, Operational, Privacy, and Compliance axes.",
            "",
        ]
        r_qa_lines: list[str] = [
            "# 03 — Pentest & QA Verification Playbook (v3.0)",
            "",
            "> Audience: AppSec Pentest & QA Engineers. Contains non-executed request sequence plans (`Step 1: Setup`, `Step 2: Mutate`, `Step 3: Observe`), vulnerable vs fixed indicators, and the Empirical Refutations Ledger.",
            "",
        ]

        surf = _load_repo_json(rdir, "unified_surface_mapper.json")
        deep_trace = _load_repo_json(rdir, "deep_trace_chain_analyst.json")
        challenger = _load_repo_json(rdir, "blinded_counterevidence_challenger.json")
        ev_gate = _load_repo_json(rdir, "analysis_evidence_gate.json")
        p3_queue = _load_repo_json(rdir, "phase3_verified_queue.json")
        actor_map = _load_repo_json(rdir, "actor_and_feasibility_assessor.json")
        beyond_code = _load_repo_json(rdir, "beyond_code_control_mapper.json")
        sfop = _load_repo_json(rdir, "sfop_risk_calibrator.json")

        scout = _load_repo_json(rdir, "codebase_scout.json")
        cov_matrix = _load_repo_json(rdir, "coverage_matrix.json")
        vis_audit = _load_repo_json(rdir, "visibility_audit.json")
        kq_file = _load_repo_json(rdir, "key_questions.json")
        ws_state = _load_repo_json(rdir, "workspace_state.json")

        p1_gate = _load_repo_json(rdir, "phase1_gate_receipt.json")
        p2_gate = _load_repo_json(rdir, "phase2_gate_receipt.json")
        p3_gate = _load_repo_json(rdir, "phase3_gate_receipt.json")
        inv = _load_repo_json(rdir, "inventory_repo.json")

        # C7: Warn if any phase gate receipt is missing OR has gate_passed != True
        missing_gates = [
            f"phase{p}_gate_receipt.json"
            for p in (1, 2, 3)
            if not (rdir / f"phase{p}_gate_receipt.json").is_file()
        ]
        failed_gates = [
            f"phase{p}_gate_receipt.json"
            for p, g in ((1, p1_gate), (2, p2_gate), (3, p3_gate))
            if (rdir / f"phase{p}_gate_receipt.json").is_file() and (not isinstance(g, dict) or g.get("gate_passed") is not True)
        ]
        gate_failed = bool(missing_gates or failed_gates)
        gate_warn_lines: list[str] = (
            [
                "> [!WARNING]",
                f"> **[UNFINALIZED / GATE FAILED]**: One or more phase gates did not pass or are missing for this repository (missing: `{', '.join(missing_gates) or 'none'}`, failed: `{', '.join(failed_gates) or 'none'}`). Treat findings below as unfinalized.",
                "",
            ]
            if gate_failed
            else []
        )

        clusters_by_id: dict[str, dict[str, Any]] = {}
        for cl in surf.get("semantic_clusters", []) or surf.get("equivalence_clusters", []):
            if isinstance(cl, dict) and cl.get("cluster_id"):
                clusters_by_id[str(cl["cluster_id"])] = cl

        # R3-A2: Collect refuted IDs strictly from current p3_queue reconciliation_log (or current challenger verdicts if p3_queue is absent)
        refuted_ids: set[str] = set()
        if (rdir / "phase3_verified_queue.json").is_file() and isinstance(p3_queue.get("reconciliation_log"), list):
            for r_entry in p3_queue.get("reconciliation_log", []):
                if isinstance(r_entry, dict) and str(r_entry.get("reconciled_status") or "") == "REFUTED_FALSE_POSITIVE":
                    for rk in ("chain_id", "candidate_id", "finding_id"):
                        if r_entry.get(rk):
                            refuted_ids.add(str(r_entry[rk]))
        else:
            for sc in list(challenger.get("challenged_chains", [])) + list(challenger.get("step_challenges", [])):
                if isinstance(sc, dict) and str(sc.get("challenge_verdict") or sc.get("challenger_verdict") or sc.get("verdict") or "") in {"mitigated_by_existing_control", "broken_link", "refuted"}:
                    for rk in ("chain_id", "candidate_id", "finding_id"):
                        if sc.get(rk):
                            refuted_ids.add(str(sc[rk]))

        raw_dt_chains = list(deep_trace.get("chains") or deep_trace.get("verified_chains") or [])
        dt_by_id: dict[str, dict[str, Any]] = {}
        for dtc in raw_dt_chains:
            if isinstance(dtc, dict):
                for k in ("chain_id", "finding_id", "candidate_id"):
                    if dtc.get(k):
                        dt_by_id[str(dtc[k])] = dtc

        if (rdir / "phase3_verified_queue.json").is_file():
            surviving_chains = [
                c for c in p3_queue.get("verified_findings", [])
                if isinstance(c, dict)
                and str(c.get("reconciled_status") or "REACHABLE_VULNERABILITY") != "REFUTED_FALSE_POSITIVE"
                and str(c.get("chain_id") or c.get("candidate_id") or "") not in refuted_ids
            ]
        else:
            surviving_chains = [
                c for c in raw_dt_chains
                if isinstance(c, dict)
                and str(c.get("reconciled_status") or "") != "REFUTED_FALSE_POSITIVE"
                and str(c.get("chain_id") or c.get("candidate_id") or "") not in refuted_ids
            ]

        calibrated = [
            cf for cf in sfop.get("calibrated_findings", [])
            if isinstance(cf, dict)
            and str(cf.get("finding_id") or cf.get("chain_id") or cf.get("candidate_id") or "") not in refuted_ids
        ]
        cal_by_id: dict[str, dict[str, Any]] = {}
        for cf in calibrated:
            fid = str(cf.get("finding_id") or cf.get("chain_id") or cf.get("candidate_id") or "")
            if fid:
                cal_by_id[fid] = cf

        # Merge surviving_chains with calibrated details when available
        chains: list[dict[str, Any]] = []
        seen_fids: set[str] = set()
        for ch in surviving_chains:
            fid = str(ch.get("chain_id") or ch.get("finding_id") or ch.get("candidate_id") or "")
            merged_ch = {**dt_by_id.get(fid, {}), **ch, **cal_by_id.get(fid, {})} if fid else ch
            chains.append(merged_ch)
            if fid:
                seen_fids.add(fid)
        if not chains and not (rdir / "phase3_verified_queue.json").is_file():
            for cf in calibrated:
                fid = str(cf.get("finding_id") or cf.get("chain_id") or cf.get("candidate_id") or "")
                if fid not in seen_fids:
                    chains.append({**dt_by_id.get(fid, {}), **cf})
                    if fid:
                        seen_fids.add(fid)

        # Check Gate 0 / Emergency Brake per repo
        for cf in calibrated or chains:
            if not isinstance(cf, dict):
                continue
            sfop_blk = cf.get("impact_axes") or cf.get("sfop_impacts") or cf
            s_raw = sfop_blk.get("safety") if isinstance(sfop_blk, dict) and "safety" in sfop_blk else sfop_blk.get("safety_impact") or cf.get("safety_impact") or "NONE"
            s_imp = str(s_raw.get("level", "NONE") if isinstance(s_raw, dict) else s_raw).upper()
            if s_imp in {"CRITICAL", "CATASTROPHIC"} or cf.get("gate_0_emergency_brake") is True:
                repo_gate0_triggered = True
        if repo_gate0_triggered and rname not in repos_with_gate0:
            repos_with_gate0.append(rname)

        repo_dev_sec: list[str] = [f"## Repository: `{_md(rname)}`", ""] + list(gate_warn_lines)
        if not chains:
            repo_dev_sec.append("_No verified reachable vulnerability chains recorded for this repository._")
            repo_dev_sec.append("")

        for idx, ch in enumerate(chains, 1):
            if not isinstance(ch, dict):
                continue
            if is_target_repo:
                total_findings += 1
            fid = str(ch.get("chain_id") or ch.get("finding_id") or ch.get("candidate_id") or f"FINDING-{idx}")
            rc_cluster_id = str(ch.get("root_cause_cluster_id") or ch.get("cluster_id") or "[UNSPECIFIED — REQUIRES UPDATE]")
            rc_obj = ch.get("root_cause")
            rc_desc = str(
                (rc_obj.get("summary") or rc_obj.get("description") if isinstance(rc_obj, dict) else rc_obj)
                or ch.get("root_cause_summary")
                or ch.get("title")
                or "[UNSPECIFIED — REQUIRES UPDATE]"
            )
            ev_ids = [str(e) for e in ch.get("evidence_ids", []) if str(e).startswith("ev_")]
            hops = ch.get("hops", [])
            primary_loc = "[UNSPECIFIED — REQUIRES UPDATE]"
            if isinstance(hops, list) and hops:
                first_hop = hops[0] if isinstance(hops[0], dict) else {}
                hop_file = first_hop.get("path") or first_hop.get("file")
                hop_line = first_hop.get("line") or first_hop.get("line_start")
                if hop_file:
                    primary_loc = f"{hop_file}:{hop_line or 1}"
                for hp in hops:
                    if isinstance(hp, dict):
                        for e in hp.get("evidence_ids", []):
                            if str(e).startswith("ev_") and str(e) not in ev_ids:
                                ev_ids.append(str(e))
            elif ch.get("path") or ch.get("file"):
                primary_loc = f"{ch.get('path') or ch.get('file')}:{ch.get('line') or ch.get('line_start') or 1}"

            cluster_info = clusters_by_id.get(rc_cluster_id, {})
            cluster_members = (
                cluster_info.get("member_files")
                or cluster_info.get("member_endpoints")
                or cluster_info.get("members")
                or ch.get("cluster_wide_targets")
                or [primary_loc]
            )

            rep_fix = str(
                ch.get("representative_fix")
                or ch.get("remediation")
                or (rc_obj.get("representative_fix") if isinstance(rc_obj, dict) else None)
                or "[UNSPECIFIED — REQUIRES UPDATE]"
            )
            reg_spec = str(
                ch.get("regression_test_spec")
                or (rc_obj.get("regression_test_spec") if isinstance(rc_obj, dict) else None)
                or "[UNSPECIFIED — REQUIRES UPDATE]"
            )

            repo_dev_sec += [
                f"### Remediation Card `{_md(fid)}`",
                f"- **Root-Cause Pattern ID**: `{_md(rc_cluster_id)}`",
                f"- **Primary Location (`File:Line`)**: `{_md(primary_loc)}`",
                f"- **Supporting Evidence (`ev_...`)**: {', '.join(f'`{e}`' for e in ev_ids) if ev_ids else '`[UNSPECIFIED — REQUIRES UPDATE]`'}",
                f"- **Root Cause Summary**: {_md(rc_desc)}",
                f"- **Representative Fix**: {_md(rep_fix)}",
                "- **Cluster-Wide Fixes (All Members of `root_cause_cluster_id`)**:",
            ]
            for cm in cluster_members:
                repo_dev_sec.append(f"  - `{_md(cm)}`")
            repo_dev_sec += [
                f"- **Regression Test Spec**: {_md(reg_spec)}",
                "",
            ]

        dev_lines.extend(repo_dev_sec)
        r_dev_lines.extend(repo_dev_sec)

        # Executive section for repo
        repo_exec_sec: list[str] = [f"## Repository: `{_md(rname)}`", ""] + list(gate_warn_lines)
        if repo_gate0_triggered:
            repo_exec_sec += [
                "> [!CAUTION]",
                "> **GATE 0 / EMERGENCY BRAKE ACTIVE**: One or more findings in this repository carry `safety == CRITICAL`. Release and deployment must be halted pending formal `safety_owner` sign-off.",
                "",
            ]
        repo_exec_sec += [
            "### S-F-O-P-C Risk Matrix & Ownership Sign-Off Table",
            "",
            "| Finding ID | Safety (S) | Financial (F) | Operational (O) | Privacy (P) | Compliance (C) | Overall Risk | Feasibility | Blast Radius | Risk Owner | Safety Owner | Gate 0 Brake |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        def _axis_lvl(blk: dict[str, Any], axis_key: str, legacy_key: str, default: str) -> str:
            val = blk.get(axis_key) if isinstance(blk, dict) and axis_key in blk else blk.get(legacy_key)
            if isinstance(val, dict):
                lvl = val.get("level")
                return str(lvl).upper() if lvl else default
            return str(val).upper() if val else default

        exec_items = calibrated if calibrated else chains
        override_notes: list[str] = []
        for idx, cf in enumerate(exec_items, 1):
            if not isinstance(cf, dict):
                continue
            fid = str(cf.get("finding_id") or cf.get("chain_id") or cf.get("candidate_id") or f"FINDING-{idx}")
            sfop_blk = cf.get("impact_axes") or cf.get("sfop_impacts") or cf
            s_val = _axis_lvl(sfop_blk, "safety", "safety_impact", "[UNSPECIFIED — REQUIRES UPDATE]")
            f_val = _axis_lvl(sfop_blk, "financial", "financial_impact", "[UNSPECIFIED — REQUIRES UPDATE]")
            o_val = _axis_lvl(sfop_blk, "operational", "operational_impact", "[UNSPECIFIED — REQUIRES UPDATE]")
            p_val = _axis_lvl(sfop_blk, "privacy", "privacy_impact", "[UNSPECIFIED — REQUIRES UPDATE]")
            c_val = _axis_lvl(sfop_blk, "compliance", "compliance_impact", "[UNSPECIFIED — REQUIRES UPDATE]")
            # C6: Show both contextual_risk_rating and derived_risk_rating when an evidenced override was applied
            drv_raw = cf.get("derived_risk_rating")
            ctx_raw = cf.get("contextual_risk_rating") or cf.get("overall_risk") or drv_raw
            override_applied = bool(
                cf.get("risk_override_applied")
                or (drv_raw and ctx_raw and str(drv_raw).lower() != str(ctx_raw).lower() and cf.get("risk_override_rationale"))
            )
            if override_applied and drv_raw and ctx_raw:
                ov_val = f"{str(ctx_raw).upper()} (derived: {str(drv_raw).upper()})"
                ov_eids = ", ".join(f"`{e}`" for e in (cf.get("risk_override_evidence_ids") or []))
                override_notes.append(
                    f"- **Risk Override on `{_md(fid)}`**: Contextual risk `{str(ctx_raw).upper()}` vs derived `{str(drv_raw).upper()}` — {_md(cf.get('risk_override_rationale', ''), 160)} ({ov_eids or 'evidenced'})."
                )
            else:
                ov_raw = drv_raw or ctx_raw
                ov_val = str(ov_raw).upper() if ov_raw else "[UNSPECIFIED — REQUIRES UPDATE]"
            feas_val = str(cf.get("feasibility_derived") or cf.get("exploitability_likelihood") or "[UNSPECIFIED — REQUIRES UPDATE]")
            br_val = str(cf.get("blast_radius") or "[UNSPECIFIED — REQUIRES UPDATE]")
            r_owner = str(cf.get("risk_owner") or cf.get("owner_role") or "[UNSPECIFIED — REQUIRES UPDATE]")
            s_owner = str(cf.get("safety_owner") or "N/A")
            g0 = "YES" if (s_val in {"CRITICAL", "CATASTROPHIC"} or cf.get("gate_0_emergency_brake") is True) else "NO"
            repo_exec_sec.append(
                f"| `{_md(fid)}` | `{s_val}` | `{f_val}` | `{o_val}` | `{p_val}` | `{c_val}` | **`{ov_val}`** | `{_md(feas_val)}` | `{_md(br_val)}` | `{_md(r_owner)}` | `{_md(s_owner)}` | `{g0}` |"
            )
        repo_exec_sec.append("")
        if override_notes:
            repo_exec_sec.extend(override_notes)
            repo_exec_sec.append("")
        repo_exec_sec.append("### Key Questions for Architect / DevOps / Safety (`key_questions.json`)")
        repo_exec_sec.append("")
        key_questions: list[str] = []
        pending_kq_count = 0
        for q_obj in kq_file.get("questions", []):
            if isinstance(q_obj, dict):
                q_stat = str(q_obj.get("status", "pending"))
                if "pending" in q_stat.lower():
                    pending_kq_count += 1
                outcomes = ""
                if q_obj.get("outcome_if_yes") or q_obj.get("outcome_if_no"):
                    outcomes = f" (If YES: {q_obj.get('outcome_if_yes', 'N/A')} | If NO: {q_obj.get('outcome_if_no', 'N/A')})"
                key_questions.append(
                    f"[{q_obj.get('question_id', 'KQ')} -> `{q_obj.get('target_team', 'ops')}` | `{q_stat}`] {q_obj.get('question', '')}{outcomes}"
                )
        for q_str in list(sfop.get("key_questions", [])) + list(beyond_code.get("unverified_control_questions", [])):
            if isinstance(q_str, str):
                key_questions.append(q_str)
            elif isinstance(q_str, dict):
                key_questions.append(str(q_str.get("question") or q_str))
        if not key_questions:
            repo_exec_sec.append("_No open key questions recorded for this repository._")
        else:
            for kq in key_questions[:20]:
                repo_exec_sec.append(f"- {_md(kq)}")
        repo_exec_sec.append("")

        # Auto-generated Uncovered & Unverified Scope section
        repo_exec_sec.append("### Uncovered & Unverified Scope (Chưa phủ / Miễn trừ / Giới hạn ranh giới phần cứng & Cloud)")
        repo_exec_sec.append("")
        ignored_mods = scout.get("ignored_modules", [])
        unvisited_mods = vis_audit.get("visibility_report", {}).get("unvisited_target_modules", [])
        deferred_files = (
            vis_audit.get("visibility_report", {}).get("deferred_out_of_budget", [])
            or ws_state.get("deferred_out_of_budget", [])
        )
        status_counts = cov_matrix.get("status_counts") or {}
        if not status_counts and isinstance(cov_matrix.get("records"), list):
            for rec in cov_matrix.get("records", []):
                if isinstance(rec, dict):
                    st_k = str(rec.get("status") or "unassessed")
                    status_counts[st_k] = status_counts.get(st_k, 0) + 1
        unexp_cands = deep_trace.get("unexploitable_candidates", [])
        hyp_findings = [h for h in p3_queue.get("hypothesis_only_findings", []) if isinstance(h, dict)]
        unchallenged_list = list(p2_gate.get("unchallenged_chains") or ev_gate.get("unchallenged_chains") or [])
        deferred_ext_count = int(inv.get("deferred_external_tool_findings_count", len(inv.get("deferred_external_tool_findings", []))) or 0)
        unassigned_ext = inv.get("unassigned_project_external_findings", [])
        unassigned_ext_count = int(inv.get("unassigned_project_external_findings_count", len(unassigned_ext)) or 0)

        repo_exec_sec.append(
            f"- **Coverage Matrix Summary**: `{cov_matrix.get('record_count', len(cov_matrix.get('records', [])))}` surface × attack-class cells "
            f"(`covered_safe={status_counts.get('covered_safe', 0)}`, `flagged_for_phase_2={status_counts.get('flagged_for_phase_2', 0)}`, "
            f"`unassessed={status_counts.get('unassessed', 0)}`, `deferred={status_counts.get('deferred', 0)}`)."
        )
        repo_exec_sec.append(
            f"- **Unvisited Target Modules**: `{len(unvisited_mods)}` ({', '.join(unvisited_mods) if unvisited_mods else '0 — 100% target_modules visited'})."
        )
        repo_exec_sec.append(
            f"- **Deferred Out-of-Budget Files (`deferred_out_of_budget`)**: `{len(deferred_files)}` ({', '.join(str(x) for x in deferred_files) if deferred_files else 'none'})."
        )
        repo_exec_sec.append(
            f"- **Unexploitable Candidates Filtered in Phase 2 (`unexploitable_candidates`)**: `{len(unexp_cands)}`."
        )
        hyp_summary = (
            ", ".join(
                f"`{_md(h.get('chain_id') or h.get('candidate_id') or 'chain')}` (`{_md(h.get('challenger_verdict') or h.get('challenge_verdict') or 'needs_runtime_verification')}`)"
                for h in hyp_findings
            )
            if hyp_findings
            else "none"
        )
        repo_exec_sec.append(
            f"- **Hypothesis-Only Chains Requiring Runtime Verification (HYPOTHESIS_ONLY_UNVERIFIED)**: `{len(hyp_findings)}` ({hyp_summary})."
        )
        unch_summary = ", ".join(f"`{_md(u)}`" for u in unchallenged_list) if unchallenged_list else "none"
        repo_exec_sec.append(
            f"- **Unchallenged / Blocked Chains (UNCHALLENGED_BLOCKED)**: `{len(unchallenged_list)}` ({unch_summary})."
        )
        repo_exec_sec.append(
            f"- **Deferred Lower-Severity External Scanner Findings**: `{deferred_ext_count}`."
        )
        repo_exec_sec.append(
            f"- **Unassigned Project-Level External Scanner Findings (`unassigned_project_external_findings`)**: `{unassigned_ext_count}`."
        )
        repo_exec_sec.append(
            f"- **Pending Operator / Safety Key Questions**: `{pending_kq_count}`."
        )
        if ignored_mods:
            for ig in ignored_mods:
                if isinstance(ig, dict):
                    repo_exec_sec.append(f"- **Waived / Ignored Module**: `{_md(ig.get('path') or ig.get('module'))}` (reason: `{_md(ig.get('reason'))}`)")
        repo_exec_sec.append(
            "- **Hardware / Firmware & Cloud Boundary Note**: Physical OT/PLC/ECU hardware interlocks and live cloud WAF/ALB/IAM runtime policies outside the software repository require verification via `ingest_runtime_facts` and formal `ot_safety_engineering` / `infra_cloud_sec` sign-off."
        )
        repo_exec_sec.append("")

        exec_lines.extend(repo_exec_sec)
        r_exec_lines.extend(repo_exec_sec)

        # QA / Pentest Playbook section for repo
        repo_qa_sec: list[str] = (
            [f"## Repository: `{_md(rname)}`", ""]
            + list(gate_warn_lines)
            + [
                "### Verification Request Sequences (`request_plan_is_not_execution: true`)",
                "",
            ]
        )
        if not chains:
            repo_qa_sec.append("_No verified reachable vulnerability chains to generate request sequences for._")
            repo_qa_sec.append("")

        def _fmt_step(step_item: Any) -> str:
            if isinstance(step_item, dict):
                return str(step_item.get("description") or step_item.get("request") or step_item.get("action") or json.dumps(step_item, ensure_ascii=False))
            return str(step_item)

        for idx, ch in enumerate(chains, 1):
            if not isinstance(ch, dict):
                continue
            fid = str(ch.get("chain_id") or ch.get("candidate_id") or f"CHAIN-{idx}")
            rplan = ch.get("request_plan") or ch.get("request_sequence_plan") or ch.get("reproduction_plan") or {}
            steps: list[Any] = []
            if isinstance(rplan, dict):
                steps = list(rplan.get("steps") or rplan.get("discriminating_requests") or [])
            elif isinstance(rplan, list):
                steps = list(rplan)
            if not steps and isinstance(ch.get("discriminating_requests"), list):
                steps = list(ch.get("discriminating_requests", []))

            vuln_ind = (
                (rplan.get("expected_vulnerable_indicator") or rplan.get("expected_vulnerable_behavior") if isinstance(rplan, dict) else None)
                or ch.get("expected_vulnerable_indicator")
                or ch.get("expected_vulnerable_behavior")
                or "[UNSPECIFIED — REQUIRES UPDATE]"
            )
            safe_ind = (
                (rplan.get("expected_fixed_indicator") or rplan.get("expected_safe_behavior") if isinstance(rplan, dict) else None)
                or ch.get("expected_fixed_indicator")
                or ch.get("expected_safe_behavior")
                or "[UNSPECIFIED — REQUIRES UPDATE]"
            )

            repo_qa_sec += [
                f"#### Playbook for `{_md(fid)}`",
                f"- **Step 1: Setup**: {_md(_fmt_step(steps[0]) if len(steps) > 0 else '[UNSPECIFIED — REQUIRES UPDATE]')}",
                f"- **Step 2: Mutate**: {_md(_fmt_step(steps[1]) if len(steps) > 1 else (_fmt_step(steps[0]) if len(steps) == 1 else '[UNSPECIFIED — REQUIRES UPDATE]'))}",
                f"- **Step 3: Observe**: {_md(_fmt_step(steps[2]) if len(steps) > 2 else '[UNSPECIFIED — REQUIRES UPDATE]')}",
                f"- **Expected Vulnerable Indicator**: {_md(vuln_ind)}",
                f"- **Expected Fixed Indicator**: {_md(safe_ind)}",
                "",
            ]

        repo_qa_sec.append("### Runtime Verification Playbook for Hypothesis-Only & Unchallenged Chains")
        repo_qa_sec.append("")
        if not hyp_findings and not unchallenged_list:
            repo_qa_sec.append("_No hypothesis-only or unchallenged chains requiring separate runtime verification._")
            repo_qa_sec.append("")
        else:
            for idx, hch in enumerate(hyp_findings, 1):
                hfid = str(hch.get("chain_id") or hch.get("candidate_id") or f"HYP-CHAIN-{idx}")
                hverdict = str(hch.get("challenger_verdict") or hch.get("challenge_verdict") or "needs_runtime_verification")
                rplan = hch.get("request_plan") or hch.get("request_sequence_plan") or hch.get("reproduction_plan") or {}
                steps = []
                if isinstance(rplan, dict):
                    steps = list(rplan.get("steps") or rplan.get("discriminating_requests") or [])
                elif isinstance(rplan, list):
                    steps = list(rplan)
                if not steps and isinstance(hch.get("discriminating_requests"), list):
                    steps = list(hch.get("discriminating_requests", []))
                vuln_ind = (
                    (rplan.get("expected_vulnerable_indicator") or rplan.get("expected_vulnerable_behavior") if isinstance(rplan, dict) else None)
                    or hch.get("expected_vulnerable_indicator")
                    or hch.get("expected_vulnerable_behavior")
                    or "[UNSPECIFIED — REQUIRES UPDATE]"
                )
                safe_ind = (
                    (rplan.get("expected_fixed_indicator") or rplan.get("expected_safe_behavior") if isinstance(rplan, dict) else None)
                    or hch.get("expected_fixed_indicator")
                    or hch.get("expected_safe_behavior")
                    or "[UNSPECIFIED — REQUIRES UPDATE]"
                )
                repo_qa_sec += [
                    f"#### Hypothesis-Only Playbook for `{_md(hfid)}` (`{_md(hverdict)}`)",
                    f"- **Step 1: Setup**: {_md(_fmt_step(steps[0]) if len(steps) > 0 else '[UNSPECIFIED — REQUIRES UPDATE]')}",
                    f"- **Step 2: Mutate**: {_md(_fmt_step(steps[1]) if len(steps) > 1 else (_fmt_step(steps[0]) if len(steps) == 1 else '[UNSPECIFIED — REQUIRES UPDATE]'))}",
                    f"- **Step 3: Observe**: {_md(_fmt_step(steps[2]) if len(steps) > 2 else '[UNSPECIFIED — REQUIRES UPDATE]')}",
                    f"- **Expected Vulnerable Indicator**: {_md(vuln_ind)}",
                    f"- **Expected Fixed Indicator**: {_md(safe_ind)}",
                    "",
                ]
            for u_id in unchallenged_list:
                repo_qa_sec.append(
                    f"- **Unchallenged / Blocked Chain `{_md(u_id)}`**: Requires `blinded_counterevidence_challenger` verification before promotion."
                )
            if unchallenged_list:
                repo_qa_sec.append("")

        repo_qa_sec.append("### Empirical Refutations Ledger Summary")
        repo_qa_sec.append("")
        refutations = list(p3_queue.get("empirical_refutations_ledger", [])) if (rdir / "phase3_verified_queue.json").is_file() else []
        seen_ref_ids = {
            str(r.get("candidate_id") or r.get("chain_id") or "")
            for r in refutations
            if isinstance(r, dict)
        }
        if not (rdir / "phase3_verified_queue.json").is_file():
            for sc in list(challenger.get("challenged_chains", [])) + list(challenger.get("step_challenges", [])):
                if isinstance(sc, dict) and str(sc.get("challenger_verdict") or sc.get("challenge_verdict") or sc.get("verdict") or "") in {"mitigated_by_existing_control", "broken_link", "refuted"}:
                    sc_id = str(sc.get("chain_id") or sc.get("candidate_id") or "")
                    if sc_id not in seen_ref_ids:
                        refutations.append({
                            "candidate_id": sc_id,
                            "refutation_reason": sc.get("rationale") or sc.get("notes") or sc.get("challenger_verdict") or sc.get("challenge_verdict"),
                            "counterevidence_ids": sc.get("counter_evidence_ids") or sc.get("counterevidence_ids") or sc.get("evidence_ids") or [],
                        })
                        seen_ref_ids.add(sc_id)
        if not refutations:
            repo_qa_sec.append("_No refuted candidates recorded in the Empirical Refutations Ledger._")
            repo_qa_sec.append("")
        else:
            for ref in refutations:
                if isinstance(ref, dict):
                    if is_target_repo:
                        total_refutations += 1
                    rcid = ref.get("candidate_id") or ref.get("chain_id") or "[UNSPECIFIED — REQUIRES UPDATE]"
                    rreason = ref.get("refutation_reason") or ref.get("reason") or "[UNSPECIFIED — REQUIRES UPDATE]"
                    cevs = [str(e) for e in (ref.get("counterevidence_ids") or ref.get("evidence_ids") or []) if str(e).startswith("ev_")]
                    repo_qa_sec.append(
                        f"- **`{_md(rcid)}`**: {_md(rreason)} (Counterevidence: {', '.join(f'`{e}`' for e in cevs) if cevs else '`[UNSPECIFIED — REQUIRES UPDATE]`'})"
                    )
            repo_qa_sec.append("")

        qa_lines.extend(repo_qa_sec)
        r_qa_lines.extend(repo_qa_sec)

        if is_target_repo:
            sub_dir = docs_dir / rname
            sub_dir.mkdir(parents=True, exist_ok=True)
            rf1 = sub_dir / "01_developer_remediation_cards.md"
            rf2 = sub_dir / "02_executive_risk_and_key_questions.md"
            rf3 = sub_dir / "03_pentest_qa_verification_playbook.md"
            _write_md(rf1, r_dev_lines)
            _write_md(rf2, r_exec_lines)
            _write_md(rf3, r_qa_lines)
            repo_files_written.extend([str(rf1), str(rf2), str(rf3)])
            # Also write to documents/_v3/<repo>/ so documents/<repo>/01_repo_profile.md never collides in Phase 4
            v3_sub_dir = docs_dir / "_v3" / rname
            v3_sub_dir.mkdir(parents=True, exist_ok=True)
            _write_md(v3_sub_dir / "01_developer_remediation_cards.md", r_dev_lines)
            _write_md(v3_sub_dir / "02_executive_risk_and_key_questions.md", r_exec_lines)
            _write_md(v3_sub_dir / "03_pentest_qa_verification_playbook.md", r_qa_lines)

    f1 = docs_dir / "01_developer_remediation_cards.md"
    f2 = docs_dir / "02_executive_risk_and_key_questions.md"
    f3 = docs_dir / "03_pentest_qa_verification_playbook.md"
    _write_md(f1, dev_lines)
    _write_md(f2, exec_lines)
    _write_md(f3, qa_lines)
    files_written = [str(f1), str(f2), str(f3)]

    return {
        "ok": True,
        "run_id": run_id,
        "repo_name": repo_name,
        "output_dir": str(docs_dir),
        "files_written": files_written,
        "repo_files_written": repo_files_written,
        "total_findings_rendered": total_findings,
        "total_refutations_rendered": total_refutations,
        "gate_0_emergency_brake_active": len(repos_with_gate0) > 0,
        "repos_with_gate0": repos_with_gate0,
    }


def export_final_phase_inputs(project_root: Path, run_id: str = "default") -> dict[str, Any]:
    """Phase 4 Adapter & Report Synthesizer:
    Exports .localsec/runs/<run_id>/ artifacts into the canonical documents/ layout
    (documents/<repo>/, documents/_analysis/, documents/_system/, documents/_report/, documents/_v3/),
    converts Phase 3 S-F-O-P-C calibrations into documents/_report/work/risk/F-xx.json with zero LLM tokens,
    verifies risk re-derivation parity against derived_risk_rating, and generates
    documents/_report/00_manifest.md, BAO_CAO_TONG_HOP_BAO_MAT.md, and DANH_GIA_RUI_RO.md.
    """
    project_root = Path(project_root).expanduser().resolve()
    runs_root = project_root / ".localsec" / "runs" / run_id
    docs_dir = project_root / "documents"
    docs_dir.mkdir(parents=True, exist_ok=True)

    # First ensure v3 per-repo & top-level cards are rendered (including documents/_v3/<repo>/)
    render_v3_reports(project_root, repo_name=None, run_id=run_id)

    def _load_json(fp: Path) -> dict[str, Any]:
        if fp.is_file():
            try:
                raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw, dict):
                    return raw.get("result", raw) if isinstance(raw.get("result"), dict) else raw
            except Exception:
                pass
        return {}

    repo_dirs: list[Path] = []
    if runs_root.is_dir():
        for d in sorted(runs_root.iterdir(), key=lambda p: p.name):
            if d.is_dir() and not d.name.startswith("_"):
                repo_dirs.append(d)

    axis_vn_map = {
        "safety": "an_toan_vat_ly",
        "financial": "tai_chinh",
        "operational": "van_hanh",
        "privacy": "du_lieu_ca_nhan",
        "compliance": "tuan_thu",
    }
    actor_vn_map = {
        "external_unauthenticated": "ngoai",
        "authenticated_user": "nguoi_dung",
        "authenticated_ev_driver": "nguoi_dung",
        "b2b_partner_cross_scope": "doi_tac",
        "rogue_insider_or_operator": "noi_bo",
        "compromised_internal_component": "thanh_phan_bi_chiem",
        "compromised_edge_device_tbox_charger_robot": "thanh_phan_bi_chiem",
        "physical_or_local_bus_attacker": "thanh_phan_bi_chiem",
    }
    pre_vn_map = {"yes": "co", "no": "khong", "unknown": "chua_ro"}
    team_vn_map = {
        "dev_team": "team_dev",
        "infra_cloud_sec": "platform_devops",
        "iam_platform": "platform_devops",
        "appsec_architecture": "security",
        "appsec_pentest_qa": "security",
        "security_governance": "security",
        "data_privacy_dpo": "phap_che",
        "ot_safety_engineering": "van_hanh",
    }
    rank_map = {"none": 0, "negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "catastrophic": 5}
    inv_rank = {0: "negligible", 1: "low", 2: "medium", 3: "high", 4: "critical", 5: "catastrophic"}

    exported_files: list[str] = []
    all_chains_index: list[dict[str, Any]] = []
    root_causes_by_cluster: dict[str, dict[str, Any]] = {}
    consolidated_findings: list[dict[str, Any]] = []
    risk_files_written: list[str] = []
    risk_parity_checks: list[dict[str, Any]] = []
    merged_runtime_controls: list[dict[str, Any]] = []
    merged_runtime_answers: dict[str, Any] = {}
    manifest_rows: list[dict[str, Any]] = []
    all_trust_mismatches: list[dict[str, Any]] = []
    all_arch_diagrams: list[str] = []
    all_refutations: list[dict[str, Any]] = []
    all_hypotheses: list[dict[str, Any]] = []
    all_unchallenged: list[str] = []
    all_key_questions: list[dict[str, Any]] = []
    gate0_repos: list[str] = []

    chains_out_dir = docs_dir / "_analysis" / "chains"
    chains_out_dir.mkdir(parents=True, exist_ok=True)
    system_out_dir = docs_dir / "_system"
    system_out_dir.mkdir(parents=True, exist_ok=True)
    report_out_dir = docs_dir / "_report"
    risk_work_dir = report_out_dir / "work" / "risk"
    risk_work_dir.mkdir(parents=True, exist_ok=True)

    finding_counter = 0

    for rdir in repo_dirs:
        rname = rdir.name
        repo_doc_dir = docs_dir / rname
        repo_doc_dir.mkdir(parents=True, exist_ok=True)
        basv_dir = repo_doc_dir / "basv"
        basv_dir.mkdir(parents=True, exist_ok=True)

        inv = _load_json(rdir / "inventory_repo.json")
        scout = _load_json(rdir / "codebase_scout.json")
        intent = _load_json(rdir / "intent_invariant_modeler.json")
        surf = _load_json(rdir / "unified_surface_mapper.json")
        arch = _load_json(rdir / "cross_repo_and_arch_review.json")
        cov_matrix = _load_json(rdir / "coverage_matrix.json")
        cand_queue = _load_json(rdir / "candidate_queue.json")
        vis_aud = _load_json(rdir / "coverage_and_evidence_auditor.json")
        ws_state = _load_json(rdir / "workspace_state.json")
        deep_trace = _load_json(rdir / "deep_trace_chain_analyst.json")
        challenger = _load_json(rdir / "blinded_counterevidence_challenger.json")
        p3_queue = _load_json(rdir / "phase3_verified_queue.json")
        actor_map = _load_json(rdir / "actor_and_feasibility_assessor.json")
        beyond_code = _load_json(rdir / "beyond_code_control_mapper.json")
        sfop = _load_json(rdir / "sfop_risk_calibrator.json")
        kq_data = _load_json(rdir / "key_questions.json")
        rt_facts = _load_json(rdir / "runtime_environment_facts.json")

        p1_receipt = _load_json(rdir / "phase1_gate_receipt.json")
        p2_receipt = _load_json(rdir / "phase2_gate_receipt.json")
        p3_receipt = _load_json(rdir / "phase3_gate_receipt.json")
        p1_passed = (rdir / "phase1_gate_receipt.json").is_file() and p1_receipt.get("gate_passed") is True
        p2_passed = (rdir / "phase2_gate_receipt.json").is_file() and p2_receipt.get("gate_passed") is True
        p3_passed = (rdir / "phase3_gate_receipt.json").is_file() and p3_receipt.get("gate_passed") is True

        if isinstance(rt_facts.get("controls"), list):
            merged_runtime_controls.extend(rt_facts["controls"])
        if isinstance(rt_facts.get("answers"), dict):
            merged_runtime_answers.update(rt_facts["answers"])

        # 1. documents/<repo>/01_repo_profile.md
        archetypes = scout.get("product_archetypes") or scout.get("detected_archetypes") or []
        t_mods = scout.get("target_modules") or []
        ig_mods = scout.get("ignored_modules") or []
        invariants_list = intent.get("invariants") or []
        profile_lines = [
            f"# Hồ sơ Repository: `{rname}`",
            "",
            f"- **Phân tầng (Repo Tier)**: `{scout.get('repo_tier') or inv.get('recommended_tier') or 'tier_1'}`",
            f"- **Product Archetypes**: {', '.join(f'`{a}`' for a in archetypes) if archetypes else '`unspecified`'}",
            f"- **Target Modules (`target_modules`)**: {', '.join(f'`{m}`' for m in t_mods) if t_mods else '`all`'}",
            f"- **Ignored Modules (`ignored_modules`)**: `{len(ig_mods)}`",
            "",
            "## Bất biến Nghiệp vụ & An toàn (S-F-O-P-C Invariants)",
            "",
        ]
        if invariants_list:
            for inv_item in invariants_list:
                if isinstance(inv_item, dict):
                    profile_lines.append(
                        f"- **`{inv_item.get('invariant_id', 'INV')}`** (`{inv_item.get('axis', 'operational')}` | `{inv_item.get('status', 'confirmed')}`): "
                        f"{inv_item.get('statement') or inv_item.get('description') or ''} "
                        f"(Evidence: {', '.join(f'`{e}`' for e in (inv_item.get('evidence_ids') or [])) or 'none'})"
                    )
        else:
            profile_lines.append("_Chưa ghi nhận bất biến riêng cho repository này._")
        profile_lines.append("")
        p_01 = repo_doc_dir / "01_repo_profile.md"
        p_01.write_text("\n".join(profile_lines), encoding="utf-8")
        exported_files.append(str(p_01))

        # 2. documents/<repo>/02_techstack.json
        p_02 = repo_doc_dir / "02_techstack.json"
        write_json(
            p_02,
            {
                "repo_name": rname,
                "repo_tier": scout.get("repo_tier") or inv.get("recommended_tier") or "tier_1",
                "product_archetypes": archetypes,
                "coding_conventions": scout.get("coding_conventions", {}),
                "dependency_manifests": inv.get("dependency_manifests", []),
                "dependency_leads": inv.get("dependency_leads", []),
            },
        )
        exported_files.append(str(p_02))

        # 3. documents/<repo>/05_inbound_outbound.json
        p_05 = repo_doc_dir / "05_inbound_outbound.json"
        write_json(
            p_05,
            {
                "repo_name": rname,
                "surface_checklist": surf.get("surface_checklist", {}),
                "entrypoints": surf.get("entrypoints", []),
                "data_flows": surf.get("data_flows", []),
                "sensitive_data": surf.get("sensitive_data", []),
            },
        )
        exported_files.append(str(p_05))

        # 4. documents/<repo>/16_code_coverage.json (with explicit coverage_semantics: "file_touched")
        vis_rep = vis_aud.get("visibility_report") or p1_receipt.get("visibility_audit", {}).get("visibility_report") or {}
        read_ranges = ws_state.get("read_ranges", {}) if isinstance(ws_state.get("read_ranges"), dict) else {}
        files_touched_count = len(read_ranges)
        mandatory_ep = list((inv.get("mandatory_files") or {}).get("entrypoint", []))
        mandatory_sec = list((inv.get("mandatory_files") or {}).get("security", []))
        total_mandatory = max(1, len(set(mandatory_ep + mandatory_sec)))
        touched_mandatory = len([f for f in set(mandatory_ep + mandatory_sec) if f in read_ranges])
        file_touched_pct = round((touched_mandatory / total_mandatory) * 100.0, 2) if (mandatory_ep or mandatory_sec) else 100.0
        lines_read_total = 0
        for rng_list in read_ranges.values():
            if isinstance(rng_list, list):
                for pair in rng_list:
                    if isinstance(pair, (list, tuple)) and len(pair) == 2:
                        lines_read_total += max(0, int(pair[1]) - int(pair[0]) + 1)
        p_16 = repo_doc_dir / "16_code_coverage.json"
        write_json(
            p_16,
            {
                "repo_name": rname,
                "coverage_semantics": "file_touched",
                "file_touched_coverage_pct": file_touched_pct,
                "files_touched_count": files_touched_count,
                "lines_read_total": lines_read_total,
                "line_coverage_pct": vis_rep.get("line_coverage_pct"),
                "target_modules_coverage_pct": vis_rep.get("coverage_percentage", file_touched_pct),
                "unvisited_target_modules": vis_rep.get("unvisited_target_modules", []),
                "grazed_files": vis_rep.get("grazed_files", []),
                "mandatory_entrypoint_coverage": vis_rep.get("mandatory_entrypoint_coverage", {}),
                "mandatory_security_coverage": vis_rep.get("mandatory_security_coverage", {}),
                "deferred_out_of_budget": vis_rep.get("deferred_out_of_budget", []),
            },
        )
        exported_files.append(str(p_16))

        # 5. documents/<repo>/12_analysis_status.json — ONLY written if Phase 1 gate passed!
        if p1_passed:
            p_12 = repo_doc_dir / "12_analysis_status.json"
            write_json(
                p_12,
                {
                    "repo_name": rname,
                    "run_id": run_id,
                    "status": "completed",
                    "phase1_gate_passed": p1_passed,
                    "phase2_gate_passed": p2_passed,
                    "phase3_gate_passed": p3_passed,
                    "coverage_semantics": "file_touched",
                    "file_touched_coverage_pct": file_touched_pct,
                },
            )
            exported_files.append(str(p_12))

        # 6. documents/<repo>/basv/18_business_aware_synthesis.json
        p_18 = basv_dir / "18_business_aware_synthesis.json"
        write_json(
            p_18,
            {
                "repo_name": rname,
                "invariants": intent.get("invariants", []),
                "self_challenged_gaps": intent.get("self_challenged_gaps", []),
                "invariant_checks": surf.get("invariant_checks", []),
                "semantic_clusters": surf.get("semantic_clusters", []),
            },
        )
        exported_files.append(str(p_18))

        # 7. documents/<repo>/basv/19_basv_epistemic_and_contradiction_diagnostics.json — ONLY written if Phase 2 gate passed!
        if p2_passed:
            p_19 = basv_dir / "19_basv_epistemic_and_contradiction_diagnostics.json"
            write_json(
                p_19,
                {
                    "repo_name": rname,
                    "gate_passed": True,
                    "semantic_downgrades": p1_receipt.get("semantic_downgrades", []),
                    "empirical_refutations_ledger": p3_queue.get("empirical_refutations_ledger", []),
                    "reconciliation_log": p3_queue.get("reconciliation_log", []),
                },
            )
            exported_files.append(str(p_19))

        # Collect cross-repo arch findings
        for tm in arch.get("trust_boundary_mismatches", []):
            if isinstance(tm, dict):
                all_trust_mismatches.append({"repo_name": rname, **tm})
        for dg in arch.get("diagrams", []):
            if isinstance(dg, str) and dg.strip():
                all_arch_diagrams.append(dg.strip())

        # Collect refutations, hypotheses, unchallenged
        for ref_item in p3_queue.get("empirical_refutations_ledger", []):
            if isinstance(ref_item, dict):
                all_refutations.append({"repo_name": rname, **ref_item})
        for hyp_item in p3_queue.get("hypothesis_only_findings", []):
            if isinstance(hyp_item, dict):
                all_hypotheses.append({"repo_name": rname, **hyp_item})
        for unch_id in p2_receipt.get("unchallenged_chains", []):
            all_unchallenged.append(f"{rname}:{unch_id}")

        # Index 3.1, 3.2, 3.3 for this repo
        actor_by_chain: dict[str, dict[str, Any]] = {}
        for a_item in list(actor_map.get("actor_assessments") or []) + list(actor_map.get("assessments") or []):
            if isinstance(a_item, dict):
                cid_k = str(a_item.get("chain_id") or a_item.get("finding_id") or "")
                if cid_k:
                    actor_by_chain[cid_k] = a_item

        controls_by_chain: dict[str, list[dict[str, Any]]] = {}
        for c_item in list(beyond_code.get("beyond_code_controls") or []):
            if isinstance(c_item, dict):
                cid_k = str(c_item.get("chain_id") or c_item.get("finding_id") or "")
                controls_by_chain.setdefault(cid_k, []).append(c_item)

        cal_by_chain: dict[str, dict[str, Any]] = {}
        for cf_item in list(sfop.get("calibrated_findings") or []):
            if isinstance(cf_item, dict):
                cid_k = str(cf_item.get("chain_id") or cf_item.get("finding_id") or "")
                if cid_k:
                    cal_by_chain[cid_k] = cf_item

        repo_kqs = [q for q in kq_data.get("questions", []) if isinstance(q, dict)]
        for q_item in repo_kqs:
            all_key_questions.append({"repo_name": rname, **q_item})

        # 8. Build documents/<repo>/09_findings.json and documents/_analysis/chains/chain_<ID>.json
        repo_findings: list[dict[str, Any]] = []
        surviving_p2 = [
            c for c in p3_queue.get("verified_findings", [])
            if isinstance(c, dict) and str(c.get("reconciled_status") or "REACHABLE_VULNERABILITY") == "REACHABLE_VULNERABILITY"
        ]
        if not surviving_p2 and not (rdir / "phase3_verified_queue.json").is_file():
            surviving_p2 = [c for c in (deep_trace.get("chains") or []) if isinstance(c, dict)]

        for ch_obj in surviving_p2:
            cid = str(ch_obj.get("chain_id") or ch_obj.get("finding_id") or ch_obj.get("candidate_id") or "CHAIN")
            cal_obj = cal_by_chain.get(cid, {})
            actor_obj = actor_by_chain.get(cid, {})
            ctrl_list = controls_by_chain.get(cid, [])

            finding_counter += 1
            f_code = f"F-{finding_counter:02d}"

            # Separate technical code_verified_severity from contextual_risk_rating
            code_sev = str(
                ch_obj.get("code_verified_severity")
                or ch_obj.get("severity")
                or cal_obj.get("max_impact")
                or "high"
            ).lower()
            ver_status = str(ch_obj.get("chain_verdict") or ch_obj.get("verification_status") or "code_supported").lower()
            eids = list(dict.fromkeys(
                [str(e) for e in (ch_obj.get("evidence_ids") or []) if str(e).startswith("ev_")]
                + [str(e) for e in (cal_obj.get("evidence_ids") or []) if str(e).startswith("ev_")]
            ))

            rc_cluster = str(ch_obj.get("root_cause_cluster_id") or ch_obj.get("cluster_id") or f"RC-{rname}-{cid}")
            rc_raw = ch_obj.get("root_cause")
            rc_summary = str(
                (rc_raw.get("summary") or rc_raw.get("description") if isinstance(rc_raw, dict) else rc_raw)
                or ch_obj.get("title")
                or cid
            )
            rep_fix = str(ch_obj.get("remediation") or ch_obj.get("representative_fix") or "")

            root_causes_by_cluster.setdefault(
                rc_cluster,
                {
                    "cluster_id": rc_cluster,
                    "repo_name": rname,
                    "summary": rc_summary,
                    "representative_fix": rep_fix,
                    "chain_ids": [],
                    "finding_ids": [],
                    "evidence_ids": [],
                },
            )
            if cid not in root_causes_by_cluster[rc_cluster]["chain_ids"]:
                root_causes_by_cluster[rc_cluster]["chain_ids"].append(cid)
            root_causes_by_cluster[rc_cluster]["finding_ids"].append(f_code)
            for e in eids:
                if e not in root_causes_by_cluster[rc_cluster]["evidence_ids"]:
                    root_causes_by_cluster[rc_cluster]["evidence_ids"].append(e)

            chain_export = {
                "chain_id": cid,
                "finding_id": f_code,
                "repo_name": rname,
                "title": str(ch_obj.get("title") or rc_summary),
                "verification_status": ver_status,
                "code_verified_severity": code_sev,
                "challenger_verdict": ch_obj.get("challenger_verdict") or ch_obj.get("challenge_verdict") or "confirmed_exploit_chain",
                "reconciled_status": ch_obj.get("reconciled_status") or "REACHABLE_VULNERABILITY",
                "root_cause_cluster_id": rc_cluster,
                "root_cause": rc_raw or rc_summary,
                "remediation": rep_fix,
                "hops": ch_obj.get("hops", []),
                "request_plan": ch_obj.get("request_plan", {}),
                "evidence_ids": eids,
            }
            safe_cid = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{rname}_{cid}")
            ch_path = chains_out_dir / f"chain_{safe_cid}.json"
            write_json(ch_path, chain_export)
            exported_files.append(str(ch_path))
            all_chains_index.append(chain_export)

            finding_entry = {
                "finding_id": f_code,
                "chain_id": cid,
                "repo_name": rname,
                "title": str(ch_obj.get("title") or rc_summary),
                "verification_status": ver_status,
                "code_verified_severity": code_sev,
                "derived_risk_rating": str(cal_obj.get("derived_risk_rating") or cal_obj.get("max_impact") or code_sev).lower(),
                "contextual_risk_rating": str(cal_obj.get("contextual_risk_rating") or cal_obj.get("derived_risk_rating") or code_sev).lower(),
                "risk_override_applied": bool(cal_obj.get("risk_override_applied", False)),
                "risk_override_rationale": str(cal_obj.get("risk_override_rationale") or ""),
                "feasibility_derived": str(cal_obj.get("feasibility_derived") or "feasible"),
                "owner_role": str(cal_obj.get("owner_role") or "unassigned_pending_roster"),
                "risk_owner": str(cal_obj.get("risk_owner") or "unassigned_pending_roster"),
                "safety_owner": str(cal_obj.get("safety_owner") or "N/A"),
                "gate_0_emergency_brake": bool(cal_obj.get("gate_0_emergency_brake", False)),
                "root_cause_cluster_id": rc_cluster,
                "remediation": rep_fix,
                "evidence_ids": eids,
            }
            repo_findings.append(finding_entry)
            consolidated_findings.append(finding_entry)

            # Convert Phase 3 to documents/_report/work/risk/F-xx.json (zero LLM tokens)
            raw_axes = cal_obj.get("impact_axes") or cal_obj.get("sfop_impacts") or {}
            anh_huong_5_chieu: dict[str, dict[str, Any]] = {}
            max_rank_val = 0
            for eng_ax, vn_ax in axis_vn_map.items():
                ax_val = raw_axes.get(eng_ax) if isinstance(raw_axes, dict) else None
                if isinstance(ax_val, dict):
                    lvl = str(ax_val.get("level") or "negligible").lower()
                    basis = str(ax_val.get("basis") or ax_val.get("rationale") or "")
                    br = str(ax_val.get("blast_radius") or cal_obj.get("blast_radius") or "service")
                else:
                    lvl = str(ax_val or "negligible").lower()
                    basis = ""
                    br = str(cal_obj.get("blast_radius") or "service")
                max_rank_val = max(max_rank_val, rank_map.get(lvl, 0))
                anh_huong_5_chieu[vn_ax] = {
                    "muc_do": lvl,
                    "pham_vi_lan_toa": br,
                    "co_so": basis,
                }
                if eng_ax == "safety" and lvl in {"critical", "catastrophic"} and rname not in gate0_repos:
                    gate0_repos.append(rname)

            max_impact_vn = inv_rank.get(max_rank_val, str(cal_obj.get("max_impact") or "medium").lower())
            infeasible_vn = "low" if max_rank_val >= 1 else "negligible"

            mat_xich_suy_dien: list[dict[str, Any]] = []
            for pre in actor_obj.get("preconditions", []):
                if isinstance(pre, dict):
                    raw_pst = str(pre.get("status") or pre.get("precondition_status") or "unknown").lower()
                    vn_st = pre_vn_map.get(raw_pst, "chua_ro")
                    mat_xich_suy_dien.append({
                        "loai": "dieu_kien_tien_quyet",
                        "mo_ta": str(pre.get("description") or pre.get("condition") or ""),
                        "trang_thai": vn_st,
                        "evidence_ids": list(pre.get("evidence_ids") or []),
                        "searched_paths": list(pre.get("searched_paths") or []),
                    })

            for ctrl in ctrl_list:
                if isinstance(ctrl, dict):
                    cst = str(ctrl.get("status") or "hypothesis").lower()
                    ceff = str(ctrl.get("mitigation_effect") or "none").lower()
                    if cst == "confirmed" and ceff == "blocks_exploit":
                        # Control confirmed & blocks exploit -> attack link cannot pass ("khong")
                        vn_ctrl_st = "khong"
                    elif cst in {"hypothesis", "unknown", "assumed_unverified"}:
                        vn_ctrl_st = "chua_ro"
                    else:
                        vn_ctrl_st = "co"
                    mat_xich_suy_dien.append({
                        "loai": "kiem_soat_ngoai_code",
                        "mo_ta": str(ctrl.get("control_id") or ctrl.get("layer") or ""),
                        "trang_thai": vn_ctrl_st,
                        "evidence_ids": list(ctrl.get("evidence_ids") or []),
                        "searched_paths": list(ctrl.get("searched_paths") or []),
                    })

            # Also include any pending key questions for this chain that came from runtime controls
            chain_kqs_vn: list[dict[str, Any]] = []
            for q_item in repo_kqs:
                if str(q_item.get("chain_id") or "") == cid:
                    raw_team = str(q_item.get("target_team") or "security")
                    chain_kqs_vn.append({
                        "question_id": q_item.get("question_id"),
                        "nguoi_nhan": team_vn_map.get(raw_team, "security"),
                        "cau_hoi": q_item.get("question"),
                        "neu_co": q_item.get("outcome_if_yes"),
                        "neu_khong": q_item.get("outcome_if_no"),
                        "trang_thai": q_item.get("status"),
                    })
                    if str(q_item.get("status") or "").startswith("pending") and not any(m["trang_thai"] == "chua_ro" for m in mat_xich_suy_dien):
                        mat_xich_suy_dien.append({
                            "loai": "cau_hoi_mo",
                            "mo_ta": str(q_item.get("question") or ""),
                            "trang_thai": "chua_ro",
                            "evidence_ids": [],
                            "searched_paths": list(q_item.get("searched_paths") or []),
                        })

            # Re-derive risk from converted F-xx.json links and verify parity with derived_risk_rating
            if any(m["trang_thai"] == "khong" for m in mat_xich_suy_dien):
                kha_thi_vn = "khong_kha_thi"
                re_derived_risk = infeasible_vn
            elif any(m["trang_thai"] == "chua_ro" for m in mat_xich_suy_dien):
                kha_thi_vn = "tam_thoi_chua_ro"
                re_derived_risk = max_impact_vn
            else:
                kha_thi_vn = "kha_thi"
                re_derived_risk = max_impact_vn

            expected_derived = str(cal_obj.get("derived_risk_rating") or re_derived_risk).lower()
            parity_ok = re_derived_risk == expected_derived
            risk_parity_checks.append({
                "finding_id": f_code,
                "chain_id": cid,
                "repo_name": rname,
                "re_derived_risk": re_derived_risk,
                "phase3_derived_risk_rating": expected_derived,
                "parity_verified": parity_ok,
            })

            raw_actor = str(actor_obj.get("minimum_actor") or "authenticated_user")
            f_risk_payload = {
                "finding_id": f_code,
                "chain_id": cid,
                "repo_name": rname,
                "ke_tan_cong_toi_thieu": actor_vn_map.get(raw_actor, "nguoi_dung"),
                "minimum_actor": raw_actor,
                "anh_huong_5_chieu": anh_huong_5_chieu,
                "muc_do_anh_huong_toi_da": max_impact_vn,
                "mat_xich_suy_dien": mat_xich_suy_dien,
                "kha_thi": kha_thi_vn,
                "muc_rui_ro_suy_ra": re_derived_risk,
                "muc_rui_ro_cuoi": str(cal_obj.get("contextual_risk_rating") or re_derived_risk).lower(),
                "risk_override_applied": bool(cal_obj.get("risk_override_applied", False)),
                "risk_override_rationale": str(cal_obj.get("risk_override_rationale") or ""),
                "owner_role": str(cal_obj.get("owner_role") or "unassigned_pending_roster"),
                "risk_owner": str(cal_obj.get("risk_owner") or "unassigned_pending_roster"),
                "safety_owner": str(cal_obj.get("safety_owner") or "N/A"),
                "cau_hoi_mo": chain_kqs_vn,
                "parity_verified": parity_ok,
            }
            f_risk_path = risk_work_dir / f"{f_code}.json"
            write_json(f_risk_path, f_risk_payload)
            risk_files_written.append(str(f_risk_path))
            exported_files.append(str(f_risk_path))

        p_09 = repo_doc_dir / "09_findings.json"
        write_json(
            p_09,
            {
                "repo_name": rname,
                "finding_count": len(repo_findings),
                "findings": repo_findings,
            },
        )
        exported_files.append(str(p_09))

        manifest_rows.append({
            "repo_name": rname,
            "tier": scout.get("repo_tier") or inv.get("recommended_tier") or "tier_1",
            "p1_passed": p1_passed,
            "p2_passed": p2_passed,
            "p3_passed": p3_passed,
            "file_touched_coverage_pct": file_touched_pct,
            "line_coverage_pct": vis_rep.get("line_coverage_pct"),
            "findings_count": len(repo_findings),
            "refutations_count": len(p3_queue.get("empirical_refutations_ledger", [])),
            "hypotheses_count": len(p3_queue.get("hypothesis_only_findings", [])),
        })

    # Write Group 2 system/analysis files
    rc_map_path = docs_dir / "_analysis" / "06_root_cause_map.json"
    write_json(
        rc_map_path,
        {
            "run_id": run_id,
            "cluster_count": len(root_causes_by_cluster),
            "root_cause_clusters": list(root_causes_by_cluster.values()),
        },
    )
    exported_files.append(str(rc_map_path))

    chain_rep_path = docs_dir / "_analysis" / "99_project_chain_report.json"
    write_json(
        chain_rep_path,
        {
            "run_id": run_id,
            "verified_reachable_chains_count": len(all_chains_index),
            "verified_reachable_chains": all_chains_index,
            "hypothesis_only_chains": all_hypotheses,
            "refuted_chains": all_refutations,
            "unchallenged_chains": all_unchallenged,
        },
    )
    exported_files.append(str(chain_rep_path))

    matched_boundaries = _load_json(runs_root / "_analysis" / "matched_cross_repo_boundaries.json")
    cross_repo_path = system_out_dir / "02_cross_repo_review.json"
    write_json(
        cross_repo_path,
        {
            "run_id": run_id,
            "matched_edges": matched_boundaries.get("matched_edges", []),
            "unmatched_producers": matched_boundaries.get("unmatched_producers", []),
            "unmatched_consumers": matched_boundaries.get("unmatched_consumers", []),
            "auth_propagation_gaps": matched_boundaries.get("auth_propagation_gaps", []),
            "trust_boundary_mismatches": all_trust_mismatches,
            "diagrams": all_arch_diagrams,
        },
    )
    exported_files.append(str(cross_repo_path))

    # Write Group 3 report work files
    unassigned_ext_file = _load_json(runs_root / "_analysis" / "unassigned_external_tool_findings.json")
    rt_out_path = report_out_dir / "runtime_facts.json"
    write_json(
        rt_out_path,
        {
            "run_id": run_id,
            "controls": merged_runtime_controls,
            "answers": merged_runtime_answers,
            "unassigned_external_tool_findings": unassigned_ext_file.get("findings", []),
        },
    )
    exported_files.append(str(rt_out_path))

    cons_path = report_out_dir / "work" / "findings_consolidated.json"
    write_json(
        cons_path,
        {
            "run_id": run_id,
            "total_findings": len(consolidated_findings),
            "findings": consolidated_findings,
        },
    )
    exported_files.append(str(cons_path))

    combos_path = risk_work_dir / "_combinations.json"
    write_json(
        combos_path,
        {
            "run_id": run_id,
            "cross_repo_auth_gaps": matched_boundaries.get("auth_propagation_gaps", []),
            "trust_boundary_mismatches": all_trust_mismatches,
            "root_cause_clusters": list(root_causes_by_cluster.values()),
        },
    )
    exported_files.append(str(combos_path))

    # Group 4: Synthesize Phase 4 Vietnamese Reports (00_manifest.md, BAO_CAO_TONG_HOP_BAO_MAT.md, DANH_GIA_RUI_RO.md)
    any_gate_failed = any(not (r["p1_passed"] and r["p2_passed"] and r["p3_passed"]) for r in manifest_rows)

    manifest_md = [
        "# 00 — Manifest & Chỉ mục Báo cáo Kiểm toán Bảo mật (Phase 4)",
        "",
        f"- **Run ID**: `{run_id}`",
        f"- **Tổng số Repository**: `{len(manifest_rows)}`",
        f"- **Tổng số Lỗ hổng Đã Xác minh (`F-xx`)**: `{len(consolidated_findings)}`",
        f"- **Kiểm chứng Tương đương Công thức Rủi ro (`parity_verified`)**: `{all(p['parity_verified'] for p in risk_parity_checks)}`",
        "",
        "## Bảng Trạng thái Cổng Kiểm toán & Độ phủ theo Repository",
        "",
        "| Repository | Tier | Phase 1 Gate | Phase 2 Gate | Phase 3 Gate | Độ phủ (`coverage_semantics: file_touched`) | `line_coverage_pct` | Lỗ hổng (`F-xx`) | Bác bỏ (`Refuted`) | Cần kiểm Runtime (`Hypothesis`) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for r in manifest_rows:
        manifest_md.append(
            f"| `{r['repo_name']}` | `{r['tier']}` | `{'PASS' if r['p1_passed'] else 'FAIL/MISSING'}` | "
            f"`{'PASS' if r['p2_passed'] else 'FAIL/MISSING'}` | `{'PASS' if r['p3_passed'] else 'FAIL/MISSING'}` | "
            f"`{r['file_touched_coverage_pct']}%` (`file_touched`) | `{r['line_coverage_pct'] if r['line_coverage_pct'] is not None else 'null'}` | "
            f"`{r['findings_count']}` | `{r['refutations_count']}` | `{r['hypotheses_count']}` |"
        )
    manifest_md += [
        "",
        "## Danh mục Tài liệu Đầu ra (`documents/`)",
        "",
        "- `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md` — Báo cáo Kỹ thuật & Kiến trúc Bảo mật Tổng hợp",
        "- `documents/_report/DANH_GIA_RUI_RO.md` — Báo cáo Đánh giá Rủi ro Ngữ cảnh 5 Trục S-F-O-P-C & Câu hỏi Mở",
        "- `documents/_system/02_cross_repo_review.json` — Đối sánh Ranh giới Liên thông Xuyên Repo",
        "- `documents/_analysis/06_root_cause_map.json` — Bản đồ Gom cụm Nguyên nhân Gốc",
        "- `documents/_analysis/99_project_chain_report.json` — Báo cáo Chuỗi Tấn công Toàn Dự án",
        "",
    ]
    manifest_path = report_out_dir / "00_manifest.md"
    manifest_path.write_text("\n".join(manifest_md), encoding="utf-8")
    exported_files.append(str(manifest_path))

    # BAO_CAO_TONG_HOP_BAO_MAT.md
    tech_md = [
        "# BÁO CÁO TỔNG HỢP BẢO MẬT KỸ THUẬT & KIẾN TRÚC (PHASE 4)",
        "",
    ]
    if any_gate_failed:
        tech_md += [
            "> [!WARNING]",
            "> **[UNFINALIZED / GATE FAILED]**: Một hoặc nhiều repository chưa vượt qua đủ 3 cổng kiểm toán (`phase1/2/3_gate_receipt.json`). Xem chi tiết tại `00_manifest.md`.",
            "",
        ]
    tech_md += [
        "## 1. Tổng quan Kiến trúc & Lệch Giả định Tin cậy Xuyên Repo (`02_cross_repo_review.json`)",
        "",
        f"- **Số kết nối liên dịch vụ đã ghép cặp (`matched_edges`)**: `{len(matched_boundaries.get('matched_edges', []))}`",
        f"- **Lệch lan truyền xác thực (`auth_propagation_gaps`)**: `{len(matched_boundaries.get('auth_propagation_gaps', []))}`",
        f"- **Lệch ranh giới tin cậy (`trust_boundary_mismatches`)**: `{len(all_trust_mismatches)}`",
        "",
    ]
    for gap in matched_boundaries.get("auth_propagation_gaps", []):
        if isinstance(gap, dict):
            tech_md.append(
                f"- **`{gap.get('producer_repo')} -> {gap.get('consumer_repo')}`** (`{gap.get('normalized_target')}`): {gap.get('gap_reason')}"
            )
    for tm in all_trust_mismatches:
        if isinstance(tm, dict):
            tech_md.append(
                f"- **`[{tm.get('repo_name')}] {tm.get('title') or tm.get('mismatch_id')}`**: `{tm.get('consumer_path') or tm.get('path') or ''}` (Evidence: {', '.join(f'`{e}`' for e in (tm.get('evidence_ids') or []))})"
            )
    tech_md += [
        "",
        "## 2. Bản đồ Nguyên nhân Gốc (`06_root_cause_map.json`)",
        "",
    ]
    if root_causes_by_cluster:
        for rc_id, rc_info in root_causes_by_cluster.items():
            tech_md.append(
                f"- **`{rc_id}`** (Repo: `{rc_info['repo_name']}` | Findings: {', '.join(f'`{f}`' for f in rc_info['finding_ids'])}): "
                f"{rc_info['summary']} — **Khuyến nghị sửa đại diện**: {rc_info['representative_fix'] or '[UNSPECIFIED]'}"
            )
    else:
        tech_md.append("_Không có cụm nguyên nhân gốc nào được ghi nhận._")

    tech_md += [
        "",
        "## 3. Danh mục Lỗ hổng Đã Xác minh (`findings_consolidated.json`)",
        "",
        "| Mã (`F-xx`) | Chuỗi (`chain_id`) | Repo | Tiêu đề | Mức Kỹ thuật (`code_verified_severity`) | Mức Rủi ro Suy ra (`derived_risk_rating`) | Mức Rủi ro Cuối (`contextual_risk_rating`) | Trạng thái Xác minh | Bằng chứng (`ev_...`) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for f_item in consolidated_findings:
        ctx_disp = f_item["contextual_risk_rating"].upper()
        if f_item.get("risk_override_applied"):
            ctx_disp = f"{ctx_disp} (override từ {f_item['derived_risk_rating'].upper()})"
        tech_md.append(
            f"| `{f_item['finding_id']}` | `{f_item['chain_id']}` | `{f_item['repo_name']}` | {_md(f_item['title'], 100)} | "
            f"`{f_item['code_verified_severity'].upper()}` | `{f_item['derived_risk_rating'].upper()}` | **`{ctx_disp}`** | "
            f"`{f_item['verification_status']}` | {', '.join(f'`{e}`' for e in f_item['evidence_ids'][:4]) or '`[UNSPECIFIED]`'} |"
        )
    tech_md += [
        "",
        "## 4. Sổ cái Bác bỏ Thực nghiệm (`empirical_refutations_ledger`) & Phạm vi Chưa phủ",
        "",
        f"- **Tổng số ứng viên/chuỗi đã bác bỏ có phản chứng (`Refuted`)**: `{len(all_refutations)}`",
        f"- **Chuỗi giả thuyết cần kiểm chứng Runtime (`HYPOTHESIS_ONLY_UNVERIFIED`)**: `{len(all_hypotheses)}`",
        f"- **Chuỗi bị chặn do thiếu phản biện (`UNCHALLENGED_BLOCKED`)**: `{len(all_unchallenged)}`",
        f"- **Kết quả công cụ ngoài cấp dự án chưa gán được về repo (`unassigned_external_tool_findings`)**: `{len(unassigned_ext_file.get('findings', []))}`",
        "",
    ]
    tech_report_path = report_out_dir / "BAO_CAO_TONG_HOP_BAO_MAT.md"
    tech_report_path.write_text("\n".join(tech_md), encoding="utf-8")
    exported_files.append(str(tech_report_path))

    # DANH_GIA_RUI_RO.md
    risk_md = [
        "# BÁO CÁO ĐÁNH GIÁ RỦI RO NGỮ CẢNH 5 TRỤC S-F-O-P-C (PHASE 4)",
        "",
    ]
    if gate0_repos:
        risk_md += [
            "> [!CAUTION]",
            f"> **PHANH KHẨN CẤP GATE 0 / EMERGENCY BRAKE ĐANG KÍCH HOẠT** tại repo: `{', '.join(gate0_repos)}`. Phát hiện lỗ hổng chạm trục An toàn Vật lý (`an_toan_vat_ly: CRITICAL/CATASTROPHIC`). Yêu cầu dừng phát hành cho tới khi `safety_owner` ký duyệt khóa liên động vật lý.",
            "",
        ]
    risk_md += [
        "## 1. Bảng Ma trận Rủi ro Ngữ cảnh & Phân quyền Chịu trách nhiệm (`F-xx.json`)",
        "",
        "| Mã (`F-xx`) | Repo | Mức Suy ra (`derived_risk_rating`) | Mức Cuối (`contextual_risk_rating`) | Độ Khả thi (`feasibility_derived`) | Vai trò Chủ sở hữu (`owner_role`) | Risk Owner | Safety Owner | Phanh Gate 0 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for f_item in consolidated_findings:
        risk_md.append(
            f"| `{f_item['finding_id']}` | `{f_item['repo_name']}` | `{f_item['derived_risk_rating'].upper()}` | "
            f"**`{f_item['contextual_risk_rating'].upper()}`** | `{f_item['feasibility_derived']}` | "
            f"`{f_item['owner_role']}` | `{_md(f_item['risk_owner'], 60)}` | `{_md(f_item['safety_owner'], 60)}` | "
            f"`{'YES' if f_item['gate_0_emergency_brake'] else 'NO'}` |"
        )
    risk_md += [
        "",
        "## 2. Danh sách Câu hỏi Mở Có Trọng số (`key_questions.json`)",
        "",
    ]
    if all_key_questions:
        for q_obj in all_key_questions:
            risk_md.append(
                f"- **`[{q_obj.get('repo_name')}:{q_obj.get('question_id', 'KQ')}]`** (-> `{q_obj.get('target_team', 'security')}` | `{q_obj.get('status', 'pending')}`): "
                f"{q_obj.get('question', '')} "
                f"(Nếu CÓ: _{q_obj.get('outcome_if_yes', 'N/A')}_ | Nếu KHÔNG: _{q_obj.get('outcome_if_no', 'N/A')}_)"
            )
    else:
        risk_md.append("_Không có câu hỏi mở nào đang chờ phản hồi._")
    risk_md.append("")
    risk_report_path = report_out_dir / "DANH_GIA_RUI_RO.md"
    risk_report_path.write_text("\n".join(risk_md), encoding="utf-8")
    exported_files.append(str(risk_report_path))

    phase4_receipt = {
        "phase": "phase_4",
        "run_id": run_id,
        "gate_passed": not any_gate_failed and all(p["parity_verified"] for p in risk_parity_checks),
        "repos_exported": [r["repo_name"] for r in manifest_rows],
        "total_consolidated_findings": len(consolidated_findings),
        "risk_parity_verified": all(p["parity_verified"] for p in risk_parity_checks),
        "risk_parity_checks": risk_parity_checks,
        "exported_files_count": len(exported_files),
        "exported_files": exported_files,
        "reports_written": [str(manifest_path), str(tech_report_path), str(risk_report_path)],
    }
    write_json(runs_root / "_analysis" / "phase4_gate_receipt.json", phase4_receipt)
    return phase4_receipt


def finalize_v3_phase4(project_root: Path, run_id: str = "default") -> dict[str, Any]:
    """Alias for export_final_phase_inputs to match finalize_v3_phase1/2/3 CLI convention."""
    return export_final_phase_inputs(project_root, run_id=run_id)




