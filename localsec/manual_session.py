from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .config import load_config
from .orchestrator import (
    ACA_SPECIALIST_ORDER,
    BASV_SPECIALIST_ORDER,
    SPECIALIST_ORDER,
    _apply_audit,
    _compact,
    _iter_claims,
    _safe_name,
    _select_claims_for_audit,
    _select_cross_repo_evidence,
    build_blinded_chain_verifier_context,
    build_blinded_challenger_context,
    build_blinded_targeted_verifier_context,
    check_aca_convergence,
    execute_constrained_local_request,
)
from .prompts import system_prompt
from .reporting import (
    write_aca_analysis_documents,
    write_basv_repo_documents,
    write_basv_system_documents,
    write_cross_repo_documents,
    write_repo_documents,
)
from .validators import OutputValidationError, validate_agent_output
from .workspace import ManualWorkspace, write_json

DEFAULT_RUN_ID = "manual-v0.2"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_workspace(
    repo_name: str,
    cfg: dict[str, Any],
    run_id: str = DEFAULT_RUN_ID,
    allowed_read_paths: list[str] | None = None,
) -> tuple[ManualWorkspace, Path]:
    root = _project_root()
    if repo_name in {"_analysis", "_system"}:
        repo_path = root
        safe_name = repo_name
    else:
        repo_path = (root / repo_name).resolve(strict=True)
        safe_name = _safe_name(repo_name)
    ws = ManualWorkspace(
        repo_path,
        safe_name,
        cfg.get("analysis", {}),
        run_id,
        allowed_read_paths=allowed_read_paths,
        project_root=root,
    )
    run_dir = root / ".localsec" / "runs" / run_id / safe_name
    run_dir.mkdir(parents=True, exist_ok=True)
    state_file = run_dir / "workspace_state.json"
    if state_file.is_file():
        state = json.loads(state_file.read_text(encoding="utf-8"))
        ws.evidence = state.get("evidence", {})
        ws.tool_log = state.get("tool_log", [])
        ws.read_ranges = {
            k: [(int(r[0]), int(r[1])) for r in v]
            for k, v in state.get("read_ranges", {}).items()
        }
    return ws, run_dir


def _all_project_evidence_ids(root: Path, run_id: str = DEFAULT_RUN_ID) -> dict[str, dict[str, Any]]:
    run_root = root / ".localsec" / "runs" / run_id
    out: dict[str, dict[str, Any]] = {}
    if not run_root.is_dir():
        return out
    for child in sorted(run_root.iterdir()):
        if not child.is_dir():
            continue
        sf = child / "workspace_state.json"
        if sf.is_file():
            try:
                st = json.loads(sf.read_text(encoding="utf-8"))
                rname = st.get("repo_name", child.name)
                for eid, rec in st.get("evidence", {}).items():
                    if isinstance(rec, dict) and "repo_name" not in rec:
                        rec = {**rec, "repo_name": rname}
                    out[eid] = rec
            except Exception:
                pass
    return out


def _save_workspace(ws: ManualWorkspace, run_dir: Path) -> None:
    state_file = run_dir / "workspace_state.json"
    write_json(
        state_file,
        {
            "repo_name": ws.repo_name,
            "run_id": ws.run_id,
            "evidence": ws.evidence,
            "tool_log": ws.tool_log,
            "read_ranges": {k: [[s, e] for s, e in v] for k, v in ws.read_ranges.items()},
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m localsec.manual_session")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ls = sub.add_parser("list_dir", help="List directory via ManualWorkspace")
    p_ls.add_argument("repo_name")
    p_ls.add_argument("path", nargs="?", default=".")
    p_ls.add_argument("--depth", type=int, default=1)
    p_ls.add_argument("--offset", type=int, default=0)
    p_ls.add_argument("--limit", type=int, default=None)
    p_ls.add_argument("--skill", default="repo_profile")

    p_rf = sub.add_parser("read_file", help="Read file lines via ManualWorkspace and mint evidence_id")
    p_rf.add_argument("repo_name")
    p_rf.add_argument("path")
    p_rf.add_argument("start_line", nargs="?", type=int, default=1)
    p_rf.add_argument("end_line", nargs="?", type=int, default=180)
    p_rf.add_argument("--skill", default="repo_profile")
    p_rf.add_argument("--allowed-paths", default=None, help="Comma-separated exact_paths allow-list for targeted_verifier")

    p_ev = sub.add_parser("list_evidence", help="List all minted evidence_ids for a repo")
    p_ev.add_argument("repo_name")

    p_cl = sub.add_parser("extract_claims", help="Extract claims from the 5 specialist skills for evidence_auditor")
    p_cl.add_argument("repo_name")

    p_bcl = sub.add_parser("extract_basv_claims", help="Extract claims from BASV specialist skills for evidence_auditor")
    p_bcl.add_argument("repo_name")

    p_acl = sub.add_parser("extract_aca_claims", help="Extract claims from Phase 3 ACA specialist skills for evidence_auditor")
    p_acl.add_argument("repo_name", nargs="?", default="_analysis")

    p_bcv = sub.add_parser("prepare_blinded_chain_verifier", help="Prepare blinded context for chain_step_verifier or counterevidence_challenger")
    p_bcv.add_argument("chain_json")

    p_rplan = sub.add_parser("run_aca_request_plan", help="Execute constrained local request plan or mark not_executed fail-closed")
    p_rplan.add_argument("request_json")
    p_rplan.add_argument("--target-profile", default=None)

    p_afin = sub.add_parser("finalize_aca", help="Apply Phase 3 evidence audit and write ./documents/_analysis/")
    p_afin.add_argument("repo_name", nargs="?", default="_analysis")
    p_afin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_stat = sub.add_parser("phase_status", help="Show completed vs remaining steps and next required step for a phase")
    p_stat.add_argument("repo_name", nargs="?", default="_analysis")
    p_stat.add_argument("--phase", type=int, choices=[1, 2, 3], default=1)

    p_sub = sub.add_parser("submit_skill", help="Validate and save a skill JSON output for a repo")
    p_sub.add_argument("repo_name")
    p_sub.add_argument("skill")
    p_sub.add_argument("json_file")
    p_sub.add_argument("--artifact-id", default=None)

    p_fin = sub.add_parser("finalize_repo", help="Apply evidence audit and write ./documents/<repo_name>/")
    p_fin.add_argument("repo_name")
    p_fin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_bfin = sub.add_parser("finalize_basv_repo", help="Apply BASV evidence audit and write ./documents/<repo_name>/basv/")
    p_bfin.add_argument("repo_name")
    p_bfin.add_argument("--branch", default="prod")
    p_bfin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_bsys_fin = sub.add_parser("finalize_basv_system", help="Write system-wide BASV documents and 5-axis contradiction graph")
    p_bsys_fin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_sys_ctx = sub.add_parser("prepare_system_context", help="Prepare cross-repo context and Round-Robin evidence catalog")
    p_sys_ctx.add_argument("--out", default=f".localsec/runs/{DEFAULT_RUN_ID}/_system_context.json")

    p_sys_fin = sub.add_parser("finalize_system", help="Validate and write ./documents/_system/ and repo diagrams")
    p_sys_fin.add_argument("--cross-repo", required=True)
    p_sys_fin.add_argument("--sys-audit", required=True)
    p_sys_fin.add_argument("--diagrams", required=True)
    p_sys_fin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_vsem = sub.add_parser("verify_semantic_claims", help="Run deterministic Semantic Claim-to-Excerpt Verifier Gate on a repo or _analysis")
    p_vsem.add_argument("repo_name", nargs="?", default="_analysis")

    args = parser.parse_args(argv)
    root = _project_root()
    cfg = load_config(root / "localsec.toml")

    if args.cmd == "verify_semantic_claims":
        from .orchestrator import _resolve_path
        from .validators import verify_claim_to_excerpt_semantics

        ws, run_dir = _load_workspace(args.repo_name, cfg)
        catalog = _all_project_evidence_ids(root)
        catalog.update(ws.evidence)
        contradictions_found: list[dict[str, Any]] = []
        skill_candidates = SPECIALIST_ORDER + BASV_SPECIALIST_ORDER + ACA_SPECIALIST_ORDER + ["business_aware_synthesizer", "chain_synthesizer"]
        for skill in skill_candidates:
            sf = run_dir / f"{skill}.json"
            if not sf.is_file():
                continue
            entry = json.loads(sf.read_text(encoding="utf-8"))
            res_obj = entry.get("result") if isinstance(entry.get("result"), dict) else None
            if not isinstance(res_obj, dict):
                continue
            for claim in _iter_claims(res_obj, skill):
                target = _resolve_path(res_obj, claim["claim_ref"].split(":", 1)[1])
                if not isinstance(target, dict):
                    continue
                issues = verify_claim_to_excerpt_semantics(target, claim["cited_evidence_ids"], catalog)
                if issues:
                    contradictions_found.append(
                        {
                            "claim_ref": claim["claim_ref"],
                            "claim_status": claim["claim_status"],
                            "cited_evidence_ids": claim["cited_evidence_ids"],
                            "contradictions": issues,
                        }
                    )
        print(
            json.dumps(
                {
                    "repo_name": ws.repo_name,
                    "contradiction_count": len(contradictions_found),
                    "contradictions": contradictions_found,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if not contradictions_found else 2

    if args.cmd == "list_dir":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        res = ws.execute_tool(
            args.skill,
            "list_dir",
            {"path": args.path, "depth": args.depth, "offset": args.offset, "limit": args.limit},
        )
        ws.tool_log[-1]["skill"] = args.skill
        _save_workspace(ws, run_dir)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if args.cmd == "read_file":
        allowed = [p.strip() for p in args.allowed_paths.split(",") if p.strip()] if args.allowed_paths else None
        ws, run_dir = _load_workspace(args.repo_name, cfg, allowed_read_paths=allowed)
        res = ws.execute_tool(
            args.skill,
            "read_file",
            {"path": args.path, "start_line": args.start_line, "end_line": args.end_line},
        )
        ws.tool_log[-1]["skill"] = args.skill
        _save_workspace(ws, run_dir)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if args.cmd == "list_evidence":
        ws, _ = _load_workspace(args.repo_name, cfg)
        summary = [
            {
                "evidence_id": rec["evidence_id"],
                "repo_name": rec.get("repo_name", ws.repo_name),
                "path": rec["path"],
                "line_start": rec["line_start"],
                "line_end": rec["line_end"],
                "read_by": rec.get("read_by", []),
            }
            for rec in ws.evidence.values()
        ]
        print(json.dumps({"repo_name": ws.repo_name, "evidence_count": len(summary), "evidence": summary}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "extract_claims":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        all_claims: list[dict[str, Any]] = []
        for skill in SPECIALIST_ORDER:
            skill_file = run_dir / f"{skill}.json"
            if skill_file.is_file():
                entry = json.loads(skill_file.read_text(encoding="utf-8"))
                if entry.get("status") == "ok" and isinstance(entry.get("result"), dict):
                    all_claims.extend(_iter_claims(entry["result"], skill))
        batches, skipped = _select_claims_for_audit(all_claims, cfg)
        flattened_selected = [c for b in batches for c in b]
        print(
            json.dumps(
                {
                    "repo_name": ws.repo_name,
                    "total_actionable_claims": len(flattened_selected),
                    "claims_to_audit": flattened_selected,
                    "not_audited_due_to_budget": skipped,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.cmd == "extract_basv_claims":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        all_claims = []
        for skill in BASV_SPECIALIST_ORDER:
            skill_file = run_dir / f"{skill}.json"
            if skill_file.is_file():
                entry = json.loads(skill_file.read_text(encoding="utf-8"))
                if entry.get("status") == "ok" and isinstance(entry.get("result"), dict):
                    all_claims.extend(_iter_claims(entry["result"], skill))
        batches, skipped = _select_claims_for_audit(all_claims, cfg)
        flattened_selected = [c for b in batches for c in b]
        print(
            json.dumps(
                {
                    "repo_name": ws.repo_name,
                    "total_actionable_claims": len(flattened_selected),
                    "claims_to_audit": flattened_selected,
                    "not_audited_due_to_budget": skipped,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.cmd == "extract_aca_claims":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        all_claims = []
        aca_subdirs = {
            "code_trace_builder": "traces",
            "attack_chain_constructor": "chains",
            "chain_step_verifier": "verifications",
            "request_sequence_designer": "requests",
            "root_cause_mapper": "root_causes",
            "counterevidence_challenger": "challenges",
        }
        for skill in ACA_SPECIALIST_ORDER:
            subdir = aca_subdirs.get(skill)
            sub_files = sorted((run_dir / subdir).glob("*.json")) if subdir and (run_dir / subdir).is_dir() else []
            if sub_files:
                for sf in sub_files:
                    entry = json.loads(sf.read_text(encoding="utf-8"))
                    res_obj = entry.get("result") if isinstance(entry.get("result"), dict) else entry
                    if isinstance(res_obj, dict):
                        all_claims.extend(_iter_claims(res_obj, f"{skill}[{sf.stem}]"))
            else:
                skill_file = run_dir / f"{skill}.json"
                if skill_file.is_file():
                    entry = json.loads(skill_file.read_text(encoding="utf-8"))
                    if entry.get("status") == "ok" and isinstance(entry.get("result"), dict):
                        all_claims.extend(_iter_claims(entry["result"], skill))
        batches, skipped = _select_claims_for_audit(all_claims, cfg)
        flattened_selected = [c for b in batches for c in b]
        print(
            json.dumps(
                {
                    "repo_name": ws.repo_name,
                    "total_actionable_claims": len(flattened_selected),
                    "claims_to_audit": flattened_selected,
                    "not_audited_due_to_budget": skipped,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.cmd == "phase_status":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        if args.phase == 1:
            req_order = SPECIALIST_ORDER + ["evidence_auditor", "diagram_author"]
        elif args.phase == 2:
            req_order = BASV_SPECIALIST_ORDER + ["evidence_auditor", "business_aware_synthesizer"]
        else:
            req_order = [
                "finding_intake",
                "code_trace_builder",
                "attack_chain_constructor",
                "chain_step_verifier",
                "request_sequence_designer",
                "root_cause_mapper",
                "counterevidence_challenger",
                "aca_evidence_auditor",
                "chain_synthesizer",
            ]
        completed: list[str] = []
        remaining: list[str] = []
        for s in req_order:
            candidates = [run_dir / f"{s}.json"]
            if args.phase == 2 and s == "evidence_auditor":
                candidates.insert(0, run_dir / "basv_evidence_auditor.json")
            if args.phase == 3 and s == "aca_evidence_auditor":
                candidates.append(run_dir / "evidence_auditor.json")
            done = any(
                c.is_file() and json.loads(c.read_text(encoding="utf-8")).get("status") == "ok"
                for c in candidates
            )
            if done:
                completed.append(s)
            else:
                remaining.append(s)
        from .workspace import classify_source_authority_and_role
        distinct_files = {rec.get("path", "") for rec in ws.evidence.values() if isinstance(rec, dict) and rec.get("path")}
        prov_counts = {"intent_artifact": 0, "config_or_manifest": 0, "implementation_code": 0}
        role_counts = {"entrypoint_or_wiring": 0, "domain_service_or_sink": 0, "specification_or_contract": 0, "auxiliary_or_helper": 0}
        for fp in distinct_files:
            meta = classify_source_authority_and_role(str(fp))
            pk = meta["provenance_kind"]
            rl = meta["execution_role"]
            if pk in prov_counts:
                prov_counts[pk] += 1
            if rl in role_counts:
                role_counts[rl] += 1

        # 5-Domain Critical Business-Flow Control-Surface Matrix (file coverage != business-flow coverage)
        combined_text = " ".join(
            (str(rec.get("path", "")) + " " + str(rec.get("excerpt", ""))[:600]).lower()
            for rec in ws.evidence.values()
            if isinstance(rec, dict)
        )
        business_flow_surfaces = {
            "auth_boundary": any(k in combined_text for k in ("authorize", "jwt", "bearer", "token", "login", "authn", "middleware", "guard")),
            "tenant_or_object_boundary": any(k in combined_text for k in ("userid", "agentid", "owner", "tenant", "group", "bola", "idor", "permission", "role")),
            "value_or_money_movement": any(k in combined_text for k in ("loan", "commission", "voucher", "amount", "disburse", "limit", "collateral", "payment", "price")),
            "state_transition_and_maker_checker": any(k in combined_text for k in ("status", "state", "approve", "reject", "maker", "checker", "workflow", "transition")),
            "audit_trail_and_idempotency": any(k in combined_text for k in ("audit", "history", "log", "idempoten", "dedup", "unique", "transaction")),
        }
        adversarial_scenarios = {
            "replay": any(k in combined_text for k in ("replay", "nonce", "timestamp", "exp", "otp", "dedup", "idempoten")),
            "impersonation": any(k in combined_text for k in ("impersonat", "jwt", "claim", "sub", "userid", "agent_code", "token", "spoof")),
            "tenant_crossover": any(k in combined_text for k in ("tenant", "agentid", "branch", "showroom", "group", "owner", "bola", "idor")),
            "idempotency_abuse": any(k in combined_text for k in ("idempoten", "dedup", "by_pass_dedup", "duplicate", "race", "lock", "concurrent")),
            "state_desynchronization": any(k in combined_text for k in ("status", "state", "transition", "callback", "webhook", "sync", "etl", "cdc", "queue")),
            "audit_suppression": any(k in combined_text for k in ("audit", "history", "log", "trace", "track")),
            "partial_failure_or_retry_storm": any(k in combined_text for k in ("retry", "timeout", "rollback", "transaction", "catch", "fallback", "deadletter", "dlq")),
        }

        semantic_warnings: list[str] = []
        if args.phase in {1, 2} and len(distinct_files) < 3:
            semantic_warnings.append(
                f"Low semantic file coverage: only {len(distinct_files)} distinct file(s) read in workspace (< 3)."
            )
        if args.phase in {1, 2} and role_counts["entrypoint_or_wiring"] == 0 and role_counts["domain_service_or_sink"] == 0 and len(distinct_files) > 0:
            semantic_warnings.append(
                "Formally valid but contextually weak coverage: no entrypoint_or_wiring or domain_service_or_sink files read yet."
            )
        if args.phase == 2 and prov_counts["intent_artifact"] == 0 and "business_intent_modeler" in completed:
            semantic_warnings.append(
                "No intent_artifact files (.md/.docx/.xlsx/.sql/spec/test) recorded in local workspace evidence; verify cross-repo intent provenance."
            )
        print(
            json.dumps(
                {
                    "repo_name": ws.repo_name,
                    "phase": args.phase,
                    "completed_steps": completed,
                    "remaining_steps": remaining,
                    "next_required_step": remaining[0] if remaining else "FINALIZE_READY",
                    "ready_to_finalize": len(remaining) == 0,
                    "semantic_coverage_diagnostics": {
                        "distinct_files_read": len(distinct_files),
                        "provenance_breakdown": prov_counts,
                        "execution_role_breakdown": role_counts,
                        "business_flow_coverage_matrix": business_flow_surfaces,
                        "adversarial_scenario_coverage_matrix": adversarial_scenarios,
                        "semantic_warnings": semantic_warnings,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.cmd == "submit_skill":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        if args.skill == "business_aware_synthesizer":
            if not (run_dir / "basv_evidence_auditor.json").is_file() and not (run_dir / "evidence_auditor.json").is_file():
                print(
                    "PREREQUISITE_ERROR: cannot submit business_aware_synthesizer before evidence_auditor has completed.",
                    file=sys.stderr,
                )
                return 1
        if args.skill == "chain_synthesizer":
            if not (run_dir / "aca_evidence_auditor.json").is_file() and not (run_dir / "evidence_auditor.json").is_file():
                print(
                    "PREREQUISITE_ERROR: cannot submit chain_synthesizer before aca_evidence_auditor / evidence_auditor has completed.",
                    file=sys.stderr,
                )
                return 1
        payload = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
        project_ev_map = _all_project_evidence_ids(root)
        merged_catalog = dict(project_ev_map)
        merged_catalog.update(ws.evidence)
        valid_eids = set(merged_catalog.keys())
        try:
            validate_agent_output(args.skill, payload, valid_eids, evidence_catalog=merged_catalog)
        except OutputValidationError as exc:
            print(f"VALIDATION_ERROR ({args.skill}): {exc}", file=sys.stderr)
            return 1
        prompt_text, spec = system_prompt(args.skill)
        prompt_sha = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        payload_sha = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        skill_logs = [e for e in ws.tool_log if e.get("skill") == args.skill]
        dir_calls = len([e for e in skill_logs if e.get("tool") == "list_dir"])
        read_calls = len([e for e in skill_logs if e.get("tool") == "read_file"])
        envelope = {
            "skill": args.skill,
            "version": spec.get("version", "2.1.0"),
            "status": "ok",
            "result": payload,
            "tool_calls": dir_calls + read_calls,
            "dir_calls": dir_calls,
            "read_calls": read_calls,
            "model_turns": dir_calls + read_calls + 1,
            "validation_retries": 0,
            "evidence_ids_seen": sorted(ws.evidence.keys()),
            "evidence_ids_read_during_job": sorted(
                {e["evidence_id"] for e in skill_logs if e.get("tool") == "read_file" and "evidence_id" in e}
            ),
            "tool_trace": skill_logs,
            "system_prompt_sha256": prompt_sha,
            "initial_payload_sha256": payload_sha,
            "warnings": [],
        }
        out_name = "basv_evidence_auditor.json" if args.skill == "evidence_auditor" and (run_dir / "business_intent_modeler.json").is_file() and (run_dir / "evidence_auditor.json").is_file() else f"{args.skill}.json"
        write_json(run_dir / out_name, envelope)
        aca_id_field = {
            "code_trace_builder": ("traces", "trace_id", "trace"),
            "attack_chain_constructor": ("chains", "chain_id", "chain"),
            "chain_step_verifier": ("verifications", "verification_id", "verify"),
            "request_sequence_designer": ("requests", "request_sequence_id", "req"),
            "request_reproduction_operator": ("requests", "request_sequence_id", "req"),
            "root_cause_mapper": ("root_causes", "root_cause_id", "rc"),
            "counterevidence_challenger": ("challenges", "challenge_id", "chal"),
        }.get(args.skill)
        if aca_id_field and isinstance(payload, dict):
            subdir, id_key, prefix = aca_id_field
            art_id = _safe_name(str(args.artifact_id or payload.get(id_key) or payload.get("chain_id") or prefix))
            write_json(run_dir / subdir / f"{prefix}_{art_id}.json", envelope)
        print(f"OK: validated and saved {args.skill} ({out_name}) for {ws.repo_name} ({len(ws.evidence)} local / {len(valid_eids)} project evidence records)")
        return 0

    if args.cmd == "prepare_blinded_chain_verifier":
        chain_data = json.loads(Path(args.chain_json).read_text(encoding="utf-8"))
        if isinstance(chain_data.get("result"), dict):
            chain_data = chain_data["result"]
        blinded = build_blinded_chain_verifier_context(attack_chain=chain_data)
        print(json.dumps(blinded, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "run_aca_request_plan":
        req_data = json.loads(Path(args.request_json).read_text(encoding="utf-8"))
        if isinstance(req_data.get("result"), dict):
            req_data = req_data["result"]
        prof = json.loads(Path(args.target_profile).read_text(encoding="utf-8")) if args.target_profile else None
        res = execute_constrained_local_request(request_plan=req_data, target_profile=prof)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "finalize_aca":
        from .orchestrator import (
            _build_proof_obligation_and_challenge,
            _walk_evidence_ids,
            check_aca_convergence,
            evaluate_contextual_evidence_strength,
            manage_hypothesis_lifecycle,
        )

        ws, run_dir = _load_workspace(args.repo_name, cfg)
        ai_aca: dict[str, Any] = {}
        for skill in ACA_SPECIALIST_ORDER + ["aca_evidence_auditor", "evidence_auditor", "chain_synthesizer", "analysis_session"]:
            sf = run_dir / f"{skill}.json"
            if sf.is_file():
                ai_aca[skill] = json.loads(sf.read_text(encoding="utf-8"))
        aca_subdirs = {
            "code_trace_builder": "traces",
            "attack_chain_constructor": "chains",
            "chain_step_verifier": "verifications",
            "request_sequence_designer": "requests",
            "root_cause_mapper": "root_causes",
            "counterevidence_challenger": "challenges",
        }
        for skill, subdir in aca_subdirs.items():
            d = run_dir / subdir
            if d.is_dir():
                for sf in sorted(d.glob("*.json")):
                    ai_aca[f"{skill}[{sf.stem}]"] = json.loads(sf.read_text(encoding="utf-8"))
        auditor_env = ai_aca.get("aca_evidence_auditor") or ai_aca.get("evidence_auditor")
        required_aca = [
            "finding_intake",
            "code_trace_builder",
            "attack_chain_constructor",
            "chain_step_verifier",
            "request_sequence_designer",
            "root_cause_mapper",
            "counterevidence_challenger",
            "chain_synthesizer",
        ]
        missing = [s for s in required_aca if ai_aca.get(s, {}).get("status") != "ok"]
        if not auditor_env or auditor_env.get("status") != "ok":
            missing.append("aca_evidence_auditor")
        if missing:
            print(f"ERROR: cannot finalize Phase 3 ACA for {ws.repo_name}; missing required steps: {missing}", file=sys.stderr)
            return 1
        project_ev_map = _all_project_evidence_ids(root)
        merged_catalog = dict(project_ev_map)
        merged_catalog.update(ws.evidence)
        _apply_audit(ai_aca, auditor_env, evidence_catalog=merged_catalog)

        def _collect_aca_items(subdir: str, fallback_skill: str) -> list[dict[str, Any]]:
            items: list[dict[str, Any]] = []
            d = run_dir / subdir
            if d.is_dir():
                for f in sorted(d.glob("*.json")):
                    key = f"{fallback_skill}[{f.stem}]"
                    env = ai_aca.get(key) or json.loads(f.read_text(encoding="utf-8"))
                    items.append(env["result"] if isinstance(env.get("result"), dict) else env)
            if not items and isinstance(ai_aca.get(fallback_skill, {}).get("result"), dict):
                items.append(ai_aca[fallback_skill]["result"])
            return items

        session_res = ai_aca.get("analysis_session", {}).get("result") or {"schema_version": "1.0.0", "analysis_id": ws.run_id, "project_name": root.name}
        cand_res = ai_aca.get("finding_intake", {}).get("result") or {"candidate_claims": [], "chain_hypotheses": []}
        audit_res = (auditor_env or {}).get("result") or {}
        synth_res = ai_aca.get("chain_synthesizer", {}).get("result") or {}
        traces_list = _collect_aca_items("traces", "code_trace_builder")
        chains_list = _collect_aca_items("chains", "attack_chain_constructor")
        verifs_list = _collect_aca_items("verifications", "chain_step_verifier")
        reqs_list = _collect_aca_items("requests", "request_sequence_designer")
        rcs_list = _collect_aca_items("root_causes", "root_cause_mapper")
        chals_list = _collect_aca_items("challenges", "counterevidence_challenger")

        intake_eids = _walk_evidence_ids(cand_res)
        current_eids = set(intake_eids)
        for item_list in (traces_list, chains_list, verifs_list, reqs_list, rcs_list, chals_list):
            for it in item_list:
                current_eids.update(_walk_evidence_ids(it))
        prev_qs: list[str] = []
        for c_item in cand_res.get("candidates", []):
            if isinstance(c_item, dict):
                prev_qs.extend(str(q) for q in c_item.get("unresolved_questions", []))
        curr_qs = [str(q) for q in (synth_res.get("unverified_claims_and_gaps") or synth_res.get("unresolved_questions") or [])]
        verified_count = 0
        for vf in verifs_list:
            for sr in vf.get("step_results", []):
                if isinstance(sr, dict) and sr.get("result") in {"confirmed_by_source", "confirmed_by_observation"}:
                    verified_count += 1
            for er in vf.get("edge_results", []):
                if isinstance(er, dict) and er.get("status") in {"confirmed_by_source", "confirmed_by_observation"}:
                    verified_count += 1
        conv_diag = check_aca_convergence(
            traces=traces_list,
            previous_evidence_ids=intake_eids,
            current_evidence_ids=current_eids,
            previous_unresolved_questions=prev_qs,
            current_unresolved_questions=curr_qs,
            previous_verified_steps_or_edges=0,
            current_verified_steps_or_edges=verified_count,
            evidence_catalog=merged_catalog,
        )

        verdict_breakdown: dict[str, int] = {}
        exec_breakdown: dict[str, int] = {}
        chain_profiles: list[dict[str, Any]] = []
        for ch in chains_list:
            cv = str(ch.get("chain_verdict", "unknown"))
            es = str(ch.get("execution_status", "unknown"))
            verdict_breakdown[cv] = verdict_breakdown.get(cv, 0) + 1
            exec_breakdown[es] = exec_breakdown.get(es, 0) + 1
            ch_eids = sorted(_walk_evidence_ids(ch))
            cs = evaluate_contextual_evidence_strength(ch_eids, merged_catalog)
            po, bcl = _build_proof_obligation_and_challenge(ch, "attack_chain_constructor")
            chain_profiles.append(
                {
                    "chain_id": ch.get("chain_id"),
                    "title": ch.get("title"),
                    "chain_verdict": cv,
                    "execution_status": es,
                    "scope_repositories": ch.get("scope", {}).get("repositories", []),
                    "step_count": len(ch.get("steps", [])),
                    "cited_evidence_count": len(ch_eids),
                    "contextual_evidence_strength": cs,
                    "proof_obligation": po,
                    "bounded_challenge_loop": bcl,
                }
            )

        out_dir_name = args.output_dir or cfg.get("analysis", {}).get("output_dir", "documents")
        output_root = (root / out_dir_name).resolve()

        # Cross-phase hypothesis lifecycle closure from Phase 2 BASV into Phase 3 ACA
        raw_hypotheses: list[dict[str, Any]] = []
        for diag19 in sorted(output_root.glob("*/basv/19_basv_epistemic_and_contradiction_diagnostics.json")):
            try:
                d19 = json.loads(diag19.read_text(encoding="utf-8"))
                hl_prev = d19.get("cross_phase_hypothesis_lifecycle", {})
                raw_hypotheses.extend(hl_prev.get("active_hypotheses", []))
                raw_hypotheses.extend(hl_prev.get("archived_hypotheses", []))
            except Exception:
                pass
        chain_repos = {str(r) for ch in chains_list for r in ch.get("scope", {}).get("repositories", [])}
        hl_phase3_raw = manage_hypothesis_lifecycle(
            raw_hypotheses,
            current_round=3,
            max_stagnant_rounds=2,
            new_evidence_ids=current_eids,
            new_evidence_repos=chain_repos,
        )
        hl_phase3 = {
            "total_raw_leads": len(raw_hypotheses),
            "promoted_to_chains_count": sum(len(ch.get("originating_finding_ids", [])) for ch in chains_list),
            "active_count": len(hl_phase3_raw.get("active_hypotheses", [])),
            "reactivated_count": len(hl_phase3_raw.get("reactivated_hypotheses", [])),
            "archived_count": len(hl_phase3_raw.get("archived_hypotheses", [])),
            "active_hypotheses": hl_phase3_raw.get("active_hypotheses", [])[:25],
            "archived_hypotheses": hl_phase3_raw.get("archived_hypotheses", [])[:25],
            "reactivated_hypotheses": hl_phase3_raw.get("reactivated_hypotheses", [])[:25],
        }

        total_hops = sum(len(t.get("hops", [])) for t in traces_list)
        epistemic_diagnostics = {
            "pipeline_version": "2.4.0-refute-first",
            "analysis_id": session_res.get("analysis_id", ws.run_id),
            "project_name": session_res.get("project_name", root.name),
            "total_candidates": len(cand_res.get("candidates", [])),
            "total_traces": len(traces_list),
            "total_trace_hops": total_hops,
            "total_chains": len(chains_list),
            "chain_verdict_breakdown": verdict_breakdown,
            "execution_status_breakdown": exec_breakdown,
            "total_root_causes": len(rcs_list),
            "total_challenges": len(chals_list),
            "convergence_governor": conv_diag,
            "chain_epistemic_profiles": chain_profiles,
            "cross_phase_hypothesis_lifecycle": hl_phase3,
        }

        write_aca_analysis_documents(
            output_root / "_analysis",
            session=session_res,
            candidate_claims=cand_res,
            traces=traces_list,
            chains=chains_list,
            verifications=verifs_list,
            request_plans=reqs_list,
            root_causes=rcs_list,
            challenges=chals_list,
            evidence_audit=audit_res,
            synthesis_report=synth_res,
            evidence_catalog=merged_catalog,
            epistemic_diagnostics=epistemic_diagnostics,
        )
        print(f"FINALIZED_ACA: {output_root / '_analysis'} ({len(chains_list)} chains, {len(traces_list)} traces, {len(rcs_list)} root causes)")
        return 0

    if args.cmd == "finalize_repo":
        from .workspace import _extract_git_metadata, enrich_evidence_record

        ws, run_dir = _load_workspace(args.repo_name, cfg)
        ai: dict[str, Any] = {}
        for skill in SPECIALIST_ORDER + ["evidence_auditor", "diagram_author"]:
            sf = run_dir / f"{skill}.json"
            if sf.is_file():
                ai[skill] = json.loads(sf.read_text(encoding="utf-8"))
        missing = [s for s in SPECIALIST_ORDER + ["evidence_auditor", "diagram_author"] if ai.get(s, {}).get("status") != "ok"]
        if missing:
            print(f"ERROR: cannot finalize {ws.repo_name}; missing skills: {missing}", file=sys.stderr)
            return 1
        _apply_audit(ai, ai["evidence_auditor"], evidence_catalog=ws.evidence)

        # Enrich all evidence records with v2.4 provenance, authority_verified_by, execution_role, git freshness, feature flags, and dead-code check
        enriched_evidence_map: dict[str, dict[str, Any]] = {}
        for eid, rec in ws.evidence.items():
            if isinstance(rec, dict):
                enriched_evidence_map[eid] = enrich_evidence_record(rec, ws.root, project_root=root)
        ws.evidence = enriched_evidence_map
        _save_workspace(ws, run_dir)

        distinct_files = {rec.get("path", "") for rec in ws.evidence.values() if isinstance(rec, dict) and rec.get("path")}
        prov_counts = {"intent_artifact": 0, "config_or_manifest": 0, "implementation_code": 0}
        role_counts = {"entrypoint_or_wiring": 0, "domain_service_or_sink": 0, "specification_or_contract": 0, "auxiliary_or_helper": 0}
        auth_ver_counts: dict[str, int] = {}
        feature_flags_detected: set[str] = set()
        for rec in ws.evidence.values():
            for ff in rec.get("feature_flag_refs") or []:
                feature_flags_detected.add(str(ff))
        seen_paths: set[str] = set()
        for rec in ws.evidence.values():
            fp = str(rec.get("path", ""))
            if not fp or fp in seen_paths:
                continue
            seen_paths.add(fp)
            pk = str(rec.get("provenance_kind", ""))
            rl = str(rec.get("execution_role", ""))
            av = str(rec.get("authority_verified_by", "unknown"))
            if pk in prov_counts:
                prov_counts[pk] += 1
            if rl in role_counts:
                role_counts[rl] += 1
            auth_ver_counts[av] = auth_ver_counts.get(av, 0) + 1

        combined_text = " ".join(
            (str(rec.get("path", "")) + " " + str(rec.get("excerpt", ""))[:600]).lower()
            for rec in ws.evidence.values()
        )
        business_flow_surfaces = {
            "auth_boundary": any(k in combined_text for k in ("authorize", "jwt", "bearer", "token", "login", "authn", "middleware", "guard")),
            "tenant_or_object_boundary": any(k in combined_text for k in ("userid", "agentid", "owner", "tenant", "group", "bola", "idor", "permission", "role")),
            "value_or_money_movement": any(k in combined_text for k in ("loan", "commission", "voucher", "amount", "disburse", "limit", "collateral", "payment", "price")),
            "state_transition_and_maker_checker": any(k in combined_text for k in ("status", "state", "approve", "reject", "maker", "checker", "workflow", "transition")),
            "audit_trail_and_idempotency": any(k in combined_text for k in ("audit", "history", "log", "idempoten", "dedup", "unique", "transaction")),
        }
        adversarial_scenarios = {
            "replay": any(k in combined_text for k in ("replay", "nonce", "timestamp", "exp", "otp", "dedup", "idempoten")),
            "impersonation": any(k in combined_text for k in ("impersonat", "jwt", "claim", "sub", "userid", "agent_code", "token", "spoof")),
            "tenant_crossover": any(k in combined_text for k in ("tenant", "agentid", "branch", "showroom", "group", "owner", "bola", "idor")),
            "idempotency_abuse": any(k in combined_text for k in ("idempoten", "dedup", "by_pass_dedup", "duplicate", "race", "lock", "concurrent")),
            "state_desynchronization": any(k in combined_text for k in ("status", "state", "transition", "callback", "webhook", "sync", "etl", "cdc", "queue")),
            "audit_suppression": any(k in combined_text for k in ("audit", "history", "log", "trace", "track")),
            "partial_failure_or_retry_storm": any(k in combined_text for k in ("retry", "timeout", "rollback", "transaction", "catch", "fallback", "deadletter", "dlq")),
        }
        semantic_warnings: list[str] = []
        if len(distinct_files) < 3:
            semantic_warnings.append(f"Low semantic file coverage: only {len(distinct_files)} distinct file(s) read in workspace (< 3).")
        if role_counts["entrypoint_or_wiring"] == 0 and role_counts["domain_service_or_sink"] == 0 and len(distinct_files) > 0:
            semantic_warnings.append("Formally valid but contextually weak coverage: no entrypoint_or_wiring or domain_service_or_sink files read yet.")

        git_meta = _extract_git_metadata(ws.root)
        coverage = ws.coverage()
        coverage["pipeline_version"] = "2.4.0-refute-first"
        coverage["git_deployment_freshness"] = {
            "git_branch": git_meta["branch"],
            "git_commit_sha": git_meta["commit_sha"],
            "git_release_tag": git_meta["release_tag"],
            "feature_flags_detected": sorted(feature_flags_detected),
        }
        coverage["semantic_coverage_diagnostics"] = {
            "distinct_files_read": len(distinct_files),
            "provenance_breakdown": prov_counts,
            "execution_role_breakdown": role_counts,
            "authority_verified_by_breakdown": auth_ver_counts,
            "business_flow_coverage_matrix": business_flow_surfaces,
            "adversarial_scenario_coverage_matrix": adversarial_scenarios,
            "semantic_warnings": semantic_warnings,
        }
        coverage["skills"] = {
            name: {
                "status": item.get("status"),
                "tool_calls": item.get("tool_calls"),
                "dir_calls": item.get("dir_calls", 0),
                "read_calls": item.get("read_calls", 0),
                "model_turns": item.get("model_turns"),
                "warnings": item.get("warnings", []),
            }
            for name, item in ai.items()
        }
        coverage["budget_exhaustions"] = [
            f"{name}: {warning}"
            for name, item in ai.items()
            for warning in item.get("warnings", [])
            if "budget_exhausted" in warning
        ]
        coverage["workflow_status"] = "completed"
        coverage["security_posture"] = "undetermined_by_design"
        coverage["important_limitations"] = [
            "AI chose which paths and line ranges to read; unvisited code may contain relevant behavior.",
            "No AST/IR, parser, grep, SAST, compiler, shell or runtime analysis was used.",
            "Evidence auditing is an independent AI critique, not formal proof.",
            "Deployment, gateway, IAM, runtime service discovery and external contracts may be outside this repo.",
        ]
        repo_result = {
            "repo_name": ws.repo_name,
            "run_id": ws.run_id,
            "pipeline_version": "2.4.0-refute-first",
            "ai": ai,
            "coverage": coverage,
            "evidence": list(ws.evidence.values()),
            "workspace_tool_log": ws.tool_log,
        }
        out_dir_name = args.output_dir or cfg.get("analysis", {}).get("output_dir", "documents")
        output_root = (root / out_dir_name).resolve()
        write_repo_documents(output_root / ws.repo_name, run_dir, repo_result)
        write_json(run_dir / "evidence_index.json", list(ws.evidence.values()))
        write_json(run_dir / "coverage.json", coverage)
        write_json(run_dir / "workspace_tool_log.json", ws.tool_log)
        write_json(run_dir / "repo_result.json", repo_result)
        print(f"FINALIZED: {ws.repo_name} -> {output_root / ws.repo_name}")
        return 0

    if args.cmd == "finalize_basv_repo":
        ws, run_dir = _load_workspace(args.repo_name, cfg)
        ai_basv: dict[str, Any] = {}
        for skill in BASV_SPECIALIST_ORDER + ["business_aware_synthesizer"]:
            sf = run_dir / f"{skill}.json"
            if sf.is_file():
                ai_basv[skill] = json.loads(sf.read_text(encoding="utf-8"))
        auditor_file = run_dir / "basv_evidence_auditor.json"
        if not auditor_file.is_file():
            auditor_file = run_dir / "evidence_auditor.json"
        if auditor_file.is_file():
            ai_basv["evidence_auditor"] = json.loads(auditor_file.read_text(encoding="utf-8"))
        required_basv = [
            "business_intent_modeler",
            "business_invariant_challenger",
            "implementation_trace_verifier",
            "intent_implementation_comparator",
            "security_consequence_mapper",
            "evidence_auditor",
            "business_aware_synthesizer",
        ]
        missing = [s for s in required_basv if ai_basv.get(s, {}).get("status") != "ok"]
        if missing:
            print(f"ERROR: cannot finalize BASV for {ws.repo_name}; missing skills: {missing}", file=sys.stderr)
            return 1
        all_eids = _all_project_evidence_ids(root)
        all_eids.update(ws.evidence)
        _apply_audit(ai_basv, ai_basv["evidence_auditor"], evidence_catalog=all_eids)
        git_branch = "unknown"
        head_file = ws.root / ".git" / "HEAD"
        if head_file.is_file():
            head_txt = head_file.read_text(encoding="utf-8", errors="replace").strip()
            git_branch = head_txt.split("refs/heads/", 1)[1] if head_txt.startswith("ref: refs/heads/") else head_txt[:12]

        out_dir_name = args.output_dir or cfg.get("analysis", {}).get("output_dir", "documents")
        output_root = (root / out_dir_name).resolve()

        # Load Phase 1 hypotheses if available for cross-phase lifecycle tracking
        phase1_hyps: list[dict[str, Any]] = []
        p1_diag_file = output_root / ws.repo_name / "15_epistemic_and_semantic_diagnostics.json"
        if p1_diag_file.is_file():
            try:
                p1_diag = json.loads(p1_diag_file.read_text(encoding="utf-8"))
                hl = p1_diag.get("hypothesis_lifecycle", {})
                phase1_hyps = list(hl.get("active_hypotheses", [])) + list(hl.get("archived_hypotheses", []))
            except Exception:
                pass

        repo_result_basv = {
            "repo_name": ws.repo_name,
            "run_id": ws.run_id,
            "git_branch": git_branch,
            "is_prod_branch": git_branch == "prod",
            "ai": ai_basv,
            "basv_ai": ai_basv,
            "coverage": ws.coverage(),
            "evidence": list(all_eids.values()),
            "workspace_tool_log": ws.tool_log,
            "phase1_hypotheses": phase1_hyps,
        }
        write_basv_repo_documents(output_root / ws.repo_name, run_dir, repo_result_basv)
        diag_19 = output_root / ws.repo_name / "basv" / "19_basv_epistemic_and_contradiction_diagnostics.json"
        if diag_19.is_file():
            try:
                repo_result_basv["epistemic_diagnostics"] = json.loads(diag_19.read_text(encoding="utf-8"))
            except Exception:
                pass
        write_json(run_dir / "basv_repo_result.json", repo_result_basv)
        print(f"FINALIZED_BASV: {ws.repo_name} (branch={git_branch}) -> {output_root / ws.repo_name / 'basv'}")
        return 0

    if args.cmd == "finalize_basv_system":
        run_root = root / ".localsec" / "runs" / DEFAULT_RUN_ID
        repo_basv_results: list[dict[str, Any]] = []
        for child in sorted(run_root.iterdir()):
            if child.is_dir() and (child / "basv_repo_result.json").is_file():
                rbr = json.loads((child / "basv_repo_result.json").read_text(encoding="utf-8"))
                repo_basv_results.append(rbr)
        all_eids = _all_project_evidence_ids(root)
        old_basv_sys = root / "documents" / "_system" / "basv"
        interconnections = []
        if (old_basv_sys / "01_service_interconnection_matrix.json").is_file():
            interconnections = json.loads(
                (old_basv_sys / "01_service_interconnection_matrix.json").read_text(encoding="utf-8")
            ).get("inter_service_connections", [])
        sys_syn = {}
        if (old_basv_sys / "03_system_business_aware_synthesis.json").is_file():
            sys_syn = json.loads(
                (old_basv_sys / "03_system_business_aware_synthesis.json").read_text(encoding="utf-8")
            )
        sys_aud = {}
        if (old_basv_sys / "04_system_basv_evidence_audit.json").is_file():
            sys_aud = json.loads(
                (old_basv_sys / "04_system_basv_evidence_audit.json").read_text(encoding="utf-8")
            )
        topo_mmd = None
        if (old_basv_sys / "diagrams" / "service_interconnection_topology.mmd").is_file():
            topo_mmd = (old_basv_sys / "diagrams" / "service_interconnection_topology.mmd").read_text(encoding="utf-8")

        out_dir_name = args.output_dir or cfg.get("analysis", {}).get("output_dir", "documents")
        output_root = (root / out_dir_name).resolve()
        write_basv_system_documents(
            output_root / "_system",
            sys_syn,
            sys_aud,
            repo_basv_results,
            interconnections=interconnections,
            topology_mermaid=topo_mmd,
            evidence_catalog=all_eids,
        )
        print(f"BASV SYSTEM FINALIZED: {output_root / '_system' / 'basv'} across {len(repo_basv_results)} repositories")
        return 0

    if args.cmd == "prepare_system_context":
        run_root = root / ".localsec" / "runs" / DEFAULT_RUN_ID
        repo_results: list[dict[str, Any]] = []
        sys_evidence: dict[str, dict[str, Any]] = {}
        for child in sorted(run_root.iterdir()):
            if child.is_dir() and (child / "repo_result.json").is_file():
                rr = json.loads((child / "repo_result.json").read_text(encoding="utf-8"))
                repo_results.append(rr)
                for rec in rr.get("evidence", []):
                    sys_evidence[rec["evidence_id"]] = rec
        sys_catalog = _select_cross_repo_evidence(repo_results, sys_evidence, cfg)
        system_context_base = {
            "repositories": [
                {
                    "repo_name": r["repo_name"],
                    "coverage": {
                        "workflow_status": r["coverage"].get("workflow_status"),
                        "unique_files_read_count": len(r["coverage"].get("unique_files_read", [])),
                        "evidence_count": r["coverage"].get("evidence_count", 0),
                    },
                    "profile": r["ai"].get("repo_profile", {}).get("result"),
                    "api_authz": r["ai"].get("api_authz", {}).get("result"),
                    "dataflow": r["ai"].get("dataflow", {}).get("result"),
                    "threat_model": r["ai"].get("threat_model", {}).get("result"),
                    "architecture_review": r["ai"].get("architecture_review", {}).get("result"),
                }
                for r in repo_results
            ],
            "coverage_note": "Each repo was reviewed by model-guided, manually selected file reads. Treat unvisited files and non-repository config as unknown.",
        }
        out_path = root / args.out
        write_json(
            out_path,
            {
                "repo_count": len(repo_results),
                "total_system_evidence": len(sys_evidence),
                "selected_cross_repo_evidence_count": len(sys_catalog),
                "system_review_input": _compact(system_context_base),
                "available_evidence": sys_catalog,
                "all_valid_evidence_ids": sorted(sys_evidence.keys()),
            },
        )
        print(f"Prepared system context for {len(repo_results)} repos ({len(sys_evidence)} total evidence records, {len(sys_catalog)} Round-Robin selected) -> {out_path}")
        return 0

    if args.cmd == "finalize_system":
        run_root = root / ".localsec" / "runs" / DEFAULT_RUN_ID
        repo_results = []
        sys_evidence: dict[str, dict[str, Any]] = {}
        for child in sorted(run_root.iterdir()):
            if child.is_dir() and (child / "repo_result.json").is_file():
                rr = json.loads((child / "repo_result.json").read_text(encoding="utf-8"))
                repo_results.append(rr)
                for rec in rr.get("evidence", []):
                    sys_evidence[rec["evidence_id"]] = rec
        valid_eids = set(sys_evidence.keys())
        cross_payload = json.loads(Path(args.cross_repo).read_text(encoding="utf-8"))
        audit_payload = json.loads(Path(args.sys_audit).read_text(encoding="utf-8"))
        diag_payload = json.loads(Path(args.diagrams).read_text(encoding="utf-8"))
        if not diag_payload.get("repo_diagrams"):
            merged_repo_diags = []
            for rr in repo_results:
                d_res = rr.get("ai", {}).get("diagram_author", {}).get("result", {})
                for item in d_res.get("repo_diagrams", []):
                    if item.get("repo_name") == rr["repo_name"]:
                        merged_repo_diags.append(item)
            diag_payload["repo_diagrams"] = merged_repo_diags

        validate_agent_output("cross_repo_review", cross_payload, valid_eids)
        validate_agent_output("evidence_auditor", audit_payload, valid_eids)
        validate_agent_output("diagram_author", diag_payload, valid_eids)

        cross_env = {"skill": "cross_repo_review", "version": "2.1.0", "status": "ok", "result": cross_payload, "tool_calls": 0, "dir_calls": 0, "read_calls": 0, "model_turns": 1, "warnings": []}
        audit_env = {"skill": "evidence_auditor", "version": "2.1.0", "status": "ok", "result": audit_payload, "tool_calls": 0, "dir_calls": 0, "read_calls": 0, "model_turns": 1, "warnings": []}
        diag_env = {"skill": "diagram_author", "version": "2.1.0", "status": "ok", "result": diag_payload, "tool_calls": 0, "dir_calls": 0, "read_calls": 0, "model_turns": 1, "warnings": []}

        temp = {"cross_repo_review": cross_env}
        _apply_audit(temp, audit_env)
        cross_env = temp["cross_repo_review"]

        out_dir_name = args.output_dir or cfg.get("analysis", {}).get("output_dir", "documents")
        output_root = (root / out_dir_name).resolve()
        write_cross_repo_documents(output_root / "_system", cross_env, audit_env, diag_env, repo_results)
        sys_catalog = _select_cross_repo_evidence(repo_results, sys_evidence, cfg)
        write_json(run_root / "cross_repo_review.json", cross_env)
        write_json(run_root / "cross_repo_evidence_audit.json", audit_env)
        write_json(run_root / "diagrams.json", diag_env)
        write_json(run_root / "system_evidence_index.json", sys_catalog)

        bf_totals = {
            "auth_boundary": 0,
            "tenant_or_object_boundary": 0,
            "value_or_money_movement": 0,
            "state_transition_and_maker_checker": 0,
            "audit_trail_and_idempotency": 0,
        }
        adv_totals = {
            "replay": 0,
            "impersonation": 0,
            "tenant_crossover": 0,
            "idempotency_abuse": 0,
            "state_desynchronization": 0,
            "audit_suppression": 0,
            "partial_failure_or_retry_storm": 0,
        }
        repos_with_warnings = []
        for r in repo_results:
            sem = r.get("coverage", {}).get("semantic_coverage_diagnostics", {})
            for k, v in (sem.get("business_flow_coverage_matrix") or {}).items():
                if v and k in bf_totals:
                    bf_totals[k] += 1
            for k, v in (sem.get("adversarial_scenario_coverage_matrix") or {}).items():
                if v and k in adv_totals:
                    adv_totals[k] += 1
            if sem.get("semantic_warnings"):
                repos_with_warnings.append(
                    {"repo_name": r["repo_name"], "warnings": sem["semantic_warnings"]}
                )

        system_coverage = {
            "run_id": DEFAULT_RUN_ID,
            "pipeline_version": "2.4.0-refute-first",
            "analysis_mode": "ai_manual_file_reading",
            "workflow_status": "completed",
            "coverage_status": "bounded_manual_review",
            "security_posture": "undetermined_by_design",
            "exhaustive_repository_scan": False,
            "llm": {"model": "antigravity-localsec-v2.4-manual-agent", "endpoint_kind": "antigravity_direct_skill_execution"},
            "system_semantic_and_adversarial_rollup": {
                "total_repositories": len(repo_results),
                "total_evidence_records": len(sys_evidence),
                "round_robin_selected_cross_repo_evidence": len(sys_catalog),
                "repos_covering_business_flow_surface": bf_totals,
                "repos_covering_adversarial_scenario": adv_totals,
                "repos_with_semantic_warnings": repos_with_warnings,
            },
            "repos": [
                {
                    "repo_name": r["repo_name"],
                    "workflow_status": r["coverage"]["workflow_status"],
                    "unique_files_read": len(r["coverage"]["unique_files_read"]),
                    "evidence_count": r["coverage"]["evidence_count"],
                    "git_deployment_freshness": r["coverage"].get("git_deployment_freshness", {}),
                    "semantic_coverage_diagnostics": r["coverage"].get("semantic_coverage_diagnostics", {}),
                    "skill_status": {k: v.get("status") for k, v in r["ai"].items()},
                }
                for r in repo_results
            ],
            "cross_repo_review_status": "ok",
            "cross_repo_evidence_audit_status": "ok",
            "diagram_author_status": "ok",
            "limitations": [
                "The AI-selected file reads are not exhaustive.",
                "No static analysis tools, AST/IR parsing, shell commands, builds, or runtime tests were used.",
                "A completed workflow is not a security clearance or confirmation that there are no vulnerabilities.",
            ],
        }
        write_json(output_root / "_system" / "04_system_coverage.json", system_coverage)
        write_json(run_root / "system_coverage.json", system_coverage)
        print(f"SYSTEM FINALIZED: {output_root / '_system'} across {len(repo_results)} repositories")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
