from __future__ import annotations

import argparse
import hashlib
import json
import os
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

DEFAULT_RUN_ID = "default"


def _toolkit_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _project_root() -> Path:
    env_root = os.environ.get("LOCALSEC_PROJECT_ROOT")
    if env_root:
        return Path(env_root).expanduser().resolve()
    toolkit = _toolkit_root()
    cwd = Path.cwd().resolve()
    # When cloned into a target project (e.g. <Project-Root>/AI-skills) and executed from <Project-Root>,
    # resolve project_root to <Project-Root> while keeping schemas/contracts/config inside the toolkit folder.
    if toolkit.parent == cwd:
        return cwd
    if cwd != toolkit and ((cwd / ".agents").is_dir() or (cwd / ".claude").is_dir()):
        return cwd
    if toolkit.name.lower() in {"ai-skills", "localsec-antigravity-skills"} and cwd != toolkit:
        return toolkit.parent
    return toolkit


def _resolve_config_path(project_root: Path) -> Path | None:
    for candidate in (project_root / "localsec.toml", _toolkit_root() / "localsec.toml"):
        if candidate.is_file():
            return candidate
    return None


def _resolve_run_id(
    root: Path,
    cfg: dict[str, Any] | None = None,
    explicit_run_id: str | None = None,
    repo_name: str | None = None,
) -> str:
    if explicit_run_id:
        return str(explicit_run_id)
    if repo_name:
        safe_r = (
            repo_name
            if repo_name in {"_analysis", "_system"}
            else (_safe_name(root.name) if repo_name == "." else _safe_name(repo_name))
        )
        for cand_r in (repo_name, safe_r):
            if (root / ".localsec" / "runs" / "default" / cand_r).exists():
                return "default"
        for cand_r in (repo_name, safe_r):
            if (root / ".localsec" / "runs" / "manual-v0.2" / cand_r).exists():
                return "manual-v0.2"
    if (root / ".localsec" / "runs" / "default").exists():
        return "default"
    if (root / ".localsec" / "runs" / "manual-v0.2").exists():
        return "manual-v0.2"
    cfg_default = (cfg or {}).get("analysis", {}).get("default_run_id")
    return str(cfg_default) if cfg_default else DEFAULT_RUN_ID


def _load_workspace(
    repo_name: str,
    cfg: dict[str, Any],
    run_id: str | None = None,
    allowed_read_paths: list[str] | None = None,
) -> tuple[ManualWorkspace, Path]:
    root = _project_root()
    if repo_name in {"_analysis", "_system"}:
        repo_path = root
        safe_name = repo_name
    elif repo_name == "." or (repo_name == root.name and not (root / repo_name).exists()):
        repo_path = root
        safe_name = _safe_name(root.name)
    else:
        repo_path = (root / repo_name).resolve(strict=True)
        safe_name = _safe_name(repo_name)
    effective_run_id = _resolve_run_id(root, cfg, explicit_run_id=run_id, repo_name=safe_name)
    analysis_cfg = dict(cfg.get("analysis", {}))
    ignored = list(analysis_cfg.get("ignored_dirs", []))
    extra_ignores = [
        _toolkit_root().name,
        ".agents",
        ".claude",
        ".localsec",
        str(analysis_cfg.get("output_dir", "documents")),
    ]
    bridge_init = root / "localsec" / "__init__.py"
    if bridge_init.is_file() and "AI-SKILLS-BRIDGE" in bridge_init.read_text(encoding="utf-8", errors="ignore"):
        extra_ignores.append("localsec")
    for extra_ignore in extra_ignores:
        if extra_ignore and extra_ignore not in ignored:
            ignored.append(extra_ignore)
    analysis_cfg["ignored_dirs"] = ignored
    ws = ManualWorkspace(
        repo_path,
        safe_name,
        analysis_cfg,
        effective_run_id,
        allowed_read_paths=allowed_read_paths,
        project_root=root,
    )
    run_dir = root / ".localsec" / "runs" / effective_run_id / safe_name
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
        ws.deferred_out_of_budget = list(state.get("deferred_out_of_budget", []))
        setattr(ws, "_blinded_allowed_paths", state.get("blinded_allowed_paths"))
    return ws, run_dir


def _all_project_evidence_ids(root: Path, run_id: str | None = None) -> dict[str, dict[str, Any]]:
    effective_run_id = _resolve_run_id(root, explicit_run_id=run_id)
    run_root = root / ".localsec" / "runs" / effective_run_id
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
                    out.setdefault(eid, rec)
            except Exception:
                pass
    return out


def _save_workspace(ws: ManualWorkspace, run_dir: Path) -> None:
    state_file = run_dir / "workspace_state.json"
    existing_blinded = getattr(ws, "_blinded_allowed_paths", None)
    if existing_blinded is None and state_file.is_file():
        try:
            existing_blinded = json.loads(state_file.read_text(encoding="utf-8")).get("blinded_allowed_paths")
        except Exception:
            existing_blinded = None
    payload: dict[str, Any] = {
        "repo_name": ws.repo_name,
        "run_id": ws.run_id,
        "evidence": ws.evidence,
        "tool_log": ws.tool_log,
        "read_ranges": {k: [[s, e] for k, v_list in [(k, v)] for s, e in v_list] for k, v in ws.read_ranges.items()},
        "deferred_out_of_budget": list(getattr(ws, "deferred_out_of_budget", [])),
    }
    if existing_blinded is not None:
        payload["blinded_allowed_paths"] = existing_blinded
    write_json(state_file, payload)


def _resolve_json_arg(raw_path: str, root: Path) -> Path:
    cand = Path(raw_path)
    if cand.is_file():
        return cand
    rel_cand = root / raw_path
    if rel_cand.is_file():
        return rel_cand
    norm = raw_path.replace("\\", "/")
    if norm.startswith("/tmp/"):
        fallback = root / ".localsec" / "tmp" / norm[5:]
        if fallback.is_file():
            return fallback
    return cand


def main(argv: list[str] | None = None) -> int:
    # BUG-08: Reconfigure stdout/stderr to UTF-8 on Windows to prevent cp1252 UnicodeEncodeError on Vietnamese text.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and getattr(stream, "encoding", "").lower() != "utf-8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    parser = argparse.ArgumentParser(prog="python -m localsec.manual_session")
    parser.add_argument("--project-root", default=None, help="Optional project root override")
    parser.add_argument("--run-id", default=None, help="Optional run ID override (default: 'default')")
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
    p_rf.add_argument("--start-line", dest="opt_start_line", type=int, default=None)
    p_rf.add_argument("--end-line", dest="opt_end_line", type=int, default=None)
    p_rf.add_argument("--skill", default="repo_profile")
    p_rf.add_argument(
        "--allowed-paths",
        nargs="+",
        default=None,
        help="Comma- or space-separated exact_paths allow-list for targeted_verifier",
    )

    p_sev = sub.add_parser("show_evidence", help="DEPTH-4.5: Show cached evidence excerpt by evidence_id without re-reading disk")
    p_sev.add_argument("repo_name")
    p_sev.add_argument("evidence_id")
    p_sev.add_argument("--start-line", type=int, default=None)
    p_sev.add_argument("--end-line", type=int, default=None)

    p_ev = sub.add_parser("list_evidence", help="List all minted evidence_ids for a repo")
    p_ev.add_argument("repo_name")

    p_cl = sub.add_parser("extract_claims", help="Extract claims from the 5 specialist skills for evidence_auditor")
    p_cl.add_argument("repo_name")

    p_bcl = sub.add_parser("extract_basv_claims", help="Extract claims from BASV specialist skills for evidence_auditor")
    p_bcl.add_argument("repo_name")

    p_acl = sub.add_parser("extract_aca_claims", help="Extract claims from Phase 3 ACA specialist skills for evidence_auditor")
    p_acl.add_argument("repo_name", nargs="?", default="_analysis")

    p_pbc = sub.add_parser("prepare_blinded_challenger", help="Prepare blinded context for Phase 2 business_invariant_challenger")
    p_pbc.add_argument("repo_name")

    p_pbtv = sub.add_parser("prepare_blinded_targeted_verifier", help="Prepare blinded context for Phase 2 targeted_verifier")
    p_pbtv.add_argument("repo_name")
    p_pbtv.add_argument("--task-id", default=None)

    p_bcv = sub.add_parser("prepare_blinded_chain_verifier", help="Prepare blinded context for chain_step_verifier, counterevidence_challenger, or blinded_counterevidence_challenger")
    p_bcv.add_argument("chain_json", nargs="?", default="_analysis")

    p_rplan = sub.add_parser("run_aca_request_plan", help="Execute constrained local request plan or mark not_executed fail-closed")
    p_rplan.add_argument("request_json")
    p_rplan.add_argument("--target-profile", default=None)

    p_afin = sub.add_parser("finalize_aca", help="Apply Phase 3 evidence audit and write ./documents/_analysis/")
    p_afin.add_argument("repo_name", nargs="?", default="_analysis")
    p_afin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_stat = sub.add_parser("phase_status", help="Show completed vs remaining steps and next required step for a phase")
    p_stat.add_argument("repo_name", nargs="?", default="_analysis")
    p_stat.add_argument("--phase", type=int, choices=[1, 2, 3, 4], default=1)
    p_stat.add_argument("--flow", choices=["v3", "v2"], default=None, help="Pipeline flow version (default: v3 unless v2 artifacts detected)")

    p_sub = sub.add_parser("submit_skill", help="Validate and save a skill JSON output for a repo")
    p_sub.add_argument("repo_name")
    p_sub.add_argument("skill")
    p_sub.add_argument("json_file", nargs="?", default=None)
    p_sub.add_argument("--input-file", dest="input_file", default=None, help="Optional alias for positional json_file")
    p_sub.add_argument("--artifact-id", default=None)

    p_fin = sub.add_parser("finalize_repo", help="Apply evidence audit and write ./documents/<repo_name>/")
    p_fin.add_argument("repo_name")
    p_fin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_bfin = sub.add_parser("finalize_basv_repo", help="Apply BASV evidence audit and write ./documents/<repo_name>/basv/")
    p_bfin.add_argument("repo_name")
    p_bfin.add_argument("--branch", default="prod")
    p_bfin.add_argument("--output-dir", default=None, help="Override output directory (e.g., documents_phase1_v2)")

    p_bsys_fin = sub.add_parser("finalize_basv_system", help="Write system-wide BASV documents and 5-axis contradiction graph")
    p_bsys_fin.add_argument("--synthesis", default=None, help="Optional path to system business_aware_synthesizer JSON")
    p_bsys_fin.add_argument("--sys-audit", default=None, help="Optional path to system BASV evidence_auditor JSON")
    p_bsys_fin.add_argument("--interconnections", default=None, help="Optional path to service interconnection matrix JSON")
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

    p_inv = sub.add_parser("inventory_repo", help="ARCH-3C: Deterministic pre-scout file tree, mandatory surface, secret lead, and dependency inventory")
    p_inv.add_argument("repo_name")
    p_inv.add_argument("--tier", default=None, help="Optional operator-assigned tier (1, 2, 3)")

    p_sac = sub.add_parser("select_attack_companions", help="Select verbatim Attack-Class Companion blocks for a repo based on scouted archetypes/techstack")
    p_sac.add_argument("repo_name")
    p_sac.add_argument("--techstack", nargs="*", default=[])
    p_sac.add_argument("--archetypes", nargs="*", default=[])
    p_sac.add_argument("--signals", nargs="*", default=[])
    p_sac.add_argument("--candidate-classes", nargs="*", default=[])

    p_rsm = sub.add_parser("register_scout_map", help="Validate and save Phase 1.1 codebase_scout output (Target Modules Map & Repo Tier)")
    p_rsm.add_argument("repo_name")
    p_rsm.add_argument("json_file")

    p_rte = sub.add_parser("run_tailored_extractor", help="Phase 1.2: Run standard or AI-tailored structural extractor verified on canary files first")
    p_rte.add_argument("repo_name")
    p_rte.add_argument("--mode", choices=["USE_STANDARD_EXTRACTOR", "TAILOR_CUSTOM_EXTRACTOR", "SKIP_EXTRACTOR_DIRECT_READ"], default="USE_STANDARD_EXTRACTOR")
    p_rte.add_argument("--canary-files", nargs="*", default=[])
    p_rte.add_argument("--patterns-file", default=None, help="Optional JSON file containing custom extractor regex patterns")
    p_rte.add_argument("--expected-canary-hits", type=int, default=1)
    p_rte.add_argument("--target-modules", nargs="*", default=None)

    p_avis = sub.add_parser("audit_visibility", help="Phase 1.6: Run physical Visibility Tracker and Coverage Ledger gate")
    p_avis.add_argument("repo_name")

    p_avist = sub.add_parser("audit_visibility_tracker", help="Phase 1.6: Alias for audit_visibility")
    p_avist.add_argument("repo_name")

    p_gcm = sub.add_parser("generate_coverage_matrix", help="DEPTH-4.3a: Generate deterministic coverage_matrix.json for a repo")
    p_gcm.add_argument("repo_name")

    p_bcq = sub.add_parser("build_v3_candidate_queue", help="ARCH-3G: Collect all 7 candidate sources into candidate_queue.json")
    p_bcq.add_argument("repo_name")

    p_mcb = sub.add_parser("match_cross_repo_boundaries", help="DEPTH-4.1f: Match cross-repo outbound producers and inbound consumers")

    p_fp1 = sub.add_parser("finalize_v3_phase1", help="ARCH-3D: Finalize v3 Phase 1 and emit phase1_gate_Certificate.json")
    p_fp1.add_argument("repo_name")

    p_fp2 = sub.add_parser("finalize_v3_phase2", help="ARCH-3D: Finalize v3 Phase 2, reconcile challenger verdicts, and emit phase2_gate_Certificate.json")
    p_fp2.add_argument("repo_name")

    p_fp3 = sub.add_parser("finalize_v3_phase3", help="ARCH-3D: Finalize v3 Phase 3, audit beyond-code controls & SFOP hard laws, and emit phase3_gate_Certificate.json")
    p_fp3.add_argument("repo_name")

    p_fp4 = sub.add_parser("finalize_v3_phase4", help="Phase 4: Export canonical documents/ tree, risk work files, and synthesize final reports")
    p_fp4.add_argument("repo_name", nargs="?", default=None)
    p_fp4.add_argument("--force-overwrite", action="store_true", help="Allow overwriting existing non-wins files in documents/")

    p_efpi = sub.add_parser("export_final_phase_inputs", help="Phase 4: Export v3 run outputs into canonical documents/ layout and synthesize final reports")
    p_efpi.add_argument("repo_name", nargs="?", default=None)
    p_efpi.add_argument("--force-overwrite", action="store_true", help="Allow overwriting existing non-wins files in documents/")

    p_irf = sub.add_parser("ingest_runtime_facts", help="DEPTH-4.4a: Ingest operator-supplied runtime_environment_facts.json")
    p_irf.add_argument("repo_name")
    p_irf.add_argument("facts_json")

    p_rv3 = sub.add_parser("render_v3_report", help="ARCH-3I: Render the 3 v3 audience-tailored Markdown deliverables")
    p_rv3.add_argument("repo_name", nargs="?", default=None)

    p_rv3s = sub.add_parser("render_v3_reports", help="ARCH-3I: Alias for render_v3_report")
    p_rv3s.add_argument("repo_name", nargs="?", default=None)

    p_dpr = sub.add_parser("diff_prior_run", help="Incremental delta-recon: reopen coverage_ledger records affected by changed files")
    p_dpr.add_argument("repo_name")
    p_dpr.add_argument("--changed-files", nargs="+", required=True)
    p_dpr.add_argument("--prior-ledger", default=None)

    args = parser.parse_args(argv)
    if args.project_root:
        os.environ["LOCALSEC_PROJECT_ROOT"] = str(Path(args.project_root).expanduser().resolve())
    root = _project_root()
    (root / ".localsec" / "tmp").mkdir(parents=True, exist_ok=True)
    cfg = load_config(_resolve_config_path(root))
    if args.run_id:
        cfg.setdefault("analysis", {})["default_run_id"] = args.run_id

    def _effective_v3_run_id(repo_name: str | None = None) -> str:
        return _resolve_run_id(root, cfg, explicit_run_id=args.run_id, repo_name=repo_name)

    if args.cmd == "inventory_repo":
        from .orchestrator import inventory_repo

        eff_run = _effective_v3_run_id(args.repo_name)
        res = inventory_repo(root, args.repo_name, run_id=eff_run, operator_tier=args.tier)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "show_evidence":
        ws, _ = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        try:
            res = ws.show_evidence(
                repo_name=ws.repo_name,
                evidence_id=args.evidence_id,
                start_line=args.start_line,
                end_line=args.end_line,
            )
            print(json.dumps({"ok": True, "result": res}, ensure_ascii=False, indent=2))
            return 0
        except Exception as exc:
            print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False, indent=2))
            return 1

    if args.cmd == "select_attack_companions":
        from .prompts import select_companion_blocks

        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        scout_file = run_dir / "codebase_scout.json"
        archetypes = list(args.archetypes or [])
        techstack = list(args.techstack or [])
        signals = list(args.signals or [])
        cand_classes = list(getattr(args, "candidate_classes", None) or [])
        if scout_file.is_file():
            sdata = json.loads(scout_file.read_text(encoding="utf-8"))
            sres = sdata.get("result") if isinstance(sdata.get("result"), dict) else sdata
            archetypes.extend(str(x) for x in sres.get("product_archetypes", []))
            archetypes.extend(str(x) for x in sres.get("detected_archetypes", []))
            conv = sres.get("coding_conventions", {})
            if isinstance(conv, dict):
                for v in conv.values():
                    if isinstance(v, str):
                        signals.append(v)
                    elif isinstance(v, list):
                        signals.extend(str(i) for i in v)
        selected = select_companion_blocks(
            techstack=techstack,
            archetypes=archetypes,
            signals=signals,
            candidate_classes=cand_classes,
            run_dir=run_dir,
        )
        write_json(run_dir / "selected_attack_companions.json", selected)
        print(json.dumps(selected, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "register_scout_map":
        from .orchestrator import validate_scout_map_against_inventory

        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        payload = json.loads(_resolve_json_arg(args.json_file, root).read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("result"), dict) and "status" in payload:
            payload = payload["result"]
        valid_eids = set(ws.evidence.keys()) | set(_all_project_evidence_ids(root, run_id=ws.run_id).keys())
        validate_agent_output("codebase_scout", payload, valid_eids, evidence_catalog=ws.evidence)
        inv_data = None
        if (run_dir / "inventory_repo.json").is_file():
            inv_data = json.loads((run_dir / "inventory_repo.json").read_text(encoding="utf-8"))
        inv_check = validate_scout_map_against_inventory(payload, inv_data)
        if not inv_check.get("valid", True):
            print(
                f"VALIDATION_ERROR (codebase_scout vs inventory_repo): unaccounted_mandatory_directories={inv_check.get('unaccounted_mandatory_directories')}, invalid_ignored_modules={inv_check.get('invalid_ignored_modules')}",
                file=sys.stderr,
            )
            return 1
        env = {"skill": "codebase_scout", "version": "3.0.0", "status": "ok", "result": payload, "inventory_validation": inv_check}
        write_json(run_dir / "codebase_scout.json", env)
        print(f"OK: registered codebase_scout map for {ws.repo_name} (tier={payload.get('repo_tier')}, target_modules={len(payload.get('target_modules', []))})")
        return 0

    if args.cmd == "run_tailored_extractor":
        from .orchestrator import run_tailored_extractor_safely

        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        res = run_tailored_extractor_safely(
            repo_root=ws.root,
            mode=args.mode,
            canary_files=args.canary_files,
            patterns_file=args.patterns_file,
            expected_canary_hits=args.expected_canary_hits,
            target_modules=args.target_modules,
            run_dir=run_dir,
        )
        write_json(run_dir / "extractor_tailor.json", {"skill": "extractor_tailor", "version": "3.0.0", "status": "ok" if res.get("canary_verified") else "failed_canary", "result": res})
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("canary_verified") else 2

    if args.cmd in {"audit_visibility", "audit_visibility_tracker"}:
        from .orchestrator import audit_visibility_and_coverage

        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        scout_map = None
        if (run_dir / "codebase_scout.json").is_file():
            raw_s = json.loads((run_dir / "codebase_scout.json").read_text(encoding="utf-8"))
            scout_map = raw_s.get("result") if isinstance(raw_s.get("result"), dict) else raw_s
        cov_ledger = None
        if (run_dir / "coverage_ledger.json").is_file():
            raw_c = json.loads((run_dir / "coverage_ledger.json").read_text(encoding="utf-8"))
            cov_ledger = raw_c.get("result") if isinstance(raw_c.get("result"), dict) else raw_c
        inv_data = None
        if (run_dir / "inventory_repo.json").is_file():
            inv_data = json.loads((run_dir / "inventory_repo.json").read_text(encoding="utf-8"))
        surf_data = None
        if (run_dir / "unified_surface_mapper.json").is_file():
            surf_data = json.loads((run_dir / "unified_surface_mapper.json").read_text(encoding="utf-8"))
        report = audit_visibility_and_coverage(
            workspace=ws,
            scout_map=scout_map,
            coverage_ledger=cov_ledger,
            inventory=inv_data,
            surface_map=surf_data,
        )
        write_json(run_dir / "visibility_audit.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report.get("gate_passed") else 2

    if args.cmd == "generate_coverage_matrix":
        from .orchestrator import generate_coverage_matrix

        _, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        res = generate_coverage_matrix(run_dir, args.repo_name)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "build_v3_candidate_queue":
        from .orchestrator import build_v3_candidate_queue

        _, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        res = build_v3_candidate_queue(run_dir, args.repo_name)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "match_cross_repo_boundaries":
        from .orchestrator import match_cross_repo_boundaries

        eff_run = _effective_v3_run_id()
        res = match_cross_repo_boundaries(root, run_id=eff_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "finalize_v3_phase1":
        from .orchestrator import finalize_v3_phase1

        eff_run = _effective_v3_run_id(args.repo_name)
        res = finalize_v3_phase1(root, args.repo_name, run_id=eff_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("gate_passed") else 2

    if args.cmd == "finalize_v3_phase2":
        from .orchestrator import finalize_v3_phase2

        eff_run = _effective_v3_run_id(args.repo_name)
        res = finalize_v3_phase2(root, args.repo_name, run_id=eff_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("gate_passed") else 2

    if args.cmd == "finalize_v3_phase3":
        from .orchestrator import finalize_v3_phase3

        eff_run = _effective_v3_run_id(args.repo_name)
        res = finalize_v3_phase3(root, args.repo_name, run_id=eff_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("gate_passed") else 2

    if args.cmd in {"finalize_v3_phase4", "export_final_phase_inputs"}:
        from .reporting import export_final_phase_inputs

        eff_run = _effective_v3_run_id(getattr(args, "repo_name", None))
        res = export_final_phase_inputs(
            root,
            run_id=eff_run,
            force_overwrite=bool(getattr(args, "force_overwrite", False)),
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("gate_passed") else 2

    if args.cmd == "ingest_runtime_facts":
        from .orchestrator import ingest_runtime_facts

        eff_run = _effective_v3_run_id(args.repo_name)
        facts_file = _resolve_json_arg(args.facts_json, root)
        res = ingest_runtime_facts(root, args.repo_name, facts_file, run_id=eff_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd in {"render_v3_report", "render_v3_reports"}:
        from .reporting import render_v3_reports

        eff_run = _effective_v3_run_id(args.repo_name)
        res = render_v3_reports(root, repo_name=args.repo_name, run_id=eff_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "diff_prior_run":
        from .orchestrator import diff_prior_run

        ws, run_dir = _load_workspace(args.repo_name, cfg)
        scout_map = {}
        if (run_dir / "codebase_scout.json").is_file():
            raw_s = json.loads((run_dir / "codebase_scout.json").read_text(encoding="utf-8"))
            scout_map = raw_s.get("result") if isinstance(raw_s.get("result"), dict) else raw_s
        ledger_path = _resolve_json_arg(args.prior_ledger, root) if args.prior_ledger else (run_dir / "coverage_ledger.json")
        prior_ledger = json.loads(ledger_path.read_text(encoding="utf-8")) if ledger_path.is_file() else {"records": [], "semantic_clusters": []}
        if isinstance(prior_ledger.get("result"), dict):
            prior_ledger = prior_ledger["result"]
        diff_res = diff_prior_run(current_scout_map=scout_map, prior_coverage_ledger=prior_ledger, changed_files=args.changed_files)
        print(json.dumps(diff_res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "verify_semantic_claims":
        from .orchestrator import _resolve_path
        from .validators import verify_claim_to_excerpt_semantics

        ws, run_dir = _load_workspace(args.repo_name, cfg)
        catalog = _all_project_evidence_ids(root)
        catalog.update(ws.evidence)
        contradictions_found: list[dict[str, Any]] = []
        v3_skills = [
            "codebase_scout",
            "extractor_tailor",
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
        ]
        skill_candidates = (
            SPECIALIST_ORDER
            + BASV_SPECIALIST_ORDER
            + ACA_SPECIALIST_ORDER
            + ["business_aware_synthesizer", "chain_synthesizer"]
            + v3_skills
        )
        for skill in skill_candidates:
            sf = run_dir / f"{skill}.json"
            if not sf.is_file():
                continue
            entry = json.loads(sf.read_text(encoding="utf-8"))
            res_obj = entry.get("result") if isinstance(entry.get("result"), dict) else entry
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
            # BUG-02: Also verify v3 list items containing evidence_ids directly
            for v3_list_key in ("anomalies", "intent_vs_code_gaps", "verified_chains", "calibrated_findings", "trust_boundary_mismatches"):
                v3_items = res_obj.get(v3_list_key)
                if isinstance(v3_items, list):
                    for idx, item in enumerate(v3_items):
                        if isinstance(item, dict) and isinstance(item.get("evidence_ids"), list) and item["evidence_ids"]:
                            eids = [str(e) for e in item["evidence_ids"] if str(e).startswith("ev_")]
                            if eids:
                                issues = verify_claim_to_excerpt_semantics(item, eids, catalog)
                                if issues:
                                    contradictions_found.append(
                                        {
                                            "claim_ref": f"{skill}:{v3_list_key}[{idx}]",
                                            "claim_status": str(item.get("status", "confirmed")),
                                            "cited_evidence_ids": eids,
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
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        res = ws.execute_tool(
            args.skill,
            "list_dir",
            {"path": args.path, "depth": args.depth, "offset": args.offset, "limit": args.limit},
        )
        if ws.tool_log:
            ws.tool_log[-1]["skill"] = args.skill
        _save_workspace(ws, run_dir)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if args.cmd == "read_file":
        allowed = (
            [p.strip() for token in args.allowed_paths for p in token.split(",") if p.strip()]
            if args.allowed_paths
            else None
        )
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id, allowed_read_paths=allowed)
        if allowed is None and args.skill == "blinded_counterevidence_challenger":
            persisted_allowed = getattr(ws, "_blinded_allowed_paths", None)
            if not persisted_allowed:
                tmp_blinded = root / ".localsec" / "tmp" / f"blinded_chains_{_safe_name(args.repo_name)}.json"
                if tmp_blinded.is_file():
                    try:
                        persisted_allowed = json.loads(tmp_blinded.read_text(encoding="utf-8")).get("exact_paths")
                    except Exception:
                        persisted_allowed = None
            if isinstance(persisted_allowed, list) and persisted_allowed:
                ws.allowed_read_paths = {
                    str(p).replace("\\", "/").lstrip("./")
                    for p in persisted_allowed
                    if str(p).strip()
                }
        s_line = args.opt_start_line if args.opt_start_line is not None else args.start_line
        e_line = args.opt_end_line if args.opt_end_line is not None else args.end_line
        res = ws.execute_tool(
            args.skill,
            "read_file",
            {"path": args.path, "start_line": s_line, "end_line": e_line},
        )
        if ws.tool_log:
            ws.tool_log[-1]["skill"] = args.skill
        _save_workspace(ws, run_dir)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if args.cmd == "list_evidence":
        ws, _ = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
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
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
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
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
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
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
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
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        v2_indicators = ("repo_profile.json", "business_intent_modeler.json", "finding_intake.json", "attack_chain_constructor.json")
        v3_indicators = ("codebase_scout.json", "inventory_repo.json", "intent_invariant_modeler.json", "unified_surface_mapper.json", "deep_trace_chain_analyst.json", "sfop_risk_calibrator.json")
        if args.flow in {"v3", "v2"}:
            active_flow = args.flow
        elif any((run_dir / f).is_file() for f in v2_indicators) and not any((run_dir / f).is_file() for f in v3_indicators):
            active_flow = "v2"
        else:
            active_flow = "v3"

        if active_flow == "v3":
            from .prompts import load_v3_orchestration

            v3_orch = load_v3_orchestration()
            phase_spec = v3_orch.get("phases", {}).get(str(args.phase), {})
            req_order = list(
                phase_spec.get("ordered_steps")
                or phase_spec.get("order")
                or (
                    [
                        "codebase_scout",
                        "intent_invariant_modeler",
                        "extractor_tailor",
                        "unified_surface_mapper",
                        "cross_repo_and_arch_review",
                        "coverage_and_evidence_auditor",
                    ]
                    if args.phase == 1
                    else [
                        "candidate_intake_planner",
                        "deep_trace_chain_analyst",
                        "blinded_counterevidence_challenger",
                        "analysis_evidence_gate",
                    ]
                    if args.phase == 2
                    else [
                        "actor_and_feasibility_assessor",
                        "beyond_code_control_mapper",
                        "sfop_risk_calibrator",
                    ]
                )
            )
        else:
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
            if active_flow == "v3" and s == "cross_repo_and_arch_review":
                candidates.append(run_dir.parent / "_analysis" / "cross_repo_and_arch_review.json")
            if active_flow == "v2" and args.phase == 2 and s == "evidence_auditor":
                candidates.insert(0, run_dir / "basv_evidence_auditor.json")
            if active_flow == "v2" and args.phase == 3 and s == "aca_evidence_auditor":
                candidates.append(run_dir / "evidence_auditor.json")
            done = False
            for c in candidates:
                if c.is_file():
                    try:
                        c_data = json.loads(c.read_text(encoding="utf-8"))
                        if c_data.get("status", "ok") == "ok":
                            done = True
                            break
                    except Exception:
                        pass
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
                    "run_id": ws.run_id,
                    "run_dir": str(run_dir),
                    "flow": active_flow,
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
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
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
        raw_json_arg = args.json_file or getattr(args, "input_file", None)
        if not raw_json_arg:
            print("ERROR: submit_skill requires json_file (positional or --input-file).", file=sys.stderr)
            return 1
        payload = json.loads(_resolve_json_arg(raw_json_arg, root).read_text(encoding="utf-8"))
        from .validators import V30_SKILLS
        if args.skill in V30_SKILLS and isinstance(payload, dict) and isinstance(payload.get("result"), dict) and "status" in payload:
            payload = payload["result"]
        project_ev_map = _all_project_evidence_ids(root, run_id=ws.run_id)
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

    if args.cmd == "prepare_blinded_challenger":
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)

        def _unwrap_skill(skill_name: str) -> dict[str, Any]:
            sf = run_dir / f"{skill_name}.json"
            if not sf.is_file():
                return {}
            data = json.loads(sf.read_text(encoding="utf-8"))
            return data["result"] if isinstance(data.get("result"), dict) else data

        blinded = build_blinded_challenger_context(
            intent_model=_unwrap_skill("business_intent_modeler"),
            repo_profile=_unwrap_skill("repo_profile"),
            api_authz=_unwrap_skill("api_authz"),
            dataflow=_unwrap_skill("dataflow"),
            coverage=ws.coverage(),
        )
        print(json.dumps(blinded, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "prepare_blinded_targeted_verifier":
        ws, run_dir = _load_workspace(args.repo_name, cfg, run_id=args.run_id)
        planner_path = run_dir / "verification_planner.json"
        if not planner_path.is_file():
            print(f"MISSING_PREREQUISITE: verification_planner.json not found in {run_dir}", file=sys.stderr)
            return 1
        planner_raw = json.loads(planner_path.read_text(encoding="utf-8"))
        planner = planner_raw["result"] if isinstance(planner_raw.get("result"), dict) else planner_raw
        intent_path = run_dir / "business_intent_modeler.json"
        inv_map: dict[str, str] = {}
        if intent_path.is_file():
            intent_raw = json.loads(intent_path.read_text(encoding="utf-8"))
            intent = intent_raw["result"] if isinstance(intent_raw.get("result"), dict) else intent_raw
            for inv in intent.get("business_invariants", []):
                if isinstance(inv, dict) and inv.get("id"):
                    inv_map[str(inv["id"])] = str(inv.get("expected_behavior") or inv.get("statement") or "")
        tasks = [t for t in planner.get("verification_tasks", []) if isinstance(t, dict)]
        if args.task_id:
            tasks = [t for t in tasks if str(t.get("task_id")) == args.task_id]
        blinded_tasks = [
            build_blinded_targeted_verifier_context(
                task=t,
                related_invariant_expected_behavior=inv_map.get(str(t.get("related_invariant_id", "")), ""),
            )
            for t in tasks
        ]
        if args.task_id and len(blinded_tasks) == 1:
            print(json.dumps(blinded_tasks[0], ensure_ascii=False, indent=2))
        else:
            print(
                json.dumps(
                    {
                        "repo_name": ws.repo_name,
                        "context_blinding_policy": (
                            "comparison_result, security_impact, exploitability, and "
                            "previous_agent_recommended_conclusion are strictly excluded"
                        ),
                        "blinded_tasks": blinded_tasks,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        return 0

    if args.cmd == "prepare_blinded_chain_verifier":
        allowed_chain_keys = {
            "chain_id",
            "candidate_ids",
            "entrypoint",
            "actor",
        }
        allowed_hop_keys = {
            "hop_id",
            "hop_kind",
            "repo_name",
            "file",
            "path",
            "function_or_symbol",
            "line_start",
            "line_end",
        }

        def _blind_v3_deep_trace(
            dt_payload: dict[str, Any],
            repo_label: str,
            target_run_dir: Path | None = None,
        ) -> dict[str, Any]:
            exact_paths_set: set[str] = set()
            blinded_v3_chains: list[dict[str, Any]] = []
            raw_chains = dt_payload.get("chains") if isinstance(dt_payload.get("chains"), list) else dt_payload.get("verified_chains", [])
            for ch in raw_chains:
                if not isinstance(ch, dict):
                    continue
                if ch.get("path"):
                    exact_paths_set.add(str(ch["path"]).strip())
                if ch.get("file"):
                    exact_paths_set.add(str(ch["file"]).strip())
                clean_ch: dict[str, Any] = {}
                for k in allowed_chain_keys:
                    if k in ch:
                        clean_ch[k] = ch[k]
                if "candidate_ids" not in clean_ch and isinstance(ch.get("source_candidate_ids"), list):
                    clean_ch["candidate_ids"] = ch["source_candidate_ids"]
                clean_hops: list[dict[str, Any]] = []
                for hp in ch.get("hops", []):
                    if isinstance(hp, dict):
                        clean_hp = {k: v for k, v in hp.items() if k in allowed_hop_keys}
                        hpath = str(clean_hp.get("path") or clean_hp.get("file") or "").strip()
                        if hpath:
                            exact_paths_set.add(hpath)
                        clean_hops.append(clean_hp)
                clean_ch["hops"] = clean_hops
                blinded_v3_chains.append(clean_ch)

            control_search_paths: list[str] = []
            inv_candidates: list[Path] = []
            if target_run_dir is not None:
                inv_candidates.append(target_run_dir / "inventory_repo.json")
            eff_run = _effective_v3_run_id(repo_label)
            inv_candidates.append(root / ".localsec" / "runs" / eff_run / _safe_name(repo_label) / "inventory_repo.json")
            inv_candidates.append(root / ".localsec" / "runs" / "default" / _safe_name(repo_label) / "inventory_repo.json")
            for inv_f in inv_candidates:
                if inv_f.is_file():
                    try:
                        inv_obj = json.loads(inv_f.read_text(encoding="utf-8"))
                        mf = inv_obj.get("mandatory_files", {})
                        if isinstance(mf, dict):
                            for cat in ("security", "wiring_config", "data_access"):
                                for p in mf.get(cat, []):
                                    if isinstance(p, str) and p.strip():
                                        control_search_paths.append(p.strip())
                        break
                    except Exception:
                        pass

            sorted_control_paths = sorted(set(control_search_paths))
            combined_exact_paths = sorted({p for p in exact_paths_set if p} | set(sorted_control_paths))
            tmp_out = root / ".localsec" / "tmp" / f"blinded_chains_{_safe_name(repo_label)}.json"
            out_obj = {
                "repo_name": repo_label,
                "context_blinding_policy": (
                    "Strict whitelist enforced: only chain_id, candidate_ids, entrypoint, actor, preconditions, "
                    "and hop structural locations are retained; title, root_cause, remediation, chain_verdict, "
                    "severity, confidence, state_after, and expected_vulnerable_behavior are strictly stripped"
                ),
                "exact_paths": combined_exact_paths,
                "control_search_paths": sorted_control_paths,
                "blinded_chains": blinded_v3_chains,
                "saved_to": str(tmp_out),
            }
            write_json(tmp_out, out_obj)
            state_dir = target_run_dir or (root / ".localsec" / "runs" / eff_run / _safe_name(repo_label))
            if state_dir.is_dir():
                sf = state_dir / "workspace_state.json"
                st_data: dict[str, Any] = {}
                if sf.is_file():
                    try:
                        st_data = json.loads(sf.read_text(encoding="utf-8"))
                    except Exception:
                        st_data = {}
                st_data.setdefault("repo_name", _safe_name(repo_label))
                st_data.setdefault("run_id", eff_run)
                st_data.setdefault("evidence", {})
                st_data.setdefault("tool_log", [])
                st_data.setdefault("read_ranges", {})
                st_data["blinded_allowed_paths"] = combined_exact_paths
                write_json(sf, st_data)
            return out_obj

        cand_path = _resolve_json_arg(args.chain_json, root)
        if cand_path.is_file():
            chain_data = json.loads(cand_path.read_text(encoding="utf-8"))
            if isinstance(chain_data.get("result"), dict):
                chain_data = chain_data["result"]
            if isinstance(chain_data, dict) and ("verified_chains" in chain_data or "chains" in chain_data):
                out_obj = _blind_v3_deep_trace(chain_data, cand_path.parent.name or "repo", target_run_dir=cand_path.parent)
                print(json.dumps(out_obj, ensure_ascii=False, indent=2))
                return 0
            blinded = build_blinded_chain_verifier_context(attack_chain=chain_data)
            print(json.dumps(blinded, ensure_ascii=False, indent=2))
            return 0

        _, run_dir = _load_workspace(args.chain_json, cfg, run_id=args.run_id)
        if not (run_dir / "deep_trace_chain_analyst.json").is_file() and (root / ".localsec" / "runs" / "default" / args.chain_json / "deep_trace_chain_analyst.json").is_file():
            run_dir = root / ".localsec" / "runs" / "default" / args.chain_json

        # BUG-04: Prefer v3 deep_trace_chain_analyst.json when present
        dt_file = run_dir / "deep_trace_chain_analyst.json"
        if dt_file.is_file():
            dt_raw = json.loads(dt_file.read_text(encoding="utf-8"))
            dt_payload = dt_raw["result"] if isinstance(dt_raw.get("result"), dict) else dt_raw
            if isinstance(dt_payload, dict):
                out_obj = _blind_v3_deep_trace(dt_payload, args.chain_json, target_run_dir=run_dir)
                print(json.dumps(out_obj, ensure_ascii=False, indent=2))
                return 0

        # Fallback to v2 attack_chain_constructor.json
        traces: list[dict[str, Any]] = []
        tb_file = run_dir / "code_trace_builder.json"
        if tb_file.is_file():
            tb_raw = json.loads(tb_file.read_text(encoding="utf-8"))
            traces.append(tb_raw["result"] if isinstance(tb_raw.get("result"), dict) else tb_raw)
        traces_dir = run_dir / "traces"
        if traces_dir.is_dir():
            for tf in sorted(traces_dir.glob("*.json")):
                tr_raw = json.loads(tf.read_text(encoding="utf-8"))
                traces.append(tr_raw["result"] if isinstance(tr_raw.get("result"), dict) else tr_raw)
        chains: list[dict[str, Any]] = []
        chains_dir = run_dir / "chains"
        if chains_dir.is_dir():
            for cf in sorted(chains_dir.glob("*.json")):
                ch_raw = json.loads(cf.read_text(encoding="utf-8"))
                chains.append(ch_raw["result"] if isinstance(ch_raw.get("result"), dict) else ch_raw)
        if not chains and (run_dir / "attack_chain_constructor.json").is_file():
            ac_raw = json.loads((run_dir / "attack_chain_constructor.json").read_text(encoding="utf-8"))
            chains.append(ac_raw["result"] if isinstance(ac_raw.get("result"), dict) else ac_raw)
        blinded_chains = [build_blinded_chain_verifier_context(attack_chain=c, code_traces=traces) for c in chains]
        tmp_out = root / ".localsec" / "tmp" / f"blinded_chains_{_safe_name(args.chain_json)}.json"
        if len(blinded_chains) == 1:
            write_json(tmp_out, blinded_chains[0])
            print(json.dumps(blinded_chains[0], ensure_ascii=False, indent=2))
        else:
            out_legacy = {
                "repo_name": args.chain_json,
                "blinded_chains": blinded_chains,
            }
            write_json(tmp_out, out_legacy)
            print(json.dumps(out_legacy, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "run_aca_request_plan":
        req_data = json.loads(_resolve_json_arg(args.request_json, root).read_text(encoding="utf-8"))
        if isinstance(req_data.get("result"), dict):
            req_data = req_data["result"]
        prof = json.loads(_resolve_json_arg(args.target_profile, root).read_text(encoding="utf-8")) if args.target_profile else None
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
        eff_sys_run = _effective_v3_run_id()
        run_root = root / ".localsec" / "runs" / eff_sys_run
        repo_basv_results: list[dict[str, Any]] = []
        if run_root.is_dir():
            for child in sorted(run_root.iterdir()):
                if child.is_dir() and (child / "basv_repo_result.json").is_file():
                    rbr = json.loads((child / "basv_repo_result.json").read_text(encoding="utf-8"))
                    repo_basv_results.append(rbr)
        all_eids = _all_project_evidence_ids(root, run_id=eff_sys_run)
        out_dir_name = args.output_dir or cfg.get("analysis", {}).get("output_dir", "documents")
        output_root = (root / out_dir_name).resolve()
        basv_sys_dir = output_root / "_system" / "basv"
        sys_run_dir = run_root / "_system"

        def _load_json_unwrapped(path: Path) -> Any:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return raw["result"] if isinstance(raw, dict) and isinstance(raw.get("result"), dict) else raw

        interconnections = []
        if getattr(args, "interconnections", None) and _resolve_json_arg(args.interconnections, root).is_file():
            ic_raw = json.loads(_resolve_json_arg(args.interconnections, root).read_text(encoding="utf-8"))
            interconnections = ic_raw.get("inter_service_connections", ic_raw) if isinstance(ic_raw, dict) else ic_raw
        elif (basv_sys_dir / "01_service_interconnection_matrix.json").is_file():
            interconnections = json.loads(
                (basv_sys_dir / "01_service_interconnection_matrix.json").read_text(encoding="utf-8")
            ).get("inter_service_connections", [])

        sys_syn = {}
        if getattr(args, "synthesis", None) and _resolve_json_arg(args.synthesis, root).is_file():
            sys_syn = _load_json_unwrapped(_resolve_json_arg(args.synthesis, root))
        elif (sys_run_dir / "business_aware_synthesizer.json").is_file():
            sys_syn = _load_json_unwrapped(sys_run_dir / "business_aware_synthesizer.json")
        elif (basv_sys_dir / "03_system_business_aware_synthesis.json").is_file():
            sys_syn = _load_json_unwrapped(basv_sys_dir / "03_system_business_aware_synthesis.json")

        sys_aud = {}
        if getattr(args, "sys_audit", None) and _resolve_json_arg(args.sys_audit, root).is_file():
            sys_aud = _load_json_unwrapped(_resolve_json_arg(args.sys_audit, root))
        elif (sys_run_dir / "basv_evidence_auditor.json").is_file():
            sys_aud = _load_json_unwrapped(sys_run_dir / "basv_evidence_auditor.json")
        elif (sys_run_dir / "evidence_auditor.json").is_file():
            sys_aud = _load_json_unwrapped(sys_run_dir / "evidence_auditor.json")
        elif (basv_sys_dir / "04_system_basv_evidence_audit.json").is_file():
            sys_aud = _load_json_unwrapped(basv_sys_dir / "04_system_basv_evidence_audit.json")

        topo_mmd = None
        if (basv_sys_dir / "diagrams" / "service_interconnection_topology.mmd").is_file():
            topo_mmd = (basv_sys_dir / "diagrams" / "service_interconnection_topology.mmd").read_text(encoding="utf-8")

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
        eff_sys_run = _effective_v3_run_id()
        run_root = root / ".localsec" / "runs" / eff_sys_run
        repo_results: list[dict[str, Any]] = []
        sys_evidence: dict[str, dict[str, Any]] = {}
        if run_root.is_dir():
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
        eff_sys_run = _effective_v3_run_id()
        run_root = root / ".localsec" / "runs" / eff_sys_run
        repo_results = []
        sys_evidence: dict[str, dict[str, Any]] = {}
        if run_root.is_dir():
            for child in sorted(run_root.iterdir()):
                if child.is_dir() and (child / "repo_result.json").is_file():
                    rr = json.loads((child / "repo_result.json").read_text(encoding="utf-8"))
                    repo_results.append(rr)
                    for rec in rr.get("evidence", []):
                        sys_evidence[rec["evidence_id"]] = rec
        valid_eids = set(sys_evidence.keys())
        cross_payload = json.loads(_resolve_json_arg(args.cross_repo, root).read_text(encoding="utf-8"))
        audit_payload = json.loads(_resolve_json_arg(args.sys_audit, root).read_text(encoding="utf-8"))
        diag_payload = json.loads(_resolve_json_arg(args.diagrams, root).read_text(encoding="utf-8"))
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
            "run_id": eff_sys_run,
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
