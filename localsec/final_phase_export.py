"""Phase 4 (Phase cuối, sau Phase đánh giá Risk) — xuất kết quả `.localsec/runs/<run_id>/` thành đầu vào của
`reporting/report.py collect` (bộ báo cáo tổng hợp dùng chung, vendored trong `reporting/`).

Nguyên tắc:
- Chỉ chép và đổi tên trường từ dữ liệu đã khoá sổ. Không điền câu mẫu, không tự đặt trạng thái/mức độ: thiếu thì để trống,
  để cổng `report.py check` và các bước có model (kiến trúc, hợp nhất F, tác động, Phase Risk, rà soát) xử lý.
- Không ghi báo cáo cuối, không ghi `documents/_report/work/` (F-xx, `_combinations.json`…): đó là việc của luồng
  `/phase-4-consolidated-report` và `/phase-risk-assessment`, có cổng `report.py check` và `risk.py`.
- Kiểm ghi đè cho MỌI file trước khi ghi file nào: file đã có mà không mang dấu `generated_by: wins` thì dừng.
- Thiếu biên nhận cổng Phase 1/2/3 thì dừng, trừ khi `allow_unfinalized=True` (khi đó repo chưa đạt không có
  `12_analysis_status.json`, nên `collect` ghi nhận là chưa xong).
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

MARKER_MD = "<!-- generated_by: wins -->"
SURVIVING = {"REACHABLE_VULNERABILITY", "REACHABLE_PARTIALLY_MITIGATED"}
EXPORT_NOTE = "documents/_v3/wins_phase3_risk.json"


def _load(fp: Path) -> dict[str, Any]:
    if fp.is_file():
        try:
            raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return {}
        if isinstance(raw, dict):
            return raw["result"] if isinstance(raw.get("result"), dict) else raw
    return {}


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _ev(ids: Any) -> list[str]:
    return [str(e) for e in _list(ids) if str(e).startswith("ev_")]


def _merge_ranges(pairs: list[Any]) -> list[tuple[int, int]]:
    pts = sorted((int(p[0]), int(p[1])) for p in pairs if isinstance(p, (list, tuple)) and len(p) == 2 and int(p[1]) >= int(p[0]))
    out: list[tuple[int, int]] = []
    for s, e in pts:
        if out and s <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _line_count(fp: Path) -> int:
    try:
        return len(fp.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return 0


def _module_line_pct(vis_rep: dict[str, Any]) -> float | None:
    mods = _dict(vis_rep.get("target_module_line_coverage"))
    read = sum(int(_dict(m).get("lines_read") or 0) for m in mods.values())
    total = sum(int(_dict(m).get("lines_total") or 0) for m in mods.values())
    return round(read * 100.0 / total, 2) if total else None


# V23: report.py collect cites these Markdown files in every "Nguồn" line (09_findings.md, 18_…md, 03_cross_repo_review.md,
# 99_project_chain_report.md). The local toolkit writes .md next to .json; wins only wrote .json, so every source link was dead.
MD_COMPANIONS = {
    "09_findings.json": "09_findings.md",
    "18_business_aware_synthesis.json": "18_business_aware_synthesis.md",
    "02_cross_repo_review.json": "03_cross_repo_review.md",
    "99_project_chain_report.json": "99_project_chain_report.md",
}
_MD_COLS = ("id", "chain_id", "root_cause_id", "title", "priority", "severity", "status", "chain_verdict", "evidence_ids")


def _cell(v: Any) -> str:
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v[:8]) + (" …" if len(v) > 8 else "")
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")[:300]


def _md_from_json(title: str, obj: dict[str, Any]) -> list[str]:
    """Readable twin of an exported JSON: one table per list of records (id, title, level, status, evidence)."""
    lines = [f"# {title}", "", "Bản đọc của file `.json` cùng tên do `wins` xuất; dữ liệu đầy đủ ở file `.json`.", ""]
    for key, val in obj.items():
        rows = [r for r in _list(val) if isinstance(r, dict)]
        if not rows:
            continue
        cols = [c for c in _MD_COLS if any(c in r for r in rows)] or list(rows[0])[:6]
        lines += [f"## {key} ({len(rows)})", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        lines += ["| " + " | ".join(_cell(r.get(c)) for c in cols) + " |" for r in rows]
        lines.append("")
    return lines


def _sev_to_priority(sev: str) -> str:
    return {"critical": "P0", "catastrophic": "P0", "high": "P1", "medium": "P2", "low": "P3"}.get(sev, "")


class _Outputs:
    """Gom mọi file định ghi; chỉ ghi khi toàn bộ đã qua kiểm ghi đè."""

    def __init__(self, docs: Path) -> None:
        self.docs = docs
        self.files: dict[Path, str] = {}

    def json(self, rel: str, obj: dict[str, Any]) -> None:
        self.files[self.docs / rel] = json.dumps({"generated_by": "wins", **obj}, ensure_ascii=False, indent=2) + "\n"
        name = rel.rsplit("/", 1)[-1]
        if name in MD_COMPANIONS:
            md_rel = rel[: len(rel) - len(name)] + MD_COMPANIONS[name]
            self.md(md_rel, _md_from_json(name.removesuffix(".json"), obj))

    def md(self, rel: str, lines: list[str]) -> None:
        self.files[self.docs / rel] = "\n".join([MARKER_MD, *lines]) + "\n"

    def conflicts(self) -> list[str]:
        bad: list[str] = []
        for fp in self.files:
            if not fp.is_file():
                continue
            txt = fp.read_text(encoding="utf-8", errors="replace")
            if fp.suffix == ".json":
                try:
                    ok = _dict(json.loads(txt)).get("generated_by") == "wins"
                except Exception:
                    ok = False
            else:
                ok = MARKER_MD in txt
            if not ok:
                bad.append(str(fp))
        return bad

    def write(self) -> list[str]:
        for fp, txt in self.files.items():
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(txt, encoding="utf-8")
        return [str(p) for p in self.files]


def _repo_files(project_root: Path, rdir: Path, rname: str, out: _Outputs, ctx: dict[str, Any], gates_ok: bool) -> None:
    inv = _load(rdir / "inventory_repo.json")
    scout = _load(rdir / "codebase_scout.json")
    intent = _load(rdir / "intent_invariant_modeler.json")
    surf = _load(rdir / "unified_surface_mapper.json")
    arch = _load(rdir / "cross_repo_and_arch_review.json")
    cand_queue = _load(rdir / "candidate_queue.json")
    intake = _load(rdir / "candidate_intake_planner.json")
    vis = _load(rdir / "coverage_and_evidence_auditor.json")
    deep = _load(rdir / "deep_trace_chain_analyst.json")
    p3q = _load(rdir / "phase3_verified_queue.json")
    actor_map = _load(rdir / "actor_and_feasibility_assessor.json")
    beyond = _load(rdir / "beyond_code_control_mapper.json")
    sfop = _load(rdir / "sfop_risk_calibrator.json")
    kq = _load(rdir / "key_questions.json")
    rt = _load(rdir / "runtime_environment_facts.json")
    p1r, p2r = _load(rdir / "phase1_gate_receipt.json"), _load(rdir / "phase2_gate_receipt.json")
    ws_raw: dict[str, Any] = {}
    if (rdir / "workspace_state.json").is_file():
        try:
            ws_raw = _dict(json.loads((rdir / "workspace_state.json").read_text(encoding="utf-8", errors="replace")))
        except Exception:
            ws_raw = {}
    evidence = _dict(ws_raw.get("evidence"))
    read_ranges = _dict(ws_raw.get("read_ranges"))
    gates = ctx["gates"][rname]

    # 01_repo_profile.md — collect đọc dòng đầu sau `## Purpose` và `## Criticality assessment`
    archetypes = [str(a) for a in _list(scout.get("product_archetypes") or scout.get("detected_archetypes"))]
    raw_tier = str(scout.get("repo_tier") or inv.get("recommended_tier") or "").lower()
    tier_num = next((n for n in (1, 2, 3) if str(n) in raw_tier), None)
    purpose = str(scout.get("summary") or intent.get("summary") or "").replace("\n", " ").strip()
    out.md(f"{rname}/01_repo_profile.md", [
        f"# Hồ sơ repository `{rname}`",
        "",
        "## Purpose",
        purpose or "[chưa có — codebase_scout không ghi `summary`]",
        "",
        "## Criticality assessment",
        f"tier {tier_num}" if tier_num else "[chưa có — chưa phân tầng]",
        "",
        f"- Product archetypes: {', '.join(f'`{a}`' for a in archetypes) or '[chưa có]'}",
        f"- Target modules: {', '.join(f'`{m}`' for m in _list(scout.get('target_modules'))) or '[toàn repo]'}",
        f"- Ignored modules: {len(_list(scout.get('ignored_modules')))}",
    ])

    # 02_techstack.json
    caps = [{"name": a, "source": "codebase_scout.product_archetypes"} for a in archetypes]
    for c in _list(scout.get("business_capabilities")) + _list(intent.get("business_capabilities")):
        if isinstance(c, dict) and c.get("name"):
            caps.append({"name": str(c["name"]), "source": "phase1"})
        elif isinstance(c, str) and c.strip():
            caps.append({"name": c.strip(), "source": "phase1"})
    sens = []
    for sd in _list(surf.get("sensitive_data")):
        if isinstance(sd, dict):
            sens.append({**sd, "data_class": str(sd.get("data_class") or sd.get("type") or sd.get("name") or "")})
        elif isinstance(sd, str) and sd.strip():
            sens.append({"data_class": sd.strip()})
    kinds: list[dict[str, Any]] = []
    sc = surf.get("surface_checklist")
    for k, v in (_dict(sc).items() if isinstance(sc, dict) else []):
        if str((v.get("status") if isinstance(v, dict) else v) or "").lower() == "present":
            kinds.append({"kind": str(k)})
    conv = _dict(scout.get("coding_conventions"))
    out.json(f"{rname}/02_techstack.json", {
        "repo_name": rname,
        "business_capabilities": caps,
        "sensitive_data": sens,
        "entrypoints": kinds,
        "techstack": [{"name": str(k), "value": v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)} for k, v in conv.items()],
        "dependency_manifests": _list(inv.get("dependency_manifests")),
    })

    # 05_inbound_outbound.json — giá trị lấy nguyên từ mapper; thiếu thì để trống (không mặc định "confirmed")
    inbound = []
    for ep in _list(surf.get("entrypoints")):
        if isinstance(ep, dict):
            inbound.append({
                "id": str(ep.get("id") or ep.get("path") or ""),
                "source": str(ep.get("caller") or ep.get("authn") or ""),
                "trust_boundary": str(ep.get("surface_type") or ""),
                "identity_context": str(ep.get("authz") or ep.get("ownership_check") or ""),
                "status": str(ep.get("status") or ""),
                "path": str(ep.get("path") or ""),
                "file": str(ep.get("file") or ""),
                "evidence_ids": _ev(ep.get("evidence_ids")),
            })
    outbound = []
    for df in _list(surf.get("data_flows")):
        if isinstance(df, dict):
            outbound.append({
                "destination": str(df.get("destination") or df.get("target") or df.get("sink") or ""),
                "protocol": str(df.get("protocol") or df.get("channel") or ""),
                "identity_context": str(df.get("identity_forwarding") or ""),
                "status": str(df.get("status") or ""),
                "evidence_ids": _ev(df.get("evidence_ids")),
            })
    out.json(f"{rname}/05_inbound_outbound.json", {"repo_name": rname, "inbound_flows": inbound, "outbound_flows": outbound})

    # 16_code_coverage.json — mandatory_pct theo DÒNG đã đọc của file bắt buộc (đúng nghĩa ở bộ báo cáo)
    mfiles = _dict(inv.get("mandatory_files"))
    mandatory = sorted({str(f) for cat in ("entrypoint", "security") for f in _list(mfiles.get(cat))})
    total = read = 0
    for f in mandatory:
        n = _line_count(project_root / rname / f)
        total += n
        read += sum(min(e, n) - s + 1 for s, e in _merge_ranges(_list(read_ranges.get(f))) if s <= n) if n else 0
    vis_rep = _dict(vis.get("visibility_report") or _dict(p1r.get("visibility_audit")).get("visibility_report"))
    out.json(f"{rname}/16_code_coverage.json", {
        "repo_name": rname,
        "tier": tier_num,
        "mandatory_pct": round(read * 100.0 / total, 2) if total else None,
        "sweep_required": tier_num == 1 if tier_num else None,
        "sweep_pct": _module_line_pct(vis_rep),
        "all_code_pct": vis_rep.get("line_coverage_pct"),
        "waivers": [{"path": str(i.get("path") or i.get("module") or ""), "reason": str(i.get("reason") or "")}
                    for i in _list(scout.get("ignored_modules")) if isinstance(i, dict)],
        "leads": _list(inv.get("secret_leads")) + _list(inv.get("external_tool_leads")),
        "coverage_semantics": {
            "mandatory_pct": "số dòng đã đọc / tổng số dòng của file bắt buộc (entrypoint + security)",
            "sweep_pct": "số dòng đã đọc / tổng số dòng nguồn (không tính test) của các target_modules",
            "all_code_pct": "visibility_report.line_coverage_pct của wins",
        },
        "unvisited_target_modules": _list(vis_rep.get("unvisited_target_modules")),
        "deferred_out_of_budget": _list(ws_raw.get("deferred_out_of_budget")),
    })

    # 12_analysis_status.json — chỉ khi cả ba cổng đạt (collect coi file này là "Phase 1 xong").
    # Repo chưa đạt: bản 12/19 do lần xuất trước để lại phải bị gỡ, nếu không collect vẫn coi là đã xong.
    if not gates_ok:
        ctx["stale"] += [out.docs / rname / "12_analysis_status.json",
                         out.docs / rname / "basv" / "19_basv_epistemic_and_contradiction_diagnostics.json"]
    if gates_ok:
        git_rec = next((r for r in evidence.values() if isinstance(r, dict) and r.get("git_commit_sha")), {})
        out.json(f"{rname}/12_analysis_status.json", {
            "repo_name": rname,
            "run_id": ctx["run_id"],
            "status": "completed",
            "semantic_coverage_diagnostics": {"distinct_files_read": len(read_ranges)},
            "git_deployment_freshness": {"git_branch": str(git_rec.get("git_branch") or ""), "git_commit_sha": str(git_rec.get("git_commit_sha") or "")},
            "limitations": [f"Unvisited target module: {m}" for m in _list(vis_rep.get("unvisited_target_modules"))]
            + [f"Deferred out-of-budget file: {f}" for f in _list(ws_raw.get("deferred_out_of_budget"))],
        })

    # evidence_index.json — để `risk.py` nhận các ev_ đã đọc làm bằng chứng hợp lệ
    out.json(f"{rname}/evidence_index.json", {
        "repo_name": rname,
        "evidence": [
            {"evidence_id": eid, "path": r.get("path"), "line_start": r.get("line_start"), "line_end": r.get("line_end")}
            for eid, r in sorted(evidence.items()) if isinstance(r, dict)
        ],
    })

    # Chuỗi Phase 2 (wins) và trạng thái sau đối chiếu phản biện
    chains = [c for c in _list(deep.get("chains") or deep.get("verified_chains")) if isinstance(c, dict)]
    rec_by = {str(r.get("chain_id")): r for r in _list(p3q.get("reconciliation_log")) if isinstance(r, dict) and r.get("chain_id")}
    surviving_ids = {str(c.get("chain_id") or c.get("finding_id") or "") for c in _list(p3q.get("verified_findings"))
                     if isinstance(c, dict) and str(c.get("reconciled_status") or "REACHABLE_VULNERABILITY") in SURVIVING}
    cal_by = {}
    for cf in _list(sfop.get("calibrated_findings")):
        if isinstance(cf, dict):
            for k in ("chain_id", "finding_id"):
                if cf.get(k):
                    cal_by[str(cf[k])] = cf
    actor_by = {str(a.get("chain_id") or a.get("finding_id")): a
                for a in _list(actor_map.get("actor_assessments")) + _list(actor_map.get("assessments")) if isinstance(a, dict)}
    ctrl_by: dict[str, list[Any]] = {}
    for c in _list(beyond.get("beyond_code_controls")):
        if isinstance(c, dict):
            ctrl_by.setdefault(str(c.get("chain_id") or c.get("finding_id")), []).append(c)
    for a in _list(beyond.get("assessments")):
        if isinstance(a, dict):
            ctrl_by.setdefault(str(a.get("finding_id") or a.get("chain_id")), []).extend(
                {**c, "exposure_tier": a.get("exposure_tier")} for c in _list(a.get("compensating_controls")) if isinstance(c, dict))
    questions = [q for q in _list(kq.get("questions")) if isinstance(q, dict)]

    clustered: set[str] = set()
    split_cands: dict[str, str] = {}
    cand_by_id = {str(c.get("candidate_id")): c for c in _list(cand_queue.get("candidates")) if isinstance(c, dict)}
    for sp in _list(p3q.get("broken_link_splits")):
        if isinstance(sp, dict):
            for cid in _list(sp.get("candidate_ids")):
                split_cands[str(cid)] = str(sp.get("chain_id") or "")
                cand = cand_by_id.get(str(cid), {})
                # Exported as a system risk so report.py collect makes it must-map (needs its own F or a reasoned exclusion)
                ctx["split_risks"].append({
                    "id": f"SPLIT-{cid}",
                    "title": f"[{rname}] {cand.get('title') or cid} (tách từ chuỗi {sp.get('chain_id')} bị bác vì broken_link)",
                    "impact": str(cand.get("impact") or ""),
                    "priority": str(cand.get("priority") or ""),
                    "status": "hypothesis",
                    "notes": "broken_link chỉ chứng minh các hop không nối với nhau, không phải bằng chứng phản bác cho từng ứng viên",
                    "evidence_ids": _ev(cand.get("evidence_ids")),
                })
            ctx["gaps"].append(
                f"{rname}:{sp.get('chain_id')} — chuỗi bị bác vì broken_link (các hop không nối với nhau); "
                f"{len(_list(sp.get('candidate_ids')))} ứng viên của nó phải được đánh giá riêng, không coi là đã bác"
            )
    for item in _list(deep.get("unexploitable_candidates")) + _list(intake.get("dismissed_candidates")):
        if isinstance(item, dict) and item.get("candidate_id"):
            clustered.add(str(item["candidate_id"]))
    surviving_cands: set[str] = set()
    for c in chains:
        cid = str(c.get("chain_id") or c.get("finding_id") or c.get("candidate_id") or "")
        origins = [str(x) for x in _list(c.get("candidate_ids")) + _list(c.get("source_candidate_ids")) if x]
        if not origins and c.get("candidate_id"):
            origins = [str(c["candidate_id"])]
        clustered.update(origins)
        status = str(c.get("reconciled_status") or _dict(rec_by.get(cid)).get("reconciled_status")
                     or ("REACHABLE_VULNERABILITY" if cid in surviving_ids else "HYPOTHESIS_ONLY_UNVERIFIED"))
        raw_v = str(c.get("chain_verdict") or c.get("verification_status") or "").lower()
        if status in SURVIVING:
            surviving_cands.update(origins)
            # E9: report.py shows `code_supported` as "Đã xác nhận". Only a chain Phase 2 marked confirmed, or whose request
            # plan was executed and fully survived, may say so; otherwise it is partially confirmed (static evidence only).
            exec_done = str(_dict(c.get("request_plan")).get("execution_status") or c.get("execution_status") or "") == "executed"
            if raw_v == "confirmed":
                verdict = "confirmed"
            elif exec_done and status == "REACHABLE_VULNERABILITY":
                verdict = "code_supported"
            else:
                verdict = "partially_confirmed"
        elif status == "REFUTED_FALSE_POSITIVE":
            verdict = "refuted"
        else:
            verdict = "hypothesized"
        cal = _dict(cal_by.get(cid))
        sev = str(c.get("code_verified_severity") or c.get("severity") or "").lower()
        rc_raw = c.get("root_cause")
        rc_text = str((_dict(rc_raw).get("summary") or _dict(rc_raw).get("description")) if isinstance(rc_raw, dict) else (rc_raw or ""))
        plan = _dict(c.get("request_plan"))
        exec_status = str(plan.get("execution_status") or c.get("execution_status") or "not_executed")
        prevents = []
        if exec_status != "executed":
            prevents.append(f"request_plan chưa chạy (execution_status={exec_status})")
        if status != "REACHABLE_VULNERABILITY":
            prevents.append(f"reconciled_status={status}")
        notes = _dict(rec_by.get(cid)).get("challenger_notes") or c.get("challenger_notes")
        if notes:
            prevents.append(f"challenger: {notes}")
        repos = sorted({rname} | {str(h.get("repo_name")) for h in _list(c.get("hops")) if isinstance(h, dict) and h.get("repo_name")})
        eids = list(dict.fromkeys(_ev(c.get("evidence_ids")) + _ev(cal.get("evidence_ids"))))
        rc_id = str(c.get("root_cause_cluster_id") or c.get("cluster_id") or "")
        safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in f"{rname}_{cid}")
        chain_doc = {
            "chain_id": f"{rname}:{cid}",
            "title": str(c.get("title") or rc_text or cid),
            "chain_verdict": verdict,
            "reconciled_status": status,
            "challenger_verdict": _dict(rec_by.get(cid)).get("challenger_verdict") or c.get("challenger_verdict") or "",
            "impact_assessment": {
                "severity": sev,
                "conditional_impact": str(cal.get("max_impact") or ""),
                "code_supported_impact": rc_text,
                "business_consequence": str(c.get("business_impact") or c.get("business_consequence") or ""),
                "what_prevents_a_stronger_claim": prevents,
            },
            "scope": {"repositories": repos},
            "root_cause_ids": [rc_id] if rc_id else [],
            "originating_finding_ids": [f"{rname}:{o}" for o in origins],
            "execution_status": exec_status,
            "weakest_unverified_link": str(c.get("weakest_link") or c.get("weakest_unverified_link") or ""),
            "hops": _list(c.get("hops")),
            "request_plan": plan,
            "remediation": str(c.get("remediation") or c.get("representative_fix") or ""),
            "evidence_refs": eids,
        }
        out.json(f"_analysis/chains/chain_{safe}.json", chain_doc)
        ctx["chains"].append({**chain_doc, "_repo": rname, "_rc_text": rc_text, "_rc_category": str(_dict(rc_raw).get("category") or "")})
        if status in SURVIVING | {"HYPOTHESIS_ONLY_UNVERIFIED"}:
            ctx["risk_hints"].append({
                "repo_name": rname,
                "chain_id": f"{rname}:{cid}",
                "reconciled_status": status,
                "minimum_actor": _dict(actor_by.get(cid)).get("minimum_actor") or _dict(actor_by.get(cid)).get("minimum_viable_actor"),
                "preconditions": _list(_dict(actor_by.get(cid)).get("preconditions")),
                "actors_considered": _dict(actor_by.get(cid)).get("actors_considered"),
                "beyond_code_controls": ctrl_by.get(cid, []),
                "impact_axes": cal.get("impact_axes") or cal.get("sfop_impacts"),
                "max_impact": cal.get("max_impact"),
                "derived_risk_rating": cal.get("derived_risk_rating"),
                "contextual_risk_rating": cal.get("contextual_risk_rating"),
                "risk_override_applied": cal.get("risk_override_applied"),
                "risk_override_rationale": cal.get("risk_override_rationale"),
                "feasibility_derived": cal.get("feasibility_derived"),
                "owner_role": cal.get("owner_role"),
                "risk_owner": cal.get("risk_owner"),
                "safety_owner": cal.get("safety_owner"),
                "gate_0_emergency_brake": cal.get("gate_0_emergency_brake"),
                "key_questions": [q for q in questions if str(q.get("chain_id") or "") == cid],
            })
    ctx["repo_questions"] += [{**q, "repo_name": rname} for q in questions if str(q.get("chain_id") or "") in {"", "repo_wide"}]

    # 09_findings.json — toàn bộ candidate_queue + phát hiện kiến trúc; mức/ưu tiên chỉ lấy từ dữ liệu
    findings = []
    for cand in _list(cand_queue.get("candidates")):
        if not isinstance(cand, dict):
            continue
        cid = str(cand.get("candidate_id") or "")
        if cid and cid not in clustered:
            ctx["unclustered"].append(f"{rname}:{cid} — {cand.get('title') or ''}")
        if cid in split_cands and cid not in surviving_cands:
            # V17: keep it alive as an unverified source so collect makes it must-map, instead of riding the refuted chain
            status = "needs_own_assessment_after_broken_link"
        else:
            status = "confirmed_in_chain" if cid in surviving_cands else ("clustered_in_phase2" if cid in clustered else str(cand.get("status") or "candidate"))
        classes = _list(cand.get("attack_classes")) or ([cand["attack_class"]] if cand.get("attack_class") else [])
        findings.append({
            "source": "threat_model",
            "id": cid,
            "category": str(classes[0] if classes else cand.get("source_type") or ""),
            "scenario": str(cand.get("description") or cand.get("rationale") or cand.get("title") or ""),
            "title": str(cand.get("title") or cid),
            "priority": str(cand.get("priority") or cand.get("severity") or ""),
            "impact": str(cand.get("impact") or ""),
            "status": status,
            "notes": (f"source_type={cand.get('source_type', '')}; target_paths={_list(cand.get('target_paths'))}"
                      + (f"; split from broken_link chain {split_cands[cid]}" if cid in split_cands else "")),
            "evidence_ids": _ev(cand.get("evidence_ids")),
        })
    for item in _list(arch.get("architecture_findings")) + _list(arch.get("trust_boundary_mismatches")):
        if isinstance(item, dict):
            findings.append({
                "source": "architecture_review",
                "id": str(item.get("id") or item.get("mismatch_id") or ""),
                "title": str(item.get("title") or item.get("description") or ""),
                "impact": str(item.get("impact") or item.get("description") or ""),
                "priority": str(item.get("priority") or item.get("severity") or ""),
                "status": str(item.get("status") or ""),
                "notes": f"producer={item.get('producer_repo', '')}; consumer={item.get('consumer_repo', '')}",
                "evidence_ids": _ev(item.get("evidence_ids")),
            })
    out.json(f"{rname}/09_findings.json", {"repo_name": rname, "findings": findings})

    # basv/18 — "confirmed" chỉ khi bất biến được một chuỗi sống sót nêu đích danh
    surviving_text = " ".join(json.dumps(c, ensure_ascii=False) for c in chains
                              if str(c.get("chain_id") or c.get("finding_id") or "") in surviving_ids)
    confirmed, potential = [], []
    for ic in _list(surf.get("invariant_checks")):
        if not isinstance(ic, dict):
            continue
        st = str(ic.get("enforcement_status") or "").lower()
        if st == "enforced":
            continue
        inv_id = str(ic.get("invariant_id") or "")
        obj = {
            "id": inv_id,
            "title": str(ic.get("title") or ic.get("description") or f"Invariant {inv_id}: enforcement_status={st or '?'}"),
            "status": "derived" if (st == "missing" and inv_id and inv_id in surviving_text) else "",
            "outcome": st,
            "evidence_ids": _ev(_list(ic.get("intent_evidence_ids")) + _list(ic.get("implementation_evidence_ids"))),
        }
        (confirmed if obj["status"] else potential).append(obj)
    for gap in _list(intent.get("self_challenged_gaps")):
        if isinstance(gap, dict):
            potential.append({"id": str(gap.get("gap_id") or ""), "title": str(gap.get("title") or gap.get("description") or ""),
                              "outcome": "unverified", "evidence_ids": _ev(gap.get("evidence_ids"))})
        elif isinstance(gap, str) and gap.strip():
            potential.append({"id": "", "title": gap.strip(), "outcome": "unverified", "evidence_ids": []})
    workflows = [{"name": str(i.get("statement") or i.get("invariant_id") or ""), "invariant_id": str(i.get("invariant_id") or ""),
                  "intent_status": "inferred" if str(i.get("source_type") or "").lower() == "inferred_hypothesis" else "documented",
                  "evidence_ids": _ev(i.get("evidence_ids"))}
                 for i in _list(intent.get("invariants")) if isinstance(i, dict)]
    out.json(f"{rname}/basv/18_business_aware_synthesis.json", {
        "repo_name": rname, "confirmed_mismatches": confirmed, "potential_or_unverified_mismatches": potential,
        "business_workflows": workflows,
    })
    if gates_ok and gates["phase2"]:
        out.json(f"{rname}/basv/19_basv_epistemic_and_contradiction_diagnostics.json", {
            "repo_name": rname,
            "semantic_downgrades": _list(p1r.get("semantic_downgrades")),
            "empirical_refutations_ledger": _list(p3q.get("empirical_refutations_ledger")),
            "reconciliation_log": _list(p3q.get("reconciliation_log")),
        })

    # Bác bỏ / giả thuyết / chưa phản biện, dạng câu cho 99_project_chain_report
    for r in _list(p3q.get("empirical_refutations_ledger")) + _list(deep.get("unexploitable_candidates")) + _list(intake.get("dismissed_candidates")):
        if isinstance(r, dict):
            rid = r.get("chain_id") or r.get("candidate_id") or "?"
            ev = _ev(r.get("counter_evidence_ids") or r.get("counterevidence_ids") or r.get("evidence_ids"))
            ctx["refuted"].append(f"{rname}:{rid} — {r.get('refutation_reason') or r.get('reason') or ''} (evidence: {', '.join(ev) or 'none'})")
    for h in _list(p3q.get("hypothesis_only_findings")):
        if isinstance(h, dict):
            ctx["gaps"].append(f"{rname}:{h.get('chain_id') or h.get('candidate_id')} — HYPOTHESIS_ONLY_UNVERIFIED: {h.get('title') or ''}")
    for u in _list(p2r.get("unchallenged_chains")):
        ctx["gaps"].append(f"{rname}:{u} — UNCHALLENGED_BLOCKED (chưa có kết quả phản biện 2.3)")

    for tm in _list(arch.get("trust_boundary_mismatches")):
        if isinstance(tm, dict):
            ctx["trust_mismatches"].append({**tm, "repo_name": rname})

    # Sự thật runtime do người vận hành xác nhận
    rt_fp = rdir / "runtime_environment_facts.json"
    rt_date = str(rt.get("ingested_at") or rt.get("date") or "")[:10]
    if not rt_date and rt_fp.is_file():
        rt_date = _dt.date.fromtimestamp(rt_fp.stat().st_mtime).isoformat()
    src = str(rt.get("ingested_from") or "runtime_environment_facts.json")
    for i, c in enumerate(_list(rt.get("controls")), 1):
        if isinstance(c, dict):
            ctx["facts"].append({"id": f"{rname}.{c.get('control_id') or f'CTRL-{i}'}",
                                 "question": f"Kiểm soát runtime {c.get('control_id') or c.get('layer') or ''}",
                                 "answer": f"status={c.get('status', '')}, mitigation_effect={c.get('mitigation_effect', '')}",
                                 "source": src, "date": rt_date})
    for k, v in _dict(rt.get("answers")).items():
        ctx["facts"].append({"id": f"{rname}.{k}", "question": str(k), "answer": str(v), "source": src, "date": rt_date})


def export_final_phase_inputs(
    project_root: Path,
    run_id: str = "default",
    force_overwrite: bool = False,
    allow_unfinalized: bool = False,
) -> dict[str, Any]:
    project_root = Path(project_root).expanduser().resolve()
    runs_root = project_root / ".localsec" / "runs" / run_id
    docs = project_root / "documents"
    repo_dirs = sorted(d for d in runs_root.iterdir() if d.is_dir() and not d.name.startswith("_")) if runs_root.is_dir() else []
    receipt: dict[str, Any] = {"phase": "phase_4_export", "run_id": run_id, "gate_passed": False}
    if not repo_dirs:
        receipt["error"] = f"Không thấy repo nào trong {runs_root}."
        return receipt

    gates: dict[str, dict[str, bool]] = {}
    for d in repo_dirs:
        gates[d.name] = {
            f"phase{n}": (d / f"phase{n}_gate_receipt.json").is_file() and _load(d / f"phase{n}_gate_receipt.json").get("gate_passed") is True
            for n in (1, 2, 3)
        }
    failed = sorted(r for r, g in gates.items() if not all(g.values()))
    receipt["repo_gates"] = gates
    if failed and not allow_unfinalized:
        receipt["error"] = (f"{len(failed)} repo chưa qua đủ cổng Phase 1/2/3: {', '.join(failed)}. "
                            "Chạy finalize_v3_phase1/2/3 trước, hoặc truyền --allow-unfinalized để xuất bản chưa khoá sổ.")
        return receipt

    ctx: dict[str, Any] = {"run_id": run_id, "gates": gates, "chains": [], "risk_hints": [], "repo_questions": [],
                           "unclustered": [], "refuted": [], "gaps": [], "trust_mismatches": [], "facts": [], "stale": [], "split_risks": []}
    out = _Outputs(docs)
    for d in repo_dirs:
        _repo_files(project_root, d, d.name, out, ctx, gates_ok=d.name not in failed)

    # 06_root_cause_map.json — gom theo root_cause_cluster_id của chuỗi; không tự viết cách sửa
    clusters: dict[str, list[dict[str, Any]]] = {}
    for c in ctx["chains"]:
        for rc in c["root_cause_ids"]:
            clusters.setdefault(rc, []).append(c)
    root_causes = []
    for rc, cs in clusters.items():
        live = [c for c in cs if c["reconciled_status"] in SURVIVING]
        status = ("confirmed" if any(c["chain_verdict"] == "confirmed" for c in live)
                  else "strongly_supported" if live else "hypothesis")
        root_causes.append({
            "root_cause_id": rc,
            "title": next((c["_rc_text"] for c in cs if c["_rc_text"]), cs[0]["title"]),
            "root_cause_status": status,
            "cause_category": next((c["_rc_category"] for c in cs if c["_rc_category"]), ""),
            "affected_services": sorted({r for c in cs for r in c["scope"]["repositories"]}),
            "affected_chain_ids": [c["chain_id"] for c in cs],
            "remediation_at_root": next((c["remediation"] for c in live if c["remediation"]), ""),
            "remediation_that_only_treats_symptom": [],
        })
    out.json("_analysis/06_root_cause_map.json", {"run_id": run_id, "root_causes": root_causes})

    matched = _load(runs_root / "_analysis" / "matched_cross_repo_boundaries.json")
    live_chains = [c for c in ctx["chains"] if c["reconciled_status"] in SURVIVING]
    remediations = []
    for rc in root_causes:
        if rc["remediation_at_root"]:
            sevs = [c["impact_assessment"]["severity"] for c in live_chains if rc["root_cause_id"] in c["root_cause_ids"]]
            top = min(sevs, key=lambda s: ["catastrophic", "critical", "high", "medium", "low"].index(s)
                      if s in ["catastrophic", "critical", "high", "medium", "low"] else 9) if sevs else ""
            remediations.append({"priority": _sev_to_priority(top), "action": rc["remediation_at_root"],
                                 "root_cause_ids": [rc["root_cause_id"]], "chain_ids": rc["affected_chain_ids"]})
    out.json("_analysis/99_project_chain_report.json", {
        "run_id": run_id,
        "analysis_status": "complete" if not failed else "partial",
        "highest_credible_chains": [{"chain_id": c["chain_id"], "chain_verdict": c["chain_verdict"], "title": c["title"]} for c in live_chains],
        "refuted_or_weakened_chains": ctx["refuted"],
        "unverified_claims_and_gaps": ctx["gaps"] + [f"{u} — UNCLUSTERED_CANDIDATE" for u in ctx["unclustered"]],
        "recommended_remediations": remediations,
        "cross_service_patterns": [],
    })

    # _system/02 — cạnh ghép bằng script và lệch xác thực là GIẢ THUYẾT (khớp đường dẫn), không phải "confirmed"
    interactions = [{"source_repo": str(e.get("producer_repo") or ""),
                     "target": f"{e.get('consumer_repo') or ''} {e.get('normalized_target') or ''}".strip(),
                     "relationship": f"{e.get('method') or ''} {e.get('protocol') or ''}".strip(),
                     "status": "matched_by_path_pattern"}
                    for e in _list(matched.get("matched_edges")) if isinstance(e, dict)]
    system_risks = []
    for i, g in enumerate(_list(matched.get("auth_propagation_gaps")), 1):
        if isinstance(g, dict):
            system_risks.append({"id": f"SR-{i:02d}", "title": f"Lệch chuyển danh tính {g.get('producer_repo')} → {g.get('consumer_repo')}",
                                 "impact": str(g.get("gap_reason") or ""), "priority": "", "status": "hypothesis",
                                 "evidence_ids": _ev(g.get("evidence_ids"))})
    for tm in ctx["trust_mismatches"]:
        system_risks.append({"id": str(tm.get("mismatch_id") or tm.get("id") or f"SR-{len(system_risks) + 1:02d}"),
                             "title": str(tm.get("title") or tm.get("description") or ""),
                             "impact": str(tm.get("impact") or tm.get("description") or ""),
                             "priority": str(tm.get("priority") or tm.get("severity") or ""),
                             "status": str(tm.get("status") or "hypothesis"),
                             "evidence_ids": _ev(tm.get("evidence_ids"))})
    system_risks += ctx["split_risks"]
    unassigned = _list(_load(runs_root / "_analysis" / "unassigned_external_tool_findings.json").get("findings"))
    out.json("_system/02_cross_repo_review.json", {
        "run_id": run_id,
        "interactions": interactions,
        "system_risks": system_risks,
        "coverage_gaps": [{"area": f"producer {p.get('producer_repo', '') if isinstance(p, dict) else p}",
                           "reason": "không ghép được với consumer nào"} for p in _list(matched.get("unmatched_producers"))]
        + [{"area": f"consumer {c.get('consumer_repo', '') if isinstance(c, dict) else c}",
            "reason": "không ghép được với producer nào"} for c in _list(matched.get("unmatched_consumers"))],
        "unknowns": [f"[UNASSIGNED_SCANNER] {u.get('rule_id') or u.get('id')} ({u.get('severity')}) @ {u.get('path') or u.get('target')}"
                     for u in unassigned if isinstance(u, dict)],
    })

    # Gợi ý cho Phase Risk của bộ báo cáo: nguyên dữ liệu Phase 3 của wins, không diễn giải
    out.json("_v3/wins_phase3_risk.json", {
        "run_id": run_id,
        "usage": ("Dữ liệu Phase 3 (3.1 actor/điều kiện, 3.2 kiểm soát ngoài code, 3.3 S-F-O-P-C) theo chuỗi, chép nguyên. "
                  "Dùng làm nguồn khi viết work/risk/F-xx.json ở /phase-risk-exploit-path; mức rủi ro cuối do risk.py suy ra. "
                  "Nếu risk.py suy ra khác `derived_risk_rating` ở đây, giải thích trong lập luận R.3."),
        "chains": ctx["risk_hints"],
        "repo_wide_questions": ctx["repo_questions"],
    })
    out.json("_v3/wins_export_manifest.json", {
        "run_id": run_id,
        "repo_gates": gates,
        "unfinalized_repos": failed,
        "chains_exported": len(ctx["chains"]),
        "chains_reachable": len(live_chains),
        "unclustered_candidates": ctx["unclustered"],
    })

    conflicts = [] if force_overwrite else out.conflicts()
    facts_fp = docs / "_report" / "runtime_facts.json"
    if conflicts:
        receipt.update({"overwrite_blocked": True, "conflicting_files": conflicts,
                        "error": f"{len(conflicts)} file trong documents/ không do wins sinh. Dùng --force-overwrite nếu chắc chắn."})
        return receipt
    written = out.write()
    for fp in ctx["stale"]:
        if fp.is_file() and fp not in out.files:
            try:
                is_ours = _dict(json.loads(fp.read_text(encoding="utf-8", errors="replace"))).get("generated_by") == "wins"
            except Exception:
                is_ours = False
            if is_ours:
                fp.unlink()

    # runtime_facts.json là file người vận hành sửa tiếp: gộp, không ghi đè fact đã có
    existing = _load(facts_fp) if facts_fp.is_file() else {}
    by_id = {str(f.get("id")): f for f in _list(existing.get("facts")) if isinstance(f, dict)}
    for f in ctx["facts"]:
        by_id.setdefault(f["id"], f)
    facts_fp.parent.mkdir(parents=True, exist_ok=True)
    facts_fp.write_text(json.dumps({**existing, "facts": list(by_id.values())}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    written.append(str(facts_fp))

    receipt.update({"gate_passed": not failed, "overwrite_blocked": False, "unfinalized_repos": failed,
                    "exported_files_count": len(written), "exported_files": written,
                    "next": "python AI-skills/reporting/report.py collect, rồi /phase-4-consolidated-report"})
    (runs_root / "_analysis").mkdir(parents=True, exist_ok=True)
    (runs_root / "_analysis" / "phase4_export_receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    return receipt
