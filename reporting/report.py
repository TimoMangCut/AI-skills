#!/usr/bin/env python3
"""LocalSec Phase 4 — gom kết quả Phase 1/2/3, kiểm tra và dựng Báo cáo tổng hợp bảo mật.

Chạy từ <Project-Root> (Windows: `python` nếu không có `python3`):
  python3 AI-skills/reporting/report.py collect [--related ../project-khac ...]
  python3 AI-skills/reporting/report.py status
  python3 AI-skills/reporting/report.py check [--stage architecture|findings|impact|risk-paths|risk|final] [--only F-xx]
  python3 AI-skills/reporting/report.py access --for F-xx      # (Phase Risk R.1) phần chỉ mục truy cập của một F
  python3 AI-skills/reporting/report.py risk-digest             # (Phase Risk R.2) bảng ghép chéo gọn
  python3 AI-skills/reporting/report.py render-risk [--draft]
  python3 AI-skills/reporting/report.py render [--draft]

Nguyên tắc:
- Chỉ đọc kết quả đã khoá sổ trong documents/ (và reports/, specs/, reviews/ nếu có). Không đọc mã nguồn.
- Phần tất định (kiểm kê, rút gọn, độ phủ, cổng độ tin cậy, dàn trang) do script làm; phần phán đoán
  (kiến trúc, gom nhóm, tác động nghiệp vụ) do model ghi vào documents/_report/work/.
- Chỉ dùng thư viện chuẩn, Python 3.9+.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk as RISK  # noqa: E402  (phase rủi ro thực tế: reporting/risk.py)

try:  # console Windows mặc định không phải UTF-8
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

OUT_REL = Path("documents") / "_report"
REPORT_NAME = "BAO_CAO_TONG_HOP_BAO_MAT.md"
RISK_DOC_NAME = "DANH_GIA_RUI_RO.md"

SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEV_VI = {"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình", "low": "Thấp", "info": "Thông tin", "unknown": "Chưa rõ"}
_PRIORITY_TO_SEV = {"p0": "critical", "p1": "high", "p2": "medium", "p3": "low", "p4": "low", "informational": "info"}

# Trạng thái gốc -> gợi ý xử lý (disposition). Model có thể đổi, nhưng `check` buộc nêu lý do.
DISP_VI = {
    "xac_nhan": "Đã xác nhận",
    "xac_nhan_mot_phan": "Xác nhận một phần",
    "chua_kiem_toan": "P2 xác nhận – chưa qua kiểm toán",
    "co_bang_chung": "Có bằng chứng mã nguồn",
    "can_xac_minh": "Giả thuyết – cần xác minh",
    "bac_bo": "Đã bác bỏ / hạ cấp",
}
DISP_ORDER = list(DISP_VI)

CONFIDENCE_VI = {
    "confirmed": "Đã xác nhận",
    "evidence_backed": "Có bằng chứng – còn điều kiện chưa kiểm",
    "hypothesis": "Giả thuyết – cần xác minh",
}
PRIORITIES = ["P0", "P1", "P2", "P3"]
DIMENSIONS_VI = {
    "tai_chinh": "Tài chính",
    "du_lieu_ca_nhan": "Dữ liệu cá nhân/khách hàng",
    "toan_ven_nghiep_vu": "Toàn vẹn giao dịch/nghiệp vụ",
    "van_hanh": "Vận hành/khả dụng",
    "an_toan_vat_ly": "An toàn vật lý/thiết bị",
    "kiem_soat_he_thong": "Mất quyền kiểm soát hệ thống",
    "tuan_thu": "Tuân thủ/hợp đồng",
    "uy_tin": "Uy tín/niềm tin khách hàng",
}
BLAST_VI = {
    "component": "Một thành phần",
    "service": "Một service",
    "domain": "Một cụm nghiệp vụ",
    "cross_domain": "Nhiều cụm nghiệp vụ",
    "platform": "Toàn nền tảng",
}
EXCLUDE_REASONS_VI = {
    "bac_bo": "Bác bỏ (bằng chứng phản bác / kiểm toán không ủng hộ)",
    "trung_lap": "Trùng lặp — đã gộp",
    "ngoai_pham_vi": "Ngoài phạm vi đánh giá",
    "khong_phai_lo_hong": "Không phải lỗ hổng (thực hành tốt / ghi nhận)",
    "muc_thap": "Mức thấp — chỉ liệt kê ở phụ lục",
}
STAGES = ["architecture", "findings", "impact", "risk-paths", "risk", "final"]
STAGE_ALIASES: dict[str, str] = {}

GIANT_F_WARN, GIANT_F_ERROR = 25, 50
EXCLUDE_RATIO_WARN = 0.3
REVIEW_CONTEXTS = {"fresh_subagent": "subagent context mới", "new_session": "phiên hội thoại mới"}
REVIEW_SEVERITY = {"nang": "nặng", "vua": "vừa", "nhe": "nhẹ"}
_GENERIC_IMPACT = ["thiệt hại tài chính", "tổn thất tài chính", "ảnh hưởng uy tín", "ảnh hưởng đến uy tín", "rủi ro bảo mật",
                   "mất an toàn thông tin", "ảnh hưởng nghiêm trọng", "gây thiệt hại", "ảnh hưởng hoạt động kinh doanh"]
_AUDIT_RE = re.compile(r"\[Evidence audit:\s*(supported|partially_supported|inconclusive|unsupported)\b", re.I)
_TOKEN_STOP = {"domain", "service", "services", "admin", "portal", "job", "jobs", "api", "app", "web", "common", "core", "gateway",
               "swap", "battery", "management", "server", "client", "backend", "frontend", "prj", "agents", "tool", "tools"}


# ----------------------------------------------------------------------------- tiện ích

def _load(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def short(value: Any, n: int = 160) -> str:
    s = " ".join(str(value or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def cell(value: Any, n: int = 160) -> str:
    return short(value, n).replace("|", "\\|")


_SEV_WORDS = [("nghiêm trọng", "critical"), ("trung bình", "medium"), ("thấp", "low"), ("cao", "high")]


def norm_sev(value: Any) -> str:
    """'P1', 'high', 'P2 - trung bình; phụ thuộc…', 'Cao' → mức chuẩn."""
    s = str(value or "").strip().lower()
    m = re.match(r"(p[0-4]|critical|high|medium|low|info(?:rmational)?)(?![a-z])", s)
    if m:
        tok = m.group(1)
        return _PRIORITY_TO_SEV.get(tok, tok if tok in SEV_ORDER else "info")
    for word, sev in _SEV_WORDS:
        if s.startswith(word):
            return sev
    return "unknown"


def canon_repo(name: Any, repos: list[str]) -> str:
    """Đưa 'org/group/loms-service' hoặc 'loms-service' về tên thư mục documents/<repo> nếu khớp duy nhất."""
    raw = str(name or "").strip().strip("`")
    if not raw or raw in repos:
        return raw
    flat = raw.replace("/", "_")
    if flat in repos:
        return flat
    tail = raw.replace("/", "_").split("_")[-1]
    hits = [r for r in repos if r == tail or r.endswith("_" + tail) or r.endswith("/" + tail)]
    return hits[0] if len(hits) == 1 else raw


def sev_rank(value: str) -> int:
    return SEV_ORDER.index(value) if value in SEV_ORDER else len(SEV_ORDER)


def rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _first_line_after(md: str, heading: str) -> str:
    m = re.search(rf"^##\s+{re.escape(heading)}\s*$", md, re.M)
    if not m:
        return ""
    for line in md[m.end():].splitlines():
        line = line.strip()
        if line.startswith("#"):
            return ""
        if line:
            return line
    return ""


def disp_p1(status: Any) -> str:
    s = str(status or "").lower()
    if s in {"observed", "derived", "confirmed", "supported"}:
        return "co_bang_chung"
    if s in {"unknown", "unsupported", "refuted", "rejected"}:
        return "bac_bo"
    return "can_xac_minh"


def disp_p2_confirmed(item: dict[str, Any]) -> str:
    """Mismatch P2 `confirmed` chỉ là Đã xác nhận khi trạng thái SAU kiểm toán là observed/derived.

    `outcome: confirmed` mà `status: hypothesis` (kiểm toán không trả verdict / chỉ ủng hộ một phần) là fail-closed:
    có bằng chứng và đã qua cổng BASV, nhưng chưa được kiểm toán độc lập xác nhận.
    """
    if item.get("demoted_from_confirmed"):
        return "can_xac_minh"
    s = str(item.get("status") or "").lower()
    if s in {"observed", "derived", "confirmed"}:
        return "xac_nhan"
    if s in {"unknown", "unsupported", "refuted", "rejected"}:
        return "bac_bo"
    return "chua_kiem_toan"


def disp_chain(verdict: Any) -> str:
    v = str(verdict or "").lower()
    if v in {"confirmed", "demonstrated", "code_supported", "confirmed_by_source", "confirmed_by_observation"}:
        return "xac_nhan"
    if v in {"partially_confirmed", "partially_supported"}:
        return "xac_nhan_mot_phan"
    if v in {"refuted", "rejected", "falsified"}:
        return "bac_bo"
    return "can_xac_minh"


def disp_root_cause(status: Any) -> str:
    v = str(status or "").lower()
    if v == "confirmed":
        return "xac_nhan"
    if v == "strongly_supported":  # bằng chứng mạnh nhưng chưa phải xác nhận; không hiển thị là "Đã xác nhận"
        return "xac_nhan_mot_phan"
    if v in {"refuted", "rejected"}:
        return "bac_bo"
    return "can_xac_minh"


# ----------------------------------------------------------------------------- thu thập

class Project:
    def __init__(self, root: Path, out: Path | None = None) -> None:
        self.root = root.resolve()
        self.docs = self.root / "documents"
        self.out = out.resolve() if out else self.root / OUT_REL
        self.inputs = self.out / "inputs"
        self.work = self.out / "work"

    def repo_dirs(self) -> list[Path]:
        if not self.docs.is_dir():
            return []
        return sorted(
            p for p in self.docs.iterdir()
            if p.is_dir() and not p.name.startswith(("_", "."))
            and ((p / "09_findings.json").is_file() or (p / "01_repo_profile.md").is_file())
        )

    def business_doc_dirs(self) -> list[Path]:
        """Thư mục trong documents/ không phải repo và không phải đầu ra hệ thống: tài liệu nghiệp vụ."""
        if not self.docs.is_dir():
            return []
        repos = {p.name for p in self.repo_dirs()}
        return sorted(p for p in self.docs.iterdir() if p.is_dir() and not p.name.startswith(("_", ".")) and p.name not in repos)


def _finding(sid: str, repo: str, phase: str, kind: str, title: Any, sev: Any, status: Any, disp: str,
             ref: str, impact: Any = "", business_impact: Any = "", notes: Any = "", evidence_n: int = 0,
             extra: dict[str, Any] | None = None) -> dict[str, Any]:
    audit = _AUDIT_RE.search(str(notes or ""))
    rec = {
        "sid": sid,
        "repo": repo,
        "phase": phase,
        "kind": kind,
        "title": short(title, 220),
        "sev": norm_sev(sev),
        "status": str(status or ""),
        "disposition": disp,
        "audit": audit.group(1).lower() if audit else "",
        "impact": short(impact, 320),
        "business_impact": short(business_impact, 320),
        "evidence_n": evidence_n,
        "ref": ref,
    }
    if extra:
        rec.update(extra)
    return rec


def _unique(sid: str, seen: set[str]) -> str:
    base, i = sid, 2
    while sid in seen:
        sid = f"{base}~{i}"
        i += 1
    seen.add(sid)
    return sid


def _code_coverage(repo_dir: Path) -> dict[str, Any] | None:
    """documents/<repo>/16_code_coverage.json do finalize_repo ghi (Phase 1 có cổng độ phủ). None = chưa kiểm kê."""
    cov = _load(repo_dir / "16_code_coverage.json")
    if not isinstance(cov, dict):
        return None
    return {"tier": cov.get("tier"), "mandatory_pct": cov.get("mandatory_pct"), "sweep_required": cov.get("sweep_required"),
            "sweep_pct": cov.get("sweep_pct"), "all_code_pct": cov.get("all_code_pct"), "waivers": len(cov.get("waivers") or []),
            "leads": len(cov.get("leads") or [])}


def collect_repo(prj: Project, repo_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    name = repo_dir.name
    root = prj.root
    status = _load(repo_dir / "12_analysis_status.json") or {}
    tech = _load(repo_dir / "02_techstack.json") or {}
    flows = _load(repo_dir / "05_inbound_outbound.json") or {}
    synth = _load(repo_dir / "basv" / "18_business_aware_synthesis.json") or {}
    profile_md = (repo_dir / "01_repo_profile.md").read_text(encoding="utf-8") if (repo_dir / "01_repo_profile.md").is_file() else ""
    sem = status.get("semantic_coverage_diagnostics") or {}
    git = status.get("git_deployment_freshness") or {}
    intent = Counter(str(w.get("intent_status") or "unknown") for w in synth.get("business_workflows", []) if isinstance(w, dict))

    service = {
        "repo": name,
        "purpose": short(_first_line_after(profile_md, "Purpose"), 400),
        "criticality": short(_first_line_after(profile_md, "Criticality assessment"), 40),
        "capabilities": [short(c.get("name"), 120) for c in tech.get("business_capabilities", []) if isinstance(c, dict)],
        "sensitive_data": [short(c.get("data_class"), 90) for c in tech.get("sensitive_data", []) if isinstance(c, dict)],
        "entrypoint_kinds": sorted({str(e.get("kind")) for e in tech.get("entrypoints", []) if isinstance(e, dict) and e.get("kind")}),
        "techstack": [short(f"{t.get('name')}: {t.get('value')}", 120) for t in tech.get("techstack", []) if isinstance(t, dict)][:4],
        "inbound": [
            {"source": short(f.get("source"), 120), "trust_boundary": short(f.get("trust_boundary"), 90),
             "identity_context": f.get("identity_context", ""), "status": f.get("status", "")}
            for f in flows.get("inbound_flows", []) if isinstance(f, dict)
        ],
        "outbound": [
            {"destination": short(f.get("destination"), 140), "protocol": short(f.get("protocol"), 60),
             "identity_context": f.get("identity_context", ""), "status": f.get("status", "")}
            for f in flows.get("outbound_flows", []) if isinstance(f, dict)
        ],
        "phase1": "done" if (repo_dir / "12_analysis_status.json").is_file() else ("partial" if (repo_dir / "09_findings.json").is_file() else "missing"),
        "phase2": "done" if (repo_dir / "basv" / "19_basv_epistemic_and_contradiction_diagnostics.json").is_file()
                  else ("partial" if (repo_dir / "basv").is_dir() else "missing"),
        "business_intent": dict(intent),
        "files_read": sem.get("distinct_files_read"),
        "git": f"{git.get('git_branch', '')}@{git.get('git_commit_sha', '')}".strip("@"),
        "limitations": [short(x, 200) for x in status.get("limitations", [])][:3],
        "code_coverage": _code_coverage(repo_dir),
    }

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    data = _load(repo_dir / "09_findings.json") or {}
    ref_p1 = rel(root, repo_dir / "09_findings.md")
    n_tm = n_ar = 0
    for item in data.get("findings", []):
        if not isinstance(item, dict):
            continue
        src = item.get("source") or "threat_model"
        if src == "architecture_review":
            n_ar += 1
            local = f"AR-{n_ar:02d}"
            kind, title, impact = "p1_architecture", item.get("title"), item.get("impact") or item.get("assessment")
        else:
            n_tm += 1
            local = str(item.get("id") or f"TM-{n_tm:02d}")
            kind, title, impact = "p1_threat", item.get("category") or item.get("scenario"), item.get("impact")
            if item.get("scenario"):
                title = f"{item.get('category') or ''} — {item.get('scenario')}".strip(" —")
        findings.append(_finding(
            _unique(f"{name}:{local}", seen), name, "P1", kind, title, item.get("priority"), item.get("status"),
            disp_p1(item.get("status")), ref_p1, impact=impact, notes=item.get("notes"),
            evidence_n=len(item.get("evidence_ids") or []),
        ))

    ref_p2 = rel(root, repo_dir / "basv" / "18_business_aware_synthesis.md")
    for item in synth.get("confirmed_mismatches", []):
        if not isinstance(item, dict):
            continue
        findings.append(_finding(
            _unique(f"{name}:{item.get('id') or 'CM'}", seen), name, "P2", "p2_confirmed", item.get("title"),
            item.get("priority"), item.get("status") or item.get("outcome"), disp_p2_confirmed(item), ref_p2,
            impact=item.get("security_impact"), business_impact=item.get("business_impact"), notes=item.get("notes"),
            evidence_n=len(item.get("evidence_ids") or []),
            extra={"confidence_src": item.get("confidence", ""), "outcome": item.get("outcome", "")},
        ))
    for item in synth.get("potential_or_unverified_mismatches", []):
        if not isinstance(item, dict):
            continue
        findings.append(_finding(
            _unique(f"{name}:{item.get('id') or 'PM'}", seen), name, "P2", "p2_potential", item.get("title"),
            item.get("priority"), item.get("outcome"), "can_xac_minh", ref_p2,
            impact=item.get("security_impact"), business_impact=item.get("business_impact"), notes=item.get("notes"),
            evidence_n=len(item.get("evidence_ids") or []), extra={"confidence_src": item.get("confidence", "")},
        ))
    return service, findings


def collect_system(prj: Project) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    root, sysd = prj.root, prj.docs / "_system"
    findings: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    info: dict[str, Any] = {"present": sysd.is_dir(), "diagrams": []}

    cross = _load(sysd / "02_cross_repo_review.json") or {}
    ref = rel(root, sysd / "03_cross_repo_review.md")
    for i, item in enumerate(cross.get("system_risks", []), 1):
        if isinstance(item, dict):
            findings.append(_finding(
                _unique(f"_system:{item.get('id') or f'SR-{i:02d}'}", seen), "_system", "P1", "system_risk",
                item.get("title"), item.get("priority"), item.get("status"), disp_p1(item.get("status")), ref,
                impact=item.get("impact"), notes=item.get("notes"), evidence_n=len(item.get("evidence_ids") or []),
            ))
    for item in cross.get("interactions", []):
        if isinstance(item, dict):
            edges.append({"origin": "P1 cross_repo", "source": item.get("source_repo", ""), "target": short(item.get("target"), 160),
                          "mechanism": short(item.get("relationship"), 160), "auth": "", "status": item.get("status", "")})
    info["coverage_gaps"] = [short(f"{g.get('area')}: {g.get('reason')}", 260) for g in cross.get("coverage_gaps", []) if isinstance(g, dict)]
    info["unknowns"] = [short(u, 220) for u in cross.get("unknowns", [])]

    matrix = _load(sysd / "basv" / "01_service_interconnection_matrix.json") or {}
    for item in matrix.get("inter_service_connections", []):
        if isinstance(item, dict):
            edges.append({"origin": "P2 interconnection", "source": item.get("source_repo", ""), "target": short(item.get("target"), 160),
                          "mechanism": short(item.get("mechanism"), 160), "auth": short(item.get("auth_context"), 120), "status": ""})

    sbasv = _load(sysd / "basv" / "03_system_business_aware_synthesis.json") or {}
    ref2 = rel(root, sysd / "basv" / "03_system_business_aware_synthesis.md")
    for key, kind in (("confirmed_mismatches", "p2_sys_confirmed"), ("potential_or_unverified_mismatches", "p2_sys_potential")):
        for item in sbasv.get(key, []):
            if not isinstance(item, dict):
                continue
            disp = disp_p2_confirmed(item) if kind == "p2_sys_confirmed" else "can_xac_minh"
            findings.append(_finding(
                _unique(f"_system:{item.get('id') or kind}", seen), "_system", "P2", kind, item.get("title"),
                item.get("priority"), item.get("status") or item.get("outcome"), disp, ref2, impact=item.get("security_impact"),
                business_impact=item.get("business_impact"), notes=item.get("notes"),
                evidence_n=len(item.get("evidence_ids") or []),
                extra={"affected_repos": item.get("affected_repos", []), "related_refs": item.get("related_refs", [])[:12]},
            ))
    for d in (sysd / "diagrams", sysd / "basv" / "diagrams"):
        if d.is_dir():
            info["diagrams"] += [rel(root, p) for p in sorted(d.glob("*.mmd"))]
    return findings, edges, info


def collect_analysis(prj: Project) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    root, ad = prj.root, prj.docs / "_analysis"
    findings: list[dict[str, Any]] = []
    root_causes: list[dict[str, Any]] = []
    patterns: list[dict[str, Any]] = []
    info: dict[str, Any] = {"present": ad.is_dir(), "discrepancies": [], "lite": False}
    if not ad.is_dir():
        return findings, root_causes, patterns, info

    report = _load(ad / "99_project_chain_report.json") or {}
    info.update({
        "analysis_status": report.get("analysis_status", ""),
        "model_assessment": report.get("model_assessment", ""),
        "executive_summary": short(report.get("executive_summary"), 900),
        "refuted_or_weakened": [short(x, 300) for x in report.get("refuted_or_weakened_chains", [])],
        "unverified_gaps": [short(x, 260) for x in report.get("unverified_claims_and_gaps", [])],
        "recommended_remediations": [
            {"priority": r.get("priority", ""), "action": short(r.get("action"), 300),
             "root_cause_ids": r.get("root_cause_ids", []), "chain_ids": r.get("chain_ids", [])}
            for r in report.get("recommended_remediations", []) if isinstance(r, dict)
        ],
    })
    diag = _load(ad / "10_aca_epistemic_and_convergence_diagnostics.json") or {}
    info["lite"] = "lite" in json.dumps(diag, ensure_ascii=False)[:4000].lower() or "lite" in str(report.get("analysis_id", "")).lower()

    report_verdicts = {c.get("chain_id"): c.get("chain_verdict") for c in report.get("highest_credible_chains", []) if isinstance(c, dict)}
    ref = rel(root, ad / "07_attack_chain_analysis.md") if (ad / "07_attack_chain_analysis.md").is_file() else rel(root, ad / "99_project_chain_report.md")
    seen: set[str] = set()
    chain_files = sorted((ad / "chains").glob("chain_*.json")) if (ad / "chains").is_dir() else []
    chains = [c for c in (_load(p) for p in chain_files) if isinstance(c, dict)]
    if not chains:  # chưa có file chuỗi riêng: dùng báo cáo 99
        chains = [c for c in report.get("highest_credible_chains", []) if isinstance(c, dict)]
    for c in chains:
        cid = str(c.get("chain_id") or "C?")
        verdict = c.get("chain_verdict")
        rv = report_verdicts.get(cid)
        if rv and verdict and rv != verdict:
            info["discrepancies"].append(
                f"Chuỗi {cid}: 99_project_chain_report ghi `{rv}` nhưng chains/chain_{cid}.json (sau khoá sổ) ghi `{verdict}` — dùng `{verdict}`.")
        ia = c.get("impact_assessment") or {}
        scope = c.get("scope") or {}
        findings.append(_finding(
            _unique(f"_analysis:{cid}", seen), "_analysis", "P3", "p3_chain", c.get("title"),
            (ia.get("severity") or c.get("severity")), verdict, disp_chain(verdict), ref,
            impact=ia.get("conditional_impact") or ia.get("code_supported_impact") or c.get("credible_impact"),
            business_impact=ia.get("business_consequence"), evidence_n=len(c.get("evidence_refs") or []),
            extra={
                "repos": (scope.get("repositories") or [])[:12],
                "root_cause_ids": c.get("root_cause_ids", []),
                "originating_finding_ids": [str(x) for x in (c.get("originating_finding_ids") or [])],
                "execution_status": c.get("execution_status", ""),
                "weakest_link": short(c.get("weakest_unverified_link") or "; ".join(map(str, ia.get("what_prevents_a_stronger_claim") or [])), 300),
            },
        ))

    rc_data = _load(ad / "06_root_cause_map.json") or {}
    for rc in rc_data.get("root_causes", []) or report.get("root_causes", []):
        if isinstance(rc, dict):
            status = rc.get("root_cause_status") or rc.get("status")
            root_causes.append({
                "id": rc.get("root_cause_id", ""), "title": short(rc.get("title"), 220), "status": status,
                "disposition": disp_root_cause(status), "category": rc.get("cause_category", ""),
                "affected_services": rc.get("affected_services", []), "chains": rc.get("affected_chain_ids", []),
                "remediation": short(rc.get("remediation_at_root"), 400),
                "symptom_only_fixes": [short(x, 160) for x in rc.get("remediation_that_only_treats_symptom", [])][:3],
            })
    for p in report.get("cross_service_patterns", []):
        if isinstance(p, dict):
            patterns.append({
                "id": p.get("pattern_id", ""), "pattern": short(p.get("pattern"), 300), "status": p.get("status", ""),
                "services": p.get("affected_services", []), "chains": p.get("related_chain_ids", []),
                "root_cause_ids": p.get("root_cause_ids", []),
            })
    return findings, root_causes, patterns, info


def collect_external(prj: Project) -> dict[str, Any]:
    """Nguồn ngoài pipeline: SAST/SCA/DAST, review thủ công, báo cáo tổng hợp cũ, tài liệu nghiệp vụ."""
    root = prj.root
    ext: dict[str, Any] = {"tool_reports": [], "manual_reports": [], "previous_reports": [], "business_docs": []}
    skip = {"AI-skills", ".agents", ".claude", ".localsec", "documents", ".git", "node_modules"}
    for top in ("reports", "reviews", "independent-review"):
        base = root / top
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.name.startswith("."):
                continue
            entry: dict[str, Any] = {"path": rel(root, p), "size_kb": round(p.stat().st_size / 1024, 1)}
            name = p.name.lower()
            if name.endswith((".sarif", ".sarif.json")):
                sarif = _load(p) or {}
                levels: Counter[str] = Counter()
                rules: Counter[str] = Counter()
                for run in sarif.get("runs", []) if isinstance(sarif, dict) else []:
                    for r in run.get("results", []) or []:
                        levels[str(r.get("level") or "warning")] += 1
                        rules[str(r.get("ruleId") or "?")] += 1
                entry["sarif"] = {"results": sum(levels.values()), "levels": dict(levels), "top_rules": rules.most_common(8)}
                ext["tool_reports"].append(entry)
            elif name.endswith(".jsonl"):
                try:
                    with p.open(encoding="utf-8", errors="ignore") as fh:
                        entry["lines"] = sum(1 for line in fh if line.strip())
                except OSError:
                    pass
                ext["tool_reports"].append(entry)
            elif name.endswith((".json", ".xlsx", ".csv", ".html", ".burp")):
                ext["tool_reports"].append(entry)
            elif name.endswith((".md", ".txt")):
                ext["manual_reports"].append(entry)
    pat = re.compile(r"(bao[_-]?cao|report|tong[_-]?hop)", re.I)
    for p in sorted(list(root.glob("*.md")) + list(prj.docs.glob("*.md"))):
        if pat.search(p.name) and p.name.upper() not in {"README.MD", "AGENTS.MD", "CLAUDE.MD", "SOUL.MD"}:
            ext["previous_reports"].append({"path": rel(root, p), "size_kb": round(p.stat().st_size / 1024, 1)})
    doc_dirs = [root / "specs"] + prj.business_doc_dirs()
    doc_dirs += [p for p in sorted(root.iterdir()) if p.is_dir() and p.name not in skip and p not in doc_dirs
                 and re.search(r"(doc|brd|brs|spec|nghiep[-_]?vu|requirement)", p.name, re.I)]
    seen_docs: set[str] = set()
    for d in doc_dirs:
        if d.is_dir():
            for p in sorted(d.rglob("*")):
                if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in {".md", ".json", ".txt", ".pdf", ".docx", ".xlsx", ".html", ".sql", ".yaml", ".yml"}:
                    r = rel(root, p)
                    if r not in seen_docs:
                        seen_docs.add(r)
                        ext["business_docs"].append({"path": r, "size_kb": round(p.stat().st_size / 1024, 1)})
    return ext


def _resolve_origin(oid: str, chain_repos: list[str], reg: set[str], by_local: dict[str, list[str]], repos: list[str]) -> str | None:
    """Đưa ID gốc trong `originating_finding_ids` của chuỗi P3 về SID của Phase 4 (None nếu không chắc chắn)."""
    oid = oid.strip().strip("`")
    m = re.fullmatch(r"(?:(.+):)?system_risks\[(\d+)\]", oid)
    if m:
        sid = f"_system:SR-{int(m.group(2)) + 1:02d}"
        return sid if sid in reg else None
    local = oid
    if ":" in oid:
        scope, local = oid.rsplit(":", 1)
        sid = f"{canon_repo(scope, repos)}:{local}"
        if sid in reg:
            return sid
    cands = by_local.get(local, [])
    scoped = [c for c in cands if c.split(":", 1)[0] in chain_repos]
    if len(scoped) == 1:
        return scoped[0]
    if len(cands) == 1:
        return cands[0]
    sys_c = [c for c in cands if c.startswith("_system:")]
    return sys_c[0] if len(sys_c) == 1 and not scoped else None


def link_chain_origins(findings: list[dict[str, Any]], repos: list[str], ana_info: dict[str, Any]) -> None:
    """Gắn mỗi chuỗi P3 với các mục gốc nó được dựng từ đó (`origin_sids`) và ghi ngược `in_chains` vào mục gốc.

    Nhờ vậy `check` phát hiện được F gắn `confirmed` trong khi chuỗi khai thác dựng từ chính các nguồn đó chưa được xác nhận.
    """
    reg = {f["sid"]: f for f in findings}
    by_local: dict[str, list[str]] = defaultdict(list)
    for sid in reg:
        if ":" in sid and not sid.startswith(("ext:", "_analysis:")):
            by_local[sid.split(":", 1)[1]].append(sid)
    unresolved_all = []
    for ch in (f for f in findings if f["kind"] == "p3_chain"):
        sids, unresolved = [], []
        for oid in ch.get("originating_finding_ids", []):
            sid = _resolve_origin(oid, ch.get("repos", []), set(reg), by_local, repos)
            (sids if sid else unresolved).append(sid or oid)
        ch["origin_sids"] = list(dict.fromkeys(sids))
        ch["origin_unresolved"] = unresolved
        for sid in ch["origin_sids"]:
            reg[sid].setdefault("in_chains", []).append(
                {"chain": ch["sid"], "verdict": ch["status"], "disposition": ch["disposition"]})
        if unresolved:
            unresolved_all.append(f"{ch['sid']}: {', '.join(unresolved)}")
    ana_info["origin_unresolved"] = unresolved_all


_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _cvss_sev(text: str) -> str | None:
    m = re.search(r"Score:\s*([0-9]+(?:\.[0-9])?)", text)
    if not m:
        return None
    x = float(m.group(1))
    return "critical" if x >= 9 else "high" if x >= 7 else "medium" if x >= 4 else "low" if x > 0 else "info"


def _json_docs(path: Path) -> list[Any]:
    """Đọc JSON thường, JSON Lines hoặc nhiều tài liệu JSON nối tiếp (định dạng xuất của trivy/gitleaks)."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    dec, i, docs = json.JSONDecoder(), 0, []
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break
        docs.append(obj)
    return docs


def collect_tool_findings(prj: Project) -> list[dict[str, Any]]:
    """Kết quả SAST (SARIF), secret (gitleaks/trivy) và SCA/misconfig (trivy) trong reports/ thành mục gốc `ext:`.

    Đây là đầu ra công cụ CHƯA xác minh (`can_xac_minh`). Mục bắt buộc: mọi secret, SAST/misconfig mức critical/high,
    thư viện có CVE critical. Loại trừ dương tính giả phải dẫn báo cáo xác minh (ví dụ VERIFY-*.md).
    """
    root, out = prj.root, []
    base = root / "reports"
    if not base.is_dir():
        return out
    for path in sorted(base.rglob("*")):
        name = path.name.lower()
        if not path.is_file() or not name.endswith((".json", ".jsonl", ".sarif")):
            continue
        if not re.search(r"(sarif|trivy|gitleaks|secret|sca|misconfig)", rel(root, path).lower()):
            continue
        r = rel(root, path)
        seen: set[str] = set()
        docs = _json_docs(path)
        if "sarif" in name:
            n = 0
            for doc in docs:
                for run in (doc.get("runs", []) if isinstance(doc, dict) else []):
                    for res in run.get("results", []) or []:
                        n += 1
                        msg = str((res.get("message") or {}).get("text") or "")
                        head = re.split(r":\s*#|\n", msg, maxsplit=1)[0]
                        loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                        uri = (loc.get("artifactLocation") or {}).get("uri", "")
                        line = (loc.get("region") or {}).get("startLine", "")
                        sev = _cvss_sev(msg) or _SARIF_LEVEL.get(str(res.get("level") or "warning"), "medium")
                        out.append(_finding(_unique(f"ext:{r}#{n}", seen), "_ext", "EXT", "ext_sast",
                                            f"{res.get('ruleId', '?')} — {head} @ {uri}:{line}", sev, res.get("level", ""),
                                            "can_xac_minh", r, impact=msg[:400]))
            continue
        pkgs: dict[str, dict[str, Any]] = {}
        mis: dict[str, dict[str, Any]] = {}
        for doc in docs:
            items = doc if isinstance(doc, list) else [doc]
            for it in items:
                if not isinstance(it, dict):
                    continue
                if "RuleID" in it:  # gitleaks
                    out.append(_finding(_unique(f"ext:{r}#{it.get('RuleID')}@{it.get('File')}:{it.get('StartLine')}", seen),
                                        "_ext", "EXT", "ext_secret", f"Secret `{it.get('RuleID')}` @ {it.get('File')}:{it.get('StartLine')}",
                                        "high", "tool", "can_xac_minh", r, impact=it.get("Description", "")))
                for res in it.get("Results", []) or []:
                    target = res.get("Target", "")
                    for v in res.get("Vulnerabilities", []) or []:
                        key = f"{v.get('PkgName')}@{v.get('InstalledVersion')}"
                        p = pkgs.setdefault(key, {"sev": "unknown", "cves": [], "target": target, "fixed": set()})
                        sv = norm_sev(v.get("Severity"))
                        if sev_rank(sv) < sev_rank(p["sev"]):
                            p["sev"] = sv
                        p["cves"].append(f"{v.get('VulnerabilityID')}({sv})")
                        if v.get("FixedVersion"):
                            p["fixed"].add(str(v["FixedVersion"]))
                    for m_ in res.get("Misconfigurations", []) or []:
                        key = str(m_.get("ID") or m_.get("AVDID") or m_.get("Title"))
                        mm = mis.setdefault(key, {"sev": norm_sev(m_.get("Severity")), "title": m_.get("Title", ""), "targets": []})
                        mm["targets"].append(target)
                    for sc in res.get("Secrets", []) or []:
                        out.append(_finding(_unique(f"ext:{r}#secret:{sc.get('RuleID')}@{target}:{sc.get('StartLine')}", seen),
                                            "_ext", "EXT", "ext_secret", f"Secret `{sc.get('RuleID')}` @ {target}:{sc.get('StartLine')}",
                                            norm_sev(sc.get("Severity")) if sc.get("Severity") else "high", "tool", "can_xac_minh", r,
                                            impact=sc.get("Title", "")))
        for key, p in pkgs.items():
            out.append(_finding(_unique(f"ext:{r}#pkg:{key}", seen), "_ext", "EXT", "ext_sca",
                                f"Thư viện `{key}` — {len(p['cves'])} CVE ({p['target']})", p["sev"], "tool", "can_xac_minh", r,
                                impact=f"CVE: {', '.join(p['cves'][:8])}{' …' if len(p['cves']) > 8 else ''}; bản sửa: {', '.join(sorted(p['fixed'])[:3]) or '?'}"))
        for key, m_ in mis.items():
            out.append(_finding(_unique(f"ext:{r}#misconfig:{key}", seen), "_ext", "EXT", "ext_misconfig",
                                f"Cấu hình `{key}` — {m_['title']} ({len(m_['targets'])} vị trí)", m_["sev"], "tool", "can_xac_minh", r,
                                impact=", ".join(sorted(set(m_["targets"]))[:5])))
    return out


def collect_related(paths: list[str], own_text: str) -> list[dict[str, Any]]:
    out = []
    low = own_text.lower()
    for raw in paths:
        prj = Project(Path(raw))
        if not prj.docs.is_dir():
            out.append({"path": raw, "error": "không thấy documents/"})
            continue
        services = []
        hits: Counter[str] = Counter()
        for d in prj.repo_dirs():
            md = (d / "01_repo_profile.md").read_text(encoding="utf-8") if (d / "01_repo_profile.md").is_file() else ""
            services.append({"repo": d.name, "purpose": short(_first_line_after(md, "Purpose"), 220)})
            tokens = {t for t in re.split(r"[_\-.]", d.name.lower()) if len(t) >= 3 and t not in _TOKEN_STOP}
            tokens.add(d.name.split("_")[-1].lower())
            for token in tokens:
                n = len(re.findall(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", low))
                if n:
                    hits[token] = n
        name = prj.root.name
        sb = _load(prj.docs / "_system" / "basv" / "03_system_business_aware_synthesis.json") or {}
        chains = []
        cdir = prj.docs / "_analysis" / "chains"
        for p in sorted(cdir.glob("chain_*.json")) if cdir.is_dir() else []:
            c = _load(p) or {}
            chains.append(f"{c.get('chain_id')}: {short(c.get('title'), 140)} (`{c.get('chain_verdict')}`)")
        out.append({
            "path": raw, "project": name, "services": services,
            "system_confirmed": [short(f"{x.get('id')}: {x.get('title')}", 200) for x in sb.get("confirmed_mismatches", []) if isinstance(x, dict)][:10],
            "chains": chains,
            "mentions_in_this_project": [f"{t} ×{n}" for t, n in hits.most_common()],
        })
    return out


def cmd_collect(prj: Project, related: list[str]) -> int:
    if not prj.docs.is_dir():
        print(f"[x] Không thấy {prj.docs}. Chạy từ <Project-Root> sau khi Phase 1–3 đã khoá sổ.", file=sys.stderr)
        return 1
    services: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for d in prj.repo_dirs():
        svc, fs = collect_repo(prj, d)
        services.append(svc)
        findings += fs
    sys_f, edges, sys_info = collect_system(prj)
    ana_f, root_causes, patterns, ana_info = collect_analysis(prj)
    findings += sys_f + ana_f
    ext = collect_external(prj)
    findings += collect_tool_findings(prj)

    repo_names = [s["repo"] for s in services]
    for f in findings:
        f["must_map"] = must_map(f)
        for key in ("repos", "affected_repos"):
            if f.get(key):
                f[key] = [canon_repo(x, repo_names) for x in f[key]]
    link_chain_origins(findings, repo_names, ana_info)
    for rc in root_causes:
        rc["affected_services"] = [canon_repo(x, repo_names) for x in rc["affected_services"]]
    for p in patterns:
        p["services"] = [canon_repo(x, repo_names) for x in p["services"]]
    for e in edges:
        e["source"] = canon_repo(e["source"], repo_names)

    own_text = json.dumps([edges, services, [f["title"] for f in findings]], ensure_ascii=False)
    related_info = collect_related(related, own_text) if related else []

    data = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "project": prj.root.name,
        "services": services,
        "edges": edges,
        "findings": findings,
        "root_causes": root_causes,
        "patterns": patterns,
        "system": sys_info,
        "analysis": ana_info,
        "external": ext,
        "related_projects": related_info,
        "evidence_ids": RISK.collect_evidence_ids(prj.docs),
    }
    _dump(prj.inputs / "inputs.json", data)
    _write_inputs_md(prj, data)
    n_must = sum(1 for f in findings if f["must_map"])
    print(f"[+] Đã gom {len(services)} repo, {len(findings)} mục phát hiện ({n_must} bắt buộc gom nhóm), "
          f"{len(edges)} cạnh giao tiếp, {len(root_causes)} nguyên nhân gốc → {rel(prj.root, prj.inputs)}/")
    print(f"    Đọc trước: {rel(prj.root, prj.inputs / '00_manifest.md')}")
    for msg in ana_info.get("discrepancies", []):
        print(f"[!] {msg}")
    return 0


def must_map(f: dict[str, Any]) -> bool:
    """Mục bắt buộc phải được gom vào một F-xx hoặc loại trừ có lý do."""
    if f["disposition"] == "bac_bo":
        return False
    if f["kind"] == "ext_secret":
        return True
    if f["kind"] == "ext_sca":
        return f["sev"] == "critical"
    if f["kind"] in {"ext_sast", "ext_misconfig"}:
        return f["sev"] in {"critical", "high"}
    if f["kind"] in {"p3_chain", "p2_confirmed", "p2_potential", "p2_sys_confirmed", "p2_sys_potential", "system_risk"}:
        return True
    if f["kind"] in {"p1_threat", "p1_architecture"}:
        if f["sev"] == "critical":
            return True
        return f["sev"] == "high" and f["disposition"] == "co_bang_chung"
    return False


def _coverage_cell(cc: dict[str, Any] | None) -> str:
    if not cc:
        return "**chưa kiểm kê**"
    sweep = f", quét {cc['sweep_pct']}%" if cc.get("sweep_required") else ""
    return f"tầng {cc.get('tier')}: kiến trúc {cc.get('mandatory_pct')}%{sweep}"


def _write_inputs_md(prj: Project, data: dict[str, Any]) -> None:
    root = prj.root
    findings = data["findings"]
    services = data["services"]
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_repo[f["repo"]].append(f)

    # 00 — manifest
    m = [f"# Phase 4 — Kiểm kê đầu vào: {data['project']}", "",
         f"Sinh lúc {data['generated_at']} bởi `report.py collect`. File này là bản rút gọn; nguồn sự thật vẫn là `documents/`.", "",
         "## Trạng thái các phase", "",
         "| Repo | Phase 1 | Phase 2 | Ý định nghiệp vụ (BASV) | File đã đọc | Độ phủ đọc mã | Nhánh@commit |", "|---|---|---|---|---|---|---|"]
    for s in services:
        intent = ", ".join(f"{k}:{v}" for k, v in s["business_intent"].items()) or "—"
        m.append(f"| `{s['repo']}` | {s['phase1']} | {s['phase2']} | {intent} | {s['files_read'] or '—'} | {_coverage_cell(s.get('code_coverage'))} | `{s['git'] or '—'}` |")
    a = data["analysis"]
    m += ["", f"- Cấp hệ thống (`documents/_system`): {'có' if data['system']['present'] else '**không có**'}",
          f"- Phase 3 (`documents/_analysis`): {'có' if a['present'] else '**không có**'}"
          + (f" — trạng thái `{a.get('analysis_status')}`, đánh giá `{a.get('model_assessment')}`{', bản lite' if a.get('lite') else ''}" if a["present"] else ""),
          ""]
    if a.get("discrepancies"):
        m += ["## Lệch giữa các artifact (phải nêu trong báo cáo)", ""] + [f"- {x}" for x in a["discrepancies"]] + [""]
    # thống kê
    m += ["## Thống kê phát hiện theo nguồn", "", "| Nguồn | " + " | ".join(DISP_VI[d] for d in DISP_ORDER) + " | Tổng | Bắt buộc gom |",
          "|---|" + "---|" * (len(DISP_ORDER) + 2)]
    kinds = Counter(f["kind"] for f in findings)
    for kind in sorted(kinds):
        row = [f for f in findings if f["kind"] == kind]
        c = Counter(f["disposition"] for f in row)
        m.append(f"| `{kind}` | " + " | ".join(str(c.get(d, 0)) for d in DISP_ORDER) + f" | {len(row)} | {sum(1 for f in row if f['must_map'])} |")
    m += ["", "Quy tắc `bắt buộc gom`: mọi chuỗi P3, mọi mismatch P2 (repo + hệ thống), mọi rủi ro hệ thống P1, finding P1 mức critical,"
          " và finding P1 mức high có bằng chứng (observed/derived). Mục đã bác bỏ không bắt buộc (tự vào phụ lục).", "",
          "## Thứ tự đọc đề xuất", "",
          "1. `inputs/01_services.md` — danh mục service một dòng/repo (chi tiết: `01_services_detail.md`).",
          "2. `inputs/02_edges.md` — danh sách kề giữa service (chi tiết: `02_edges_detail.md`).",
          "3. `inputs/03_findings_index.md` — chuỗi P3, nguyên nhân gốc, mục cấp hệ thống.",
          "4. `inputs/findings/<repo>.md` — từng repo một, theo thứ tự bảng dưới; kết quả gom ghi vào `work/map/<repo>.json`.",
          "5. `inputs/05_access_index.md` — (Phase Risk) mọi mục về bí mật, scope của client, đường vào mạng; dùng để tìm người nắm giữ.", "",
          "| Repo | Tổng | Bắt buộc gom | Critical | High | File |", "|---|---|---|---|---|---|"]
    order = sorted(by_repo, key=lambda r: (-sum(1 for f in by_repo[r] if f["must_map"]), r))
    for r in order:
        fs = by_repo[r]
        m.append(f"| `{r}` | {len(fs)} | {sum(1 for f in fs if f['must_map'])} | {sum(1 for f in fs if f['sev'] == 'critical')} | "
                 f"{sum(1 for f in fs if f['sev'] == 'high')} | `inputs/findings/{r}.md` |")
    ext = data["external"]
    m += ["", "## Nguồn ngoài pipeline LocalSec", ""]
    if ext["tool_reports"]:
        m += ["**Báo cáo công cụ (SAST/SCA/DAST):**", ""]
        for e in ext["tool_reports"]:
            extra = ""
            if "sarif" in e:
                extra = f" — SARIF {e['sarif']['results']} kết quả {e['sarif']['levels']}"
            elif "lines" in e:
                extra = f" — {e['lines']} dòng"
            m.append(f"- `{e['path']}` ({e['size_kb']} KB){extra}")
        m.append("")
    if ext["manual_reports"]:
        m += ["**Báo cáo/ghi chú thủ công (đọc để lấy finding bổ sung, tham chiếu dạng `ext:<đường dẫn>#<ID>`):**", ""]
        m += [f"- `{e['path']}` ({e['size_kb']} KB)" for e in ext["manual_reports"]] + [""]
    if ext["previous_reports"]:
        m += ["**Báo cáo tổng hợp trước đây (chỉ tham khảo, KHÔNG phải nguồn sự thật):**", ""]
        m += [f"- `{e['path']}` ({e['size_kb']} KB)" for e in ext["previous_reports"]] + [""]
    m += ["**Tài liệu nghiệp vụ (BRD/BRS/specs):**", ""]
    m += ([f"- `{e['path']}` ({e['size_kb']} KB)" for e in ext["business_docs"]] or
          ["- Không có. Ngữ cảnh nghiệp vụ chỉ còn từ Phase 1 (`01_repo_profile.md`, `02_techstack.json`) và `basv/10_business_intent_model.md` — "
           "tác động nghiệp vụ phải ghi cơ sở là *suy luận từ recon*."])
    if data["related_projects"]:
        m += ["", "## Project liên quan", "", "Xem `inputs/04_related_projects.md`."]
    _write(prj.inputs / "00_manifest.md", m)

    # 01 — services: bản gọn (một dòng/repo) + bản chi tiết
    s_md = [f"# Danh mục service (bản gọn) — {data['project']}", "",
            "Một dòng mỗi repo. Chi tiết năng lực, công nghệ, entrypoint: `01_services_detail.md`. "
            "Cột *Ý định* lấy từ BASV: `documented` = có tài liệu nghiệp vụ, `inferred` = suy từ mã nguồn.", "",
            "| Repo | Trọng yếu | Mục đích | Dữ liệu nhạy cảm | Ý định |", "|---|---|---|---|---|"]
    for s in services:
        intent = ",".join(sorted(s["business_intent"])) or "—"
        s_md.append(f"| `{s['repo']}` | {cell(s['criticality'], 12) or '—'} | {cell(s['purpose'], 170) or '—'} | {cell('; '.join(s['sensitive_data']), 90) or '—'} | {intent} |")
    _write(prj.inputs / "01_services.md", s_md)

    s_md = [f"# Danh mục service (chi tiết) — {data['project']}", "",
            "Nguồn: `01_repo_profile.md`, `02_techstack.json`, `basv/18` (trạng thái ý định). `inferred` = ý định suy từ code, chưa có tài liệu.", ""]
    for s in services:
        s_md += [f"## `{s['repo']}` — trọng yếu: {s['criticality'] or '—'}", "",
                 f"- Mục đích: {s['purpose'] or '—'}",
                 f"- Năng lực nghiệp vụ: {'; '.join(s['capabilities']) or '—'}",
                 f"- Dữ liệu nhạy cảm: {'; '.join(s['sensitive_data']) or '—'}",
                 f"- Loại entrypoint: {', '.join(s['entrypoint_kinds']) or '—'}",
                 f"- Công nghệ: {'; '.join(s['techstack']) or '—'}",
                 f"- Ý định nghiệp vụ (BASV): {', '.join(f'{k}:{v}' for k, v in s['business_intent'].items()) or 'chưa có'}",
                 f"- Nguồn chi tiết: `documents/{s['repo']}/01_repo_profile.md`, `08_architecture_review.md`, `basv/10_business_intent_model.md`", ""]
    _write(prj.inputs / "01_services_detail.md", s_md)

    # 02 — edges: bản gọn (danh sách kề) + bản chi tiết
    adj: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for e in data["edges"]:
        for t in re.split(r",\s*", str(e["target"])):
            t = short(t, 70)
            if t:
                adj[str(e["source"]) or "?"][t].add(e["status"] or e["origin"].split()[0])
    e_md = [f"# Cạnh giao tiếp (bản gọn) — {data['project']}", "",
            "Danh sách kề gom từ P1 cross-repo và P2 interconnection. Nhãn trong ngoặc: trạng thái cạnh (`hypothesis` = chưa chứng minh ở production; `P2` = từ ma trận BASV, xem cột ngữ cảnh xác thực ở bản chi tiết). "
            "Bản chi tiết (cơ chế, xác thực, luồng ra/vào từng repo): `02_edges_detail.md`.", ""]
    for src in sorted(adj):
        e_md.append(f"- **`{src}`** → " + "; ".join(f"{t} ({'/'.join(sorted(st))})" for t, st in sorted(adj[src].items())))
    if data["system"].get("diagrams"):
        e_md += ["", "Sơ đồ đã có: " + ", ".join(f"`{d}`" for d in data["system"]["diagrams"])]
    _write(prj.inputs / "02_edges.md", e_md)

    e_md = [f"# Cạnh giao tiếp & tích hợp (chi tiết) — {data['project']}", "",
            "Nguồn: `_system/02_cross_repo_review.json` (P1) và `_system/basv/01_service_interconnection_matrix.json` (P2). "
            "Trạng thái `hypothesis` = chưa chứng minh cạnh này hoạt động ở production.", "",
            "| # | Nguồn | Đích | Cơ chế | Ngữ cảnh xác thực | Trạng thái | Gốc |", "|---|---|---|---|---|---|---|"]
    for i, e in enumerate(data["edges"], 1):
        e_md.append(f"| {i} | `{cell(e['source'], 50)}` | {cell(e['target'], 110)} | {cell(e['mechanism'], 120)} | {cell(e['auth'], 80) or '—'} | {e['status'] or '—'} | {e['origin']} |")
    e_md += ["", "## Luồng ra theo repo (tích hợp nội bộ/bên ngoài, từ `05_inbound_outbound.json`)", ""]
    for s in services:
        if s["outbound"]:
            e_md.append(f"**`{s['repo']}`**")
            e_md += [f"- → {o['destination']} · {o['protocol']} · danh tính `{o['identity_context'] or '?'}` · `{o['status']}`" for o in s["outbound"]]
            e_md.append("")
    e_md += ["## Luồng vào & ranh giới tin cậy theo repo", ""]
    for s in services:
        if s["inbound"]:
            e_md.append(f"**`{s['repo']}`**")
            e_md += [f"- ← {i_['source']} · ranh giới: {i_['trust_boundary'] or '?'} · danh tính `{i_['identity_context'] or '?'}`" for i_ in s["inbound"]]
            e_md.append("")
    _write(prj.inputs / "02_edges_detail.md", e_md)

    # 03 — index mức hệ thống
    i_md = [f"# Chỉ mục phát hiện mức hệ thống — {data['project']}", "",
            "Cột *Xử lý gốc* là gợi ý tất định từ trạng thái sau kiểm toán của từng phase; muốn đổi phải nêu lý do trong `consolidation.json`.", ""]
    a = data["analysis"]
    if a["present"]:
        i_md += ["## Phase 3 — chuỗi tấn công (trạng thái sau khoá sổ)", "",
                 "Cột *Dựng từ* là các mục gốc của chuỗi: nên gom cùng F với chuỗi. F chứa các mục này không được gắn `confirmed` khi chuỗi chưa xác nhận.", "",
                 "| SID | Verdict | Xử lý gốc | Repo | RC | Dựng từ | Tiêu đề | Mắt xích yếu nhất |", "|---|---|---|---|---|---|---|---|"]
        for f in by_repo.get("_analysis", []):
            origin = ", ".join(f"`{x}`" for x in f.get("origin_sids", [])) or "—"
            if f.get("origin_unresolved"):
                origin += f" (không đối chiếu được: {', '.join(f['origin_unresolved'])})"
            i_md.append(f"| `{f['sid']}` | `{f['status']}` | {DISP_VI[f['disposition']]} | {cell(', '.join(f.get('repos', [])), 80)} | "
                        f"{', '.join(f.get('root_cause_ids', []))} | {cell(origin, 220)} | {cell(f['title'], 140)} | {cell(f.get('weakest_link'), 160)} |")
        i_md += ["", "## Phase 3 — nguyên nhân gốc", "", "| ID | Trạng thái | Tiêu đề | Service bị ảnh hưởng | Khắc phục tại gốc |", "|---|---|---|---|---|"]
        for rc in data["root_causes"]:
            i_md.append(f"| `{rc['id']}` | `{rc['status']}` | {cell(rc['title'], 140)} | {cell(', '.join(rc['affected_services']), 120)} | {cell(rc['remediation'], 200)} |")
        if data["patterns"]:
            i_md += ["", "## Phase 3 — khuôn mẫu lặp xuyên service", ""]
            i_md += [f"- `{p['id']}` (`{p['status']}`) {p['pattern']} — service: {', '.join(p['services'])}; RC: {', '.join(p['root_cause_ids'])}" for p in data["patterns"]]
        if a.get("refuted_or_weakened"):
            i_md += ["", "## Phase 3 — chuỗi/giả thuyết bị bác bỏ hoặc làm yếu", ""] + [f"- {x}" for x in a["refuted_or_weakened"]]
        if a.get("unverified_gaps"):
            i_md += ["", "## Phase 3 — điểm chưa kiểm chứng", ""] + [f"- {x}" for x in a["unverified_gaps"]]
        if a.get("recommended_remediations"):
            i_md += ["", "## Phase 3 — khắc phục đề xuất", ""]
            i_md += [f"- [{r['priority']}] {r['action']} (RC: {', '.join(r['root_cause_ids'])}; chuỗi: {', '.join(r['chain_ids'])})" for r in a["recommended_remediations"]]
    sysf = by_repo.get("_system", [])
    if sysf:
        i_md += ["", "## Cấp hệ thống — rủi ro P1 và mismatch P2", "", "| SID | Mức | Xử lý gốc | Repo liên quan | Tiêu đề | Tác động nghiệp vụ (nguồn) |", "|---|---|---|---|---|---|"]
        for f in sorted(sysf, key=lambda x: (sev_rank(x["sev"]), x["sid"])):
            i_md.append(f"| `{f['sid']}` | {f['sev']} | {DISP_VI[f['disposition']]} | {cell(', '.join(f.get('affected_repos', [])), 90)} | "
                        f"{cell(f['title'], 150)} | {cell(f['business_impact'] or f['impact'], 200)} |")
    if data["system"].get("coverage_gaps"):
        i_md += ["", "## Khoảng trống độ phủ cấp hệ thống", ""] + [f"- {x}" for x in data["system"]["coverage_gaps"]]
    _write(prj.inputs / "03_findings_index.md", i_md)
    _write(prj.inputs / "05_access_index.md", RISK.access_index(data["findings"], prj.docs))

    # findings/<repo>.md — một dòng mỗi mục, xếp theo mức
    fdir = prj.inputs / "findings"
    if fdir.is_dir():
        for old in fdir.glob("*.md"):
            old.unlink()
    for r, fs in by_repo.items():
        fs = sorted(fs, key=lambda x: (not x["must_map"], sev_rank(x["sev"]), DISP_ORDER.index(x["disposition"]), x["sid"]))
        lines = [f"# Phát hiện gốc — `{r}`", "",
                 f"{len(fs)} mục, {sum(1 for f in fs if f['must_map'])} bắt buộc gom (★). Chi tiết: cột *Nguồn*.", "",
                 "| ★ | SID | Loại | Mức | Xử lý gốc | Audit | Chuỗi P3 | Tiêu đề | Tác động (nguồn) | Nguồn |", "|---|---|---|---|---|---|---|---|---|---|"]
        if r == "_ext":
            lines[2:2] = ["Đầu ra công cụ (SAST/SCA/secret) **chưa xác minh**. Trước khi loại trừ là dương tính giả, đọc báo cáo xác minh/thủ công "
                          "trong `reports/` (liệt kê ở `00_manifest.md`) và dẫn nó trong `note`. Lỗi giống lỗi đã có ở một F (cùng gốc, cùng cách sửa) thì gán vào F đó.", ""]
        for f in fs:
            chains = ", ".join(f"{c['chain'].split(':', 1)[1]} `{c['verdict']}`" for c in f.get("in_chains", [])) or "—"
            lines.append(f"| {'★' if f['must_map'] else ''} | `{f['sid']}` | {f['kind']} | {f['sev']} | {DISP_VI[f['disposition']]} | {f['audit'] or '—'} | {chains} | "
                         f"{cell(f['title'], 150)} | {cell(f['business_impact'] or f['impact'], 180)} | `{f['ref']}` |")
        _write(fdir / f"{r}.md", lines)

    if data["related_projects"]:
        r_md = ["# Project liên quan (cụm nghiệp vụ khác)", "",
                "Chỉ là gợi ý: tên repo của project kia xuất hiện trong cạnh/luồng ra của project này. Phải đối chiếu với `02_edges.md` trước khi kết luận có liên kết.", ""]
        for rp in data["related_projects"]:
            if rp.get("error"):
                r_md += [f"## `{rp['path']}` — {rp['error']}", ""]
                continue
            r_md += [f"## {rp['project']} (`{rp['path']}`)", "",
                     f"- Nhắc tới trong project này: {', '.join(rp['mentions_in_this_project']) or 'không tìm thấy'}", "", "**Service:**"]
            r_md += [f"- `{s['repo']}`: {s['purpose']}" for s in rp["services"]]
            if rp["system_confirmed"]:
                r_md += ["", "**Mismatch hệ thống đã xác nhận:**"] + [f"- {x}" for x in rp["system_confirmed"]]
            if rp["chains"]:
                r_md += ["", "**Chuỗi tấn công:**"] + [f"- {x}" for x in rp["chains"]]
            r_md.append("")
        _write(prj.inputs / "04_related_projects.md", r_md)


# ----------------------------------------------------------------------------- kiểm tra

class Checker:
    def __init__(self, prj: Project, stage: str, skip_review: bool = False, skip_risk_review: bool = False) -> None:
        stage = STAGE_ALIASES.get(stage, stage)
        self.prj, self.stage, self.skip_review, self.skip_risk_review = prj, stage, skip_review, skip_risk_review
        self.risk_items, self.risk_combos = RISK.load_risk(prj.work)
        self.risk_derived: dict[str, Any] = {}
        self.risk_combos_derived: list[dict[str, Any]] = []
        self.risk_err: dict[str, int] = {}
        self.risk_missing: dict[str, list[str]] = {}
        self.only: list[str] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.inputs = _load(prj.inputs / "inputs.json")
        self.arch = _load(prj.work / "architecture.json")
        self.cons = _load(prj.work / "consolidation.json")

    def at_least(self, stage: str) -> bool:
        return STAGES.index(self.stage) >= STAGES.index(stage)

    def run(self) -> int:
        if not isinstance(self.inputs, dict):
            self.errors.append("Thiếu documents/_report/inputs/inputs.json — chạy `report.py collect` trước.")
            return self.report()
        self.check_architecture()
        if self.at_least("findings"):
            self.check_findings()
        if self.at_least("risk-paths") and isinstance(self.cons, dict):
            self.check_risk()
        if self.at_least("final"):
            self.check_final()
        return self.report()

    def report(self) -> int:
        keep = (lambda m: any(t in m for t in self.only)) if self.only else (lambda m: True)
        for w in self.warnings:
            if keep(w):
                print(f"[!] {w}")
        for e in self.errors:
            if keep(e):
                print(f"[x] {e}")
        if self.only:
            print(f"(chỉ hiện dòng có {', '.join(self.only)}; tổng số lỗi ở dòng dưới là của cả project)")
        verdict = "ĐẠT" if not self.errors else "CHƯA ĐẠT"
        print(f"== check --stage {self.stage}: {verdict} ({len(self.errors)} lỗi, {len(self.warnings)} cảnh báo)")
        return 1 if self.errors else 0

    def check_architecture(self) -> None:
        md = self.prj.work / "architecture.md"
        if not md.is_file():
            self.errors.append("Thiếu work/architecture.md (bước 4.2).")
        else:
            text = md.read_text(encoding="utf-8")
            if "```mermaid" not in text:
                self.warnings.append("architecture.md chưa có sơ đồ ```mermaid.")
            for h in ("### 2.1", "### 2.2", "### 2.3", "### 2.4", "### 2.5", "### 2.6"):
                if h not in text:
                    self.errors.append(f"architecture.md thiếu mục `{h}` (xem templates/architecture.template.md).")
            if re.search(r"^#{1,2}\s", text, re.M):
                self.errors.append("architecture.md chỉ dùng heading từ `###` trở xuống (renderer đặt nó dưới `## 2`).")
        if not isinstance(self.arch, dict):
            self.errors.append("Thiếu hoặc hỏng work/architecture.json (bước 4.2).")
            return
        repos = {s["repo"] for s in self.inputs["services"]}
        ids: set[str] = set()
        assigned: set[str] = set()
        for d in self.arch.get("domains", []):
            did = d.get("id")
            if not did or did in ids:
                self.errors.append(f"Domain id trống hoặc trùng: {did!r}")
            ids.add(did)
            for field in ("name", "description"):
                if not d.get(field):
                    self.errors.append(f"Domain {did}: thiếu `{field}`.")
            for s in d.get("services", []):
                if s not in repos:
                    self.errors.append(f"Domain {did}: service `{s}` không có trong documents/.")
                assigned.add(s)
        if not ids:
            self.errors.append("architecture.json chưa có `domains`.")
        missing = sorted(repos - assigned)
        if missing:
            self.errors.append(f"{len(missing)} repo chưa thuộc cụm nghiệp vụ nào: {', '.join(missing[:15])}"
                               + (" …" if len(missing) > 15 else "") + " (repo hạ tầng/rỗng vẫn phải xếp vào một cụm, ví dụ `Nền tảng & hạ tầng`).")
        self.domain_ids = ids

    def load_maps(self) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
        """Đọc work/map/*.json: {"repo": ..., "items": [{"sid", "to": "F-xx"|"excluded"|"NEW:<slug>", ...}]}.

        `NEW:<slug>` là đề xuất F mới của một lô (thường do subagent làm); phiên chính hợp nhất bằng `report.py promote`.
        """
        extra: dict[str, list[str]] = defaultdict(list)
        excluded: list[dict[str, Any]] = []
        self.proposals: dict[str, list[dict[str, Any]]] = defaultdict(list)
        mdir = self.prj.work / "map"
        for p in sorted(mdir.glob("*.json")) if mdir.is_dir() else []:
            data = _load(p)
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                self.errors.append(f"{rel(self.prj.root, p)}: JSON hỏng hoặc thiếu `items`.")
                continue
            for it in data["items"]:
                if not isinstance(it, dict) or not it.get("sid"):
                    self.errors.append(f"{rel(self.prj.root, p)}: mục thiếu `sid`.")
                    continue
                to = str(it.get("to", ""))
                if to == "excluded":
                    excluded.append({"source_id": it["sid"], "reason": it.get("reason"), "into": it.get("into"),
                                     "note": it.get("note"), "_file": p.name})
                elif re.fullmatch(r"F-\d{2,}", to):
                    extra[to].append(it["sid"])
                elif re.fullmatch(r"NEW:[a-z0-9][a-z0-9_-]*", to):
                    self.proposals[to].append({"sid": it["sid"], "file": p.name, "proposal": it.get("proposal") or {}})
                else:
                    self.errors.append(f"{rel(self.prj.root, p)}: `{it['sid']}` có `to` = {to!r}; phải là `F-xx`, `excluded` hoặc `NEW:<slug>`.")
        return extra, excluded

    def check_findings(self) -> None:
        if not isinstance(self.cons, dict):
            self.errors.append("Thiếu hoặc hỏng work/consolidation.json (bước 4.3).")
            return
        reg = {f["sid"]: f for f in self.inputs["findings"]}
        repos = {s["repo"] for s in self.inputs["services"]}
        rcs = {rc["id"] for rc in self.inputs["root_causes"]}
        domain_ids = getattr(self, "domain_ids", set())
        used: dict[str, list[str]] = defaultdict(list)
        fids: set[str] = {f.get("id", "") for f in self.cons.get("findings", [])}
        map_extra, map_excluded = self.load_maps()
        for fid in map_extra:
            if fid not in fids:
                self.errors.append(f"work/map: gán vào `{fid}` nhưng `{fid}` chưa có trong consolidation.json.")
        self.all_sources: dict[str, list[str]] = {}
        self.all_excluded = list(self.cons.get("excluded", [])) + map_excluded
        if self.at_least("risk"):
            # Tác động nghiệp vụ (4.4) giữ nguyên ở consolidation.json. Rủi ro và ưu tiên cuối do engine suy ra từ khả năng
            # khai thác thực tế (Phase Risk) đặt cạnh tác động đó, cộng tổ hợp; giá trị ở 4.3–4.4 chỉ là tạm.
            impacts = {f.get("id"): (f.get("business_impact") or {}).get("level") for f in self.cons.get("findings", [])}
            self.risk_derived, self.risk_combos_derived = RISK.derive_all(self.risk_items, impacts, self.risk_combos)
            for f in self.cons.get("findings", []):
                d = self.risk_derived.get(f.get("id"))
                if d:
                    f["risk"], f["priority"] = d["risk"], d["priority"]
                    it = self.risk_items.get(f.get("id"))
                    if isinstance(it, dict) and isinstance(it.get("rationale"), str) and it["rationale"].strip():
                        f["risk_rationale"] = f"{RISK.state_text(d)}. {it['rationale'].strip()}"
        fids = set()

        def known(sid: str, where: str) -> bool:
            if sid in reg:
                return True
            if sid.startswith("ext:"):
                path = sid[4:].split("#", 1)[0]
                if (self.prj.root / path).is_file():
                    return True
                self.errors.append(f"{where}: `{sid}` trỏ tới file không tồn tại.")
                return False
            self.errors.append(f"{where}: SID `{sid}` không có trong inputs.json (sai chính tả hoặc bịa).")
            return False

        for f in self.cons.get("findings", []):
            fid = f.get("id", "")
            where = f"Finding {fid or '?'}"
            if not re.fullmatch(r"F-\d{2,}", fid or "") or fid in fids:
                self.errors.append(f"{where}: id phải dạng F-01 và không trùng.")
            fids.add(fid)
            for field in ("title", "core_issue", "risk", "confidence", "priority", "remediation", "risk_rationale"):
                if not f.get(field):
                    self.errors.append(f"{where}: thiếu `{field}`.")
            if f.get("risk") not in SEV_VI or f.get("risk") in {"info", "unknown"}:
                self.errors.append(f"{where}: `risk` phải là critical|high|medium|low.")
            if f.get("confidence") not in CONFIDENCE_VI:
                self.errors.append(f"{where}: `confidence` phải là {'|'.join(CONFIDENCE_VI)}.")
            if f.get("priority") not in PRIORITIES:
                self.errors.append(f"{where}: `priority` phải là P0–P3.")
            if f.get("confidence") != "confirmed" and not f.get("validation"):
                self.errors.append(f"{where}: chưa `confirmed` thì phải có `validation` (việc cần làm để xác nhận).")
            for s in f.get("services", []):
                if s not in repos:
                    self.warnings.append(f"{where}: service `{s}` không phải repo trong documents/ (ghi đúng tên thư mục nếu là repo).")
            if domain_ids:
                for d in f.get("domains", []):
                    if d not in domain_ids:
                        self.errors.append(f"{where}: domain `{d}` không có trong architecture.json.")
                if not f.get("domains"):
                    self.errors.append(f"{where}: thiếu `domains`.")
            for rc in f.get("root_causes", []):
                if rc not in rcs:
                    self.errors.append(f"{where}: nguyên nhân gốc `{rc}` không có trong Phase 3.")
            key = f.get("source_ids") or []
            if not key:
                self.errors.append(f"{where}: thiếu `source_ids` (nguồn chính) — mọi kết luận phải truy về nguồn.")
            sids = list(dict.fromkeys(key + map_extra.get(fid, [])))
            self.all_sources[fid] = sids
            if len(sids) > GIANT_F_ERROR and not f.get("scope_note"):
                self.errors.append(f"{where}: gom {len(sids)} nguồn — gần như chắc chắn đang trộn nhiều vấn đề. Tách F, hoặc ghi `scope_note` "
                                   "giải thích vì sao đây là MỘT điểm yếu hệ thống với MỘT cách sửa.")
            elif len(sids) > GIANT_F_WARN:
                self.warnings.append(f"{where}: gom {len(sids)} nguồn — kiểm lại có cùng nguyên nhân gốc và cùng cách sửa không.")
            if len(set(f.get("root_causes", []))) > 2:
                self.warnings.append(f"{where}: gắn {len(set(f['root_causes']))} nguyên nhân gốc — một F thường ứng với 1–2 nguyên nhân.")
            disps = []
            for sid in sids:
                if known(sid, where):
                    used[sid].append(fid)
                    if sid in reg:
                        disps.append(reg[sid]["disposition"])
                        if reg[sid]["disposition"] == "bac_bo" and not f.get("override_note"):
                            self.errors.append(f"{where}: dùng `{sid}` đã bị bác bỏ ở phase trước mà không có `override_note`.")
            self._confidence_gate(f, where, sids, reg, disps)
            if self.at_least("impact"):
                self._impact(f, where)

        for x in self.all_excluded:
            sid = x.get("source_id", "")
            where = f"Loại trừ `{sid}`" + (f" ({x['_file']})" if x.get("_file") else "")
            if known(sid, where):
                used[sid].append("excluded")
            if x.get("reason") not in EXCLUDE_REASONS_VI:
                self.errors.append(f"{where}: `reason` phải là {'|'.join(EXCLUDE_REASONS_VI)}.")
            if x.get("reason") == "trung_lap" and x.get("into") not in fids:
                self.errors.append(f"{where}: `trung_lap` phải có `into` trỏ tới một F-xx tồn tại.")
            note = str(x.get("note") or "").strip()
            src = reg.get(sid, {})
            if not note:
                self.errors.append(f"{where}: thiếu `note` (lý do cụ thể).")
            elif src.get("must_map") and x.get("reason") != "trung_lap" and len(note) < 25:
                self.errors.append(f"{where}: loại trừ mục bắt buộc cần `note` cụ thể (≥25 ký tự), không phải vài chữ.")
            if x.get("reason") == "muc_thap" and src.get("sev") == "critical":
                self.errors.append(f"{where}: không được hạ mục critical bằng `muc_thap` — gom vào F (có thể với mức thấp hơn và risk_rationale), hoặc dùng lý do khác có bằng chứng.")
            if x.get("reason") == "muc_thap" and src.get("sev") == "high" and len(note) < 40:
                self.errors.append(f"{where}: hạ mục high bằng `muc_thap` cần `note` ≥40 ký tự nêu vì sao tác động/khả năng khai thác thấp.")
            if x.get("reason") == "bac_bo" and sid in reg and reg[sid]["disposition"] != "bac_bo" and len(str(x.get("note", ""))) < 40:
                self.errors.append(f"{where}: bác bỏ mới ở Phase 4 (phase trước chưa bác bỏ) cần `note` nêu bằng chứng phản bác cụ thể.")
            if x.get("reason") in {"bac_bo", "khong_phai_lo_hong", "muc_thap"} and reg.get(sid, {}).get("kind", "").startswith("ext_") \
                    and not re.search(r"(\.(md|json|sarif|xlsx)\b|reports/|verify|xác minh)", str(x.get("note", "")), re.I):
                self.errors.append(f"{where}: loại trừ kết quả công cụ là dương tính giả phải dẫn báo cáo xác minh (file trong reports/ hoặc VERIFY-*.md).")

        n_prop = sum(len(v) for v in self.proposals.values())
        if n_prop:
            for slug, items in self.proposals.items():
                for it in items:
                    used[it["sid"]].append(slug)
            self.errors.append(f"{n_prop} mục đang ở đề xuất F mới chưa hợp nhất ({', '.join(sorted(self.proposals))}) — "
                               "tạo F trong consolidation.json rồi chạy `report.py promote <NEW:slug> <F-xx>`.")
        must = [f for f in self.inputs["findings"] if f["must_map"]]
        ex_must = Counter(x.get("reason") for x in self.all_excluded
                          if reg.get(x.get("source_id"), {}).get("must_map") and x.get("reason") != "trung_lap")
        self.exclusion_stats = {"must": len(must), "excluded": sum(ex_must.values()), "by_reason": dict(ex_must)}
        if must and sum(ex_must.values()) / len(must) > EXCLUDE_RATIO_WARN:
            self.warnings.append(f"{sum(ex_must.values())}/{len(must)} mục bắt buộc bị loại trừ ({dict(ex_must)}) — tỷ lệ cao; "
                                 "báo cáo sẽ ghi rõ con số này ở mục 7.")
        missing = [f for f in self.inputs["findings"] if f["must_map"] and f["sid"] not in used]
        if missing:
            by_repo = Counter(f["repo"] for f in missing)
            self.errors.append(f"{len(missing)} mục bắt buộc chưa được gom hoặc loại trừ: "
                               + ", ".join(f"{r} ({n})" for r, n in by_repo.most_common()))
            for f in missing[:25]:
                self.errors.append(f"   chưa gom: `{f['sid']}` [{f['sev']}] {short(f['title'], 90)}")
            if len(missing) > 25:
                self.errors.append(f"   … và {len(missing) - 25} mục khác (xem `report.py status`).")
        self.used = used
        multi = {s: v for s, v in used.items() if len(v) > 1}
        for s, v in list(multi.items())[:10]:
            self.warnings.append(f"`{s}` xuất hiện ở nhiều nơi: {', '.join(v)} — mỗi SID nên thuộc đúng một F hoặc một dòng loại trừ.")
        self._chain_consistency(reg)
        if self.at_least("impact"):
            self._impact_duplicates()
            used_rcs = {rc for f in self.cons.get("findings", []) for rc in f.get("root_causes", [])}
            for rc in self.inputs["root_causes"]:
                if rc["disposition"] != "bac_bo" and rc["id"] not in used_rcs:
                    self.warnings.append(f"Nguyên nhân gốc `{rc['id']}` chưa gắn với finding nào.")

    def _chain_consistency(self, reg: dict[str, Any]) -> None:
        """Nguồn gốc của một chuỗi P3 nên nằm cùng F với chuỗi; bác bỏ nguồn của chuỗi còn đứng phải có lý do."""
        home: dict[str, str] = {}
        for fid, sids in self.all_sources.items():
            for sid in sids:
                home.setdefault(sid, fid)
        excluded = {x.get("source_id"): x for x in self.all_excluded}
        for ch in (f for f in self.inputs["findings"] if f["kind"] == "p3_chain"):
            fa = home.get(ch["sid"])
            for o in ch.get("origin_sids", []):
                fb = home.get(o)
                if fa and fb and fa != fb:
                    self.warnings.append(f"Chuỗi `{ch['sid']}` ở {fa} nhưng nguồn gốc `{o}` của nó ở {fb} — xem lại cách gom (cùng gốc thì cùng F).")
                if o in excluded and excluded[o].get("reason") == "bac_bo" and ch["disposition"] in {"xac_nhan", "xac_nhan_mot_phan"}:
                    self.errors.append(f"`{o}` bị loại trừ `bac_bo` trong khi chuỗi `{ch['sid']}` dựng từ nó vẫn `{ch['status']}` — mâu thuẫn.")

    def _impact_duplicates(self) -> None:
        def toks(t: str) -> set[str]:
            return set(re.findall(r"\w+", t.lower()))
        items = [(f.get("id"), str((f.get("business_impact") or {}).get("consequence", ""))) for f in self.cons.get("findings", [])]
        for i, (a, ta) in enumerate(items):
            for b, tb in items[i + 1:]:
                if not ta or not tb:
                    continue
                if " ".join(ta.lower().split()) == " ".join(tb.lower().split()):
                    self.errors.append(f"{a} và {b} dùng cùng một câu consequence — mỗi F phải có hậu quả riêng.")
                    continue
                x, y = toks(ta), toks(tb)
                if x and y and len(x & y) / len(x | y) >= 0.75:
                    self.warnings.append(f"{a} và {b} có consequence gần trùng — kiểm lại có phải cùng một vấn đề không.")

    def _confidence_gate(self, f: dict[str, Any], where: str, sids: list[str], reg: dict[str, Any], disps: list[str]) -> None:
        conf = f.get("confidence")
        if conf == "confirmed" and "xac_nhan" not in disps:
            self.errors.append(f"{where}: `confirmed` nhưng không nguồn nào ở trạng thái Đã xác nhận (fail-closed) — hạ xuống evidence_backed/hypothesis.")
        backed = {"xac_nhan", "xac_nhan_mot_phan", "chua_kiem_toan", "co_bang_chung"}
        if conf == "evidence_backed" and not set(disps) & backed and not any(s.startswith("ext:") and s not in reg for s in sids):
            self.errors.append(f"{where}: `evidence_backed` nhưng mọi nguồn đều là giả thuyết — hạ xuống hypothesis.")
        if conf == "confirmed":
            weak = {s: reg[s]["status"] for s in sids if s in reg and reg[s]["kind"] == "p3_chain" and reg[s]["disposition"] in {"can_xac_minh", "bac_bo"}}
            for s in sids:
                for c in reg.get(s, {}).get("in_chains", []):
                    if c["disposition"] in {"can_xac_minh", "bac_bo"}:
                        weak[c["chain"]] = c["verdict"]
            if weak and not f.get("override_note"):
                self.errors.append(f"{where}: `confirmed` nhưng chuỗi khai thác Phase 3 dựng từ chính các nguồn này chưa được xác nhận ("
                                   + ", ".join(f"{k} `{v}`" for k, v in weak.items())
                                   + ") — hạ xuống evidence_backed, hoặc ghi `override_note` nêu bằng chứng khai thác độc lập.")
        srcs = [reg[s]["sev"] for s in sids if s in reg and reg[s]["sev"] not in {"unknown", "info"}]
        if srcs and f.get("risk") in SEV_VI and min(sev_rank(x) for x in srcs) > sev_rank(f["risk"]):
            self.warnings.append(f"{where}: mức `{f['risk']}` cao hơn mọi nguồn ({', '.join(sorted(set(srcs)))}) — risk_rationale phải giải thích vì sao nâng.")

    def _impact(self, f: dict[str, Any], where: str) -> None:
        bi = f.get("business_impact")
        if not isinstance(bi, dict):
            self.errors.append(f"{where}: thiếu `business_impact` (bước 4.4).")
            return
        for field in ("capability", "scenario", "consequence", "level", "blast_radius", "basis"):
            if not bi.get(field):
                self.errors.append(f"{where}: business_impact thiếu `{field}`.")
        dims = bi.get("dimensions") or []
        if not dims:
            self.errors.append(f"{where}: business_impact thiếu `dimensions`.")
        for d in dims:
            if d not in DIMENSIONS_VI:
                self.errors.append(f"{where}: dimension `{d}` không hợp lệ ({'|'.join(DIMENSIONS_VI)}).")
        if bi.get("level") and bi["level"] not in {"critical", "high", "medium", "low"}:
            self.errors.append(f"{where}: business_impact.level phải là critical|high|medium|low.")
        if bi.get("blast_radius") and bi["blast_radius"] not in BLAST_VI:
            self.errors.append(f"{where}: blast_radius phải là {'|'.join(BLAST_VI)}.")
        if bi.get("blast_radius") in {"cross_domain", "platform"} and len(f.get("domains", [])) < 2 and bi.get("blast_radius") == "cross_domain":
            self.warnings.append(f"{where}: blast_radius cross_domain nhưng chỉ gắn {len(f.get('domains', []))} domain.")
        if f.get("confidence") != "confirmed" and not bi.get("conditions"):
            self.errors.append(f"{where}: tác động chưa xác nhận phải ghi `conditions` (điều kiện để hậu quả xảy ra).")
        for field, n in (("capability", 10), ("scenario", 25), ("consequence", 40)):
            if bi.get(field) and len(str(bi[field]).strip()) < n:
                self.errors.append(f"{where}: business_impact.{field} quá ngắn (<{n} ký tự) — nêu cụ thể ai, làm gì, hỏng việc gì.")
        cons_txt = str(bi.get("consequence", "")).lower()
        generic = [g for g in _GENERIC_IMPACT if g in cons_txt]
        if generic and len(cons_txt) < 110:
            self.errors.append(f"{where}: consequence chung chung ('{generic[0]}…') — nêu năng lực nghiệp vụ, đối tượng và hậu quả cụ thể.")
        if bi.get("basis") and not re.search(r"(\w:[A-Za-z]|\bRC-?\d|\.(md|json)\b|/|suy luận|brd|srs|tài liệu)", str(bi["basis"]), re.I):
            self.errors.append(f"{where}: business_impact.basis phải dẫn SID/RC/file nguồn, hoặc ghi rõ 'Suy luận từ recon: …'.")
        if len(dims) > 3:
            self.warnings.append(f"{where}: {len(dims)} dimensions — giữ 1–3 khía cạnh chính.")
        if dims == ["uy_tin"]:
            self.errors.append(f"{where}: `uy_tin` không được là khía cạnh duy nhất — nêu tác động trực tiếp trước.")
        text = " ".join(str(bi.get(k, "")) for k in ("consequence", "scenario"))
        if re.search(r"\d[\d.,]*\s*(tỷ|triệu|nghìn|usd|vnd|đồng|\$)", text, re.I) and "basis" in bi and "số liệu" not in str(bi["basis"]).lower():
            self.warnings.append(f"{where}: có ước lượng tiền — chỉ giữ nếu `basis` dẫn tới số liệu nghiệp vụ thật.")

    def check_risk(self) -> None:
        """Phase rủi ro: mỗi F có work/risk/F-xx.json hợp lệ, tổ hợp xuyên điểm yếu đã xét, thách thức độc lập đã xử lý."""
        fids = {f.get("id") for f in self.cons.get("findings", [])}
        sid_to_f: dict[str, str] = {}
        for f in self.cons.get("findings", []):
            for s in f.get("source_ids") or []:
                sid_to_f.setdefault(s, f.get("id"))
        excluded = {x.get("source_id"): str(x.get("reason")) for x in self.cons.get("excluded", []) if isinstance(x, dict)}
        mdir = self.prj.work / "map"
        for p in sorted(mdir.glob("*.json")) if mdir.is_dir() else []:
            data = _load(p)
            for it in (data.get("items") if isinstance(data, dict) else None) or []:
                if not isinstance(it, dict) or not it.get("sid"):
                    continue
                to = str(it.get("to", ""))
                if re.fullmatch(r"F-\d{2,}", to):
                    sid_to_f.setdefault(it["sid"], to)
                elif to == "excluded":
                    excluded[it["sid"]] = str(it.get("reason"))
        # SID trùng lặp đã gộp vào F khác: coi như thuộc F đó
        for x in list(self.cons.get("excluded", [])) + [it for p in (sorted(mdir.glob("*.json")) if mdir.is_dir() else [])
                                                       for it in ((_load(p) or {}).get("items") or []) if isinstance(it, dict)]:
            if isinstance(x, dict) and x.get("reason") == "trung_lap" and re.fullmatch(r"F-\d{2,}", str(x.get("into") or "")):
                sid = x.get("source_id") or x.get("sid")
                sid_to_f.setdefault(sid, x["into"])
                excluded.pop(sid, None)
        full = self.at_least("risk")
        key_unlocks = {str(u) for q in ((self.risk_combos or {}).get("key_questions") or []) if isinstance(q, dict)
                       for u in (q.get("unlocks") or [])} if full and isinstance(self.risk_combos, dict) else set()
        feas = {fid: RISK.finding_feasibility(it) for fid, it in self.risk_items.items() if isinstance(it, dict)}
        ctx = RISK.RiskContext(self.prj.root, self.prj.out, {f["sid"]: f for f in self.inputs["findings"]}, fids,
                               set(self.inputs.get("evidence_ids", [])), sid_to_f, excluded, key_unlocks, feas)
        missing = sorted(fids - set(self.risk_items))
        self.risk_missing = {"R.1": list(missing), "R.3": []}
        self.risk_err = {"R.1": 0, "R.2": 0, "R.3": 0, "R.4": 0}
        if missing:
            self.errors.append(f"Phase rủi ro: {len(missing)} phát hiện chưa có work/risk/<F>.json: {', '.join(missing[:12])} (/phase-risk-exploit-path).")
            self.risk_err["R.1"] += 1
        impacts = {f.get("id"): (f.get("business_impact") or {}).get("level") for f in self.cons.get("findings", [])}
        for fid in sorted(fids & set(self.risk_items)):
            e_paths, w = RISK.check_item(fid, self.risk_items[fid], ctx, impact_level=impacts.get(fid), phase="paths")
            if e_paths:
                self.risk_missing["R.1"].append(fid)
            self.risk_err["R.1"] += len(e_paths)
            if full:
                e, w = RISK.check_item(fid, self.risk_items[fid], ctx, impact_level=impacts.get(fid), phase="full")
                extra = [x for x in e if x not in e_paths]
                if extra:
                    self.risk_missing["R.3"].append(fid)
                self.risk_err["R.3"] += len(extra)
                self.errors += e
            else:
                self.errors += e_paths
            self.warnings += w
        if full and not missing:
            e, w = RISK.check_combinations(self.risk_combos, self.risk_items, ctx, impacts)
            self.risk_err["R.2"] += len(e)
            self.errors += e
            self.warnings += w
        stray = sorted(set(self.risk_items) - fids)
        if stray:
            self.warnings.append(f"work/risk có file cho F không còn tồn tại: {', '.join(stray)}.")
        if full and not self.skip_risk_review and not self.errors:
            n = len(self.errors)
            self.check_review("risk_review.json", "R.4 (/phase-risk-challenge)", {"combinations", "overall"})
            self.risk_err["R.4"] += len(self.errors) - n

    def check_review(self, fname: str = "review.json", step: str = "4.6 (/phase-4-independent-review)",
                     extra_targets: set[str] | None = None) -> None:
        """Rà soát/thách thức bởi context không phải tác giả. Mọi F có kết luận; mọi vấn đề có cách xử lý của tác giả."""
        extra_targets = extra_targets if extra_targets is not None else {"report", "architecture", "summary", "roadmap"}
        is_risk = fname == "risk_review.json"
        stem = fname[:-5]
        parts = [(fname, _load(self.prj.work / fname))] if (self.prj.work / fname).is_file() else []
        bdir = self.prj.work / stem
        parts += [(f"{stem}/{q.name}", _load(q)) for q in sorted(bdir.glob("*.json"))] if bdir.is_dir() else []
        if not parts:
            self.errors.append(f"Thiếu work/{fname} (hoặc work/{stem}/<lô>.json) — chạy bước {step} trong context mới, rồi xử lý từng vấn đề.")
            return
        items_all: list[dict[str, Any]] = []
        rv: dict[str, Any] = {"items": items_all}
        for pname, data in parts:
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                self.errors.append(f"{pname}: JSON hỏng hoặc thiếu `items`.")
                continue
            if data.get("context") not in REVIEW_CONTEXTS:
                self.errors.append(f"{pname}: `context` phải là {'|'.join(REVIEW_CONTEXTS)} (người rà soát không được là phiên vừa viết).")
            rv.setdefault("context", data.get("context"))
            items_all += [dict(x, _file=pname) for x in data["items"] if isinstance(x, dict)]
        review_name = fname
        fids = {f.get("id") for f in (self.cons or {}).get("findings", [])}
        seen: set[str] = set()
        ref_rx = re.compile(r"(\b[\w.\-]+:[A-Za-z][\w\-]*\d|\bF-\d{2,}|\bRC-\d+|\bev_[0-9a-f]{18}|[\w/.\-]+\.(md|json|sql|ya?ml|tf|java|go|py|kt|swift)\b|fact:\w+)")
        for it in items_all:
            t = it.get("target")
            if is_risk and (not str(it.get("check") or "").strip() or len(str(it.get("note") or "").strip()) < 20):
                self.errors.append(f"{it['_file']} `{t}`: mỗi mục (kể cả `ok`) cần `check` (câu hỏi số mấy) và `note` ≥20 ký tự nói đã đối chiếu gì.")
            if t not in fids and t not in extra_targets:
                self.errors.append(f"{it.get('_file', review_name)}: target `{t}` không tồn tại.")
            seen.add(t)
            if it.get("verdict") not in {"ok", "issue"}:
                self.errors.append(f"{it.get('_file', review_name)} `{t}`: verdict phải là ok|issue.")
            if it.get("verdict") == "issue":
                if it.get("severity") not in REVIEW_SEVERITY:
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: vấn đề phải có `severity` là {'|'.join(REVIEW_SEVERITY)}.")
                if fname == "risk_review.json" and not str(it.get("check") or "").strip():
                    self.errors.append(f"{review_name} `{t}`: ghi `check` — đã kiểm theo câu hỏi số mấy của /phase-risk-challenge.")
                if fname == "risk_review.json" and it.get("direction") not in {"de_hon", "kho_hon"}:
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: vấn đề phải có `direction` là de_hon (dễ khai thác hơn đã nói) | kho_hon.")
                res = str(it.get("resolution") or "").strip()
                body = re.sub(r"^(Đã sửa|Giữ nguyên)\s*:\s*", "", res)
                if not res:
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: vấn đề \"{short(it.get('note'), 80)}\" chưa có `resolution` của tác giả.")
                elif not re.match(r"(Đã sửa|Giữ nguyên)\s*:", res):
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: `resolution` phải bắt đầu bằng \"Đã sửa:\" (nói sửa gì) hoặc \"Giữ nguyên:\" (kèm bằng chứng).")
                elif len(body) < 20:
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: `resolution` phải nói cụ thể đã sửa gì / vì sao giữ (≥20 ký tự sau tiền tố).")
                elif res.startswith("Giữ nguyên") and not ref_rx.search(body):
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: \"Giữ nguyên\" phải dẫn SID/F/ev_/file làm bằng chứng phản bác người rà soát.")
                elif it.get("severity") == "nang" and res.startswith("Giữ nguyên") and len(res) < 60:
                    self.errors.append(f"{it.get('_file', review_name)} `{t}`: giữ nguyên trước vấn đề nặng cần giải thích ≥60 ký tự.")
        missing = sorted(fids - seen)
        if missing:
            self.errors.append(f"{review_name} chưa rà {len(missing)} phát hiện: {', '.join(missing[:12])} (có thể chia lô: work/{stem}/<lô>.json).")
        if True:
            # Phiên bản: mục rà soát của F phải khớp bản hiện tại, hoặc tác giả đã sửa theo một vấn đề của F đó và ghi ack.
            cur = RISK.file_hashes(self.prj.work) if is_risk else review_hashes(self.prj)
            basis = _load(self.prj.work / f"{stem}_basis.json") or {}
            acked = _load(self.prj.work / f"{stem}_ack.json") or {}
            ack_cmd = "risk-ack" if is_risk else "review-ack"
            redo = f"R.4 (`render-risk --draft`)" if is_risk else "4.6 (`render --draft`)"
            for fid in sorted(fids & seen):
                its = [x for x in items_all if x.get("target") == fid]
                bases = {str(x.get("basis") or basis.get(fid) or "") for x in its}
                fixed = any(str(x.get("resolution") or "").startswith("Đã sửa") for x in its)
                if cur.get(fid) in bases:
                    continue
                if not fixed:
                    self.errors.append(f"{review_name} `{fid}`: {fid} đã đổi sau lần rà soát mà không có vấn đề nào \"Đã sửa:\" giải thích — "
                                       f"chạy lại {redo} cho {fid}.")
                elif acked.get(fid) != cur.get(fid):
                    self.errors.append(f"{review_name} `{fid}`: {fid} đổi sau khi sửa theo rà soát — nếu đây là bản sửa theo \"Đã sửa:\" thì chạy "
                                       f"`report.py {ack_cmd}`; nếu là thay đổi mới thì chạy lại {redo} cho {fid}.")
        if fname == "review.json":
            self.review = rv
        else:
            self.risk_review = rv

    def check_final(self) -> None:
        if not self.skip_review:
            self.check_review()
        cons = self.cons if isinstance(self.cons, dict) else {}
        es = cons.get("executive_summary") or {}
        if not es.get("posture"):
            self.errors.append("Thiếu executive_summary.posture.")
        km = es.get("key_messages") or []
        if not 3 <= len(km) <= 7:
            self.errors.append("executive_summary.key_messages cần 3–7 ý.")
        fids = {f.get("id") for f in cons.get("findings", [])}
        roadmap = cons.get("roadmap") or []
        if not roadmap:
            self.errors.append("Thiếu `roadmap`.")
        covered: set[str] = set()
        for a in roadmap:
            where = f"Hành động {a.get('id', '?')}"
            for field in ("id", "priority", "action", "acceptance"):
                if not a.get(field):
                    self.errors.append(f"{where}: thiếu `{field}`.")
            if a.get("priority") not in PRIORITIES:
                self.errors.append(f"{where}: priority phải là P0–P3.")
            for fid in a.get("findings", []):
                if fid not in fids:
                    self.errors.append(f"{where}: finding `{fid}` không tồn tại.")
                covered.add(fid)
        prio_of = {f.get("id"): f.get("priority") for f in cons.get("findings", [])}
        for a in roadmap:
            worst = [prio_of[x] for x in a.get("findings", []) if prio_of.get(x) in PRIORITIES]
            if worst and a.get("priority") in PRIORITIES and PRIORITIES.index(a["priority"]) > min(PRIORITIES.index(x) for x in worst):
                self.errors.append(f"Hành động {a.get('id', '?')}: ưu tiên {a['priority']} thấp hơn phát hiện nó xử lý ({min(worst)}) — "
                                   "ưu tiên của hành động phải bằng ưu tiên cao nhất của các F (ưu tiên F do Phase Risk chốt).")
        for f in cons.get("findings", []):
            if f.get("priority") in {"P0", "P1"} and f.get("id") not in covered:
                self.warnings.append(f"{f.get('id')} ({f.get('priority')}) chưa có hành động trong roadmap.")
        doc = self.prj.out / RISK_DOC_NAME
        if not doc.is_file():
            self.errors.append(f"Thiếu documents/_report/{RISK_DOC_NAME} — chạy `report.py render-risk` sau R.5.")
        else:
            newest = max([q.stat().st_mtime for q in (self.prj.work / "risk").glob("*.json")] +
                         [q.stat().st_mtime for q in [self.prj.work / "risk_review.json"] if q.is_file()] +
                         [q.stat().st_mtime for q in (self.prj.work / "risk_review").glob("*.json")] if (self.prj.work / "risk").is_dir() else [0])
            if "BẢN NHÁP" in doc.read_text(encoding="utf-8")[:400]:
                self.errors.append(f"{RISK_DOC_NAME} vẫn là bản nháp — chạy `report.py render-risk` (không --draft) sau R.5.")
            elif doc.stat().st_mtime < newest:
                self.errors.append(f"{RISK_DOC_NAME} cũ hơn dữ liệu rủi ro — chạy lại `report.py render-risk`.")
        if not cons.get("gaps"):
            self.warnings.append("`gaps` trống — gần như chắc chắn còn khoảng trống (runtime, cấu hình gateway, repo chưa phủ…).")


# ----------------------------------------------------------------------------- render

def cmd_render(prj: Project, draft: bool = False) -> int:
    chk = Checker(prj, "final", skip_review=draft)
    if chk.run() != 0:
        print("[x] Sửa lỗi ở trên trước khi render.", file=sys.stderr)
        return 1
    if draft:
        _dump(prj.work / "review_basis.json", review_hashes(prj))
    data, arch, cons = chk.inputs, chk.arch, chk.cons
    reg = {f["sid"]: f for f in data["findings"]}
    findings = sorted(cons["findings"], key=lambda f: (PRIORITIES.index(f["priority"]), sev_rank(f["risk"]), f["id"]))
    domains = {d["id"]: d for d in arch.get("domains", [])}
    today = _dt.date.today().isoformat()
    proj = arch.get("project", {}).get("name") or data["project"]
    services = data["services"]
    a = data["analysis"]

    L: list[str] = [f"# Báo cáo tổng hợp đánh giá bảo mật mã nguồn — {proj}", ""]
    if draft:
        L += ["> **BẢN NHÁP — chưa qua rà soát độc lập (bước 4.6).** Không gửi bản này.", ""]
    p1 = sum(1 for s in services if s["phase1"] == "done")
    p2 = sum(1 for s in services if s["phase2"] == "done")
    L += [f"> **Ngày lập:** {today} · **Phạm vi:** {len(services)} repository · **Nguồn:** LocalSec Phase 1 (Recon, kiến trúc, threat model — {p1}/{len(services)} repo khoá sổ), "
          f"Phase 2 (BASV — {p2}/{len(services)} repo), Phase 3 ({'có' if a['present'] else 'không có'}{', bản lite' if a.get('lite') else ''}), cấp hệ thống "
          f"({'có' if data['system']['present'] else 'không có'}).",
          "> Báo cáo chỉ tổng hợp kết quả đã qua kiểm toán bằng chứng và bác bỏ; chi tiết kỹ thuật nằm ở các file nguồn được dẫn trong từng phát hiện.",
          ""]
    L += ["## Mục lục", "", "1. Tóm tắt điều hành", "2. Kiến trúc tổng thể hệ thống", "3. Bảng tổng hợp phát hiện", "4. Chi tiết phát hiện và tác động nghiệp vụ",
          "5. Nguyên nhân gốc và rủi ro hệ thống", "6. Lộ trình khắc phục", "7. Khoảng trống đánh giá và rủi ro tồn dư", "Phụ lục A–D", ""]

    # 1
    es = cons["executive_summary"]
    L += ["## 1. Tóm tắt điều hành", "", es["posture"].strip(), ""]
    L += [f"- {k.strip()}" for k in es["key_messages"]] + [""]
    grid = Counter((f["risk"], f["confidence"]) for f in findings)
    L += ["| Mức rủi ro | " + " | ".join(CONFIDENCE_VI.values()) + " | Tổng |", "|---|" + "---|" * (len(CONFIDENCE_VI) + 1)]
    for sev in ("critical", "high", "medium", "low"):
        row = [grid.get((sev, c), 0) for c in CONFIDENCE_VI]
        L.append(f"| {SEV_VI[sev]} | " + " | ".join(map(str, row)) + f" | {sum(row)} |")
    L.append(f"| **Tổng** | " + " | ".join(str(sum(grid.get((s, c), 0) for s in SEV_VI)) for c in CONFIDENCE_VI) + f" | **{len(findings)}** |")
    n_src = len(data["findings"])
    n_rej = sum(1 for f in data["findings"] if f["disposition"] == "bac_bo") + sum(1 for x in chk.all_excluded if x.get("reason") == "bac_bo")
    ex_by = Counter(x.get("reason") for x in chk.all_excluded)
    ex_txt = ", ".join(f"{n} {EXCLUDE_REASONS_VI[r].split(' (')[0].split(' —')[0].lower()}" for r, n in ex_by.most_common() if r in EXCLUDE_REASONS_VI)
    L += ["", f"*{n_src} mục từ các phase trước được hợp nhất thành {len(findings)} phát hiện; {n_rej} mục đã bị bác bỏ/hạ cấp ở các phase trước hoặc ở bước này"
          + (f"; loại trừ ở bước tổng hợp: {ex_txt}" if ex_txt else "") + " (Phụ lục B).*", ""]
    top = [f for f in findings if f["priority"] in {"P0", "P1"}][:8]
    if top:
        L += ["**Ưu tiên xử lý ngay:**", "", "| ID | Phát hiện | Tác động nghiệp vụ | Ưu tiên |", "|---|---|---|---|"]
        L += [f"| [{f['id']}](#{_anchor(f)}) | {cell(f['title'], 110)} | {cell(f['business_impact']['consequence'], 170)} | {f['priority']} |" for f in top]
        L.append("")

    # 2
    L += ["## 2. Kiến trúc tổng thể hệ thống", ""]
    L += [(prj.work / "architecture.md").read_text(encoding="utf-8").strip(), ""]
    L += ["### 2.7 Bản đồ rủi ro theo cụm nghiệp vụ", "", "Tổng hợp tự động từ phát hiện ở mục 4 (một phát hiện có thể thuộc nhiều cụm).", "",
          "| Cụm nghiệp vụ | Service | Nghiêm trọng | Cao | Trung bình | Thấp | Phát hiện |", "|---|---|---|---|---|---|---|"]
    for did, d in domains.items():
        fs = [f for f in findings if did in f.get("domains", [])]
        c = Counter(f["risk"] for f in fs)
        L.append(f"| **{d['name']}** | {len(d.get('services', []))} | {c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} | {c.get('low', 0)} | "
                 f"{', '.join(f['id'] for f in fs) or '—'} |")
    L.append("")

    # 3
    L += ["## 3. Bảng tổng hợp phát hiện", "", "| ID | Phát hiện | Mức rủi ro | Độ tin cậy | Cụm nghiệp vụ | Phạm vi lan | Ưu tiên |", "|---|---|---|---|---|---|---|"]
    for f in findings:
        dn = ", ".join(domains[d]["name"] for d in f.get("domains", []) if d in domains)
        L.append(f"| [{f['id']}](#{_anchor(f)}) | {cell(f['title'], 110)} | {SEV_VI[f['risk']]} | {CONFIDENCE_VI[f['confidence']]} | {cell(dn, 60)} | "
                 f"{BLAST_VI.get(f['business_impact']['blast_radius'], '')} | {f['priority']} |")
    L.append("")

    impacts_all = {f.get("id"): f["business_impact"].get("level") for f in findings}
    if chk.risk_combos_derived:
        hot = [c for c in chk.risk_combos_derived if c.get("feasible") == "co"]
        cond = [c for c in chk.risk_combos_derived if c.get("feasible") == "chua_ro"]
        L += ["### 3.1 Tổ hợp làm tăng rủi ro", "",
              "Một phát hiện đưa cho kẻ tấn công đúng thứ mắt xích của phát hiện khác cần. Chỉ tổ hợp **khai thác được** kéo ưu tiên của cả hai phía lên; "
              f"{len(cond)} tổ hợp còn phụ thuộc mắt xích chưa rõ (có điều kiện, không kéo ưu tiên) liệt kê trong `documents/_report/{RISK_DOC_NAME}`.", ""]
        if hot:
            L += ["| ID | Bên cho → bên nhận | Cách ghép | Rủi ro | Ưu tiên |", "|---|---|---|---|---|"]
            L += [f"| {c.get('id')} | {c.get('giver')} → {c.get('target')} | {cell(c.get('how'), 200)} | {RISK.RISK_VI.get(c.get('risk'), '—')} | {c.get('priority') or '—'} |"
                  for c in hot]
        else:
            L.append("Chưa có tổ hợp nào khai thác được với hiện trạng bằng chứng.")
        L.append("")
    kq = RISK.key_questions_table(chk.risk_combos, chk.risk_items, impacts_all)
    if kq:
        L += ["### 3.2 Câu hỏi quyết định", "", "Các mức rủi ro *tạm tính* sẽ chốt theo câu trả lời dưới đây (script tính sẵn kết quả cho từng câu trả lời).", ""] + kq + [""]

    # 4
    L += ["## 4. Chi tiết phát hiện và tác động nghiệp vụ", "",
          "Mỗi phát hiện chỉ nêu điều cốt lõi; mô tả kỹ thuật đầy đủ, mã nguồn và `ev_...` nằm ở file nguồn.", ""]
    for f in findings:
        bi = f["business_impact"]
        dn = ", ".join(domains[d]["name"] for d in f.get("domains", []) if d in domains)
        L += [f"### {f['id']} · {f['title']}", "",
              "| Mức rủi ro | Độ tin cậy | Ưu tiên | Cụm nghiệp vụ | Service |", "|---|---|---|---|---|",
              f"| **{SEV_VI[f['risk']]}** | {CONFIDENCE_VI[f['confidence']]} | {f['priority']} | {cell(dn, 80)} | {cell(', '.join(f.get('services', [])), 120)} |", "",
              f"**Vấn đề.** {f['core_issue'].strip()}", "",
              f"**Tác động nghiệp vụ.** *{bi['capability'].strip()}* — {bi['scenario'].strip()} → **{bi['consequence'].strip()}**",
              f"Khía cạnh: {', '.join(DIMENSIONS_VI[d] for d in bi['dimensions'])} · Mức tác động: {SEV_VI[bi['level']]} · Phạm vi lan: {BLAST_VI[bi['blast_radius']]} · Cơ sở: {bi['basis'].strip()}"]
        if bi.get("conditions"):
            L.append(f"Điều kiện để xảy ra: {bi['conditions'].strip()}")
        L.append("")
        if isinstance(chk.risk_items.get(f["id"]), dict):
            L += RISK.item_markdown(f["id"], chk.risk_items[f["id"]], compact=True, derived=chk.risk_derived.get(f["id"]))
        L += [f"**Vì sao mức này.** {f['risk_rationale'].strip()}", "", f"**Khắc phục.** {f['remediation'].strip()}", ""]
        if f.get("validation"):
            L += [f"**Cần xác minh.** {f['validation'].strip()}", ""]
        if f.get("root_causes"):
            L += [f"**Nguyên nhân gốc:** {', '.join(f['root_causes'])}", ""]
        refs = []
        for sid in chk.all_sources[f["id"]]:
            mark = "**chính** · " if sid in f["source_ids"] else ""
            if sid in reg:
                refs.append(f"{mark}`{sid}` ({DISP_VI[reg[sid]['disposition']]}) → `{reg[sid]['ref']}`")
            else:
                refs.append(f"{mark}`{sid}`")
        L += [f"**Nguồn chính:** {', '.join(f'`{x}`' for x in f['source_ids'])}", "",
              "<details><summary>Toàn bộ nguồn (" + str(len(refs)) + ")</summary>", "", *[f"- {r}" for r in refs], "", "</details>", ""]

    # 5
    L += ["## 5. Nguyên nhân gốc và rủi ro hệ thống", ""]
    if data["root_causes"]:
        L += ["| ID | Nguyên nhân gốc | Trạng thái | Service bị ảnh hưởng | Phát hiện liên quan | Khắc phục tại gốc |", "|---|---|---|---|---|---|"]
        for rc in data["root_causes"]:
            fs = [f["id"] for f in findings if rc["id"] in f.get("root_causes", [])]
            L.append(f"| `{rc['id']}` | {cell(rc['title'], 130)} | {DISP_VI[rc['disposition']]} (`{rc['status']}`) | {cell(', '.join(rc['affected_services']), 90)} | "
                     f"{', '.join(fs) or '—'} | {cell(rc['remediation'], 220)} |")
        L.append("")
    else:
        L += ["Phase 3 chưa có bản đồ nguyên nhân gốc; nhóm theo nguyên nhân dựa trên phát hiện ở mục 4.", ""]
    if data["patterns"]:
        L += ["**Khuôn mẫu lặp lại xuyên service:**", ""]
        L += [f"- `{p['id']}` ({p['status']}): {p['pattern']} — {', '.join(p['services'])}" for p in data["patterns"]] + [""]

    # 6
    L += ["## 6. Lộ trình khắc phục", ""]
    for pr in PRIORITIES:
        acts = [x for x in cons["roadmap"] if x["priority"] == pr]
        if not acts:
            continue
        L += [f"### {pr}", "", "| ID | Hành động | Phát hiện | Nguyên nhân gốc | Phụ trách | Tiêu chí nghiệm thu |", "|---|---|---|---|---|---|"]
        L += [f"| {x['id']} | {cell(x['action'], 260)} | {', '.join(x.get('findings', []))} | {', '.join(x.get('root_causes', [])) or '—'} | "
              f"{cell(x.get('owner'), 40) or '—'} | {cell(x['acceptance'], 200)} |" for x in acts]
        L.append("")

    # 7
    L += ["## 7. Khoảng trống đánh giá và rủi ro tồn dư", ""]
    if cons.get("gaps"):
        L += ["| ID | Khu vực | Vì sao quan trọng | Việc cần làm |", "|---|---|---|---|"]
        L += [f"| {g.get('id', '')} | {cell(g.get('area'), 120)} | {cell(g.get('why'), 200)} | {cell(g.get('next'), 200)} |" for g in cons["gaps"]]
        L.append("")
    auto: list[str] = []
    auto += [f"Repo chưa khoá sổ Phase 1: `{s['repo']}`." for s in services if s["phase1"] != "done"]
    no_p2 = [s["repo"] for s in services if s["phase2"] != "done"]
    if no_p2:
        auto.append(f"{len(no_p2)} repo chưa khoá sổ Phase 2 (BASV): {', '.join(no_p2[:12])}{' …' if len(no_p2) > 12 else ''}.")
    inferred = [s["repo"] for s in services if s["business_intent"] and set(s["business_intent"]) <= {"inferred", "unknown"}]
    if inferred:
        auto.append(f"{len(inferred)} repo chỉ có ý định nghiệp vụ suy từ mã nguồn (không có BRD/tài liệu): {', '.join(inferred[:12])}{' …' if len(inferred) > 12 else ''}"
                    " — tác động nghiệp vụ của các repo này là suy luận.")
    prov = [f["id"] for f in findings if chk.risk_derived.get(f["id"], {}).get("state") == "tam_tinh"]
    if prov:
        auto.append(f"{len(prov)} phát hiện có mức rủi ro **tạm tính** vì còn mắt xích khai thác chưa xác nhận được ({', '.join(prov[:10])}); "
                    "câu hỏi cần xác nhận ở Phụ lục E và trong `DANH_GIA_RUI_RO.md`.")
    n_unaudited = sum(1 for f in data["findings"] if f["disposition"] == "chua_kiem_toan")
    if n_unaudited:
        auto.append(f"{n_unaudited} mismatch Phase 2 có `outcome: confirmed` nhưng trạng thái sau kiểm toán vẫn là `hypothesis` "
                    "(kiểm toán độc lập không trả verdict hoặc chỉ ủng hộ một phần) — được tính là *chưa qua kiểm toán*, không phải *đã xác nhận*.")
    auto += a.get("discrepancies", [])
    if a.get("origin_unresolved"):
        auto.append("Một số ID nguồn của chuỗi Phase 3 trỏ tới artifact trung gian, không đối chiếu được với finding: "
                    + "; ".join(a["origin_unresolved"][:6]) + ".")
    st = getattr(chk, "exclusion_stats", None)
    if st and st["excluded"]:
        auto.append(f"Ở bước tổng hợp, {st['excluded']}/{st['must']} mục bắt buộc bị loại trừ (không tính trùng lặp): "
                    + ", ".join(f"{k} {v}" for k, v in st["by_reason"].items()) + " — chi tiết từng mục ở Phụ lục B.")
    rv = getattr(chk, "review", None)
    if rv:
        issues = [i for i in rv.get("items", []) if i.get("verdict") == "issue"]
        sev = Counter(i.get("severity") for i in issues)
        kept = sum(1 for i in issues if str(i.get("resolution", "")).startswith("Giữ nguyên"))
        auto.append(f"Rà soát độc lập (bước 4.6, {REVIEW_CONTEXTS.get(rv.get('context'), rv.get('context'))}): {len(rv.get('items', []))} mục được rà, "
                    f"{len(issues)} vấn đề ({', '.join(f'{n} {REVIEW_SEVERITY.get(k, k)}' for k, n in sev.items())}); "
                    f"tác giả sửa {len(issues) - kept}, giữ nguyên có lý do {kept} (`documents/_report/work/review.json`).")
    no_cov = [s["repo"] for s in services if not s.get("code_coverage")]
    if no_cov:
        auto.append(f"{len(no_cov)}/{len(services)} repo chưa có kiểm kê độ phủ đọc mã (Phase 1 chạy trước khi có cổng độ phủ): "
                    f"{', '.join(no_cov[:12])}{' …' if len(no_cov) > 12 else ''} — model đã tự chọn file để đọc, nên độ phủ kiến trúc "
                    "của các repo này **chưa xác định**; chạy `/phase-1-coverage-topup` rồi lập lại báo cáo.")
        auto.append("Với các repo trên, đánh giá là đọc mã thủ công có giới hạn (`bounded_manual_review`); không có phát hiện ở một "
                    "khu vực không có nghĩa là khu vực đó an toàn.")
    L += ["**Giới hạn ghi nhận tự động:**", ""] + [f"- {x}" for x in auto] + [""]
    L += ["**Độ phủ đọc mã theo repo** (kiểm kê tất định của Phase 1; chi tiết `documents/<repo>/16_code_coverage.md`):", "",
          "| Repo | Tầng | Tập bắt buộc (kiến trúc) | Tập quét | Toàn bộ mã | Miễn trừ | Manh mối | Nhánh@commit |",
          "|---|---|---|---|---|---|---|---|"]
    for s in services:
        cc = s.get("code_coverage")
        if cc:
            sweep = f"{cc['sweep_pct']}%" if cc.get("sweep_required") else "không bắt buộc"
            L.append(f"| `{s['repo']}` | {cc.get('tier')} | {cc.get('mandatory_pct')}% | {sweep} | {cc.get('all_code_pct')}% | "
                     f"{cc.get('waivers')} | {cc.get('leads')} | `{s.get('git') or '—'}` |")
        else:
            L.append(f"| `{s['repo']}` | — | **chưa kiểm kê** | — | — | — | — | `{s.get('git') or '—'}` |")
    L.append("")

    # Phụ lục
    L += ["## Phụ lục A — Truy vết nguồn → phát hiện tổng hợp", "",
          "| SID gốc | Loại | Mức gốc | Trạng thái sau kiểm toán | Đưa vào |", "|---|---|---|---|---|"]
    mapping: dict[str, str] = {}
    for f in findings:
        for sid in chk.all_sources[f["id"]]:
            mapping.setdefault(sid, f["id"])
    excluded = {x["source_id"]: x for x in chk.all_excluded}
    for sid, x in excluded.items():
        mapping.setdefault(sid, f"Loại trừ (`{x['reason']}`)" + (f" → {x['into']}" if x.get("into") else ""))
    for f in sorted((reg[s] for s in mapping if s in reg), key=lambda x: (x["repo"], x["sid"])):
        L.append(f"| `{f['sid']}` | {f['kind']} | {f['sev']} | {DISP_VI[f['disposition']]} | {mapping[f['sid']]} |")
    L += [f"| `{s}` | ngoài pipeline | — | — | {m} |" for s, m in mapping.items() if s not in reg]
    L.append("")

    L += ["## Phụ lục B — Mục đã bác bỏ / hạ cấp / loại trừ", "",
          "Mọi mục bị loại khỏi danh sách phát hiện ở bước tổng hợp đều nằm ở đây, kèm lý do; không có loại trừ ẩn.", "",
          "| SID | Mức gốc | Tiêu đề | Lý do | Nguồn |", "|---|---|---|---|---|"]
    order = list(EXCLUDE_REASONS_VI)
    for sid, x in sorted(excluded.items(), key=lambda kv: (order.index(kv[1]["reason"]) if kv[1].get("reason") in order else 99, kv[0])):
        t = reg.get(sid, {}).get("title", "")
        into = f" → {x['into']}" if x.get("into") else ""
        L.append(f"| `{sid}` | {reg.get(sid, {}).get('sev', '—')} | {cell(t, 110)} | {EXCLUDE_REASONS_VI.get(x['reason'], x['reason'])}{into}: {cell(x['note'], 200)} | "
                 f"`{reg.get(sid, {}).get('ref', sid)}` |")
    auto_rej = [f for f in data["findings"] if f["disposition"] == "bac_bo" and f["sid"] not in mapping]
    for f in sorted(auto_rej, key=lambda x: x["sid"]):
        reason = f"Phase trước bác bỏ/hạ cấp (`{f['status']}`" + (f", audit `{f['audit']}`" if f["audit"] else "") + ")"
        L.append(f"| `{f['sid']}` | {cell(f['title'], 110)} | {reason} | `{f['ref']}` |")
    if a.get("refuted_or_weakened"):
        L += ["", "**Chuỗi/giả thuyết Phase 3 bị bác bỏ hoặc làm yếu:**", ""] + [f"- {x}" for x in a["refuted_or_weakened"]]
    L.append("")

    rest = [f for f in data["findings"] if f["sid"] not in mapping and f["disposition"] != "bac_bo"]
    top_rest = sorted((f for f in rest if f["sev"] in {"critical", "high"}), key=lambda x: (sev_rank(x["sev"]), x["sid"]))
    L += ["## Phụ lục C — Phát hiện khác chưa gom nhóm", "",
          f"{len(rest)} mục không đưa vào mục 4 (phần lớn là giả thuyết chưa đủ bằng chứng). Chúng là đầu vào cho đợt kiểm thử tiếp theo, "
          "không phải kết luận rằng khu vực đó an toàn.", ""]
    if top_rest:
        L += [f"**{len(top_rest)} mục mức critical/high chưa gom** (cần xác minh ở đợt sau):", "",
              "| SID | Mức | Trạng thái | Tiêu đề | Nguồn |", "|---|---|---|---|---|"]
        L += [f"| `{f['sid']}` | {f['sev']} | {DISP_VI[f['disposition']]} | {cell(f['title'], 130)} | `{f['ref']}` |" for f in top_rest]
        L.append("")
    L += ["**Thống kê toàn bộ mục chưa gom theo repo** (danh sách đầy đủ: `documents/_report/inputs/findings/<repo>.md`):", "",
          "| Repo | Critical | High | Medium | Low/khác | Tổng |", "|---|---|---|---|---|---|"]
    by_repo: dict[str, Counter[str]] = defaultdict(Counter)
    for f in rest:
        by_repo[f["repo"]][f["sev"]] += 1
    for r in sorted(by_repo):
        c = by_repo[r]
        L.append(f"| `{r}` | {c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} | {sum(c.values()) - c.get('critical', 0) - c.get('high', 0) - c.get('medium', 0)} | {sum(c.values())} |")
    L.append("")

    ext = data["external"]
    n_q = sum(len((chk.risk_items.get(f["id"]) or {}).get("open_questions") or []) for f in findings if isinstance(chk.risk_items.get(f["id"]), dict))
    if kq or n_q:
        L += ["## Phụ lục E — Câu hỏi cần xác nhận để chốt rủi ro", ""]
        L += (["Câu hỏi quyết định: xem mục 3.2."] if kq else []) + [
            f"Còn {n_q} câu hỏi theo từng mắt xích, gom theo người cần hỏi trong `documents/_report/{RISK_DOC_NAME}`. "
            "Trả lời xác nhận ghi vào `documents/_report/runtime_facts.json` rồi chạy lại Phase Risk R.3–R.5.", ""]
    L += ["## Phụ lục D — Nguồn tài liệu", "",
          "- Phase 1 theo repo: `documents/<repo>/01–15_*` (hồ sơ, API, dataflow, threat model, kiến trúc, findings, kiểm toán bằng chứng).",
          "- Phase 2 theo repo: `documents/<repo>/basv/10–19_*`; cấp hệ thống: `documents/_system/basv/`.",
          "- Cấp hệ thống Phase 1: `documents/_system/02_cross_repo_review.json`, `03_cross_repo_review.md`.",
          "- Phase 3: `documents/_analysis/` (chuỗi, nguyên nhân gốc, phản chứng)."]
    for key, label in (("tool_reports", "Báo cáo công cụ"), ("manual_reports", "Báo cáo thủ công"), ("business_docs", "Tài liệu nghiệp vụ")):
        if ext[key]:
            L.append(f"- {label}: " + ", ".join(f"`{e['path']}`" for e in ext[key][:20]) + (" …" if len(ext[key]) > 20 else ""))
    L += ["- Dữ liệu trung gian của báo cáo này: `documents/_report/inputs/`, `documents/_report/work/`.", ""]

    out = prj.out / REPORT_NAME
    _write(out, L)
    print(f"[+] Đã dựng {rel(prj.root, out)} ({len(findings)} phát hiện, {sum(len(x) for x in L) // 1024} KB).")
    return 0


def cmd_render_risk(prj: Project, draft: bool = False) -> int:
    """documents/_report/DANH_GIA_RUI_RO.md — tài liệu riêng của phase rủi ro (bản nháp cho bước thách thức R.4)."""
    chk = Checker(prj, "risk", skip_risk_review=draft)
    if chk.run() != 0:
        print("[x] Sửa lỗi ở trên trước khi dựng tài liệu rủi ro.", file=sys.stderr)
        return 1
    arch = chk.arch if isinstance(chk.arch, dict) else {}
    proj = arch.get("project", {}).get("name") or chk.inputs["project"]
    findings = sorted(chk.cons["findings"], key=lambda f: (PRIORITIES.index(f["priority"]), sev_rank(f["risk"]), f["id"]))
    impacts = {f.get("id"): (f.get("business_impact") or {}).get("level") for f in chk.cons["findings"]}
    lines = RISK.risk_document(proj, findings, chk.risk_items, chk.risk_combos, draft, _dt.date.today().isoformat(),
                               chk.risk_derived, chk.risk_combos_derived, impacts)
    out = prj.out / RISK_DOC_NAME
    _write(out, lines)
    if draft:
        _dump(prj.work / "risk_review_basis.json", RISK.file_hashes(prj.work))
        print("[+] Đã ghi phiên bản file rủi ro vào work/risk_review_basis.json (R.4 đối chiếu theo phiên bản này).")
    print(f"[+] Đã dựng {rel(prj.root, out)} ({len(findings)} phát hiện).")
    return 0


def cmd_access(prj: Project, fid: str) -> int:
    inputs = _load(prj.inputs / "inputs.json")
    cons = _load(prj.work / "consolidation.json")
    if not isinstance(inputs, dict) or not isinstance(cons, dict):
        print("[x] Cần inputs (report.py collect) và work/consolidation.json (bước 4.3).", file=sys.stderr)
        return 1
    f = next((x for x in cons.get("findings", []) if x.get("id") == fid), None)
    if f is None:
        print(f"[x] Không có {fid} trong consolidation.json.", file=sys.stderr)
        return 1
    print("\n".join(RISK.access_for(inputs["findings"], prj.docs, f)))
    return 0


def review_hashes(prj: Project) -> dict[str, str]:
    """Phiên bản mỗi F cho rà soát 4.6: mục F trong consolidation.json (bản gốc, chưa merge) + file rủi ro của F."""
    import hashlib
    cons = _load(prj.work / "consolidation.json")
    risk_h = RISK.file_hashes(prj.work)
    out = {}
    for f in (cons.get("findings", []) if isinstance(cons, dict) else []):
        if isinstance(f, dict) and f.get("id"):
            blob = json.dumps(f, ensure_ascii=False, sort_keys=True) + risk_h.get(f["id"], "")
            out[f["id"]] = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return out


def _ack(prj: Project, stem: str, cur: dict[str, str], ack_name: str) -> int:
    items: list[dict[str, Any]] = []
    for q in [prj.work / f"{stem}.json"] + (sorted((prj.work / stem).glob("*.json")) if (prj.work / stem).is_dir() else []):
        data = _load(q)
        if isinstance(data, dict):
            items += [x for x in data.get("items", []) if isinstance(x, dict)]
    fixed = sorted({x.get("target") for x in items if str(x.get("resolution") or "").startswith("Đã sửa") and str(x.get("target", "")).startswith("F-")})
    ack = _load(prj.work / ack_name) or {}
    ack.update({f: cur[f] for f in fixed if f in cur})
    _dump(prj.work / ack_name, ack)
    print(f"[+] Đã ghi phiên bản sau sửa cho {len(fixed)} phát hiện: {', '.join(fixed) or '—'} (work/{ack_name}).")
    return 0


def cmd_review_ack(prj: Project) -> int:
    """Sau 4.7: ghi phiên bản hiện tại của mọi F có vấn đề 4.6 "Đã sửa:". Sửa F đó thêm thì check lại báo cũ."""
    return _ack(prj, "review", review_hashes(prj), "review_ack.json")


def cmd_risk_ack(prj: Project) -> int:
    """Sau R.5: ghi hash hiện tại của mọi F có ít nhất một vấn đề "Đã sửa:". Sửa F đó thêm lần nữa thì check lại báo cũ."""
    return _ack(prj, "risk_review", RISK.file_hashes(prj.work), "risk_review_ack.json")


def cmd_risk_digest(prj: Project) -> int:
    import contextlib
    import io
    chk = Checker(prj, "risk", skip_risk_review=True)
    with contextlib.redirect_stdout(io.StringIO()):
        chk.run()
    if not isinstance(chk.cons, dict):
        print("[x] Cần work/consolidation.json.", file=sys.stderr)
        return 1
    print("\n".join(RISK.risk_digest(chk.cons.get("findings", []), chk.risk_items, chk.risk_derived)))
    return 0


def _anchor(f: dict[str, Any]) -> str:
    """Slug kiểu GitHub/VS Code: chữ thường, bỏ dấu câu (giữ chữ có dấu, số, _ và -), mỗi khoảng trắng thành một '-'."""
    text = f"{f['id']} · {f['title']}".strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.U)
    return text.replace(" ", "-")


# ----------------------------------------------------------------------------- status

def cmd_status(prj: Project) -> int:
    inputs = _load(prj.inputs / "inputs.json")
    if not isinstance(inputs, dict):
        print("4.1 collect      : CHƯA — chạy `report.py collect`")
        print("next: 4.1")
        return 0
    print(f"4.1 collect      : xong ({inputs['generated_at']}, {len(inputs['findings'])} mục)")
    nxt = None
    stage_steps = [("architecture", "4.2 kiến trúc    ", False, False), ("findings", "4.3 hợp nhất     ", False, False),
                   ("impact", "4.4 tác động     ", False, False), ("risk-paths", "R.1 đường khai thác", False, True),
                   ("risk", "R.2–R.3 ghép chéo, kết luận", False, True), ("risk", "R.4–R.5 thách thức rủi ro", False, False),
                   ("final", "4.5 viết báo cáo ", True, False), ("final", "4.6 rà soát độc lập", False, False)]
    for stage, label, skip, skip_risk in stage_steps:
        chk = Checker(prj, stage, skip_review=skip, skip_risk_review=skip_risk)
        # chạy im lặng
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = chk.run()
        if code == 0:
            print(f"{label}: xong")
            continue
        has_review = (prj.work / "review.json").is_file()
        if label.startswith("R.1"):
            left = chk.risk_missing.get("R.1", [])
            hint = (f"F còn thiếu/lỗi ở R.1: {', '.join(left[:15]) or '—'}{' …' if len(left) > 15 else ''}; theo /phase-risk-assessment "
                    "(R.1 mỗi F: /phase-risk-exploit-path) — `report.py check --stage risk-paths --only F-xx` để xem")
        elif label.startswith("R.2"):
            left = chk.risk_missing.get("R.3", [])
            hint = (f"ghép chéo: {chk.risk_err.get('R.2', 0)} lỗi (`report.py risk-digest`, /phase-risk-cross-link); "
                    f"kết luận: F còn lỗi {', '.join(left[:15]) or '—'} (/phase-risk-verdict mục R.3)")
        elif label.startswith("R.4"):
            hint = ("điền `resolution` trong work/risk_review.json theo /phase-risk-verdict mục R.5" if (prj.work / "risk_review.json").is_file()
                    else "`report.py render-risk --draft` rồi chạy /phase-risk-challenge trong context mới (subagent hoặc cuộc hội thoại mới)")
        elif label.startswith("4.6") and has_review:
            label = "4.7 xử lý rà soát"
            hint = "điền `resolution` (Đã sửa:/Giữ nguyên:) cho từng vấn đề theo /phase-4-report-writer mục 4.7; `report.py check --stage final` để xem"
        elif label.startswith("4.6"):
            hint = "`report.py render --draft` rồi chạy /phase-4-independent-review trong context mới (subagent hoặc cuộc hội thoại mới)"
        else:
            hint = f"`report.py check --stage {stage}` để xem"
        print(f"{label}: CHƯA ({len(chk.errors)} lỗi) — {hint}")
        nxt = nxt or label.split()[0]
        if stage == "findings" and isinstance(chk.cons, dict):
            used = getattr(chk, "used", {})
            left = Counter(f["repo"] for f in inputs["findings"] if f["must_map"] and f["sid"] not in used)
            if left:
                print("    còn phải gom: " + ", ".join(f"{r} ({n})" for r, n in left.most_common()))
        break
    rep = prj.out / REPORT_NAME
    if nxt is None:
        print(f"render          : {'có ' + rel(prj.root, rep) if rep.is_file() else 'CHƯA — chạy `report.py render`'}")
        nxt = "render" if not rep.is_file() else "xong — rà soát báo cáo theo checklist 4.6"
    print(f"next: {nxt}")
    return 0


def _risk_cell(it: Any) -> str:
    if not isinstance(it, dict):
        return "chưa"
    return f"{RISK.VERDICTS[RISK.finding_feasibility(it)]}"


def cmd_catalog(prj: Project) -> int:
    """Danh mục F-xx hiện có + tiến độ gom theo repo — đọc trước mỗi lô ở bước 4.3."""
    import contextlib
    import io
    chk = Checker(prj, "findings")
    with contextlib.redirect_stdout(io.StringIO()):
        chk.run()
    if not isinstance(chk.inputs, dict):
        print("Chưa có inputs — chạy `report.py collect`.")
        return 1
    cons = chk.cons if isinstance(chk.cons, dict) else {}
    sources = getattr(chk, "all_sources", {})
    print("| ID | Mức | Ưu tiên | Domain | RC | Số nguồn | Rủi ro (R) | Tiêu đề |")
    print("|---|---|---|---|---|---|---|---|")
    for f in cons.get("findings", []):
        print(f"| {f.get('id')} | {f.get('risk', '')} | {f.get('priority', '')} | {','.join(f.get('domains', []))} | "
              f"{','.join(f.get('root_causes', []))} | {len(sources.get(f.get('id'), f.get('source_ids', [])))} | "
              f"{_risk_cell(chk.risk_items.get(f.get('id')))} | {short(f.get('title'), 110)} |")
    if not cons.get("findings"):
        print("| — | | | | | | chưa có finding nào |")
    props = getattr(chk, "proposals", {})
    if props:
        print("\nĐề xuất F mới chờ hợp nhất (tạo F trong consolidation.json rồi `report.py promote <NEW:slug> <F-xx>`):")
        for slug, items in props.items():
            pr = next((i["proposal"] for i in items if i["proposal"]), {})
            print(f"- {slug} ({len(items)} mục, từ {', '.join(sorted({i['file'] for i in items}))}): {short(pr.get('title'), 110)}")
    used = getattr(chk, "used", {})
    total: Counter[str] = Counter()
    done: Counter[str] = Counter()
    for f in chk.inputs["findings"]:
        if f["must_map"]:
            total[f["repo"]] += 1
            done[f["repo"]] += f["sid"] in used
    print("\nTiến độ gom (mục bắt buộc): " + ", ".join(f"{r} {done[r]}/{n}" for r, n in sorted(total.items(), key=lambda x: (done[x[0]] >= x[1], x[0]))))
    todo = [r for r, n in sorted(total.items(), key=lambda x: -x[1]) if done[r] < n]
    print(f"Lô tiếp theo: {todo[0] if todo else 'không còn — chạy `check --stage findings`'}")
    return 0


def cmd_promote(prj: Project, slug: str, fid: str) -> int:
    """Đổi mọi `to: NEW:<slug>` trong work/map/*.json thành F-xx (sau khi đã tạo F đó trong consolidation.json)."""
    if not re.fullmatch(r"NEW:[a-z0-9][a-z0-9_-]*", slug) or not re.fullmatch(r"F-\d{2,}", fid):
        print("[x] Cú pháp: report.py promote NEW:<slug> F-xx", file=sys.stderr)
        return 1
    cons = _load(prj.work / "consolidation.json") or {}
    if fid not in {f.get("id") for f in cons.get("findings", [])}:
        print(f"[x] {fid} chưa có trong consolidation.json — tạo F trước rồi promote.", file=sys.stderr)
        return 1
    n = 0
    for path in sorted((prj.work / "map").glob("*.json")):
        data = _load(path)
        if not isinstance(data, dict):
            continue
        changed = False
        for it in data.get("items", []):
            if it.get("to") == slug:
                it["to"] = fid
                it.pop("proposal", None)
                n += 1
                changed = True
        if changed:
            _dump(path, data)
    print(f"[+] {slug} → {fid}: cập nhật {n} mục.")
    return 0 if n else 1


# ----------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="LocalSec Phase 4 — báo cáo tổng hợp")
    ap.add_argument("--root", default=".", help="Project root (mặc định: thư mục hiện tại)")
    ap.add_argument("--out", default=None, help="thư mục đầu ra (mặc định: <root>/documents/_report)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="gom và rút gọn kết quả Phase 1/2/3 vào documents/_report/inputs/")
    c.add_argument("--related", action="append", default=[], help="đường dẫn project liên quan (cụm nghiệp vụ khác), lặp được")
    sub.add_parser("status", help="bước nào đã xong, bước tiếp theo")
    sub.add_parser("catalog", help="danh mục F-xx hiện có và tiến độ gom theo repo")
    k = sub.add_parser("check", help="kiểm tra work/*.json theo giai đoạn")
    k.add_argument("--stage", choices=STAGES + list(STAGE_ALIASES), default="final")
    k.add_argument("--only", action="append", default=[], help="chỉ in lỗi/cảnh báo có chuỗi này (ví dụ F-03), lặp được")
    ac = sub.add_parser("access", help="(Phase Risk R.1) phần chỉ mục truy cập liên quan tới một F")
    ac.add_argument("--for", dest="for_f", required=True)
    sub.add_parser("risk-digest", help="(Phase Risk R.2) bảng ghép chéo gọn: yields của mỗi F, mắt xích chưa đạt")
    sub.add_parser("risk-ack", help="(Phase Risk R.5) ghi phiên bản file rủi ro của các F vừa sửa theo thách thức (\"Đã sửa:\")")
    sub.add_parser("review-ack", help="(4.7) ghi phiên bản của các F vừa sửa theo rà soát độc lập (\"Đã sửa:\")")
    rr = sub.add_parser("render-risk", help="dựng documents/_report/DANH_GIA_RUI_RO.md (phase rủi ro)")
    rr.add_argument("--draft", action="store_true", help="bản nháp cho bước thách thức R.4 (chưa cần risk_review.json)")
    rd = sub.add_parser("render", help="dựng documents/_report/" + REPORT_NAME)
    rd.add_argument("--draft", action="store_true", help="bản nháp cho bước rà soát độc lập (chưa cần review.json)")
    pr = sub.add_parser("promote", help="hợp nhất đề xuất NEW:<slug> trong work/map thành F-xx")
    pr.add_argument("slug")
    pr.add_argument("fid")
    args = ap.parse_args(argv)
    prj = Project(Path(args.root), Path(args.out) if args.out else None)
    if args.cmd == "collect":
        return cmd_collect(prj, args.related)
    if args.cmd == "status":
        return cmd_status(prj)
    if args.cmd == "catalog":
        return cmd_catalog(prj)
    if args.cmd == "check":
        chk = Checker(prj, args.stage)
        chk.only = args.only
        return chk.run()
    if args.cmd == "access":
        return cmd_access(prj, args.for_f)
    if args.cmd == "risk-digest":
        return cmd_risk_digest(prj)
    if args.cmd == "risk-ack":
        return cmd_risk_ack(prj)
    if args.cmd == "review-ack":
        return cmd_review_ack(prj)
    if args.cmd == "promote":
        return cmd_promote(prj, args.slug, args.fid)
    if args.cmd == "render-risk":
        return cmd_render_risk(prj, draft=args.draft)
    return cmd_render(prj, draft=args.draft)


if __name__ == "__main__":
    sys.exit(main())
