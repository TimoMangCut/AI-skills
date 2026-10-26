"""Phase 4 (reporting/report.py): collect, cổng kiểm tra fail-closed, liên kết chuỗi P3, nguồn công cụ, map theo repo, render."""
from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLKIT / "reporting"))

import report  # noqa: E402


def _w(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _project(root: Path) -> None:
    docs = root / "documents"
    for repo in ("svc-pay", "svc-gw"):
        d = docs / repo
        _w(d / "01_repo_profile.md", f"# Repository profile — {repo}\n\n## Purpose\nDịch vụ {repo}.\n- Status: `observed`\n\n## Criticality assessment\nhigh\n")
        _w(d / "02_techstack.json", {"business_capabilities": [{"name": "Thanh toán"}], "sensitive_data": [{"data_class": "PII"}], "entrypoints": [], "techstack": []})
        _w(d / "05_inbound_outbound.json", {"inbound_flows": [], "outbound_flows": [{"destination": "BSS gateway", "protocol": "HTTP"}]})
        _w(d / "12_analysis_status.json", {"semantic_coverage_diagnostics": {"distinct_files_read": 3}})
        _w(d / "basv" / "19_basv_epistemic_and_contradiction_diagnostics.json", {})
    _w(docs / "svc-pay" / "09_findings.json", {"findings": [
        {"source": "threat_model", "id": "TM-1", "category": "Callback forgery", "scenario": "Gửi callback giả", "priority": "critical", "status": "derived", "evidence_ids": ["ev_1"]},
        {"source": "threat_model", "id": "TM-2", "category": "Low thing", "priority": "low", "status": "hypothesis"},
        {"source": "architecture_review", "title": "Bị bác bỏ", "priority": "high", "status": "unknown", "notes": "[Evidence audit: unsupported; x]"},
    ]})
    _w(docs / "svc-pay" / "basv" / "18_business_aware_synthesis.json", {
        "business_workflows": [{"intent_status": "inferred"}],
        "confirmed_mismatches": [
            {"id": "CM-1", "title": "Callback không ký", "priority": "P0", "outcome": "confirmed", "status": "derived", "business_impact": "Gạch nợ giả"},
            {"id": "CM-2", "title": "Tính tiền sai nhiều hoá đơn", "priority": "P0", "outcome": "confirmed", "status": "hypothesis",
             "notes": "[Evidence audit: no verdict returned by auditor]"},
        ],
        "potential_or_unverified_mismatches": [],
    })
    _w(docs / "svc-gw" / "09_findings.json", {"findings": [
        {"source": "architecture_review", "title": "Header danh tính không ký", "priority": "high", "status": "hypothesis"},
    ]})
    _w(docs / "_analysis" / "99_project_chain_report.json", {"analysis_status": "partial", "highest_credible_chains": [{"chain_id": "C1", "chain_verdict": "partially_confirmed"}]})
    _w(docs / "_analysis" / "chains" / "chain_C1.json", {"chain_id": "C1", "title": "Callback giả", "chain_verdict": "hypothesized", "root_cause_ids": ["RC-1"],
                                                         "scope": {"repositories": ["org/svc-pay"]}, "originating_finding_ids": ["TM-1", "SC-09"]})
    _w(docs / "_analysis" / "06_root_cause_map.json", {"root_causes": [{"root_cause_id": "RC-1", "title": "Thiếu xác thực callback", "root_cause_status": "confirmed"}]})
    _w(root / "specs" / "brd.md", "# BRD")
    _w(docs / "svc-pay" / "16_code_coverage.json", {"tier": "A", "mandatory_pct": 100.0, "sweep_required": True, "sweep_pct": 100.0,
                                                    "all_code_pct": 100.0, "waivers": [{"path": "x"}], "leads": []})
    _w(root / "reports" / "svc-pay" / "sast.sarif", {"runs": [{"results": [
        {"ruleId": "CWE-89", "level": "warning", "message": {"text": "SQL injection in report query: ### chi tiết (Score: 8.1)"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/Repo.java"}, "region": {"startLine": 42}}}]},
        {"ruleId": "CWE-200", "level": "note", "message": {"text": "Verbose error"}},
    ]}]})
    _w(root / "reports" / "svc-pay" / "gitleaks.jsonl", "[]\n[]\n")


ARCH = {"project": {"name": "Demo"}, "domains": [
    {"id": "D1", "name": "Thanh toán", "description": "Thu tiền", "services": ["svc-pay"]},
    {"id": "D2", "name": "Nền tảng", "description": "Gateway", "services": ["svc-gw"]}]}
ARCH_MD = "\n\n".join(f"### 2.{i} Mục {i}\nNội dung." for i in range(1, 7)) + "\n\n```mermaid\nflowchart LR\nA-->B\n```\n"
SAST = "ext:reports/svc-pay/sast.sarif#1"


def _bi(consequence: str = "Hoá đơn thuê pin bị gạch nợ mà không có tiền vào; ERP ghi nhận doanh thu không có thật.") -> dict:
    return {"capability": "Thu tiền thuê pin và đối soát công nợ", "scenario": "Bên có credential gửi callback giả success=true cho hoá đơn bất kỳ",
            "consequence": consequence, "dimensions": ["tai_chinh"], "level": "critical", "blast_radius": "service",
            "basis": "P2 `svc-pay:CM-1` business_impact", "conditions": "Route callback reachable"}


def _finding(fid: str = "F-01", conf: str = "evidence_backed", sources=None) -> dict:
    return {
        "id": fid, "title": "Callback thanh toán không ký", "services": ["svc-pay"], "domains": ["D1"],
        "source_ids": sources or ["svc-pay:CM-1", "_analysis:C1"], "root_causes": ["RC-1"],
        "core_issue": "Callback không kiểm chữ ký.", "risk": "critical", "confidence": conf, "priority": "P0",
        "risk_rationale": "Tiền + lặp được.", "remediation": "Kiểm HMAC.", "validation": "Kiểm scope gateway.",
        "business_impact": _bi(),
    }


def _set_link(c: dict, v: str, why: str, ev: list) -> None:
    """Đổi kết luận một mắt xích `nam_giu` cùng người nắm giữ của nó (engine buộc hai thứ khớp nhau)."""
    c.update(attainable=v, why=why, evidence=ev)
    for h in c.get("holders") or []:
        h.update(attainable=v, why=why, evidence=ev)


def _risk_item(fid: str, bi: dict | None = None, **over) -> dict:
    item = {
        "finding": fid,
        "attack_paths": [{
            "id": "P1", "summary": "Gửi callback giả tới route thanh toán qua gateway",
            "actor": "Bên có client credential hợp lệ của gateway (đối tác hoặc app bị bóc tách)",
            "reaches_impact": "co",
            "entry": {"surface": "POST /callback qua gateway", "reachable": "co",
                      "why": "Route được đăng ký và không có kiểm tra chữ ký theo mismatch đã xác nhận", "evidence": ["svc-pay:CM-1"]},
            "preconditions": [{"id": "C1", "kind": "nam_giu", "need": "Có client credential có scope tới route callback", "attainable": "chua_ro",
                               "why": "Chưa biết bảng scope của gateway ở production", "evidence": [], "searched": ["svc-pay:CM-1", "inputs/05_access_index.md"],
                               "holders": [{"who": "Client của payment hub (người giữ theo thiết kế)", "attainable": "chua_ro",
                                            "why": "Chưa biết credential lưu ở đâu, ai đọc được", "evidence": [], "searched": ["svc-pay:CM-1"]}]}],
            "blocking_controls": [],
            "effort": "Vài phút nếu đã có credential; không cần kỹ năng đặc biệt",
        }],
        "actors_considered": {"ngoai": ["P1"], "nguoi_dung": ["P1"], "doi_tac": ["P1"],
                              "noi_bo": "Vận hành sửa thẳng DB được nên lỗi này không cho họ thêm khả năng nào",
                              "thanh_phan_bi_chiem": "Đường gọi thẳng từ pod bị chiếm thuộc phát hiện khác"},
        "yields": ["Không cho thêm quyền hay bí mật nào; chỉ đổi trạng thái hoá đơn"],
        "detection": {"would_be_noticed": "chua_ro", "why": "Chưa biết có đối soát hằng ngày với cổng thanh toán", "evidence": [],
                      "searched": ["svc-pay:CM-1"]},
        "likelihood": {"hardest": "P1.C1",
                       "why": "Mắt xích khó nhất là credential có scope tới route; chưa biết ai giữ credential đó ở production"},
        "rationale": "Hậu quả tài chính trực tiếp, nhưng khai thác phụ thuộc credential có scope chưa xác nhận nên còn tạm tính",
        "escalation_triggers": ["Nếu credential của portal lộ thì P1.C1 thành có và rủi ro thành critical"],
        "open_questions": [
            {"question": "Route callback nằm trong scope của client nào?", "to": "platform_devops", "affects": "P1.C1"},
            {"question": "Có đối soát giao dịch với cổng thanh toán hằng ngày không?", "to": "tai_chinh", "affects": "detection"},
        ],
    }
    item.update(over)
    return item


ALL_MUST_MAP = {"repo": "svc-pay", "items": [
    {"sid": "svc-pay:TM-1", "to": "F-01"}, {"sid": "svc-pay:CM-2", "to": "F-01"},
    {"sid": SAST, "to": "excluded", "reason": "bac_bo", "note": "Báo cáo xác minh SAST cho thấy truy vấn dùng tham số hoá, không ghép chuỗi (VERIFY-SAST.md)"},
]}


class _ReportingBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _project(self.root)
        self.prj = report.Project(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = report.main(["--root", str(self.root), *argv])
        return code, buf.getvalue()

    def _collect(self) -> dict:
        code, out = self._run("collect")
        self.assertEqual(code, 0, out)
        return json.loads((self.prj.inputs / "inputs.json").read_text(encoding="utf-8"))

    def _arch(self) -> None:
        _w(self.prj.work / "architecture.md", ARCH_MD)
        _w(self.prj.work / "architecture.json", ARCH)

    def _risk_ready(self, review: bool = True) -> None:
        """Phase rủi ro tối thiểu hợp lệ cho mọi F trong consolidation.json (tác động lấy từ consolidation)."""
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        for f in cons["findings"]:
            _w(self.prj.work / "risk" / f"{f['id']}.json", _risk_item(f["id"]))
        _w(self.prj.work / "risk" / "_combinations.json", {"method_note": "Đã xét các cặp F cùng service và cùng chuỗi P3", "combinations": []})
        if review:
            basis = report.RISK.file_hashes(self.prj.work)
            _w(self.prj.work / "risk_review.json", {"context": "fresh_subagent", "items": [
                {"target": f["id"], "verdict": "ok", "check": "1-6", "note": "Đối chiếu svc-pay:CM-1 với từng mắt xích", "basis": basis.get(f["id"])}
                for f in cons["findings"]]})


class ReportingTest(_ReportingBase):
    def test_collect_dispositions_must_map_and_discrepancy(self) -> None:
        data = self._collect()
        reg = {f["sid"]: f for f in data["findings"]}
        self.assertEqual(reg["svc-pay:TM-1"]["disposition"], "co_bang_chung")
        self.assertTrue(reg["svc-pay:TM-1"]["must_map"])
        self.assertFalse(reg["svc-pay:TM-2"]["must_map"])
        self.assertEqual(reg["svc-pay:AR-01"]["disposition"], "bac_bo")
        self.assertEqual(reg["svc-pay:AR-01"]["audit"], "unsupported")
        self.assertFalse(reg["svc-gw:AR-01"]["must_map"], "high hypothesis is optional")
        self.assertEqual(reg["_analysis:C1"]["status"], "hypothesized")
        self.assertTrue(data["analysis"]["discrepancies"])
        manifest = (self.prj.inputs / "00_manifest.md").read_text(encoding="utf-8")
        self.assertIn("Lệch giữa các artifact", manifest)
        self.assertIn("specs/brd.md", manifest)

    def test_p0_unaudited_p2_confirmation_is_not_confirmed(self) -> None:
        reg = {f["sid"]: f for f in self._collect()["findings"]}
        self.assertEqual(reg["svc-pay:CM-1"]["disposition"], "xac_nhan")
        self.assertEqual(reg["svc-pay:CM-2"]["disposition"], "chua_kiem_toan")
        self.assertTrue(reg["svc-pay:CM-2"]["must_map"])
        self._arch()
        f = _finding("F-01", "confirmed", ["svc-pay:CM-2"])
        _w(self.prj.work / "consolidation.json", {"findings": [f]})
        code, out = self._run("check", "--stage", "findings")
        self.assertIn("fail-closed", out)
        f["confidence"] = "evidence_backed"
        _w(self.prj.work / "consolidation.json", {"findings": [f]})
        self.assertNotIn("fail-closed", self._run("check", "--stage", "findings")[1])

    def test_chain_origins_linked_and_gate_blocks_confirmed(self) -> None:
        data = self._collect()
        reg = {f["sid"]: f for f in data["findings"]}
        self.assertEqual(reg["_analysis:C1"]["origin_sids"], ["svc-pay:TM-1"])
        self.assertEqual(reg["_analysis:C1"]["origin_unresolved"], ["SC-09"])
        self.assertEqual(reg["svc-pay:TM-1"]["in_chains"][0]["chain"], "_analysis:C1")
        index = (self.prj.inputs / "03_findings_index.md").read_text(encoding="utf-8")
        self.assertIn("`svc-pay:TM-1`", index)
        self._arch()
        f = _finding("F-01", "confirmed", ["svc-pay:CM-1", "svc-pay:TM-1"])
        _w(self.prj.work / "consolidation.json", {"findings": [f]})
        _w(self.prj.work / "map" / "svc-pay.json", ALL_MUST_MAP | {"items": [i for i in ALL_MUST_MAP["items"] if i["sid"] != "svc-pay:TM-1"]
                                                                   + [{"sid": "_analysis:C1", "to": "F-01"}]})
        code, out = self._run("check", "--stage", "findings")
        self.assertEqual(code, 1)
        self.assertIn("chuỗi khai thác Phase 3", out)
        f["override_note"] = "PoC trên môi trường test được phê duyệt ngày X chứng minh khai thác"
        _w(self.prj.work / "consolidation.json", {"findings": [f]})
        code, out = self._run("check", "--stage", "findings")
        self.assertEqual(code, 0, out)

    def test_tool_findings_registered_and_must_map(self) -> None:
        reg = {f["sid"]: f for f in self._collect()["findings"]}
        self.assertEqual(reg[SAST]["kind"], "ext_sast")
        self.assertEqual(reg[SAST]["sev"], "high", "CVSS 8.1 → high dù level=warning")
        self.assertTrue(reg[SAST]["must_map"])
        self.assertFalse(reg["ext:reports/svc-pay/sast.sarif#2"]["must_map"])
        self.assertTrue((self.prj.inputs / "findings" / "_ext.md").is_file())
        self._arch()
        _w(self.prj.work / "consolidation.json", {"findings": [_finding()]})
        _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": [i for i in ALL_MUST_MAP["items"] if i["sid"] != SAST]})
        code, out = self._run("check", "--stage", "findings")
        self.assertIn(SAST, out)
        _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": [
            {"sid": "svc-pay:TM-1", "to": "F-01"}, {"sid": "svc-pay:CM-2", "to": "F-01"},
            {"sid": SAST, "to": "excluded", "reason": "bac_bo", "note": "dương tính giả"}]})
        code, out = self._run("check", "--stage", "findings")
        self.assertIn("phản bác cụ thể", out)
        self.assertIn("dẫn báo cáo xác minh", out)

    def test_business_impact_quality_gates(self) -> None:
        self._collect()
        self._arch()
        f1, f2 = _finding("F-01"), _finding("F-02", sources=["svc-pay:CM-2"])
        f2["business_impact"] = _bi()  # trùng nguyên câu với F-01
        f1["business_impact"] = _bi("Có thể gây thiệt hại tài chính.")
        f1["business_impact"]["basis"] = "Kinh nghiệm chung"
        _w(self.prj.work / "consolidation.json", {"findings": [f1, f2]})
        _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": [i for i in ALL_MUST_MAP["items"] if i["sid"] != "svc-pay:CM-2"]})
        code, out = self._run("check", "--stage", "impact")
        self.assertEqual(code, 1)
        self.assertIn("chung chung", out)
        self.assertIn("basis phải dẫn", out)
        f1["business_impact"] = _bi()
        _w(self.prj.work / "consolidation.json", {"findings": [f1, f2]})
        code, out = self._run("check", "--stage", "impact")
        self.assertIn("cùng một câu consequence", out)

    def test_missing_must_map_then_full_render(self) -> None:
        self._collect()
        self._arch()
        _w(self.prj.work / "consolidation.json", {"findings": [_finding()]})
        code, out = self._run("check", "--stage", "findings")
        self.assertEqual(code, 1)
        self.assertIn("svc-pay:TM-1", out)
        _w(self.prj.work / "map" / "svc-pay.json", ALL_MUST_MAP)
        code, out = self._run("check", "--stage", "impact")
        self.assertEqual(code, 0, out)
        self.assertIn("4.4 tác động     : xong", self._run("status")[1])
        code, out = self._run("check", "--stage", "risk")
        self.assertIn("chưa có work/risk", out)
        self._risk_ready(review=False)
        code, out = self._run("check", "--stage", "risk")
        self.assertIn("risk_review.json", out)
        self.assertEqual(self._run("render-risk", "--draft")[0], 0)
        self.assertIn("BẢN NHÁP", (self.prj.out / report.RISK_DOC_NAME).read_text(encoding="utf-8"))
        self._risk_ready()
        code, out = self._run("check", "--stage", "risk")
        self.assertEqual(code, 0, out)
        self.assertEqual(self._run("render-risk")[0], 0)
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        cons.update({
            "executive_summary": {"posture": "Tư thế.", "key_messages": ["a F-01", "b", "c"]},
            "roadmap": [{"id": "A-01", "priority": "P0", "action": "Kiểm HMAC", "findings": ["F-01"], "acceptance": "401"}],
            "gaps": [{"id": "G-01", "area": "Self-check: x", "why": "y", "next": "z"}],
        })
        _w(self.prj.work / "consolidation.json", cons)
        # 4.5: bản nháp được, bản cuối bị chặn khi chưa rà soát độc lập
        code, out = self._run("render", "--draft")
        self.assertEqual(code, 0, out)
        self.assertIn("BẢN NHÁP", (self.prj.out / report.REPORT_NAME).read_text(encoding="utf-8"))
        self.assertIn("4.6 rà soát độc lập: CHƯA", self._run("status")[1])  # chưa có review.json
        code, out = self._run("render")
        self.assertEqual(code, 1)
        self.assertIn("review.json", out)
        review = {"context": "same_session", "items": [{"target": "F-01", "verdict": "issue", "check": "2", "note": "x"}]}
        _w(self.prj.work / "review.json", review)
        code, out = self._run("check", "--stage", "final")
        self.assertIn("fresh_subagent", out)
        self.assertIn("chưa có `resolution`", out)
        self.assertIn("`severity`", out)
        review["context"] = "fresh_subagent"
        review["items"][0]["severity"] = "nang"
        review["items"][0]["resolution"] = "ok"
        _w(self.prj.work / "review.json", review)
        self.assertIn("phải bắt đầu bằng", self._run("check", "--stage", "final")[1])
        review["items"][0]["resolution"] = "Giữ nguyên: evidence_backed là đúng vì chuỗi `_analysis:C1` dựng từ svc-pay:TM-1 vẫn hypothesized"
        _w(self.prj.work / "review.json", review)
        code, out = self._run("render")
        self.assertEqual(code, 0, out)
        text = (self.prj.out / report.REPORT_NAME).read_text(encoding="utf-8")
        self.assertNotIn("BẢN NHÁP", text)
        self.assertIn("Rà soát độc lập (bước 4.6", text)
        self.assertIn("giữ nguyên có lý do 1", text)
        for needle in ("Khả năng khai thác thực tế: Tạm tính", "| C1 | Có client credential", "Phụ lục E", "rủi ro thành critical"):
            self.assertIn(needle, text)
        self.assertEqual(report.disp_root_cause("strongly_supported"), "xac_nhan_mot_phan")
        self.assertIn("Loại trừ (`bac_bo`)", text)
        for needle in ("## 1. Tóm tắt điều hành", "### 2.7 Bản đồ rủi ro theo cụm nghiệp vụ", "### F-01 · Callback thanh toán không ký",
                       "ERP ghi nhận doanh thu", "`svc-pay:TM-1`", "Phụ lục B", "`svc-pay:AR-01`", "hypothesized",
                       "chưa qua kiểm toán", "`svc-gw:AR-01`", "SC-09", "Độ phủ đọc mã theo repo", "| `svc-pay` | A | 100.0% |",
                       "**chưa kiểm kê**", "/phase-1-coverage-topup"):
            self.assertIn(needle, text)
        anchor = re.search(r"\]\(#(f-01[^)]*)\)", text).group(1)
        self.assertEqual(anchor, "f-01--callback-thanh-toán-không-ký")
        self.assertIn("next: xong", self._run("status")[1])
        # 4.6 có phiên bản: sửa F sau rà soát mà không có "Đã sửa:" thì phải rà lại
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        cons["findings"][0]["core_issue"] = "Callback không kiểm chữ ký (sửa sau rà soát)."
        _w(self.prj.work / "consolidation.json", cons)
        self.assertIn("4.6 (`render --draft`)", self._run("check", "--stage", "final")[1])
        review["items"][0]["resolution"] = "Đã sửa: core_issue nói rõ callback không kiểm chữ ký theo svc-pay:CM-1"
        _w(self.prj.work / "review.json", review)
        self.assertIn("review-ack", self._run("check", "--stage", "final")[1])
        self.assertEqual(self._run("review-ack")[0], 0)
        code, out = self._run("check", "--stage", "final")
        self.assertEqual(code, 0, out)


class ReportingGateTest(_ReportingBase):
    """Các lỗ có thể bị lách: loại trừ hàng loạt, F khổng lồ, đề xuất NEW: chưa hợp nhất."""

    def _base(self) -> None:
        self._collect()
        self._arch()
        _w(self.prj.work / "consolidation.json", {"findings": [_finding()]})

    def test_exclusion_loopholes_closed_and_visible(self) -> None:
        self._base()
        items = [i for i in ALL_MUST_MAP["items"] if i["sid"] != "svc-pay:TM-1"]
        _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": items + [
            {"sid": "svc-pay:TM-1", "to": "excluded", "reason": "muc_thap", "note": "thấp"}]})
        code, out = self._run("check", "--stage", "findings")
        self.assertEqual(code, 1)
        self.assertIn("không được hạ mục critical", out)
        self.assertIn("≥25 ký tự", out)
        self.assertIn("tỷ lệ cao", out)

    def test_giant_finding_needs_scope_note(self) -> None:
        self._base()
        _w(self.prj.work / "map" / "svc-pay.json", ALL_MUST_MAP)
        old = report.GIANT_F_ERROR
        report.GIANT_F_ERROR = 2
        try:
            code, out = self._run("check", "--stage", "findings")
            self.assertIn("gần như chắc chắn đang trộn", out)
            cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
            cons["findings"][0]["scope_note"] = "Một điểm yếu: callback không ký, sửa chung bằng HMAC"
            _w(self.prj.work / "consolidation.json", cons)
            self.assertEqual(self._run("check", "--stage", "findings")[0], 0)
        finally:
            report.GIANT_F_ERROR = old

    def test_new_proposals_must_be_promoted(self) -> None:
        self._base()
        items = [i for i in ALL_MUST_MAP["items"] if i["sid"] != "svc-pay:CM-2"]
        _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": items + [
            {"sid": "svc-pay:CM-2", "to": "NEW:multi-bill", "proposal": {"title": "Tính tiền sai khi gộp hoá đơn"}}]})
        code, out = self._run("check", "--stage", "findings")
        self.assertEqual(code, 1)
        self.assertIn("chưa hợp nhất", out)
        self.assertNotIn("chưa gom: `svc-pay:CM-2`", out)
        self.assertIn("NEW:multi-bill", self._run("catalog")[1])
        self.assertEqual(self._run("promote", "NEW:multi-bill", "F-02")[0], 1, "F-02 chưa tồn tại")
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        f2 = _finding("F-02", sources=["svc-pay:CM-2"])
        f2["business_impact"] = _bi("Khách hàng gộp nhiều hoá đơn đổi pin chỉ bị thu tiền hoá đơn đầu tiên, phần còn lại thất thu.")
        cons["findings"].append(f2)
        _w(self.prj.work / "consolidation.json", cons)
        code, out = self._run("promote", "NEW:multi-bill", "F-02")
        self.assertEqual(code, 0, out)
        code, out = self._run("check", "--stage", "findings")
        self.assertEqual(code, 0, out)


class RiskPhaseTest(_ReportingBase):
    """Phase rủi ro: khả thi, rủi ro, ưu tiên do engine suy ra từ mắt xích; mọi kết luận có lý do và bằng chứng thật."""

    def _setup(self, n: int = 1) -> None:
        self._collect()
        self._arch()
        fs = [_finding()] + ([_finding("F-02", sources=["svc-pay:CM-2"])] if n > 1 else [])
        if n > 1:
            fs[1]["business_impact"] = _bi("Khách hàng gộp nhiều hoá đơn đổi pin chỉ bị thu tiền hoá đơn đầu tiên, phần còn lại thất thu.")
            _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": [i for i in ALL_MUST_MAP["items"] if i["sid"] != "svc-pay:CM-2"]})
        else:
            _w(self.prj.work / "map" / "svc-pay.json", ALL_MUST_MAP)
        _w(self.prj.work / "consolidation.json", {"findings": fs})
        self._risk_ready()

    def _put(self, item: dict, fid: str = "F-01", stage: str = "risk") -> tuple[int, str]:
        _w(self.prj.work / "risk" / f"{fid}.json", item)
        return self._run("check", "--stage", stage)

    def test_access_index_groups_secrets_scope_network(self) -> None:
        import risk as R
        doc = "\n".join(R.access_index([
            {"sid": "a:1", "title": "client_secret nằm trong seed SQL", "impact": "", "disposition": "co_bang_chung"},
            {"sid": "a:2", "title": "Route không có NetworkPolicy", "impact": "", "disposition": "can_xac_minh"},
            {"sid": "a:3", "title": "Secret cũ", "impact": "", "disposition": "bac_bo"}]))
        self.assertIn("`a:1`", doc)
        self.assertIn("`a:2`", doc)
        self.assertNotIn("`a:3`", doc, "mục đã bác bỏ không vào chỉ mục")
        docs = self.root / "documents"
        (docs / "svc-x").mkdir(parents=True)
        (docs / "svc-x" / "03_api_inventory.md").write_text(
            "- callback chỉ gắn client_scope cho client PAYHUBHANDLERX9 (không IP policy)\n"
            "- seed client_id ANDROIDAPP và client_secret K9ZQ7XW2PLM4 cho mọi môi trường\n"
            "- password của client: Q7W8E9R0T1Y2 trong seed\n", encoding="utf-8")
        doc = chr(10).join(R.access_index([], docs))
        self.assertIn("`PAYHUBHANDLERX9`", doc)
        self.assertIn("`ANDROIDAPP`", doc)
        self.assertNotIn("K9ZQ7XW2PLM4", doc, "không chép chuỗi trông như bí mật")
        self.assertNotIn("Q7W8E9R0T1Y2", doc, "dòng có 'password' cũng không chép chuỗi lẫn số")
        self.assertIn("`documents/svc-x/03_api_inventory.md`: 1, 2", doc)
        f = {"id": "F-09", "title": "x", "services": ["svc-x"], "source_ids": []}
        part = chr(10).join(R.access_for([{"sid": "svc-y:1", "repo": "svc-y", "title": "mật khẩu DB trong repo", "impact": "", "disposition": "co_bang_chung"},
                                         {"sid": "svc-y:2", "repo": "svc-y", "title": "client_secret của client kiểm thử trong seed", "impact": "", "disposition": "co_bang_chung"}],
                                        docs, f))
        self.assertNotIn("`svc-y:1`", part, "bí mật ở repo khác, không nói về client/token, không vào bản lọc")
        self.assertIn("`svc-y:2`", part, "client/seed ở repo khác vẫn giữ: thường là người nắm giữ cho F này")

    def test_controls_count_only_when_their_existence_is_proven(self) -> None:
        import risk as R
        p = {"id": "P1", "entry": {"reachable": "co"}, "preconditions": [{"id": "C1", "attainable": "co"}],
             "blocking_controls": [{"control": "Có thể có NetworkPolicy ngoài repo", "exists": "chua_ro", "effective": "chua_ro"}]}
        self.assertEqual(R.path_feasibility(p), "co", "kiểm soát giả định không treo được đường")
        p["blocking_controls"][0].update(exists="co", effective="chua_ro")
        self.assertEqual(R.path_feasibility(p), "chua_ro")
        p["blocking_controls"][0]["effective"] = "co"
        self.assertEqual(R.path_feasibility(p), "khong")
        p["preconditions"][0]["attainable"] = "chua_ro"
        p["blocking_controls"] = []
        self.assertEqual(R.path_feasibility(p, {"P1.C1": "co"}), "co", "mô phỏng câu trả lời của câu hỏi quyết định")
        self._setup()
        item = _risk_item("F-01")
        item["attack_paths"][0]["blocking_controls"] = [{"control": "Allowlist IP ở gateway", "exists": "co", "exists_evidence": [],
                                                         "effective": "co", "why": "Chỉ IP của cổng thanh toán", "evidence": ["svc-pay:CM-1"]}]
        code, out = self._put(item)
        self.assertIn("cần `exists_evidence`", out)
        item["attack_paths"][0]["blocking_controls"][0].update(exists="chua_ro")
        code, out = self._put(item)
        self.assertIn("không thể ghi `effective: co`", out)

    def test_risk_and_priority_are_derived(self) -> None:
        import risk as R
        base = _risk_item("F-01")
        self.assertEqual(R.derive(base, "critical")["risk"], "critical")
        self.assertEqual(R.derive(base, "critical")["priority"], "P1", "tạm tính: mức tác động, ưu tiên hạ một bậc")
        _set_link(base["attack_paths"][0]["preconditions"][0], "co", "Client secret của portal nằm trong bundle JS công khai", ["svc-pay:CM-1"])
        self.assertEqual((R.derive(base, "critical")["risk"], R.derive(base, "critical")["priority"]), ("critical", "P0"))
        _set_link(base["attack_paths"][0]["preconditions"][0], "khong", "Route chỉ nhận IP của cổng thanh toán theo cấu hình", ["svc-pay:CM-1"])
        self.assertEqual((R.derive(base, "critical")["risk"], R.derive(base, "critical")["priority"]), ("low", "P3"))
        self._setup()
        item = _risk_item("F-01", risk="high", priority="P1")
        code, out = self._put(item)
        self.assertIn("engine suy ra 'critical'", out)
        item = _risk_item("F-01")
        _set_link(item["attack_paths"][0]["preconditions"][0], "co", "Client secret của portal nằm trong bundle JS công khai", ["svc-pay:CM-1"])
        item["risk_override"] = {"risk": "low", "reason": "x" * 90, "evidence": ["svc-pay:CM-1"]}
        code, out = self._put(item)
        self.assertIn("chỉ được hạ đúng một bậc", out)
        item["risk_override"]["risk"] = "high"
        code, out = self._put(item)
        self.assertNotIn("risk_override", out)
        item = _risk_item("F-01", risk_override={"risk": "low", "reason": "y" * 90, "evidence": ["svc-pay:CM-1"]})
        code, out = self._put(item)
        self.assertIn("còn mắt xích chưa rõ thì không ghi đè", out)

    def test_evidence_must_be_real_and_reasons_not_guesses(self) -> None:
        self._setup()
        (self.root / "documents" / "notes").mkdir(parents=True, exist_ok=True)
        for bad, msg in (("documents/", "không phải file"), ("documents/_report/work/consolidation.json", "chính báo cáo"),
                         ("F-01", "tự trích"), ("svc-pay:AR-01", "bị bác bỏ"), ("ev_000000000000000000", "không có trong kết quả")):
            item = _risk_item("F-01")
            item["attack_paths"][0]["entry"]["evidence"] = [bad]
            code, out = self._put(item)
            self.assertIn(msg, out, bad)
        for why in ("Route nhieu kha nang mo ra Internet vi gateway la diem vao duy nhat",
                    "Route nhiều  khả năng mở ra Internet vì gateway là điểm vào duy nhất",
                    "Route nhiều khả năng mở ra Internet vì gateway là điểm vào"):
            item = _risk_item("F-01")
            item["attack_paths"][0]["entry"]["why"] = why
            code, out = self._put(item)
            self.assertIn("câu phỏng đoán", out, why)
        item = _risk_item("F-01")
        item["attack_paths"][0]["preconditions"][0].pop("searched")
        item["attack_paths"][0]["entry"]["why"] = "R.5: đã sửa — route có thật và không kiểm chữ ký theo mismatch"
        item["detection"]["why"] = "Secret: K9ZQ7XW2PLM4AB nằm trong file cấu hình nên đối soát không biết"
        code, out = self._put(item)
        self.assertIn("phải ghi `searched`", out)
        self.assertIn("ghi chú quá trình", out)
        self.assertIn("giá trị bí mật", out)
        item = _risk_item("F-01", rationale=[""] * 10, escalation_triggers=[""])
        code, out = self._put(item)
        self.assertIn("`rationale` (≥60", out)
        self.assertIn("escalation_triggers", out)
        item = _risk_item("F-01")
        item["open_questions"][0]["to"] = "Team Payment"
        self.assertIn("`to` phải là một trong", self._put(item)[1])

    def test_wrong_types_do_not_crash(self) -> None:
        self._setup()
        for over in ({"likelihood": "cao"}, {"attack_paths": ["P1"]}, {"detection": "khong"}, {"actors_considered": "tất cả"}):
            item = _risk_item("F-01", **over)
            code, out = self._put(item)
            self.assertEqual(code, 1, over)
            self.assertIn("[x]", out)
            self.assertEqual(self._run("status")[0], 0)
            self.assertEqual(self._run("catalog")[0], 0)
        item = _risk_item("F-01")
        item["attack_paths"][0]["entry"] = "POST /cb"
        self.assertIn("phải là object", self._put(item)[1])

    def test_caps_and_paths_stage(self) -> None:
        self._setup()
        item = _risk_item("F-01")
        p = item["attack_paths"][0]
        item["attack_paths"] = [dict(p, id=f"P{i}") for i in range(1, 6)]
        item["open_questions"] = [dict(item["open_questions"][0], question=f"Câu hỏi số {i} về scope route?") for i in range(11)]
        code, out = self._put(item)
        self.assertIn("vượt trần 4", out)
        self.assertIn("vượt trần 10", out)
        item = _risk_item("F-01")
        for k in ("likelihood", "rationale", "escalation_triggers"):
            item.pop(k)
        code, out = self._put(item, stage="risk-paths")
        self.assertEqual(code, 0, out)
        self.assertIn("R.1 đường khai thác: xong", self._run("status")[1])
        code, out = self._put(item, stage="risk")
        self.assertIn("likelihood", out)

    def test_other_outcome_path_goes_back_to_impact(self) -> None:
        self._setup()
        item = _risk_item("F-01")
        p2 = json.loads(json.dumps(item["attack_paths"][0]))
        p2.update(id="P2", reaches_impact="khong", outcome="Chỉ đẩy hoá đơn của người khác sang PAY_FAILED, không gạch nợ")
        _set_link(p2["preconditions"][0], "co", "Client secret của portal nằm trong bundle JS công khai", ["svc-pay:CM-1"])
        item["attack_paths"].append(p2)
        item["actors_considered"]["ngoai"] = ["P1", "P2"]
        code, out = self._put(item)
        self.assertIn("hậu quả khác 4.4", out)

    def test_key_questions_give_outcomes_for_each_answer(self) -> None:
        import risk as R
        self._setup(n=2)
        items = {"F-01": _risk_item("F-01"), "F-02": _risk_item("F-02")}
        q = {"id": "Q1", "question": "Route callback nằm trong scope của những client nào?", "to": "platform_devops",
             "unlocks": ["F-01.P1.C1", "F-02.P1.C1"]}
        out = R.key_question_outcomes(q, items, {"F-01": "critical", "F-02": "high"})
        self.assertEqual((out["F-01"]["co"]["risk"], out["F-01"]["co"]["priority"]), ("critical", "P0"))
        self.assertEqual((out["F-02"]["khong"]["risk"], out["F-02"]["khong"]["priority"]), ("low", "P3"))
        ctx = R.RiskContext(self.root, self.root, {}, {"F-01", "F-02"}, set())
        combos = {"method_note": "Đã xét cặp F-01/F-02: không bên nào cho bên kia thứ nó cần", "combinations": [], "key_questions": [q]}
        self.assertEqual(R.check_combinations(combos, items, ctx)[0], [])
        q["unlocks"] = ["F-01.P1.entry", "F-01.P9.C1"]
        errors = R.check_combinations(combos, items, ctx)[0]
        self.assertTrue(any("không tồn tại" in e for e in errors))
        self.assertTrue(any("chỉ đưa mắt xích đang `chua_ro`" in e for e in errors))
        self.assertTrue(any("≥2 F" in e for e in errors))
        q["unlocks"] = ["F-01.P1.C1", "F-02.P1.C1"]
        _w(self.prj.work / "risk" / "_combinations.json", combos)
        for fid in ("F-01", "F-02"):
            it = _risk_item(fid)
            it["open_questions"] = [x for x in it["open_questions"] if x["affects"] != "P1.C1"]
            _w(self.prj.work / "risk" / f"{fid}.json", it)
        code, out = self._run("check", "--stage", "risk", "--only", "risk/")
        self.assertNotIn("phải có câu hỏi", out, "mắt xích nằm trong câu hỏi quyết định thì không cần câu hỏi riêng")
        self.assertEqual(self._run("render-risk", "--draft")[0], 0)
        doc = (self.prj.out / report.RISK_DOC_NAME).read_text(encoding="utf-8")
        self.assertIn("### Câu hỏi quyết định", doc)
        self.assertIn("F-01: Nghiêm trọng/P0", doc)
        self.assertNotIn("[F-01 · `P1.C1`]", doc)
        self.assertIn("↳ H1", doc)
        self.assertIn("Đã xét các loại người khai thác", doc)

    def test_holders_actor_coverage(self) -> None:
        self._setup()
        item = _risk_item("F-01")
        c = item["attack_paths"][0]["preconditions"][0]
        c["holders"].append({"who": "Client kiểm thử seed trong migration", "attainable": "co",
                             "why": "Secret nằm rõ trong file seed của repo, ai đọc repo cũng có", "evidence": ["svc-pay:CM-1"]})
        self.assertIn("không khớp danh sách người nắm giữ", self._put(item)[1])
        c.pop("holders")
        self.assertIn("phải có `holders`", self._put(item)[1])
        item = _risk_item("F-01")
        item["attack_paths"][0]["preconditions"][0]["kind"] = "biet"
        self.assertIn("chỉ dùng cho mắt xích `nam_giu`", self._put(item)[1])
        item = _risk_item("F-01")
        item["actors_considered"].pop("doi_tac")
        item["actors_considered"]["noi_bo"] = "không"
        out = self._put(item)[1]
        self.assertIn("actors_considered.doi_tac", out)
        self.assertIn("actors_considered.noi_bo", out)
        item = _risk_item("F-01")
        item.pop("yields")
        self.assertIn("cần `yields`", self._put(item)[1])
        self.assertEqual(self._put(_risk_item("F-01"))[0], 0)

    def test_enabled_by_sid_ties_back_to_consolidation(self) -> None:
        self._setup()
        item = _risk_item("F-01")
        item["attack_paths"][0]["preconditions"][0]["enabled_by"] = ["svc-pay:CM-2"]
        self.assertIn("là nguồn của chính F-01", self._put(item)[1])
        _w(self.prj.work / "map" / "svc-pay.json", {"repo": "svc-pay", "items": [
            {"sid": "svc-pay:TM-1", "to": "F-01"},
            {"sid": "svc-pay:CM-2", "to": "excluded", "reason": "bac_bo", "note": "Bác bỏ theo kiểm toán"},
            ALL_MUST_MAP["items"][2]]})
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        cons["findings"][0]["source_ids"] = ["svc-pay:CM-1", "_analysis:C1"]
        _w(self.prj.work / "consolidation.json", cons)
        self.assertIn("bị loại trừ ở 4.3", self._put(item)[1])

    def test_combinations_are_derived_and_lift_priority(self) -> None:
        self._setup(n=2)
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        cons["findings"][1]["business_impact"]["level"] = "medium"
        _w(self.prj.work / "consolidation.json", cons)
        f1 = _risk_item("F-01")
        f1["attack_paths"][0]["preconditions"][0]["enabled_by"] = ["F-02"]
        _w(self.prj.work / "risk" / "F-01.json", f1)
        code, out = self._run("check", "--stage", "risk")
        self.assertIn("chưa có tổ hợp tương ứng", out)
        combos = {"method_note": "Xét F-01 với F-02 cùng service thanh toán", "combinations": [
            {"id": "X1", "giver": "F-02", "target": "F-01", "link": "F-01.P1.C1",
             "how": "F-02 cho biết mã hoá đơn và credential của người khác, đó là thứ P1.C1 của F-01 cần", "risk": "high"}]}
        _w(self.prj.work / "risk" / "_combinations.json", combos)
        code, out = self._run("check", "--stage", "risk")
        self.assertIn("engine suy ra", out, "khả thi/rủi ro của tổ hợp không do model gán")
        combos["combinations"][0].pop("risk")
        _w(self.prj.work / "risk" / "_combinations.json", combos)
        # F-01.P1.C1 = co chỉ nhờ F-02 mà F-02 chưa khai thác được → lỗi
        _set_link(f1["attack_paths"][0]["preconditions"][0], "co", "F-02 làm lộ credential có scope tới route callback", ["F-02"])
        _w(self.prj.work / "risk" / "F-01.json", f1)
        self.assertIn("chưa khai thác được", self._run("check", "--stage", "risk")[1])
        # F-02 khai thác được → F-01 khai thác được, tổ hợp khả thi, ưu tiên F-02 bị kéo lên theo tổ hợp
        f2 = _risk_item("F-02")
        _set_link(f2["attack_paths"][0]["preconditions"][0], "co", "Client secret của portal nằm trong bundle JS công khai", ["svc-pay:CM-2"])
        _w(self.prj.work / "risk" / "F-02.json", f2)
        f1["open_questions"] = [q for q in f1["open_questions"] if q["affects"] != "P1.C1"]
        _w(self.prj.work / "risk" / "F-01.json", f1)
        _w(self.prj.work / "risk_review.json", {"context": "fresh_subagent", "items": [
            {"target": x, "verdict": "ok", "check": "1-6", "note": "Đối chiếu svc-pay:CM-1 và svc-pay:CM-2"} for x in ("F-01", "F-02")]})
        self._run("render-risk", "--draft")
        rv = json.loads((self.prj.work / "risk_review_basis.json").read_text(encoding="utf-8"))
        self.assertIn("F-01", rv)
        code, out = self._run("check", "--stage", "risk")
        self.assertEqual(code, 0, out)
        chk = report.Checker(self.prj, "risk")
        with redirect_stdout(io.StringIO()):
            chk.run()
        self.assertEqual(chk.risk_combos_derived[0]["feasible"], "co")
        self.assertEqual(chk.risk_derived["F-02"]["priority"], "P0", "bên cho được kéo lên theo tổ hợp critical khả thi")
        self.assertEqual(chk.risk_derived["F-02"]["lifted_by"], ["X1"])

    def test_reviews_batched_versioned_and_substantive(self) -> None:
        self._setup()
        (self.prj.work / "risk_review.json").unlink()
        _w(self.prj.work / "risk_review" / "lo1.json", {"context": "fresh_subagent", "items": [{"target": "F-01", "verdict": "ok"}]})
        out = self._run("check", "--stage", "risk")[1]
        self.assertIn("cần `check`", out)
        self._run("render-risk", "--draft")
        _w(self.prj.work / "risk_review" / "lo1.json", {"context": "fresh_subagent", "items": [
            {"target": "F-01", "verdict": "issue", "severity": "vua", "direction": "de_hon", "check": "3", "note": "Thiếu client kiểm thử trong seed",
             "resolution": "Đã sửa:"}]})
        self.assertIn("≥20 ký tự sau tiền tố", self._run("check", "--stage", "risk")[1])
        _w(self.prj.work / "risk_review" / "lo1.json", {"context": "fresh_subagent", "items": [
            {"target": "F-01", "verdict": "ok", "check": "1-6", "note": "Đối chiếu svc-pay:CM-1 với file rủi ro"}]})
        self.assertEqual(self._run("check", "--stage", "risk")[0], 0)
        item = _risk_item("F-01")
        item["rationale"] += " (sửa sau rà soát)"
        _w(self.prj.work / "risk" / "F-01.json", item)
        self.assertIn("đã đổi sau lần rà soát", self._run("check", "--stage", "risk")[1])
        _w(self.prj.work / "risk_review" / "lo1.json", {"context": "fresh_subagent", "items": [
            {"target": "F-01", "verdict": "issue", "severity": "vua", "direction": "de_hon", "check": "3", "note": "Rationale chưa nói mắt xích quyết định",
             "resolution": "Đã sửa: rationale nói rõ mắt xích P1.C1 là mắt xích quyết định"}]})
        self.assertIn("risk-ack", self._run("check", "--stage", "risk")[1], "sửa theo rà soát phải được ghi phiên bản")
        self.assertEqual(self._run("risk-ack")[0], 0)
        self.assertEqual(self._run("check", "--stage", "risk")[0], 0)
        item["rationale"] += " (đổi thêm, không qua rà soát)"
        _w(self.prj.work / "risk" / "F-01.json", item)
        self.assertIn("đổi sau khi sửa theo rà soát", self._run("check", "--stage", "risk")[1])

    def test_roadmap_and_risk_doc_gate_final(self) -> None:
        self._setup()
        cons = json.loads((self.prj.work / "consolidation.json").read_text(encoding="utf-8"))
        cons.update({"executive_summary": {"posture": "Tư thế.", "key_messages": ["a", "b", "c"]},
                     "roadmap": [{"id": "A-01", "priority": "P3", "action": "Kiểm HMAC", "findings": ["F-01"], "acceptance": "401"}],
                     "gaps": [{"id": "G-01", "area": "Self-check: x", "why": "y", "next": "z"}]})
        _w(self.prj.work / "consolidation.json", cons)
        out = self._run("check", "--stage", "final")[1]
        self.assertIn("thấp hơn phát hiện nó xử lý (P1)", out)
        self.assertIn(report.RISK_DOC_NAME, out)
        self._run("render-risk", "--draft")
        self.assertIn("vẫn là bản nháp", self._run("check", "--stage", "final")[1])


class ReportingDocsTest(unittest.TestCase):
    def test_skill_docs_reference_real_paths_and_subcommands(self) -> None:
        docs = (sorted((TOOLKIT / ".agents" / "skills").glob("phase-4-*/SKILL.md")) + sorted((TOOLKIT / ".agents" / "skills").glob("phase-risk-*/SKILL.md"))
                + sorted((TOOLKIT / "reporting").rglob("*.md")))
        # wins: phase-4-orchestrator (export + hand-off) is wins' own entry point on top of the 6 vendored phase-4 skills
        self.assertEqual(len([p for p in (TOOLKIT / ".agents" / "skills").glob("phase-4-*/SKILL.md") if p.parent.name != "phase-4-orchestrator"]), 6)
        self.assertEqual(len(list((TOOLKIT / ".agents" / "skills").glob("phase-risk-*/SKILL.md"))), 5)
        src = (TOOLKIT / "reporting" / "report.py").read_text(encoding="utf-8")
        subcmds = set(re.findall(r'sub\.add_parser\("([a-z][a-z-]*)"', src))
        for md in docs:
            text = md.read_text(encoding="utf-8")
            for match in re.findall(r"`(AI-skills/[A-Za-z0-9_./-]+)`", text):
                self.assertTrue((TOOLKIT / match.removeprefix("AI-skills/")).exists(), f"{md.name}: {match}")
            for cmd in re.findall(r"report\.py\s+(?:--\S+\s+\S+\s+)*([a-z][a-z-]*)", text):
                self.assertIn(cmd, subcmds, f"{md.name}: report.py {cmd}")
        for example in (TOOLKIT / "reporting" / "templates").glob("*.json"):
            json.loads(example.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
