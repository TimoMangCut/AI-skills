---
name: phase-4-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 4 Final Report Synthesis and Canonical Export v3.0 (xuất toàn bộ cây tài liệu chuẩn documents/, chuyển đổi F-xx.json không tốn token, kiểm chứng tương đương rủi ro S-F-O-P-C và tổng hợp 00_manifest.md, BAO_CAO_TONG_HOP_BAO_MAT.md, DANH_GIA_RUI_RO.md). Kích hoạt khi người dùng gọi /phase-4-orchestrator.
---

# LocalSec v3.0 — Phase 4 Master Orchestrator: Final Report Synthesis & Canonical Export

> **Hợp đồng điều phối chuẩn:** `AI-skills/contracts/v3-orchestration.json`

## 1. Mục tiêu của Phase 4 (Phase Báo cáo Tổng hợp Cuối cùng)

Sau khi hoàn tất:
- **Phase 1 (`phase-1-orchestrator`)**: Unified Reconnaissance (`1.1 -> 1.6`, đóng cổng bằng `finalize_v3_phase1`)
- **Phase 2 (`phase-2-orchestrator`)**: Deep Analysis & Falsification (`2.1 -> 2.4`, đóng cổng bằng `finalize_v3_phase2`)
- **Phase 3 (`phase-3-orchestrator`)**: Contextual S-F-O-P-C Risk & Exploitability Assessment (`3.1 -> 3.3`, đóng cổng bằng `finalize_v3_phase3`)

**Phase 4 (`phase-4-orchestrator`)** đóng vai trò là **Phase Báo cáo Tổng hợp & Xuất Hồ sơ Chuẩn (`Final Report Synthesis & Canonical Export`)** trên toàn bộ dự án:
1. Chuyển đổi toàn bộ kết quả `.localsec/runs/<run_id>/` sang cây thư mục chuẩn `documents/` mà không phải đọc lại mã nguồn:
   - `documents/_v3/<repo>/01..03.md` (3 thẻ báo cáo v3 theo đối tượng: Developer, Executive, QA/Pentest)
   - `documents/<repo>/01_repo_profile.md`, `02_techstack.json`, `05_inbound_outbound.json`, `09_findings.json`, `16_code_coverage.json` (ghi rõ `coverage_semantics: "file_touched"` và `line_coverage_pct`), `basv/18_business_aware_synthesis.json`
   - `documents/<repo>/12_analysis_status.json` (**chỉ tạo khi `phase1_gate_receipt.json` có `gate_passed: true`**)
   - `documents/<repo>/basv/19_basv_epistemic_and_contradiction_diagnostics.json` (**chỉ tạo khi `phase2_gate_receipt.json` có `gate_passed: true`**)
   - `documents/_analysis/chains/chain_<ID>.json`, `06_root_cause_map.json`, `99_project_chain_report.json`
   - `documents/_system/02_cross_repo_review.json`
   - `documents/_report/runtime_facts.json`, `documents/_report/work/findings_consolidated.json`
2. Chuyển đổi tất định (0 LLM token) kết quả Phase 3 (`3.1` + `3.2` + `3.3`) sang `documents/_report/work/risk/F-xx.json` và `_combinations.json` theo cấu trúc 5 chiều tiếng Việt (`an_toan_vat_ly`, `tai_chinh`, `van_hanh`, `du_lieu_ca_nhan`, `tuan_thu`), tự động tính lại `muc_rui_ro_suy_ra` và đối chiếu tương đương (`parity_verified: true`) với `derived_risk_rating`.
3. Tổng hợp 3 báo cáo cấp dự án tại `documents/_report/`:
   - `documents/_report/00_manifest.md`: Bảng kiểm kê toàn bộ repo, trạng thái 3 cổng kiểm toán Phase 1/2/3, độ phủ `file_touched` vs `line_coverage_pct`, và chỉ mục tài liệu.
   - `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md`: Báo cáo kỹ thuật & kiến trúc bảo mật tổng hợp toàn dự án (tách bạch `code_verified_severity` với `derived_risk_rating` và `contextual_risk_rating`).
   - `documents/_report/DANH_GIA_RUI_RO.md`: Báo cáo đánh giá rủi ro 5 trục S-F-O-P-C, trạng thái Phanh khẩn cấp `Gate 0 / Emergency Brake`, vai trò chủ sở hữu (`owner_role`), và danh sách câu hỏi mở có trọng số (`key_questions.json`).

---

## 2. Quy trình Thực thi Phase 4

### Bước 4.1: Xuất Hồ sơ Chuẩn & Kiểm chứng Tương đương Rủi ro (`export_final_phase_inputs` / `finalize_v3_phase4`)

Chạy lệnh đóng cổng và xuất báo cáo Phase 4:

```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase4
```

*(Hoặc gọi trực tiếp alias `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session export_final_phase_inputs`).*

Lệnh này thực hiện:
1. Gọi `render_v3_reports` để cập nhật bộ 3 tài liệu v3 (`01_developer_remediation_cards.md`, `02_executive_risk_and_key_questions.md`, `03_pentest_qa_verification_playbook.md`) tại `documents/` và `documents/_v3/<repo>/`.
2. Xuất toàn bộ các tệp JSON/Markdown chuẩn vào `documents/<repo>/`, `documents/_analysis/`, `documents/_system/`, và `documents/_report/work/risk/F-xx.json`.
3. Kiểm tra `risk_parity_verified`: đảm bảo 100% `F-xx.json` suy ra `muc_rui_ro_suy_ra` khớp tuyệt đối với `derived_risk_rating` của Phase 3.
4. Xuất `documents/_report/00_manifest.md`, `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md`, `documents/_report/DANH_GIA_RUI_RO.md` và ghi biên nhận `.localsec/runs/default/_analysis/phase4_gate_receipt.json`.

### Bước 4.2: Kiểm tra Biên nhận Phase 4 & Bàn giao

Đọc kết quả JSON trả về từ `finalize_v3_phase4` (hoặc kiểm tra `.localsec/runs/default/_analysis/phase4_gate_receipt.json`):
- Nếu `gate_passed: true` và `risk_parity_verified: true`: Báo cáo hoàn tất toàn bộ 4 Phase.
- Nếu `gate_passed: false` (do bất kỳ repo nào thiếu hoặc trượt `phase1/2/3_gate_receipt.json`): Giữ nguyên cảnh báo `[UNFINALIZED / GATE FAILED]` ở đầu báo cáo và liệt kê rõ các repo/chain cần chạy bổ sung.
