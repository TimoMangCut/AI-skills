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
1. **Bảo vệ chống ghi đè ngoài ý muốn (`Overwrite Guard — B2`)**: Trước khi ghi vào `documents/`, kiểm tra xem có file nào do bộ công cụ khác tạo (không mang dấu `"generated_by": "wins"` hoặc `<!-- generated_by: wins -->`) hay không. Nếu phát hiện, dừng lại an toàn trừ khi truyền cờ `--force-overwrite`.
2. **Chuyển đổi toàn bộ kết quả `.localsec/runs/<run_id>/` sang cây thư mục chuẩn `documents/` tương thích schema 100% (`B1`)**:
   - `documents/_v3/<repo>/01..03.md` (3 thẻ báo cáo v3 theo đối tượng: Developer, Executive, QA/Pentest)
   - `documents/<repo>/01_repo_profile.md` (đủ mục `## Purpose` và `## Criticality assessment`), `02_techstack.json` (`languages`, `frameworks`), `05_inbound_outbound.json` (`inbound`, `outbound`), `09_findings.json` (giữ nguyên 100% `candidate_queue` + `architecture_findings` từ Phase 1), `16_code_coverage.json` (ghi rõ `coverage_semantics: "file_touched"` và `line_coverage_pct`), `basv/18_business_aware_synthesis.json` (`invariants`, `gaps`)
   - `documents/<repo>/12_analysis_status.json` (**chỉ tạo khi `phase1_gate_receipt.json` có `gate_passed: true`**)
   - `documents/<repo>/basv/19_basv_epistemic_and_contradiction_diagnostics.json` (**chỉ tạo khi `phase2_gate_receipt.json` có `gate_passed: true`**)
   - `documents/_analysis/chains/chain_<ID>.json` (cho toàn bộ chuỗi của dự án), `06_root_cause_map.json` (`root_causes[]`), `99_project_chain_report.json` (`chains[]`)
   - `documents/_system/02_cross_repo_review.json` (`findings[]`)
   - `documents/_report/runtime_facts.json`, `documents/_report/work/findings_consolidated.json` (gom nhóm chuỗi theo `root_cause_cluster_id` thành `F-01`, `F-02`, ... — `B4`)
3. **Chuyển đổi tất định (0 LLM token) kết quả Phase 3 (`3.1` + `3.2` + `3.3`) sang `documents/_report/work/risk/F-xx.json` và `_combinations.json` (`B1`, `B5`)**:
   - Đầy đủ `attack_paths` (`links`, `controls`, `path_feasibility`), `actors_considered`, `yields`, `detection`, `business_impact` (5 chiều `an_toan_vat_ly`, `tai_chinh`, `van_hanh`, `du_lieu_ca_nhan`, `tuan_thu`), `open_questions`.
   - Tự động tính lại `muc_rui_ro_suy_ra` theo đúng luật của `finalize_v3_phase3` (kể cả kiểm soát từ `runtime_environment_facts.json` và hạ điều kiện `"no"` thiếu bằng chứng về `"unknown"`) và đối chiếu tương đương (`parity_verified: true`) với `derived_risk_rating`.
4. **Tổng hợp 3 báo cáo cấp dự án tại `documents/_report/` (`B3`, `B6`)**:
   - `documents/_report/00_manifest.md`: Bảng kiểm kê toàn bộ repo, trạng thái 3 cổng kiểm toán Phase 1/2/3, độ phủ `file_touched` vs `line_coverage_pct`, và chỉ mục tài liệu.
   - `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md`: Báo cáo kỹ thuật & kiến trúc bảo mật tổng hợp toàn dự án (Executive Summary, Kiến trúc & Blast Radius, Chi tiết từng lỗ hổng hợp nhất `F-xx` kèm `hops[]`, `evidence_ids`, `discriminating_requests`, Lộ trình khắc phục P0/P1/P2, Phạm vi chưa kiểm chứng, và Phụ lục A/B/C).
   - `documents/_report/DANH_GIA_RUI_RO.md`: Báo cáo đánh giá rủi ro 5 trục S-F-O-P-C (Chi tiết từng `F-xx` với bảng mắt xích `attack_paths`, `holders`, `actors_considered`, Rủi ro kết hợp `_combinations.json`, trạng thái `Gate 0 / Emergency Brake`, và Bảng câu hỏi mở hai chiều `outcome_if_yes` / `outcome_if_no`).

---

## 2. Quy trình Thực thi Phase 4

### Bước 4.1: Xuất Hồ sơ Chuẩn & Kiểm chứng Tương đương Rủi ro (`finalize_v3_phase4` / `export_final_phase_inputs`)

Chạy lệnh đóng cổng và xuất báo cáo Phase 4:

```bash
python -m localsec.manual_session finalize_v3_phase4
```

*(Nếu cần ghi đè lên thư mục `documents/` có sẵn từ công cụ khác, thêm cờ `--force-overwrite`: `python -m localsec.manual_session finalize_v3_phase4 --force-overwrite`).*

### Bước 4.2: Kiểm tra Biên nhận Phase 4 & Bàn giao

Đọc kết quả JSON trả về từ `finalize_v3_phase4` (hoặc kiểm tra `.localsec/runs/default/_analysis/phase4_gate_receipt.json`):
- Nếu `gate_passed: true` và `risk_parity_verified: true`: Báo cáo hoàn tất toàn bộ 4 Phase.
- Nếu `gate_passed: false` (do bất kỳ repo nào thiếu/trượt `phase1/2/3_gate_receipt.json`, lệch `risk_parity_verified`, hoặc bị chặn bởi `overwrite_blocked`): Giữ nguyên cảnh báo `[UNFINALIZED / GATE FAILED]` và xử lý nguyên nhân trước khi phát hành báo cáo.
