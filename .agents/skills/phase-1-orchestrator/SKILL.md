---
name: phase-1-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 1 Unified Reconnaissance v3.0 (kết hợp Technical Recon và Business/Safety Intent Recon trong một lượt đọc, kèm AI Scouting, Tailored Extractor, AI Semantic Clustering và Visibility Tracker) trên toàn bộ repositories của dự án. Kích hoạt khi người dùng gọi /phase-1-orchestrator.
---

# Phase 1 Master Orchestrator: Unified Reconnaissance (LocalSec v3.0)

> **Session Boundary Directive (`Repo x Phase`)**: Run Phase 1 in a dedicated session per repository. Once `finalize_v3_phase1 <repo_name>` passes and writes `phase1_gate_receipt.json` + `candidate_queue.json`, end the session and start Phase 2 in a fresh context.

Khi người dùng gọi `/phase-1-orchestrator`, bạn là **Master Orchestrator của Phase 1 (Unified Reconnaissance v3.0)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`.
Phase 1 của LocalSec v3.0 gộp **Technical Recon** và **Business/Safety Intent Recon (S-F-O-P-C)** vào chung một lượt khảo sát thông minh để **tiết kiệm 50–60% usage** đồng thời **chống triệt để bệnh "giả vờ đủ coverage"** trên các dự án đa sản phẩm (VinFast Connected Car, V-Green OCPP, VinEnergo BESS SCADA, VinRobotics `vla.cpp`, WebApps/SPAs, Mobile Apps, Multi-Cloud/Edge/On-Prem, CI/CD, Data/AI Lakehouse, SAP/MuleSoft).

---

## Kiến trúc 6 Bước Tinh gọn của Phase 1 — Intent Before Code (`ARCH-3K`)

Với mỗi repository trong dự án (hoặc chạy tăng dần `--changed-files` qua `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>`), bắt buộc thực thi theo đúng thứ tự **Intent Before Code (`ARCH-3K`)** dưới đây:

1. **Bước 1.1 — Inventory & Codebase Scout (`inventory_repo` + `/phase-1-codebase-scout` / `codebase_scout`)**:
   - Chạy kiểm kê tất định trước tiên: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session inventory_repo <repo_name> --tier 1` (`ARCH-3C`, `DEPTH-4.1e`, `DEPTH-4.3d`, `DEPTH-4.7`) để sinh `.localsec/runs/default/<repo_name>/inventory_repo.json` (gồm danh sách `mandatory_files` phân nhóm `entrypoint`, `security`, `wiring_config`, `outbound`, `data_access`, `control_search_paths` và `scan_repo_leads`).
   - AI dùng `list_dir` (depth 2) và chỉ đọc các file manifest/config/wiring để xác định **Product Archetypes** (`product_archetypes` & `detected_archetypes`), phân hạng **Repo Tier (`tier_1` / `tier_2` / `tier_3`)**, nắm quy ước tổ chức repo và lập **`Target Modules Map`** (`target_modules` phải bao phủ 100% thư mục chứa `entrypoint` hoặc `security` files, hoặc khai báo `ignored_modules` kèm enum `reason` hợp lệ).
   - Đăng ký qua CLI: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/codebase_scout.schema.json`).

2. **Bước 1.3 (Chạy TRƯỚC khi đọc code thực thi) — `/phase-1-intent-invariant-modeler` (`intent_invariant_modeler` — `ARCH-3K`)**:
   - Thực thi **TRƯỚC khi đọc mã nguồn thực thi** (engine tự động chặn các đuôi file code `.go`, `.py`, `.ts`, `.cs`, `.java`, `.cpp` khi dùng `--skill intent_invariant_modeler`).
   - Chỉ đọc tài liệu thiết kế/README/OpenAPI/Proto/SQL/Manifest để lập mô hình **Ý định Nghiệp vụ & Bất biến An toàn Vật lý** trên 5 trục chữ thường đầy đủ (`"safety" | "financial" | "operational" | "privacy" | "compliance"`) và thực hiện **Tự rà soát phản biện bất biến (`self_challenged_gaps` — `ARCH-3E`)**.
   - Nộp qua CLI: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> intent_invariant_modeler .localsec/tmp/intent_invariant_modeler_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/intent_invariant_modeler.schema.json`).

3. **Bước 1.2 — `/phase-1-extractor-tailor` (`extractor_tailor` Micro-Skill)**:
   - AI đánh giá xem quy ước code của repo có dùng được Python structural extractor hay không (`USE_STANDARD_EXTRACTOR`, `TAILOR_CUSTOM_EXTRACTOR`, hoặc `SKIP_EXTRACTOR_DIRECT_READ`).
   - Chạy qua CLI với `--canary-files` và `--expected-canary-hits` (`BUG-05`):
     `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session run_tailored_extractor <repo_name> --mode USE_STANDARD_EXTRACTOR --canary-files <file1> --expected-canary-hits 1`
   - Khi số điểm khớp trên canary đạt `>= expected_canary_hits`, engine tự động quét toàn bộ `target_modules` và lưu kết quả theo `AI-skills/schemas/v3/extractor_tailor.schema.json`.

4. **Bước 1.4 — `/phase-1-unified-surface-mapper` (`unified_surface_mapper` + `coverage_ledger`)**:
   - Nạp nguyên văn các khối `Attack-Class Companion`: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session select_attack_companions <repo_name>`.
   - Đọc mã nguồn **một lượt duy nhất (Single-Pass)**: điền đầy đủ `surface_checklist` (9 loại bề mặt với `"status": "present" | "absent" | "unknown"`), `entrypoints[]` giàu ngữ cảnh (`id`, `method`, `path`, `file`, `object_id_params`, `ownership_check`, `input_binding`, `evidence_ids`), `invariant_checks[]`, `data_flows[]` (kèm `identity_forwarding`), `sensitive_data[]` và `candidate_queue`.
   - Thực hiện **AI Semantic Clustering** tuân thủ **Safe Clustering Rule (`ARCH-3F`)**: khai báo cả `representative_file` + `member_files` lẫn `representative_endpoint` + `member_endpoints`; bất kỳ entrypoint nào có `object_id_params` khác rỗng **KHÔNG ĐƯỢC** gom cụm ngầm trừ khi có `ownership_check: "present"` kèm `evidence_ids`, hoặc phải đưa vào `outliers` / `candidate_queue`.
   - Nộp `unified_surface_mapper` (`AI-skills/schemas/v3/unified_surface_mapper.schema.json`) và `coverage_ledger` (`AI-skills/schemas/v3/coverage_ledger.schema.json`).

5. **Bước 1.5 — `/phase-1-cross-repo-and-arch-review` (`match_cross_repo_boundaries` + `cross_repo_and_arch_review`)**:
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session match_cross_repo_boundaries` (`DEPTH-4.1f`) trước để ghép cặp tự động các luồng `data_flows[]` chiều đi (outbound) với `entrypoints[]` chiều đến (inbound) xuyên repo.
   - Phân tích lệch giả định tin cậy xuyên dịch vụ/xuyên repo (`trust_boundary_mismatches`, `architecture_findings`, `matched_cross_repo_boundaries`, `diagrams`), nộp theo `AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`.

6. **Bước 1.6 — `/phase-1-coverage-and-evidence-auditor` (`coverage_and_evidence_auditor` + `finalize_v3_phase1`)**:
   - Chạy cổng khóa sổ tất định có thẩm quyền cuối cùng: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>` (`ARCH-3D`, `ARCH-3G`, `R2-P1-04`) để kiểm toán `audit_visibility`, kiểm chứng ngữ nghĩa `verify_semantic_claims`, hạ cấp Fail-Closed các tuyên bố thiếu bằng chứng, xuất `coverage_matrix.json` (mặc định `"unassessed"`), `candidate_queue.json`, `coverage_and_evidence_auditor.json` và `phase1_gate_receipt.json`.

---

## Bàn giao Phiên (`Repo x Phase` Session Boundary)

Sau khi `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>` báo `gate_passed: true`, **kết thúc phiên làm việc hiện tại** và in ra lệnh chính xác dưới đây để người dùng khởi chạy **Phase 2** trong một phiên mới (Fresh Session):

```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0) cho repo <repo_name> trong phiên làm việc mới, đọc trực tiếp .localsec/runs/default/<repo_name>/candidate_queue.json từ Phase 1.
```
