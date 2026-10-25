---
name: phase-1-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 1 Unified Reconnaissance v3.0 (kết hợp Technical Recon và Business/Safety Intent Recon trong một lượt đọc, kèm AI Scouting, Tailored Extractor, AI Semantic Clustering và Visibility Tracker) trên toàn bộ repositories của dự án. Kích hoạt khi người dùng gọi /phase-1-orchestrator.
---

# Phase 1 Master Orchestrator: Unified Reconnaissance (LocalSec v3.0)

Khi người dùng gọi `/phase-1-orchestrator`, bạn là **Master Orchestrator của Phase 1 (Unified Reconnaissance v3.0)**.
Phase 1 của LocalSec v3.0 gộp **Technical Recon** và **Business/Safety Intent Recon (S-F-O-P-C)** vào chung một lượt khảo sát thông minh để **tiết kiệm 50–60% usage** đồng thời **chống triệt để bệnh "giả vờ đủ coverage"** trên các dự án đa sản phẩm (VinFast Connected Car, V-Green OCPP, VinEnergo BESS SCADA, VinRobotics `vla.cpp`, WebApps/SPAs, Mobile Apps, Multi-Cloud/Edge/On-Prem, CI/CD, Data/AI Lakehouse, SAP/MuleSoft).

---

## Kiến trúc 6 Bước Tinh gọn của Phase 1 (LocalSec v3.0)

Với mỗi repository trong dự án (hoặc chạytăng dần (incremental) `--changed-files` qua `diff_prior_run`), thực thi tuần tự:

1. **Bước 1.1 — `/phase-1-codebase-scout` (`codebase_scout` Micro-Skill)**:
   - AI dùng `list_dir` (depth 2) và đọc lướt 3–5 file mẫu để xác định **Product Archetypes**, phân hạng **Repo Tier (`tier_1` / `tier_2` / `tier_3`)**, nắm quy ước code của team và lập **`Target Modules Map`** (`target_modules` + `ignored_modules` kèm lý do).
   - Đăng ký qua CLI: `python -m localsec.manual_session register_scout_map <repo_name> <json_file>`.
2. **Bước 1.2 — `/phase-1-extractor-tailor` (`extractor_tailor` Micro-Skill)**:
   - AI đánh giá xem quy ước code của repo có dùng được Python structural extractor hay không:
     - Chọn `USE_STANDARD_EXTRACTOR` hoặc `TAILOR_CUSTOM_EXTRACTOR` (bắt buộc kiểm thử khớp trên `canary_files` trước: `canary_verified = true`).
     - Hoặc chọn `SKIP_EXTRACTOR_DIRECT_READ` nếu code quá động/macro C++ phức tạp để tránh thiên kiến SAST.
   - Chạy qua CLI: `python -m localsec.manual_session run_tailored_extractor <repo_name> --mode ... --canary-files ...`.
3. **Bước 1.3 — `/phase-1-intent-invariant-modeler` (`intent_invariant_modeler`)**:
   - Đọc tài liệu thiết kế/README/OpenAPI/Proto/SQL/Manifest để lập mô hình **Ý định Nghiệp vụ & Bất biến An toàn Vật lý (5 trục S-F-O-P-C)** và tự phản biện mù ngữ cảnh trước khi đọc code thực thi.
4. **Bước 1.4 — `/phase-1-unified-surface-mapper` (`unified_surface_mapper` + `coverage_ledger`)**:
   - Nạp nguyên văn các khối `Attack-Class Companion` (`python -m localsec.manual_session select_attack_companions <repo_name>`).
   - Đọc mã nguồn **một lượt duy nhất (Single-Pass)**: vừa kiểm kê Entrypoints/AuthN/AuthZ/Dataflow, vừa đối sánh Intent vs Implementation.
   - Thực hiện **AI Semantic Clustering** (100% do AI quyết định): đọc sâu đại diện của nhóm `Shared-Control Group` và dồn toàn lực đọc sâu các **Dị biệt (`outliers`)**.
   - Ghi sổ `coverage_ledger.json` (chuẩn `coverage_id` RFC 3986 4–5 phân đoạn `surface::boundary::subsystem::attack_class[::lifecycle]`) và lập **`Candidate Queue`** cho Phase 2.
5. **Bước 1.5 — `/phase-1-cross-repo-and-arch-review` (`cross_repo_and_arch_review`)**:
   - Phân tích lệch giả định tin cậy xuyên dịch vụ/xuyên repo (Gateway $\leftrightarrow$ Upstream, Producer $\leftrightarrow$ Consumer Kafka/EMQX/ZeroMQ, Cloud $\leftrightarrow$ Edge/OT) và vẽ sơ đồ Mermaid (`-->` confirmed vs `-.->` hypothesis).
6. **Bước 1.6 — `/phase-1-coverage-and-evidence-auditor` (`coverage_and_evidence_auditor`)**:
   - Chạy `python -m localsec.manual_session audit_visibility <repo_name>` để kiểm tra **Visibility Tracker** (`unvisited_target_modules == 0`) và **Anti-Grazing** (`shallow_grazing_files == 0`, cấm đọc lướt $\le 8$ dòng).
   - Chạy `python -m localsec.manual_session verify_semantic_claims <repo_name>` để kiểm toán bằng chứng `ev_...` theo cơ chế **Fail-Closed**.
