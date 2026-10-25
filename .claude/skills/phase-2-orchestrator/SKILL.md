---
name: phase-2-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 2 Deep Analysis and Falsification v3.0 (truy vết sâu chuỗi tấn công trên Candidate Queue, truy nguyên nhân gốc, phản biện đối kháng mù kết luận và kiểm toán bằng chứng) trên toàn dự án. Kích hoạt khi người dùng gọi /phase-2-orchestrator.
---

# Phase 2 Master Orchestrator: Deep Analysis & Falsification (LocalSec v3.0)

Khi người dùng gọi `/phase-2-orchestrator`, bạn là **Master Orchestrator của Phase 2 (Deep Analysis & Falsification v3.0)**.
Sau khi Phase 1 (Unified Reconnaissance) đã hoàn tất kiểm kê bề mặt, đối sánh bất biến S-F-O-P-C và gom cụm tương đương, Phase 2 **chỉ tập trung nguồn lực đọc sâu vào các ứng viên trong `Candidate Queue`** để chứng minh khả năng chạm tới lỗ hổng (**Code-Level Reachability**), dựng chuỗi tấn công đa bước, tìm nguyên nhân gốc (Root-Cause) và thực hiện **Phản biện Bác bỏ Mù Kết luận (Refute-First)**.

---

## Kiến trúc 4 Bước Tinh gọn của Phase 2 (LocalSec v3.0)

1. **Bước 2.1 — `/phase-2-candidate-intake-planner` (`candidate_intake_planner`)**:
   - Chuẩn hóa và xếp hạng ưu tiên các mục trong `Candidate Queue` từ Phase 1 (`P0` cho Safety/Financial/BOLA/RCE).
   - Chạy `python -m localsec.manual_session select_attack_companions <repo_name>` để tiêm **nguyên văn** các khối `## [ BLOCK: ... ]` từ `contracts/attack-taxonomy-v1/`.
2. **Bước 2.2 — `/phase-2-deep-trace-chain-analyst` (`deep_trace_chain_analyst`)**:
   - Trong một lượt đọc sâu liền mạch cho mỗi ứng viên:
     - Truy vết từng bước nhảy thực thi (`hops[]`) từ Entrypoint qua Middleware/Guard tới Sink kèm `ev_...`.
     - Dựng chuỗi tấn công đa bước (`steps[]`, `preconditions`, `state_before`, `state_after`, `linked_next_steps[]`).
     - Truy nguyên nhân gốc rễ (`Root-Cause Mapping`) để sửa lỗi một lần ở kiến trúc/máy trạng thái.
     - Thiết kế chuỗi request kiểm định phân biệt rõ hành vi an toàn và hành vi lỗi (`plan_only` / `not_executed`).
3. **Bước 2.3 — `/phase-2-blinded-counterevidence-challenger` (`blinded_counterevidence_challenger`)**:
   - Chạy `python -m localsec.manual_session prepare_blinded_chain_verifier _analysis` để cắt bỏ toàn bộ kết luận/verdict của Bước 2.2.
   - Đọc độc lập trong danh sách `exact_paths` để xác minh từng mắt xích và chủ động săn tìm kiểm soát bù trừ trong code, ghi vào **Sổ cái Phản biện Thực nghiệm (`Empirical Refutations Ledger`)**.
4. **Bước 2.4 — `/phase-2-analysis-evidence-gate` (`analysis_evidence_gate`)**:
   - Chạy `python -m localsec.manual_session verify_semantic_claims _analysis`.
   - Áp dụng luật cứng `request_plan_is_not_execution` và hạ cấp **Fail-Closed** mọi mắt xích thiếu `ev_...` hoặc bị phản bác trước khi bàn giao danh sách lỗ hổng **Reachable** sang Phase 3.

> **Tương thích ngược (Granular BASV/ACA Mode)**: Nếu người vận hành yêu cầu chạy chi tiết từng bước rời của BASV v1.0 hoặc ACA v1.0 và xuất báo cáo qua `finalize_basv_repo` / `finalize_aca`, bạn vẫn có thể gọi trực tiếp các sub-skills tương ứng.
