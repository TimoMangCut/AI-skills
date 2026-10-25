---
name: phase-2-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 2 Deep Analysis and Falsification v3.0 (truy vết sâu chuỗi tấn công trên Candidate Queue, truy nguyên nhân gốc, phản biện đối kháng mù kết luận và kiểm toán bằng chứng) trên toàn dự án. Kích hoạt khi người dùng gọi /phase-2-orchestrator.
---

# Phase 2 Master Orchestrator: Deep Analysis & Falsification (LocalSec v3.0)

> **Session Boundary Directive (`Repo x Phase`)**: Run Phase 2 in a fresh session per repository, starting from `.localsec/runs/default/<repo_name>/candidate_queue.json`. Launch Step 2.3 (`blinded_counterevidence_challenger`) in an isolated subagent / fresh conversation passing ONLY `.localsec/tmp/blinded_chains_<repo_name>.json`.

Khi người dùng gọi `/phase-2-orchestrator`, bạn là **Master Orchestrator của Phase 2 (Deep Analysis & Falsification v3.0)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`.
Sau khi Phase 1 (`finalize_v3_phase1`) đã hoàn tất kiểm kê bề mặt, đối sánh bất biến S-F-O-P-C và xuất `.localsec/runs/default/<repo_name>/candidate_queue.json`, Phase 2 **chỉ tập trung nguồn lực đọc sâu vào các ứng viên trong `Candidate Queue`** để chứng minh khả năng chạm tới lỗ hổng (**Code-Level Reachability**), dựng chuỗi tấn công đa bước, tìm nguyên nhân gốc (`Root-Cause`) và thực hiện **Phản biện Bác bỏ Mù Kết luận Độc lập (`ARCH-3E`)**.

---

## Ranh giới Phiên làm việc & Tái sử dụng Bằng chứng (`DEPTH-4.5`)

- **Ranh giới Phiên (`Repo x Phase` Session Boundary)**: Mỗi repo trong Phase 2 chạy trong một phiên làm việc mới (Fresh Session), đọc đầu vào từ `.localsec/runs/default/<repo_name>/candidate_queue.json`.
- **Tái sử dụng Bằng chứng Phase 1 (`show_evidence` / `list_evidence`)**: Dùng lệnh `python -m localsec.manual_session show_evidence <repo_name> <ev_id>` hoặc `python -m localsec.manual_session list_evidence <repo_name>` để xem lại trích đoạn code đã đọc ở Phase 1 mà không cần đọc lại toàn bộ file từ đầu.

---

## Kiến trúc 4 Bước Tinh gọn của Phase 2 (LocalSec v3.0)

1. **Bước 2.1 — `/phase-2-candidate-intake-planner` (`candidate_intake_planner`)**:
   - Đọc `.localsec/runs/default/<repo_name>/candidate_queue.json` do `finalize_v3_phase1` sinh ra (`ARCH-3G`).
   - Chạy `python -m localsec.manual_session select_attack_companions <repo_name> --archetypes ...` để nạp nguyên văn các khối `## [ BLOCK: ... ]` từ `AI-skills/contracts/attack-taxonomy-v1/manifest.json` và ghi ra `.localsec/runs/default/<repo_name>/selected_attack_companions.json` (`DEPTH-4.5`).
   - Gom nhóm ứng viên vào `deduplicated_batches[]` kèm `selected_companions` và nộp qua CLI: `python -m localsec.manual_session submit_skill <repo_name> candidate_intake_planner .localsec/tmp/candidate_intake_planner_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/candidate_intake_planner.schema.json`).

2. **Bước 2.2 — `/phase-2-deep-trace-chain-analyst` (`deep_trace_chain_analyst`)**:
   - **Bảo toàn 100% `candidate_id` (`ARCH-3G`)**: Mọi `candidate_id` từ `candidate_queue.json` bắt buộc phải được hạch toán đầy đủ vào `chains[].candidate_ids` hoặc `unexploitable_candidates[]` (kèm lý do và `ev_...`).
   - Sử dụng `chain_verdict` (`"code_supported"` khi chưa thực thi runtime) và truy vết từng bước nhảy thực thi (`hops[]`) bắt buộc khai báo `hop_kind` (`in_process`, `http`, `grpc`, `message_queue`, `zmq_or_ipc`, `db`, `file_or_hardware`) cùng mảng `caller_evidence_ids` và `callee_evidence_ids` (`DEPTH-4.2b`).
   - Truy nguyên nhân gốc (`root_cause`), hướng sửa (`remediation`) và thiết kế `request_plan` (`execution_status: "not_executed"`).
   - Nộp qua CLI: `python -m localsec.manual_session submit_skill <repo_name> deep_trace_chain_analyst .localsec/tmp/deep_trace_chain_analyst_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`).

3. **Bước 2.3 — `/phase-2-blinded-counterevidence-challenger` (`blinded_counterevidence_challenger` — Subagent Cô lập `ARCH-3E`, `R2-P1-01`, `R2-P1-02`)**:
   - Chạy `python -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>` để xuất gói Whitelist `.localsec/tmp/blinded_chains_<repo_name>.json` (đã loại bỏ `title`, `root_cause`, `severity`, `expected_vulnerable_behavior`, kèm danh sách `control_search_paths` từ `inventory_repo.json`).
   - **Bắt buộc khởi chạy Bước 2.3 trong một Subagent độc lập / Fresh Conversation (`ARCH-3E`)** và **CHỈ truyền duy nhất đường dẫn `.localsec/tmp/blinded_chains_<repo_name>.json`** (tuyệt đối không đọc `deep_trace_chain_analyst.json`).
   - Kiểm tra đủ 6 vị trí kiểm soát cố định trong `control_search_checklist` với `status` thuộc `"checked_found" | "checked_not_found" | "not_applicable"`, đảm bảo mọi mục `"checked_not_found"` / `"checked_found"` đều có cả `searched_paths` lẫn `evidence_ids` khác rỗng, và nộp `challenged_chains` theo `AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json`.

4. **Bước 2.4 — `/phase-2-analysis-evidence-gate` (`analysis_evidence_gate` + `finalize_v3_phase2` — `R2-P1-04`)**:
   - Chạy cổng khóa sổ tất định có thẩm quyền cuối cùng: `python -m localsec.manual_session finalize_v3_phase2 <repo_name>` (`ARCH-3D`, `ARCH-3G`, `R2-P1-04`) để kiểm tra đối khớp 100% `candidate_id`, chặn mọi chuỗi chưa qua phản biện (`UNCHALLENGED_BLOCKED`), kiểm tra đủ 6 vị trí challenger + timestamp freshness, áp trần `code_supported` cho mọi `request_plan` chưa thực thi, và tự động ghi `analysis_evidence_gate.json`, `phase2_gate_receipt.json` cùng `phase3_verified_queue.json`.

---

## Bàn giao Phiên (`Repo x Phase` Session Boundary)

Sau khi `python -m localsec.manual_session finalize_v3_phase2 <repo_name>` báo `gate_passed: true`, **kết thúc phiên làm việc hiện tại** và in ra lệnh chính xác dưới đây để người dùng khởi chạy **Phase 3** trong một phiên mới (Fresh Session):

```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability Assessment v3.0) cho repo <repo_name> trong phiên làm việc mới, đọc trực tiếp .localsec/runs/default/<repo_name>/phase3_verified_queue.json từ Phase 2.
```
