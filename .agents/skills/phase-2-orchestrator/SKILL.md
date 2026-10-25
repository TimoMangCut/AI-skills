---
name: phase-2-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 2 Deep Analysis and Falsification v3.0 (truy vết sâu chuỗi tấn công trên Candidate Queue, truy nguyên nhân gốc, phản biện đối kháng mù kết luận và kiểm toán bằng chứng) trên toàn dự án. Kích hoạt khi người dùng gọi /phase-2-orchestrator.
---

# Phase 2 Master Orchestrator: Deep Analysis & Falsification (LocalSec v3.0)

Khi người dùng gọi `/phase-2-orchestrator`, bạn là **Master Orchestrator của Phase 2 (Deep Analysis & Falsification v3.0)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`.
Sau khi Phase 1 (`finalize_v3_phase1`) đã hoàn tất kiểm kê bề mặt, đối sánh bất biến S-F-O-P-C và xuất `.localsec/runs/default/<repo_name>/candidate_queue.json`, Phase 2 **chỉ tập trung nguồn lực đọc sâu vào các ứng viên trong `Candidate Queue`** để chứng minh khả năng chạm tới lỗ hổng (**Code-Level Reachability**), dựng chuỗi tấn công đa bước, tìm nguyên nhân gốc (`Root-Cause`) và thực hiện **Phản biện Bác bỏ Mù Kết luận Độc lập (`ARCH-3E`)**.

---

## Ranh giới Phiên làm việc & Tái sử dụng Bằng chứng (`DEPTH-4.5`)

- **Ranh giới Phiên (`Repo x Phase` Session Boundary)**: Mỗi repo trong Phase 2 chạy trong ngữ cảnh sạch, đọc đầu vào từ `.localsec/runs/default/<repo_name>/candidate_queue.json`.
- **Tái sử dụng Bằng chứng Phase 1 (`show_evidence` / `list_evidence`)**: Dùng lệnh `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session show_evidence <repo_name> <ev_id>` hoặc `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_evidence <repo_name>` để xem lại trích đoạn code đã đọc ở Phase 1 mà không cần đọc lại toàn bộ file từ đầu.

---

## Kiến trúc 4 Bước Tinh gọn của Phase 2 (LocalSec v3.0)

1. **Bước 2.1 — `/phase-2-candidate-intake-planner` (`candidate_intake_planner`)**:
   - Đọc `.localsec/runs/default/<repo_name>/candidate_queue.json` do `finalize_v3_phase1` sinh ra (`ARCH-3G`).
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session select_attack_companions <repo_name> --archetypes ...` để nạp nguyên văn các khối `## [ BLOCK: ... ]` từ `AI-skills/contracts/attack-taxonomy-v1/manifest.json` và ghi ra `.localsec/runs/default/<repo_name>/selected_attack_companions.json` (`DEPTH-4.5`).
   - Nộp qua CLI: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> candidate_intake_planner /tmp/candidate_intake_planner_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/candidate_intake_planner.schema.json`).

2. **Bước 2.2 — `/phase-2-deep-trace-chain-analyst` (`deep_trace_chain_analyst`)**:
   - **Bảo toàn 100% `candidate_id` (`ARCH-3G`)**: Mọi `candidate_id` từ `candidate_queue.json` bắt buộc phải được hạch toán đầy đủ vào `chains[]` (qua `source_candidate_ids`) hoặc `unexploitable_candidates[]` (kèm lý do và `ev_...`).
   - Truy vết từng bước nhảy thực thi (`hops[]`) bắt buộc khai báo `hop_kind` (`in_process`, `http`, `grpc`, `message_queue`, `zmq_or_ipc`, `db`, `file_or_hardware`) và nếu nhảy xuyên dịch vụ phải có cả `ev_...` phía caller lẫn callee (`DEPTH-4.2b`).
   - Dựng chuỗi tấn công đa bước (`steps[]`), truy nguyên nhân gốc (`root_cause`) và thiết kế chuỗi request kiểm định (`request_plan` ở chế độ `plan_only` / `not_executed`).
   - Nộp qua CLI: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> deep_trace_chain_analyst /tmp/deep_trace_chain_analyst_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`).

3. **Bước 2.3 — `/phase-2-blinded-counterevidence-challenger` (`blinded_counterevidence_challenger` — Subagent Cô lập `ARCH-3E`)**:
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>` để xuất file `/tmp/blinded_chains_<repo_name>.json` đã cắt bỏ toàn bộ kết luận/verdict của Bước 2.2.
   - **Bắt buộc khởi chạy trong một Subagent độc lập / Fresh Context (`ARCH-3E`)** chỉ nhận đầu vào là `/tmp/blinded_chains_<repo_name>.json`.
   - Kiểm tra đủ 6 vị trí kiểm soát cố định (`control_search_checklist` — `DEPTH-4.2d`) kèm `searched_paths` và nộp theo `AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json`.

4. **Bước 2.4 — `/phase-2-analysis-evidence-gate` (`analysis_evidence_gate` + `finalize_v3_phase2`)**:
   - Nộp `analysis_evidence_gate` (`AI-skills/schemas/v3/analysis_evidence_gate.schema.json`).
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase2 <repo_name>` (`ARCH-3D`, `ARCH-3G`) để kiểm tra đối khớp 100% `candidate_id`, áp trần `code_supported` cho mọi `request_plan` chưa thực thi, áp dụng kết quả bác bỏ từ Bước 2.3, hạ cấp Fail-Closed các tuyên bố thiếu bằng chứng và bàn giao danh sách `chain_id` sống sót sang Phase 3.
