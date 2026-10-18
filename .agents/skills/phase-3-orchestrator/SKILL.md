---
name: phase-3-orchestrator
description: Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 3 (Attack Chain & Root-Cause Analysis v1.0 — 9 bước bắt buộc) trên toàn dự án.

## Bản Đồ Đường Dẫn Nội Bộ (Internal Resource Mapping tại `AI-skills/`)
> **LƯU Ý QUAN TRỌNG CHO AI AGENT**: Khi bộ kỹ năng được tích hợp vào một Project mục tiêu (`<Project-Root>`), toàn bộ mã nguồn Engine, Prompts và JSON Schemas nằm gọn bên trong thư mục `AI-skills/` (không nằm rời rạc ở gốc Project). Hãy truy cập trực tiếp các đường dẫn chuẩn hóa sau:
- **Engine CLI**: `AI-skills/localsec/manual_session.py` (gọi qua `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...`)
- **Cấu hình Runtime**: `AI-skills/localsec.toml` (hoặc `<Project-Root>/localsec.toml` nếu muốn ghi đè)
- **Skill Registry**: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`
- **Thư mục Prompts gốc**: `AI-skills/contracts/attack-chain-analysis-v1/prompts/`
- **Thư mục JSON Schemas**: `AI-skills/contracts/attack-chain-analysis-v1/schemas/`
- **Quy ước `<repo_name>`**:
  - **Multi-repo Workspace** (nhiều repo con nằm trong `<Project-Root>`): truyền tên thư mục con (ví dụ: `auth-service`, `payment-api`).
  - **Single-repo Project** (`<Project-Root>` chính là repo cần review): truyền `.` hoặc tên thư mục gốc của project; Engine tự động bỏ qua `AI-skills/`, `.agents/`, `.localsec/`, `documents/`.

---

# `phase-3-orchestrator` — Master Orchestrator cho Phase 3 (Attack Chain & Root-Cause Analysis)

Khi người dùng gọi `/phase-3-orchestrator`, bạn **BẮT BUỘC** thực thi đầy đủ **9 bước chuyên môn** bên dưới để truy vết chuỗi tấn công xuyên dịch vụ và nguyên nhân gốc. **Cơ chế khóa cứng (State-Machine Gate)** trong `AI-skills/localsec/manual_session.py` sẽ chặn việc nộp `chain_synthesizer` nếu chưa chạy `aca_evidence_auditor`, và chặn `finalize_aca` nếu thiếu bất kỳ bước bắt buộc nào.

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-orchestrator Thực hiện trọn bộ Phase 3 (Attack Chain Analysis) nối tiếp kết quả Phase 1 & 2 để xây dựng và kiểm chứng các chuỗi tấn công đa bước xuyên dịch vụ.
Mọi finding trước đó chỉ là manh mối (leads, not truth): phải chứng minh từng mắt xích (step) và từng cạnh chuyển tiếp trạng thái (edge) bằng ev_..., làm mù kết luận khi verify/challenge, truy tới nguyên nhân gốc và tuyệt đối không gán confirmed nếu chỉ có kế hoạch request (request_plan_only).
```

---

## Quy trình Thực thi Bắt buộc (Kiểm tra tiến độ bằng `phase_status _analysis --phase 3`)

Trước và sau mỗi bước, kiểm tra trạng thái bằng:
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status _analysis --phase 3
```

1. **Bước 3.1 — `finding_intake`** (Tham chiếu `.agents/skills/phase-3-finding-intake/SKILL.md`):
   - Thu nạp các findings từ Phase 1 & mismatches từ Phase 2 thành `candidate_claims` và `chain_hypotheses` (không được đọc trực tiếp source code ở bước này).
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis finding_intake <json_file>`
2. **Bước 3.2 — `code_trace_builder`** (Tham chiếu `.agents/skills/phase-3-code-trace-builder/SKILL.md`):
   - Truy vết thủ công từng hop (`hops[]`) qua mã nguồn (`--skill code_trace_builder`), mỗi hop `directly_read` bắt buộc đính kèm `evidence_refs`.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis code_trace_builder <json_file> --artifact-id <trace_id>`
3. **Bước 3.3 — `attack_chain_constructor`** (Tham chiếu `.agents/skills/phase-3-attack-chain-constructor/SKILL.md`):
   - Xây dựng chuỗi tấn công với `preconditions`, `steps[]` và `linked_next_steps[]` (tuân thủ 6 cổng kiểm định trong `_validate_aca_epistemic_gates`).
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis attack_chain_constructor <json_file> --artifact-id <chain_id>`
4. **Bước 3.4 — `chain_step_verifier` (Context-Blinded)**:
   - Tạo ngữ cảnh làm mù kết luận của Constructor: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier <chain_json>`
   - Đọc mã nguồn độc lập (`--skill chain_step_verifier`) để xác minh từng `step_results[]` và `edge_results[]`.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis chain_step_verifier <json_file> --artifact-id <verify_id>`
5. **Bước 3.5 — `request_sequence_designer` & `request_reproduction_operator`**:
   - Thiết kế chuỗi request kiểm định bằng dữ liệu giả lập (`plan_only`), sau đó chạy qua adapter an toàn: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session run_aca_request_plan <request_json>` (mặc định trả về `not_executed` khi không có môi trường local được phê duyệt).
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis request_sequence_designer <json_file> --artifact-id <req_id>`
6. **Bước 3.6 — `root_cause_mapper`** (Tham chiếu `.agents/skills/phase-3-root-cause-mapper/SKILL.md`):
   - Truy nguyên từ triệu chứng bề mặt về nguyên nhân gốc trong kiến trúc/phân quyền/máy trạng thái (`--skill root_cause_mapper`).
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis root_cause_mapper <json_file> --artifact-id <rc_id>`
7. **Bước 3.7 — `counterevidence_challenger` (Context-Blinded Adversarial Challenge & Runaway Governor)**:
   - Dùng ngữ cảnh làm mù (`prepare_blinded_chain_verifier`) và đọc source code (`--skill counterevidence_challenger`) để săn tìm guard ẩn, điều kiện vô nghiệm hoặc nhánh tấn công thay thế.
   - **Bộ Điều tốc Chống Phình to Câu hỏi (`Question-Space Runaway Governor` trong `check_aca_convergence`)**: Cuối mỗi vòng phân tích, nếu số câu hỏi mới sinh ra lớn hơn số câu hỏi giải quyết được (`added_questions > resolved_questions`), trong khi `resolved_question_count == 0` và `verified_step_or_edge_delta == 0`, runtime sẽ bật cờ `question_runaway_detected: true` và yêu cầu dừng mở rộng nhánh để chuyển sang Bước 3.8.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis counterevidence_challenger <json_file> --artifact-id <chal_id>`
8. **Bước 3.8 — `aca_evidence_auditor` (Bắt buộc chạy TRƯỚC `chain_synthesizer`)**:
   - Trích xuất claims: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_aca_claims _analysis`
   - Nộp kiểm toán: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis aca_evidence_auditor <json_file>`
9. **Bước 3.9 — `chain_synthesizer` & Khóa sổ (`finalize_aca`)**:
   - Nộp báo cáo tổng hợp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis chain_synthesizer <json_file>`
   - Khóa sổ và xuất trọn bộ `./documents/_analysis/` + `./documents/_analysis/chains/<chain_id>/`: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_aca _analysis`
