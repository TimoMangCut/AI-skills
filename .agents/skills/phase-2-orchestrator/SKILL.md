---
name: phase-2-orchestrator
description: Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 2 (Business-Aware Security Verification v1.0 — 9 bước bắt buộc) trên toàn bộ repositories của dự án.

## Bản Đồ Đường Dẫn Nội Bộ (Internal Resource Mapping tại `AI-skills/`)
> **LƯU Ý QUAN TRỌNG CHO AI AGENT**: Khi bộ kỹ năng được tích hợp vào một Project mục tiêu (`<Project-Root>`), toàn bộ mã nguồn Engine, Prompts và JSON Schemas nằm gọn bên trong thư mục `AI-skills/` (không nằm rời rạc ở gốc Project). Hãy truy cập trực tiếp các đường dẫn chuẩn hóa sau:
- **Engine CLI**: `AI-skills/localsec/manual_session.py` (gọi qua `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...`)
- **Cấu hình Runtime**: `AI-skills/localsec.toml` (hoặc `<Project-Root>/localsec.toml` nếu muốn ghi đè)
- **Skill Registry**: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`
- **Thư mục Prompts gốc**: `AI-skills/contracts/business-aware-security-verification-v1/prompts/`
- **Thư mục JSON Schemas**: `AI-skills/contracts/business-aware-security-verification-v1/schemas/`
- **Quy ước `<repo_name>`**:
  - **Multi-repo Workspace** (nhiều repo con nằm trong `<Project-Root>`): truyền tên thư mục con (ví dụ: `auth-service`, `payment-api`).
  - **Single-repo Project** (`<Project-Root>` chính là repo cần review): truyền `.` hoặc tên thư mục gốc của project; Engine tự động bỏ qua `AI-skills/`, `.agents/`, `.localsec/`, `documents/`.

---

# `phase-2-orchestrator` — Master Orchestrator cho Phase 2 (Business-Aware Security Verification)

Khi người dùng gọi `/phase-2-orchestrator`, bạn **BẮT BUỘC** thực thi tuần tự toàn bộ **9 bước chuyên môn** bên dưới cho từng repository và tổng hợp toàn hệ thống. **Cơ chế khóa cứng (State-Machine Gate)** trong `AI-skills/localsec/manual_session.py` sẽ chặn việc nộp `business_aware_synthesizer` nếu chưa có `evidence_auditor`, và chặn `finalize_basv_repo` nếu thiếu bất kỳ bước bắt buộc nào.

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-orchestrator Thực hiện trọn bộ Phase 2 (Business-Aware Security Verification) nối tiếp kết quả Phase 1 trên toàn bộ repositories.
Bắt buộc đối chiếu nguồn sự thật nghiệp vụ (BRD/BRS/SQL/Specs), làm mù ngữ cảnh (Context-Blinding) khi chạy Challenger & Targeted Verifier, lập bản đồ liên kết giữa các service và chạy evidence_auditor trước khi tổng hợp.
```

---

## Vòng lặp Thực thi Bắt buộc cho Từng Repository (`<repo_name>`)

Trước và sau mỗi bước, kiểm tra trạng thái bằng:
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 2
```

1. **Bước 2.1 — `business_intent_modeler`** (Tham chiếu `.agents/skills/phase-2-business-intent-modeler/SKILL.md`):
   - Đọc tài liệu BRD/BRS/Specs/SQL (hỗ trợ đọc liên repo `<other_repo>:<rel_path>` và file `.xlsx`/`.docx`) bằng `--skill business_intent_modeler`.
   - **Cổng Chống Nhiễm Bẩn Nguồn Gốc (Provenance Contamination Gate)**: Mỗi `ev_...` được runtime gắn nhãn `provenance_kind` (`intent_artifact` vs `config_or_manifest` vs `implementation_code`). Tuyệt đối không gán `authoritative_in_input` cho `implementation_inference`, và không được gán `authoritative_in_input` (`explicit_requirement`) nếu toàn bộ `evidence_ids` đều thuộc loại `implementation_code`.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> business_intent_modeler <json_file>`
2. **Bước 2.2 — `business_invariant_challenger` (Context-Blinded)** (Tham chiếu `.agents/skills/phase-2-business-invariant-challenger/SKILL.md`):
   - Lấy ngữ cảnh đã làm mù (tự động loại bỏ Threat Model & Findings của Phase 1):
     `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_challenger <repo_name>`
   - Phản biện các bất biến nghiệp vụ trong chế độ mù ngữ cảnh.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> business_invariant_challenger <json_file>`
3. **Bước 2.3 — `implementation_trace_verifier`** (Tham chiếu `.agents/skills/phase-2-implementation-trace-verifier/SKILL.md`):
   - Đọc mã nguồn thực thi (`--skill implementation_trace_verifier`) qua Controller, Service, DB, HTTP/gRPC Client liên dịch vụ.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> implementation_trace_verifier <json_file>`
4. **Bước 2.4 — `intent_implementation_comparator`** (Tham chiếu `.agents/skills/phase-2-intent-implementation-comparator/SKILL.md`):
   - Đối sánh Expected Intent với Observed Implementation. Mọi `mismatch` ở mức `observed`/`derived` bắt buộc phải có cả `intent_evidence_ids` lẫn `implementation_evidence_ids`.
   - **Cổng Chặn Tự So Sánh Vòng Lặp (Anti-Circular Provenance Gate)**: Runtime sẽ bác bỏ (`OutputValidationError`) nếu `set(intent_evidence_ids) == set(implementation_evidence_ids)` hoặc nếu một `observed` mismatch chỉ trích dẫn `implementation_code` trong `intent_evidence_ids`.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> intent_implementation_comparator <json_file>`
5. **Bước 2.5 — `verification_planner`** (Tham chiếu `.agents/skills/phase-2-verification-planner/SKILL.md`):
   - Đặt câu hỏi kiểm chứng trung lập (không dẫn dắt) kèm danh sách `candidate_paths` cụ thể.
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> verification_planner <json_file>`
6. **Bước 2.6 — `targeted_verifier` (Context-Blinded & Path-Bound)** (Tham chiếu `.agents/skills/phase-2-targeted-verifier/SKILL.md`):
   - Lấy danh sách task đã làm mù (tự động loại bỏ `comparison_result`, `security_impact`, `exploitability`):
     `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_targeted_verifier <repo_name>`
   - Chỉ đọc các file trong `--allowed-paths` để tìm cả bằng chứng ủng hộ (`evidence_ids`) lẫn bằng chứng bác bỏ (`counter_evidence_ids`).
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> targeted_verifier <json_file>`
7. **Bước 2.7 — `security_consequence_mapper`** (Tham chiếu `.agents/skills/phase-2-security-consequence-mapper/SKILL.md`):
   - Tách bạch lỗi nghiệp vụ thuần túy (`business_correctness_only`) với lỗ hổng bảo mật (`security_relevant`).
   - Nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> security_consequence_mapper <json_file>`
8. **Bước 2.8 — `evidence_auditor` (Bắt buộc chạy TRƯỚC `business_aware_synthesizer` — Có Bảo Toàn Giả Thuyết)**:
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_basv_claims <repo_name>`
   - **Cơ chế Bảo toàn Giả thuyết (`Hypothesis Preservation`)**: Chỉ những claim bị phán quyết `unsupported` mới bị hạ về `unknown`; các claim `partially_supported` hoặc `inconclusive` được hạ về `hypothesis` (`preserved_hypothesis_lead: true`) để giữ lại manh mối cho `verification_planner` và Phase 3 `finding_intake`.
   - Nộp kiểm toán: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> evidence_auditor <json_file>`
9. **Bước 2.9 — `business_aware_synthesizer` & Khóa sổ (`finalize_basv_repo`)**:
   - Nộp tổng hợp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> business_aware_synthesizer <json_file>`
   - Khóa sổ và xuất `./documents/<repo_name>/basv/`: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_basv_repo <repo_name>`

---

## Bước Tổng hợp Toàn Hệ thống (System-Level BASV Synthesis)

Sau khi tất cả repositories đã chạy xong `finalize_basv_repo`:
1. Xuất trọn bộ báo cáo BASV cấp hệ thống vào `./documents/_system/basv/` (gồm Ma trận Liên kết Dịch vụ, Đồ thị Mâu thuẫn 5 Trục, và Báo cáo Tổng hợp BASV Toàn Hệ thống):
   ```bash
   PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_basv_system
   ```
   *(Tùy chọn truyền thêm `--synthesis <json_file> --sys-audit <json_file> --interconnections <json_file>` nếu có bản tổng hợp/kiểm toán cấp hệ thống riêng).*
