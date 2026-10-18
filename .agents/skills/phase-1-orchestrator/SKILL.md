---
name: phase-1-orchestrator
description: Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 1 (Manual Code Reconnaissance v0.2 — 8 bước bắt buộc) trên toàn bộ repositories của dự án.

## Bản Đồ Đường Dẫn Nội Bộ (Internal Resource Mapping tại `AI-skills/`)
> **LƯU Ý QUAN TRỌNG CHO AI AGENT**: Khi bộ kỹ năng được tích hợp vào một Project mục tiêu (`<Project-Root>`), toàn bộ mã nguồn Engine, Prompts và JSON Schemas nằm gọn bên trong thư mục `AI-skills/` (không nằm rời rạc ở gốc Project). Hãy truy cập trực tiếp các đường dẫn chuẩn hóa sau:
- **Engine CLI**: `AI-skills/localsec/manual_session.py` (gọi qua `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...`)
- **Cấu hình Runtime**: `AI-skills/localsec.toml` (hoặc `<Project-Root>/localsec.toml` nếu muốn ghi đè)
- **Skill Registry**: `AI-skills/skills/registry.json`
- **Thư mục Prompts gốc**: `AI-skills/skills/prompts/`
- **Thư mục JSON Schemas**: `AI-skills/schemas/`
- **Quy ước `<repo_name>`**:
  - **Multi-repo Workspace** (nhiều repo con nằm trong `<Project-Root>`): truyền tên thư mục con (ví dụ: `auth-service`, `payment-api`).
  - **Single-repo Project** (`<Project-Root>` chính là repo cần review): truyền `.` hoặc tên thư mục gốc của project; Engine tự động bỏ qua `AI-skills/`, `.agents/`, `.localsec/`, `documents/`.

---

# `phase-1-orchestrator` — Master Orchestrator cho Phase 1 (Manual Code Reconnaissance)

Khi người dùng gọi `/phase-1-orchestrator`, bạn **BẮT BUỘC** thực thi tuần tự toàn bộ **8 bước chuyên môn** bên dưới cho từng repository và tổng hợp toàn hệ thống. **Cơ chế khóa cứng (State-Machine Gate)** trong `AI-skills/localsec/manual_session.py` sẽ chặn lệnh `finalize_repo` nếu bạn bỏ qua bất kỳ bước nào.

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-orchestrator Thực hiện trọn bộ Phase 1 (Manual Recon) cho toàn bộ repositories trên nhánh <prod|main>.
Áp dụng kỷ luật Refute-first: không dùng SAST/grep, chỉ đọc file thủ công qua ManualWorkspace để sinh mã ev_..., tách bạch Confirmed (observed/derived) với Hypothesis/Unknown, và bắt buộc chạy evidence_auditor hạ cấp fail-closed trước khi tổng hợp hệ thống.
```

---

## Vòng lặp Thực thi Bắt buộc cho Từng Repository (`<repo_name>`)

Trước và sau mỗi bước, kiểm tra trạng thái và chẩn đoán độ phủ ngữ nghĩa (`semantic_coverage_diagnostics`) bằng:
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 1
```
- **Cổng Chống Độ Phủ Giả Tạo (Semantic vs File Coverage Gate)**: Không được dừng ở việc nộp đủ 7 file JSON trên giấy tờ. Phải kiểm tra `semantic_coverage_diagnostics.distinct_files_read` và đảm bảo không còn `semantic_warnings` (đọc tối thiểu các manifest, entrypoints, auth middleware, controllers và DB/HTTP clients trước khi đóng gói).

1. **Bước 1.1 — `repo_profile`** (Tham chiếu `.agents/skills/phase-1-repo-profile/SKILL.md` & `AI-skills/schemas/repo_profile.schema.json`):
   - Chạy `list_dir` (`--depth 2`) và `read_file` (`--skill repo_profile`) trên manifest, entrypoint, config.
   - Nộp kết quả: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> repo_profile <json_file>`
2. **Bước 1.2 — `api_authz`** (Tham chiếu `.agents/skills/phase-1-api-authz/SKILL.md` & `AI-skills/schemas/api_authz.schema.json`):
   - Đọc controllers, routes, auth middleware (`--skill api_authz`), kiểm tra RBAC/ABAC và `object_level_authz` (BOLA/IDOR).
   - Nộp kết quả: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> api_authz <json_file>`
3. **Bước 1.3 — `dataflow`** (Tham chiếu `.agents/skills/phase-1-dataflow/SKILL.md` & `AI-skills/schemas/dataflow.schema.json`):
   - Đọc DB repositories, HTTP/gRPC clients, queue producers/consumers (`--skill dataflow`), xác định `trust_boundaries` và `identity_context`.
   - Nộp kết quả: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> dataflow <json_file>`
4. **Bước 1.4 — `threat_model`** (Tham chiếu `.agents/skills/phase-1-threat-model/SKILL.md` & `AI-skills/schemas/threat_model.schema.json`):
   - Xây dựng kịch bản STRIDE và lạm dụng nghiệp vụ gắn với `evidence_ids` thực tế.
   - Nộp kết quả: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> threat_model <json_file>`
5. **Bước 1.5 — `architecture_review`** (Tham chiếu `.agents/skills/phase-1-architecture-review/SKILL.md` & `AI-skills/schemas/architecture_review.schema.json`):
   - Đánh giá kiến trúc bảo mật, quản lý secret, logging/auditability.
   - Nộp kết quả: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> architecture_review <json_file>`
6. **Bước 1.6 — `evidence_auditor` (Cổng Kiểm toán Độc lập — Bắt buộc chạy trước khi xuất báo cáo)**:
   - Trích xuất claims: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_claims <repo_name>`
   - Đối chiếu từng claim với trích đoạn `ev_...` và nộp: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> evidence_auditor <json_file>`
7. **Bước 1.7 — `diagram_author`** (Tham chiếu `.agents/skills/phase-1-diagram-author/SKILL.md` & `AI-skills/schemas/diagrams.schema.json`):
   - Nộp sơ đồ Mermaid của repo: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> diagram_author <json_file>`
8. **Bước 1.8 — Khóa sổ Repository (`finalize_repo`)**:
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_repo <repo_name>` (tự động áp dụng `_apply_audit` hạ cấp fail-closed và xuất `./documents/<repo_name>/`).

---

## Tổng hợp Cấp Hệ thống (Sau khi tất cả Repositories hoàn tất Bước 1.1 – 1.8)

1. Chuẩn bị ngữ cảnh Round-Robin: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_system_context`
2. Thực thi `cross_repo_review` (`.agents/skills/phase-1-cross-repo-review/SKILL.md`), kiểm toán `evidence_auditor` cấp hệ thống và `diagram_author` cấp hệ thống.
3. Khóa sổ toàn hệ thống: `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_system --cross-repo <path> --sys-audit <path> --diagrams <path>`
