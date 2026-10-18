---
name: phase-1-diagram-author
description: Phase 1.8 — Xây dựng sơ đồ Mermaid biểu diễn kiến trúc và luồng dữ liệu có phân biệt rõ cạnh đã xác nhận và cạnh giả thuyết (`diagram_author`).
---

# `phase-1-diagram-author` (PHASE-1 — Internal Skill ID: `diagram_author`)

Phase 1.8 — Xây dựng sơ đồ Mermaid biểu diễn kiến trúc và luồng dữ liệu có phân biệt rõ cạnh đã xác nhận và cạnh giả thuyết (`diagram_author`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-diagram-author Vẽ sơ đồ Mermaid cho từng repository và toàn hệ thống từ kết quả đã qua kiểm toán.
Mọi kết nối liên dịch vụ chưa xác minh đủ cả hai đầu phải được vẽ bằng nét đứt hoặc gắn nhãn hypothesis/unknown, tuyệt đối không vẽ thành luồng xác nhận giả tạo.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Xuất `repo_diagrams[]` và `system_diagram` đúng cú pháp `flowchart LR` / `flowchart TD`.
- Schema đích: `AI-skills/schemas/diagrams.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> diagram_author <json_file>
```
