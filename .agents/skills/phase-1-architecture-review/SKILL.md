---
name: phase-1-architecture-review
description: Phase 1.5 — Đánh giá thiết kế kiến trúc bảo mật, phân tách vùng tin cậy, khả năng chống chịu, nhật ký kiểm toán và giả định thiết kế (`architecture_review`).
---

# `phase-1-architecture-review` (PHASE-1 — Internal Skill ID: `architecture_review`)

Phase 1.5 — Đánh giá thiết kế kiến trúc bảo mật, phân tách vùng tin cậy, khả năng chống chịu, nhật ký kiểm toán và giả định thiết kế (`architecture_review`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-architecture-review Đánh giá kiến trúc bảo mật, quản lý bí mật, tính nguyên tử giao dịch và khả năng truy vết kiểm toán (auditability).
Tự phản biện: một cơ chế phòng thủ có trong thư viện dùng chung nhưng không được gắn vào pipeline khởi tạo (`Program.cs`/`main.go`) thì không được tính là kiểm soát đang hoạt động.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Ghi nhận các nhận định kiến trúc (`observations[]`) và điểm mạnh có bằng chứng (`strengths[]`).
- Schema đích: `AI-skills/schemas/architecture_review.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill architecture_review
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> architecture_review <json_file>
```
