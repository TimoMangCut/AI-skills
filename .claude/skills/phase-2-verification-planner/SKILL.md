---
name: phase-2-verification-planner
description: >-
  Phase 2.5 — Lập kế hoạch kiểm chứng có giới hạn và đặt câu hỏi trung lập (không dẫn dắt) cho các sai lệch còn nghi ngờ (verification_planner). Kích hoạt khi người dùng gọi /phase-2-verification-planner hoặc thực hiện bước này trong pipeline.
---

# `phase-2-verification-planner` (PHASE-2 — Internal Skill ID: `verification_planner`)

Phase 2.5 — Lập kế hoạch kiểm chứng có giới hạn và đặt câu hỏi trung lập (không dẫn dắt) cho các sai lệch còn nghi ngờ (`verification_planner`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-verification-planner Thiết kế các nhiệm vụ kiểm chứng mục tiêu (`tasks[]`) với câu hỏi hoàn toàn trung lập và danh sách đường dẫn `candidate_paths` cụ thể.
Tuyệt đối không cài kết luận mỏ neo vào câu hỏi: hãy hỏi 'Hàm X kiểm tra điều kiện gì trước khi cập nhật trạng thái Y?' thay vì 'Hãy xác nhận hàm X bị lỗi thiếu kiểm tra'.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Xác định `candidate_paths`, `expected_evidence`, `acceptance_criteria`, và `stop_if` cho mỗi nhiệm vụ kiểm chứng.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/verification_planner.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/verification_plan.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> verification_planner <json_file>
```
