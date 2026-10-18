---
name: phase-3-request-reproduction-operator
description: Phase 3.6 — Thực thi có kiểm soát chuỗi request trên môi trường local/test được phê duyệt hoặc ghi nhận trạng thái `not_executed` / `blocked` (`request_reproduction_operator`).
---

# `phase-3-request-reproduction-operator` (PHASE-3 — Internal Skill ID: `request_reproduction_operator`)

Phase 3.6 — Thực thi có kiểm soát chuỗi request trên môi trường local/test được phê duyệt hoặc ghi nhận trạng thái `not_executed` / `blocked` (`request_reproduction_operator`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-request-reproduction-operator Kiểm tra điều kiện an toàn trước khi thực thi bất kỳ request nào qua `run_aca_request_plan`.
Nếu không có môi trường local/test được phê duyệt tường minh (`operator_approved: true` trên localhost), bắt buộc giữ nguyên trạng thái `not_executed` — tuyệt đối không giả lập kết quả phản hồi động hay coi HTTP 200 đơn thuần là bằng chứng khai thác thành công.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Thực thi qua adapter an toàn `execute_constrained_local_request()`.
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/request_reproduction_operator.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/request_reproduction.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session run_aca_request_plan <request_json> [--target-profile <profile_json>]
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis request_reproduction_operator <json_file> --artifact-id <req_id>
```
