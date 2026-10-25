---
name: phase-2-implementation-trace-verifier
description: >-
  Phase 2.3 — Truy vết thủ công luồng thực thi mã nguồn thực tế đối với từng quy trình nghiệp vụ và điểm kiểm soát bất biến (implementation_trace_verifier). Kích hoạt khi người dùng gọi /phase-2-implementation-trace-verifier hoặc thực hiện bước này trong pipeline.
---

# `phase-2-implementation-trace-verifier` (PHASE-2 — Internal Skill ID: `implementation_trace_verifier`)

Phase 2.3 — Truy vết thủ công luồng thực thi mã nguồn thực tế đối với từng quy trình nghiệp vụ và điểm kiểm soát bất biến (`implementation_trace_verifier`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-implementation-trace-verifier Truy vết từng bước thực thi trong code cho mỗi bất biến nghiệp vụ (`invariants`) và giả thuyết phản biện (`challenge_cases`).
Kiểm tra đủ 5 chiều: xác thực/phân quyền, kiểm tra đầu vào, ràng buộc chuyển trạng thái (State Machine), tác động lưu trữ DB/gọi dịch vụ ngoài, và ghi vết audit.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Tạo danh sách `traces[]` với từng bước `execution_steps[]` có gắn `evidence_ids` và `counter_evidence_ids`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/implementation_trace_verifier.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/implementation_trace.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill implementation_trace_verifier
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> implementation_trace_verifier <json_file>
```
