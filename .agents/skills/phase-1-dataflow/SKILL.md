---
name: phase-1-dataflow
description: >-
  Phase 1.3 — Truy vết thủ công luồng dữ liệu inbound/outbound, lưu trữ DB/Cache, hàng đợi, gọi dịch vụ ngoài và ranh giới tin cậy (dataflow). Kích hoạt khi người dùng gọi /phase-1-dataflow hoặc thực hiện bước này trong pipeline.
---

# `phase-1-dataflow` (PHASE-1 — Internal Skill ID: `dataflow`)

Phase 1.3 — Truy vết thủ công luồng dữ liệu inbound/outbound, lưu trữ DB/Cache, hàng đợi, gọi dịch vụ ngoài và ranh giới tin cậy (`dataflow`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-dataflow Truy vết luồng dữ liệu từ điểm vào qua xử lý nội bộ tới DB, Queue và các lệnh gọi liên dịch vụ (HTTP/gRPC).
Kiểm tra критически tại mỗi ranh giới tin cậy (Trust Boundary): danh tính người gọi (identity_context) có được truyền nguyên vẹn và xác thực lại ở đầu nhận hay bị tin tưởng mù quáng?
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Xác định `flows[]` (`direction`, `source`, `destination`, `protocol`, `data_types`, `trust_boundary`, `identity_context`, `controls`) và `trust_boundaries[]`.
- Prompt & Contract gốc: `AI-skills/skills/prompts/dataflow.md` (Registry: `AI-skills/skills/registry.json`).
- Schema đích: `AI-skills/schemas/dataflow.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill dataflow
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> dataflow <json_file>
```
