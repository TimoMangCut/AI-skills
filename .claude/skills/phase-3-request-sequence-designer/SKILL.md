---
name: phase-3-request-sequence-designer
description: >-
  Phase 3.5 — Thiết kế chuỗi HTTP/RPC request kiểm định có khả năng phân biệt rõ hành vi an toàn và hành vi lỗi bằng dữ liệu giả lập (request_sequence_designer). Kích hoạt khi người dùng gọi /phase-3-request-sequence-designer hoặc thực hiện bước này trong pipeline.
---

# `phase-3-request-sequence-designer` (PHASE-3 — Internal Skill ID: `request_sequence_designer`)

Phase 3.5 — Thiết kế chuỗi HTTP/RPC request kiểm định có khả năng phân biệt rõ hành vi an toàn và hành vi lỗi bằng dữ liệu giả lập (`request_sequence_designer`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-request-sequence-designer Thiết kế chuỗi request kiểm định giả thuyết sử dụng hoàn toàn biến giữ chỗ (`${BASE_URL}`, `${SYNTHETIC_TOKEN}`) và dữ liệu giả lập an toàn.
Mỗi bước request phải định nghĩa rõ tiêu chí phân biệt: phản hồi/trạng thái nào chứng minh kiểm soát bảo mật hoạt động đúng (`expected_safe_outcome`) và dấu hiệu nào chứng minh lỗ hổng tồn tại (`expected_vulnerable_outcome`).
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Mặc định `execution_status: "plan_only"` và `executed: false` đối với mọi request chưa thực thi.
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/request_sequence_designer.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/request_reproduction.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session submit_skill _analysis request_sequence_designer <json_file> --artifact-id <req_id>
```
