---
name: phase-3-code-trace-builder
description: Phase 3.2 — Truy vết thủ công từng bước nhảy thực thi (`hops[]`) xuyên qua controllers, middleware, services, HTTP clients và hàm SQL (`code_trace_builder`).
---

# `phase-3-code-trace-builder` (PHASE-3 — Internal Skill ID: `code_trace_builder`)

Phase 3.2 — Truy vết thủ công từng bước nhảy thực thi (`hops[]`) xuyên qua controllers, middleware, services, HTTP clients và hàm SQL (`code_trace_builder`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-code-trace-builder Truy vết thủ công đường đi thực thi trong mã nguồn từ điểm vào qua từng hàm gọi, middleware, lệnh gọi HTTP/gRPC liên dịch vụ tới câu lệnh lưu trữ DB.
Không nhảy cóc qua các lớp trung gian: mỗi hop đánh dấu `directly_read` bắt buộc phải có `evidence_refs` (`ev_...`) chỉ rõ dữ liệu đầu vào biến đổi thế nào và nhánh kiểm tra nào đã thực thi hay bị bỏ qua.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Được phép gọi `list_dir` và `read_file` trên toàn bộ repositories (`<repo_name>:<rel_path>`).
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/code_trace_builder.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/code_trace.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file _analysis "<repo_name>:<rel_path>" 1 160 --skill code_trace_builder
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis code_trace_builder <json_file> --artifact-id <trace_id>
```
