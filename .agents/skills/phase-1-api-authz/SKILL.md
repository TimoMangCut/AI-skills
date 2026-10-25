---
name: phase-1-api-authz
description: >-
  Phase 1.2 — Kiểm kê thủ công các inbound HTTP/RPC/Consumer entrypoints và truy vết cơ chế xác thực, phân quyền RBAC/ABAC & BOLA (api_authz). Kích hoạt khi người dùng gọi /phase-1-api-authz hoặc thực hiện bước này trong pipeline.
---

# `phase-1-api-authz` (PHASE-1 — Internal Skill ID: `api_authz`)

Phase 1.2 — Kiểm kê thủ công các inbound HTTP/RPC/Consumer entrypoints và truy vết cơ chế xác thực, phân quyền RBAC/ABAC & BOLA (`api_authz`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-api-authz Kiểm kê toàn bộ API/RPC entrypoints và truy vết cơ chế xác thực/phân quyền thực tế trong code.
Bác bỏ giả định 'chắc middleware hoặc gateway đã chặn': nếu không đọc thấy decorator/middleware kiểm tra cả vai trò (RBAC) lẫn quyền sở hữu đối tượng (BOLA/IDOR) trong trích đoạn ev_..., phải ghi nhận rõ khoảng trống kiểm soát.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Truy vết route definitions, controllers/handlers, JWT/session middleware, Casbin/policy guards, và kiểm tra `object_level_authz`.
- Prompt & Contract gốc: `AI-skills/skills/prompts/api_authz.md` (Registry: `AI-skills/skills/registry.json`).
- Schema đích: `AI-skills/schemas/api_authz.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill api_authz
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> api_authz <json_file>
```
