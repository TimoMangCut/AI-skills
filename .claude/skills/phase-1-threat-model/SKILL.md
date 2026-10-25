---
name: phase-1-threat-model
description: >-
  Phase 1.4 — Xây dựng mô hình mối đe dọa STRIDE & kịch bản lạm dụng nghiệp vụ dựa trên bằng chứng mã nguồn (threat_model). Kích hoạt khi người dùng gọi /phase-1-threat-model hoặc thực hiện bước này trong pipeline.
---

# `phase-1-threat-model` (PHASE-1 — Internal Skill ID: `threat_model`)

Phase 1.4 — Xây dựng mô hình mối đe dọa STRIDE & kịch bản lạm dụng nghiệp vụ dựa trên bằng chứng mã nguồn (`threat_model`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-threat-model Xây dựng mô hình mối đe dọa STRIDE và kịch bản lạm dụng nghiệp vụ từ kết quả api_authz và dataflow.
Không liệt kê lý thuyết chung chung: mỗi kịch bản đe dọa phải chỉ rõ kẻ tấn công lợi dụng khe hở kiểm soát cụ thể nào trong code (`ev_...`), tài sản nào bị ảnh hưởng và cách kiểm chứng.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Ánh xạ các mối đe dọa thực tế (`threats[]`) gắn với `existing_controls`, `control_gaps`, `validation_needed`, và ưu tiên theo ngữ cảnh nghiệp vụ.
- Prompt & Contract gốc: `AI-skills/skills/prompts/threat_model.md` (Registry: `AI-skills/skills/registry.json`).
- Schema đích: `AI-skills/schemas/threat_model.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill threat_model
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> threat_model <json_file>
```
