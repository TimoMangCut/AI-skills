---
name: phase-1-repo-profile
description: Phase 1.1 — Khảo sát thủ công mục đích nghiệp vụ, mức độ trọng yếu, techstack, entrypoints và dữ liệu nhạy cảm của repository (`repo_profile`).
---

# `phase-1-repo-profile` (PHASE-1 — Internal Skill ID: `repo_profile`)

Phase 1.1 — Khảo sát thủ công mục đích nghiệp vụ, mức độ trọng yếu, techstack, entrypoints và dữ liệu nhạy cảm của repository (`repo_profile`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-repo-profile Khảo sát thủ công cấu trúc, manifest, cấu hình và điểm vào của repository.
Đặt câu hỏi phản biện: 'Làm sao biết thành phần này thực sự chạy ở production chứ không phải dead code/template?' Chỉ đánh dấu observed khi có ev_... trực tiếp; mọi suy đoán từ tên file phải gắn nhãn hypothesis hoặc unknown.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Đọc manifest, `Program.cs`/`main.go`/`package.json`/`pubspec.yaml`, Dockerfile, cấu hình môi trường để xác định `purpose`, `criticality`, `techstack`, `business_capabilities`, `entrypoints`, `sensitive_data`.
- Prompt & Contract gốc: `AI-skills/skills/prompts/repo_profile.md` (Registry: `AI-skills/skills/registry.json`).
- Schema đích: `AI-skills/schemas/repo_profile.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill repo_profile
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill repo_profile
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> repo_profile <json_file>
```
