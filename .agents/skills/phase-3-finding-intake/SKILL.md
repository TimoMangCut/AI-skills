---
name: phase-3-finding-intake
description: Phase 3.1 — Chuẩn hóa các findings từ Phase 1 (Recon) và Phase 2 (BASV) thành các tuyên bố ứng viên và giả thuyết chuỗi tấn công cần đọc lại code (`finding_intake`).
---

# `phase-3-finding-intake` (PHASE-3 — Internal Skill ID: `finding_intake`)

Phase 3.1 — Chuẩn hóa các findings từ Phase 1 (Recon) và Phase 2 (BASV) thành các tuyên bố ứng viên và giả thuyết chuỗi tấn công cần đọc lại code (`finding_intake`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-finding-intake Thu nạp các findings từ Phase 1 và mismatches từ Phase 2 dưới dạng các giả thuyết đầu vào (candidate claims), tuyệt đối không mặc định chúng đã đúng.
Xác định rõ cho mỗi ứng viên: điều kiện tiên quyết nào còn thiếu, dịch vụ/file nào cần đọc bổ sung, và những mắt xích nào có thể ghép nối thành một chuỗi tấn công hoàn chỉnh.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Chỉ đọc artifacts của Phase 1 & 2 (`read_scope: none` đối với source code).
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/finding_intake.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/candidate_claims.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis finding_intake <json_file>
```
