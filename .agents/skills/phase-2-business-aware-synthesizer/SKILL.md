---
name: phase-2-business-aware-synthesizer
description: >-
  Phase 2.8 — Tổng hợp báo cáo xác minh bảo mật gắn ngữ cảnh nghiệp vụ sau khi đã qua kiểm toán bằng chứng độc lập (business_aware_synthesizer). Kích hoạt khi người dùng gọi /phase-2-business-aware-synthesizer hoặc thực hiện bước này trong pipeline.
---

# `phase-2-business-aware-synthesizer` (PHASE-2 — Internal Skill ID: `business_aware_synthesizer`)

Phase 2.8 — Tổng hợp báo cáo xác minh bảo mật gắn ngữ cảnh nghiệp vụ sau khi đã qua kiểm toán bằng chứng độc lập (`business_aware_synthesizer`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-business-aware-synthesizer Tổng hợp kết quả Phase 2 sau khi đã chạy evidence_auditor, tách bạch nghiêm ngặt giữa Confirmed Mismatches và Potential/Unverified Mismatches.
Không một sai lệch nào được đưa vào nhóm Confirmed nếu chưa vượt qua đủ 6 cổng kiểm định (nguồn ý định rõ ràng, trace code trực tiếp, đối sánh khớp, phản chứng đã giải quyết, hậu quả xác định, kiểm toán supported).
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Xuất báo cáo `./documents/<repo_name>/basv/18_business_aware_synthesis.md` và cấp hệ thống `./documents/_system/basv/`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/business_aware_synthesizer.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/business_aware_synthesis.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session extract_basv_claims <repo_name>
python -m localsec.manual_session submit_skill <repo_name> evidence_auditor <audit_json>
python -m localsec.manual_session submit_skill <repo_name> business_aware_synthesizer <synth_json>
python -m localsec.manual_session finalize_basv_repo <repo_name>
```
