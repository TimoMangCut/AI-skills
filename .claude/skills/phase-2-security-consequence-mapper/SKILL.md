---
name: phase-2-security-consequence-mapper
description: >-
  Phase 2.7 — Đánh giá xem các sai lệch giữa ý định và triển khai có tạo ra hậu quả bảo mật, gian lận tài chính hay vi phạm toàn vẹn thực sự hay không (security_consequence_mapper). Kích hoạt khi người dùng gọi /phase-2-security-consequence-mapper hoặc thực hiện bước này trong pipeline.
---

# `phase-2-security-consequence-mapper` (PHASE-2 — Internal Skill ID: `security_consequence_mapper`)

Phase 2.7 — Đánh giá xem các sai lệch giữa ý định và triển khai có tạo ra hậu quả bảo mật, gian lận tài chính hay vi phạm toàn vẹn thực sự hay không (`security_consequence_mapper`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-security-consequence-mapper Phân biệt rạch ròi giữa lỗi logic nghiệp vụ thuần túy (`business_correctness_only`) và lỗ hổng bảo mật có thể bị khai thác (`security_relevant`).
Đánh giá mức độ nghiêm trọng theo ngữ cảnh thực tế: khả năng tự động hóa, vượt chốt kiểm soát tài chính/Maker-Checker, độ rộng vùng ảnh hưởng (blast radius) và các lớp phòng thủ bù trừ.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Xây dựng các kịch bản hậu quả bảo mật (`scenarios[]`) và tách riêng `non_security_business_mismatches[]`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/security_consequence_mapper.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/security_consequence_map.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session submit_skill <repo_name> security_consequence_mapper <json_file>
```
