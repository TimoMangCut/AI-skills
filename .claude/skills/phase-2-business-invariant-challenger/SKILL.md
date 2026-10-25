---
name: phase-2-business-invariant-challenger
description: >-
  Phase 2.2 — Phản biện đối kháng mô hình ý định nghiệp vụ trong chế độ mù ngữ cảnh (Context-Blinded) để tìm các bất biến bị bỏ sót và trường hợp biên (business_invariant_challenger). Kích hoạt khi người dùng gọi /phase-2-business-invariant-challenger hoặc thực hiện bước này trong pipeline.
---

# `phase-2-business-invariant-challenger` (PHASE-2 — Internal Skill ID: `business_invariant_challenger`)

Phase 2.2 — Phản biện đối kháng mô hình ý định nghiệp vụ trong chế độ mù ngữ cảnh (Context-Blinded) để tìm các bất biến bị bỏ sót và trường hợp biên (`business_invariant_challenger`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-business-invariant-challenger Phản biện mô hình nghiệp vụ dưới góc nhìn kẻ gian lận (Fraudster/Attacker) mà không nhìn trước kết quả lỗ hổng của Phase 1.
Đặt câu hỏi cho mọi quy trình: 'Điều gì xảy ra nếu bước A bị gọi lặp, bỏ qua bước B, đảo thứ tự trạng thái, hoặc người tạo tự phê duyệt chính hồ sơ của mình?'
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Nhận ngữ cảnh đã làm mù từ `build_blinded_challenger_context()` và sinh các `challenge_cases[]` cùng `coverage_gaps[]`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/business_invariant_challenger.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/business_invariant_challenge.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session prepare_blinded_challenger <repo_name>
python -m localsec.manual_session submit_skill <repo_name> business_invariant_challenger <json_file>
```
