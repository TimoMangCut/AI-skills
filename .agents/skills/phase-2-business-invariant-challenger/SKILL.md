---
name: phase-2-business-invariant-challenger
description: Phase 2.2 — Phản biện đối kháng mô hình ý định nghiệp vụ trong chế độ mù ngữ cảnh (Context-Blinded) để tìm các bất biến bị bỏ sót và trường hợp biên (`business_invariant_challenger`).
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
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/business_invariant_challenge.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> business_invariant_challenger <json_file>
```
