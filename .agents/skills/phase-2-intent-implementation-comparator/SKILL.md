---
name: phase-2-intent-implementation-comparator
description: Phase 2.4 — Đối sánh Ý định Nghiệp vụ với Triển khai Thực tế qua cổng kiểm định bằng chứng kép (`intent_implementation_comparator`).
---

# `phase-2-intent-implementation-comparator` (PHASE-2 — Internal Skill ID: `intent_implementation_comparator`)

Phase 2.4 — Đối sánh Ý định Nghiệp vụ với Triển khai Thực tế qua cổng kiểm định bằng chứng kép (`intent_implementation_comparator`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-intent-implementation-comparator Đối sánh trực tiếp hành vi kỳ vọng (Expected Intent) với hành vi thực tế trong code (Observed Implementation).
Tuân thủ cổng bằng chứng kép: chỉ được kết luận `mismatch` ở mức `observed`/`derived` khi có ĐỒNG THỜI cả `intent_evidence_ids` lẫn `implementation_evidence_ids`; nếu ý định mơ hồ phải gán `intent_ambiguous`.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic & Provenance Gates)
- Phân loại từng `comparisons[]` thành `aligned`, `mismatch`, `partial`, `contradictory`, `intent_ambiguous`, hoặc `not_verified`.
- **Cổng Chặn Tự So Sánh Vòng Lặp (Anti-Circular Provenance Gate)**: Mọi `mismatch` ở mức `observed`/`derived` phải có `set(intent_evidence_ids) != set(implementation_evidence_ids)` và một `observed` mismatch không được chỉ trích dẫn `implementation_code` trong `intent_evidence_ids`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/intent_implementation_comparator.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/intent_implementation_comparison.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> intent_implementation_comparator <json_file>
```
