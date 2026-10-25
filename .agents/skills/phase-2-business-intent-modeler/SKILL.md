---
name: phase-2-business-intent-modeler
description: >-
  Phase 2.1 — Xây dựng mô hình ý định nghiệp vụ, tác nhân, quy trình và bất biến miền từ tài liệu thiết kế/BRD/BRS/SQL mà không suy diễn ngược từ code (business_intent_modeler). Kích hoạt khi người dùng gọi /phase-2-business-intent-modeler hoặc thực hiện bước này trong pipeline.
---

# `phase-2-business-intent-modeler` (PHASE-2 — Internal Skill ID: `business_intent_modeler`)

Phase 2.1 — Xây dựng mô hình ý định nghiệp vụ, tác nhân, quy trình và bất biến miền từ tài liệu thiết kế/BRD/BRS/SQL mà không suy diễn ngược từ code (`business_intent_modeler`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-business-intent-modeler Trích xuất quy tắc nghiệp vụ và bất biến bảo mật (invariants) từ tài liệu BRD/BRS, đặc tả API, migration SQL và biểu mẫu.
Nguyên tắc tối thượng: Code hiện tại KHÔNG phải là ý định thiết kế; nếu phải suy luận từ code (`implementation_inference`), tuyệt đối không được gán `authoritative_in_input`.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic & Provenance Gates)
- Mô hình hóa `capabilities[]`, `invariants[]` (Maker-Checker, phân quyền, chuyển trạng thái, toàn vẹn dữ liệu), `workflows[]`, và `conflicts_and_unknowns[]`.
- **Cổng Chống Nhiễm Bẩn Nguồn Gốc (`provenance_kind`)**: Runtime tự động gắn nhãn mỗi `ev_...` thành `intent_artifact` (`.md`/`.docx`/`.xlsx`/`.sql`/spec/test), `config_or_manifest` hoặc `implementation_code`. Không được gán `authority_assessment: "authoritative_in_input"` nếu `intent_basis == "implementation_inference"` hoặc nếu toàn bộ `evidence_ids` đều thuộc loại `implementation_code`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/business_intent_modeler.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/business_intent_model.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill business_intent_modeler
python -m localsec.manual_session submit_skill <repo_name> business_intent_modeler <json_file>
```
