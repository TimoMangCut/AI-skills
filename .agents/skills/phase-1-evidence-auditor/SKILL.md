---
name: phase-1-evidence-auditor
description: Phase 1.6 — Kiểm toán độc lập từng tuyên bố (claim) đối chiếu trực tiếp với trích đoạn mã nguồn `ev_...` và hạ cấp fail-closed các kết luận vượt quá bằng chứng (`evidence_auditor`).
---

# `phase-1-evidence-auditor` (PHASE-1 — Internal Skill ID: `evidence_auditor`)

Phase 1.6 — Kiểm toán độc lập từng tuyên bố (claim) đối chiếu trực tiếp với trích đoạn mã nguồn `ev_...` và hạ cấp fail-closed các kết luận vượt quá bằng chứng (`evidence_auditor`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-evidence-auditor Đóng vai kiểm toán viên độc lập: đọc từng claim và đối chiếu từng chữ với trích đoạn mã nguồn trong cited_evidence_catalog.
Không chấp nhận suy diễn hợp lý bề ngoài: nếu trích đoạn ev_... không trực tiếp chứng minh claim, bắt buộc phán quyết partially_supported, unsupported hoặc inconclusive để hệ thống tự động hạ cấp fail-closed.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Không có quyền đọc thêm file (`read_scope: none`); chỉ kiểm toán dựa trên bằng chứng đã thu thập.
- **Semantic Claim-to-Excerpt Verifier Gate**: Bắt buộc chạy `verify_semantic_claims <repo_name>` để đối chiếu tự động các ký hiệu mã nguồn (ví dụ: `TokenValidationParameters.SignatureValidator`, `SecurityAlgorithms.None`, `JwtClearToken`, tên hàm/thuộc tính) được nêu trong claim với nội dung thực tế trong `excerpt` của `ev_...`. Mọi trường hợp LLM gắn `evidence_id` thật nhưng nội dung `excerpt` không chứa ký hiệu được tuyên bố hoặc mâu thuẫn ngữ nghĩa sẽ bị cổng kiểm định tự động ép về `verdict: "unsupported"` (hạ cấp fail-closed về `unknown`).
- Prompt & Contract gốc: `AI-skills/skills/prompts/evidence_auditor.md` (Registry: `AI-skills/skills/registry.json`).
- Schema đích: `AI-skills/schemas/evidence_audit.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_claims <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> evidence_auditor <json_file>
```

