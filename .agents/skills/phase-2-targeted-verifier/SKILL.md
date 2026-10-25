---
name: phase-2-targeted-verifier
description: >-
  Phase 2.6 — Thực thi đọc file giới hạn trong danh sách exact_paths ở chế độ mù ngữ cảnh và chủ động tìm bằng chứng phản bác (targeted_verifier). Kích hoạt khi người dùng gọi /phase-2-targeted-verifier hoặc thực hiện bước này trong pipeline.
---

# `phase-2-targeted-verifier` (PHASE-2 — Internal Skill ID: `targeted_verifier`)

Phase 2.6 — Thực thi đọc file giới hạn trong danh sách `exact_paths` ở chế độ mù ngữ cảnh và chủ động tìm bằng chứng phản bác (`targeted_verifier`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-2-targeted-verifier Chỉ đọc các file nằm trong danh sách cho phép (`--allowed-paths`) để trả lời câu hỏi kiểm chứng một cách khách quan.
Bắt buộc tìm kiếm cả bằng chứng ủng hộ (`evidence_ids`) lẫn bằng chứng bác bỏ (`counter_evidence_ids` như guard ở tầng dưới, trigger SQL hoặc điều kiện chặn sớm).
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Bị giới hạn cứng bởi `read_scope: exact_paths` trong `ManualWorkspace`.
- **Semantic Claim-to-Excerpt Verifier Gate**: Mọi kết luận `observed` / `derived` hoặc `confirmed` trong Phase 2.6 phải đi qua kiểm định đối chiếu ký hiệu mã nguồn với `excerpt` thực tế (`verify_semantic_claims <repo_name>`). Nếu `excerpt` của `ev_...` không chứa hàm/thuộc tính/cấu hình như mô tả (ví dụ nhầm lẫn cấu hình từ repo khác sang repo hiện tại), hệ thống tự động bác bỏ khi `submit_skill` hoặc hạ cấp fail-closed khi `finalize_basv_repo`.
- Prompt & Contract gốc: `AI-skills/contracts/business-aware-security-verification-v1/prompts/targeted_verifier.md` (Registry: `AI-skills/contracts/business-aware-security-verification-v1/registry.json`).
- Schema đích: `AI-skills/contracts/business-aware-security-verification-v1/schemas/targeted_verification.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_targeted_verifier <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> 1 160 --skill targeted_verifier --allowed-paths "<path1>,<path2>"
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> targeted_verifier <json_file>
```

