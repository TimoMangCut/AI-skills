---
name: phase-3-chain-step-verifier
description: Phase 3.4 — Xác minh độc lập từng mắt xích (`step_results`) và từng cạnh chuyển tiếp (`edge_results`) của chuỗi tấn công trong chế độ mù kết luận (`chain_step_verifier`).
---

# `phase-3-chain-step-verifier` (PHASE-3 — Internal Skill ID: `chain_step_verifier`)

Phase 3.4 — Xác minh độc lập từng mắt xích (`step_results`) và từng cạnh chuyển tiếp (`edge_results`) của chuỗi tấn công trong chế độ mù kết luận (`chain_step_verifier`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-chain-step-verifier Kiểm chứng độc lập từng bước và từng cạnh nối của chuỗi tấn công từ ngữ cảnh đã cắt bỏ kết luận của Constructor (`prepare_blinded_chain_verifier`).
Đọc lại mã nguồn độc lập để trả lời: bước này có thực sự chạm tới được với quyền của Actor không, và trạng thái tạo ra ở bước trước có thực sự được bước sau tiêu thụ như tuyên bố không?
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Được phép đọc mã nguồn độc lập (`list_dir`, `read_file`) để xác nhận hoặc bác bỏ từng bước/cạnh.
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/chain_verification.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier <chain_json>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file _analysis "<repo_name>:<rel_path>" 1 160 --skill chain_step_verifier
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis chain_step_verifier <json_file> --artifact-id <verification_id>
```
