---
name: phase-3-counterevidence-challenger
description: Phase 3.8 — Thử thách đối kháng các chuỗi tấn công ứng viên bằng cách săn tìm kiểm soát bù trừ, cạnh nối đứt gãy, điều kiện vô nghiệm hoặc nhánh thay thế (`counterevidence_challenger`).
---

# `phase-3-counterevidence-challenger` (PHASE-3 — Internal Skill ID: `counterevidence_challenger`)

Phase 3.8 — Thử thách đối kháng các chuỗi tấn công ứng viên bằng cách săn tìm kiểm soát bù trừ, cạnh nối đứt gãy, điều kiện vô nghiệm hoặc nhánh thay thế (`counterevidence_challenger`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-counterevidence-challenger Đóng vai người bác bỏ chuỗi tấn công: chủ động đọc code để tìm các middleware, gateway filter, ràng buộc khóa ngoại/trigger SQL, hoặc điều kiện quyền hạn khiến chuỗi bị đứt gãy.
Nếu phát hiện chốt chặn làm gãy một mắt xích, hãy hạ cấp kết luận về phạm vi hẹp nhất còn đúng sự thật, đồng thời kiểm tra xem có lối vào thay thế nào đi vòng qua chốt chặn đó không.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Nhận ngữ cảnh làm mù từ `prepare_blinded_chain_verifier` và được phép đọc source code để tìm phản chứng (`counterevidence_refs`).
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/counterevidence_challenger.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/counterevidence_challenge.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier <chain_json>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file _analysis "<repo_name>:<rel_path>" 1 160 --skill counterevidence_challenger
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis counterevidence_challenger <json_file> --artifact-id <chal_id>
```
