---
name: phase-3-attack-chain-constructor
description: >-
  Phase 3.3 — Xây dựng chuỗi tấn công đa bước / xuyên dịch vụ với điều kiện tiên quyết, độ lệch trạng thái (state_after) và cạnh kích hoạt (linked_next_steps) (attack_chain_constructor). Kích hoạt khi người dùng gọi /phase-3-attack-chain-constructor hoặc thực hiện bước này trong pipeline.
---

# `phase-3-attack-chain-constructor` (PHASE-3 — Internal Skill ID: `attack_chain_constructor`)

Phase 3.3 — Xây dựng chuỗi tấn công đa bước / xuyên dịch vụ với điều kiện tiên quyết, độ lệch trạng thái (`state_after`) và cạnh kích hoạt (`linked_next_steps`) (`attack_chain_constructor`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-attack-chain-constructor Kết nối các điểm yếu rời rạc thành chuỗi tấn công có hướng từ quyền truy cập ban đầu của kẻ tấn công tới tác động nghiệp vụ tối đa có căn cứ.
Chứng minh tính bắc cầu của từng cạnh nối: đầu ra, trạng thái hoặc đặc quyền thu được ở Bước N phải khớp chính xác với điều kiện đầu vào cần thiết để kích hoạt Bước N+1.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Tuân thủ nghiêm ngặt 6 cổng kiểm định trong `_validate_aca_epistemic_gates()` (không nâng lên `confirmed` khi `request_plan_only` hoặc khi còn `preconditions` ở mức `unknown`/`refuted`).
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/attack_chain_constructor.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/attack_chain.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session submit_skill _analysis attack_chain_constructor <json_file> --artifact-id <chain_id>
```
