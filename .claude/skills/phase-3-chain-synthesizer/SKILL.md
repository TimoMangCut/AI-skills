---
name: phase-3-chain-synthesizer
description: >-
  Phase 3.9 — Tổng hợp toàn bộ các chuỗi tấn công đã qua kiểm toán, phản biện đối kháng và bản đồ nguyên nhân gốc thành báo cáo cấp dự án (chain_synthesizer). Kích hoạt khi người dùng gọi /phase-3-chain-synthesizer hoặc thực hiện bước này trong pipeline.
---

# `phase-3-chain-synthesizer` (PHASE-3 — Internal Skill ID: `chain_synthesizer`)

Phase 3.9 — Tổng hợp toàn bộ các chuỗi tấn công đã qua kiểm toán, phản biện đối kháng và bản đồ nguyên nhân gốc thành báo cáo cấp dự án (`chain_synthesizer`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-chain-synthesizer Tổng hợp báo cáo chuỗi tấn công cấp dự án chỉ sau khi toàn bộ các mắt xích đã đi qua counterevidence_challenger và aca_evidence_auditor.
Phân tầng trung thực giữa chuỗi đã xác nhận động (`confirmed`), chuỗi được chứng minh hoàn toàn bằng mã nguồn (`code_supported`), chuỗi mới xác nhận một phần (`partially_confirmed`), chuỗi giả thuyết (`hypothesized`) và chuỗi đã bị bác bỏ (`refuted`).
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Xuất báo cáo tổng hợp `./documents/_analysis/07_attack_chain_analysis.md`, `09_unknowns_and_counterevidence.md`, `99_project_chain_report.md` và các thư mục `./documents/_analysis/chains/<chain_id>/`.
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/chain_synthesizer.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/chain_synthesis_report.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_aca_claims _analysis
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis aca_evidence_auditor <audit_json>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill _analysis chain_synthesizer <synth_json>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_aca _analysis
```
