---
name: phase-3-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 3 Contextual Risk and Exploitability Assessment v3.0 (chứng minh Actor/Role nào chạm được code path, đánh giá kiểm soát ngoài code Cloudflare/WAF/VPC/OT Interlock và hiệu chuẩn rủi ro 5 trục S-F-O-P-C) trên toàn dự án. Kích hoạt khi người dùng gọi /phase-3-orchestrator.
---

# Phase 3 Master Orchestrator: Contextual Risk & Exploitability Assessment (LocalSec v3.0)

> **Session Boundary Directive (`Repo x Phase`)**: Run Phase 3 in a fresh session per repository, starting from `.localsec/runs/default/<repo_name>/phase3_verified_queue.json` produced by `finalize_v3_phase2`.

Khi người dùng gọi `/phase-3-orchestrator`, bạn là **Master Orchestrator của Phase 3 (Contextual Risk & Exploitability Assessment v3.0)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`.
Sau khi Phase 2 (`finalize_v3_phase2`) đã bàn giao danh sách các chuỗi tấn công **Reachable về mặt mã nguồn (`phase3_verified_queue.json`)**, Phase 3 bắt buộc đánh giá **100% các `chain_id` trong cả `verified_findings` (gồm `REACHABLE_VULNERABILITY` và `REACHABLE_PARTIALLY_MITIGATED`) lẫn `hypothesis_only_findings` (`ARCH-3G`, Đợt 7 — E3)**. Chuỗi giả thuyết vẫn được đánh giá người tấn công, kiểm soát và tác động; mức rủi ro của chúng là tạm tính cho tới khi có kiểm chứng runtime. Với chuỗi `REACHABLE_PARTIALLY_MITIGATED`, đọc `challenger_notes` để biết kiểm soát nào đã che một phần. Mục tiêu là trả lời câu hỏi quyết định ngoài đời thực:
**"Ai (`minimum_actor` nào) mới có thể chạm vào code path đó, có lớp phòng thủ hạ tầng/vật lý nào ngoài code chặn trước hay không, khả năng xảy ra thực tế là bao nhiêu, và mức độ rủi ro thực tế trên 5 trục S-F-O-P-C kèm chủ sở hữu rủi ro là gì?"**

---

## Kiến trúc 3 Bước + Khóa sổ & Xuất Báo cáo của Phase 3 (LocalSec v3.0)

1. **Bước 3.0 (Tùy chọn khi có thông tin vận hành/hạ tầng thực tế) — Nạp `runtime_facts.json` (`DEPTH-4.4a`)**:
   - Nếu đội vận hành/DevSecOps cung cấp thông tin thực tế về hạ tầng (WAF, ALB, VPC, mTLS, phần cứng OT), chạy:
     `python -m localsec.manual_session ingest_runtime_facts <repo_name> .localsec/tmp/runtime_facts.json`
   - Lưu ý: Có thể chạy lại `ingest_runtime_facts` bất cứ lúc nào sau khi hoàn tất Phase 3 để tự động tính lại `feasibility_derived`, `derived_risk_rating` và cập nhật `key_questions.json` mà không tốn thêm LLM token.

2. **Bước 3.1 — `/phase-3-actor-and-feasibility-assessor` (`actor_and_feasibility_assessor` — `ARCH-3G`, `ARCH-3H`, `R2-P0-01`, `R3-A1`, `R3-A5`)**:
   - Giữ nguyên mã `chain_id` từ Phase 2 cho **100% các chuỗi trong `verified_findings` và `hypothesis_only_findings`** trong `actor_assessments[]` (thiếu chuỗi nào thì `finalize_v3_phase3` liệt kê trong `unaccounted_phase2_chains` và cổng không đạt).
   - Xác định **Tác nhân Tối thiểu (`minimum_actor`)** thuộc đúng 6 giá trị chuẩn (`external_unauthenticated`, `authenticated_user`, `b2b_partner_cross_scope`, `rogue_insider_or_operator`, `compromised_internal_component`, `physical_or_local_bus_attacker`), **Chi phí chiếm đoạt danh tính (`identity_acquisition_cost`: `none` | `low` | `medium` | `high`)**, và đánh giá từng điều kiện tiên quyết `preconditions[]` với `"status"`: `"yes"` | `"no"` | `"unknown"` (hỗ trợ cả bí danh `"precondition_status"` — `R3-A1`). Khi khai báo `"status": "no"`, bắt buộc phải cung cấp `"evidence_ids"` và `"searched_paths"` khác rỗng (`R3-A5`).
   - Lưu qua CLI: `python -m localsec.manual_session submit_skill <repo_name> actor_and_feasibility_assessor .localsec/tmp/actor_and_feasibility_assessor_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`).

3. **Bước 3.2 — `/phase-3-beyond-code-control-mapper` (`beyond_code_control_mapper` — `ARCH-3G`, `ARCH-3H`, `R2-P0-01`)**:
   - Giữ nguyên mã `chain_id` từ Phase 2 trong `beyond_code_controls[]`, đánh giá `control_id`, `layer`, `exposure_tier`, `status` (`"confirmed" | "hypothesis" | "absent"` — không dùng `"observed"`), `mitigation_effect` (`"blocks_exploit" | "reduces_likelihood" | "partial_mitigation" | "none"`), `searched_paths` và `evidence_ids`.
   - **Luật Cứng**: Một kiểm soát ngoài code đang ở trạng thái `status: "hypothesis"` **TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `mitigation_effect: "blocks_exploit"`** (chỉ được gán `"reduces_likelihood"` hoặc `"none"`).
   - Lưu qua CLI: `python -m localsec.manual_session submit_skill <repo_name> beyond_code_control_mapper .localsec/tmp/beyond_code_control_mapper_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`).

4. **Bước 3.3 — `/phase-3-sfop-risk-calibrator` (`sfop_risk_calibrator` — `DEPTH-4.4b`, `DEPTH-4.4d`, `R2-P0-01`, `R2-P0-03`, `R2-P2-01`, `R3-A5`)**:
   - Hiệu chuẩn tác động độc lập trong **`impact_axes`** (không dùng `"sfop_impacts"`) trên **5 trục S-F-O-P-C** theo bảng rubric định lượng trong `contracts/v3-orchestration.json`, bắt buộc có `basis` và `blast_radius` (`component` | `service` | `domain` | `cross_domain` | `platform`) trên từng trục.
   - Bắt buộc khai báo `"owner_role"` trên mọi finding từ danh mục chuẩn (`dev_team`, `infra_cloud_sec`, `iam_platform`, `ot_safety_engineering`, `data_privacy_dpo`, `unassigned_pending_roster`) và dùng định danh theo vai trò (`"dev_team (pending project roster)"`, `"ot_safety_engineering (pending project roster)"`) khi chưa có `owners.json` (`R3-A5`).
   - Tuân thủ **Luật Cứng**: `overall_risk <= max_impact`, `safety_owner != risk_owner` khi `safety != "negligible"`. Mặc định `finalize_v3_phase3` sẽ gán `contextual_risk_rating = derived_risk_rating` (cả trần lẫn sàn); nếu đề xuất điều chỉnh tối đa 1 bậc, bắt buộc có `"risk_override_rationale"` ($\ge 80$ ký tự) và `"risk_override_evidence_ids"` khác rỗng (`R3-A5`).
   - Lưu qua CLI: `python -m localsec.manual_session submit_skill <repo_name> sfop_risk_calibrator .localsec/tmp/sfop_risk_calibrator_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`).

5. **Bước 3.4 — Khóa sổ Phase 3 & Xuất Báo cáo (`finalize_v3_phase3` + `render_v3_report` — `ARCH-3H`, `ARCH-3I`, `R2-P0-03`, `R3-A5`, `C2`, `C6`)**:
   - Chạy `python -m localsec.manual_session finalize_v3_phase3 <repo_name>` để kiểm tra tính toàn vẹn `chain_id` xuyên suốt `3.1 -> 3.2 -> 3.3`, tính toán tất định `feasibility_derived` cùng `derived_risk_rating` (áp dụng `contextual_risk_rating = derived_risk_rating` trừ khi có override 1 bậc hợp lệ kèm `"risk_override_applied": true`), và xuất `.localsec/runs/default/<repo_name>/key_questions.json` (kèm hai nhánh `outcome_if_yes` / `outcome_if_no` và câu hỏi `KQ-OWNER-*` nếu `owner_role == "unassigned_pending_roster"`) cùng `phase3_gate_receipt.json`.
   - Chạy `python -m localsec.manual_session render_v3_report <repo_name>` để kết xuất bộ 3 báo cáo kiểm toán per-repo ra thư mục `./documents/<repo_name>/`.
   - Sau khi tất cả các repository trong dự án đã hoàn tất Phase 3, chuyển sang **Phase 4 (`/phase-4-orchestrator` — Final Synthesis & Canonical Report Generation)** trong một phiên mới:

```text
python -m localsec.manual_session finalize_v3_phase4
```
