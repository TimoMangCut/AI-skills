---
name: phase-3-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 3 Contextual Risk and Exploitability Assessment v3.0 (chứng minh Actor/Role nào chạm được code path, đánh giá kiểm soát ngoài code Cloudflare/WAF/VPC/OT Interlock và hiệu chuẩn rủi ro 5 trục S-F-O-P-C) trên toàn dự án. Kích hoạt khi người dùng gọi /phase-3-orchestrator.
---

# Phase 3 Master Orchestrator: Contextual Risk & Exploitability Assessment (LocalSec v3.0)

Khi người dùng gọi `/phase-3-orchestrator`, bạn là **Master Orchestrator của Phase 3 (Contextual Risk & Exploitability Assessment v3.0)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`.
Sau khi Phase 2 (`finalize_v3_phase2`) đã bàn giao danh sách các chuỗi tấn công **Reachable về mặt mã nguồn (`surviving_chain_ids`)**, Phase 3 bắt buộc đánh giá **100% các `chain_id` sống sót (`ARCH-3G`)** để trả lời câu hỏi quyết định ngoài đời thực:
**"Ai (Actor/Role nào) mới có thể chạm vào code path đó, có lớp phòng thủ hạ tầng/vật lý nào ngoài code chặn trước hay không, khả năng xảy ra thực tế là bao nhiêu, và mức độ rủi ro thực tế trên 5 trục S-F-O-P-C kèm chủ sở hữu rủi ro là gì?"**

---

## Kiến trúc 3 Bước + Khóa sổ & Xuất Báo cáo của Phase 3 (LocalSec v3.0)

1. **Bước 3.0 (Tùy chọn khi có thông tin vận hành/hạ tầng thực tế) — Nạp `runtime_facts.json` (`DEPTH-4.4a`)**:
   - Nếu đội vận hành/DevSecOps cung cấp thông tin thực tế về hạ tầng (WAF, ALB, VPC, mTLS, phần cứng OT), chạy:
     `python -m localsec.manual_session ingest_runtime_facts <repo_name> .localsec/tmp/runtime_facts.json`

2. **Bước 3.1 — `/phase-3-actor-and-feasibility-assessor` (`actor_and_feasibility_assessor` — `ARCH-3G`, `ARCH-3H`)**:
   - Giữ nguyên mã `chain_id` từ Phase 2 cho **100% các chuỗi sống sót**.
   - Xác định **Tác nhân Tối thiểu (`minimum_viable_actor`)**, **Chi phí chiếm đoạt danh tính (`identity_acquisition_cost`: `low` | `medium` | `high`)**, và đánh giá từng điều kiện tiên quyết theo cấu trúc `yes` / `no` / `unknown` kèm `evidence_ids` hoặc `searched_paths` (`ARCH-3H`).
   - Lưu qua CLI: `python -m localsec.manual_session submit_skill <repo_name> actor_and_feasibility_assessor .localsec/tmp/actor_and_feasibility_assessor_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`).

3. **Bước 3.2 — `/phase-3-beyond-code-control-mapper` (`beyond_code_control_mapper` — `ARCH-3G`, `ARCH-3H`)**:
   - Giữ nguyên mã `chain_id` từ Phase 2, đánh giá **Mức độ Phơi nhiễm Hạ tầng (`exposure_tier`)** và các **Kiểm soát Bù trừ Ngoài Mã nguồn (`compensating_controls`)** với trường cấu trúc `present` (`yes` | `no` | `unknown`), `status` (`observed` | `confirmed` | `hypothesis` | `absent`) và `mitigation_effect` (`blocks_exploit` | `reduces_likelihood` | `none`).
   - **Luật Cứng**: Một kiểm soát ngoài code đang ở trạng thái `status: "hypothesis"` **TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `mitigation_effect: "blocks_exploit"`**.
   - Lưu qua CLI: `python -m localsec.manual_session submit_skill <repo_name> beyond_code_control_mapper .localsec/tmp/beyond_code_control_mapper_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`).

4. **Bước 3.3 — `/phase-3-sfop-risk-calibrator` (`sfop_risk_calibrator` — `DEPTH-4.4b`, `DEPTH-4.4d`)**:
   - Hiệu chuẩn tác động độc lập trên **5 trục S-F-O-P-C** theo rubric định lượng (`basis` + `blast_radius`: `component` | `service` | `domain` | `cross_domain` | `platform`).
   - Với trục `Safety`, bắt buộc đánh giá chỉ báo kỹ thuật `actuator_command_path_without_interlock` (`yes` | `no` | `unknown`) và sinh câu hỏi bàn giao cho bộ phận HSE/Functional Safety (`hse_handoff_question`).
   - Chọn `owner_role` từ `owners.json` hoặc danh mục chuẩn (`dev_team`, `infra_cloud_sec`, `iam_platform`, `ot_safety_engineering`, `data_privacy_dpo`, `unassigned_pending_roster` — `DEPTH-4.4d`).
   - Tuân thủ **3 Luật Cứng**: `overall_risk <= max_impact`, `safety_owner != risk_owner` khi `safety != "negligible"`, và giữ song song `code_verified_severity` cùng `contextual_risk_rating`.
   - Lưu qua CLI: `python -m localsec.manual_session submit_skill <repo_name> sfop_risk_calibrator .localsec/tmp/sfop_risk_calibrator_<repo_name>.json` (tuân thủ `AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`).

5. **Bước 3.4 — Khóa sổ Phase 3 & Xuất Báo cáo (`finalize_v3_phase3` + `render_v3_report` — `ARCH-3H`, `ARCH-3I`, `DEPTH-4.8`)**:
   - Chạy `python -m localsec.manual_session finalize_v3_phase3 <repo_name>` để kiểm tra tính toàn vẹn `chain_id` xuyên suốt `3.1 -> 3.2 -> 3.3` và đối khớp công thức rủi ro.
   - Chạy `python -m localsec.manual_session render_v3_report <repo_name>` để kết xuất báo cáo kiểm toán hoàn chỉnh ra thư mục `./documents/`.
