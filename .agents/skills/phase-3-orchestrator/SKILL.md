---
name: phase-3-orchestrator
description: >-
  Master Orchestrator duy nhất cần gọi để chạy trọn bộ Phase 3 Contextual Risk and Exploitability Assessment v3.0 (chứng minh Actor/Role nào chạm được code path, đánh giá kiểm soát ngoài code Cloudflare/WAF/VPC/OT Interlock và hiệu chuẩn rủi ro 5 trục S-F-O-P-C) trên toàn dự án. Kích hoạt khi người dùng gọi /phase-3-orchestrator.
---

# Phase 3 Master Orchestrator: Contextual Risk & Exploitability Assessment (LocalSec v3.0)

Khi người dùng gọi `/phase-3-orchestrator`, bạn là **Master Orchestrator của Phase 3 (Contextual Risk & Exploitability Assessment v3.0)**.
Sau khi Phase 2 đã chứng minh một lỗ hổng/chuỗi tấn công là **Reachable về mặt mã nguồn** và vượt qua phản biện bác bỏ, Phase 3 trả lời câu hỏi quyết định ngoài đời thực:
**"Ai (Actor/Role nào) mới có thể chạm vào code path đó, có lớp phòng thủ hạ tầng/vật lý nào ngoài code chặn trước hay không, khả năng xảy ra thực tế là bao nhiêu, và mức độ rủi ro thực tế trên 5 trục S-F-O-P-C là gì?"**

*(Lưu ý: Phase 4 — Viết Report tổng hợp — được tách riêng và chưa kích hoạt trong phạm vi Phase 3 này).*

---

## Kiến trúc 3 Bước Bắt buộc của Phase 3 (LocalSec v3.0)

1. **Bước 3.1 — `/phase-3-actor-and-feasibility-assessor` (`actor_and_feasibility_assessor`)**:
   - Xác định **Tác nhân Tối thiểu (`minimum_viable_actor`)** có thể kích hoạt code path lỗi:
     - `unauthenticated_external`
     - `authenticated_consumer_b2c` (tự đăng ký tài khoản Mobile/Web)
     - `enterprise_partner_dealer` (đại lý/đối tác B2B/nhượng quyền)
     - `internal_employee_operator` (nhân viên vận hành/kỹ thuật viên xưởng/SOC)
     - `compromised_edge_device_tbox_charger_robot` (T-Box xe, trụ sạc OCPP, Robot, PLC)
     - `privileged_admin_devops`
   - Đánh giá **Chi phí chiếm đoạt danh tính (`identity_acquisition_cost`: `low` | `medium` | `high`)**, điều kiện vận hành tiên quyết (`operational_preconditions`) và ghi nhận trung thực nếu việc kiểm chứng thực tế đang bị chặn bởi môi trường (`blocked_by_environment: true`, ví dụ thiếu tài khoản test role Dealer hoặc thiết bị phần cứng).
   - Lưu qua CLI: `python3 -m localsec.manual_session submit_skill _analysis actor_and_feasibility_assessor /tmp/actor_and_feasibility_assessor.json`.

2. **Bước 3.2 — `/phase-3-beyond-code-control-mapper` (`beyond_code_control_mapper`)**:
   - Đánh giá **Mức độ Phơi nhiễm Hạ tầng (`exposure_tier`)**:
     - `internet_public_behind_cloudflare_waf` vs `internet_public_bare_alb_direct_ip`
     - `partner_b2b_mtls_vpn` vs `internal_vpc_rfc1918` (`10.x`) vs `air_gapped_ot_cell_vlan`
   - Đánh giá các **Kiểm soát Bù trừ Ngoài Mã nguồn (`compensating_controls`)**: Cloudflare WAF, Kong/KrakenD Gateway plugin, K8s NetworkPolicy, AWS IoT Core Policy, mTLS pinning, Hardware BMS Cutoff / PLC Safety Interlock.
   - **Luật Cứng**: Một kiểm soát ngoài code đang ở trạng thái `status: "hypothesis"` (chưa có bằng chứng cấu hình/IaC xác nhận) **TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `mitigation_effect: "blocks_exploit"`**.
   - Lưu qua CLI: `python3 -m localsec.manual_session submit_skill _analysis beyond_code_control_mapper /tmp/beyond_code_control_mapper.json`.

3. **Bước 3.3 — `/phase-3-sfop-risk-calibrator` (`sfop_risk_calibrator`)**:
   - Đánh giá tác động độc lập trên **5 trục S-F-O-P-C**:
     - `safety` (An toàn Sinh mạng & Vật lý: xe điện, trạm sạc, pin BESS, robot, y tế, luyện kim, đường sắt)
     - `financial` (Tài chính, thanh toán, cước sạc, SAP/B2B)
     - `operational` (Vận hành, độ sẵn sàng đội xe/nhà máy/trạm sạc/SCADA)
     - `privacy` (PII, hành trình GPS, video/audio cabin, trọng số mô hình AI)
     - `compliance` (Nghị định 13 PDPD, UNECE R155/R156, ISO 26262, IEC 62443, PCI-DSS)
   - Tuân thủ **3 Luật Cứng Bắt buộc**:
     1. **`overall_risk <= max_impact`**: `contextual_risk_rating` không bao giờ vượt quá `max_impact` của 5 trục (cấm cộng dồn đa trục).
     2. **`Safety Owner != Security Risk Owner`**: Khi `safety != "negligible"`, bắt buộc khai báo `safety_owner` (HSE / Functional Safety) tách biệt với `risk_owner`.
     3. **Giữ song song `code_verified_severity` (từ Phase 2) và `contextual_risk_rating` (từ Phase 3)**.
   - Lưu qua CLI: `python3 -m localsec.manual_session submit_skill _analysis sfop_risk_calibrator /tmp/sfop_risk_calibrator.json`.
