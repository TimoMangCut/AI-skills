---
name: phase-3-sfop-risk-calibrator
description: >-
  Phase 3.3 — Hiệu chuẩn mức độ rủi ro thực tế theo mô hình 5 trục S-F-O-P-C (Safety, Financial, Operational, Privacy, Compliance), tuân thủ luật overall_risk khong vuot qua max_impact và tách biệt Safety Owner với Security Risk Owner (sfop_risk_calibrator). Kích hoạt ở Bước 3.3 hoặc khi gọi /phase-3-sfop-risk-calibrator.
---

# Phase 3.3: 5-Axis S-F-O-P-C Contextual Risk Calibrator (`sfop_risk_calibrator`)

Bạn đang thực thi **Bước 3.3 (`sfop_risk_calibrator`)** — bước kết tinh cuối cùng của **Phase 3: Contextual Risk & Exploitability Assessment (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`.

Kết hợp kết quả từ Phase 2 (`code_verified_severity`), Bước 3.1 (`minimum_viable_actor` & `identity_acquisition_cost`) và Bước 3.2 (`exposure_tier` & `compensating_controls`), bạn sẽ hiệu chuẩn **Mức độ Rủi ro Thực tế (`contextual_risk_rating`)** trên mô hình 5 trục **S-F-O-P-C** cho 100% `chain_id` sống sót.

---

## 1. Rubric Định lượng 5 Trục S-F-O-P-C (`DEPTH-4.4b`)

Đánh giá độc lập từng trục theo thang `critical` | `high` | `medium` | `low` | `negligible`, đồng thời bắt buộc cung cấp `axis_rubric` với **`basis`** (căn cứ định lượng) và **`blast_radius`** thuộc đúng tập `component` | `service` | `domain` | `cross_domain` | `platform`:
1. **`safety` (S — An toàn Sinh mạng & Vật lý)**:
   - Ảnh hưởng tới hành khách trên xe điện, an toàn cháy nổ pin BESS/trạm sạc, chuyển động cánh tay robot công nghiệp/phẫu thuật, dây chuyền luyện kim/tàu tốc độ cao.
   - **Chỉ báo Kỹ thuật Bắt buộc cho Trục Safety (`DEPTH-4.4b`)**: Bắt buộc khai báo `actuator_command_path_without_interlock`: `"yes"` | `"no"` | `"unknown"` và khi `safety != "negligible"` phải sinh câu hỏi bàn giao chuyên môn `hse_handoff_question` cho bộ phận HSE / Functional Safety.
2. **`financial` (F — Tài chính & Thương mại)**:
   - Thất thoát doanh thu sạc điện, gian lận thanh toán/voucher, thao túng công nợ đại lý B2B/SAP, phạt hợp đồng SLA.
3. **`operational` (O — Vận hành & Độ sẵn sàng)**:
   - Ngừng trệ diện rộng đội xe/mạng lưới trạm sạc, tê liệt dây chuyền nhà máy, mất điều khiển từ xa hoặc làm mù hệ thống giám sát SOC/SCADA.
4. **`privacy` (P — Quyền riêng tư & Dữ liệu nhạy cảm)**:
   - Lộ dữ liệu hành trình GPS, camera/mic trong xe/nhà, PII khách hàng VIP, bí mật công nghệ (trọng số mô hình AI VLA, bản vẽ thiết kế).
5. **`compliance` (C — Tuân thủ & Pháp lý)**:
   - Vi phạm Luật BVDLCN 91/2025, Luật ANM 116/2025, UNECE R155/R156, ISO/SAE 21434, IEC 62443, PCI-DSS.

---

## 2. Bốn Luật Cứng Bắt buộc (`ARCH-3H`, `DEPTH-4.4b`, `DEPTH-4.4d`)

1. **Luật Cứng 1 — Không Cộng dồn Đa trục (`overall_risk <= max_impact`)**:
   - `max_impact` phải bằng đúng giá trị cao nhất trong 5 trục `(S, F, O, P, C)`.
   - `contextual_risk_rating` (`overall_risk`) **KHÔNG BAO GIỜ ĐƯỢC VƯỢT QUÁ `max_impact`**.
2. **Luật Cứng 2 — Tách biệt `Safety Owner != Security Risk Owner`**:
   - Khi `impact_axes.safety != "negligible"`, trường `safety_owner` **BẮT BUỘC phải được khai báo** và **phải khác** với `risk_owner`.
3. **Luật Cứng 3 — Gán `owner_role` từ `owners.json` hoặc Roster Cố định (`DEPTH-4.4d`)**:
   - Trường `owner_role` bắt buộc phải lấy từ `owners.json` của dự án hoặc chọn từ danh mục cố định:
     - `dev_team`
     - `infra_cloud_sec`
     - `iam_platform`
     - `ot_safety_engineering`
     - `data_privacy_dpo`
     - `unassigned_pending_roster`
4. **Luật Cứng 4 — Tách bạch `code_verified_severity` và `contextual_risk_rating`**:
   - Luôn giữ nguyên `code_verified_severity` (từ Phase 2) bên cạnh `contextual_risk_rating` (từ Phase 3).

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON (`AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`)

```bash
# 1. Lưu và kiểm định kết quả hiệu chuẩn rủi ro S-F-O-P-C (đối chiếu AI-skills/schemas/v3/sfop_risk_calibrator.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> sfop_risk_calibrator /tmp/sfop_risk_calibrator_<repo_name>.json

# 2. Khóa sổ Phase 3 tất định (kiểm tra đối khớp chain_id xuyên suốt 3.1 -> 3.2 -> 3.3 và công thức rủi ro)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase3 <repo_name>

# 3. Kết xuất báo cáo kiểm toán v3.0 hoàn chỉnh ra ./documents/
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session render_v3_report <repo_name>
```

```json
{
  "calibrated_findings": [
    {
      "chain_id": "CHAIN-OCPP-STOP-01",
      "finding_id": "CHAIN-OCPP-STOP-01",
      "code_verified_severity": "high",
      "exploitability_likelihood": "high",
      "impact_axes": {
        "safety": "low",
        "financial": "medium",
        "operational": "high",
        "privacy": "low",
        "compliance": "medium"
      },
      "axis_rubric": {
        "safety": {
          "basis": "Stopping charging interrupts power delivery cleanly via contactor sequence without bypassing BMS hardware cutoff",
          "blast_radius": "service",
          "actuator_command_path_without_interlock": "no",
          "hse_handoff_question": "Confirm with EVSE electrical safety team whether repeated remote-stop cycling under peak load degrades contactor relay lifetime."
        },
        "financial": {
          "basis": "Prematurely terminated charging sessions reduce station utilization and billing revenue across multiple connectors",
          "blast_radius": "domain"
        },
        "operational": {
          "basis": "Any B2C user can remotely interrupt active charging sessions across the CSMS domain",
          "blast_radius": "domain"
        },
        "privacy": {
          "basis": "Response leaks session status transitions for targeted sessionId",
          "blast_radius": "service"
        },
        "compliance": {
          "basis": "Unauthorized manipulation of EV charging infrastructure telemetry and session state",
          "blast_radius": "domain"
        }
      },
      "max_impact": "high",
      "contextual_risk_rating": "high",
      "owner_role": "dev_team",
      "risk_owner": "V-Green CSMS Platform Engineering Lead",
      "safety_owner": "V-Green Hardware & Electrical Safety Officer (HSE)",
      "rationale": "Any B2C user can remotely stop active charging sessions across stations (low identity cost, Cloudflare WAF does not inspect business ownership inside JSON payload). Max impact is Operational=high; overall_risk=high (<= max_impact)."
    }
  ]
}
```
