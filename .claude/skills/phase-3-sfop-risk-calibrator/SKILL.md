---
name: phase-3-sfop-risk-calibrator
description: >-
  Phase 3.3 — Hiệu chuẩn mức độ rủi ro thực tế theo mô hình 5 trục S-F-O-P-C (Safety, Financial, Operational, Privacy, Compliance), tuân thủ luật overall_risk khong vuot qua max_impact và tách biệt Safety Owner với Security Risk Owner (sfop_risk_calibrator). Kích hoạt ở Bước 3.3 hoặc khi gọi /phase-3-sfop-risk-calibrator.
---

# Phase 3.3: 5-Axis S-F-O-P-C Contextual Risk Calibrator (`sfop_risk_calibrator`)

Bạn đang thực thi **Bước 3.3 (`sfop_risk_calibrator`)** — bước kết tinh cuối cùng của **Phase 3: Contextual Risk & Exploitability Assessment (LocalSec v3.0)**.
Kết hợp kết quả từ Phase 2 (độ nghiêm trọng thuần mã nguồn `code_verified_severity`), Bước 3.1 (`minimum_viable_actor` & `identity_acquisition_cost`) và Bước 3.2 (`exposure_tier` & `compensating_controls`), bạn sẽ hiệu chuẩn **Mức độ Rủi ro Thực tế (`contextual_risk_rating`)** trên mô hình 5 trục **S-F-O-P-C**.

---

## 1. Mô hình 5 Trục Tác động S-F-O-P-C

Đánh giá độc lập từng trục theo thang `critical` | `high` | `medium` | `low` | `negligible`:
1. **`safety` (S — An toàn Sinh mạng & Vật lý)**:
   - Ảnh hưởng tới hành khách trên xe điện, an toàn cháy nổ pin BESS/trạm sạc, chuyển động cánh tay robot công nghiệp/phẫu thuật, dây chuyền luyện kim/tàu tốc độ cao.
2. **`financial` (F — Tài chính & Thương mại)**:
   - Thất thoát doanh thu sạc điện, gian lận thanh toán/voucher, thao túng công nợ đại lý B2B/SAP, phạt hợp đồng SLA.
3. **`operational` (O — Vận hành & Độ sẵn sàng)**:
   - Ngừng trệ diện rộng đội xe/mạng lưới trạm sạc, tê liệt dây chuyền nhà máy, mất điều khiển từ xa hoặc làm mù hệ thống giám sát SOC/SCADA.
4. **`privacy` (P — Quyền riêng tư & Dữ liệu nhạy cảm)**:
   - Lộ dữ liệu hành trình GPS, camera/mic trong xe/nhà, PII khách hàng VIP, bí mật công nghệ (trọng số mô hình AI VLA, bản vẽ thiết kế).
5. **`compliance` (C — Tuân thủ & Pháp lý)**:
   - Vi phạm Nghị định 13/2023/NĐ-CP (PDPD), UNECE R155/R156 (Cybersecurity & OTA ô tô), ISO 26262, IEC 62443, PCI-DSS.

---

## 2. Ba Luật Cứng Bắt buộc (Enforced by `localsec/validators.py`)

1. **Luật Cứng 1 — Không Cộng dồn Đa trục (`overall_risk <= max_impact`)**:
   - `max_impact` phải bằng đúng giá trị cao nhất trong 5 trục `(S, F, O, P, C)`.
   - `contextual_risk_rating` (`overall_risk`) **KHÔNG BAO GIỜ ĐƯỢC VƯỢT QUÁ `max_impact`**. Ví dụ: 3 trục `medium` kết hợp với khả năng khai thác `high` thì `contextual_risk_rating` tối đa vẫn là `medium` (tuyệt đối không tự nâng lên `high` hay `critical`).
2. **Luật Cứng 2 — Tách biệt `Safety Owner != Security Risk Owner`**:
   - Khi `impact_axes.safety != "negligible"`, trường `safety_owner` **BẮT BUỘC phải được khai báo** (ví dụ: `Functional Safety / HSE / Chief Engineer`) và **phải khác** với `risk_owner` (Chủ sở hữu rủi ro bảo mật/CNTT). Không một cá nhân CNTT nào được tự ký chấp nhận rủi ro an toàn vật lý.
3. **Luật Cứng 3 — Tách bạch `code_verified_severity` và `contextual_risk_rating`**:
   - Luôn giữ nguyên `code_verified_severity` (từ Phase 2) bên cạnh `contextual_risk_rating` (sau khi tính đến Actor, WAF, VPC, OT Interlock ở Phase 3) để đội ngũ kỹ thuật và lãnh đạo thấy rõ lý do nâng hoặc hạ mức độ ưu tiên xử lý.

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON

```bash
# Lưu và kiểm định kết quả hiệu chuẩn rủi ro S-F-O-P-C
python -m localsec.manual_session submit_skill _analysis sfop_risk_calibrator .localsec/tmp/sfop_risk_calibrator.json
```

```json
{
  "calibrated_findings": [
    {
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
      "max_impact": "high",
      "contextual_risk_rating": "high",
      "risk_owner": "V-Green CSMS Platform Engineering Lead",
      "safety_owner": "V-Green Hardware & Electrical Safety Officer (HSE)",
      "rationale": "Any B2C user can remotely stop active charging sessions across stations (low identity cost, Cloudflare WAF does not inspect business ownership inside JSON payload). Max impact is Operational=high; overall_risk=high (<= max_impact)."
    }
  ]
}
```
