---
name: phase-3-sfop-risk-calibrator
description: >-
  Phase 3.3 — Hiệu chuẩn mức độ rủi ro thực tế theo mô hình 5 trục S-F-O-P-C (Safety, Financial, Operational, Privacy, Compliance), tuân thủ luật overall_risk khong vuot qua max_impact và tách biệt Safety Owner với Security Risk Owner (sfop_risk_calibrator). Kích hoạt ở Bước 3.3 hoặc khi gọi /phase-3-sfop-risk-calibrator.
---

# Phase 3.3: 5-Axis S-F-O-P-C Contextual Risk Calibrator (`sfop_risk_calibrator`)

> **Subagent Isolation Directive**: Calibrate 5-axis S-F-O-P-C impacts using the quantitative rubric in `contracts/v3-orchestration.json`, then run `finalize_v3_phase3` to deterministically compute `feasibility_derived`, `derived_risk_rating`, and two-way `key_questions.json`.

Bạn đang thực thi **Bước 3.3 (`sfop_risk_calibrator`)** — bước kết tinh cuối cùng của **Phase 3: Contextual Risk & Exploitability Assessment (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`.

Kết hợp kết quả từ Phase 2 (`code_verified_severity`), Bước 3.1 (`actor_assessments`) và Bước 3.2 (`beyond_code_controls`), bạn sẽ hiệu chuẩn **Mức độ Rủi ro Thực tế (`contextual_risk_rating`)** trên mô hình 5 trục **S-F-O-P-C** cho 100% `chain_id` sống sót.

---

## 1. Bảng Rubric Định lượng 5 Trục S-F-O-P-C (`contracts/v3-orchestration.json` — `DEPTH-4.4b`, `R2-P0-01`, `R2-P2-01`)

- **LUÔN LUÔN sử dụng tên trường `"impact_axes"`** (TUYỆT ĐỐI KHÔNG dùng `"sfop_impacts"`!).
- Trên **từng trục** trong `"impact_axes"` (`safety`, `financial`, `operational`, `privacy`, `compliance`), bắt buộc khai báo đối tượng chứa **`"level"`** (`"negligible" | "low" | "medium" | "high" | "critical"`), **`"basis"`** (căn cứ định lượng theo bảng rubric dưới đây) và **`"blast_radius"`** thuộc đúng tập `["component", "service", "domain", "cross_domain", "platform"]`:

| Trục (`impact_axes`) | `negligible` | `low` | `medium` | `high` | `critical` (`catastrophic`) |
|---|---|---|---|---|---|
| **`safety`** (An toàn Vật lý & Sinh mạng) | Không có tác động cơ học, nhiệt, điện hay an toàn sinh mạng (thuần túy kỹ thuật số). | Bất tiện vật lý nhỏ hoặc thay đổi cài đặt tiện nghi không nguy hiểm (HVAC/infotainment), khóa liên động phần cứng nguyên vẹn. | Sự cố vận hành không gây chết người trên 1 thiết bị/xe hoặc gián đoạn sạc khi xe đang đỗ tĩnh (ISO 26262 S1 / IEC 62443 SL-2). | Kích hoạt cơ cấu chấp hành nguy hiểm trên 1 xe/trụ sạc/robot hoặc mất giám sát an toàn nhưng chưa lan truyền đa thiết bị (ISO 26262 S2 / ASIL-B). | Kích hoạt cơ cấu chấp hành diện rộng toàn đội xe, BESS/lưới điện, OT nhà máy có khả năng gây thương tích nặng, thoát nhiệt pin hoặc tử vong (ISO 26262 S3 / ASIL-C/D, Gate 0 Emergency Brake). |
| **`financial`** (Tài chính & Thương mại) | Không thất thoát tiền tệ, gian lận cước hay lệch đối soát (`< \$100`). | Lỗi làm tròn phí/voucher đơn lẻ trên 1 giao dịch (`< \$1,000`, hoàn tác thủ công được). | Gian lận cước sạc/ví/voucher lặp lại trên 1 tài khoản hoặc lệch đối soát B2B (`\$1,000 - \$50,000`). | Rút ruột tự động đa tài khoản ví/hoàn tiền/trợ giá sạc, bypass gói thuê bao OTA trả phí hoặc thao túng thanh toán đối tác (`\$50,000 - \$500,000`). | Rút cạn ngân quỹ/ví không giới hạn, gian lận cước diện rộng toàn đội xe hoặc làm sai lệch sổ cái tài chính ERP/SAP (`> \$500,000`). |
| **`operational`** (Vận hành & Độ sẵn sàng) | Không gây suy giảm dịch vụ hay gián đoạn vận hành đo đếm được. | Suy giảm 1 thành phần phụ trợ hoặc lỗi giao diện ảnh hưởng `< 1%` người dùng. | Gián đoạn 1 dịch vụ hoặc tính năng cấp vùng, nghẽn worker nền có phương án xử lý thủ công. | Gián đoạn đa thuê bao/domain (cổng đại lý, CSMS trạm sạc hoặc pipeline CI/CD) ảnh hưởng hoạt động cốt lõi. | Sập toàn nền tảng, mất quyền điều khiển đội xe/nhà máy/BESS, hoặc mất quyền kiểm soát IAM/K8s/ERP trung tâm. |
| **`privacy`** (Quyền riêng tư & Dữ liệu) | Không lộ PII, thông tin xác thực, telemetry hay dữ liệu mật của khách hàng. | Lộ metadata hồ sơ không nhạy cảm của 1 người dùng hoặc định danh kỹ thuật ẩn danh. | Lộ PII của 1 người dùng (họ tên, SĐT, email, VIN) hoặc lịch sử telemetry giới hạn qua lỗi BOLA. | Lộ hàng loạt hồ sơ PII/eKYC đa người dùng, theo dõi vị trí GPS xe thời gian thực, camera/giọng nói trong cabin hoặc tập dữ liệu huấn luyện AI độc quyền. | Rò rỉ quy mô lớn CCCD/eKYC/hồ sơ tài chính, giám sát toàn đội xe hoặc lộ khóa mật mã/danh tính xuyên tenant. |
| **`compliance`** (Tuân thủ & Pháp lý) | Không vi phạm quy định pháp luật, tiêu chuẩn bắt buộc hay hợp đồng. | Lệch chuẩn chính sách nội bộ nhỏ hoặc thiếu sót định dạng nhật ký kiểm toán mức thấp. | Không tuân thủ 1 kiểm soát đơn lẻ theo OWASP ASVS/MASVS hoặc chuẩn cơ sở nội bộ cần khắc phục. | Vi phạm kiểm soát phải báo cáo theo UNECE R155/R156 (CSMS/SUMS), ISO/SAE 21434, IEC 62443 hoặc PCI-DSS. | Vi phạm nghiêm trọng Luật BVDLCN 91/2025, Luật ANM 116/2025, GDPR, TT 05/2025/TT-BCT hoặc bị thu hồi chứng nhận kiểu loại (type-approval). |

---

## 2. Năm Luật Cứng Bắt buộc (`ARCH-3H`, `DEPTH-4.4b`, `DEPTH-4.4d`, `R2-P0-03`, `R3-A5`)

1. **Luật Cứng 1 — Không Cộng dồn Đa trục (`overall_risk <= max_impact`)**:
   - `max_impact` phải bằng đúng mức cao nhất trong 5 trục `(safety, financial, operational, privacy, compliance)`.
   - `contextual_risk_rating` (`overall_risk`) **KHÔNG BAO GIỜ ĐƯỢC VƯỢT QUÁ `max_impact`**.
2. **Luật Cứng 2 — Tách biệt `Safety Owner != Security Risk Owner`**:
   - Khi mức độ của trục `safety` khác `"negligible"`, trường `safety_owner` **BẮT BUỘC phải khác rỗng** và **phải khác** với `risk_owner`.
   - Khai báo thêm chỉ báo kỹ thuật `actuator_command_path_without_interlock`: `"yes" | "no" | "unknown"`.
3. **Luật Cứng 3 — Bắt buộc Gán `owner_role` Chuẩn & Không Bịa Chức danh Cá nhân (`DEPTH-4.4d`, `R2-P0-03`, `R3-A5`)**:
   - Trường `"owner_role"` **BẮT BUỘC có mặt trên mọi finding** trong `calibrated_findings[]` và chọn từ đúng 6 giá trị chuẩn:
     `["dev_team", "infra_cloud_sec", "iam_platform", "ot_safety_engineering", "data_privacy_dpo", "unassigned_pending_roster"]`.
   - Khi dự án chưa cung cấp file `owners.json`, **TUYỆT ĐỐI KHÔNG tự bịa chức danh cá nhân chưa kiểm chứng** trong `risk_owner` / `safety_owner`; hãy dùng định danh theo vai trò như `"dev_team (pending project roster)"` và `"ot_safety_engineering (pending project roster)"`.
4. **Luật Cứng 4 — Công thức Rủi ro Tất định Hai Chiều (Ceiling & Floor) trong `finalize_v3_phase3` (`R2-P0-03`, `R3-A5`)**:
   - Khi chạy `python -m localsec.manual_session finalize_v3_phase3 <repo_name>`, engine sẽ tính toán tất định `feasibility_derived` và `derived_risk_rating` từ kết quả Bước 3.1 (`actor_assessments`) + Bước 3.2 (`beyond_code_controls`) + `max_impact`, và **mặc định gán `contextual_risk_rating = derived_risk_rating`** (áp dụng cả trần lẫn sàn, chống tự ý hạ thấp rủi ro — `R3-A5`).
   - Nếu muốn đề xuất điều chỉnh `contextual_risk_rating` lệch tối đa **1 bậc** so với `derived_risk_rating` (và vẫn `<= max_impact`), finding **BẮT BUỘC** phải cung cấp `"risk_override_rationale"` (tối thiểu **80 ký tự**) và mảng `"risk_override_evidence_ids"` khác rỗng (`["ev_..."]`).
   - Đồng thời, `finalize_v3_phase3` tự động sinh các câu hỏi hai chiều có đầy đủ **`outcome_if_yes`** và **`outcome_if_no`** trong `.localsec/runs/default/<repo_name>/key_questions.json` cho mọi kiểm soát hoặc điều kiện tiên quyết đang ở trạng thái giả thuyết/chưa xác nhận.

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`)

```powershell
# 1. Lưu và kiểm định kết quả hiệu chuẩn rủi ro S-F-O-P-C (đối chiếu AI-skills/schemas/v3/sfop_risk_calibrator.schema.json)
python -m localsec.manual_session submit_skill <repo_name> sfop_risk_calibrator .localsec/tmp/sfop_risk_calibrator_<repo_name>.json

# 2. Khóa sổ Phase 3 tất định (tính feasibility_derived, derived_risk_rating, xuất key_questions.json hai chiều và phase3_gate_receipt.json)
python -m localsec.manual_session finalize_v3_phase3 <repo_name>

# 3. Kết xuất 3 báo cáo kiểm toán v3.0 hoàn chỉnh ra ./documents/
python -m localsec.manual_session render_v3_report <repo_name>
```

```json
{
  "status": "ok",
  "result": {
    "calibrated_findings": [
      {
        "chain_id": "CHAIN-OCPP-01",
        "finding_id": "CHAIN-OCPP-01",
        "code_verified_severity": "high",
        "exploitability_likelihood": "high",
        "impact_axes": {
          "safety": {
            "level": "high",
            "severity": "high",
            "basis": "Single charger hazardous energization via unverified RemoteStartTransaction command (ISO 26262 S2 / ASIL-B).",
            "blast_radius": "service",
            "actuator_command_path_without_interlock": "yes"
          },
          "financial": {
            "level": "medium",
            "severity": "medium",
            "basis": "Repeatable single-account charging billing manipulation ($1,000 - $50,000).",
            "blast_radius": "service"
          },
          "operational": {
            "level": "high",
            "severity": "high",
            "basis": "Multi-tenant charging CSMS session disruption affecting core station operations.",
            "blast_radius": "domain"
          },
          "privacy": {
            "level": "low",
            "severity": "low",
            "basis": "Single-user session identifier and connector status metadata exposure.",
            "blast_radius": "component"
          },
          "compliance": {
            "level": "medium",
            "severity": "medium",
            "basis": "Single-control non-conformance under OWASP ASVS object-level access control baseline.",
            "blast_radius": "service"
          }
        },
        "max_impact": "high",
        "contextual_risk_rating": "high",
        "blast_radius": "domain",
        "actuator_command_path_without_interlock": "yes",
        "owner_role": "dev_team",
        "risk_owner": "dev_team (pending project roster)",
        "safety_owner": "ot_safety_engineering (pending project roster)",
        "gate_0_emergency_brake": false,
        "evidence_ids": [
          "ev_001"
        ],
        "rationale": "Any authenticated_user (low identity acquisition cost) can trigger RemoteStartTransaction across sessions; Cloudflare WAF does not block BOLA and EVSE hardware interlock is unverified in software repo. Max impact is high (Safety=high, Operational=high); contextual_risk_rating=high (<= max_impact)."
      }
    ],
    "summary": "Calibrated 5-axis S-F-O-P-C risk for CHAIN-OCPP-01 with max_impact=high and contextual_risk_rating=high."
  }
}
```
