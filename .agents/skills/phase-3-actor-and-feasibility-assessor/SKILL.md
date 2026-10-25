---
name: phase-3-actor-and-feasibility-assessor
description: >-
  Phase 3.1 — Chứng minh Actor hoặc Role tối thiểu nào có thể chạm tới code path lỗi, chi phí chiếm đoạt danh tính và các điều kiện vận hành thực tế (actor_and_feasibility_assessor). Kích hoạt ở Bước 3.1 hoặc khi gọi /phase-3-actor-and-feasibility-assessor.
---

# Phase 3.1: Actor, Role Reachability & Operational Feasibility Assessor (`actor_and_feasibility_assessor`)

Bạn đang thực thi **Bước 3.1 (`actor_and_feasibility_assessor`)** trong **Phase 3: Contextual Risk & Exploitability Assessment (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`.

Sau khi Phase 2 (`finalize_v3_phase2`) đã chứng minh các chuỗi tấn công là **Reachable về mặt mã nguồn**, bạn bắt buộc giữ nguyên mã `chain_id` (và `finding_id`) từ Phase 2 (`ARCH-3G`, `ARCH-3H`) và trả lời bằng cấu trúc dữ liệu tất định:
**"Người dùng, thiết bị hay Role cụ thể nào mới có thể chạm vào code path đó, và các điều kiện tiên quyết được đánh giá `yes` / `no` / `unknown` kèm bằng chứng như thế nào?"**

---

## 1. Phân loại Tác nhân Tối thiểu (`minimum_viable_actor`)

Với mỗi `chain_id` sống sót từ Phase 2, bạn phải xác định **Tác nhân có đặc quyền thấp nhất** có thể kích hoạt code path đó:
1. `unauthenticated_external`: Kẻ tấn công ẩn danh trên Internet hoặc khách vãng lai qua BLE/Wi-Fi/QR tại trạm sạc/xe mà không cần tài khoản.
2. `authenticated_consumer_b2c`: Người dùng cuối bất kỳ có thể tự đăng ký tài khoản (Self-registration trên Mobile App VinFast / V-Green / Web Portal).
3. `enterprise_partner_dealer`: Tài khoản đại lý (Dealer), đối tác B2B, nhà cung cấp (Vendor) hoặc trạm sạc nhượng quyền.
4. `internal_employee_operator`: Nhân viên vận hành nội bộ, kỹ thuật viên bảo dưỡng (Service Workshop), nhân viên trực SOC/NOC/SCADA.
5. `compromised_edge_device_tbox_charger_robot`: Thiết bị biên vật lý đã bị can thiệp phần cứng/chiếm credential (T-Box xe, trụ sạc OCPP, Robot, PLC/RTU).
6. `privileged_admin_devops`: Quản trị viên hệ thống (`SUPER_ADMIN`), kỹ sư DevOps có quyền CI/CD hoặc truy cập DB/Cluster trực tiếp.

---

## 2. Đánh giá Tiên quyết Cấu trúc `yes` / `no` / `unknown` (`ARCH-3H`)

1. **`identity_acquisition_cost` (`low` | `medium` | `high`)**:
   - `low`: Tự đăng ký miễn phí hoặc không cần tài khoản.
   - `medium`: Cần phê duyệt tài khoản B2B/Dealer, cần eKYC hoặc cần tiếp cận vật lý trụ sạc/xe.
   - `high`: Cần chiếm quyền tài khoản Admin nội bộ có MFA phần cứng (FIDO2), chứng chỉ mTLS lưu trong HSM/TPM, hoặc VPN nội bộ có kiểm soát thiết bị (EDR).
2. **Đánh giá từng điều kiện tiên quyết (`precondition_checks[]` — `ARCH-3H`)**:
   - Mỗi điều kiện tiên quyết phải được lượng hóa rõ ràng bằng giá trị `satisfied`: `"yes"` | `"no"` | `"unknown"` kèm theo `evidence_ids` hoặc `searched_paths` (ví dụ: khả năng tự đăng ký tài khoản, khả năng đoán/liệt kê `object_id`, yêu cầu mạng nội bộ hay mTLS).
3. **`operational_preconditions` & `blocked_by_environment`**:
   - Nêu rõ các điều kiện vận hành cần thiết và ghi nhận trung thực nếu việc kiểm chứng thực tế đang bị chặn bởi yếu tố môi trường (`blocked_by_environment: true`).

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON (`AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`)

```bash
# Đọc thêm file cấu hình RBAC/IAM/Role mapping nếu cần xác minh quyền của Actor
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <path> 1 120 --skill actor_and_feasibility_assessor

# Lưu kết quả đánh giá Actor & Feasibility (đối chiếu AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> actor_and_feasibility_assessor /tmp/actor_and_feasibility_assessor_<repo_name>.json
```

```json
{
  "assessments": [
    {
      "chain_id": "CHAIN-OCPP-STOP-01",
      "finding_id": "CHAIN-OCPP-STOP-01",
      "minimum_viable_actor": "authenticated_consumer_b2c",
      "identity_acquisition_cost": "low",
      "precondition_checks": [
        {
          "check_id": "PRE-SELF-REG",
          "question": "Can an external user self-register the required B2C role without manual approval?",
          "satisfied": "yes",
          "evidence_ids": ["ev_..."],
          "searched_paths": ["src/controllers/auth.controller.ts"]
        },
        {
          "check_id": "PRE-PREDICTABLE-ID",
          "question": "Is the target sessionId sequential or discoverable by a B2C user?",
          "satisfied": "yes",
          "evidence_ids": ["ev_..."],
          "searched_paths": ["src/entities/charging-session.entity.ts"]
        }
      ],
      "operational_preconditions": [
        "Attacker registers a standard B2C mobile account",
        "Attacker enumerates or observes active transactionId integer sequence"
      ],
      "blocked_by_environment": false,
      "blocker_details": "",
      "evidence_ids": ["ev_..."]
    }
  ]
}
```
