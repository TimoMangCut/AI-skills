---
name: phase-3-actor-and-feasibility-assessor
description: >-
  Phase 3.1 — Chứng minh Actor hoặc Role tối thiểu nào có thể chạm tới code path lỗi, chi phí chiếm đoạt danh tính và các điều kiện vận hành thực tế (actor_and_feasibility_assessor). Kích hoạt ở Bước 3.1 hoặc khi gọi /phase-3-actor-and-feasibility-assessor.
---

# Phase 3.1: Actor, Role Reachability & Operational Feasibility Assessor (`actor_and_feasibility_assessor`)

> **Subagent Isolation Directive**: Start Phase 3 in a fresh session per repository, reading `.localsec/runs/default/<repo_name>/phase3_verified_queue.json` produced by `finalize_v3_phase2`.

Bạn đang thực thi **Bước 3.1 (`actor_and_feasibility_assessor`)** trong **Phase 3: Contextual Risk & Exploitability Assessment (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`.

Sau khi Phase 2 (`finalize_v3_phase2`) đã chứng minh các chuỗi tấn công là **Reachable về mặt mã nguồn** trong `phase3_verified_queue.json`, bạn bắt buộc giữ nguyên mã `chain_id` từ Phase 2 (`ARCH-3G`, `ARCH-3H`) và trả lời bằng cấu trúc dữ liệu tất định trong `actor_assessments`:
**"Tác nhân (`minimum_actor`) tối thiểu nào có thể chạm vào code path đó, chi phí chiếm đoạt danh tính (`identity_acquisition_cost`) là bao nhiêu, và từng điều kiện tiên quyết (`preconditions[]`) được đánh giá `yes` / `no` / `unknown` kèm bằng chứng như thế nào?"**

---

## 1. Phân loại 6 Tác nhân Tối thiểu Chuẩn (`minimum_actor` — `R2-P0-01`)

Với mỗi `chain_id` sống sót từ Phase 2, bắt buộc khai báo trường **`"minimum_actor"`** thuộc đúng tập 6 giá trị enum chuẩn:
1. `external_unauthenticated`: Kẻ tấn công bên ngoài trên Internet hoặc khách vãng lai qua mạng không dây/QR mà không cần tài khoản xác thực.
2. `authenticated_user`: Người dùng cuối bất kỳ đã xác thực (ví dụ người dùng tự đăng ký tài khoản B2C trên Mobile App / Web Portal).
3. `b2b_partner_cross_scope`: Tài khoản đối tác B2B, đại lý (Dealer), nhà cung cấp (Vendor) hoặc đơn vị vận hành trạm sạc nhượng quyền vượt phạm vi tenant/scope.
4. `rogue_insider_or_operator`: Nhân viên vận hành nội bộ, kỹ thuật viên bảo dưỡng (Service Workshop), nhân viên trực SOC/NOC/SCADA hoặc quản trị viên lạm quyền.
5. `compromised_internal_component`: Dịch vụ/container nội bộ hoặc thành phần phần mềm trong VPC/cluster đã bị chiếm quyền.
6. `physical_or_local_bus_attacker`: Kẻ tấn công tiếp cận vật lý thiết bị biên hoặc bus cục bộ (T-Box xe, CAN/UDS bus, cổng bảo trì trụ sạc OCPP, Robot, PLC/RTU/RS-485).

---

## 2. Đánh giá Chi phí Danh tính & Điều kiện Tiên quyết (`preconditions[]` — `ARCH-3H`, `R2-P0-01`)

1. **`identity_acquisition_cost` (`"low" | "medium" | "high" | "none"`)**:
   - `none`: Không cần bất kỳ danh tính hay tài khoản nào (`external_unauthenticated`).
   - `low`: Tự đăng ký tài khoản miễn phí hoặc dễ dàng có được.
   - `medium`: Cần phê duyệt tài khoản B2B/Dealer, cần eKYC hoặc tiếp cận vật lý thiết bị biên.
   - `high`: Cần chiếm quyền tài khoản nội bộ có MFA phần cứng (FIDO2), chứng chỉ mTLS lưu trong HSM/TPM, hoặc VPN nội bộ có kiểm soát thiết bị.
2. **Đánh giá từng điều kiện tiên quyết (`preconditions[]` — `ARCH-3H`)**:
   - Mỗi phần tử trong `preconditions[]` phải khai báo rõ `precondition_id`, `description` (hoặc `precondition`), `precondition_status` (`"yes"` | `"no"` | `"unknown"`), `evidence_ids` và `searched_paths` (không dùng khóa `"status": "yes"` vì khóa `"status"` dành riêng cho epistemic status chuẩn).
   - Mọi điều kiện tiên quyết có `precondition_status: "unknown"` sẽ được `finalize_v3_phase3` tự động chuyển thành câu hỏi hai chiều (`outcome_if_yes` / `outcome_if_no`) trong `key_questions.json`.

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`)

```powershell
# 1. Đọc thêm file cấu hình RBAC/IAM/Role mapping nếu cần xác minh quyền của Actor
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> src/ocpp_controller.py 1 120 --skill actor_and_feasibility_assessor

# 2. Lưu kết quả đánh giá Actor & Feasibility (đối chiếu AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> actor_and_feasibility_assessor /tmp/actor_and_feasibility_assessor_<repo_name>.json
```

```json
{
  "status": "ok",
  "result": {
    "actor_assessments": [
      {
        "chain_id": "CHAIN-OCPP-01",
        "minimum_actor": "authenticated_user",
        "identity_acquisition_cost": "low",
        "preconditions": [
          {
            "precondition_id": "PRE-01",
            "description": "Know target station_id",
            "precondition_status": "yes",
            "evidence_ids": [
              "ev_001"
            ],
            "searched_paths": [
              "src/ocpp_controller.py"
            ]
          }
        ],
        "attack_feasibility": "high",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "summary": "Assessed CHAIN-OCPP-01 as reachable by any authenticated_user with low identity acquisition cost."
  }
}
```
