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

## 2. Đánh giá Chi phí Danh tính & Điều kiện Tiên quyết (`preconditions[]` — `ARCH-3H`, `R2-P0-01`, `R3-A1`, `R3-A5`)

1. **`identity_acquisition_cost` (`"low" | "medium" | "high" | "none"`)**:
   - `none`: Không cần bất kỳ danh tính hay tài khoản nào (`external_unauthenticated`).
   - `low`: Tự đăng ký tài khoản miễn phí hoặc dễ dàng có được.
   - `medium`: Cần phê duyệt tài khoản B2B/Dealer, cần eKYC hoặc tiếp cận vật lý thiết bị biên.
   - `high`: Cần chiếm quyền tài khoản nội bộ có MFA phần cứng (FIDO2), chứng chỉ mTLS lưu trong HSM/TPM, hoặc VPN nội bộ có kiểm soát thiết bị.
2. **Đánh giá từng điều kiện tiên quyết (`preconditions[]` — `ARCH-3H`, `R3-A1`, `R3-A5`)**:
   - Mỗi phần tử trong `preconditions[]` phải khai báo rõ `precondition_id`, `description` (hoặc `condition` / `precondition`), **`status`** (`"yes"` | `"no"` | `"unknown"` — engine cũng chấp nhận alias `"precondition_status"`), `searched_paths` và `evidence_ids`.
   - **Luật Fail-Closed khi bác bỏ tính khả thi (`R3-A5`)**: Nếu đánh dấu một điều kiện tiên quyết là **`"status": "no"`** (không thỏa mãn $\rightarrow$ làm chuỗi tấn công trở nên `infeasible`), bắt buộc phải cung cấp **cả `"evidence_ids"` khác rỗng (`["ev_..."]`) lẫn `"searched_paths"` khác rỗng** chứng minh điều kiện đó không thể xảy ra trong thực tế. Nếu thiếu bằng chứng, validator sẽ từ chối ngay lập tức.
   - Mọi điều kiện tiên quyết có `"status": "unknown"` sẽ được `finalize_v3_phase3` tự động chuyển thành câu hỏi hai chiều (`outcome_if_yes` / `outcome_if_no`) trong `key_questions.json` và gán `feasibility_derived = "provisional_unknown"`.
3. **Người nắm giữ và từng loại người tấn công (`holders`, `actors_considered` — D6)**:
   - Với mỗi điều kiện, ghi `holders[]`. **Định nghĩa (Đợt 9 — V19):** người nắm giữ là **chỗ mà kẻ tấn công thuộc `actor_type` lấy được điều kiện đó**: một người, một workload, một hệ thống đang có sẵn điều kiện. `attainable` trả lời câu hỏi "**kẻ tấn công loại `actor_type` có lấy được điều kiện này qua người nắm giữ này không**" (`yes` | `no` | `unknown`). Câu hỏi không phải là "người nắm giữ có điều kiện đó hợp pháp không".
     - Mỗi người nắm giữ ghi `who`, `actor_type` (một giá trị của `minimum_actor`), `attainable`, `why` và `evidence_ids`. Bằng chứng là code hoặc cấu hình cho thấy người nắm giữ thật sự có điều kiện đó.
     - **Workload hợp pháp có điều kiện là người nắm giữ của `compromised_internal_component`.** Ví dụ: chat-be được cấp `AGENT_PLATFORM_KEY` (có bằng chứng trong cấu hình). Kẻ tấn công chiếm được chat-be thì có khoá, nên ghi `{"who": "chat-be workload", "actor_type": "compromised_internal_component", "attainable": "yes"}`. Không ghi `unknown` chỉ vì chat-be là chủ hợp pháp.
     - Với `external_unauthenticated`, cùng điều kiện đó thường là `no`: người ngoài không lấy được khoá, trừ khi có đường lộ.
     - Script chỉ coi một điều kiện là đạt khi có người nắm giữ `attainable: yes`, kèm bằng chứng thật, và `actor_type` trùng `minimum_actor` của chuỗi (hoặc không ghi `actor_type`); riêng điều kiện công khai đã ghi trực tiếp `"status": "yes"` kèm bằng chứng thì không bắt buộc lặp lại `holders`.
   - **Chuỗi giả thuyết giữ nguyên trạng thái tạm thời (`provisional_unknown`):** Mọi chuỗi đi sang Phase 3 từ `hypothesis_only_findings` (hoặc có `chain_verdict` là `"hypothesized"` / `"partially_confirmed"`) sẽ luôn được `finalize_v3_phase3` giữ ở `feasibility_derived = "provisional_unknown"` (rủi ro tạm tính) cho tới khi có xác nhận runtime, bất kể `preconditions[].status`.
   - Ghi `actors_considered`: với **từng** loại người tấn công đã xét, hoặc danh sách `precondition_id` của đường áp dụng cho loại đó, hoặc lý do (≥ 20 ký tự) vì sao loại đó không áp dụng. Phase 4 chép nguyên hai trường này sang Phase Risk; thiếu thì Phase Risk phải tự lập luận lại.

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`)

```powershell
# 1. Đọc thêm file cấu hình RBAC/IAM/Role mapping nếu cần xác minh quyền của Actor
python -m localsec.manual_session read_file <repo_name> src/ocpp_controller.py 1 120 --skill actor_and_feasibility_assessor

# 2. Lưu kết quả đánh giá Actor & Feasibility (đối chiếu AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json)
python -m localsec.manual_session submit_skill <repo_name> actor_and_feasibility_assessor .localsec/tmp/actor_and_feasibility_assessor_<repo_name>.json
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
            "description": "Attacker knows target station_id and active transaction_id",
            "status": "yes",
            "searched_paths": [
              "src/ocpp/session_handler.py"
            ],
            "evidence_ids": [
              "ev_001"
            ],
            "holders": [
              {
                "who": "Any registered EV driver",
                "actor_type": "authenticated_user",
                "attainable": "yes",
                "why": "station_id is printed on the charger and transaction_id is echoed in the driver's own session API",
                "evidence_ids": [
                  "ev_001"
                ]
              }
            ]
          },
          {
            "precondition_id": "PRE-02",
            "description": "CSMS WebSocket ingress allows unpinned station_id frame routing",
            "status": "unknown",
            "searched_paths": [
              "src/ocpp/charging_router.py"
            ],
            "evidence_ids": []
          }
        ],
        "actors_considered": {
          "external_unauthenticated": "WebSocket upgrade requires a driver JWT, so an unauthenticated caller never reaches the handler",
          "authenticated_user": [
            "PRE-01",
            "PRE-02"
          ],
          "compromised_edge_device_tbox_charger_robot": [
            "PRE-02"
          ]
        },
        "attack_feasibility": "high",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "summary": "Assessed CHAIN-OCPP-01 as reachable by any authenticated_user with low identity acquisition cost; PRE-02 requires runtime ingress verification."
  }
}
```
