---
name: phase-2-candidate-intake-planner
description: >-
  Phase 2.1 — Tiếp nhận Candidate Queue từ Phase 1 Recon, chuẩn hóa giả thuyết chuỗi tấn công và chọn các khối Attack-Class Companion nguyên văn (candidate_intake_planner). Kích hoạt ở Bước 2.1 hoặc khi gọi /phase-2-candidate-intake-planner.
---

# Phase 2.1: Candidate Intake & Attack Companion Planner (`candidate_intake_planner`)

> **Subagent Isolation Directive**: Start Phase 2 in a fresh session per repository, reading `.localsec/runs/default/<repo_name>/candidate_queue.json` produced by `finalize_v3_phase1`.

Bạn đang thực thi **Bước 2.1 (`candidate_intake_planner`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/candidate_intake_planner.schema.json`.

Thay vì quét lại toàn bộ mã nguồn từ đầu, Phase 2 **đọc trực tiếp `.localsec/runs/default/<repo_name>/candidate_queue.json` do `finalize_v3_phase1` sinh ra (`ARCH-3G`)**, gom nhóm vào `deduplicated_batches[]` và nạp các mô-đun `Attack-Class Companion` tương ứng.

---

## 1. Quy tắc Thực thi Bắt buộc (`ARCH-3G`, `DEPTH-4.5`, `R3-A4`)

1. **Đọc `candidate_queue.json` & Không Bỏ rơi Ứng viên (`ARCH-3G`, `R3-A4`)**:
   - Đọc danh sách ứng viên từ `.localsec/runs/default/<repo_name>/candidate_queue.json`.
   - Bảo toàn 100% mã `candidate_id` từ Phase 1 (định dạng `cand_<12-hex>`) vào các lô `deduplicated_batches[]` để phân tích ở Bước 2.2.
   - **Luật Fail-Closed khi loại bỏ ứng viên (`dismissed_candidates[]` — `R3-A4`)**: Nếu loại bỏ bất kỳ ứng viên nào trong `dismissed_candidates[]`, mỗi phần tử **BẮT BUỘC** phải là một object `{"candidate_id": "...", "reason": "...", "evidence_ids": ["ev_..."]}` có `reason` giải trình cụ thể ($\ge 10$ ký tự) và `evidence_ids` khác rỗng (nghiêm cấm truyền chuỗi trần `candidate_id` hoặc thiếu bằng chứng).
   - Sử dụng `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session show_evidence <repo_name> <ev_id>` để xem lại các trích đoạn bằng chứng Phase 1 mà không cần mở đọc lại toàn bộ file (`DEPTH-4.5`).
2. **Tiêm Nguyên văn Khối `Attack-Class Companion` (`selected_attack_companions.json` — `DEPTH-4.5`)**:
   - Chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session select_attack_companions <repo_name> --archetypes ...` để nạp nguyên văn các khối kiểm tra chuyên sâu từ `AI-skills/contracts/attack-taxonomy-v1/manifest.json` (16 mô-đun) và tự động lưu vào `.localsec/runs/default/<repo_name>/selected_attack_companions.json`.
   - **CẤM tóm tắt hoặc viết lại nội dung bên trong khối `## [ BLOCK: ... ]`**. Khai báo danh sách mô-đun đã chọn trong trường `selected_companions`.

---

## 2. Giao thức Thực thi CLI

```powershell
# 1. Xem lại trích đoạn bằng chứng từ Phase 1 mà không cần đọc lại file
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session show_evidence <repo_name> <ev_id>

# 2. Chọn các khối Attack-Class Companion nguyên văn và xuất ra .localsec/runs/default/<repo_name>/selected_attack_companions.json
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session select_attack_companions <repo_name> --archetypes ev_charging_ocpp_ocpi_bess api_rest_graphql_grpc_websocket

# 3. Lưu danh sách Candidate Queue đã chuẩn hóa (đối chiếu AI-skills/schemas/v3/candidate_intake_planner.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> candidate_intake_planner .localsec/tmp/candidate_intake_planner_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/candidate_intake_planner.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "selected_companions": [
      "ev-charging-ocpp-ocpi-battery",
      "authz-bola-bfla-multitenant"
    ],
    "deduplicated_batches": [
      {
        "batch_id": "BATCH-01",
        "candidate_ids": [
          "cand_111122223333",
          "cand_8cd467be41f0",
          "cand_d432d621c21e",
          "cand_74ef70e3b401",
          "cand_563ca97c8fcc",
          "cand_39f27929e8c3",
          "cand_8629bd86b767",
          "cand_2cbb767b759c",
          "cand_214cf9681c33",
          "cand_5a9af194a4df",
          "cand_0140b9ecdd23"
        ],
        "attack_classes": [
          "BOLA_IDOR"
        ],
        "target_repos": [
          "csms-service"
        ],
        "priority_severity": "high",
        "rationale": "Group OCPP remote-start BOLA and safety invariant candidates sharing src/ocpp_controller.py"
      }
    ],
    "dismissed_candidates": [],
    "summary": "Grouped all 11 Phase 1 candidates into BATCH-01 with 2 verbatim Attack-Class Companions."
  }
}
```
