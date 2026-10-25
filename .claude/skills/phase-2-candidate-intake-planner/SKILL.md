---
name: phase-2-candidate-intake-planner
description: >-
  Phase 2.1 — Tiếp nhận Candidate Queue từ Phase 1 Recon, chuẩn hóa giả thuyết chuỗi tấn công và chọn các khối Attack-Class Companion nguyên văn (candidate_intake_planner). Kích hoạt ở Bước 2.1 hoặc khi gọi /phase-2-candidate-intake-planner.
---

# Phase 2.1: Candidate Intake & Attack Companion Planner (`candidate_intake_planner`)

Bạn đang thực thi **Bước 2.1 (`candidate_intake_planner`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/candidate_intake_planner.schema.json`.

Thay vì quét lại toàn bộ mã nguồn từ đầu, Phase 2 **đọc trực tiếp `.localsec/runs/default/<repo_name>/candidate_queue.json` do `finalize_v3_phase1` sinh ra (`ARCH-3G`)** và nạp các mô-đun `Attack-Class Companion` tương ứng.

---

## 1. Quy tắc Thực thi Bắt buộc (`ARCH-3G`, `DEPTH-4.5`)

1. **Đọc `candidate_queue.json` & Không Bỏ rơi Ứng viên (`ARCH-3G`)**:
   - Đọc danh sách ứng viên từ `.localsec/runs/default/<repo_name>/candidate_queue.json`.
   - Bảo toàn 100% mã `candidate_id` từ Phase 1: xếp hạng ưu tiên `P0` (Safety/Financial/BOLA/RCE), `P1` (Privilege Escalation/SSRF/Deserialization), `P2` (Defense-in-Depth).
   - Sử dụng `python -m localsec.manual_session show_evidence <repo_name> <ev_id>` để xem lại các trích đoạn bằng chứng Phase 1 mà không cần mở đọc lại toàn bộ file (`DEPTH-4.5`).
2. **Tiêm Nguyên văn Khối `Attack-Class Companion` (`selected_attack_companions.json` — `DEPTH-4.5`)**:
   - Chạy `python -m localsec.manual_session select_attack_companions <repo_name> --archetypes ...` để nạp nguyên văn các khối kiểm tra chuyên sâu từ `AI-skills/contracts/attack-taxonomy-v1/manifest.json` (16 mô-đun) và tự động lưu vào `.localsec/runs/default/<repo_name>/selected_attack_companions.json`.
   - **CẤM tóm tắt hoặc viết lại nội dung bên trong khối `## [ BLOCK: ... ]`**. Nếu loại trừ bất kỳ khối nào, phải ghi rõ lý do trong `excluded_blocks`.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Xem lại trích đoạn bằng chứng từ Phase 1 mà không cần đọc lại file
python -m localsec.manual_session show_evidence <repo_name> <ev_id>

# 2. Chọn các khối Attack-Class Companion nguyên văn và xuất ra .localsec/runs/default/<repo_name>/selected_attack_companions.json
python -m localsec.manual_session select_attack_companions <repo_name> --archetypes ev_charging_ocpp_ocpi_bess api_rest_graphql_grpc_websocket

# 3. Lưu danh sách Candidate Queue đã chuẩn hóa (đối chiếu AI-skills/schemas/v3/candidate_intake_planner.schema.json)
python -m localsec.manual_session submit_skill <repo_name> candidate_intake_planner .localsec/tmp/candidate_intake_planner_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/candidate_intake_planner.schema.json`)

```json
{
  "intake_candidates": [
    {
      "candidate_id": "CAND-OCPP-BOLA-01",
      "priority": "P0",
      "affected_axis": "O",
      "hypothesis": "Authenticated B2C user can call POST /api/v1/sessions/{sessionId}/remote-stop with another user's sessionId to terminate active charging",
      "selected_companion_modules": [
        "authz-bola-bfla-multitenant",
        "ev-charging-ocpp-ocpi-battery"
      ],
      "evidence_ids": ["ev_..."]
    }
  ],
  "excluded_blocks": []
}
```
