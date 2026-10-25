---
name: phase-1-intent-invariant-modeler
description: >-
  Phase 1.3 — Xây dựng mô hình Ý định Nghiệp vụ và Bất biến An toàn Vật lý (S-F-O-P-C) từ tài liệu thiết kế/spec/manifest và tự rà soát phản biện bất biến để tìm bất biến bị bỏ sót (intent_invariant_modeler). Kích hoạt ở Bước 1.3 hoặc khi gọi /phase-1-intent-invariant-modeler.
---

# Phase 1.3: Business & Cyber-Physical Safety Intent Modeler (`intent_invariant_modeler`)

Bạn đang thực thi **Bước 1.3 (`intent_invariant_modeler`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/intent_invariant_modeler.schema.json`.

Theo kiến trúc **Intent Before Code (`ARCH-3K`)**, Bước 1.3 bắt buộc chạy **ngay sau Bước 1.1 (`codebase_scout`) và TRƯỚC khi đọc mã nguồn thực thi ở Bước 1.2 / 1.4**, nhằm trích xuất **Ý định Nghiệp vụ & Bất biến An toàn Vật lý (S-F-O-P-C)** mà không bị thiên kiến bởi cách code hiện tại.

---

## 1. Quy tắc Kỷ luật Bắt buộc (`ARCH-3K`, `ARCH-3E`)

1. **Thực thi Trước Khi Đọc Code Thực thi (`ARCH-3K` — Hard Extension Gate)**:
   - Chỉ đọc các nguồn đặc tả ý định (`intent_sources_only`): tài liệu thiết kế, `README.md`, `SECURITY.md`, BRD/SRS, OpenAPI/Swagger, `.proto`, GraphQL schema, SQL migrations/schemas, Helm/Terraform/Compose manifests, hoặc tài liệu an toàn vận hành (ISO 26262, IEC 62443, OCPP spec).
   - **Cổng chặn cứng của Engine**: Khi gọi `read_file` với `--skill intent_invariant_modeler`, runtime sẽ **tự động chặn** việc đọc các file mã nguồn thực thi (`.go`, `.py`, `.ts`, `.js`, `.cs`, `.java`, `.cpp`, `.c`, `.rs`, `.kt`, `.swift`, `.dart`).
   - **CẤM suy diễn ngược từ code thực thi rồi đóng dấu là `authoritative_in_input`**. Nếu repo không có tài liệu đặc tả cho một trục, phải ghi rõ `intent_basis: "domain_standard_or_hypothesis"` và `authority_assessment: "inferred_or_unconfirmed"`.
2. **Bao phủ đủ 5 Trục Bất biến S-F-O-P-C**:
   - **S (`Safety / Cyber-Physical`)**: Tốc độ/quỹ đạo robot (`vla.cpp`), giới hạn nhiệt/điện áp pin BESS (BMS/PCS), lệnh mở khóa xe/phanh/OTA ECU, công suất trạm sạc OCPP.
   - **F (`Financial / Billing`)**: Tính cước phiên sạc (kWh/phút), ví trả trước, voucher/khuyến mãi, đơn hàng B2B/SAP, chống cộng/trừ tiền hai lần (idempotency/atomic lock).
   - **O (`Operational / Availability`)**: Chống kẹt hàng đợi Kafka/EMQX/ZeroMQ, cô lập lỗi giữa các trạm/cell, chống DoS làm mù telemetry.
   - **P (`Privacy / Data`)**: Dữ liệu vị trí GPS hành trình xe, video/audio cabin & robot, dữ liệu y tế/PII khách hàng, cách ly dữ liệu đa thuê bao (multi-tenant).
   - **C (`Compliance / Audit`)**: Nhật ký kiểm toán bất biến cho lệnh điều khiển từ xa, chữ ký số gói cập nhật OTA/model weights.
3. **Tự rà soát phản biện bất biến (`Self-Review Invariant Gaps` — `ARCH-3E`)**:
   - Thay vì gọi là phản biện mù trong cùng một phiên, hãy thực hiện **tự rà soát phản biện bất biến (Self-Review Invariant Gaps)**: chủ động đặt câu hỏi đối kháng cho từng trục S-F-O-P-C: *"Bất biến nào tài liệu thiết kế quên ghi rõ nhưng nếu vi phạm sẽ gây mất an toàn vật lý, thất thoát tài chính hoặc chiếm quyền điều khiển chéo?"* và ghi vào `self_review_gaps`.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Đọc tài liệu đặc tả / OpenAPI / Proto / SQL Schema / Manifest (Engine chặn đọc file .go/.py/.ts/.cs/.java/.cpp ở bước này)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> README.md 1 180 --skill intent_invariant_modeler

# 2. Lưu mô hình ý định & bất biến S-F-O-P-C (đối chiếu AI-skills/schemas/v3/intent_invariant_modeler.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> intent_invariant_modeler /tmp/intent_invariant_modeler_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/intent_invariant_modeler.schema.json`)

```json
{
  "invariants": [
    {
      "id": "INV-OCPP-STOP-01",
      "axis": "O",
      "statement": "A RemoteStopTransaction command may only be triggered by the B2C user who owns the active charging session or an authorized station operator.",
      "intent_basis": "documented_spec",
      "authority_assessment": "authoritative_in_input",
      "evidence_ids": ["ev_..."]
    },
    {
      "id": "INV-BESS-THERMAL-01",
      "axis": "S",
      "statement": "Charge power setpoint commands must never bypass BMS thermal/voltage hardware interlock thresholds.",
      "intent_basis": "domain_standard_or_hypothesis",
      "authority_assessment": "inferred_or_unconfirmed",
      "evidence_ids": []
    }
  ],
  "self_review_gaps": [
    {
      "gap_id": "GAP-IDEMPOTENCY-01",
      "axis": "F",
      "question": "Does the specification define idempotency locking when stop-session and billing settlement events arrive concurrently via WebSocket and REST?",
      "recommended_code_check": "Verify transaction lock and status transition guard in session settlement service during Step 1.4."
    }
  ]
}
```
