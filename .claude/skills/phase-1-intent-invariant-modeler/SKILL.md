---
name: phase-1-intent-invariant-modeler
description: >-
  Phase 1.3 — Xây dựng mô hình Ý định Nghiệp vụ và Bất biến An toàn Vật lý (S-F-O-P-C) từ tài liệu thiết kế/spec/manifest và phản biện mù ngữ cảnh để tìm bất biến bị bỏ sót (intent_invariant_modeler). Kích hoạt ở Bước 1.3 hoặc khi gọi /phase-1-intent-invariant-modeler.
---

# Phase 1.3: Business & Cyber-Physical Safety Intent Modeler (`intent_invariant_modeler`)

Bạn đang thực thi **Bước 1.3 (`intent_invariant_modeler`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Thay vì tách rời Recon kỹ thuật và Recon nghiệp vụ thành 2 phase đọc lại từ đầu gây tốn gấp đôi usage, Bước 1.3 trích xuất **Ý định Nghiệp vụ & Bất biến An toàn Vật lý (S-F-O-P-C)** ngay trước khi đọc sâu mã nguồn thực thi ở Bước 1.4.

---

## 1. Quy tắc Kỷ luật Bắt buộc (Anti-Implementation-Inference)

1. **Chỉ đọc nguồn Ý định (`intent_sources_only`)**:
   - Tài liệu thiết kế, `README.md`, `SECURITY.md`, BRD/SRS, OpenAPI/Swagger, `.proto`, GraphQL schema, SQL migrations, Helm/Terraform/Compose manifests, hoặc tài liệu an toàn vận hành (ISO 26262, IEC 62443, OCPP spec).
   - **CẤM suy diễn ngược từ code thực thi rồi đóng dấu là `authoritative_in_input`**. Nếu repo không có tài liệu đặc tả, phải ghi rõ `intent_basis: "domain_standard_or_hypothesis"` và `authority_assessment: "inferred_or_unconfirmed"`.
2. **Bao phủ đủ 5 Trục Bất biến S-F-O-P-C**:
   - **S (`Safety / Cyber-Physical`)**: Tốc độ/quỹ đạo robot (`vla.cpp`), giới hạn nhiệt/điện áp pin BESS (BMS/PCS), lệnh mở khóa xe/phanh/OTA ECU, công suất trạm sạc OCPP.
   - **F (`Financial / Billing`)**: Tính cước phiên sạc (kWh/phút), ví trả trước, voucher/khuyến mãi, đơn hàng B2B/SAP, chống cộng/trừ tiền hai lần (idempotency/atomic lock).
   - **O (`Operational / Availability`)**: Chống kẹt hàng đợi Kafka/EMQX/ZeroMQ, cô lập lỗi giữa các trạm/cell, chống DoS làm mù telemetry.
   - **P (`Privacy / Data`)**: Dữ liệu vị trí GPS hành trình xe, video/audio cabin & robot, dữ liệu y tế/PII khách hàng, cách ly dữ liệu đa thuê bao (multi-tenant).
   - **C (`Compliance / Audit`)**: Nhật ký kiểm toán bất biến cho lệnh điều khiển từ xa, chữ ký số gói cập nhật OTA/model weights.
3. **Tự phản biện Mù Ngữ cảnh (Blinded Invariant Challenge)**:
   - Tự đặt câu hỏi đối kháng: *"Bất biến nào tài liệu quên ghi nhưng nếu vi phạm sẽ gây tai nạn vật lý, thất thoát tài chính hoặc chiếm quyền điều khiển chéo?"*

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Đọc tài liệu đặc tả / OpenAPI / Proto / SQL / Manifest
python3 -m localsec.manual_session read_file <repo_name> README.md 1 180 --skill intent_invariant_modeler

# 2. Lưu mô hình ý định & bất biến S-F-O-P-C
python3 -m localsec.manual_session submit_skill <repo_name> intent_invariant_modeler /tmp/intent_invariant_modeler_<repo_name>.json
```
