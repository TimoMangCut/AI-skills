---
name: phase-1-cross-repo-and-arch-review
description: >-
  Phase 1.5 — Đánh giá kiến trúc bảo mật, phát hiện lệch giả định tin cậy xuyên dịch vụ/xuyên repo và vẽ sơ đồ Mermaid phân biệt rõ cạnh đã xác nhận với cạnh giả thuyết (cross_repo_and_arch_review). Kích hoạt ở Bước 1.5 hoặc khi gọi /phase-1-cross-repo-and-arch-review.
---

# Phase 1.5: Architecture & Cross-Repo Trust Boundary Review (`cross_repo_and_arch_review`)

Bạn đang thực thi **Bước 1.5 (`cross_repo_and_arch_review`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Bước này tổng hợp rủi ro cấp kiến trúc và xuyên qua nhiều repositories (Mobile App $\leftrightarrow$ API Gateway $\leftrightarrow$ Microservices $\leftrightarrow$ Kafka/EMQX/ZeroMQ $\leftrightarrow$ OT/ECU/Robot), đồng thời xuất sơ đồ Mermaid trực quan.

---

## 1. Trọng tâm Kiểm tra Lệch Giả định Tin cậy (Cross-Boundary Mismatches)

1. **Gateway vs Upstream Service (`Header Spoofing`)**:
   - Upstream tin tưởng mù quáng các header `X-User-Id`, `X-Tenant-Id`, `X-Dealer-Code`, `X-Vin-Id` nhưng có thể bị gọi trực tiếp qua ALB/Ingress nội bộ mà không bị Kong/KrakenD/Cloudflare strip header.
2. **Producer vs Consumer (`Async Event / MQTT / ZeroMQ Trust`)**:
   - Consumer (Kafka, RabbitMQ, EMQX MQTT, ZeroMQ `vla.cpp`) giả định mọi message trên topic/socket đã được kiểm tra quyền hoặc schema ở Producer, trong khi thiết bị biên hoặc đối tác có thể publish trực tiếp.
3. **Cloud Control Plane vs Cyber-Physical Edge (`IT/OT & Cloud-to-Vehicle`)**:
   - Lệnh từ portal vận hành/Django/Cloud xuống T-Box, trạm sạc OCPP, BESS PCS/BMS hoặc Robot thiếu chữ ký đầu-cuối (end-to-end command signing) hoặc thiếu kiểm tra trạng thái an toàn vật lý tại biên.
4. **Sơ đồ Mermaid Chuẩn xác**:
   - Cạnh đã xác nhận bằng mã nguồn (`observed`/`derived`): dùng nét liền `-->`.
   - Cạnh giả thuyết (`hypothesis`/`unknown`): dùng nét đứt `-.->`.

---

## 2. Giao thức Thực thi CLI

```bash
# Lưu kết quả đánh giá kiến trúc & liên repo
python3 -m localsec.manual_session submit_skill <repo_name> cross_repo_and_arch_review /tmp/cross_repo_and_arch_review_<repo_name>.json
```
