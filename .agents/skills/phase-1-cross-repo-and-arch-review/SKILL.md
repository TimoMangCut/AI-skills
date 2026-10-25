---
name: phase-1-cross-repo-and-arch-review
description: >-
  Phase 1.5 — Đánh giá kiến trúc bảo mật, phát hiện lệch giả định tin cậy xuyên dịch vụ/xuyên repo và vẽ sơ đồ Mermaid phân biệt rõ cạnh đã xác nhận với cạnh giả thuyết (cross_repo_and_arch_review). Kích hoạt ở Bước 1.5 hoặc khi gọi /phase-1-cross-repo-and-arch-review.
---

# Phase 1.5: Architecture & Cross-Repo Trust Boundary Review (`cross_repo_and_arch_review`)

Bạn đang thực thi **Bước 1.5 (`cross_repo_and_arch_review`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`.

Bước này bắt đầu bằng việc chạy công cụ ghép cặp ranh giới liên repo tất định (`match_cross_repo_boundaries` — `DEPTH-4.1f`), sau đó phân tích độ lệch giả định tin cậy xuyên qua nhiều repositories (Mobile App $\leftrightarrow$ API Gateway $\leftrightarrow$ Microservices $\leftrightarrow$ Kafka/EMQX/ZeroMQ $\leftrightarrow$ OT/ECU/Robot) và xuất sơ đồ Mermaid trực quan.

---

## 1. Ghép cặp Ranh giới Xuyên Repo Tất định (`match_cross_repo_boundaries` — `DEPTH-4.1f`)

1. **Chạy lệnh `match_cross_repo_boundaries` Trước Tiên**:
   - Trước khi viết đánh giá kiến trúc, chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session match_cross_repo_boundaries`.
   - Engine sẽ tự động đối sánh các `data_flows[]` chiều đi (`outbound`) của repo này với `entrypoints[]` chiều đến (`inbound`) của các repo khác (theo HTTP path, gRPC service/method, Kafka/MQTT/ZeroMQ topic) để lập danh sách:
     - `matched_flows[]` (các cặp kết nối liên repo đã khớp),
     - `unmatched_outbound[]` / `unmatched_inbound[]` (các kết nối mồ côi hoặc gọi ra dịch vụ bên ngoài chưa có trong workspace),
     - `boundary_mismatches[]` (ví dụ: caller gửi request không đính kèm auth/signature hoặc giả định gateway đã xác thực, trong khi callee có `authn: "none"` hoặc tin tưởng header `X-User-Id`).

---

## 2. Trọng tâm Kiểm tra Lệch Giả định Tin cậy (Cross-Boundary Mismatches)

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

## 3. Giao thức Thực thi CLI

```bash
# 1. Tự động ghép cặp outbound data_flows[] và inbound entrypoints[] xuyên qua các repositories
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session match_cross_repo_boundaries

# 2. Lưu kết quả đánh giá kiến trúc & liên repo (đối chiếu AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> cross_repo_and_arch_review /tmp/cross_repo_and_arch_review_<repo_name>.json
```

---

## 4. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`)

```json
{
  "trust_boundary_mismatches": [
    {
      "mismatch_id": "XREPO-HDR-01",
      "caller_repo": "api-gateway",
      "callee_repo": "charging-service",
      "channel": "HTTP POST /internal/v1/sessions/stop",
      "caller_assumption": "Forwards client X-Tenant-Id header when route is marked pass-through",
      "callee_assumption": "Trusts X-Tenant-Id header as pre-verified by gateway without JWT re-verification",
      "status": "observed",
      "evidence_ids": ["ev_..."]
    }
  ],
  "mermaid_diagram": "flowchart LR\n  MobileApp[\"Mobile App\"] -->|HTTPS JWT| Gateway[\"API Gateway\"]\n  Gateway -->|HTTP X-Tenant-Id| ChargingSvc[\"Charging Service\"]\n  ChargingSvc -.->|OCPP WS Hypothesis| Charger[\"EV Charger\"]"
}
```
