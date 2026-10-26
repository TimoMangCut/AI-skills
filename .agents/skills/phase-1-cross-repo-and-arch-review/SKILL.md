---
name: phase-1-cross-repo-and-arch-review
description: >-
  Phase 1.5 — Đánh giá kiến trúc bảo mật, phát hiện lệch giả định tin cậy xuyên dịch vụ/xuyên repo và vẽ sơ đồ Mermaid phân biệt rõ cạnh đã xác nhận với cạnh giả thuyết (cross_repo_and_arch_review). Kích hoạt ở Bước 1.5 hoặc khi gọi /phase-1-cross-repo-and-arch-review.
---

# Phase 1.5: Architecture & Cross-Repo Trust Boundary Review (`cross_repo_and_arch_review`)

> **Subagent Isolation Directive**: Run `match_cross_repo_boundaries` first, then synthesize cross-service trust boundary mismatches and Mermaid architecture diagrams.

Bạn đang thực thi **Bước 1.5 (`cross_repo_and_arch_review`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`.

Bước này bắt đầu bằng việc chạy công cụ ghép cặp ranh giới liên repo tất định (`match_cross_repo_boundaries` — `DEPTH-4.1f`), sau đó phân tích độ lệch giả định tin cậy xuyên qua nhiều repositories (Mobile App $\leftrightarrow$ API Gateway $\leftrightarrow$ Microservices $\leftrightarrow$ Kafka/EMQX/ZeroMQ $\leftrightarrow$ OT/ECU/Robot) và xuất sơ đồ Mermaid trực quan.

---

## 1. Ghép cặp Ranh giới Xuyên Repo Tất định (`match_cross_repo_boundaries` — `DEPTH-4.1f`)

1. **Chạy lệnh `match_cross_repo_boundaries` Trước Tiên**:
   - Trước khi viết đánh giá kiến trúc, chạy `python3 -m localsec.manual_session match_cross_repo_boundaries`.
   - Engine sẽ tự động đối sánh các `data_flows[]` chiều đi (`outbound`) của repo này với `entrypoints[]` chiều đến (`inbound`) của các repo khác (theo HTTP path, gRPC service/method, Kafka/MQTT/ZeroMQ topic) để lập danh sách:
     - `matched_edges[]` (các cặp kết nối liên repo đã khớp),
     - `unmatched_producers[]` / `unmatched_consumers[]` (các kết nối mồ côi hoặc gọi ra dịch vụ bên ngoài chưa có trong workspace),
     - `auth_propagation_gaps[]` (ví dụ: producer gửi request không đính kèm auth/signature hoặc giả định gateway đã xác thực, trong khi consumer có `authn: "none"` hoặc tin tưởng header `X-Tenant-Id` không chữ ký).

---

## 2. Trọng tâm Kiểm tra Lệch Giả định Tin cậy (`trust_boundary_mismatches`)

1. **Gateway vs Upstream Service (`Header Spoofing`)**:
   - Upstream tin tưởng mù quáng các header `X-User-Id`, `X-Tenant-Id`, `X-Dealer-Code`, `X-Vin-Id` nhưng có thể bị gọi trực tiếp qua ALB/Ingress nội bộ mà không bị Kong/KrakenD/Cloudflare strip header.
2. **Producer vs Consumer (`Async Event / MQTT / ZeroMQ Trust`)**:
   - Consumer (Kafka, RabbitMQ, EMQX MQTT, ZeroMQ `vla.cpp`) giả định mọi message trên topic/socket đã được kiểm tra quyền hoặc schema ở Producer, trong khi thiết bị biên hoặc đối tác có thể publish trực tiếp.
3. **Cloud Control Plane vs Cyber-Physical Edge (`IT/OT & Cloud-to-Vehicle`)**:
   - Lệnh từ portal vận hành/Cloud xuống T-Box, trạm sạc OCPP, BESS PCS/BMS hoặc Robot thiếu chữ ký đầu-cuối (end-to-end command signing) hoặc thiếu kiểm tra trạng thái an toàn vật lý tại biên.
4. **Sơ đồ Mermaid Chuẩn xác (`diagrams`)**:
   - Cạnh đã xác nhận bằng mã nguồn (`confirmed`/`observed`): dùng nét liền `-->`.
   - Cạnh giả thuyết (`hypothesis`/`unknown`): dùng nét đứt `-.->`.


## 2b. Lượt STRIDE và hardening bắt buộc (`stride_review` — Đợt 7, E7)

`finalize_v3_phase1` không đạt nếu thiếu `stride_review` hoặc thiếu một trong 8 mục: `spoofing`, `tampering`, `repudiation`, `information_disclosure`, `denial_of_service`, `elevation_of_privilege`, `client_side_supply_chain` (script/SDK/CDN phát cho trình duyệt: SRI, nguồn tải, khoá phiên bản), `shared_service_credentials` (một token/khoá dịch vụ dùng chung cho mọi người dùng, khoá dùng chung giữa nhiều dịch vụ). Mỗi mục có `review_status`:
- `issue_found`: `issues[]`, mỗi vấn đề có `title`, `target_path`, `evidence_ids` thật, ví dụ `"denial_of_service": {"review_status": "issue_found", "issues": [{"title": "Mỗi request dựng lại toàn bộ server và đăng ký mọi tool", "target_path": "apps/mcp/server/index.ts", "evidence_ids": ["ev_..."]}]}`. Mỗi vấn đề tự động thành một ứng viên Phase 2 (`STRIDE_<MỤC>`).
- `checked_none`: đã xem và không thấy vấn đề, kèm `checked_paths` và `evidence_ids` thật của chỗ đã xem.
- `not_applicable`: `reason` ≥ 20 ký tự, nói vì sao không áp dụng.

Lượt này bù cho các lớp mà companion theo loại tấn công không phủ: thử nghiệm trên `vinfast-mcp` đã bỏ sót SRI của Chat SDK, DoS do dựng lại server mỗi request, thiếu audit và một token dịch vụ dùng chung.

---


## 2c. Danh mục mẫu lỗi cố định (`pattern_checklist` — Đợt 8, V16)

Cùng luật với `stride_review` (`review_status`: `issue_found` / `checked_none` / `not_applicable`, kèm bằng chứng). Cả 10 mục đều bắt buộc, và mỗi issue thành ứng viên `PATTERN_<MỤC>`. Mục đích là mọi lần chạy đều nhìn vào cùng những chỗ:
- `process_local_state_multi_replica`: idempotency, khoá dùng một lần, rate limit, phiên/flow lưu trong bộ nhớ tiến trình khi có nhiều replica.
- `client_asserted_identity_or_ownership`: user id, VIN, tenant, cờ sở hữu (`hasLinkedVin`) do client hoặc header gửi lên.
- `client_controlled_state_or_flags`: state blob, `termsAccepted`, `consent`, giá, số lượng do client hoặc model gửi.
- `ownership_check_on_every_object_access`: mọi đọc/sửa/xoá theo id có kiểm chủ sở hữu ở service này hay chỉ dựa vào phía sau.
- `replay_and_idempotency`: vé, nonce, request lặp, webhook lặp.
- `llm_or_tool_argument_trust`: tham số tool do model chọn (prompt injection / confused deputy).
- `outbound_url_fetch`: URL do người dùng hoặc model đưa vào lời gọi ra ngoài (SSRF).
- `environment_gated_controls`: kiểm soát bật/tắt theo `NODE_ENV`/`APP_ENV`/cờ cấu hình.
- `debug_error_and_metadata_exposure`: `/health`, stack trace, thông tin build, CORS nới ngoài prod.
- `secrets_in_code_or_config`: khoá, token trong code, file cấu hình, image.

## 3. Giao thức Thực thi CLI

```powershell
# 1. Tự động ghép cặp outbound data_flows[] và inbound entrypoints[] xuyên qua các repositories
python3 -m localsec.manual_session match_cross_repo_boundaries

# 2. Lưu kết quả đánh giá kiến trúc & liên repo (đối chiếu AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json)
python3 -m localsec.manual_session submit_skill <repo_name> cross_repo_and_arch_review .localsec/tmp/cross_repo_and_arch_review_<repo_name>.json
```

---

## 4. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "trust_boundary_mismatches": [
      {
        "mismatch_id": "XREPO-HDR-01",
        "title": "Consumer trusts unsigned X-Tenant-Id header from gateway",
        "producer_repo": "api-gateway",
        "consumer_repo": "csms-service",
        "consumer_path": "src/ocpp_controller.py",
        "attack_class": "CROSS_SERVICE_TRUST_MISMATCH",
        "status": "confirmed",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "architecture_findings": [
      {
        "id": "ARCH-OCPP-01",
        "title": "Missing end-to-end command signature between HTTP API and OCPP dispatcher",
        "severity": "high",
        "status": "confirmed",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "matched_cross_repo_boundaries": [
      {
        "boundary_id": "BND-GW-CSMS-01",
        "producer_repo": "api-gateway",
        "consumer_repo": "csms-service",
        "protocol_or_channel": "HTTP POST /api/v1/sessions/{sessionId}/remote-start",
        "trust_assumption_mismatch": "Gateway forwards unverified tenant header to CSMS consumer",
        "status": "confirmed",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "stride_review": {
      "spoofing": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "tampering": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "repudiation": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "information_disclosure": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "denial_of_service": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "elevation_of_privilege": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "client_side_supply_chain": {"review_status": "not_applicable", "reason": "Backend-only service: no browser bundle, CDN script or SDK is served from this repo"},
      "shared_service_credentials": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]}
    },
    "pattern_checklist": {
      "process_local_state_multi_replica": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "client_asserted_identity_or_ownership": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "client_controlled_state_or_flags": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "ownership_check_on_every_object_access": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "replay_and_idempotency": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "llm_or_tool_argument_trust": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "outbound_url_fetch": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "environment_gated_controls": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "debug_error_and_metadata_exposure": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]},
      "secrets_in_code_or_config": {"review_status": "checked_none", "checked_paths": ["src/ocpp_controller.py"], "evidence_ids": ["ev_001"]}
    },
    "diagrams": [
      "flowchart LR\n  Gateway-->Service"
    ],
    "summary": "Identified trust boundary mismatch on unsigned tenant header forwarding between gateway and CSMS service."
  }
}
```
