---
name: phase-1-unified-surface-mapper
description: >-
  Phase 1.4 — Đọc mã nguồn một lượt duy nhất (Single-Pass), thực hiện AI Semantic Clustering để gom cụm tương đương, đối sánh Ý định vs Triển khai và ghi sổ Coverage Ledger (unified_surface_mapper). Kích hoạt ở Bước 1.4 hoặc khi gọi /phase-1-unified-surface-mapper.
---

# Phase 1.4: Unified Surface, Dataflow & Implementation Mapper (`unified_surface_mapper`)

Bạn đang thực thi **Bước 1.4 (`unified_surface_mapper`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và hai schema mục tiêu: `AI-skills/schemas/v3/unified_surface_mapper.schema.json` cùng `AI-skills/schemas/v3/coverage_ledger.schema.json`.

Đây là bước trọng tâm kết hợp đọc mã nguồn một lượt duy nhất (**Single-Pass Manual Code Reading**), kiểm kê đầy đủ 9 loại bề mặt, đối sánh bất biến từ Bước 1.3 và gom cụm ngữ nghĩa an toàn (**Safe Semantic Clustering**):

---

## 1. Năm Yêu cầu Kỹ thuật Bắt buộc (`DEPTH-4.1a..d`, `ARCH-3F`, `DEPTH-4.2a`)

1. **Danh sách Kiểm tra 9 Loại Bề mặt Tấn công (`surface_checklist` — `DEPTH-4.1a`)**:
   - Bắt buộc đánh giá đầy đủ 9 loại bề mặt (ghi rõ `present`: `true`/`false`, số lượng và `evidence_ids` hoặc `searched_paths`):
     1. `public_http`
     2. `internal_or_admin_http`
     3. `queue_or_event_consumer`
     4. `scheduler_or_batch`
     5. `webhook_or_callback`
     6. `websocket_mqtt_ocpp`
     7. `cli_or_maintenance_job`
     8. `mobile_deeplink_or_exported_component`
     9. `ble_or_hardware_bus`
2. **Kiểm kê `entrypoints[]` Giàu Ngữ cảnh (`DEPTH-4.1b`)**:
   - Mỗi entrypoint trong `entrypoints[]` phải khai báo rõ các trường:
     `id`, `surface_type`, `method`, `path`, `file`, `authn`, `authz`, `object_id_params` (danh sách tham số định danh đối tượng như `{id}`, `orderId`, `vin`, `stationId`, `session_id`), `ownership_check`, `input_binding`, `response_shape`, `rate_limit`, `status` và `evidence_ids`.
3. **Luật Gom cụm Ngữ nghĩa An toàn (`Safe Clustering Rule` — `ARCH-3F` & `DEPTH-4.2a`)**:
   - **Cấm gom cụm mù với `object_id_params` (`ARCH-3F`)**: Bất kỳ entrypoint nào có `object_id_params` khác rỗng (`non-empty`) **TUYỆT ĐỐI KHÔNG ĐƯỢC** làm thành viên gom cụm ngầm chưa kiểm chứng (`implicit unverified cluster member`). Bạn bắt buộc phải đọc trực tiếp kiểm tra quyền sở hữu (`ownership_check`) của nó kèm `ev_...` hoặc đưa nó vào danh sách **`outliers`** để điều tra BOLA/IDOR.
   - **Kiểm tra xác suất cụm lớn (`spot_check_clusters` — `DEPTH-4.2a`)**: Với bất kỳ `semantic_cluster` nào có `>= 5` thành viên (`member_endpoints`), bắt buộc đọc sâu thêm ít nhất 1 thành viên thứ hai và ghi mã bằng chứng vào `spot_check_evidence_ids` để chứng minh tính đồng nhất của cụm.
4. **Đối sánh Bất biến (`invariant_checks[]` — `DEPTH-4.1d`) & Luồng Dữ liệu (`data_flows[]`, `sensitive_data[]` — `DEPTH-4.1c`)**:
   - Mọi `invariant_id` từ Bước 1.3 (`intent_invariant_modeler`) phải được đối chiếu thực tế triển khai trong `invariant_checks[]` (`enforced`, `violated_or_missing`, `partial`) kèm `evidence_ids`.
   - Khai báo đầy đủ `data_flows[]` (inbound/outbound qua HTTP, gRPC, Kafka, MQTT, ZeroMQ, DB) và `sensitive_data[]` (PII, token, khóa, tọa độ GPS, lệnh điều khiển vật lý).
5. **Ghi sổ `coverage_ledger.json` & Tuân thủ `Anti-Grazing`**:
   - Mọi module trong `target_modules` và mọi file `entrypoint` / `security` bắt buộc trong `inventory_repo.json` phải được mở đọc thực chất (cấm đọc lướt `<= 8` dòng đầu của file dài `> 25` dòng).
   - Mỗi bản ghi `coverage_id` tuân thủ chuẩn RFC 3986 (4–5 phân đoạn `surface::boundary::subsystem::attack_class[::lifecycle]`).

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Lấy các khối Attack-Class Companion nguyên văn từ AI-skills/contracts/attack-taxonomy-v1/manifest.json
python -m localsec.manual_session select_attack_companions <repo_name>

# 2. Đọc mã nguồn thực chất trên từng target_module và mandatory_files (tránh đọc <=8 dòng gây lỗi Anti-Grazing)
python -m localsec.manual_session read_file <repo_name> <path> 1 160 --skill unified_surface_mapper

# 3. Lưu kết quả unified_surface_mapper và coverage_ledger
python -m localsec.manual_session submit_skill <repo_name> unified_surface_mapper .localsec/tmp/unified_surface_mapper_<repo_name>.json
python -m localsec.manual_session submit_skill <repo_name> coverage_ledger .localsec/tmp/coverage_ledger_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON (`unified_surface_mapper.json` & `coverage_ledger.json`)

### 3.1. Mẫu `unified_surface_mapper.json` (`AI-skills/schemas/v3/unified_surface_mapper.schema.json`)

```json
{
  "surface_checklist": {
    "public_http": {"present": true, "count": 4, "evidence_ids": ["ev_..."]},
    "internal_or_admin_http": {"present": true, "count": 2, "evidence_ids": ["ev_..."]},
    "queue_or_event_consumer": {"present": false, "count": 0, "searched_paths": ["src/"]},
    "scheduler_or_batch": {"present": false, "count": 0, "searched_paths": ["src/"]},
    "webhook_or_callback": {"present": false, "count": 0, "searched_paths": ["src/"]},
    "websocket_mqtt_ocpp": {"present": true, "count": 3, "evidence_ids": ["ev_..."]},
    "cli_or_maintenance_job": {"present": false, "count": 0, "searched_paths": ["src/"]},
    "mobile_deeplink_or_exported_component": {"present": false, "count": 0, "searched_paths": ["src/"]},
    "ble_or_hardware_bus": {"present": false, "count": 0, "searched_paths": ["src/"]}
  },
  "entrypoints": [
    {
      "id": "EP-STOP-SESSION",
      "surface_type": "public_http",
      "method": "POST",
      "path": "/api/v1/sessions/{sessionId}/remote-stop",
      "file": "src/controllers/charging.controller.ts",
      "authn": "JwtAuthGuard",
      "authz": "Authenticated B2C User",
      "object_id_params": ["sessionId"],
      "ownership_check": "missing_or_unverified",
      "input_binding": "@Param('sessionId') + @Body() StopSessionDto",
      "response_shape": "SessionCommandAckDto",
      "rate_limit": "none_observed",
      "status": "observed",
      "evidence_ids": ["ev_..."]
    }
  ],
  "invariant_checks": [
    {
      "invariant_id": "INV-OCPP-STOP-01",
      "enforcement_status": "violated_or_missing",
      "notes": "Controller dispatches RemoteStopTransaction by sessionId without checking session.userId == req.user.id",
      "evidence_ids": ["ev_..."]
    }
  ],
  "data_flows": [
    {
      "flow_id": "DF-CSMS-TO-CHARGER",
      "direction": "outbound",
      "source": "src/controllers/charging.controller.ts",
      "destination": "ocpp-ws-gateway:/ocpp/remote-stop",
      "protocol": "WebSocket/OCPP-1.6J",
      "data_types": ["charging_command", "session_id"],
      "trust_boundary": "cloud_csms_to_station",
      "auth_or_integrity": "station_basic_auth",
      "status": "observed",
      "evidence_ids": ["ev_..."]
    }
  ],
  "sensitive_data": [
    {
      "data_class": "charging_session_control_token",
      "storage_or_sink": "Redis + OCPP WebSocket payload",
      "protection": "TLS in transit, no per-user ownership binding on stop command",
      "status": "observed",
      "evidence_ids": ["ev_..."]
    }
  ],
  "candidates": [
    {
      "candidate_id": "CAND-OCPP-BOLA-01",
      "title": "BOLA on POST /api/v1/sessions/{sessionId}/remote-stop allows arbitrary charging session termination",
      "priority": "P0",
      "affected_axis": "O",
      "entrypoint_id": "EP-STOP-SESSION",
      "violated_invariant_id": "INV-OCPP-STOP-01",
      "file": "src/controllers/charging.controller.ts",
      "evidence_ids": ["ev_..."]
    }
  ]
}
```

### 3.2. Mẫu `coverage_ledger.json` (`AI-skills/schemas/v3/coverage_ledger.schema.json`)

```json
{
  "records": [
    {
      "coverage_id": "http_api::b2c_mobile_edge::charging_controller::bola_tenant_isolation::active",
      "status": "covered_finding",
      "evidence_ids": ["ev_..."],
      "attempts": [
        {
          "attempt_number": 1,
          "skill": "unified_surface_mapper",
          "outcome": "Mismatch found: stopSession endpoint checks JWT validity but does not verify session.userId == currentUser.id"
        }
      ]
    }
  ],
  "semantic_clusters": [
    {
      "cluster_id": "CLUST-READONLY-CATALOG",
      "shared_control_signature": "JwtAuthGuard + TenantReadOnlyInterceptor with parameterized TypeORM findByTenant() and zero object_id_params",
      "representative_deep_read_evidence_ids": ["ev_..."],
      "spot_check_evidence_ids": ["ev_..."],
      "member_endpoints": [
        "GET /api/v1/stations",
        "GET /api/v1/tariffs",
        "GET /api/v1/connectors",
        "GET /api/v1/amenities",
        "GET /api/v1/regions"
      ],
      "outliers": [
        "POST /api/v1/sessions/{sessionId}/remote-stop"
      ]
    }
  ]
}
```
