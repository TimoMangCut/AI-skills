---
name: phase-1-unified-surface-mapper
description: >-
  Phase 1.4 — Đọc mã nguồn một lượt duy nhất (Single-Pass), thực hiện AI Semantic Clustering để gom cụm tương đương, đối sánh Ý định vs Triển khai và ghi sổ Coverage Ledger (unified_surface_mapper). Kích hoạt ở Bước 1.4 hoặc khi gọi /phase-1-unified-surface-mapper.
---

# Phase 1.4: Unified Surface, Dataflow & Implementation Mapper (`unified_surface_mapper`)

> **Subagent Isolation Directive**: Perform single-pass manual code reading across all `target_modules` after `intent_invariant_modeler` (Step 1.3) and `extractor_tailor` (Step 1.2) have completed.

Bạn đang thực thi **Bước 1.4 (`unified_surface_mapper`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và hai schema mục tiêu: `AI-skills/schemas/v3/unified_surface_mapper.schema.json` cùng `AI-skills/schemas/v3/coverage_ledger.schema.json`.

Đây là bước trọng tâm kết hợp đọc mã nguồn một lượt duy nhất (**Single-Pass Manual Code Reading**), kiểm kê đầy đủ 9 loại bề mặt, đối sánh bất biến từ Bước 1.3 và gom cụm ngữ nghĩa an toàn (**Safe Semantic Clustering**).

---

## 1. Năm Yêu cầu Kỹ thuật Bắt buộc (`DEPTH-4.1a..d`, `ARCH-3F`, `DEPTH-4.2a`, `R2-P0-01`)

1. **Danh sách Kiểm tra 9 Loại Bề mặt Tấn công (`surface_checklist` — `DEPTH-4.1a`)**:
   - Bắt buộc đánh giá đầy đủ 9 loại bề mặt với trường **`"status": "present" | "absent" | "unknown"`** (TUYỆT ĐỐI KHÔNG dùng `"present": true/false`):
     1. `public_http`
     2. `internal_or_admin_http`
     3. `queue_or_event_consumer`
     4. `scheduler_or_batch`
     5. `webhook_or_callback`
     6. `websocket_mqtt_ocpp`
     7. `cli_or_maintenance_job`
     8. `mobile_deeplink_or_exported_component`
     9. `ble_or_hardware_bus`
   - Mọi bề mặt có `"status": "unknown"` sẽ được `finalize_v3_phase1` tự động đưa vào `candidate_queue` để điều tra ở Phase 2.
2. **Kiểm kê `entrypoints[]` Giàu Ngữ cảnh (`DEPTH-4.1b`)**:
   - Mỗi entrypoint trong `entrypoints[]` phải khai báo rõ các trường chuẩn:
     - `id`, `method`, `path`, `file`, `authn`, `authz`, `object_id_params` (mảng tham số định danh đối tượng như `["sessionId"]` hoặc `[]`).
     - `ownership_check`: bắt buộc thuộc enum **`"present" | "missing" | "partial" | "not_applicable" | "unknown"`** (nếu `object_id_params` khác rỗng và `ownership_check != "present"`, tự động sinh ứng viên BOLA/IDOR).
     - `input_binding`: bắt buộc thuộc enum **`"dto_whitelist" | "raw_entity_or_map" | "unvalidated_json" | "none"`** (nếu `"raw_entity_or_map"`, tự động sinh ứng viên BOPLA/Mass-Assignment).
     - `response_shape`, `rate_limit`, `status` và `evidence_ids`.
3. **Luật Gom cụm Ngữ nghĩa An toàn (`Safe Clustering Rule` — `ARCH-3F` & `DEPTH-4.2a`)**:
   - Trong `semantic_clusters[]`, khai báo cả **`"representative_file"` + `"member_files"`** (cấp độ file cho Visibility Tracker) lẫn **`"representative_endpoint"` + `"member_endpoints"`** (cấp độ API), kèm `"representative_deep_read_evidence_ids"` và `"outliers"`.
   - **Cấm gom cụm mù với `object_id_params` (`ARCH-3F`)**: Bất kỳ entrypoint nào có `object_id_params` khác rỗng **TUYỆT ĐỐI KHÔNG ĐƯỢC** làm thành viên gom cụm ngầm chưa kiểm chứng. Nó bắt buộc phải có `ownership_check: "present"` kèm `evidence_ids`, hoặc phải được đưa vào **`outliers`** / **`candidate_queue`**.
   - **Kiểm tra xác suất cụm lớn (`spot_check_clusters` — `DEPTH-4.2a`)**: Với cụm có `>= 5` thành viên, bắt buộc đọc sâu thêm ít nhất 1 thành viên thứ hai ngoài `representative_file`.
4. **Đối sánh Bất biến (`invariant_checks[]` — `DEPTH-4.1d`) & Luồng Dữ liệu (`data_flows[]` — `DEPTH-4.1c`)**:
   - Mọi `invariant_id` từ Bước 1.3 phải được đối chiếu trong `invariant_checks[]` với `enforcement_status`: `"enforced" | "missing" | "partial" | "unknown"`.
   - Trong `data_flows[]`, bắt buộc khai báo trường **`"identity_forwarding"`** thuộc enum: `"jwt_forwarded" | "mtls_client_cert" | "internal_header_signed" | "internal_header_unsigned" | "none" | "unknown"`.
   - Đặt danh sách ứng viên vào trường **`"candidate_queue"`** (TUYỆT ĐỐI KHÔNG dùng tên cũ `"candidates"`).
5. **Ghi sổ `coverage_ledger.json` & Tuân thủ `Anti-Grazing`**:
   - Mỗi bản ghi trong `records[]` tuân thủ định dạng `coverage_id` 4–5 phân đoạn `surface::boundary::subsystem::attack_class[::lifecycle]` (ví dụ `"http_api::csms_edge::src::bola_idor::active"`) và `status` thuộc `"covered_clean" | "covered_finding" | "reopened" | "deferred_out_of_budget"`.

---

## 2. Giao thức Thực thi CLI

```powershell
# 1. Lấy các khối Attack-Class Companion nguyên văn từ AI-skills/contracts/attack-taxonomy-v1/manifest.json
python -m localsec.manual_session select_attack_companions <repo_name>

# 2. Đọc mã nguồn thực chất trên từng target_module và mandatory_files (tránh đọc <=8 dòng gây lỗi Anti-Grazing)
python -m localsec.manual_session read_file <repo_name> src/ocpp_controller.py 1 160 --skill unified_surface_mapper

# 3. Lưu kết quả unified_surface_mapper và coverage_ledger
python -m localsec.manual_session submit_skill <repo_name> unified_surface_mapper .localsec/tmp/unified_surface_mapper_<repo_name>.json
python -m localsec.manual_session submit_skill <repo_name> coverage_ledger .localsec/tmp/coverage_ledger_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON Chuẩn (`unified_surface_mapper.schema.json` & `coverage_ledger.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "surface_checklist": [
      {
        "surface_type": "public_http",
        "status": "present",
        "evidence_ids": [
          "ev_001"
        ]
      },
      {
        "surface_type": "internal_or_admin_http",
        "status": "absent",
        "searched_paths": [
          "src"
        ]
      },
      {
        "surface_type": "queue_or_event_consumer",
        "status": "absent",
        "searched_paths": [
          "src"
        ]
      },
      {
        "surface_type": "scheduler_or_batch",
        "status": "absent",
        "searched_paths": [
          "src"
        ]
      },
      {
        "surface_type": "webhook_or_callback",
        "status": "absent",
        "searched_paths": [
          "src"
        ]
      },
      {
        "surface_type": "websocket_mqtt_ocpp",
        "status": "present",
        "evidence_ids": [
          "ev_001"
        ]
      },
      {
        "surface_type": "cli_or_maintenance_job",
        "status": "absent",
        "searched_paths": [
          "src"
        ]
      },
      {
        "surface_type": "mobile_deeplink_or_exported_component",
        "status": "absent",
        "searched_paths": [
          "src"
        ]
      },
      {
        "surface_type": "ble_or_hardware_bus",
        "candidate_id": "cand_111122223333",
        "status": "unknown",
        "searched_paths": [
          "src"
        ]
      }
    ],
    "entrypoints": [
      {
        "id": "EP-STATION-LIST",
        "method": "GET",
        "path": "/api/v1/stations",
        "file": "src/ocpp_controller.py",
        "authn": "require_jwt",
        "authz": "authenticated_user",
        "object_id_params": [],
        "ownership_check": "not_applicable",
        "input_binding": "none",
        "response_shape": "StationListDto",
        "rate_limit": "none",
        "status": "observed",
        "evidence_ids": [
          "ev_001"
        ]
      },
      {
        "id": "EP-REMOTE-START",
        "candidate_id": "cand_111122223333",
        "method": "POST",
        "path": "/api/v1/sessions/{sessionId}/remote-start",
        "file": "src/ocpp_controller.py",
        "authn": "require_jwt",
        "authz": "authenticated_user",
        "object_id_params": [
          "sessionId"
        ],
        "ownership_check": "missing",
        "input_binding": "raw_entity_or_map",
        "response_shape": "SessionCommandAckDto",
        "rate_limit": "none",
        "status": "observed",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "semantic_clusters": [
      {
        "cluster_id": "CLUST-PUBLIC-CATALOG",
        "shared_control_signature": "require_jwt + read-only station query with empty object_id_params",
        "shared_guard_signature": "require_jwt",
        "representative_file": "src/ocpp_controller.py",
        "member_files": [
          "src/ocpp_controller.py"
        ],
        "representative_endpoint": "GET /api/v1/stations",
        "member_endpoints": [
          "GET /api/v1/stations"
        ],
        "representative_deep_read_evidence_ids": [
          "ev_001"
        ],
        "outliers": [
          {
            "candidate_id": "cand_111122223333",
            "id": "EP-REMOTE-START",
            "method": "POST",
            "path": "/api/v1/sessions/{sessionId}/remote-start",
            "file": "src/ocpp_controller.py",
            "evidence_ids": [
              "ev_001"
            ]
          }
        ]
      }
    ],
    "invariant_checks": [
      {
        "invariant_id": "INV-SAFE-01",
        "candidate_id": "cand_111122223333",
        "enforcement_status": "missing",
        "status": "observed",
        "intent_evidence_ids": [
          "ev_001"
        ],
        "implementation_evidence_ids": [
          "ev_001"
        ],
        "evidence_ids": [
          "ev_001"
        ],
        "notes": "RemoteStartTransaction handler does not verify session ownership before energizing connector"
      }
    ],
    "data_flows": [
      {
        "source": "src/ocpp_controller.py",
        "destination": "ocpp://charger/RemoteStartTransaction",
        "protocol": "websocket_ocpp",
        "identity_forwarding": "internal_header_unsigned",
        "status": "observed",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "sensitive_data": [
      {
        "data_class": "charging_session_command_token",
        "path": "src/ocpp_controller.py",
        "status": "observed",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "candidate_queue": [
      {
        "candidate_id": "cand_111122223333",
        "title": "BOLA and BOPLA on POST /api/v1/sessions/{sessionId}/remote-start",
        "target_paths": [
          "src/ocpp_controller.py"
        ],
        "attack_classes": [
          "BOLA_IDOR"
        ],
        "severity": "high",
        "evidence_ids": [
          "ev_001"
        ]
      }
    ],
    "records": [
      {
        "coverage_id": "http_api::csms_edge::src::bola_idor::active",
        "status": "covered_finding",
        "evidence_ids": [
          "ev_001"
        ],
        "attempts": [
          {
            "attempt_number": 1,
            "skill": "unified_surface_mapper",
            "outcome": "Identified missing ownership_check and raw_entity_or_map binding on remote-start endpoint"
          }
        ]
      }
    ]
  }
}
```
