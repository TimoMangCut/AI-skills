---
name: phase-1-unified-surface-mapper
description: >-
  Phase 1.4 — Đọc mã nguồn một lượt duy nhất (Single-Pass), thực hiện AI Semantic Clustering để gom cụm tương đương, đối sánh Ý định vs Triển khai và ghi sổ Coverage Ledger (unified_surface_mapper). Kích hoạt ở Bước 1.4 hoặc khi gọi /phase-1-unified-surface-mapper.
---

# Phase 1.4: Unified Surface, Dataflow & Implementation Mapper (`unified_surface_mapper`)

Bạn đang thực thi **Bước 1.4 (`unified_surface_mapper`)** trong **Phase 1: Unified Reconnaissance (LocalSec v3.0)**.
Đây là bước trọng tâm kết hợp:
1. **Single-Pass Manual Code Reading**: Trong một lần mở file controller/service/consumer duy nhất, bạn kiểm tra đồng thời cả **Entrypoint/AuthN/AuthZ**, **Dataflow/Sinks** VÀ **Điểm kiểm soát Bất biến Nghiệp vụ/An toàn (Intent vs Implementation)**. Không bao giờ đọc lại cùng một file ở hai phase khác nhau.
2. **Mục 2 — AI Semantic Clustering (100% do AI quyết định, KHÔNG dùng Python SAST)**:
   - Khi một module có nhiều endpoints/handlers dùng chung một cơ chế kiểm soát (ví dụ cùng kế thừa `BaseAuthenticatedController`, cùng dùng `@UseGuards(JwtAuthGuard, TenantScopeGuard)`, cùng gọi chuẩn ORM có filter `tenant_id`), bạn đọc sâu **1–2 đại diện (`representative_deep_read_evidence_ids`)** để xác nhận cơ chế chung, sau đó gom các endpoint chuẩn vào `semantic_clusters` (`Shared-Control Group`).
   - Dành toàn bộ ngân sách đọc sâu cho các **Dị biệt (`outliers`)**:
     - Điểm tắt/bỏ qua xác thực (`@Public()`, `AllowAnonymous`, thiếu guard, webhook/callback ngoại lệ).
     - Điểm thao tác trực tiếp lên lệnh điều khiển vật lý, tiền tệ, hạn mức, chữ ký OTA, hoặc raw SQL / subprocess / deserialization.
3. **Mục 3 — Ghi sổ `coverage_ledger.json` & Tuân thủ `Anti-Grazing`**:
   - Mọi module trong `target_modules` (từ Bước 1.1) phải được mở đọc thực chất (không đọc lướt $\le 8$ dòng đầu file dài $> 25$ dòng).
   - Mỗi đơn vị kiểm tra được gán mã `coverage_id` chuẩn RFC 3986 (4 hoặc 5 phân đoạn ngăn cách bởi `::`):
     `surface::boundary::subsystem::attack_class[::lifecycle]`
     *(Ví dụ: `ocpp_ws::csms_gateway::charging_session::bola_session_stop::active`)*.

---

## 1. Giao thức Thực thi CLI

```bash
# 1. Lấy các khối Attack-Class Companion nguyên văn phù hợp với techstack/archetype của repo
python3 -m localsec.manual_session select_attack_companions <repo_name>

# 2. Đọc mã nguồn thực chất trên từng target_module (tránh đọc <=8 dòng gây lỗi Anti-Grazing)
python3 -m localsec.manual_session read_file <repo_name> <path> 1 160 --skill unified_surface_mapper

# 3. Lưu kết quả unified_surface_mapper và coverage_ledger
python3 -m localsec.manual_session submit_skill <repo_name> unified_surface_mapper /tmp/unified_surface_mapper_<repo_name>.json
python3 -m localsec.manual_session submit_skill <repo_name> coverage_ledger /tmp/coverage_ledger_<repo_name>.json
```

---

## 2. Định dạng `coverage_ledger.json` Bắt buộc

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
      "shared_control_signature": "JwtAuthGuard + TenantReadOnlyInterceptor with parameterized TypeORM findByTenant()",
      "representative_deep_read_evidence_ids": ["ev_..."],
      "member_endpoints": [
        "GET /api/v1/stations",
        "GET /api/v1/tariffs",
        "GET /api/v1/connectors"
      ],
      "outliers": [
        "POST /api/v1/sessions/{id}/remote-stop"
      ]
    }
  ]
}
```
