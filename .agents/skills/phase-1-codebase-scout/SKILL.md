---
name: phase-1-codebase-scout
description: >-
  Phase 1.1 Micro-Skill — Khảo sát nhanh cấu trúc thư mục và 3-5 file mẫu để xác định Product Archetypes, Repo Tier (Tier 1/2/3), quy ước code của team và lập Target Modules Map (codebase_scout). Kích hoạt ở đầu Phase 1 hoặc khi gọi /phase-1-codebase-scout.
---

# Phase 1.1 Micro-Skill: Codebase & Convention Scout (`codebase_scout`)

> **Subagent Isolation Directive**: Run this skill in the Phase 1 reconnaissance context for the target repository before reading implementation code.

Bạn đang thực thi **Micro-Skill `phase-1-codebase-scout` (Bước 1.1)** trong bộ kỹ năng **LocalSec v3.0**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/codebase_scout.schema.json`.

Mục tiêu của bước này là **định vị chính xác mẫu số kiểm toán tất định** kết hợp khảo sát cấu trúc bằng AI: chạy `inventory_repo` trước để lấy danh sách `mandatory_files` và `scan_repo_leads`, sau đó dùng `list_dir` và đọc lướt các file manifest/wiring mẫu để phân loại **Product Archetype**, xếp hạng **Repo Tier (`tier_1` / `tier_2` / `tier_3`)** và khóa **Target Modules Map** trước khi chuyển sang Bước 1.3 (`intent_invariant_modeler`).

---

## 1. Quy tắc Kỷ luật Bắt buộc (`ARCH-3C`, `ARCH-3K`, `DEPTH-4.1e`, `DEPTH-4.3d`, `DEPTH-4.7`)

1. **Chạy Kiểm kê Tất định `inventory_repo` Trước Tiên (`ARCH-3C`)**:
   - Bắt buộc chạy `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session inventory_repo <repo_name> --tier 1` ngay đầu Bước 1.1.
   - File `.localsec/runs/default/<repo_name>/inventory_repo.json` cung cấp danh sách tất định `mandatory_files` (phân loại theo `entrypoint`, `security`, `wiring_config`, `outbound`, `data_access`) cùng các dấu vết nhạy cảm/phụ thuộc (`scan_repo_leads`).
2. **Độ phủ Bắt buộc của `target_modules` & Enum `ignored_modules`**:
   - `target_modules` **BẮT BUỘC phải bao phủ 100% các thư mục có chứa file `entrypoint` hoặc `security`** trong `inventory_repo.json`.
   - Nếu loại trừ bất kỳ thư mục nào vào `ignored_modules`, mỗi mục **BẮT BUỘC** phải khai báo `path` và `reason` thuộc đúng tập enum chuẩn trong `contracts/v3-orchestration.json`:
     - `test_or_mock`
     - `generated_code`
     - `third_party_vendor`
     - `deprecated_dead_code`
     - `docs_or_assets`
3. **Tuân thủ Thứ tự `Intent Before Code` (`ARCH-3K`)**:
   - Ở Bước 1.1, chỉ duyệt cấu trúc thư mục (`list_dir --depth 2`) và đọc các file manifest/build/wiring (`package.json`, `go.mod`, `pom.xml`, `CMakeLists.txt`, `Dockerfile`, `localsec.toml`, config định tuyến) để lập bản đồ module và chọn `canary_files`, giữ nguyên tính độc lập cho Bước 1.3 (`intent_invariant_modeler`).

---

## 2. Phân loại Product Archetypes & Repo Tier

### 2.1. Product Archetypes (`product_archetypes` & `detected_archetypes`)
- `automotive_connected_car_ota_tbox` (VinFast ECU/T-Box, Uptane/OTA, CAN/UDS, SOME/IP, DoIP, eSIM)
- `ev_charging_ocpp_ocpi_bess` (V-Green CSMS, OCPP 1.6J/2.0.1, OCPI, ISO 15118 Plug&Charge)
- `robotics_cpp_ros2_ot_scada_bess` (VinRobotics `vla.cpp`, C++/ZeroMQ/GGUF, ROS2/DDS, VinEnergo BESS Modbus/OPC-UA/IEC-104, VinMetal ISA-95)
- `web_spa_nextjs_ssr` (React, Next.js App Router/SSR, Angular, Vue, Nuxt, Vite)
- `mobile_android_ios_flutter` (Android/Kotlin/Java/Smali, iOS/Swift, Flutter/Dart, BLE Phone-as-a-Key)
- `api_rest_graphql_grpc_websocket` (Spring Boot, Go Gin/Echo, NestJS, FastAPI, Django, .NET, gRPC, GraphQL, EMQX/MQTT)
- `iam_auth0_cognito_azuread_fido2` (OIDC/OAuth2, Auth0, AWS Cognito, Azure AD/Entra ID, Keycloak, Passkey/FIDO2)
- `edge_cloudflare_kong_krakend_nginx` (Cloudflare Workers/WAF, Kong, KrakenD, Envoy, Nginx)
- `cloud_aws_gcp_azure_iam_storage` (Terraform, Helm, AWS IoT Core, S3/GCS, IAM Policies)
- `onprem_k8s_network_rfc1918` (Kubernetes manifests, NetworkPolicy, Harbor, Calico, RFC1918)
- `cicd_ado_github_argocd_supplychain` (Azure DevOps `azure-pipelines.yml`, GitHub Actions, ArgoCD, GitLab CI)
- `enterprise_sap_mulesoft_b2b` (SAP S/4HANA RFC/BAPI/OData, MuleSoft, Dealer/Vendor B2B Portal)
- `data_kafka_flink_doris_superset_airflow` (Kafka, Flink, Spark, Apache Doris, Superset, Airflow DAGs)
- `ai_llm_vla_model_serving_datasets` (LLM/RAG, MCP tools, PyTorch/ONNX/TensorRT/GGUF, Triton/vLLM)

### 2.2. Phân hạng Repo Tier
- **`tier_1` (Critical Production / Safety / Core Auth / Financial / Gateway / OT Control)**: Đọc sâu đầy đủ và kiểm chứng mọi bất biến S-F-O-P-C.
- **`tier_2` (Standard Internal Backend / B2B Service / Data Pipeline / Supporting App)**: Tập trung vào trust boundary, authz, đầu vào/đầu ra nhạy cảm.
- **`tier_3` (Static UI Library / SDK Wrapper / Documentation / Prototype / Test Utility)**: Chế độ khảo sát nhẹ (Lightweight Recon), kiểm tra hardcoded secrets, dependency/supply-chain và cấu hình.

---

## 3. Giao thức Thực thi CLI

```powershell
# 1. Chạy kiểm kê tất định để lấy mandatory_files (entrypoint, security, wiring_config, outbound, data_access) và scan_repo_leads
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session inventory_repo <repo_name> --tier 1

# 2. Xem cấu trúc thư mục gốc (depth 2)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout

# 3. Đọc file manifest/wiring mẫu để xác định quy ước tổ chức repo
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <path_to_manifest_or_wiring> 1 120 --skill codebase_scout

# 4. Lưu và xác thực kết quả codebase_scout.json (đối chiếu AI-skills/schemas/v3/codebase_scout.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session register_scout_map <repo_name> /tmp/codebase_scout_<repo_name>.json
```

---

## 4. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/codebase_scout.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "repo_tier": "tier_1",
    "product_archetypes": [
      "ev_charging_ocpp_ocpi_bess"
    ],
    "detected_archetypes": [
      "ev_charging_ocpp_ocpi_bess"
    ],
    "coding_conventions": {
      "framework": "FastAPI + OCPP",
      "auth_guard": "require_jwt"
    },
    "target_modules": [
      "src"
    ],
    "ignored_modules": [
      {
        "path": "docs",
        "reason": "docs_or_assets"
      }
    ],
    "canary_files": [
      "src/ocpp_controller.py"
    ],
    "sample_evidence_ids": [
      "ev_001"
    ]
  }
}
```
