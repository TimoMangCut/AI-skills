---
name: phase-3-beyond-code-control-mapper
description: >-
  Phase 3.2 — Đánh giá các lớp kiểm soát ngoài mã nguồn ứng dụng như Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC 10.x, AWS IoT Policy, mTLS và khóa liên động vật lý OT Interlock (beyond_code_control_mapper). Kích hoạt ở Bước 3.2 hoặc khi gọi /phase-3-beyond-code-control-mapper.
---

# Phase 3.2: Beyond-Code Infrastructure, Network & OT Control Mapper (`beyond_code_control_mapper`)

> **Subagent Isolation Directive**: Map infrastructure, gateway, network, and physical OT interlock controls for all surviving `chain_id` entries in Phase 3.

Bạn đang thực thi **Bước 3.2 (`beyond_code_control_mapper`)** trong **Phase 3: Contextual Risk & Exploitability Assessment (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`.

Một lỗ hổng tồn tại trong mã nguồn ứng dụng không đồng nghĩa với việc có thể khai thác ngay ngoài thực tế nếu có các lớp bảo vệ hạ tầng, mạng hoặc khóa liên động vật lý (OT/Safety Interlock) chặn trước; ngược lại, một lỗ hổng tưởng nhỏ sẽ trở nên cực kỳ nguy hiểm nếu phơi trực tiếp qua Bare ALB không có WAF.

---

## 1. Phân tầng Mức độ Phơi nhiễm Hạ tầng (`exposure_tier`)

1. `internet_public_behind_cloudflare_waf`: Phơi ra Internet nhưng đi qua Cloudflare Proxy/WAF, Rate Limiting và Bot Management.
2. `internet_public_bare_alb_direct_ip`: Phơi trực tiếp ra Internet qua AWS ALB / GCP Load Balancer / IP tĩnh mà **không đi qua Cloudflare WAF** (hoặc bị lộ Origin IP cho phép bypass Cloudflare).
3. `partner_b2b_mtls_vpn`: Chỉ kết nối với đối tác/trạm sạc/xe qua APN riêng, VPN Site-to-Site hoặc yêu cầu chứng chỉ client mTLS.
4. `internal_vpc_rfc1918`: Nằm trong dải mạng nội bộ (`10.x.x.x` / `172.16.x.x` / `192.168.x.x`), chỉ truy cập được từ trong Kubernetes cluster, mạng văn phòng/nhà máy hoặc sau khi chiếm được foothold nội bộ.
5. `air_gapped_ot_cell_vlan`: Nằm trong mạng OT/SCADA cô lập (BESS Cell VLAN, mạng nhà máy ISA-95 Level 1/2, CAN bus nội bộ xe).

---

## 2. Quy tắc Kỷ luật về Kiểm soát Ngoài Code (`beyond_code_controls` — `ARCH-3H`, `DEPTH-4.4a`, `R2-P0-01`)

1. **Sử dụng Cấu trúc Chuẩn `beyond_code_controls[]` (`R2-P0-01`)**:
   - Khai báo danh sách kiểm soát trong trường **`"beyond_code_controls"`** với các trường bắt buộc:
     - `"control_id"`: mã định danh kiểm soát (ví dụ `"CTRL-WAF-01"`).
     - `"chain_id"`: giữ nguyên mã `chain_id` từ Phase 2 (ví dụ `"CHAIN-OCPP-01"`).
     - `"layer"`: tầng kiểm soát (`"edge_waf"`, `"api_gateway"`, `"network_vpc"`, `"iot_mtls_policy"`, `"ot_hardware_interlock"`).
     - `"status"`: bắt buộc thuộc đúng 3 giá trị **`"confirmed" | "hypothesis" | "absent"`** (TUYỆT ĐỐI KHÔNG dùng `"observed"`).
     - `"mitigation_effect"`: bắt buộc thuộc **`"blocks_exploit" | "reduces_likelihood" | "partial_mitigation" | "none"`**.
     - `"searched_paths"`: mảng đường dẫn file cấu hình/IaC đã kiểm tra.
     - `"evidence_ids"`: mảng mã bằng chứng `["ev_001"]`.
2. **Hai Luật Cứng (`validator` & `finalize_v3_phase3` chặn tự động)**:
   - Nếu `"status": "confirmed"`, bắt buộc phải có `"evidence_ids"` khác rỗng (`["ev_001"]`) hoặc được xác nhận trong `runtime_environment_facts.json` qua `ingest_runtime_facts`.
   - Nếu `"status": "hypothesis"`, trường `"mitigation_effect"` **BẮT BUỘC chỉ được là `"reduces_likelihood"` hoặc `"none"`** (TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `"blocks_exploit"`). Nếu chưa có bằng chứng xác nhận kiểm soát hạ tầng đó đang bật và chặn đúng vector tấn công, không được dùng nó để xóa bỏ rủi ro!

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`)

```powershell
# (Tùy chọn) Nạp thông tin hạ tầng thực tế do đội vận hành cung cấp
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ingest_runtime_facts <repo_name> /tmp/runtime_facts.json

# Đọc các file cấu hình Ingress, Helm, Terraform, Kong, Docker Compose nếu có trong repo
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> src/ocpp_controller.py 1 120 --skill beyond_code_control_mapper

# Lưu kết quả đánh giá Beyond-Code Controls (đối chiếu AI-skills/schemas/v3/beyond_code_control_mapper.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> beyond_code_control_mapper /tmp/beyond_code_control_mapper_<repo_name>.json
```

```json
{
  "status": "ok",
  "result": {
    "beyond_code_controls": [
      {
        "control_id": "CTRL-WAF-01",
        "chain_id": "CHAIN-OCPP-01",
        "layer": "edge_waf",
        "control": "Cloudflare WAF managed ruleset",
        "exposure_tier": "internet_public_behind_cloudflare_waf",
        "status": "confirmed",
        "mitigation_effect": "none",
        "searched_paths": [
          "src/ocpp_controller.py"
        ],
        "evidence_ids": [
          "ev_001"
        ],
        "notes": "Cloudflare WAF inspects HTTP signatures but does not validate BOLA session ownership in application state"
      },
      {
        "control_id": "CTRL-OT-INTERLOCK-01",
        "chain_id": "CHAIN-OCPP-01",
        "layer": "ot_hardware_interlock",
        "control": "EVSE hardware contactor plug-present interlock",
        "exposure_tier": "internet_public_behind_cloudflare_waf",
        "status": "hypothesis",
        "mitigation_effect": "reduces_likelihood",
        "searched_paths": [
          "src/ocpp_controller.py"
        ],
        "evidence_ids": [
          "ev_001"
        ],
        "notes": "Physical EVSE firmware interlock is outside software repository and requires operator verification"
      }
    ],
    "summary": "Mapped edge WAF (confirmed, mitigation_effect=none for BOLA) and EVSE hardware interlock (hypothesis, reduces_likelihood) for CHAIN-OCPP-01."
  }
}
```
