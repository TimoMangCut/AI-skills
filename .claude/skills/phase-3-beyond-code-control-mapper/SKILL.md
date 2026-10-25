---
name: phase-3-beyond-code-control-mapper
description: >-
  Phase 3.2 — Đánh giá các lớp kiểm soát ngoài mã nguồn ứng dụng như Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC 10.x, AWS IoT Policy, mTLS và khóa liên động vật lý OT Interlock (beyond_code_control_mapper). Kích hoạt ở Bước 3.2 hoặc khi gọi /phase-3-beyond-code-control-mapper.
---

# Phase 3.2: Beyond-Code Infrastructure, Network & OT Control Mapper (`beyond_code_control_mapper`)

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

## 2. Quy tắc Kỷ luật về Kiểm soát Bù trừ Ngoài Code (`compensating_controls` — `ARCH-3H`, `DEPTH-4.4a`)

1. **Giữ nguyên `chain_id` từ Phase 2 & Khai báo Cấu trúc `yes` / `no` / `unknown` (`ARCH-3H`)**:
   - Mỗi bản ghi trong `assessments[]` phải giữ nguyên `chain_id` (và `finding_id`) từ Phase 2.
   - Mỗi kiểm soát trong `compensating_controls[]` phải khai báo rõ:
     - `present`: `"yes"` | `"no"` | `"unknown"`
     - `status`: `"observed"` | `"confirmed"` | `"hypothesis"` | `"absent"`
     - `mitigation_effect`: `"blocks_exploit"` | `"reduces_likelihood"` | `"none"`
     - `evidence_ids` và `searched_paths` (hoặc tham chiếu `runtime_facts.json` đã nạp qua `ingest_runtime_facts` — `DEPTH-4.4a`).
2. **Luật Cứng (`validator` chặn tự động)**:
   - Một kiểm soát đang ở trạng thái `status: "hypothesis"` hoặc `present: "unknown"` **TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `mitigation_effect: "blocks_exploit"`**. Nếu chưa có bằng chứng xác nhận kiểm soát hạ tầng đó đang bật và chặn đúng vector tấn công, không được dùng nó để xóa bỏ rủi ro!

---

## 3. Giao thức Thực thi CLI & Đầu ra JSON (`AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`)

```bash
# (Tùy chọn) Nạp thông tin hạ tầng thực tế do đội vận hành cung cấp
python -m localsec.manual_session ingest_runtime_facts <repo_name> .localsec/tmp/runtime_facts.json

# Đọc các file cấu hình Ingress, Helm, Terraform, Kong, Docker Compose nếu có trong repo
python -m localsec.manual_session read_file <repo_name> <path> 1 140 --skill beyond_code_control_mapper

# Lưu kết quả đánh giá Beyond-Code Controls (đối chiếu AI-skills/schemas/v3/beyond_code_control_mapper.schema.json)
python -m localsec.manual_session submit_skill <repo_name> beyond_code_control_mapper .localsec/tmp/beyond_code_control_mapper_<repo_name>.json
```

```json
{
  "assessments": [
    {
      "chain_id": "CHAIN-OCPP-STOP-01",
      "finding_id": "CHAIN-OCPP-STOP-01",
      "exposure_tier": "internet_public_behind_cloudflare_waf",
      "compensating_controls": [
        {
          "layer": "edge_waf",
          "control": "Cloudflare WAF managed ruleset",
          "present": "yes",
          "status": "observed",
          "mitigation_effect": "none",
          "searched_paths": ["deploy/ingress.yaml"],
          "evidence_ids": ["ev_..."]
        }
      ]
    }
  ]
}
```
