# 02 — Tổng hợp kiến trúc toàn hệ thống (bước 4.2)

Mục tiêu: **một** bức tranh kiến trúc cho cả project, không phải mô tả lại kiến trúc từng repo. Mỗi repo là một service; nhiều service tạo thành một **cụm nghiệp vụ**; một project có thể nối với cụm của project khác. Người đọc phải trả lời được: *service nào làm gì, thuộc cụm nào, nói chuyện với ai bằng cách nào, kiểm soát nằm ở đâu, và một service bị chiếm thì cái gì đổ theo.*

## Đầu vào (đọc theo thứ tự, dừng khi đủ)

1. `inputs/01_services.md`: một dòng mỗi repo.
2. `inputs/02_edges.md`: danh sách kề giữa service.
3. `inputs/03_findings_index.md`: chỉ đọc phần nguyên nhân gốc, khuôn mẫu lặp và rủi ro hệ thống, vì đó là điểm yếu kiến trúc đã được kiểm.
4. `documents/_system/03_cross_repo_review.md` và `_system/diagrams/*.mmd`: đọc theo đoạn.
5. Chỉ với service trọng yếu (critical/high, hoặc là gateway/IdP/config/DB dùng chung): `documents/<repo>/08_architecture_review.md`, `06_dataflow.md`.
6. `inputs/04_related_projects.md` (nếu có): liên kết sang cụm nghiệp vụ khác.
7. Cần chi tiết cạnh thì xem `inputs/02_edges_detail.md`; cần chi tiết service thì xem `inputs/01_services_detail.md`.

## Đầu ra

### `documents/_report/work/architecture.json`

```json
{
  "project": {"name": "Tên hiển thị của hệ thống", "summary": "1–2 câu: hệ thống làm gì, cho ai"},
  "domains": [
    {"id": "D1", "name": "Thanh toán & công nợ", "description": "Thu tiền đổi pin/sạc/thuê pin, đối soát SAP",
     "criticality": "critical", "services": ["vfip-payment", "vfip-charging-service"]}
  ],
  "shared_components": [
    {"name": "api-gateway", "type": "gateway|idp|config|database|cache|queue|storage|ci_cd|other",
     "used_by": ["D1", "D2"], "risk_note": "Điểm xác thực duy nhất; backend tin header do gateway gắn"}
  ],
  "related_projects": [
    {"name": "vsf-qtvhcn (BSS)", "relationship": "Escooter gọi BSS để đổi pin", "status": "documented|inferred|unknown", "evidence": "SID hoặc file"}
  ]
}
```

Quy tắc `domains`:
- Cụm là **năng lực nghiệp vụ** (thanh toán, quản lý thiết bị, định danh khách hàng…), không phải tầng kỹ thuật. Ngoại lệ được phép: một cụm `Nền tảng & hạ tầng` (gateway, config, CI/CD, IaC, script DB) và một cụm `Kênh truy cập` (app di động, portal, công cụ máy trạm).
- **Mọi** repo trong `inputs/01_services.md` thuộc đúng một cụm, kể cả repo rỗng. `check` sẽ báo lỗi nếu sót.
- Project nhiều repo thường có 4–9 cụm. Project 1–3 repo có thể chỉ 1–3 cụm.
- Căn cứ chia cụm (theo thứ tự): tài liệu nghiệp vụ → `business_workflows.participating_repos` của BASV (các repo cùng một luồng) → mục đích/năng lực trong recon → cạnh giao tiếp. Không chia cụm chỉ dựa vào tên repo.

### `documents/_report/work/architecture.md`

Theo khung `AI-skills/reporting/templates/architecture.template.md`. Heading bắt đầu từ `###` vì renderer đặt nó dưới `## 2`. Bắt buộc có các mục:

| Mục | Nội dung | Độ dài gợi ý |
|---|---|---|
| `### 2.1 Cụm nghiệp vụ và service` | Bảng: cụm → service → vai trò → dữ liệu nhạy cảm → trọng yếu | 1 bảng |
| `### 2.2 Sơ đồ kiến trúc tổng thể` | Một sơ đồ ```mermaid```: subgraph theo cụm + ranh giới tin cậy (Internet / DMZ-gateway / cluster nội bộ / bên thứ ba). Cạnh liền `-->` = có bằng chứng; cạnh đứt `-.->` = giả thuyết. Không vẽ quá ~30 node: gom service phụ vào node cụm | 1 sơ đồ |
| `### 2.3 Luồng nghiệp vụ trọng yếu xuyên service` | 3–6 luồng quan trọng nhất (tiền, định danh, điều khiển thiết bị, dữ liệu cá nhân…). Mỗi luồng: chuỗi service, kiểm soát được kỳ vọng ở đâu, thực tế ở đâu, mắt xích yếu (dẫn SID/RC; tới bước 4.5 đổi sang F-xx) | mỗi luồng 3–6 dòng |
| `### 2.4 Mô hình tin cậy và điểm thực thi kiểm soát` | Xác thực ở đâu, phân quyền ở đâu, danh tính truyền giữa service thế nào, service-to-service có xác thực không, phân đoạn mạng. Bảng: ranh giới, kiểm soát kỳ vọng, kiểm soát quan sát được, trạng thái (confirmed/hypothesis) | 1 bảng + ≤5 câu |
| `### 2.5 Thành phần dùng chung, liên kết ngoài và ảnh hưởng dây chuyền` | DB/cache/config/gateway/IdP/queue dùng chung; bên thứ ba; project liên quan. Với mỗi thành phần dùng chung: *nếu nó bị chiếm hoặc sai thì cụm nào bị ảnh hưởng*. Đây là phần trả lời "một service bị compromise ảnh hưởng service nào" | bảng + ví dụ dây chuyền |
| `### 2.6 Đánh giá kiến trúc` | Điểm mạnh thật (có bằng chứng, kể cả điều đã bác bỏ được giả thuyết xấu); điểm yếu mang tính hệ thống (không phải lỗi lập trình lẻ); giả định kiến trúc chưa được thực thi; trade-off | gạch đầu dòng |

## Kỷ luật

- Mỗi cạnh, mỗi kiểm soát phải gắn nhãn **[có bằng chứng]** hoặc **[giả thuyết]**. Cạnh trong `02_edges.md` có trạng thái `hypothesis` thì vẽ nét đứt.
- Điều không kiểm được thì ghi "chưa xác định" kèm điều cần kiểm. Không bịa NetworkPolicy, mTLS hay WAF.
- Không suy cụm nghiệp vụ hay quan hệ giữa project chỉ từ tên. `inputs/04_related_projects.md` chỉ là *gợi ý theo chuỗi ký tự*; phải có cạnh/luồng hoặc tài liệu thì mới ghi `status: documented|inferred`.
- Không lặp lại danh sách finding ở đây. Kiến trúc nói về **cấu trúc và kiểm soát**; finding nằm ở mục 4.
- Sau bước 4.3, quay lại 2.3/2.5/2.6 để thay SID/RC bằng `F-xx` (bước 4.5).

Chạy `python AI-skills/reporting/report.py check --stage architecture` tới khi đạt.
