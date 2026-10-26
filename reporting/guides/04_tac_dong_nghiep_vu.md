# 04 — Tác động nghiệp vụ cho từng phát hiện (bước 4.4)

Mỗi F phải trả lời: **lỗi này làm hỏng việc kinh doanh nào, theo cách nào, nặng tới đâu, dựa trên cơ sở gì.** Câu kiểu "có thể gây tổn thất tài chính và ảnh hưởng uy tín" không đạt.

## Chuỗi tác động: bốn mắt xích

```
Điểm yếu kỹ thuật → Kịch bản lạm dụng (ai, với điều kiện gì) → Năng lực nghiệp vụ bị ảnh hưởng → Hậu quả nghiệp vụ
```

Ghi vào `business_impact` của F:

| Trường | Viết gì | Ví dụ |
|---|---|---|
| `capability` | Năng lực/quy trình nghiệp vụ bị ảnh hưởng, dùng ngôn ngữ của nghiệp vụ | "Thu tiền thuê pin và đối soát công nợ với SAP" |
| `scenario` | Ai làm gì, cần gì: 1 câu | "Bên có client credential gửi callback giả `success=true` cho hoá đơn bất kỳ" |
| `consequence` | Hậu quả cụ thể với doanh nghiệp: 1–2 câu | "Hoá đơn bị gạch nợ mà không có tiền vào; SAP ghi nhận doanh thu giả, chỉ phát hiện được khi đối soát thủ công" |
| `dimensions` | 1–3 khía cạnh chính (bảng dưới) | `["tai_chinh", "toan_ven_nghiep_vu"]` |
| `level` | Mức tác động nghiệp vụ (rubric dưới), **chưa** tính khả năng xảy ra | `critical` |
| `blast_radius` | `component` / `service` / `domain` / `cross_domain` / `platform` | `cross_domain` (Payment → SAP) |
| `basis` | Cơ sở của nhận định: tài liệu nào, SID nào, hay suy luận | "BASV `vfip-payment:CM-1` business_impact + recon `01_repo_profile` (Criticality: high)" |
| `conditions` | Điều kiện để hậu quả xảy ra, hoặc điều chưa biết. Bắt buộc nếu chưa `confirmed` | "Route callback nằm trong scope client mà kẻ tấn công có (chưa kiểm cấu hình gateway)" |

## Khía cạnh (`dimensions`)

| Mã | Khía cạnh | Câu hỏi gợi ý |
|---|---|---|
| `tai_chinh` | Tài chính | Có thất thoát tiền, gian lận giá/khuyến mãi, sai doanh thu không? |
| `du_lieu_ca_nhan` | Dữ liệu cá nhân/khách hàng | Lộ/sửa dữ liệu của ai, bao nhiêu, loại gì (PII, vị trí, thanh toán)? |
| `toan_ven_nghiep_vu` | Toàn vẹn giao dịch/nghiệp vụ | Trạng thái nghiệp vụ có bị làm sai (phê duyệt, hoá đơn, hồ sơ, báo cáo)? Có vượt maker-checker? |
| `van_hanh` | Vận hành/khả dụng | Dịch vụ cốt lõi có ngừng, chậm, phải xử lý tay không? |
| `an_toan_vat_ly` | An toàn vật lý/thiết bị | Có điều khiển được xe/thiết bị/tủ, ảnh hưởng người dùng ngoài đời thực không? |
| `kiem_soat_he_thong` | Mất quyền kiểm soát hệ thống | Có chiếm quyền quản trị, khoá bí mật, cấu hình toàn cục không? |
| `tuan_thu` | Tuân thủ/hợp đồng | Có chạm nghĩa vụ pháp lý/hợp đồng mà **tài liệu dự án** hoặc `SOUL.md` nêu tên không? |
| `uy_tin` | Uy tín/niềm tin | Chỉ dùng khi có cơ chế cụ thể (sự cố khách hàng nhìn thấy, lộ dữ liệu hàng loạt); không dùng làm khía cạnh mặc định |

## Rubric mức tác động nghiệp vụ (`level`)

Mức tác động chỉ đo **hậu quả nếu khai thác xảy ra**. Không tính ai làm được, khó hay dễ, cần quyền gì: đó là việc của Phase Risk (`/phase-risk-assessment`). Nếu tính ở đây thì khả năng khai thác bị trừ hai lần.

| Mức | Dấu hiệu về hậu quả (chỉ cần một) |
|---|---|
| `critical` | Thất thoát tài chính trực tiếp không giới hạn theo giao dịch (toàn bộ hoá đơn, toàn bộ ví…); lộ hoặc sửa dữ liệu cá nhân **hàng loạt**; chiếm quyền quản trị/bí mật toàn nền tảng; điều khiển thiết bị vật lý của người khác; vô hiệu kiểm soát tài chính (đối soát, maker-checker) |
| `high` | Gian lận/thất thoát theo từng giao dịch; dữ liệu của khách hàng khác theo từng bản ghi; làm sai trạng thái nghiệp vụ quan trọng; gián đoạn dịch vụ cốt lõi |
| `medium` | Ảnh hưởng nội bộ; lộ thông tin kỹ thuật làm bàn đạp; gián đoạn chức năng phụ |
| `low` | Ảnh hưởng hạn chế; thiếu lớp phòng thủ chiều sâu khi lớp chính vẫn còn |

`scenario` và `conditions` mô tả **hậu quả xảy ra như thế nào về nghiệp vụ**. Các điều kiện khai thác (ai, credential nào, chạm tới được không) để Phase Risk đánh giá từng mắt xích.

## Mức rủi ro (`risk`) và ưu tiên (`priority`) ở bước này

Ở 4.4 ghi `risk` = mức tác động và `priority` theo bảng dưới, **chỉ để sắp thứ tự làm việc**. Mức cuối do Phase Risk suy ra:
- khai thác được → bằng mức tác động;
- không khai thác được → thấp;
- chưa rõ → mức tác động, *tạm tính*, ưu tiên hạ một bậc;
- tổ hợp kéo ưu tiên lên.

| `risk` (= tác động) | critical | high | medium | low |
|---|---|---|---|---|
| `priority` tạm | P0 | P1 | P2 | P3 |

`risk_rationale` (1–2 câu) nói vì sao ra mức tác động này. Báo cáo cuối thay nó bằng kết luận của Phase Risk, kèm lập luận.

## Lan rộng xuyên service

Dùng `work/architecture.json` (`shared_components`, `domains`) và `inputs/02_edges.md`:
- F ở gateway, IdP, config, DB/cache dùng chung thường có `blast_radius` là `platform` hoặc `cross_domain`.
- Ghi `cross_domain` chỉ khi có **cạnh** hoặc **thành phần dùng chung** nối các cụm. Nêu cạnh đó trong `consequence` hoặc `conditions`.
- Một F làm yếu kiểm soát mà F khác dựa vào (ví dụ gateway thiếu kiểm scope làm F "callback giả" khai thác được) thì nói rõ quan hệ trong `risk_rationale`.

## Cấm

- Bịa số tiền, số khách hàng, số giao dịch. Chỉ nêu con số khi tài liệu nghiệp vụ cung cấp, và dẫn nguồn trong `basis`.
- Bịa điều luật hay số hiệu văn bản. Chỉ nêu quy định khi tài liệu dự án hoặc `SOUL.md` nêu tên; khi nêu thì ghi "cần pháp chế xác nhận mức áp dụng".
- Viết hậu quả như thể đã xảy ra. Dùng thể điều kiện: "cho phép…", "dẫn tới…", "nếu… thì…".
- Dùng cùng một câu tác động cho nhiều F. Mỗi F có năng lực nghiệp vụ và hậu quả riêng.

## Ví dụ

Không đạt:
> `consequence`: "Có thể gây thiệt hại tài chính và ảnh hưởng uy tín công ty."

Đạt (ví dụ minh hoạ, không phải kết luận của dự án nào):
> `capability`: "Đăng nhập và quản lý phiên của khách hàng trên app"
> `scenario`: "Người cùng mạng Wi-Fi công cộng chặn được token vì app chấp nhận mọi chứng chỉ TLS"
> `consequence`: "Chiếm phiên khách hàng: xem vị trí xe, lịch sử hành trình, và gửi lệnh khoá/mở xe thay chủ xe"
> `dimensions`: `["du_lieu_ca_nhan", "an_toan_vat_ly"]` · `level`: `critical` · `blast_radius`: `domain`
> `basis`: "P2 `E-Scooter-Android:CM-1`; recon `01_repo_profile` (app điều khiển xe)"
> `conditions`: "Bản build production dùng cùng OkHttpClient trust-all (chưa đối chiếu bản phát hành trên store)"

## `check --stage impact` chặn gì

- `capability` <10, `scenario` <25, hoặc `consequence` <40 ký tự.
- `consequence` chung chung, tức chứa cụm như "thiệt hại tài chính", "ảnh hưởng uy tín", "rủi ro bảo mật" mà không có chi tiết (<110 ký tự).
- Hai F dùng **cùng một câu** `consequence`. Câu gần trùng chỉ bị cảnh báo.
- `basis` không dẫn tới SID, RC, file hay tài liệu, và cũng không ghi rõ "Suy luận từ recon".
- `uy_tin` là khía cạnh duy nhất.

Kiểm tự động chỉ bắt được lỗi hình thức. Việc tác động có **đúng** hay không vẫn phải rà theo checklist ở bước 4.6.

Chạy `python3 AI-skills/reporting/report.py check --stage impact` tới khi đạt.
