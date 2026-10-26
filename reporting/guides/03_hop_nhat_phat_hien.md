# 03 — Hợp nhất phát hiện (bước 4.3)

Mục tiêu: biến hàng trăm mục gốc (threat, quan sát kiến trúc, mismatch, chuỗi) thành **một danh sách phát hiện cuối cùng `F-xx`** gọn, không trùng, truy vết được. Mỗi mục gốc bắt buộc (★) phải đi vào đúng một F hoặc vào danh sách loại trừ, kèm lý do.

## Quy tắc gom nhóm

**Gộp vào một F khi** các mục có *cùng nguyên nhân gốc* **và** *cùng hướng sửa*, kể cả khi nằm ở nhiều repo. Ví dụ: 15 service đều tin header danh tính không ký, sửa chung bằng token nội bộ có chữ ký → một F, `services` liệt kê đủ 15.

**Tách thành F riêng khi** khác cách khai thác, khác tài sản bị hại, hoặc khác cách sửa, kể cả khi cùng repo hoặc cùng CWE. Ví dụ: "callback thanh toán không kiểm chữ ký" và "tính tiền nhiều hoá đơn chỉ lấy hoá đơn đầu" cùng nằm ở `vfip-payment` nhưng là hai F.

**Độ mịn mục tiêu:** project lớn (>15 repo) khoảng 15–40 F; project nhỏ 5–15 F. Nếu một F gom quá 25 mục gốc thuộc nhiều loại lỗi khác nhau, gần như chắc chắn nó đang trộn hai vấn đề.

**Một chuỗi P3 thường ứng với một F**, với các mismatch/threat liên quan làm nguồn phụ. Các mục ở cột *Dựng từ* của chuỗi (trong `03_findings_index.md`) nên gom cùng F với chuỗi. Nguyên nhân gốc P3 (`RC-x`) ghi vào trường `root_causes` của F, không phải `source_ids`.

**Kết quả công cụ (`_ext`)** là SAST/secret/SCA chưa xác minh. Với mỗi mục ★:
- cùng gốc với một F đã có (ví dụ SAST báo IDOR đúng endpoint mà F-03 đã nói) → gán vào F đó; nó làm tăng độ phủ chứ không tự nâng độ tin cậy;
- lỗi mới, có báo cáo xác minh thủ công khẳng định → tạo F mới, dẫn thêm SID `ext:<báo cáo xác minh>#<ID>`;
- kết quả thuộc repo/service **ngoài phạm vi** project (không có thư mục trong `documents/`) → `ngoai_pham_vi`, không phải `bac_bo`, dù báo cáo xác minh nói gì; ghi việc chuyển cho team phụ trách vào `gaps`;
- dương tính giả → `excluded` lý do `bac_bo`, `note` **phải dẫn báo cáo xác minh** (file trong `reports/` hoặc `VERIFY-*.md`); `check` chặn nếu không có. Nếu chính báo cáo xác minh tự nhận là "kiểm nhanh" hoặc còn mục mở, thì ghi giới hạn đó và các mục mở vào `gaps`;
- secret (gitleaks/trivy) luôn bắt buộc: hoặc thành F (secret trong repo), hoặc loại trừ có dẫn chứng (secret giả lập/test, đã thu hồi).

## Độ tin cậy (`confidence`): cổng fail-closed

| Giá trị | Khi nào | `check` yêu cầu |
|---|---|---|
| `confirmed` | Lỗi đã kiểm chứng **và** không còn mắt xích khai thác nào chưa rõ | ≥1 nguồn `xac_nhan`; không nguồn nào thuộc chuỗi P3 `hypothesized`/`refuted` (trừ khi có `override_note`) |
| `evidence_backed` | Lỗi có thật trong mã/cấu hình nhưng khai thác phụ thuộc điều kiện runtime/cấu hình chưa kiểm (gateway scope, NetworkPolicy, giá trị production…), hoặc P2 xác nhận nhưng chưa qua kiểm toán | ≥1 nguồn `xac_nhan`/`xac_nhan_mot_phan`/`chua_kiem_toan`/`co_bang_chung` |
| `hypothesis` | Chỉ có giả thuyết (kể cả chỉ có kết quả công cụ chưa xác minh) | — |

Nếu F gắn `confirmed` nhưng chuỗi P3 dựng từ chính các nguồn đó chỉ `hypothesized`, `check` sẽ **báo lỗi**. Thường câu trả lời đúng là `evidence_backed`, và `risk_rationale` nói rõ phần nào đã xác nhận, phần nào chưa.

## Mức rủi ro và ưu tiên

Ghi tạm `risk`/`priority` theo nguồn ở bước này; bước 4.4 sẽ chỉnh lại theo tác động nghiệp vụ. Không sao chép máy móc severity của phase trước. Cách chỉnh ở `04_tac_dong_nghiep_vu.md`.

## Loại trừ

Ghi `excluded` (trong `work/map/<repo>.json` hoặc `consolidation.json`) với `reason`:
- `bac_bo`: bằng chứng phản bác. Nếu phase trước **chưa** bác bỏ mục này thì `note` phải nêu phản chứng cụ thể (SID/ev/file), ≥40 ký tự.
- `trung_lap`: cùng một vấn đề đã có ở F khác; bắt buộc `into: "F-xx"`. Thông thường nên dùng `"to": "F-xx"` thay vì loại trừ.
- `ngoai_pham_vi`: thuộc hệ thống/repo ngoài phạm vi đánh giá.
- `khong_phai_lo_hong`: thực hành tốt, ghi nhận, hoặc mô tả kiến trúc không phải điểm yếu.
- `muc_thap`: đánh giá lại ở mức thấp (ví dụ repo rỗng, chỉ chạy dev). `note` nói vì sao.

Luật cứng cho loại trừ mục bắt buộc (★), do `check` thực thi:
- `note` ≥25 ký tự, nói cụ thể vì sao (trừ `trung_lap`, vốn đã có `into`);
- **không** được dùng `muc_thap` cho mục critical. Gom nó vào F (có thể với mức thấp hơn, kèm `risk_rationale`), hoặc dùng lý do khác có bằng chứng;
- `muc_thap` cho mục high cần `note` ≥40 ký tự nêu vì sao tác động hoặc khả năng khai thác thấp;
- mọi loại trừ đều hiện ở Phụ lục B, được đếm theo lý do ở tóm tắt điều hành và ở mục 7. Tỷ lệ loại trừ >30% thì `check` cảnh báo.

Mục không bắt buộc (không có ★) mà không gom thì renderer tự đưa vào Phụ lục C; các mục critical/high trong đó được liệt kê từng dòng. Mục `bac_bo` của phase trước tự vào Phụ lục B.

## F quá lớn

`check` cảnh báo khi một F có >25 nguồn hoặc >2 nguyên nhân gốc, và **báo lỗi** khi >50 nguồn mà không có `scope_note`. Một điểm yếu hệ thống thật (ví dụ 20 service cùng tin header danh tính không ký, sửa chung một cách) được phép lớn, nhưng phải ghi `scope_note` giải thích vì sao đây là MỘT vấn đề với MỘT cách sửa.

## Quy trình theo lô (bắt buộc với model local)

**4.3a. Dựng khung F từ mức hệ thống.** Đọc `inputs/03_findings_index.md` và `inputs/findings/_analysis.md`, `_system.md`. Tạo `work/consolidation.json` với các F đầu tiên từ: mỗi chuỗi P3, mỗi khuôn mẫu lặp/nguyên nhân gốc, mỗi mismatch hệ thống `SYS-CM`. Thường được 8–20 F. Ghi luôn `work/map/_analysis.json` và `work/map/_system.json`.

**4.3b. Chế độ lô** (mỗi repo, và lô `_ext` nếu `00_manifest.md` có báo cáo công cụ). Một lô chỉ ghi `work/map/<lô>.json`, không sửa `consolidation.json`. Vì vậy:
- công cụ có subagent: phiên chính giao mỗi lô cho một subagent (`general-purpose`, `model: sonnet`), nhiều lô chạy song song được; prompt chỉ gồm tên lô và đường dẫn SKILL.md;
- công cụ không có subagent: làm tuần tự từng lô; khi context gần đầy thì mở phiên mới, chạy `catalog` rồi làm tiếp.

Vấn đề mới mà chưa có F thì ghi `"to": "NEW:<slug>"` kèm `"proposal": {"title", "core_issue", "root_causes", "services"}`. Phiên chính hợp nhất ở 4.3c bằng `report.py promote NEW:<slug> F-xx`.

Lặp lại cho mỗi lô:
1. `python3 AI-skills/reporting/report.py catalog`: xem danh mục F hiện có và repo kế tiếp.
2. Đọc `inputs/findings/<repo>.md`. Chỉ xử lý dòng ★ là bắt buộc; dòng không ★ mức high thì nên xử lý.
3. Mỗi dòng: gán vào F có sẵn (cùng gốc, cùng cách sửa), tạo F mới trong `consolidation.json`, hoặc loại trừ.
4. Cần hiểu kỹ một mục thì mở file ở cột *Nguồn*, **đọc theo đoạn** quanh ID đó; không đọc cả file lớn.
5. Ghi `work/map/<repo>.json`, rồi chuyển repo kế tiếp. Không giữ kết quả trong đầu qua nhiều repo.

**4.3c. Rà lại danh mục.** Chạy `catalog`. Gộp các F trùng ý; tách F trộn nhiều vấn đề; đặt lại tiêu đề cho rõ, theo dạng *điểm yếu + hậu quả*. Đổi ID F thì phải sửa cả các file map. Sau đó chạy `check --stage findings` tới khi đạt.

## Định dạng

`work/map/<repo>.json` (xem `templates/map.example.json`):
```json
{"repo": "vfip-payment", "items": [
  {"sid": "vfip-payment:CM-1", "to": "F-03"},
  {"sid": "vfip-payment:TM-PAY-01", "to": "F-03"},
  {"sid": "vfip-payment:AR-07", "to": "excluded", "reason": "khong_phai_lo_hong", "note": "Mô tả cơ chế retry, không phải điểm yếu"}
]}
```

F trong `work/consolidation.json` (xem `templates/consolidation.example.json`). Trường bắt buộc ở bước này: `id`, `title`, `services`, `domains`, `source_ids` (2–6 nguồn **chính**, mạnh nhất, những nguồn khác nằm trong map), `root_causes`, `core_issue` (1–3 câu, nói *cái gì sai ở đâu*, không kể lại khai thác), `risk`, `confidence`, `priority`, `risk_rationale`, `remediation`, `validation` (nếu chưa `confirmed`).

## Không được

- Đếm một mục gốc hai lần (một SID chỉ thuộc một F hoặc một dòng loại trừ).
- Nâng giả thuyết thành xác nhận vì "nghe hợp lý" hoặc vì nhiều repo cùng có.
- Bác bỏ một mục chỉ vì không thấy nó ở phase khác: thiếu bằng chứng không phải là bằng chứng phản bác.
- Chép nguyên mô tả dài của nguồn vào `core_issue`.
