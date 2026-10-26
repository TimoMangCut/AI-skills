---
name: phase-4-independent-review
description: >-
  Phase 4.6 — Rà soát độc lập bản nháp Báo cáo tổng hợp trong một context mới (không phải phiên đã viết báo cáo) — đối chiếu từng phát hiện với nguồn gốc, độ tin cậy, tác động nghiệp vụ, trạng thái rủi ro của Phase Risk, loại trừ và kiến trúc; ghi work/review.json (hoặc work/review/LÔ.json khi chia lô), không sửa báo cáo.
---

# `phase-4-independent-review` (Phase 4.6)

Người rà soát **không được là phiên đã gom và viết báo cáo**. Đây là cùng nguyên tắc với kiểm toán bằng chứng ở Phase 1–3: tác giả tự kiểm thì không bắt được lỗi của chính mình.

## Prompt kích hoạt
```text
/phase-4-independent-review Rà soát độc lập documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md (bản nháp) theo checklist; đối chiếu nguồn, không tin lời tác giả; ghi documents/_report/work/review.json; không sửa báo cáo hay file work/ khác.
```

## Chạy ở đâu
- **Công cụ có subagent (Claude Code, Antigravity):** phiên chính giao việc qua Agent tool (Antigravity: `invoke_subagent`, `TypeName: "self"`, `Workspace: "inherit"`) cho subagent `general-purpose`, `model: sonnet`. Prompt **chỉ gồm**: "Chạy theo `.agents/skills/phase-4-independent-review/SKILL.md` cho project tại thư mục hiện tại; `context: fresh_subagent`". Không chép kết luận, không dặn "hãy xác nhận X".
- **Công cụ không có subagent (model local):** mở **cuộc hội thoại mới**, chỉ gọi skill này, rồi ghi `"context": "new_session"`. Không dán lại nội dung phiên cũ.

## Quyền truy cập
- **Được đọc (kể cả đọc sâu):** bản nháp `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md`; `documents/_report/inputs/`; **toàn bộ `documents/`** (`<repo>/0x_*`, `<repo>/basv/`, `_system/`, `_analysis/`); `reports/`, `reviews/`, `specs/` và tài liệu nghiệp vụ; `AI-skills/reporting/`. Đây là báo cáo của các phase trước, **không phải mã nguồn**.
- **Mã nguồn** là thư mục các repo ở gốc project (ví dụ `vfip-payment/`, `domain-bss/…`). Không Read/Grep/Glob vào đó.
- **Ghi:** **chỉ** `documents/_report/work/review.json`, hoặc `documents/_report/work/review/<tên lô>.json` khi được giao một lô (không ghi đè lô khác). Không sửa `consolidation.json`, `architecture.*`, `map/`.

## Đọc tới đâu
- Bắt đầu từ `inputs/findings/<repo>.md` (bản rút gọn). Mỗi khi kết luận "nguồn không nói vậy", phải mở **file gốc** ở cột *Nguồn* (`09_findings.md`, `basv/18_*.md`, `_analysis/chains/…`) để chắc. Bản rút gọn bị cắt ở ~300 ký tự.
- Nếu file gốc mâu thuẫn với chính `inputs/` (bản rút gọn sai hoặc thiếu) thì ghi `target: "report"`, `check: "input"`. Đó là lỗi của dữ liệu đầu vào, không phải của tác giả.
- Báo cáo có ≤10 F: rà một lượt rồi ghi một lần. >10 F: mỗi lượt khoảng 5 F, ghi `review.json` sau mỗi lượt (giữ các mục đã có, chỉ thêm).
- Được giao **một lô** (prompt có "lô `<tên>`: F-…"): chỉ rà các F trong lô; lô có chữ "toàn báo cáo" thì rà thêm các target `report`, `architecture`, `summary`, `roadmap`. Ghi `work/review/<tên lô>.json` cùng định dạng; `check` gộp mọi lô và đòi mọi F có ít nhất một mục.

## Checklist cho từng phát hiện `F-xx`
Với mỗi F, mở các dòng nguồn chính trong `inputs/findings/<repo>.md` (cột *Tác động (nguồn)*, *Xử lý gốc*, *Chuỗi P3*), rồi hỏi:
1. **Vấn đề** có đúng với nguồn không? Có nói quá nguồn không?
2. **Độ tin cậy** có vượt trạng thái của nguồn không? Ví dụ: `confirmed` mà nguồn chỉ là "P2 xác nhận – chưa qua kiểm toán", hoặc thuộc chuỗi `hypothesized`.
3. **Tác động nghiệp vụ** có cụ thể không: năng lực nào, ai, hậu quả gì? `basis` có thực sự chứa điều được nói không? Có con số hoặc điều luật nào không có nguồn không?
4. **Mức rủi ro/ưu tiên** là do Phase Risk suy ra, không rà theo ma trận. Hỏi: thẻ phát hiện có nói đúng trạng thái (khai thác được / tạm tính / không) như `DANH_GIA_RUI_RO.md` không? Lộ trình có đặt hành động ở đúng ưu tiên của F không? Thấy lập luận khai thác sai thì ghi vấn đề với target F đó, đề nghị chạy lại Phase Risk R.4 cho F.
5. **Khắc phục** có sửa tại gốc không, hay chỉ chữa triệu chứng (đối chiếu `remediation_that_only_treats_symptom` của Phase 3)?
6. F này có đang trộn hai vấn đề không? Hoặc có trùng với F khác không?

## Checklist toàn báo cáo (target `report`, `architecture`, `summary`, `roadmap`)
7. **Phụ lục B:** đọc mọi dòng `muc_thap`, `khong_phai_lo_hong`, `bac_bo` mới ở Phase 4. Lý do có đủ để loại một mục bắt buộc không?
8. **Phụ lục C:** trong các mục critical/high chưa gom, có mục nào lẽ ra phải là một F không?
9. **Kiến trúc:** có trả lời được "thành phần dùng chung X bị chiếm thì cụm nào bị ảnh hưởng" không? Cạnh và kiểm soát có gắn nhãn bằng chứng không?
10. **Tóm tắt điều hành** có nói đúng điểm yếu hệ thống số 1 không? Có câu nào mạnh hơn nội dung mục 4 không?

## Đầu ra: `documents/_report/work/review.json`
```json
{
  "context": "fresh_subagent",
  "reviewer_note": "Ngắn: đã rà gì, giới hạn của lượt rà",
  "items": [
    {"target": "F-01", "verdict": "ok", "check": "1-6", "note": "Khớp CM-1 và C2; độ tin cậy evidence_backed hợp lý"},
    {"target": "F-03", "verdict": "issue", "severity": "nang", "check": "2", "note": "Gắn confirmed nhưng nguồn chính là chua_kiem_toan", "resolution": ""},
    {"target": "report", "verdict": "issue", "severity": "vua", "check": "7", "note": "vfip-x:TM-04 (high) bị muc_thap với lý do không nêu khả năng khai thác", "resolution": ""}
  ]
}
```
Quy ước:
- `target`: `F-xx`, hoặc một trong `report` / `architecture` / `summary` / `roadmap`. Một target **được lặp** nhiều mục, mỗi mục một vấn đề.
- `verdict`: chỉ `ok` hoặc `issue`. Mọi F phải có ít nhất một mục; thiếu F nào thì `check` báo lỗi.
- `check`: số mục checklist ("2"), nhiều số ("1,3"), dải ("1-6"), hoặc `"input"` (lỗi dữ liệu đầu vào).
- `severity` (bắt buộc khi `issue`):
  - `nang`: làm sai kết luận chính, gồm độ tin cậy, mức rủi ro P0/P1, hậu quả nghiệp vụ, hoặc loại trừ một mục lẽ ra phải là F;
  - `vua`: làm lệch chi tiết nhưng không đổi ưu tiên;
  - `nhe`: câu chữ hoặc trình bày.
- `note`: nói **sai ở đâu**, dẫn SID hoặc file đã đối chiếu. `resolution` để trống: tác giả sẽ điền.
- Không chấm điểm cho đẹp. Không có vấn đề thì ghi `ok` kèm điều đã đối chiếu.

## Kết thúc
Trả về cho phiên chính (hoặc người dùng) tối đa 10 dòng: số F đã rà, số vấn đề, 3 vấn đề nặng nhất. Không chép lại cả `review.json`.
