---
name: phase-4-report-writer
description: >-
  Phase 4.5 và 4.7 — Viết tóm tắt điều hành, lộ trình khắc phục gom theo nguyên nhân gốc, khoảng trống/rủi ro tồn dư, nối kiến trúc với F-xx, dựng bản nháp cho rà soát độc lập; sau rà soát thì xử lý từng vấn đề và dựng Báo cáo tổng hợp cuối bằng renderer tất định.
---

# `phase-4-report-writer` (Phase 4.5 và 4.7)

Hoàn thiện phần còn lại và dựng `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md`. Báo cáo do `python3 AI-skills/reporting/report.py render` dựng; không viết hay sửa tay file báo cáo cuối.

**Quyền truy cập:** theo mục "Quyền truy cập của Phase 4" trong `.agents/skills/phase-4-consolidated-report/SKILL.md`.

## Prompt kích hoạt
```text
/phase-4-report-writer Viết executive_summary, roadmap (gom theo nguyên nhân gốc, có tiêu chí nghiệm thu) và gaps; cập nhật F-xx trong architecture.md; render --draft cho rà soát độc lập; sau rà soát thì xử lý từng vấn đề, check --stage final, render.
```

## 4.5 — Viết và dựng bản nháp
Điều kiện: `python3 AI-skills/reporting/report.py check --stage risk` đạt và đã chạy `python3 AI-skills/reporting/report.py render-risk` (không `--draft`) — Phase Risk đã xong cả thách thức độc lập. Mức rủi ro và ưu tiên dùng trong tóm tắt và lộ trình lấy từ Phase Risk; rủi ro *tạm tính* (còn mắt xích chưa rõ) phải được nói rõ, và câu hỏi của nó đưa vào `gaps`. Đọc `AI-skills/reporting/guides/05_viet_bao_cao.md` (bắt buộc).
1. `python3 AI-skills/reporting/report.py catalog` để có danh mục F.
2. Thêm vào `documents/_report/work/consolidation.json`:
   - `roadmap`: gom theo nguyên nhân gốc/kiểm soát dùng chung; mọi F P0/P1 có hành động; mỗi hành động có `acceptance` kiểm được; ưu tiên của hành động **bằng ưu tiên cao nhất** của các F nó xử lý (ưu tiên F do Phase Risk suy ra, `check` chặn nếu thấp hơn). F *tạm tính* thì hành động đầu tiên là trả lời câu hỏi quyết định (mục 3.2 của báo cáo);
   - `gaps`: từ `inputs/00_manifest.md` (repo thiếu phase, thiếu tài liệu nghiệp vụ, artifact lệch nhau), `inputs/03_findings_index.md` (điểm chưa kiểm chứng P3, khoảng trống cấp hệ thống), `validation` của các F chưa `confirmed`; thêm 3 mục `area` bắt đầu bằng "Self-check:";
   - `executive_summary`: `posture` 3–5 câu + `key_messages` 3–7 ý, viết **sau cùng**.
3. Sửa `work/architecture.md` mục 2.3, 2.5, 2.6: thay SID/RC bằng F-xx.
4. `python3 AI-skills/reporting/report.py render --draft`: dựng bản nháp có dòng cảnh báo "BẢN NHÁP".
5. Chuyển sang 4.6. Người rà soát **không phải phiên này**: Claude Code dùng Agent tool (subagent `general-purpose`, `model: sonnet`), Antigravity dùng `invoke_subagent` (`TypeName: "self"`; subagent không thừa hưởng lịch sử hội thoại); công cụ không có subagent thì mở cuộc hội thoại mới và gọi `/phase-4-independent-review`. **Không** tự viết `review.json`.

## 4.7 — Xử lý rà soát và chốt
Điều kiện: đã có `documents/_report/work/review.json` do bước 4.6 tạo.
1. Đọc từng mục `verdict: issue`, bắt đầu từ `severity: nang`. Với mỗi mục:
   - đúng → sửa `consolidation.json` / `architecture.*` / `map/`, rồi ghi `resolution` bắt đầu bằng **`Đã sửa:`** và nói đã sửa gì;
   - không đồng ý → ghi `resolution` bắt đầu bằng **`Giữ nguyên:`**, dẫn SID/file/F làm bằng chứng (≥60 ký tự nếu vấn đề `nang`);
   - không được bỏ trống, không được xoá hay sửa `note`/`severity` của người rà soát. `check` kiểm định dạng này, và mục 7 của báo cáo đếm số vấn đề đã sửa và số vấn đề giữ nguyên.
2. Sửa xong thì chạy `python3 AI-skills/reporting/report.py review-ack` (ghi phiên bản của các F vừa "Đã sửa:") rồi chạy lại `check --stage risk`, vì sửa có thể làm hỏng cổng khác. F nào đổi sau rà soát mà không có "Đã sửa:" (hoặc đổi tiếp sau ack) thì `check` báo cũ: chạy lại 4.6 cho F đó (`render --draft` rồi giao một lô mới).
3. Chốt:
   ```bash
   python3 AI-skills/reporting/report.py check --stage final
   python3 AI-skills/reporting/report.py render
   python3 AI-skills/reporting/report.py status   # phải là: next: xong
   ```
4. Nếu các sửa đổi ở bước 1 đáng kể (đổi độ tin cậy/mức rủi ro của F P0/P1, gộp/tách F) thì chạy lại 4.6 cho các F đó.

## Báo cho người dùng
Đường dẫn báo cáo; số phát hiện theo mức rủi ro × độ tin cậy; số mục bị loại trừ theo lý do; số vấn đề rà soát và cách đã xử lý; 3 việc P0 quan trọng nhất; 3 khoảng trống lớn nhất; các chỗ lệch giữa artifact đã ghi ở mục 7.
