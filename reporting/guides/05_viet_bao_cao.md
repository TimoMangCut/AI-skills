# 05 — Viết, rà soát độc lập và chốt báo cáo (bước 4.5–4.7)

Báo cáo cuối do `python AI-skills/reporting/report.py render` dựng **tự động** từ `work/architecture.md`, `work/architecture.json`, `work/consolidation.json`, `work/map/*.json` và `inputs/inputs.json`. Model không tự viết file báo cáo cuối và không sửa nó bằng tay. Muốn đổi nội dung thì sửa file `work/` rồi render lại.

## Bố cục do renderer dựng

1. Tóm tắt điều hành: `executive_summary` + bảng mức rủi ro × độ tin cậy (tự tính) + bảng việc ưu tiên P0/P1
2. Kiến trúc tổng thể: `architecture.md` (2.1–2.6) + **2.7 Bản đồ rủi ro theo cụm nghiệp vụ** (tự tính)
3. Bảng tổng hợp phát hiện (tự tính)
4. Chi tiết phát hiện: một thẻ ngắn cho mỗi F (vấn đề, tác động nghiệp vụ, lý do mức, khắc phục, cần xác minh, nguồn)
5. Nguyên nhân gốc và rủi ro hệ thống (từ Phase 3 + liên kết F, tự tính)
6. Lộ trình khắc phục (`roadmap`)
7. Khoảng trống và rủi ro tồn dư (`gaps` + giới hạn tự ghi nhận: repo chưa khoá sổ, repo chỉ có ý định suy luận, artifact lệch nhau)
- Phụ lục A: truy vết SID → F; B: mục bác bỏ/hạ cấp; C: mục chưa gom; D: nguồn tài liệu

## Phần model viết ở bước 4.5 (trong `consolidation.json`)

### `executive_summary`
- `posture`: một đoạn 3–5 câu cho lãnh đạo kỹ thuật. Câu 1 nói hệ thống làm gì. Câu 2–3 nói **điểm yếu mang tính hệ thống quan trọng nhất** và hậu quả nghiệp vụ của nó. Câu 4 nói mức tin cậy của đánh giá (đọc mã thủ công có giới hạn, chưa kiểm runtime). Câu 5 nói việc phải làm trước tiên. Không dùng "an toàn", "không có lỗ hổng".
- `key_messages`: 3–7 gạch đầu dòng, mỗi ý ≤2 câu, có F-xx. Bao gồm ít nhất: 1 điểm mạnh có bằng chứng (nếu có), 1 khoảng trống lớn nhất.

### `roadmap`
- Gom theo **nguyên nhân gốc / kiểm soát dùng chung**, không mỗi F một hành động. Một hành động sửa gốc có thể đóng nhiều F.
- Mỗi hành động gồm: `id` (A-01…), `priority` (P0–P3), `action` (động từ + đối tượng + phạm vi, ≤2 câu), `findings`, `root_causes`, `owner` (vai trò, nếu biết, ví dụ "Team Payment", "Platform/DevOps"), `acceptance` (tiêu chí kiểm được, ví dụ "Gọi trực tiếp pod payment không qua gateway bị từ chối 401/403").
- Mọi F mức P0/P1 phải có ít nhất một hành động. Không ghi hạn chót, không nói "đã sửa".
- Tách hành động *sửa tại gốc* khỏi *giảm thiểu tạm thời* nếu cả hai cần (gợi ý: `remediation_that_only_treats_symptom` của Phase 3 cho biết cách nào chỉ chữa triệu chứng).

### `gaps`
Khoảng trống còn lại sau cả ba phase, mỗi mục gồm `id` (G-01…), `area`, `why` (vì sao quan trọng), `next` (việc cần làm, ai làm). Nguồn gợi ý: `unknowns`/`coverage_gaps` của `_system`, `unverified_claims_and_gaps` của Phase 3, `validation` của các F `evidence_backed`/`hypothesis`, repo chưa có tài liệu nghiệp vụ, cấu hình runtime ngoài repo (gateway DB, Helm values, secret store).

### Cập nhật `architecture.md`
Thay SID/RC ở mục 2.3, 2.5, 2.6 bằng `F-xx` tương ứng để người đọc nhảy từ kiến trúc sang phát hiện.

## Văn phong

- Tiếng Việt có dấu. Giữ nguyên tên kỹ thuật (endpoint, class, header, tên repo) trong `backtick`.
- Ngắn: `core_issue` ≤3 câu, `consequence` ≤2 câu, `remediation` ≤3 câu. Chi tiết dài đã có ở file nguồn.
- Mỗi khẳng định có nhãn tin cậy: "đã xác nhận", "có bằng chứng mã nguồn", "giả thuyết", "chưa xác định".
- Không nịnh, không doạ. Nêu trade-off khi đề xuất sửa kiến trúc.

## Dựng bản nháp, rà soát độc lập, chốt

```bash
python AI-skills/reporting/report.py render --draft      # 4.5: bản nháp có dòng "BẢN NHÁP"
# 4.6: /phase-4-independent-review trong context MỚI (subagent hoặc cuộc hội thoại mới) → work/review.json
python AI-skills/reporting/report.py check --stage final # 4.7: sau khi điền `resolution` cho mọi vấn đề
python AI-skills/reporting/report.py render
```

`check --stage final` chặn khi:
- chưa có `review.json`;
- `context` không phải `fresh_subagent`/`new_session`;
- có F chưa được rà;
- có vấn đề chưa có `resolution`.

Mục 7 của báo cáo tự ghi số mục đã rà và số vấn đề đã xử lý.

## Vì sao tác giả không tự rà soát

Phiên đã gom và viết tác động sẽ đọc lại báo cáo bằng chính những giả định đã dùng để viết nó, nên hầu như không bắt được lỗi của mình. Đó là lý do Phase 1–3 tách kiểm toán viên. Phase 4 làm tương tự: checklist chi tiết nằm ở `.agents/skills/phase-4-independent-review/SKILL.md` và chỉ người rà soát dùng. Tác giả chỉ làm hai việc trước khi giao rà soát:
- thêm 3 mục `gaps` có `area` bắt đầu bằng "Self-check:", nêu ba chỗ báo cáo có thể sai và cách kiểm chứng;
- kiểm lại các chỗ lệch giữa artifact (mục 7) đã được giải thích.
