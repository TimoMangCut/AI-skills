---
name: phase-risk-assessment
description: >-
  Phase Risk — Đánh giá rủi ro THỰC TẾ của các điểm yếu đã đứng vững sau phase bác bỏ - ai trong thực tế khai thác được, phải vượt những mắt xích nào (chạm tới, danh tính, thứ phải nắm giữ và ai đang giữ, thông tin, trạng thái, quy mô, kiểm soát có thật), mỗi mắt xích có/không/chưa rõ và vì sao; ghép chéo điểm yếu; script suy ra rủi ro và ưu tiên từ đó và từ tác động nghiệp vụ. Không dùng khung chấm điểm.
---

# `phase-risk-assessment` — Phase Risk (điểm vào)

Điểm yếu có thật (đã qua bác bỏ) chưa chắc là rủi ro thật. Phase này trả lời: **trong thực tế ai khai thác được, phải vượt những gì, vượt được không, vì sao**. Model chỉ kết luận từng mắt xích Có / Không / Chưa rõ kèm lý do và bằng chứng. Script suy ra phần còn lại: khả thi, mức rủi ro, ưu tiên, tác động của tổ hợp, và kết quả của từng câu trả lời cho câu hỏi quyết định. Không dùng CVSS, OWASP Risk Rating hay bất kỳ khung chấm điểm nào.

## Prompt kích hoạt
```text
/phase-risk-assessment Đánh giá rủi ro thực tế cho mọi phát hiện đã hợp nhất: dựng các đường khai thác thực tế, kết luận từng mắt xích có/không/chưa rõ và vì sao kèm bằng chứng, ghép chéo điểm yếu, đặt câu hỏi quyết định; thách thức độc lập trước khi chốt.
```

## Vị trí
- **Đầu vào:**
  - phát hiện đã hợp nhất (`documents/_report/work/consolidation.json`, bước 4.3) và tác động nghiệp vụ của chúng (bước 4.4);
  - kiến trúc (`work/architecture.*`);
  - chỉ mục truy cập (`python3 AI-skills/reporting/report.py access --for F-xx`);
  - kết quả đã khoá sổ trong `documents/`.
- **Đầu ra:**
  - `work/risk/F-xx.json`;
  - `work/risk/_combinations.json`;
  - `work/risk_review.json` hoặc `work/risk_review/<lô>.json`;
  - `documents/_report/DANH_GIA_RUI_RO.md`.
- **Cổng:** báo cáo tổng hợp (4.5) chỉ được viết khi `python3 AI-skills/reporting/report.py check --stage risk` đạt và đã chạy `render-risk` (không `--draft`). Mức rủi ro và ưu tiên trong báo cáo do script suy ra ở phase này.

## Quyền truy cập
- **Đọc:**
  - `documents/` (kết quả đã khoá sổ), `reports/`, `reviews/`, `specs/`;
  - tài liệu nghiệp vụ;
  - `documents/_report/`, `AI-skills/reporting/`.
- **Ghi:** chỉ trong `documents/_report/`:
  - `work/risk/`;
  - `work/risk_review*`;
  - `runtime_facts.json` (khi người vận hành xác nhận).
- **Không đọc mã nguồn của repo.** Mắt xích nào cần thêm bằng chứng từ mã thì để `chua_ro`, kèm câu hỏi hoặc đề xuất kiểm tra.

## Điều phối

| Bước | Việc | Công cụ có subagent (Claude Code, Antigravity) | Công cụ không có subagent (model local) | Cổng |
|---|---|---|---|---|
| R.1 | Đường khai thác, mắt xích, người nắm giữ cho từng F | Agent tool, `general-purpose`, `model: sonnet`, mỗi subagent 1–2 F; prompt chỉ gồm: "Theo `.agents/skills/phase-risk-exploit-path/SKILL.md`, F: <F-xx>". Chạy song song được, mỗi F một file | tuần tự. **Context dưới 64K: mỗi lượt 1 F**; trên 64K: tối đa 2 F. Mở phiên mới khi context gần đầy, rồi chạy `status` | `check --stage risk-paths` |
| R.2 | Ghép chéo, câu hỏi quyết định | phiên chính, làm trên `python3 AI-skills/reporting/report.py risk-digest` (không mở mọi file F) | như bên trái | `check --stage risk` (phần `_combinations`) |
| R.3 | Lập luận kết luận cho từng F | phiên chính, theo `.agents/skills/phase-risk-verdict/SKILL.md` mục R.3, rồi `python3 AI-skills/reporting/report.py render-risk --draft` | như bên trái, mỗi lượt khoảng 5 F | `status` dòng R.2–R.3 |
| R.4 | Thách thức độc lập hai chiều | **không phải phiên chính**. Chia lô khoảng 8 F, mỗi lô một subagent `general-purpose`, `model: sonnet`; prompt chỉ gồm: "Theo `.agents/skills/phase-risk-challenge/SKILL.md`; `context: fresh_subagent`; lô `<tên>`: F-01, F-02, …". Mỗi lô ghi `work/risk_review/<tên>.json` | **cuộc hội thoại mới** cho mỗi lô, gọi `/phase-risk-challenge`, ghi `context: new_session` | — |
| R.5 | Xử lý thách thức, chốt | `.agents/skills/phase-risk-verdict/SKILL.md` mục R.5, rồi `python3 AI-skills/reporting/report.py render-risk` | như bên trái | `status` dòng R.4–R.5 |

Mọi lệnh chạy từ `<Project-Root>` (trên Windows dùng `python`; trên macOS/Linux dùng `python3`):
```bash
python3 AI-skills/reporting/report.py status                         # dòng R.1, R.2–R.3, R.4–R.5 kèm F còn thiếu
python3 AI-skills/reporting/report.py access --for F-03              # chỉ mục truy cập của một F (không đọc nguyên 05_access_index.md)
python3 AI-skills/reporting/report.py check --stage risk-paths --only F-03   # chỉ lỗi R.1 của F-03
python3 AI-skills/reporting/report.py risk-digest                    # bảng ghép chéo gọn cho R.2
python3 AI-skills/reporting/report.py check --stage risk
python3 AI-skills/reporting/report.py render-risk --draft            # trước R.4; ghi phiên bản file rủi ro
python3 AI-skills/reporting/report.py render-risk                    # sau R.5
```

## Phương pháp
Đọc `AI-skills/reporting/guides/06_rui_ro_thuc_te.md` (bắt buộc). Mẫu file: `AI-skills/reporting/templates/risk.example.json`; sự thật runtime: `AI-skills/reporting/templates/runtime_facts.example.json`.

Sáu điều không thương lượng:
1. **Không có bằng chứng thì không được kết luận Có/Không.**
   - Ghi `chua_ro`, kèm `searched` (đã tìm ở đâu), và đặt câu hỏi cho đúng người.
   - `check` từ chối câu phỏng đoán, bằng chứng là thư mục, file của chính báo cáo này, mục đã bác bỏ, hay chính F đang xét.
2. **Kiểm soát chỉ được tính khi có bằng chứng tồn tại** (`exists: co` + `exists_evidence`). Kiểm soát "có thể có" không treo được đường khai thác; nó chỉ được ghi để người đọc biết.
3. **Model không gán khả thi, rủi ro, ưu tiên.** Script suy ra:
   - khai thác được → rủi ro bằng mức tác động 4.4;
   - không khai thác được → thấp;
   - chưa rõ → mức tác động nhưng *tạm tính*, ưu tiên hạ một bậc;
   - tổ hợp khai thác được → kéo ưu tiên lên (tổ hợp chưa rõ thì không).
4. **Tác động là của 4.4.** Đường nào dẫn tới hậu quả khác 4.4 thì ghi `reaches_impact: khong` + `outcome`. Nếu đường đó khai thác được thì phải quay lại 4.4.
5. **"Phải nắm giữ X" thì phải nói ai đang giữ X** (`holders`, tra bằng `access --for`).
6. **Xét đủ năm loại người** (`actors_considered`), kể cả đối tác và nội bộ vượt phạm vi quyền hợp pháp. Lý do "không áp dụng" phải nói về khả năng, không phải động cơ.

## Trần mỗi F (để tài liệu đọc được và model local chạy được)
- Mỗi F có tối đa 4 đường.
- Mỗi đường có tối đa 6 mắt xích.
- Mỗi mắt xích có tối đa 5 người nắm giữ.
- Mỗi F có tối đa 10 câu hỏi; file tối đa khoảng 26 KB.
- Có nhiều loại người đi cùng một đường thì gộp vào một đường (`actors_considered` cho phép một đường thuộc nhiều loại).
- Câu hỏi chung cho nhiều F đưa lên `key_questions`.

## Kết thúc
`status` hết dòng CHƯA ở R.1 tới R.4–R.5. Báo cho người dùng:
- số phát hiện khai thác được / tạm tính / không khai thác được;
- các tổ hợp khả thi;
- các câu hỏi quyết định, kèm kết quả theo từng câu trả lời (lấy từ mục "Câu hỏi quyết định" của `DANH_GIA_RUI_RO.md`);
- đường dẫn `DANH_GIA_RUI_RO.md`.
