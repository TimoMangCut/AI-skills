---
name: phase-risk-verdict
description: >-
  Phase Risk R.3 và R.5 — Viết lập luận kết luận cho từng phát hiện (mắt xích khó nhất và ai vượt được, vì sao ra kết quả này, điều gì làm rủi ro đổi) trong khi script suy ra rủi ro và ưu tiên; dựng bản nháp DANH_GIA_RUI_RO.md; sau thách thức độc lập thì xử lý từng vấn đề và chốt.
---

# `phase-risk-verdict` (Phase Risk — R.3, R.5)

**Quyền truy cập:** theo `.agents/skills/phase-risk-assessment/SKILL.md`.

## Prompt kích hoạt
```text
/phase-risk-verdict Viết lập luận cho từng F: mắt xích khó nhất và ai vượt được nó, vì sao khai thác được / không / chưa rõ, điều gì làm rủi ro đổi; script suy ra rủi ro và ưu tiên.
```

## Script suy ra (model không gán)

| Khả thi (từ mắt xích + kiểm soát có thật, chỉ các đường `reaches_impact: co`) | Rủi ro | Ưu tiên |
|---|---|---|
| Khai thác được | bằng mức tác động 4.4 | critical→P0, high→P1, medium→P2, low→P3 |
| Không khai thác được | low | P3 |
| Chưa rõ (tạm tính) | bằng mức tác động 4.4 | hạ một bậc (critical→P1…) cho tới khi trả lời câu hỏi |

Tổ hợp kéo ưu tiên lên:
- chỉ tổ hợp **khai thác được** kéo ưu tiên của bên cho và bên nhận lên mức của tổ hợp;
- tổ hợp còn chưa rõ không kéo ưu tiên (nó có điều kiện; điều kiện đó thường nằm trong câu hỏi quyết định).

Muốn khác bảng trên thì dùng `risk_override` (`risk`, `reason` ≥80 ký tự, `evidence`), với hai điều kiện:
- chỉ khi đã khai thác được, và chỉ được hạ đúng một bậc;
- phải nói vì sao hậu quả thực tế nhỏ hơn tác động 4.4.

Còn mắt xích chưa rõ thì không được ghi đè; trả lời câu hỏi trước. Thấy tác động 4.4 sai thì sửa ở 4.4.

## R.3 — Lập luận kết luận
Điều kiện: `check --stage risk-paths` đạt và R.2 xong. Mỗi lượt khoảng 5 F. Với từng `work/risk/F-xx.json`, thêm:
- `likelihood.hardest`: mắt xích khó vượt nhất trên đường dễ nhất, ví dụ `P1.C1`. Có thể là một kiểm soát (`P1.K1`).
- `likelihood.why`: ai trong thực tế vượt được mắt xích đó, bằng cách nào. Nếu không ai vượt được thì nói vì sao.
- `rationale`: vì sao ra kết quả này, tức đường nào khai thác được / không / chưa rõ và mắt xích quyết định. Không ghi chú quá trình.
- `escalation_triggers` (bắt buộc khi chưa khai thác được): mắt xích hay kiểm soát nào đổi thì rủi ro thành gì.

Không ghi `risk`/`priority`; nếu có ghi thì phải khớp giá trị script suy ra.

Sau đó:
```bash
python AI-skills/reporting/report.py check --stage risk
python AI-skills/reporting/report.py render-risk --draft     # ghi cả work/risk_review_basis.json (phiên bản cho R.4)
```
Rồi chuyển sang R.4. Người thách thức **không phải phiên này**: chia lô theo `phase-risk-assessment`. Không tự viết `risk_review*`.

## R.5 — Xử lý thách thức và chốt
Điều kiện: đã có `work/risk_review.json` hoặc `work/risk_review/<lô>.json` do R.4 tạo.
1. Với mỗi mục `verdict: issue`, bắt đầu từ `severity: nang`:
   - đồng ý → sửa file rủi ro, rồi ghi `resolution` bắt đầu bằng **`Đã sửa:`** và nói cụ thể đã sửa gì (≥20 ký tự);
   - không đồng ý → ghi `resolution` bắt đầu bằng **`Giữ nguyên:`**, dẫn SID/F/`ev_`/file làm bằng chứng.

   Không xoá hay sửa `note`/`severity` của người thách thức.
2. File F nào đổi sau rà soát mà không có mục "Đã sửa:" giải thích thì `check` báo cũ: chạy lại R.4 cho F đó.
   - Chạy `render-risk --draft` để cập nhật phiên bản, rồi giao một lô mới (file mới trong `work/risk_review/`).
   - **Không** ghi đè lô cũ.
3. Khi người vận hành trả lời câu hỏi:
   - ghi vào `documents/_report/runtime_facts.json` (mẫu `AI-skills/reporting/templates/runtime_facts.example.json`, mỗi sự thật có `id`, `answer`, `source`, `date`);
   - đổi mắt xích `chua_ro` thành `co`/`khong` với `evidence: ["fact:<id>"]`;
   - chạy lại R.3 cho các F đó.
4. Chốt:
   ```bash
   python AI-skills/reporting/report.py risk-ack          # ghi phiên bản của các F vừa "Đã sửa:"; sửa tiếp sau đó thì phải rà lại
   python AI-skills/reporting/report.py check --stage risk
   python AI-skills/reporting/report.py render-risk
   ```
