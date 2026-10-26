---
name: phase-risk-cross-link
description: >-
  Phase Risk R.2 — Ghép chéo các điểm yếu trên bảng gọn (risk-digest) - thứ một phát hiện cho kẻ tấn công (yields) có đúng là thứ mắt xích của phát hiện khác cần không; ghi enabled_by và tổ hợp (script suy ra khả thi, rủi ro, ưu tiên của tổ hợp); gom câu hỏi chung thành câu hỏi quyết định.
---

# `phase-risk-cross-link` (Phase Risk — R.2)

Rủi ro thật thường nằm ở **tổ hợp**: một điểm yếu riêng lẻ có thể không khai thác được, nhưng điểm yếu khác lại làm mắt xích đang chặn nó trở nên đạt được.

**Quyền truy cập:** theo `.agents/skills/phase-risk-assessment/SKILL.md`.

## Prompt kích hoạt
```text
/phase-risk-cross-link Ghép thứ mỗi F cho kẻ tấn công với mắt xích chưa đạt của F khác; ghi enabled_by và tổ hợp; gom câu hỏi chung thành câu hỏi quyết định.
```

## Điều kiện
`python3 AI-skills/reporting/report.py check --stage risk-paths` đạt (mọi F đã qua R.1).

## Làm
1. Chạy `python3 AI-skills/reporting/report.py risk-digest`. Bảng gồm:
   - `yields` của mỗi F, kèm F đó khả thi hay không;
   - mọi mắt xích `khong`/`chua_ro` của mọi F (một dòng mỗi mắt xích).

   Làm trên bảng này; chỉ mở file F khi cần sửa.
2. Ghép:
   - Chỉ ghép khi thứ F-B **cho** đúng là thứ mắt xích của F-A **cần**.
   - Ghi `enabled_by: ["F-B"]` vào mắt xích đó của F-A, rồi xét lại kết luận:
     - F-B khai thác được thì mắt xích thường thành `co`;
     - F-B còn chưa rõ thì giữ `chua_ro` (`check` chặn `co` chỉ dựa vào một F chưa khai thác được).
   - Thêm một tổ hợp vào `work/risk/_combinations.json`:
     ```json
     {"method_note": "Đã xét những cặp nào, vì sao",
      "combinations": [{"id": "X1", "giver": "F-08", "target": "F-03", "link": "F-03.P1.C1",
                        "how": "F-08 làm lộ secret portal trong bundle JS — đó là credential mà P1.C1 của F-03 cần"}],
      "key_questions": []}
     ```
   - **Không** ghi `feasible`/`risk`, vì script suy ra từ đường chứa `link`:
     - chỉ tổ hợp khai thác được mới kéo ưu tiên của cả hai F lên mức của tổ hợp;
     - tổ hợp còn chưa rõ không kéo ưu tiên, chỉ hiện trong bảng tổ hợp.
   - `giver` có thể là một SID chưa thuộc F nào. Khi đó `check` cảnh báo: quay lại 4.3 gom nó thành F.
3. **Câu hỏi quyết định.** Khi cùng một sự thật chưa biết quyết định mắt xích `chua_ro` của **≥2 F** (ví dụ bảng scope của gateway, NetworkPolicy của cluster, một bí mật có còn ở production không), ghi một mục:
   ```json
   {"id": "Q1", "question": "Xuất bảng client_scope của gateway production (chỉ tên client)…", "to": "platform_devops",
    "unlocks": ["F-02.P1.C1", "F-05.P1.C2"]}
   ```
   - `unlocks`: **mọi** mắt xích `chua_ro` phụ thuộc sự thật đó, kể cả `entry` và kiểm soát (`P1.K1`).
   - Câu hỏi phải trả lời được bằng một lần xuất dữ liệu hoặc một lệnh, và nêu đích danh đối tượng cần kiểm (ví dụ client kiểm thử trong seed).
   - Script tính sẵn kết quả rủi ro/ưu tiên cho từng câu trả lời "có" / "không".
   - Mắt xích đã nằm trong câu hỏi quyết định không cần câu hỏi riêng trong file F nữa: xoá câu hỏi trùng để giữ dưới trần 10 câu.
4. Tìm thứ cung cấp mắt xích **cả ngoài tập F**: `python3 AI-skills/reporting/report.py access --for F-xx`, `inputs/03_findings_index.md`, kể cả mục đã loại trừ ở 4.3.
   - Nguồn nào có trong chỉ mục mà chưa thành holder thì thêm.
   - `enabled_by` bằng SID: `check` báo lỗi nếu SID đã thuộc F (ghi F đó), hoặc đã bị loại trừ (quay lại 4.3).
5. `python3 AI-skills/reporting/report.py check --stage risk`: phần `_combinations` không còn lỗi; cảnh báo "`enabled_by` … chưa có tổ hợp tương ứng" phải hết.

## Không được
- Ghép hai điểm yếu chỉ vì cùng service hay cùng chủ đề. Phải chỉ ra đúng mắt xích nào được mở.
- Bỏ qua tổ hợp vì từng điểm yếu riêng lẻ "chỉ medium".
- Tự gán khả thi hay rủi ro cho tổ hợp.
