---
name: phase-risk-challenge
description: >-
  Phase Risk R.4 — Thách thức độc lập hai chiều theo lô, trong context mới (không phải phiên đã đánh giá) - khai thác có dễ hơn đã nói không (đường hay người nắm giữ bị bỏ sót, mắt xích ghi không nhưng vượt được, tổ hợp chưa xét) và có khó hơn đã nói không (mắt xích ghi có nhưng bằng chứng yếu, kiểm soát có thật bị bỏ qua); ghi work/risk_review/LÔ.json.
---

# `phase-risk-challenge` (Phase Risk — R.4)

Người thách thức **không được là phiên đã đánh giá rủi ro**. Nhiệm vụ là tìm chỗ đánh giá sai **theo cả hai chiều**, không chỉ chiều làm rủi ro cao lên. Mỗi lượt rà một lô F (khoảng 8 F) được giao trong prompt.

## Prompt kích hoạt
```text
/phase-risk-challenge lô <tên>: F-01, F-02, … — thách thức hai chiều: dễ khai thác hơn đã nói ở đâu, khó hơn đã nói ở đâu; đối chiếu nguồn, không tin lời người đánh giá; ghi work/risk_review/<tên>.json.
```

## Chạy ở đâu
- **Công cụ có subagent (Claude Code, Antigravity):** phiên chính giao qua Agent tool (Antigravity: `invoke_subagent`, `TypeName: "self"`, `Workspace: "inherit"`) (`general-purpose`, `model: sonnet`). Prompt chỉ gồm đường dẫn skill này, `context: fresh_subagent`, tên lô và danh sách F.
- **Công cụ không có subagent (model local):** mở **cuộc hội thoại mới** cho mỗi lô, ghi `context: new_session`.

## Quyền truy cập
- **Đọc:**
  - `documents/_report/DANH_GIA_RUI_RO.md` (bản nháp; chỉ đọc mục của các F trong lô, cùng mục "Câu hỏi quyết định" và "Tổ hợp");
  - `documents/_report/work/risk/`, `work/consolidation.json`, `work/risk_review_basis.json`;
  - `documents/_report/runtime_facts.json`;
  - `documents/` (báo cáo các phase trước, không phải mã nguồn), `reports/`, `AI-skills/reporting/`.
- **Ghi:** chỉ `documents/_report/work/risk_review/<tên lô>.json`. Không ghi đè lô khác.
- Không đọc mã nguồn repo; không sửa file rủi ro.

## Trước khi hỏi
Với mỗi F trong lô:
- chạy `python3 AI-skills/reporting/report.py access --for F-xx` (bắt buộc);
- so kết quả với `holders` của các mắt xích `nam_giu`, với `actors_considered`, và với các kiểm soát.

## Hỏi cho từng F
**Dễ hơn đã nói?**
1. Có cách khai thác thực tế nào khác bị bỏ sót không: đối tượng khác, entry khác, đi đường nội bộ, qua job/scheduler, qua dữ liệu đã nhập sẵn?
   - Riêng **người đã có quyền hợp pháp** (đối tác, nhân viên, khách hàng): họ có vượt được phạm vi của mình không?
   - Lý do "không áp dụng" trong `actors_considered` có nói về khả năng không, hay chỉ về động cơ?
2. Mắt xích ghi `khong`: bằng chứng có thật sự loại trừ nó không? Mắt xích ghi `chua_ro`: `searched` có bỏ sót chỗ đã có câu trả lời không (ví dụ migration, cấu hình đã có trong `documents/`)?
3. Mắt xích `nam_giu`: `holders` có thiếu người/nơi đang giữ nào mà `access --for` nêu không (client kiểm thử trong seed, secret trong bundle, đối tác, cấu hình)?
   - 3b. Có điểm yếu khác (kể cả mục ngoài tập F hoặc đã loại trừ ở 4.3) làm mắt xích đạt được mà R.2 chưa ghép không?

**Khó hơn đã nói?**

4. Mắt xích ghi `co`: bằng chứng có thật sự chứng minh *trong thực tế* đạt được không, hay chỉ chứng minh code cho phép? Lý do có dựa vào nhận định chung mà bằng chứng không nói tới không?
5. Có kiểm soát **có thật** (có bằng chứng tồn tại) đang chặn mà bị bỏ qua không: gateway, mạng, quy trình, đối soát? Ngược lại, kiểm soát ghi `exists: co` có bằng chứng thật không?

**Kết luận**

6. Mắt xích khó nhất có đúng là khó nhất không? `reaches_impact` có đúng không? Có đường dẫn tới hậu quả khác 4.4 mà bị ghi `co` không?

**Toàn lô (target `combinations`, `overall`)**

7. Có tổ hợp nguy hiểm chưa xét không? Câu hỏi quyết định có thiếu mắt xích cùng phụ thuộc một sự thật không?
8. Câu hỏi cho vận hành có hỏi đúng người, đủ cụ thể để trả lời được bằng một lần xuất dữ liệu hay một lệnh không?

## Đầu ra: `documents/_report/work/risk_review/<tên lô>.json`
```json
{"context": "fresh_subagent", "batch": "lo1", "reviewer_note": "đã rà gì, giới hạn",
 "items": [
   {"target": "F-03", "basis": "<hash của F-03 trong work/risk_review_basis.json>", "verdict": "issue", "severity": "nang", "check": "3",
    "direction": "de_hon", "note": "P1.C1 thiếu holder: client kiểm thử trong seed (vfip-db-scripts:TM-DB-01) có scope toàn bộ route", "resolution": ""},
   {"target": "F-05", "basis": "<hash>", "verdict": "ok", "check": "1-6", "note": "Đối chiếu _analysis:C4, access --for F-05 và từng holder"}
 ]}
```
- **Mục bắt buộc:** mọi F trong lô có ít nhất một mục. `target` có thể là `F-xx`, `combinations` hoặc `overall`.
- **Trường bắt buộc ở mọi mục** (kể cả `ok`):
  - `basis`: lấy từ `work/risk_review_basis.json`;
  - `check`: số câu hỏi đã dùng;
  - `note` ≥20 ký tự: nói đã đối chiếu gì.
- **Khi `issue`:**
  - `severity`: `nang`/`vua`/`nhe`;
  - `direction`: `de_hon` = dễ khai thác hơn đã nói, `kho_hon` = khó hơn;
  - `note` dẫn bằng chứng;
  - để trống `resolution`.

## Kết thúc
Trả về tối đa 10 dòng: lô và số F đã rà, số vấn đề theo chiều (dễ hơn / khó hơn), 3 vấn đề nặng nhất.
