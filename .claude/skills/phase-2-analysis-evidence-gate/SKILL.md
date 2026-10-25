---
name: phase-2-analysis-evidence-gate
description: >-
  Phase 2.4 — Cổng kiểm toán bằng chứng độc lập và Sổ cái Phản biện Thực nghiệm (Empirical Refutations Ledger) trước khi chuyển các lỗ hổng đã chứng minh Reachable sang Phase 3 Risk Assessment (analysis_evidence_gate). Kích hoạt ở Bước 2.4 hoặc khi gọi /phase-2-analysis-evidence-gate.
---

# Phase 2.4: Analysis Evidence Auditor & Empirical Refutations Gate (`analysis_evidence_gate`)

Bạn đang thực thi **Bước 2.4 (`analysis_evidence_gate`)** — Cổng chặn cuối cùng của **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Chỉ những chuỗi tấn công và lỗ hổng đã vượt qua kiểm toán bằng chứng mã nguồn (`ev_...`) và sống sót qua phản biện đối kháng ở Bước 2.3 mới được chuyển sang **Phase 3 (Đánh giá Rủi ro Thực tế & Khả năng Khai thác)**.

---

## 1. Các Điều kiện Chặn Bắt buộc (Fail-Closed Gates)

1. **`request_plan_is_not_execution`**:
   - Nếu chuỗi request chỉ ở trạng thái `plan_only` / `not_executed`, phán quyết tối đa về mặt mã nguồn là `code_supported`, **TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `confirmed`** (trừ khi đã thực thi thật trên môi trường test được phê duyệt và có log phản hồi).
2. **Đầy đủ Bằng chứng cho mọi Mắt xích (`steps[]`) và Cạnh nối (`linked_next_steps[]`)**:
   - Bất kỳ mắt xích nào thiếu `ev_...` hoặc bị Bước 2.3 chứng minh có kiểm soát chặn đứng sẽ làm toàn bộ chuỗi hạ xuống `refuted` hoặc `partial_or_hypothesis`.
3. **Kiểm tra Ngữ nghĩa Claim-to-Excerpt**:
   - Chạy `verify_semantic_claims` để chặn mọi trường hợp AI trích dẫn `ev_...` hợp lệ nhưng diễn giải sai tên hàm/thuộc tính bên trong trích đoạn.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Kiểm tra mâu thuẫn ngữ nghĩa giữa tuyên bố và trích đoạn ev_...
python3 -m localsec.manual_session verify_semantic_claims _analysis

# 2. Lưu kết quả cổng kiểm toán Phase 2
python3 -m localsec.manual_session submit_skill _analysis analysis_evidence_gate /tmp/analysis_evidence_gate.json
```
