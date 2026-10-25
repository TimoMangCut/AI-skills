---
name: phase-2-blinded-counterevidence-challenger
description: >-
  Phase 2.3 — Xác minh độc lập từng mắt xích chuỗi tấn công trong chế độ Mù Kết luận (Context-Blinded) và chủ động săn tìm bằng chứng phản bác hoặc kiểm soát bù trừ trong code (blinded_counterevidence_challenger). Kích hoạt ở Bước 2.3 hoặc khi gọi /phase-2-blinded-counterevidence-challenger.
---

# Phase 2.3: Context-Blinded Step Verifier & Counterevidence Challenger (`blinded_counterevidence_challenger`)

Bạn đang thực thi **Bước 2.3 (`blinded_counterevidence_challenger`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Theo nguyên lý **Refute-First (Bác bỏ trước, khẳng định sau)**: một chuỗi tấn công chỉ đáng tin khi đã sống sót qua nỗ lực bác bỏ độc lập.

---

## 1. Quy tắc Mù Kết luận & Phản biện Đối kháng

1. **Chế độ Mù Kết luận (`prepare_blinded_chain_verifier`)**:
   - Đầu vào của bạn đã bị cắt bỏ toàn bộ `chain_verdict`, `impact_assessment`, `verification_status` và kết luận của Bước 2.2.
   - Bạn chỉ nhận cấu trúc các bước (`steps[]`), câu hỏi kiểm chứng trung lập và danh sách `exact_paths`.
2. **Săn tìm Bằng chứng Phản bác (Active Counterevidence Hunting)**:
   - Tìm kiếm các Global Middleware, Interceptor, Decorator, Trigger DB, Schema Validator, hoặc điều kiện rẽ nhánh làm chuỗi tấn công **vô nghiệm** (`refuted_by_counterevidence`).
   - Ghi nhận mọi nỗ lực phản biện vào **Sổ cái Phản biện Thực nghiệm (`Empirical Refutations Ledger`)**: nêu rõ đã kiểm tra kiểm soát bù trừ nào, ở dòng code nào (`ev_...`), và tại sao kiểm soát đó chặn được hay không chặn được chuỗi tấn công.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Tạo ngữ cảnh mù kết luận cho chuỗi tấn công
python -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# 2. Chỉ đọc trong danh sách exact_paths để tìm bằng chứng xác nhận hoặc bác bỏ
python -m localsec.manual_session read_file <repo_name> <path> <start_line> <end_line> \
  --skill blinded_counterevidence_challenger \
  --allowed-paths <exact_paths>

# 3. Lưu kết quả phản biện đối kháng
python -m localsec.manual_session submit_skill _analysis blinded_counterevidence_challenger .localsec/tmp/blinded_counterevidence_challenger.json
```
