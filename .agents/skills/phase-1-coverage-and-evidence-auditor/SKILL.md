---
name: phase-1-coverage-and-evidence-auditor
description: >-
  Phase 1.6 — Cổng kiểm toán độc lập kết hợp kiểm tra bằng chứng ev_... (Fail-Closed) và kiểm tra độ phủ vật lý Visibility Tracker chống đọc lướt Anti-Grazing (coverage_and_evidence_auditor). Kích hoạt ở Bước 1.6 hoặc khi gọi /phase-1-coverage-and-evidence-auditor.
---

# Phase 1.6: Coverage Ledger & Evidence Auditor (`coverage_and_evidence_auditor`)

Bạn đang thực thi **Bước 1.6 (`coverage_and_evidence_auditor`)** — Cổng chặn cuối cùng của **Phase 1: Unified Reconnaissance (LocalSec v3.0)** trước khi chuyển `Candidate Queue` sang Phase 2.

---

## 1. Hai Cổng Kiểm toán Bắt buộc (Dual Deterministic Gates)

### Cổng 1: Kiểm toán Độ phủ Vật lý & Chống "Giả vờ Đủ Coverage" (`Visibility Tracker` & `Coverage Ledger`)
1. Chạy lệnh `python -m localsec.manual_session audit_visibility <repo_name>`.
2. Công cụ Python sẽ đối chiếu khách quan nhật ký `read_file` thực tế với `target_modules` đã đăng ký ở Bước 1.1 (`codebase_scout.json`):
   - **`unvisited_target_modules`**: Nếu còn bất kỳ module mục tiêu nào có tỷ lệ đọc `0%`, cổng sẽ **FAIL**. AI bắt buộc phải quay lại Bước 1.4 đọc module bị bỏ quên đó (hoặc cập nhật `ignored_modules` kèm lý do chính đáng).
   - **`shallow_grazing_files` (Anti-Grazing)**: Nếu AI chỉ mở đọc lướt $\le 8$ dòng đầu (chỉ xem `import` hoặc khai báo class) của một file có độ dài $> 25$ dòng để lấy mã `ev_...` giả tạo, cổng sẽ **FAIL**.
   - **Kiểm tra `coverage_ledger.json`**: Mọi bản ghi phải tuân thủ định dạng `coverage_id` RFC 3986 (4–5 phân đoạn `surface::boundary::subsystem::attack_class[::lifecycle]`) và có lịch sử `attempts[]` bất biến.

### Cổng 2: Kiểm toán Bằng chứng Độc lập (`ev_...` Fail-Closed Audit)
1. Chạy lệnh `python -m localsec.manual_session verify_semantic_claims <repo_name>` để phát hiện mâu thuẫn ngữ nghĩa giữa tuyên bố và trích đoạn code thực tế.
2. Mọi tuyên bố `observed` hoặc `derived` không khớp với nội dung dòng code trong `ev_...` phải bị hạ cấp **Fail-Closed** xuống `hypothesis` hoặc bị loại bỏ.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Chạy cổng kiểm tra Visibility Tracker + Anti-Grazing + Coverage Ledger
python -m localsec.manual_session audit_visibility <repo_name>

# 2. Chạy cổng kiểm tra ngữ nghĩa Claim-to-Excerpt
python -m localsec.manual_session verify_semantic_claims <repo_name>

# 3. Lưu kết quả kiểm toán Phase 1
python -m localsec.manual_session submit_skill <repo_name> coverage_and_evidence_auditor .localsec/tmp/coverage_and_evidence_auditor_<repo_name>.json
```
