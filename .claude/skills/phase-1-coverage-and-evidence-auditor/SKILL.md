---
name: phase-1-coverage-and-evidence-auditor
description: >-
  Phase 1.6 — Cổng kiểm toán độc lập kết hợp kiểm tra bằng chứng ev_... (Fail-Closed) và kiểm tra độ phủ vật lý Visibility Tracker chống đọc lướt Anti-Grazing (coverage_and_evidence_auditor). Kích hoạt ở Bước 1.6 hoặc khi gọi /phase-1-coverage-and-evidence-auditor.
---

# Phase 1.6: Coverage Ledger & Evidence Auditor (`coverage_and_evidence_auditor`)

Bạn đang thực thi **Bước 1.6 (`coverage_and_evidence_auditor`)** — Cổng chặn cuối cùng của **Phase 1: Unified Reconnaissance (LocalSec v3.0)** trước khi chuyển `Candidate Queue` sang Phase 2.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json`.

---

## 1. Hai Cổng Kiểm toán & Khóa sổ Tất định (`finalize_v3_phase1` — `ARCH-3D`, `ARCH-3G`, `DEPTH-4.3a`)

### Cổng 1: Kiểm toán Độ phủ Vật lý & Chống "Giả vờ Đủ Coverage" (`Visibility Tracker` & `Coverage Ledger`)
1. Chạy lệnh `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session audit_visibility <repo_name>`.
2. Công cụ Python sẽ đối chiếu khách quan nhật ký `read_file` thực tế với `target_modules` (`codebase_scout.json`) và `mandatory_files` (`inventory_repo.json`):
   - **`unvisited_target_modules`**: Nếu còn bất kỳ module mục tiêu nào có tỷ lệ đọc `0%`, cổng sẽ **FAIL**. AI bắt buộc phải quay lại Bước 1.4 đọc module bị bỏ quên đó.
   - **`unvisited_mandatory_files`**: Mọi file thuộc nhóm `entrypoint` và `security` trong `inventory_repo.json` phải được đọc thực chất.
   - **`shallow_grazing_files` (Anti-Grazing)**: Nếu AI chỉ mở đọc lướt `<= 8` dòng đầu (chỉ xem `import` hoặc khai báo class) của một file có độ dài `> 25` dòng để lấy mã `ev_...` giả tạo, cổng sẽ **FAIL**.
   - **Kiểm tra `coverage_ledger.json` & Safe Clustering (`ARCH-3F`)**: Mọi bản ghi phải tuân thủ định dạng `coverage_id` RFC 3986 (4–5 phân đoạn `surface::boundary::subsystem::attack_class[::lifecycle]`), không có entrypoint chứa `object_id_params` nào bị gom cụm ngầm, và các cụm `>= 5` thành viên đều có `spot_check_evidence_ids`.

### Cổng 2: Kiểm toán Bằng chứng Độc lập & Tự động Sinh `coverage_matrix.json` + `candidate_queue.json`
1. Chạy lệnh `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>` để phát hiện mâu thuẫn ngữ nghĩa giữa tuyên bố và trích đoạn code thực tế.
2. Nộp `coverage_and_evidence_auditor` và chạy lệnh khóa sổ tất định:
   `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>`
3. Lệnh `finalize_v3_phase1` sẽ thực thi tự động:
   - Kiểm tra `audit_visibility` và `verify_semantic_claims`.
   - Tự động hạ cấp **Fail-Closed** mọi tuyên bố `observed`/`derived` thiếu bằng chứng hoặc lệch ngữ nghĩa xuống `hypothesis`.
   - Xuất bảng đối soát `.localsec/runs/default/<repo_name>/coverage_matrix.json` (`DEPTH-4.3a`) và hàng đợi ứng viên `.localsec/runs/default/<repo_name>/candidate_queue.json` (`ARCH-3G`) để bàn giao sang Phase 2.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Chạy cổng kiểm tra Visibility Tracker + Anti-Grazing + Coverage Ledger
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session audit_visibility <repo_name>

# 2. Chạy cổng kiểm tra ngữ nghĩa Claim-to-Excerpt
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>

# 3. Lưu kết quả kiểm toán Phase 1 (đối chiếu AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> coverage_and_evidence_auditor /tmp/coverage_and_evidence_auditor_<repo_name>.json

# 4. Khóa sổ Phase 1 tất định: hạ cấp Fail-Closed và xuất coverage_matrix.json + candidate_queue.json
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>
```

---

## 3. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json`)

```json
{
  "visibility_gate_passed": true,
  "unvisited_target_modules": [],
  "shallow_grazing_files": [],
  "semantic_verification_passed": true,
  "downgraded_claims": [],
  "approved_candidate_ids": [
    "CAND-OCPP-BOLA-01"
  ],
  "audit_summary": "All target_modules and mandatory entrypoint/security files visited without shallow grazing; 1 P0 candidate exported to candidate_queue.json."
}
```
