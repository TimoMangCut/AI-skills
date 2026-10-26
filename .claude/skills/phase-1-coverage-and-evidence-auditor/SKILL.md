---
name: phase-1-coverage-and-evidence-auditor
description: >-
  Phase 1.6 — Cổng kiểm toán độc lập kết hợp kiểm tra bằng chứng ev_... (Fail-Closed) và kiểm tra độ phủ vật lý Visibility Tracker chống đọc lướt Anti-Grazing (coverage_and_evidence_auditor). Kích hoạt ở Bước 1.6 hoặc khi gọi /phase-1-coverage-and-evidence-auditor.
---

# Phase 1.6: Coverage Ledger & Evidence Auditor (`coverage_and_evidence_auditor`)

> **Subagent Isolation Directive**: Execute `finalize_v3_phase1` as the authoritative script-enforced gate to close Phase 1 before starting Phase 2 in a fresh session.

Bạn đang thực thi **Bước 1.6 (`coverage_and_evidence_auditor`)** — Cổng chặn cuối cùng của **Phase 1: Unified Reconnaissance (LocalSec v3.0)** trước khi chuyển `Candidate Queue` sang Phase 2.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json`.

---

## 1. Cổng Kiểm toán Thực thi Bằng Script (`finalize_v3_phase1` — `ARCH-3D`, `ARCH-3G`, `R2-P1-04`)

1. **`finalize_v3_phase1` là Cổng Chặn Tất định Có Thẩm quyền Cuối cùng (`R2-P1-04`)**:
   - Lệnh `python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>` là cổng kiểm toán thực thi bằng script có thẩm quyền cao nhất của Phase 1.
   - Khi chạy `finalize_v3_phase1 <repo_name>`, engine tự động thực hiện toàn bộ chuỗi kiểm định:
     - Tính toán độ phủ vật lý **Visibility Tracker** đối chiếu với `target_modules` (`codebase_scout.json`) và `mandatory_files` (`inventory_repo.json`): chặn mọi `unvisited_target_modules`, `unvisited_mandatory_files`, `shallow_grazing_files` (Anti-Grazing `<= 8` dòng trên file `> 25` dòng), và `spot_check_violations`.
     - Chạy kiểm chứng ngữ nghĩa **Semantic Claim-to-Excerpt Verifier** (`verify_semantic_claims`) và tự động hạ cấp **Fail-Closed** mọi tuyên bố thiếu bằng chứng hoặc lệch ngữ nghĩa xuống `hypothesis`.
     - Tự động sinh bảng đối soát `.localsec/runs/default/<repo_name>/coverage_matrix.json` (mặc định đánh dấu `"unassessed"` cho các ô chưa được kiểm tra trực tiếp trong `coverage_ledger.json`) và hàng đợi ứng viên `.localsec/runs/default/<repo_name>/candidate_queue.json` từ 7 nguồn ứng viên.
     - Tự động ghi nhận `.localsec/runs/default/<repo_name>/coverage_and_evidence_auditor.json` cùng biên nhận khóa sổ `.localsec/runs/default/<repo_name>/phase1_gate_receipt.json` (và `phase1_gate_Certificate.json`).

---

## 2. Giao thức Thực thi CLI

```powershell
# 1. Chạy cổng kiểm tra Visibility Tracker + Anti-Grazing + Coverage Ledger
python3 -m localsec.manual_session audit_visibility <repo_name>

# 2. Chạy cổng kiểm tra ngữ nghĩa Claim-to-Excerpt
python3 -m localsec.manual_session verify_semantic_claims <repo_name>

# 3. (Tùy chọn) Lưu kết quả kiểm toán Phase 1 thủ công trước khi khóa sổ
python3 -m localsec.manual_session submit_skill <repo_name> coverage_and_evidence_auditor .localsec/tmp/coverage_and_evidence_auditor_<repo_name>.json

# 4. Chạy cổng khóa sổ tất định Phase 1 (tự động xuất coverage_matrix.json, candidate_queue.json, coverage_and_evidence_auditor.json và phase1_gate_receipt.json)
python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>
```

---

## 3. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "visibility_audit_passed": true,
    "gate_passed": true,
    "audited_claims": [
      {
        "claim_id": "CLM-01",
        "claim_ref": "unified_surface_mapper:entrypoints[1]",
        "verdict": "supported",
        "evidence_ids": [
          "ev_001"
        ],
        "reason": "Excerpt in src/ocpp_controller.py confirms missing session ownership check"
      }
    ],
    "downgraded_claims": [],
    "summary": "All target_modules and mandatory entrypoint/security files visited without shallow grazing; candidate_queue.json and phase1_gate_receipt.json generated."
  }
}
```
