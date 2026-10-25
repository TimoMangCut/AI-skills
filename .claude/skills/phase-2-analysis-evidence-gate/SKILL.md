---
name: phase-2-analysis-evidence-gate
description: >-
  Phase 2.4 — Cổng kiểm toán bằng chứng độc lập và Sổ cái Phản biện Thực nghiệm (Empirical Refutations Ledger) trước khi chuyển các lỗ hổng đã chứng minh Reachable sang Phase 3 Risk Assessment (analysis_evidence_gate). Kích hoạt ở Bước 2.4 hoặc khi gọi /phase-2-analysis-evidence-gate.
---

# Phase 2.4: Analysis Evidence Auditor & Empirical Refutations Gate (`analysis_evidence_gate`)

> **Subagent Isolation Directive**: Run `finalize_v3_phase2` as the authoritative script-enforced gate to reconcile Phase 2 chains and emit `phase3_verified_queue.json` before starting Phase 3 in a fresh session.

Bạn đang thực thi **Bước 2.4 (`analysis_evidence_gate`)** — Cổng chặn cuối cùng của **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/analysis_evidence_gate.schema.json`.

Chỉ những chuỗi tấn công đã vượt qua kiểm toán bằng chứng mã nguồn (`ev_...`), sống sót qua phản biện đối kháng ở Bước 2.3 và qua cổng khóa sổ tất định `finalize_v3_phase2` mới được chuyển sang **Phase 3 (Đánh giá Rủi ro Thực tế & Khả năng Khai thác)**.

---

## 1. Cổng Kiểm toán Thực thi Bằng Script (`finalize_v3_phase2` — `ARCH-3D`, `ARCH-3G`, `R2-P1-04`)

1. **`finalize_v3_phase2` là Cổng Chặn Tất định Có Thẩm quyền Cuối cùng của Phase 2 (`R2-P1-04`)**:
   - Lệnh `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase2 <repo_name>` thực thi tự động toàn bộ các quy tắc kiểm toán:
     - **Hạch toán 100% Ứng viên (`100% Candidate Accounting` — `ARCH-3G`)**: Kiểm tra mọi `candidate_id` từ `.localsec/runs/default/<repo_name>/candidate_queue.json` đều đã được hạch toán vào `chains[].candidate_ids` hoặc `unexploitable_candidates[]`. Nếu sót bất kỳ `candidate_id` nào, cổng sẽ **FAIL**.
     - **Chặn Chuỗi Chưa Qua Phản biện (`UNCHALLENGED_BLOCKED` — `R2-P1-01`, `R2-P1-02`)**: Kiểm tra mọi `chain_id` đều đã được Bước 2.3 (`blinded_counterevidence_challenger`) phản biện sau thời điểm sinh gói `/tmp/blinded_chains_<repo_name>.json` (kiểm tra tính mới của timestamp) và kiểm tra đủ cả 6 vị trí trong `control_search_checklist` kèm `searched_paths` + `evidence_ids`. Mọi chuỗi chưa qua phản biện sẽ bị chặn (`UNCHALLENGED_BLOCKED`).
     - **Luật Cứng `request_plan_is_not_execution`**: Tự động áp trần `chain_verdict` ở `"code_supported"` cho mọi chuỗi có `execution_status != "executed"`.
     - **Ghi Sổ cái & Hàng đợi Phase 3**: Tự động xuất `.localsec/runs/default/<repo_name>/analysis_evidence_gate.json`, `.localsec/runs/default/<repo_name>/phase3_verified_queue.json` và biên nhận `.localsec/runs/default/<repo_name>/phase2_gate_receipt.json`.

---

## 2. Giao thức Thực thi CLI

```powershell
# 1. Kiểm tra mâu thuẫn ngữ nghĩa giữa tuyên bố và trích đoạn ev_...
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>

# 2. (Tùy chọn) Lưu kết quả cổng kiểm toán Phase 2 trước khi khóa sổ
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> analysis_evidence_gate /tmp/analysis_evidence_gate_<repo_name>.json

# 3. Chạy cổng khóa sổ tất định Phase 2 (kiểm tra 100% candidate_queue, UNCHALLENGED_BLOCKED, 6 vị trí challenger và xuất phase3_verified_queue.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase2 <repo_name>
```

---

## 3. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/analysis_evidence_gate.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "gate_passed": true,
    "confirmed_reachable_chains": [
      "CHAIN-OCPP-01"
    ],
    "downgraded_or_refuted_chains": [],
    "empirical_refutations_ledger": [],
    "summary": "100% of candidate_queue accounted for; CHAIN-OCPP-01 verified across all 6 challenger control locations and exported to phase3_verified_queue.json."
  }
}
```
