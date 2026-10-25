---
name: phase-2-analysis-evidence-gate
description: >-
  Phase 2.4 — Cổng kiểm toán bằng chứng độc lập và Sổ cái Phản biện Thực nghiệm (Empirical Refutations Ledger) trước khi chuyển các lỗ hổng đã chứng minh Reachable sang Phase 3 Risk Assessment (analysis_evidence_gate). Kích hoạt ở Bước 2.4 hoặc khi gọi /phase-2-analysis-evidence-gate.
---

# Phase 2.4: Analysis Evidence Auditor & Empirical Refutations Gate (`analysis_evidence_gate`)

Bạn đang thực thi **Bước 2.4 (`analysis_evidence_gate`)** — Cổng chặn cuối cùng của **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/analysis_evidence_gate.schema.json`.

Chỉ những chuỗi tấn công đã vượt qua kiểm toán bằng chứng mã nguồn (`ev_...`), sống sót qua phản biện đối kháng ở Bước 2.3 và qua cổng khóa sổ tất định `finalize_v3_phase2` mới được chuyển sang **Phase 3 (Đánh giá Rủi ro Thực tế & Khả năng Khai thác)**.

---

## 1. Bốn Điều kiện Chặn Tất định (`finalize_v3_phase2` — `ARCH-3D`, `ARCH-3G`)

1. **Đối khớp 100% Ứng viên (`100% Candidate Accounting` — `ARCH-3G`)**:
   - `finalize_v3_phase2` kiểm tra mọi `candidate_id` từ `.localsec/runs/default/<repo_name>/candidate_queue.json` đều đã được hạch toán vào `chains[]` hoặc `unexploitable_candidates[]`. Nếu sót bất kỳ `candidate_id` nào, cổng sẽ **FAIL**.
2. **Luật Cứng `request_plan_is_not_execution`**:
   - Nếu chuỗi request chỉ ở trạng thái `plan_only` / `not_executed`, phán quyết tối đa về mặt mã nguồn được tự động áp trần ở `code_supported`, **TUYỆT ĐỐI KHÔNG ĐƯỢC GÁN `confirmed`** (trừ khi đã thực thi thật qua `run_aca_request_plan` trên môi trường local được phê duyệt).
3. **Áp dụng Phản biện Đối kháng từ Bước 2.3**:
   - Bất kỳ chuỗi hoặc mắt xích nào bị Bước 2.3 (`blinded_counterevidence_challenger`) chứng minh có kiểm soát chặn đứng (`refuted_by_counterevidence`) hoặc chưa kiểm tra đủ 6 vị trí trong `control_search_checklist` sẽ bị hạ xuống `refuted` hoặc `partial_or_hypothesis`.
4. **Kiểm tra Ngữ nghĩa Claim-to-Excerpt & Hạ cấp Fail-Closed**:
   - Chạy `verify_semantic_claims` và `finalize_v3_phase2 <repo_name>` để tự động hạ cấp mọi tuyên bố thiếu `ev_...` hoặc lệch ngữ nghĩa, đồng thời xuất danh sách `surviving_chains` cho Phase 3.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Kiểm tra mâu thuẫn ngữ nghĩa giữa tuyên bố và trích đoạn ev_...
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>

# 2. Lưu kết quả cổng kiểm toán Phase 2 (đối chiếu AI-skills/schemas/v3/analysis_evidence_gate.schema.json)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> analysis_evidence_gate /tmp/analysis_evidence_gate_<repo_name>.json

# 3. Khóa sổ Phase 2 tất định: đối khớp 100% candidate_queue, áp trần code_supported và xuất surviving_chains cho Phase 3
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase2 <repo_name>
```

---

## 3. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/analysis_evidence_gate.schema.json`)

```json
{
  "candidate_accounting_complete": true,
  "surviving_chain_ids": [
    "CHAIN-OCPP-STOP-01"
  ],
  "refuted_chain_ids": [],
  "downgraded_chain_ids": [],
  "request_plan_capped_at_code_supported": true,
  "gate_summary": "100% of candidate_queue accounted for; CHAIN-OCPP-STOP-01 upheld across all 6 control locations and capped at code_supported for Phase 3."
}
```
