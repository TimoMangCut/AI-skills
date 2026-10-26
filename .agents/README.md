# Hướng dẫn Sử dụng Bộ 28 Skills Bảo mật 4 Phase — LocalSec v3.0 (`.agents/skills/` & `.claude/skills/`)

Tài liệu này là sổ tay tra cứu chuẩn cách vận hành hệ thống **LocalSec v3.0 AI Security Review Pipeline** qua **4 Phase chuẩn hóa** (`AI-skills/contracts/v3-orchestration.json`, `AI-skills/schemas/v3/*.schema.json`, và `AI-skills/reporting/report.py`) cho hệ sinh thái đa sản phẩm & Cyber-Physical (VinFast Connected Car, V-Green EV Charging OCPP/OCPI, VinEnergo BESS SCADA, VinRobotics `vla.cpp` C++/ZeroMQ/ROS2, WebApps/SPAs, Mobile Super-Apps, Multi-Cloud/Edge Cloudflare/Kong/KrakenD/On-Prem, CI/CD ADO/GitHub/ArgoCD, Data/AI Lakehouse, SAP/MuleSoft).

---

## 1. Tổng quan Kiến trúc 4 Phase (LocalSec v3.0 — 28 Skills Đồng Bộ)

Hệ thống gồm **28 Skills** đồng bộ phần thân giữa `.agents/skills/` (Antigravity) và `.claude/skills/` (Claude Code), kèm định nghĩa subagent cô lập tại `.agents/agents/localsec-blinded-challenger.md` + `.agents/hooks.json` (Antigravity) và `.claude/agents/localsec-blinded-challenger.md` (Claude Code):
- **16 Skills v3.0 (Phase 1, Phase 2, Phase 3):** 3 Master Orchestrators (`/phase-1-orchestrator`, `/phase-2-orchestrator`, `/phase-3-orchestrator`) + 13 Specialist Sub-skills.
- **12 Skills Báo cáo & Đánh giá Rủi ro Thực tế dùng chung (Phase 4 & Phase Risk):** `/phase-4-orchestrator`, `/phase-4-finding-consolidation`, `/phase-4-business-impact`, `/phase-4-architecture-synthesis`, `/phase-4-independent-review`, `/phase-4-report-writer`, `/phase-4-consolidated-report`, `/phase-risk-exploit-path`, `/phase-risk-assessment`, `/phase-risk-cross-link`, `/phase-risk-challenge`, `/phase-risk-verdict`.

| Phase | Master Orchestrator | Các bước cốt lõi | Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|---|
| **Phase 1: Unified Reconnaissance** | `/phase-1-orchestrator` | **6 bước theo thứ tự `Intent Before Code` (`1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`)**: `inventory_repo` + `codebase_scout` $\rightarrow$ `intent_invariant_modeler` $\rightarrow$ `extractor_tailor` $\rightarrow$ `unified_surface_mapper` $\rightarrow$ `match_cross_repo_boundaries` + `cross_repo_and_arch_review` $\rightarrow$ `coverage_and_evidence_auditor` + `finalize_v3_phase1` | Chạy kiểm kê tất định `inventory_repo` trước, dựng mô hình Ý định & Bất biến S-F-O-P-C trước khi đọc code thực thi (`ARCH-3K`), tinh chỉnh Python extractor trên canary files, đọc code theo lô ưu tiên rủi ro (`read_files --module <m> --until-pct 50`, cổng yêu cầu mỗi `target_module` đọc $\ge 50\%$ số dòng nguồn — `target_module_min_line_coverage`), thực hiện rà soát `stride_review` (8 mục) & `pattern_checklist` (10 mục) ở bước `1.5`, và khóa sổ qua `finalize_v3_phase1` để xuất `coverage_matrix.json` & `candidate_queue.json`. |
| **Phase 2: Deep Analysis & Falsification** | `/phase-2-orchestrator` | **3 bước bắt buộc + 1 bước tuỳ chọn (`2.1 -> 2.2 -> 2.3 -> [2.4]`)**: `candidate_intake_planner` $\rightarrow$ `deep_trace_chain_analyst` $\rightarrow$ `blinded_counterevidence_challenger` (Subagent cô lập) $\rightarrow$ `finalize_v3_phase2` (`analysis_evidence_gate` được `finalize_v3_phase2` tự ghi) | Đọc `candidate_queue.json`, tiêm nguyên văn khối `Attack-Class Companion`, truy vết sâu `hops[]` cho 100% ứng viên, xuất gói mù Whitelist qua `prepare_blinded_chain_verifier` (tự động thêm file import 1 cấp `imported_by_hops` và câu hỏi trung tính `claim_to_challenge`), chạy bước `2.3` trong **Subagent cô lập có hook `PreToolUse` bảo vệ**, chép `chains_fingerprint` vào `blinded_package_fingerprint`, và khóa sổ qua `finalize_v3_phase2`. |
| **Phase 3: Contextual Risk & Exploitability** | `/phase-3-orchestrator` | **3 bước (`3.1 -> 3.3` + Per-Repo Report)**: `actor_and_feasibility_assessor` $\rightarrow$ `beyond_code_control_mapper` $\rightarrow$ `sfop_risk_calibrator` + `finalize_v3_phase3` + `render_v3_report` | Đánh giá 100% `chain_id` sống sót (cùng các chuỗi từ `broken_link_splits` nếu có): chứng minh `minimum_actor`, `preconditions[]` (`status`: `yes`/`no`/`unknown`, `holders[]` với `actor_type` + `attainable`, `actors_considered`), đối chiếu kiểm soát ngoài code (`3.2`), hiệu chuẩn rủi ro 5 trục **S-F-O-P-C** (`3.3`), chạy `finalize_v3_phase3` và `render_v3_report`. |
| **Phase 4: Final Synthesis & Canonical Report Generation** | `/phase-4-orchestrator` | **Xuất dữ liệu v3 $\rightarrow$ Collect (`4.1`) $\rightarrow$ Architecture (`4.2`) $\rightarrow$ Consolidation (`4.3`) $\rightarrow$ Business Impact (`4.4`) $\rightarrow$ Phase Risk (`R.1–R.5`) $\rightarrow$ Draft (`4.5`) $\rightarrow$ Independent Review (`4.6`) $\rightarrow$ Final (`4.7`)** | Chạy `python3 -m localsec.manual_session finalize_v3_phase4` để xuất dữ liệu v3 sang `documents/<repo>/`, `documents/_analysis/`, `documents/_system/`, `documents/_v3/`; tiếp theo chạy `python3 AI-skills/reporting/report.py collect`, thực hiện các bước `4.2` $\rightarrow$ `4.3` $\rightarrow$ `4.4` $\rightarrow$ `R.1–R.5` $\rightarrow$ `4.5` $\rightarrow$ `4.6` (subagent/phiên mới) $\rightarrow$ `4.7`, kiểm định bằng `python3 AI-skills/reporting/report.py check --stage final` và kết xuất báo cáo cuối cùng bằng `python3 AI-skills/reporting/report.py render`. |

---

## 2. Ma trận Năng lực Nền tảng (Platform Capability Matrix — Kiểm chứng 2026-10-26)

Cả **Claude Code** và **Google Antigravity** đều hỗ trợ cô lập ngữ cảnh bằng Subagent và chặn lệnh đọc gian lận bằng hook `PreToolUse` trước khi công cụ chạy:

| Năng lực | Claude Code | Google Antigravity |
|---|---|---|
| **Cơ chế tách Subagent ngữ cảnh sạch (Bước 2.3, R.4, 4.6)** | Frontmatter `context: fork` + `agent: localsec-blinded-challenger` trong `.claude/skills/phase-2-blinded-counterevidence-challenger/SKILL.md` kết hợp `.claude/agents/localsec-blinded-challenger.md` ([Claude Code Subagents Docs](https://docs.anthropic.com/en/docs/claude-code/sub-agents)). | Gọi tool `invoke_subagent` với `TypeName: "localsec-blinded-challenger"` (định nghĩa tại `.agents/agents/localsec-blinded-challenger.md`), `Prompt` mở đầu bằng `/phase-2-blinded-counterevidence-challenger <repo_name>` (kèm dấu nhận diện `LOCALSEC_BLINDED_CHALLENGER_CONTEXT`). |
| **Cơ chế Hook `PreToolUse` chặn đọc ngoài Whitelist ở Bước 2.3** | Khai báo `hooks.PreToolUse` trong `.claude/agents/localsec-blinded-challenger.md` chạy `python3 -m localsec.claude_subagent_guard --mode blinded_challenger`; trả mã thoát `2` để chặn lệnh vi phạm ([Claude Code Hooks Docs](https://docs.anthropic.com/en/docs/claude-code/hooks)). | Khai báo `localsec-blinded-guard.PreToolUse` trong `.agents/hooks.json` chạy `localsec.claude_subagent_guard --platform antigravity`; đọc `transcriptPath` để phát hiện phiên có `LOCALSEC_BLINDED_CHALLENGER_CONTEXT` và trả JSON `{"decision": "deny", "reason": "..."}` (exit code `0`) khi tool cố đọc ngoài danh sách cho phép. |
| **Tự kiểm (Self-Check) lúc cài đặt (`setup_bootstrap.py`)** | Tự động tìm trình thông dịch Python hoạt động (`python`, `python3`, `py`), ghi cấu hình hook tương ứng và chạy thử lệnh đọc bị cấm $\rightarrow$ bắt buộc nhận mã thoát `2`. | Tự động tạo transcript thử chứa `LOCALSEC_BLINDED_CHALLENGER_CONTEXT` và gọi thử tool `view_file` vào đường dẫn cấm $\rightarrow$ bắt buộc nhận `"decision": "deny"`. |

---

## 3. Quy ước Đặt tên Repo Lồng nhau & Đường dẫn Chuẩn (Nested Repo Slug Normalization)

Khi dự án có các repo con nằm trong thư mục lồng nhau (ví dụ `vsf-pmns/ehiring/ehiring-backend`), hàm chuẩn hóa `_safe_name` thay dấu `/` và `\` bằng `_`:
- **Tham số `<repo_name>` truyền vào CLI:** có thể truyền đường dẫn tương đối `vsf-pmns/ehiring/ehiring-backend` (hoặc `.` nếu đứng tại repo đơn).
- **Slug chuẩn hóa (`<repo_slug>`):** `vsf-pmns_ehiring_ehiring-backend`.
- **Thư mục trạng thái chuẩn (`run_dir`):** `.localsec/runs/default/vsf-pmns_ehiring_ehiring-backend/` (các lệnh `phase_status` và `prepare_blinded_chain_verifier` đều in rõ trường `"run_dir"` và `"saved_to"` trong JSON đầu ra để kiểm tra ngay).
- **File gói mù Bước 2.3:** `.localsec/tmp/blinded_chains_vsf-pmns_ehiring_ehiring-backend.json`.

---

## 4. Cách 1 (Khuyên dùng): Chạy Trọn Bộ Từng Phase Theo Ranh Giới Phiên `Repo x Phase`

> **Kỷ luật Ranh giới Phiên (`Repo x Phase` Session Boundary):** Mỗi Phase (`Phase 1`, `Phase 2`, `Phase 3`, `Phase 4`) nên được chạy trong một phiên hội thoại mới (fresh session/context) để tránh tràn ngữ cảnh và nhiễm chéo thiên kiến giữa các Phase.

### Bước A — Chạy Toàn bộ Phase 1 (Unified Reconnaissance v3.0 — Intent Before Code)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0) cho toàn bộ repositories theo đúng thứ tự Intent Before Code (1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6).
Áp dụng kỷ luật Refute-first: chạy inventory_repo + codebase_scout, tiếp theo chạy intent_invariant_modeler trước khi đọc code thực thi, chạy extractor_tailor, đọc code qua read_files --until-pct 50 cho từng target_module ở unified_surface_mapper (đảm bảo >= 50% số dòng mỗi module và 100% mandatory_files), chạy match_cross_repo_boundaries + cross_repo_and_arch_review (đầy đủ 8 mục stride_review và 10 mục pattern_checklist), cuối cùng chạy finalize_v3_phase1.
```

### Bước B — Chạy Toàn bộ Phase 2 (Deep Analysis & Falsification v3.0 — Mở Phiên Mới)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0) nối tiếp candidate_queue.json từ Phase 1.
Chạy tuần tự: (2.1) nạp nguyên văn các khối Attack-Class Companion, (2.2) truy vết sâu hops[] + dựng chuỗi tấn công cho 100% candidate_id, chạy prepare_blinded_chain_verifier và (2.3) khởi chạy Subagent cô lập localsec-blinded-challenger (chỉ truyền duy nhất file .localsec/tmp/blinded_chains_<repo_slug>.json, chép chains_fingerprint vào blinded_package_fingerprint) để phản biện đối kháng trên 6 vị trí control_search_checklist, sau đó khóa sổ qua cổng tất định finalize_v3_phase2.
```

### Bước C — Chạy Toàn bộ Phase 3 (Contextual Risk & Exploitability Assessment v3.0 — Mở Phiên Mới)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability Assessment v3.0) cho 100% các chain_id sống sót từ Phase 2.
Chạy tuần tự 3 bước (3.1 -> 3.3): chứng minh minimum_actor, preconditions[] kèm holders[] (who, actor_type, attainable, why, evidence_ids) và actors_considered; đối chiếu các lớp kiểm soát ngoài code (Cloudflare WAF vs Bare ALB, VPC 10.x, mTLS, OT Interlock); hiệu chuẩn rủi ro định lượng 5 trục impact_axes (S-F-O-P-C), sau đó chạy cổng tất định finalize_v3_phase3 và render_v3_report.
```

### Bước D — Chạy Toàn bộ Phase 4 & Phase Risk (Final Synthesis & Canonical Report Generation — Mở Phiên Mới)
```text
/phase-4-orchestrator Thực hiện Phase 4 và Phase Risk cho toàn bộ dự án:
1. Chạy `python3 -m localsec.manual_session finalize_v3_phase4` để xuất dữ liệu v3 sang `documents/<repo>/`, `documents/_analysis/`, `documents/_system/`, `documents/_v3/`.
2. Chạy `python3 AI-skills/reporting/report.py collect` và kiểm tra `python3 AI-skills/reporting/report.py status`.
3. Thực hiện tuần tự Bước 4.2 (`/phase-4-architecture-synthesis`) -> Bước 4.3 (`/phase-4-finding-consolidation`) -> Bước 4.4 (`/phase-4-business-impact`) -> Bước R.1 đến R.5 (`/phase-risk-assessment`: `/phase-risk-exploit-path`, `/phase-risk-cross-link`, `/phase-risk-challenge` ở subagent cô lập, `/phase-risk-verdict`) -> Bước 4.5 (`/phase-4-report-writer` nháp) -> Bước 4.6 (`/phase-4-independent-review` trong subagent cô lập) -> Bước 4.7 (`/phase-4-report-writer` chốt).
4. Kiểm định bằng `python3 AI-skills/reporting/report.py check --stage final` và kết xuất báo cáo chính thức bằng `python3 AI-skills/reporting/report.py render`.
```

---

## 5. Cách 2: Bảng Tra cứu Chi tiết 28 Skills (`16` Skills v3.0 + `12` Skills Báo cáo/Risk)

### PHASE 1 — Unified Reconnaissance (`/phase-1-*` — 7 Skills, Thứ tự: `1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`)

| Thứ tự | Lệnh Skill | Schema Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|
| **1.0** | `/phase-1-orchestrator` | Điều phối trọn bộ 6 bước Phase 1 theo `AI-skills/contracts/v3-orchestration.json`, kết thúc bằng `finalize_v3_phase1`. |
| **1.1** | `/phase-1-codebase-scout` | Chạy `inventory_repo` trước, khảo sát cấu trúc thư mục và lập `Target Modules Map` bao phủ 100% thư mục chứa `entrypoint`/`security` files (`AI-skills/schemas/v3/codebase_scout.schema.json`). |
| **1.3** | `/phase-1-intent-invariant-modeler` | Chạy **TRƯỚC khi đọc code thực thi (`ARCH-3K`)**: dựng mô hình Ý định Nghiệp vụ & Bất biến S-F-O-P-C từ tài liệu/spec/manifest (`AI-skills/schemas/v3/intent_invariant_modeler.schema.json`). |
| **1.2** | `/phase-1-extractor-tailor` | Đánh giá/tinh chỉnh Python structural extractor trên `canary_files` với `--patterns-file` và `--expected-canary-hits` (`AI-skills/schemas/v3/extractor_tailor.schema.json`). |
| **1.4** | `/phase-1-unified-surface-mapper` | Đọc mã nguồn 1 lượt qua `read_files --module <m> --until-pct 50` (đạt $\ge 50\%$ số dòng mỗi `target_module` và 100% `mandatory_files`): kiểm kê 9 loại bề mặt `surface_checklist`, `entrypoints[]`, Safe Semantic Clustering, `invariant_checks[]`, `data_flows[]`, `sensitive_data[]` (`AI-skills/schemas/v3/unified_surface_mapper.schema.json` & `AI-skills/schemas/v3/coverage_ledger.schema.json`). |
| **1.5** | `/phase-1-cross-repo-and-arch-review` | Chạy `match_cross_repo_boundaries` trước, hoàn thành đủ 8 mục `stride_review` và 10 mục `pattern_checklist`, phát hiện lệch giả định tin cậy xuyên repo (`AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`). |
| **1.6** | `/phase-1-coverage-and-evidence-auditor` | Cổng kiểm toán độc lập và chạy `finalize_v3_phase1` để xuất `coverage_matrix.json` cùng `candidate_queue.json` (`AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json`). |

### PHASE 2 — Deep Analysis & Falsification (`/phase-2-*` — 5 Skills)

| Thứ tự | Lệnh Skill | Schema Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|
| **2.0** | `/phase-2-orchestrator` | Điều phối trọn bộ Phase 2 trên `candidate_queue.json`, kết thúc bằng `finalize_v3_phase2`. |
| **2.1** | `/phase-2-candidate-intake-planner` | Đọc `candidate_queue.json`, chạy `select_attack_companions` xuất `selected_attack_companions.json` (`AI-skills/schemas/v3/candidate_intake_planner.schema.json`). |
| **2.2** | `/phase-2-deep-trace-chain-analyst` | Hạch toán 100% `candidate_id` vào `chains[]` hoặc `unexploitable_candidates[]`, truy vết `hops[]` kèm `hop_kind` và bằng chứng hai đầu (`AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`). |
| **2.3** | `/phase-2-blinded-counterevidence-challenger` | Chạy trong **Subagent cô lập (`localsec-blinded-challenger`)** chỉ nhận file `.localsec/tmp/blinded_chains_<repo_slug>.json`, chép `chains_fingerprint` sang `blinded_package_fingerprint`, kiểm tra đủ 6 vị trí `control_search_checklist` (`AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json`). |
| **2.4** | `/phase-2-analysis-evidence-gate` | *(Tuỳ chọn — `finalize_v3_phase2` tự ghi `analysis_evidence_gate.json`)* Cổng khóa sổ tất định `finalize_v3_phase2` (`AI-skills/schemas/v3/analysis_evidence_gate.schema.json`). |

### PHASE 3 — Contextual Risk & Exploitability Assessment (`/phase-3-*` — 4 Skills)

| Thứ tự | Lệnh Skill | Schema Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|
| **3.0** | `/phase-3-orchestrator` | Điều phối trọn bộ Phase 3, cổng khóa sổ tất định `finalize_v3_phase3` và `render_v3_report`. |
| **3.1** | `/phase-3-actor-and-feasibility-assessor` | Giữ nguyên `chain_id` từ Phase 2, chứng minh `minimum_actor`, `preconditions[]` (`status`: `yes`/`no`/`unknown`, `holders[]`, `actors_considered`) (`AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`). |
| **3.2** | `/phase-3-beyond-code-control-mapper` | Nạp `ingest_runtime_facts` (nếu có) và đánh giá kiểm soát ngoài mã nguồn với `status`: `confirmed`/`hypothesis`/`absent` (`AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`). |
| **3.3** | `/phase-3-sfop-risk-calibrator` | Hiệu chuẩn rủi ro 5 trục `impact_axes` (**S-F-O-P-C**), chạy `finalize_v3_phase3` và `render_v3_report` (`AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`). |

### PHASE 4 & PHASE RISK — Final Synthesis, Contextual Risk Calibration & Report Generation (12 Skills)

| Thứ tự | Lệnh Skill | Chức năng & Cổng kiểm định (`AI-skills/reporting/report.py`) |
|---|---|---|
| **4.0** | `/phase-4-orchestrator` | Điều phối trọn bộ Phase 4: `finalize_v3_phase4` $\rightarrow$ `python3 AI-skills/reporting/report.py collect` $\rightarrow$ `4.2` $\rightarrow$ `4.3` $\rightarrow$ `4.4` $\rightarrow$ `R.1–R.5` $\rightarrow$ `4.5` $\rightarrow$ `4.6` $\rightarrow$ `4.7` $\rightarrow$ `python3 AI-skills/reporting/report.py check --stage final` $\rightarrow$ `python3 AI-skills/reporting/report.py render`. |
| **4.0b** | `/phase-4-consolidated-report` | Sổ tay tham chiếu toàn bộ quy trình tổng hợp báo cáo Phase 4 và các cổng kiểm định `AI-skills/reporting/report.py`. |
| **4.2** | `/phase-4-architecture-synthesis` | Tổng hợp bức tranh kiến trúc theo cụm nghiệp vụ (`documents/_report/work/architecture.json`, kiểm qua `python3 AI-skills/reporting/report.py check --stage architecture`). |
| **4.3** | `/phase-4-finding-consolidation` | Hợp nhất các phát hiện trùng nguyên nhân gốc thành danh sách chuẩn `F-01..F-NN` (`documents/_report/work/consolidation.json`, kiểm qua `python3 AI-skills/reporting/report.py check --stage findings`). |
| **4.4** | `/phase-4-business-impact` | Đánh giá tác động nghiệp vụ và kịch bản lạm dụng thực tế cho từng `F-xx` (`documents/_report/work/impact.json`, kiểm qua `python3 AI-skills/reporting/report.py check --stage impact`). |
| **R.0** | `/phase-risk-assessment` | Điểm vào điều phối Phase Risk (`R.1` $\rightarrow$ `R.2` $\rightarrow$ `R.3` $\rightarrow$ `R.4` $\rightarrow$ `R.5`). |
| **R.1** | `/phase-risk-exploit-path` | Dựng đường khai thác thực tế theo từng loại người tấn công (`actors`, `preconditions`, `holders`, `blocking_controls`) trên `documents/_report/work/risk/F-xx.json` (`python3 AI-skills/reporting/report.py check --stage risk-paths`). |
| **R.2** | `/phase-risk-cross-link` | Ghép chéo điểm yếu qua `python3 AI-skills/reporting/report.py risk-digest` và ghi `documents/_report/work/risk/_combinations.json`. |
| **R.3 & R.5** | `/phase-risk-verdict` | Viết lập luận kết luận (`verdict`), chạy `python3 AI-skills/reporting/report.py check --stage risk`, `render-risk --draft`, `risk-ack`, và `render-risk`. |
| **R.4** | `/phase-risk-challenge` | Thách thức độc lập hai chiều theo lô trong ngữ cảnh sạch (subagent cô lập), ghi `documents/_report/work/risk_review/<batch>.json`. |
| **4.5 & 4.7** | `/phase-4-report-writer` | Viết tóm tắt điều hành, lộ trình khắc phục, nối kiến trúc với `F-xx` (`render --draft`); sau rà soát thì chạy `review-ack`, `check --stage final` và `render`. |
| **4.6** | `/phase-4-independent-review` | Rà soát độc lập bản nháp Báo cáo tổng hợp trong subagent/phiên mới (`documents/_report/work/review.json`). |

---

## 6. Bảng Tra cứu Nhanh Các Lệnh CLI Chuẩn (`python3 -m localsec.manual_session` & `AI-skills/reporting/report.py`)

Trên nhánh `mac`, `setup.sh` tự động cài cầu nối package `localsec` và thư mục tạm `.localsec/tmp/` tại `<Project-Root>`, giúp mọi thao tác chạy trực tiếp trên cả **PowerShell**, **CMD**, và **Git Bash**:

```bash
# 1. Các lệnh v3.0 Phase 1 (Inventory, AI Scout, Batch Read >= 50%, Coverage Status, Cross-Repo Match, Finalize Phase 1)
python3 -m localsec.manual_session inventory_repo <repo_name> --tier 1
python3 -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout_<repo_name>.json
python3 -m localsec.manual_session run_tailored_extractor <repo_name> --mode TAILOR_CUSTOM_EXTRACTOR --canary-files <file1> --patterns-file .localsec/tmp/patterns.json --expected-canary-hits 1
python3 -m localsec.manual_session read_files <repo_name> --module <module> --until-pct 50 --skill unified_surface_mapper
python3 -m localsec.manual_session coverage_status <repo_name>
python3 -m localsec.manual_session select_attack_companions <repo_name> --archetypes connected_car_and_ota ev_charging_and_energy
python3 -m localsec.manual_session match_cross_repo_boundaries
python3 -m localsec.manual_session audit_visibility <repo_name>
python3 -m localsec.manual_session verify_semantic_claims <repo_name>
python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>
python3 -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 2. Các lệnh v3.0 Phase 2 & Phase 3 (Show Evidence, Isolated Challenger, Finalize Phase 2/3, Runtime Facts, Render Report)
python3 -m localsec.manual_session show_evidence <repo_name> <ev_id>
python3 -m localsec.manual_session list_evidence <repo_name>   # không dùng trong bước 2.3
python3 -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>
python3 -m localsec.manual_session finalize_v3_phase2 <repo_name>
python3 -m localsec.manual_session ingest_runtime_facts <repo_name> .localsec/tmp/runtime_facts.json
python3 -m localsec.manual_session finalize_v3_phase3 <repo_name>
python3 -m localsec.manual_session render_v3_report <repo_name>

# 3. Các lệnh Phase 4 & Phase Risk (Export v3 -> Collect -> Check -> Render)
python3 -m localsec.manual_session finalize_v3_phase4
python3 AI-skills/reporting/report.py collect
python3 AI-skills/reporting/report.py status
python3 AI-skills/reporting/report.py catalog
python3 AI-skills/reporting/report.py check --stage architecture
python3 AI-skills/reporting/report.py check --stage findings
python3 AI-skills/reporting/report.py check --stage impact
python3 AI-skills/reporting/report.py access --for F-01
python3 AI-skills/reporting/report.py check --stage risk-paths --only F-01
python3 AI-skills/reporting/report.py risk-digest
python3 AI-skills/reporting/report.py check --stage risk
python3 AI-skills/reporting/report.py render-risk --draft
python3 AI-skills/reporting/report.py risk-ack
python3 AI-skills/reporting/report.py render-risk
python3 AI-skills/reporting/report.py render --draft
python3 AI-skills/reporting/report.py review-ack
python3 AI-skills/reporting/report.py check --stage final
python3 AI-skills/reporting/report.py render

# 4. Kiểm tra tiến độ hoàn thành các bước của một Phase (1, 2, 3 hoặc 4)
python3 -m localsec.manual_session phase_status <repo_name> --phase 1
python3 -m localsec.manual_session phase_status <repo_name> --phase 2
python3 -m localsec.manual_session phase_status <repo_name> --phase 3
python3 -m localsec.manual_session phase_status <repo_name> --phase 4

# 5. Duyệt thư mục, đọc file thủ công (bao gồm liên repo) và nộp kết quả JSON của skill
python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>
python3 -m localsec.manual_session read_file <repo_name> "<other_repo>:<rel_path>" <start_line> <end_line> --skill intent_invariant_modeler
python3 -m localsec.manual_session submit_skill <repo_name> <skill_name> .localsec/tmp/<skill_name>_<repo_name>.json
```

---

## 7. Hướng dẫn Áp Dụng Bộ Skills Vào Dự Án Mới Trên macOS / Linux (`<Project-Root>\AI-skills\`)

1. **Clone nhánh `mac` của `AI-skills` vào trong `<Project-Root>` và chạy `setup.ps1` (hoặc `setup.bat`)**:
   ```bash
   cd <Project-Root>
   git clone -b mac https://github.com/TimoMangCut/AI-skills.git
   sh AI-skills/setup.sh
   # Hoặc trên CMD:      AI-skills\setup.bat
   # Hoặc trên Git Bash: sh AI-skills/setup.sh
   ```
   - `setup.sh` đồng bộ **28 skills** vào `<Project-Root>\.agents\skills\` và `<Project-Root>\.claude\skills\`, đồng bộ subagent cô lập `.agents\agents\localsec-blinded-challenger.md` + `.agents\hooks.json` (Antigravity) và `.claude\agents\localsec-blinded-challenger.md` (Claude Code), tự kiểm (self-check) cả hai hook bước mù, tạo cầu nối `<Project-Root>\localsec\__init__.py` cùng `<Project-Root>\.localsec\tmp\`, gộp an toàn `AGENTS.md` / `SOUL.md` / `CLAUDE.md` và cập nhật `.git/info/exclude`.
   - Nếu dự án có sẵn các skill ngoại lai cần dọn sạch khi cài đặt, truyền thêm cờ `--replace-foreign`.
   - Khi muốn gỡ bộ skills khỏi `<Project-Root>`: chạy `sh AI-skills/setup.sh --uninstall` (hoặc `AI-skills\setup.bat --uninstall`).
2. **Kiểm tra bộ cổng kiểm định (Unit Tests)**:
   ```bash
   python3 -m unittest discover -s AI-skills/tests
   ```
