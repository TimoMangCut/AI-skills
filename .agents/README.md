# Hướng dẫn Sử dụng Bộ 16 Skills Bảo mật 3 Phase — LocalSec v3.0 (`.agents/skills/` & `.claude/skills/`)

Tài liệu này là sổ tay tra cứu nhanh cách vận hành hệ thống **LocalSec v3.0 AI Security Review Pipeline** qua **3 Phase chuẩn hóa** (`AI-skills/contracts/v3-orchestration.json` và `AI-skills/schemas/v3/*.schema.json`) cho hệ sinh thái đa sản phẩm & Cyber-Physical (VinFast Connected Car, V-Green EV Charging OCPP/OCPI, VinEnergo BESS SCADA, VinRobotics `vla.cpp` C++/ZeroMQ/ROS2, WebApps/SPAs, Mobile Super-Apps, Multi-Cloud/Edge Cloudflare/Kong/KrakenD/On-Prem, CI/CD ADO/GitHub/ArgoCD, Data/AI Lakehouse, SAP/MuleSoft).

---

## 1. Tổng quan Kiến trúc 3 Phase (LocalSec v3.0 — 16 Skills Tinh Gọn)

Hệ thống gồm **16 Skills thuần v3.0** đồng bộ 100% giữa `.agents/skills/` (Antigravity) và `.claude/skills/` (Claude Code), chia thành **3 Master Orchestrators** và **13 Specialist Sub-skills**:

| Phase | Master Orchestrator | Các bước cốt lõi (13 Sub-skills v3.0) | Mục tiêu cốt lõi |
|---|---|---|---|
| **Phase 1: Unified Reconnaissance** | `/phase-1-orchestrator` | **6 bước theo thứ tự `Intent Before Code` (`1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`)**: `inventory_repo` + `codebase_scout` $\rightarrow$ `intent_invariant_modeler` $\rightarrow$ `extractor_tailor` $\rightarrow$ `unified_surface_mapper` $\rightarrow$ `match_cross_repo_boundaries` + `cross_repo_and_arch_review` $\rightarrow$ `coverage_and_evidence_auditor` + `finalize_v3_phase1` | Chạy kiểm kê tất định `inventory_repo` trước, dựng mô hình Ý định & Bất biến S-F-O-P-C trước khi đọc code thực thi (`ARCH-3K`), tinh chỉnh Python extractor trên canary files (`--patterns-file`, `--expected-canary-hits`), đọc code 1 lượt kèm gom cụm ngữ nghĩa an toàn (`ARCH-3F`), ghép cặp ranh giới liên repo và khóa sổ qua `finalize_v3_phase1` để xuất `coverage_matrix.json` & `candidate_queue.json`. |
| **Phase 2: Deep Analysis & Falsification** | `/phase-2-orchestrator` | **4 bước (`2.1 -> 2.4`)**: `candidate_intake_planner` $\rightarrow$ `deep_trace_chain_analyst` $\rightarrow$ `blinded_counterevidence_challenger` (Subagent cô lập) $\rightarrow$ `analysis_evidence_gate` + `finalize_v3_phase2` | Đọc `candidate_queue.json` từ Phase 1, tiêm nguyên văn khối `Attack-Class Companion` vào `selected_attack_companions.json`, truy vết sâu `hops[]` kèm `hop_kind` cho 100% ứng viên (`ARCH-3G`), phản biện bác bỏ trong Subagent cô lập (`ARCH-3E`) trên 6 vị trí `control_search_checklist`, và khóa sổ qua `finalize_v3_phase2`. |
| **Phase 3: Contextual Risk & Exploitability** | `/phase-3-orchestrator` | **3 bước (`3.1 -> 3.3` + Report)**: `actor_and_feasibility_assessor` $\rightarrow$ `beyond_code_control_mapper` $\rightarrow$ `sfop_risk_calibrator` + `finalize_v3_phase3` + `render_v3_report` | Đánh giá 100% `chain_id` sống sót từ Phase 2: chứng minh Actor/Role tối thiểu và điều kiện tiên quyết `yes`/`no`/`unknown`, nạp `ingest_runtime_facts` và đối chiếu kiểm soát ngoài code (Cloudflare WAF, Bare ALB, VPC `10.x`, mTLS, OT Interlock), hiệu chuẩn rủi ro định lượng 5 trục **S-F-O-P-C**, chạy `finalize_v3_phase3` và kết xuất báo cáo qua `render_v3_report`. |

---

## 2. Cách 1 (Khuyên dùng): Chạy Trọn Bộ Từng Phase Theo Ranh Giới Phiên `Repo x Phase`

> **Kỷ luật Ranh giới Phiên (`Repo x Phase` Session Boundary):** Mỗi Phase (`Phase 1`, `Phase 2`, `Phase 3`) nên được chạy trong một phiên hội thoại mới (fresh session/context) để tránh tràn ngữ cảnh và nhiễm chéo thiên kiến giữa các Phase. Cuối mỗi Phase, Orchestrator bắt buộc chạy cổng khóa sổ (`finalize_v3_phase1` / `finalize_v3_phase2` / `finalize_v3_phase3`) và in ra lệnh chính xác để khởi chạy Phase kế tiếp.

### Bước A — Chạy Toàn bộ Phase 1 (Unified Reconnaissance v3.0 — Intent Before Code)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0) cho toàn bộ repositories theo đúng thứ tự Intent Before Code (1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6).
Áp dụng kỷ luật Refute-first: chạy inventory_repo + codebase_scout, tiếp theo chạy intent_invariant_modeler trước khi đọc code thực thi, chạy extractor_tailor, unified_surface_mapper, match_cross_repo_boundaries + cross_repo_and_arch_review, cuối cùng chạy coverage_and_evidence_auditor và cổng khóa sổ tất định finalize_v3_phase1.
```

### Bước B — Chạy Toàn bộ Phase 2 (Deep Analysis & Falsification v3.0 — Mở Phiên Mới)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0) nối tiếp candidate_queue.json từ Phase 1.
Chạy tuần tự 4 bước (2.1 -> 2.4): nạp nguyên văn các khối Attack-Class Companion, truy vết sâu hops[] (kèm hop_kind) + dựng chuỗi tấn công + tìm Root-Cause cho 100% candidate_id, chạy prepare_blinded_chain_verifier và khởi chạy Subagent cô lập (chỉ truyền duy nhất file .localsec/tmp/blinded_chains_<repo_name>.json) để phản biện đối kháng ở chế độ Mù Kết luận trên 6 vị trí control_search_checklist, và khóa sổ qua analysis_evidence_gate cùng cổng tất định finalize_v3_phase2.
```

### Bước C — Chạy Toàn bộ Phase 3 (Contextual Risk & Exploitability Assessment v3.0 — Mở Phiên Mới)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability Assessment v3.0) cho 100% các chain_id sống sót từ Phase 2.
Chạy tuần tự 3 bước (3.1 -> 3.3): chứng minh minimum_actor và điều kiện tiên quyết yes/no/unknown, đối chiếu các lớp kiểm soát ngoài code (Cloudflare WAF vs Bare ALB, VPC 10.x, mTLS, OT Interlock với status confirmed/hypothesis/absent), hiệu chuẩn rủi ro định lượng 5 trục impact_axes (S-F-O-P-C), sau đó chạy cổng tất định finalize_v3_phase3 và render_v3_report.
```

---

## 3. Cách 2: Bảng Tra cứu Chi tiết 16 Skills Chuẩn v3.0

### PHASE 1 — Unified Reconnaissance (`/phase-1-*` — 7 Skills, Thứ tự Thực thi: `1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`)

| Thứ tự | Lệnh Skill | Schema Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|
| **1.0** | `/phase-1-orchestrator` | Điều phối trọn bộ 6 bước Phase 1 Unified Reconnaissance v3.0 theo `AI-skills/contracts/v3-orchestration.json`, kết thúc bằng `finalize_v3_phase1` và in lệnh chuyển sang Phase 2. |
| **1.1** | `/phase-1-codebase-scout` | Chạy `inventory_repo` trước, khảo sát cấu trúc thư mục và lập `Target Modules Map` bao phủ 100% thư mục chứa `entrypoint`/`security` files (`AI-skills/schemas/v3/codebase_scout.schema.json`). |
| **1.3** | `/phase-1-intent-invariant-modeler` | Chạy **TRƯỚC khi đọc code thực thi (`ARCH-3K`)**: dựng mô hình Ý định Nghiệp vụ & Bất biến S-F-O-P-C từ tài liệu/spec/manifest và tự rà soát phản biện bất biến (`AI-skills/schemas/v3/intent_invariant_modeler.schema.json`). |
| **1.2** | `/phase-1-extractor-tailor` | Đánh giá/tinh chỉnh Python structural extractor trên `canary_files` với `--patterns-file` và `--expected-canary-hits` (`AI-skills/schemas/v3/extractor_tailor.schema.json`). |
| **1.4** | `/phase-1-unified-surface-mapper` | Đọc mã nguồn 1 lượt (Single-Pass): kiểm kê 9 loại bề mặt (`surface_checklist`), `entrypoints[]` giàu ngữ cảnh, Safe Semantic Clustering (`ARCH-3F`), `invariant_checks[]`, `data_flows[]`, `sensitive_data[]`, `records[]` (`AI-skills/schemas/v3/unified_surface_mapper.schema.json` & `AI-skills/schemas/v3/coverage_ledger.schema.json`). |
| **1.5** | `/phase-1-cross-repo-and-arch-review` | Chạy `match_cross_repo_boundaries` trước, phát hiện lệch giả định tin cậy xuyên repo và vẽ sơ đồ Mermaid (`AI-skills/schemas/v3/cross_repo_and_arch_review.schema.json`). |
| **1.6** | `/phase-1-coverage-and-evidence-auditor` | Cổng kiểm toán độc lập và chạy cổng khóa sổ tất định `finalize_v3_phase1` để xuất `coverage_matrix.json` cùng `candidate_queue.json` (`AI-skills/schemas/v3/coverage_and_evidence_auditor.schema.json`). |

### PHASE 2 — Deep Analysis & Falsification (`/phase-2-*` — 5 Skills)

| Thứ tự | Lệnh Skill | Schema Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|
| **2.0** | `/phase-2-orchestrator` | Điều phối trọn bộ 4 bước Phase 2 Deep Analysis & Falsification v3.0 trên `candidate_queue.json`, kết thúc bằng `finalize_v3_phase2` và in lệnh chuyển sang Phase 3. |
| **2.1** | `/phase-2-candidate-intake-planner` | Đọc `candidate_queue.json`, chạy `select_attack_companions` xuất `selected_attack_companions.json` (`AI-skills/schemas/v3/candidate_intake_planner.schema.json`). |
| **2.2** | `/phase-2-deep-trace-chain-analyst` | Hạch toán 100% `candidate_id` vào `chains[]` hoặc `unexploitable_candidates[]`, truy vết `hops[]` kèm `hop_kind` và bằng chứng hai đầu (`AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`). |
| **2.3** | `/phase-2-blinded-counterevidence-challenger` | Chạy trong **Subagent cô lập / Fresh Context (`ARCH-3E`)** chỉ nhận duy nhất file Whitelist `.localsec/tmp/blinded_chains_<repo_name>.json` (gồm `control_search_paths`), kiểm tra đủ 6 vị trí `control_search_checklist` (`AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json`). |
| **2.4** | `/phase-2-analysis-evidence-gate` | Cổng kiểm toán bằng chứng và chạy cổng khóa sổ tất định `finalize_v3_phase2` để bàn giao các chuỗi sống sót sang Phase 3 (`AI-skills/schemas/v3/analysis_evidence_gate.schema.json`). |

### PHASE 3 — Contextual Risk & Exploitability Assessment (`/phase-3-*` — 4 Skills)

| Thứ tự | Lệnh Skill | Schema Mục tiêu & Cổng kiểm định cốt lõi |
|---|---|---|
| **3.0** | `/phase-3-orchestrator` | Điều phối trọn bộ Phase 3, cổng khóa sổ tất định `finalize_v3_phase3` và `render_v3_report`. |
| **3.1** | `/phase-3-actor-and-feasibility-assessor` | Giữ nguyên `chain_id` từ Phase 2, chứng minh `minimum_actor` và lượng hóa `preconditions[]` với `precondition_status`: `yes`/`no`/`unknown` (`AI-skills/schemas/v3/actor_and_feasibility_assessor.schema.json`). |
| **3.2** | `/phase-3-beyond-code-control-mapper` | Nạp `ingest_runtime_facts` (nếu có) và đánh giá kiểm soát ngoài mã nguồn với `present`: `yes`/`no`/`unknown`, `status`: `confirmed`/`hypothesis`/`absent` (`AI-skills/schemas/v3/beyond_code_control_mapper.schema.json`). |
| **3.3** | `/phase-3-sfop-risk-calibrator` | Hiệu chuẩn rủi ro 5 trục `impact_axes` (**S-F-O-P-C**) theo rubric định lượng (`basis` + `blast_radius`, chỉ báo an toàn `actuator_command_path_without_interlock`, `risk_owner`/`safety_owner` với `owner_role`), chạy `finalize_v3_phase3` và `render_v3_report` (`AI-skills/schemas/v3/sfop_risk_calibrator.schema.json`). |

---

## 4. Bảng Tra cứu Nhanh Các Lệnh CLI Chuẩn Windows (`python -m localsec.manual_session`)

Trên nhánh `wins`, `setup.ps1` / `setup.bat` tự động cài cầu nối package `localsec` và thư mục tạm `.localsec/tmp/` tại `<Project-Root>`, giúp mọi thao tác chạy trực tiếp qua `python -m localsec.manual_session` trên cả **PowerShell**, **CMD**, và **Git Bash**:

```powershell
# 1. Các lệnh v3.0 Phase 1 (Inventory, AI Scout, Tailored Extractor, Attack Companions, Cross-Repo Match, Finalize Phase 1)
python -m localsec.manual_session inventory_repo <repo_name> --tier 1
python -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout_<repo_name>.json
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode TAILOR_CUSTOM_EXTRACTOR --canary-files <file1> --patterns-file .localsec/tmp/patterns.json --expected-canary-hits 1
python -m localsec.manual_session select_attack_companions <repo_name> --archetypes connected_car_and_ota ev_charging_and_energy
python -m localsec.manual_session match_cross_repo_boundaries
python -m localsec.manual_session audit_visibility <repo_name>
python -m localsec.manual_session verify_semantic_claims <repo_name>
python -m localsec.manual_session finalize_v3_phase1 <repo_name>
python -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 2. Các lệnh v3.0 Phase 2 & Phase 3 (Show Evidence, Isolated Challenger, Finalize Phase 2/3, Runtime Facts, Render Report)
python -m localsec.manual_session show_evidence <repo_name> <ev_id>
python -m localsec.manual_session list_evidence <repo_name>
python -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>
python -m localsec.manual_session finalize_v3_phase2 <repo_name>
python -m localsec.manual_session ingest_runtime_facts <repo_name> .localsec/tmp/runtime_facts.json
python -m localsec.manual_session finalize_v3_phase3 <repo_name>
python -m localsec.manual_session render_v3_report <repo_name>

# 3. Kiểm tra tiến độ hoàn thành các bước của một Phase (1, 2 hoặc 3)
python -m localsec.manual_session phase_status <repo_name> --phase 1
python -m localsec.manual_session phase_status <repo_name> --phase 2
python -m localsec.manual_session phase_status <repo_name> --phase 3

# 4. Duyệt thư mục, đọc file thủ công (bao gồm liên repo) và nộp kết quả JSON của skill
python -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
python -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>
python -m localsec.manual_session read_file <repo_name> "<other_repo>:<rel_path>" <start_line> <end_line> --skill intent_invariant_modeler
python -m localsec.manual_session submit_skill <repo_name> <skill_name> .localsec/tmp/<skill_name>_<repo_name>.json
```

---

## 5. Hướng dẫn Áp Dụng Bộ Skills Vào Dự Án Mới Trên Windows (`<Project-Root>\AI-skills\`)

1. **Clone nhánh `wins` của `AI-skills` vào trong `<Project-Root>` và chạy `setup.ps1` (hoặc `setup.bat`)**:
   ```powershell
   cd <Project-Root>
   git clone -b wins https://github.com/TimoMangCut/AI-skills.git
   .\AI-skills\setup.ps1
   # Hoặc trên CMD:      AI-skills\setup.bat
   # Hoặc trên Git Bash: sh AI-skills/setup.sh
   ```
   - `setup.ps1` / `setup.bat` đồng bộ **16 skills v3** vào `<Project-Root>\.agents\skills\` và `<Project-Root>\.claude\skills\`, tạo cầu nối `<Project-Root>\localsec\__init__.py` cùng `<Project-Root>\.localsec\tmp\`, gộp an toàn `AGENTS.md` / `SOUL.md` / `CLAUDE.md` và cập nhật `.git/info/exclude`.
   - Khi muốn gỡ bộ skills khỏi `<Project-Root>`: chạy `.\AI-skills\setup.ps1 --uninstall` (hoặc `AI-skills\setup.bat --uninstall`).
2. **Kiểm tra bộ cổng kiểm định (Unit Tests)**:
   ```powershell
   python -m unittest discover -s AI-skills/tests
   ```
