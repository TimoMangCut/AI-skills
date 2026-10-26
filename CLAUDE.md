# CLAUDE.md — LocalSec v3.0 Security Review Pipeline (`AI-skills` — Windows Edition)

## Import (nạp lúc khởi động)
@SOUL.md
@AGENTS.md

## Vai trò & Kiến trúc Hệ thống (v3.0 — Windows Native)
Bạn đang vận hành **LocalSec v3.0 Security Review Pipeline** trên môi trường **Windows (PowerShell / CMD / Git Bash)**, kết hợp bộ **28 Skills** (trong `.claude/skills/` cho Claude Code và `.agents/skills/` cho Antigravity) cùng định nghĩa subagent cô lập `.claude/agents/localsec-blinded-challenger.md` + `.agents/agents/localsec-blinded-challenger.md` + `.agents/hooks.json` với **Python Epistemic Engine (`python -m localsec.manual_session` & `python AI-skills/reporting/report.py`)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`:

- **Phase 1 — Unified Reconnaissance (`/phase-1-orchestrator` — thứ tự `Intent Before Code`: `1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`):** Chạy `inventory_repo` + khảo sát cấu trúc & quy ước bằng AI (`codebase_scout`), dựng mô hình Ý định & Bất biến An toàn S-F-O-P-C trước khi đọc code thực thi (`intent_invariant_modeler` — `ARCH-3K`), tinh chỉnh/kiểm thử Python extractor trên canary files với `--patterns-file` và `--expected-canary-hits` (`extractor_tailor`), đọc mã nguồn theo lô ưu tiên rủi ro `read_files --module <m> --until-pct 50` kèm gom cụm ngữ nghĩa an toàn (`unified_surface_mapper` — `ARCH-3F`, `C3`), ghép cặp ranh giới liên repo `match_cross_repo_boundaries` + đánh giá kiến trúc xuyên repo với `stride_review` & `pattern_checklist` (`cross_repo_and_arch_review`), và khóa sổ qua `coverage_and_evidence_auditor` + cổng tất định `finalize_v3_phase1` (xuất `coverage_matrix.json` & `candidate_queue.json`, đối chiếu cả 9/9 loại bề mặt `surface_checklist` — `C4`, và bảo toàn `unassigned_project_external_findings` — `C5`).
- **Phase 2 — Deep Analysis & Falsification (`/phase-2-orchestrator` — `2.1 -> 2.3 -> finalize_v3_phase2`):** Đọc `candidate_queue.json` từ Phase 1 và nạp nguyên văn các mô-đun `Attack-Class Companion` ra `selected_attack_companions.json` (`candidate_intake_planner`), truy vết sâu từng bước nhảy `hops[]` kèm `hop_kind` + dựng chuỗi tấn công + truy nguyên nhân gốc cho 100% ứng viên (`deep_trace_chain_analyst` — `ARCH-3G`, `R3-A4`), phản biện bác bỏ trong **Subagent cô lập / Fresh Context (`blinded_counterevidence_challenger` — `ARCH-3E`, `context: fork`, `agent: localsec-blinded-challenger`, bảo vệ bởi PreToolUse hook `localsec/claude_subagent_guard.py` — `R3-A7`, `C1`)** chỉ nhận duy nhất file Whitelist `.localsec/tmp/blinded_chains_<repo_name>.json` (chép `chains_fingerprint` sang `blinded_package_fingerprint`) và kiểm tra đủ 6 vị trí kiểm soát cố định (`control_search_checklist`), sau đó khóa sổ qua cổng tất định `finalize_v3_phase2` (`analysis_evidence_gate.json` được `finalize_v3_phase2` tự ghi).
- **Phase 3 — Contextual Risk & Exploitability Assessment (`/phase-3-orchestrator` — 3 bước `3.1 -> 3.3` + `render_v3_report`):** Đánh giá 100% `chain_id` sống sót từ Phase 2: chứng minh `minimum_actor` và điều kiện tiên quyết `preconditions[].status`: `yes`/`no`/`unknown` kèm `holders[]` và `actors_considered` (`actor_and_feasibility_assessor`), nạp `ingest_runtime_facts` (nếu có) và đối chiếu các lớp kiểm soát ngoài code như Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC `10.x`, mTLS, OT Interlock với `status`: `confirmed`/`hypothesis`/`absent` (`beyond_code_control_mapper`), hiệu chuẩn rủi ro thực tế trên **5 trục `impact_axes` (S-F-O-P-C)** theo rubric định lượng kèm `"owner_role"` bắt buộc (`sfop_risk_calibrator`), khóa sổ bằng cổng tất định `finalize_v3_phase3` và xuất báo cáo per-repo qua `render_v3_report`.
- **Phase 4 & Phase Risk — Final Synthesis & Canonical Report Generation (`/phase-4-orchestrator`, `/phase-4-consolidated-report`, `/phase-risk-assessment`):** Chạy `python -m localsec.manual_session finalize_v3_phase4` để xuất dữ liệu đã khóa sổ sang `documents/<repo>/`, `documents/_analysis/`, `documents/_system/`, `documents/_v3/`; tiếp theo chạy `python AI-skills/reporting/report.py collect` → `4.2` (`/phase-4-architecture-synthesis`) → `4.3` (`/phase-4-finding-consolidation`) → `4.4` (`/phase-4-business-impact`) → `Phase Risk R.1–R.5` (`/phase-risk-assessment`: `/phase-risk-exploit-path`, `/phase-risk-cross-link`, `/phase-risk-challenge`, `/phase-risk-verdict`) → `4.5` (`/phase-4-report-writer` nháp) → `4.6` (`/phase-4-independent-review`) → `4.7` (`/phase-4-report-writer` chốt + `check --stage final` + `render`) để xuất `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md` và `documents/_report/DANH_GIA_RUI_RO.md`.

## Ràng buộc Bất biến khi Thực thi trên Windows (Non-Negotiable Epistemic Gates)
1. **Lệnh CLI chuẩn Windows & Ranh giới Phiên (`Repo x Phase`):** Luôn đứng tại `<Project-Root>` và gọi trực tiếp `python -m localsec.manual_session ...` cùng `python AI-skills/reporting/report.py ...`, lưu các file JSON trung gian vào `.localsec/tmp/<file>.json` (không dùng `PYTHONPATH=...` inline hay `/tmp/`), chạy mỗi Phase trong một phiên mới và in lệnh khởi chạy Phase kế tiếp sau khi cổng `finalize_v3_phase1/2/3/4` báo PASS.
2. **Không bịa mã bằng chứng (`ev_...`) & Tái sử dụng qua `show_evidence`:** Mọi trích dẫn mã nguồn/tài liệu phải được đọc qua `python -m localsec.manual_session read_file ...` (hoặc `read_files`) để runtime cấp mã `ev_<18-hex>`, và dùng `show_evidence` / `list_evidence` ở các phase sau để tránh đọc lại file.
3. **Intent Before Code (`ARCH-3K`), Safe Clustering (`ARCH-3F`, `C3`) & Physical Visibility Tracker:** Chạy `inventory_repo` + `register_scout_map`, chạy `intent_invariant_modeler` trước khi đọc code thực thi, không gom cụm ngầm các entrypoint có `object_id_params`, đọc kiểm tra xác suất theo đúng `required_spot_check_endpoint`, đọc đủ $\ge 50\%$ số dòng mỗi `target_module` và $\ge 90\%$ số dòng mỗi `mandatory_file`, và bắt buộc vượt qua `finalize_v3_phase1`.
4. **Isolated Challenger (`ARCH-3E`, `R3-A7`, `C1`), Fail-Closed Candidate Accounting (`ARCH-3G`, `R3-A4`, `C8`) & Deterministic S-F-O-P-C Risk (`R3-A5`, `C2`, `C6`):** Chạy `prepare_blinded_chain_verifier` và chỉ truyền `.localsec/tmp/blinded_chains_<repo_name>.json` cho subagent cô lập ở Bước 2.3 (`context: fork` + `agent: localsec-blinded-challenger` hoặc `invoke_subagent` với `localsec/claude_subagent_guard.py`), mọi mục trong `unexploitable_candidates[]` / `dismissed_candidates[]` phải là object có `reason` $\ge 10$ ký tự + `evidence_ids` khác rỗng, mọi phán quyết bác bỏ của challenger phải có `counter_evidence_ids` hợp lệ được tái kiểm ở `finalize_v3_phase2`, và `finalize_v3_phase3` áp dụng `contextual_risk_rating = derived_risk_rating` (cả trần lẫn sàn, kèm `overall_risk <= max_impact`).


## Luật CLI cần biết (Đợt 7 — ghi lại từ thử nghiệm `vinfast-mcp`)

- **Bước cần ngữ cảnh sạch dùng subagent trên cả hai công cụ** (2.3, R.4, 4.6): Claude Code qua skill `context: fork` / Agent tool; Antigravity qua `invoke_subagent` (2.3: `TypeName: "localsec-blinded-challenger"`, Prompt mở đầu đúng bằng `/phase-2-blinded-counterevidence-challenger <repo>`; R.4/4.6: `TypeName: "self"`). Bước 2.3 bị chặn bằng cùng guard `localsec/claude_subagent_guard.py`: Claude qua hook trong `.claude/agents/localsec-blinded-challenger.md`, Antigravity qua `.agents/hooks.json` (`--platform antigravity`). Không có subagent thì mở hội thoại mới với đúng lời mở đầu đó.
- **`read_file` trả tối đa 180 dòng mỗi lần** (`max_lines_per_read`). File dài phải đọc nhiều lần liên tiếp (`--start-line`/`--end-line`). Cổng Phase 1 tính độ phủ theo **dòng**: file bắt buộc (entrypoint + security) phải được đọc ≥ 90% số dòng (`mandatory_min_line_coverage`), không chỉ "đã mở".
- **`coverage_id`** có dạng `surface::boundary::subsystem::attack_class[::lifecycle]`, mỗi đoạn **mã hoá phần trăm theo RFC 3986**: `/` phải viết thành `%2F` (ví dụ `http_api::mcp_edge::apps%2Fmcp%2Fserver::BOLA_IDOR`). Hàm `localsec.orchestrator.build_coverage_id(...)` dựng đúng dạng này.
- **`run_tailored_extractor --patterns-file <file.json>`** nhận một danh sách `[{"name": "...", "regex": "..."}]`, hoặc object `{"patterns": [...]}`. Mỗi mẫu cần khoá `regex`.
- **Bước 2.4 (`analysis_evidence_gate`) là tuỳ chọn.** `finalize_v3_phase2` tự ghi file này, và `phase_status --phase 2` không còn đòi nó.
- **Cổng độ phủ theo module (Đợt 10 — V20):** ngoài file bắt buộc (≥ 90% số dòng), mỗi module trong `target_modules` phải được đọc ≥ `target_module_min_line_coverage` (mặc định **50%**) số dòng nguồn không tính test; module khai báo trong `ignored_modules` được miễn. Hai lệnh hỗ trợ:
  - `python -m localsec.manual_session coverage_status <repo>`: liệt kê file bắt buộc chưa đủ 90% và module chưa đủ ngưỡng.
  - `python -m localsec.manual_session read_files <repo> --module <đường dẫn module> --until-pct 50 --skill <skill>`: đọc theo lô, ưu tiên file bắt buộc chưa đọc, rồi tới file có tín hiệu rủi ro cao (đường dẫn auth/token/consent/state…, nội dung đọc header/gọi HTTP/ký token); file UI/catalog xếp sau; bỏ qua đoạn đã đọc; mỗi lượt trả khoảng 60 nghìn ký tự (`--max-chars`), mỗi đoạn có `ev_` như `read_file`. Gọi lại cùng lệnh tới khi `target_reached: true`. **Phải phân tích nội dung trả về**: cổng chỉ đếm dòng đã đọc, không đếm dòng đã hiểu.
- **Ghi nháp JSON bằng công cụ Write của agent,** không dùng heredoc của Git Bash: heredoc làm hỏng dấu `\` và chữ tiếng Việt trên Windows.

## Bảng Lệnh CLI Chuẩn Windows (`python -m localsec.manual_session` & `python AI-skills/reporting/report.py`)
```powershell
# 1. Cài đặt hoặc cập nhật bộ skills vào <Project-Root> trên Windows
.\AI-skills\setup.ps1              # PowerShell
AI-skills\setup.bat                # CMD

# 2. Các lệnh v3.0 Phase 1 (Inventory, AI Scout, Batch Read >= 50%, Coverage Status, Cross-Repo Match, Finalize Phase 1)
python -m localsec.manual_session inventory_repo <repo_name> --tier 1
python -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout_<repo_name>.json
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode TAILOR_CUSTOM_EXTRACTOR --canary-files <file1> --patterns-file .localsec/tmp/patterns.json --expected-canary-hits 1
python -m localsec.manual_session read_files <repo_name> --module <module> --until-pct 50 --skill unified_surface_mapper
python -m localsec.manual_session coverage_status <repo_name>
python -m localsec.manual_session select_attack_companions <repo_name> --archetypes ev_charging_ocpp_ocpi_bess api_rest_graphql_grpc_websocket
python -m localsec.manual_session match_cross_repo_boundaries
python -m localsec.manual_session audit_visibility <repo_name>
python -m localsec.manual_session verify_semantic_claims <repo_name>
python -m localsec.manual_session finalize_v3_phase1 <repo_name>
python -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 3. Các lệnh v3.0 Phase 2 & Phase 3 (Show Evidence, Isolated Challenger, Finalize Phase 2/3, Runtime Facts, Render Report)
python -m localsec.manual_session show_evidence <repo_name> <ev_id>
python -m localsec.manual_session list_evidence <repo_name>   # không dùng trong bước 2.3
python -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>
python -m localsec.manual_session finalize_v3_phase2 <repo_name>
python -m localsec.manual_session ingest_runtime_facts <repo_name> .localsec/tmp/runtime_facts.json
python -m localsec.manual_session finalize_v3_phase3 <repo_name>
python -m localsec.manual_session render_v3_report <repo_name>

# 4. Các lệnh Phase 4 & Phase Risk (Export v3 -> Collect -> Check -> Render)
python -m localsec.manual_session finalize_v3_phase4
python AI-skills/reporting/report.py collect
python AI-skills/reporting/report.py status
python AI-skills/reporting/report.py catalog
python AI-skills/reporting/report.py check --stage architecture
python AI-skills/reporting/report.py check --stage findings
python AI-skills/reporting/report.py check --stage impact
python AI-skills/reporting/report.py access --for F-01
python AI-skills/reporting/report.py check --stage risk-paths --only F-01
python AI-skills/reporting/report.py risk-digest
python AI-skills/reporting/report.py check --stage risk
python AI-skills/reporting/report.py render-risk --draft
python AI-skills/reporting/report.py risk-ack
python AI-skills/reporting/report.py render-risk
python AI-skills/reporting/report.py render --draft
python AI-skills/reporting/report.py review-ack
python AI-skills/reporting/report.py check --stage final
python AI-skills/reporting/report.py render

# 5. Kiểm tra tiến độ từng Phase (1, 2, 3, 4)
python -m localsec.manual_session phase_status <repo_name> --phase 1
python -m localsec.manual_session phase_status <repo_name> --phase 2
python -m localsec.manual_session phase_status <repo_name> --phase 3
python -m localsec.manual_session phase_status <repo_name> --phase 4

# 6. Duyệt thư mục, đọc file sinh mã bằng chứng ev_... và nộp kết quả skill
python -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
python -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>
python -m localsec.manual_session submit_skill <repo_name> <skill_name> .localsec/tmp/<skill_name>_<repo_name>.json
```

> Chi tiết hướng dẫn từng bước của 28 skills nằm tại `.claude/skills/{phase-*,phase-risk-*}/SKILL.md` (Claude Code), `.agents/skills/{phase-*,phase-risk-*}/SKILL.md` (Antigravity), subagent cô lập tại `.claude/agents/localsec-blinded-challenger.md` & `.agents/agents/localsec-blinded-challenger.md`, các JSON Schemas tại `AI-skills/schemas/v3/*.schema.json`, hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`, hướng dẫn báo cáo tại `AI-skills/reporting/guides/*.md`, và sổ tay tra cứu tại `.agents/README.md`.
