# CLAUDE.md — LocalSec v3.0 Security Review Pipeline (`AI-skills` — Windows Edition)

## Import (nạp lúc khởi động)
@SOUL.md
@AGENTS.md

## Vai trò & Kiến trúc Hệ thống (v3.0 — Windows Native)
Bạn đang vận hành **LocalSec v3.0 Security Review Pipeline** trên môi trường **Windows (PowerShell / CMD / Git Bash)**, kết hợp bộ **16 Skills** (trong `.claude/skills/` cho Claude Code và `.agents/skills/` cho Antigravity) với **Python Epistemic Engine (`PYTHONPATH=AI-skills:. python3 -m localsec.manual_session`)** theo hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`:

- **Phase 1 — Unified Reconnaissance (`/phase-1-orchestrator` — thứ tự `Intent Before Code`: `1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`):** Chạy `inventory_repo` + khảo sát cấu trúc & quy ước bằng AI (`codebase_scout`), dựng mô hình Ý định & Bất biến An toàn S-F-O-P-C trước khi đọc code thực thi (`intent_invariant_modeler` — `ARCH-3K`), tinh chỉnh/kiểm thử Python extractor trên canary files với `--patterns-file` và `--expected-canary-hits` (`extractor_tailor`), đọc mã nguồn 1 lượt kèm gom cụm ngữ nghĩa an toàn (`unified_surface_mapper` — `ARCH-3F`), ghép cặp ranh giới liên repo `match_cross_repo_boundaries` + đánh giá kiến trúc xuyên repo (`cross_repo_and_arch_review`), và khóa sổ qua `coverage_and_evidence_auditor` + cổng tất định `finalize_v3_phase1` (xuất `coverage_matrix.json` & `candidate_queue.json`).
- **Phase 2 — Deep Analysis & Falsification (`/phase-2-orchestrator` — 4 bước `2.1 -> 2.4`):** Đọc `candidate_queue.json` từ Phase 1 và nạp nguyên văn các mô-đun `Attack-Class Companion` ra `selected_attack_companions.json` (`candidate_intake_planner`), truy vết sâu từng bước nhảy `hops[]` kèm `hop_kind` + dựng chuỗi tấn công + truy nguyên nhân gốc cho 100% ứng viên (`deep_trace_chain_analyst` — `ARCH-3G`), phản biện bác bỏ trong **Subagent cô lập / Fresh Context (`blinded_counterevidence_challenger` — `ARCH-3E`)** chỉ nhận duy nhất file Whitelist `/tmp/blinded_chains_<repo_name>.json` và kiểm tra đủ 6 vị trí kiểm soát cố định (`control_search_checklist`), sau đó khóa sổ qua `analysis_evidence_gate` + cổng tất định `finalize_v3_phase2`.
- **Phase 3 — Contextual Risk & Exploitability Assessment (`/phase-3-orchestrator` — 3 bước `3.1 -> 3.3` + `render_v3_report`):** Đánh giá 100% `chain_id` sống sót từ Phase 2: chứng minh `minimum_actor` và điều kiện tiên quyết `yes`/`no`/`unknown` (`actor_and_feasibility_assessor`), nạp `ingest_runtime_facts` (nếu có) và đối chiếu các lớp kiểm soát ngoài code như Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC `10.x`, mTLS, OT Interlock với `status`: `confirmed`/`hypothesis`/`absent` (`beyond_code_control_mapper`), hiệu chuẩn rủi ro thực tế trên **5 trục `impact_axes` (S-F-O-P-C)** theo rubric định lượng (`sfop_risk_calibrator`), khóa sổ bằng cổng tất định `finalize_v3_phase3` và xuất báo cáo qua `render_v3_report`.

## Ràng buộc Bất biến khi Thực thi trên Windows (Non-Negotiable Epistemic Gates)
1. **Lệnh CLI chuẩn Windows & Ranh giới Phiên (`Repo x Phase`):** Luôn gọi trực tiếp `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...`, lưu các file JSON trung gian vào `/tmp/<file>.json` (không dùng `PYTHONPATH=...` inline hay `/tmp/`), chạy mỗi Phase trong một phiên mới và in lệnh khởi chạy Phase kế tiếp sau khi cổng `finalize_v3_phase1/2/3` báo PASS.
2. **Không bịa mã bằng chứng (`ev_...`) & Tái sử dụng qua `show_evidence`:** Mọi trích dẫn mã nguồn/tài liệu phải được đọc qua `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file ...` để runtime cấp mã `ev_<18-hex>`, và dùng `show_evidence` / `list_evidence` ở các phase sau để tránh đọc lại file.
3. **Intent Before Code (`ARCH-3K`), Safe Clustering (`ARCH-3F`) & Physical Visibility Tracker:** Chạy `inventory_repo` + `register_scout_map`, chạy `intent_invariant_modeler` trước khi đọc code thực thi, không gom cụm ngầm các entrypoint có `object_id_params`, và bắt buộc vượt qua `finalize_v3_phase1` (`unvisited_target_modules == 0`, `shallow_grazing_files == 0`).
4. **Isolated Challenger (`ARCH-3E`), 100% Candidate/Chain Accounting (`ARCH-3G`) & Luật Cứng S-F-O-P-C:** Chạy `prepare_blinded_chain_verifier` và chỉ truyền `/tmp/blinded_chains_<repo_name>.json` cho subagent cô lập ở Bước 2.3, bảo toàn 100% `candidate_id` / `chain_id` qua `finalize_v3_phase2` và `finalize_v3_phase3`, đảm bảo `overall_risk <= max_impact` ở Phase 3.

## Bảng Lệnh CLI Chuẩn Windows (`PYTHONPATH=AI-skills:. python3 -m localsec.manual_session`)
```powershell
# 1. Cài đặt hoặc cập nhật bộ skills vào <Project-Root> trên Windows
.\AI-skills\setup.ps1              # PowerShell
AI-skills\setup.bat                # CMD

# 2. Các lệnh v3.0 Phase 1 (Inventory, AI Scout, Intent Before Code, Tailored Extractor, Cross-Repo Match, Finalize Phase 1)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session inventory_repo <repo_name> --tier 1
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session register_scout_map <repo_name> /tmp/codebase_scout_<repo_name>.json
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session run_tailored_extractor <repo_name> --mode TAILOR_CUSTOM_EXTRACTOR --canary-files <file1> --patterns-file /tmp/patterns.json --expected-canary-hits 1
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session select_attack_companions <repo_name> --archetypes ev_charging_ocpp_ocpi_bess api_rest_graphql_grpc_websocket
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session match_cross_repo_boundaries
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session audit_visibility <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session verify_semantic_claims <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase1 <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 3. Các lệnh v3.0 Phase 2 & Phase 3 (Show Evidence, Isolated Challenger, Finalize Phase 2/3, Runtime Facts, Render Report)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session show_evidence <repo_name> <ev_id>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_evidence <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase2 <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ingest_runtime_facts <repo_name> /tmp/runtime_facts.json
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_v3_phase3 <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session render_v3_report <repo_name>

# 4. Kiểm tra tiến độ từng Phase (1, 2, 3)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 1
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 2
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 3

# 5. Duyệt thư mục, đọc file sinh mã bằng chứng ev_... và nộp kết quả skill
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> <skill_name> /tmp/<skill_name>_<repo_name>.json
```

> Chi tiết hướng dẫn từng bước của 16 skills v3.0 nằm tại `.claude/skills/phase-*/SKILL.md` (Claude Code), `.agents/skills/phase-*/SKILL.md` (Antigravity), các JSON Schemas tại `AI-skills/schemas/v3/*.schema.json`, hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json`, và sổ tay tra cứu tại `.agents/README.md`.
