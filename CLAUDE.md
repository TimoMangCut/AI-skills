# CLAUDE.md — LocalSec v3.0 Security Review Pipeline (`AI-skills` — Windows Edition)

## Import (nạp lúc khởi động)
@SOUL.md
@AGENTS.md

## Vai trò & Kiến trúc Hệ thống (v3.0 — Windows Native)
Bạn đang vận hành **LocalSec v3.0 Security Review Pipeline** trên môi trường **Windows (PowerShell / CMD / Git Bash)**, kết hợp bộ **16 Skills** (trong `.claude/skills/` cho Claude Code và `.agents/skills/` cho Antigravity) với **Python Epistemic Engine (`python -m localsec.manual_session`)**:

- **Phase 1 — Unified Reconnaissance (`/phase-1-orchestrator` — 6 bước `1.1 -> 1.6`):** Khảo sát cấu trúc & quy ước code bằng AI (`codebase_scout`), tinh chỉnh/kiểm thử Python extractor trên canary files (`extractor_tailor`), dựng mô hình Ý định & Bất biến An toàn S-F-O-P-C (`intent_invariant_modeler`), đọc mã nguồn 1 lượt kèm gom cụm ngữ nghĩa (`unified_surface_mapper`), đánh giá kiến trúc xuyên repo (`cross_repo_and_arch_review`) và kiểm toán độ phủ vật lý `Visibility Tracker` + `Evidence Audit` (`coverage_and_evidence_auditor`).
- **Phase 2 — Deep Analysis & Falsification (`/phase-2-orchestrator` — 4 bước `2.1 -> 2.4`):** Tiếp nhận `Candidate Queue` từ Phase 1 và nạp nguyên văn các mô-đun `Attack-Class Companion` (`candidate_intake_planner`), truy vết sâu từng bước nhảy `hops[]` + dựng chuỗi tấn công + truy nguyên nhân gốc (`deep_trace_chain_analyst`), phản biện bác bỏ ở chế độ **Mù Kết luận (`blinded_counterevidence_challenger`)** và khóa sổ qua cổng `analysis_evidence_gate` kèm `Empirical Refutations Ledger`.
- **Phase 3 — Contextual Risk & Exploitability Assessment (`/phase-3-orchestrator` — 3 bước `3.1 -> 3.3`):** Chứng minh **Actor/Role tối thiểu nào** chạm được code path (`actor_and_feasibility_assessor`), đối chiếu các lớp kiểm soát ngoài code như Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC `10.x`, mTLS, OT Interlock (`beyond_code_control_mapper`), và hiệu chuẩn rủi ro thực tế trên **5 trục S-F-O-P-C** (`sfop_risk_calibrator`).

## Ràng buộc Bất biến khi Thực thi trên Windows (Non-Negotiable Epistemic Gates)
1. **Lệnh CLI chuẩn Windows (Không dùng `PYTHONPATH=...` inline hay `/tmp/`):** Luôn gọi trực tiếp `python -m localsec.manual_session ...` và lưu các file JSON trung gian vào `.localsec/tmp/<file>.json` (tương thích 100% với PowerShell, CMD và Git Bash).
2. **Không bịa mã bằng chứng (`ev_...`):** Mọi trích dẫn mã nguồn/tài liệu phải được đọc qua `python -m localsec.manual_session read_file ...` để runtime cấp mã `ev_<18-hex>`.
3. **AI Scout Before Python & Physical Visibility Tracker:** Chạy `register_scout_map` trước `run_tailored_extractor`, và bắt buộc vượt qua `audit_visibility` (`unvisited_target_modules == 0`, `shallow_grazing_files == 0`).
4. **Tuân thủ Context-Blinding & 3 Luật Cứng S-F-O-P-C:** Dùng các lệnh `prepare_blinded_*` khi chạy Challenger/Verifier, và đảm bảo `overall_risk <= max_impact` ở Phase 3.

## Bảng Lệnh CLI Chuẩn Windows (`python -m localsec.manual_session`)
```powershell
# 1. Cài đặt hoặc cập nhật bộ skills vào <Project-Root> trên Windows
.\AI-skills\setup.ps1              # PowerShell
AI-skills\setup.bat                # CMD

# 2. Các lệnh v3.0 cốt lõi (AI Scout, Tailored Extractor, Attack Companions, Visibility Tracker)
python -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout.json
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode USE_STANDARD_EXTRACTOR --canary-files <file1> <file2>
python -m localsec.manual_session select_attack_companions <repo_name> --archetypes connected_car_and_ota ev_charging_and_energy
python -m localsec.manual_session audit_visibility <repo_name>
python -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 3. Kiểm tra tiến độ từng Phase (1, 2, 3)
python -m localsec.manual_session phase_status <repo_name> --phase 1
python -m localsec.manual_session phase_status <repo_name> --phase 2
python -m localsec.manual_session phase_status _analysis --phase 3

# 4. Duyệt thư mục và đọc file sinh mã bằng chứng ev_...
python -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
python -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>

# 5. Tạo gói ngữ cảnh làm mù (Context-Blinding)
python -m localsec.manual_session prepare_blinded_challenger <repo_name>
python -m localsec.manual_session prepare_blinded_targeted_verifier <repo_name>
python -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# 6. Nộp kết quả JSON của từng skill và trích xuất claims kiểm toán
python -m localsec.manual_session submit_skill <repo_name> <skill_name> .localsec/tmp/<skill_name>.json
python -m localsec.manual_session extract_claims <repo_name>
python -m localsec.manual_session extract_basv_claims <repo_name>
python -m localsec.manual_session extract_aca_claims _analysis

# 7. Khóa sổ và xuất báo cáo cuối cùng vào ./documents/
python -m localsec.manual_session finalize_repo <repo_name>
python -m localsec.manual_session finalize_system --cross-repo .localsec/tmp/cross_repo.json --sys-audit .localsec/tmp/sys_audit.json --diagrams .localsec/tmp/diagrams.json
python -m localsec.manual_session finalize_basv_repo <repo_name>
python -m localsec.manual_session finalize_basv_system
python -m localsec.manual_session finalize_aca _analysis
```

> Chi tiết hướng dẫn từng bước của 16 skills v3.0 nằm tại `.claude/skills/phase-*/SKILL.md` (Claude Code) và `.agents/skills/phase-*/SKILL.md` (Antigravity), kèm sổ tay tra cứu tại `.agents/README.md`.
