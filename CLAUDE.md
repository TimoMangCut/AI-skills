# CLAUDE.md — LocalSec 3-Phase Security Review Pipeline (`AI-skills`)

## Import (nạp lúc khởi động)
@SOUL.md
@AGENTS.md

## Vai trò & Kiến trúc Hệ thống
Bạn đang vận hành **LocalSec 3-Phase Security Review Pipeline** (`v2.4.0-refute-first`), kết hợp bộ **28 Skills** (trong `.claude/skills/` cho Claude Code và `.agents/skills/` cho Antigravity) với **Python Epistemic Engine (`localsec.manual_session`)**:

- **Phase 1 — Manual Code Reconnaissance (`/phase-1-orchestrator` — 8 bước `1.1 -> 1.8`):** Khảo sát mã nguồn thủ công qua `ManualWorkspace` (sinh mã bằng chứng `ev_<18-hex>`), kiểm kê API/AuthZ, Dataflow, STRIDE Threat Model, Architecture Review, kiểm toán bằng chứng độc lập (`evidence_auditor`) và tổng hợp liên repo (`cross_repo_review`).
- **Phase 2 — Business-Aware Security Verification / BASV (`/phase-2-orchestrator` — 9 bước `2.1 -> 2.9`):** Đối chiếu Ý định Nghiệp vụ (BRD/BRS/SQL/Specs) với Triển khai Thực tế, phản biện bất biến ở chế độ mù ngữ cảnh (`prepare_blinded_challenger`), kiểm chứng giới hạn đường dẫn (`targeted_verifier`), ánh xạ hậu quả bảo mật và kiểm toán bằng chứng kép.
- **Phase 3 — Attack Chain & Root-Cause Analysis / ACA (`/phase-3-orchestrator` — 9 bước `3.1 -> 3.9`):** Xây dựng và xác minh chuỗi tấn công đa bước xuyên dịch vụ, truy vết từng hop thực thi (`code_trace_builder`), kiểm chứng mù từng mắt xích/cạnh nối (`chain_step_verifier`), thiết kế chuỗi request kiểm định, truy nguyên nhân gốc (`root_cause_mapper`) và săn tìm bằng chứng phản bác (`counterevidence_challenger`).

## Ràng buộc Bất biến khi Thực thi (Non-Negotiable Epistemic Gates)
1. **Không bịa mã bằng chứng (`ev_...`):** Mọi trích dẫn mã nguồn/tài liệu phải được đọc qua `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file ...` để runtime cấp mã `ev_<18-hex>`.
2. **Tuân thủ Cổng Trạng thái (`phase_status` & `submit_skill`):** Kiểm tra tiến độ trước và sau mỗi bước bằng `phase_status`. Không nộp bước tổng hợp (`business_aware_synthesizer`, `chain_synthesizer`) trước khi hoàn tất `evidence_auditor` / `aca_evidence_auditor`.
3. **Tuân thủ Context-Blinding:** Khi chạy `business_invariant_challenger`, `targeted_verifier`, `chain_step_verifier`, hoặc `counterevidence_challenger`, bắt buộc dùng các lệnh `prepare_blinded_*` của CLI để cắt bỏ kết luận mỏ neo trước đó.

## Bảng Lệnh CLI Chuẩn (`localsec.manual_session`)
```bash
# Kiểm tra tiến độ từng Phase (1, 2, 3)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 1
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 2
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status _analysis --phase 3

# Duyệt thư mục và đọc file sinh mã bằng chứng ev_...
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill repo_profile
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>

# Tạo gói ngữ cảnh làm mù (Context-Blinding)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_challenger <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_targeted_verifier <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# Nộp kết quả JSON của từng skill và trích xuất claims kiểm toán
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> <skill_name> <json_path>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_claims <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_basv_claims <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_aca_claims _analysis

# Khóa sổ và xuất báo cáo cuối cùng vào ./documents/
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_repo <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_system
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_basv_repo <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_basv_system
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_aca _analysis
```

> Chi tiết hướng dẫn từng bước của 28 skills nằm tại `.claude/skills/phase-*/SKILL.md` (Claude Code) và `.agents/skills/phase-*/SKILL.md` (Antigravity), kèm sổ tay tra cứu tại `.agents/README.md`.
