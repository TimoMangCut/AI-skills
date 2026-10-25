# AI-skills — LocalSec v3.0 Security Review Pipeline (Windows Edition — Antigravity & Claude Code)

Bộ **16 Skills (`.agents/skills/` & `.claude/skills/`) + Always-On Rules (`AGENTS.md`, `SOUL.md`, `CLAUDE.md`) + Python Epistemic Engine (`localsec`)** tối ưu hóa cho môi trường **Windows (PowerShell, CMD, Git Bash)** dùng để kiểm toán bảo mật mã nguồn & hệ sinh thái Cyber-Physical (Vingroup / VinSOC) qua **3 Phase chuẩn hóa v3.0** (`AI-skills/contracts/v3-orchestration.json`):
- **Phase 1**: Unified Reconnaissance (`/phase-1-orchestrator` — 6 bước v3.0 theo thứ tự **Intent Before Code (`1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6`)**: `inventory_repo` + AI Scouting $\rightarrow$ S-F-O-P-C Invariants trước khi đọc code $\rightarrow$ Tailored Extractor $\rightarrow$ Single-Pass Safe Semantic Clustering $\rightarrow$ Cross-Repo Boundary Matching & Arch Review $\rightarrow$ Physical Visibility Tracker, Evidence Audit & `finalize_v3_phase1`)
- **Phase 2**: Deep Analysis & Falsification (`/phase-2-orchestrator` — 4 bước v3.0 (`2.1 -> 2.4`): Candidate Queue Intake + 16 Attack-Class Companions $\rightarrow$ Deep Trace & Chain Analyst (100% candidate accounting + `hop_kind`) $\rightarrow$ Isolated Context-Blinded Challenger (6-item `control_search_checklist`) $\rightarrow$ Analysis Evidence Gate & `finalize_v3_phase2`)
- **Phase 3**: Contextual Risk & Exploitability Assessment (`/phase-3-orchestrator` — 3 bước v3.0 (`3.1 -> 3.3` + Report): Actor & Structured Precondition Feasibility $\rightarrow$ Beyond-Code Controls Cloudflare/WAF/VPC/OT Interlock (`ingest_runtime_facts`) $\rightarrow$ 5-Axis S-F-O-P-C Quantitative Risk Calibrator, `finalize_v3_phase3` & `render_v3_report`)

---

## 1. Cấu trúc Khi Clone Vào Một Project Cần Áp Dụng Trên Windows (`<Project-Root>`)

Khi áp dụng bộ Skills này vào một dự án thực tế (`<Project-Root>`), `.\AI-skills\setup.ps1` (PowerShell) hoặc `AI-skills\setup.bat` (CMD) **tự động đồng bộ `.agents/`, `.claude/`, `AGENTS.md`, `SOUL.md`, `CLAUDE.md` và cầu nối `localsec/` ra ngoài gốc Project** để cả **Antigravity** lẫn **Claude Code** trên Windows chạy trực tiếp lệnh `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...` mà không cần biến môi trường POSIX `PYTHONPATH=...`:

```text
<Project-Root>\                        <-- Mở thư mục này trong Antigravity IDE hoặc Claude Code trên Windows
├── <service-repo-1>\                  <-- Các repo mã nguồn của dự án cần review
├── <service-repo-2>\
├── <docs-or-brd>\                     <-- Tài liệu nghiệp vụ BRD/BRS/Specs của dự án (nếu có)
├── documents\                         <-- Báo cáo đầu ra (render_v3_report) sẽ tự động xuất ra đây
├── .localsec\                         <-- Trạng thái phiên làm việc, .localsec\tmp\, .localsec\runs\ & mã bằng chứng ev_...
├── localsec\__init__.py               <-- [Auto-Bridge] Cầu nối package giúp `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session` chạy trực tiếp trên PowerShell/CMD
│
├── AGENTS.md                          <-- [Copy/Merge từ AI-skills] Rule Refute-first & 5 trục S-F-O-P-C
├── SOUL.md                            <-- [Copy/Merge từ AI-skills] Lớp giá trị cốt lõi
├── CLAUDE.md                          <-- [Copy/Merge từ AI-skills] Entrypoint cho Claude Code (@SOUL.md, @AGENTS.md)
├── .agents\                           <-- [Copy từ AI-skills] 16 Skills & Rules chuẩn Antigravity
│   ├── README.md                      <-- Sổ tay tra cứu nhanh các lệnh & mẫu Prompt trên Windows
│   ├── rules\soul.md
│   └── skills\phase-{1,2,3}-*\SKILL.md
├── .claude\                           <-- [Copy từ AI-skills] 16 Skills chuẩn Claude Code
│   └── skills\phase-{1,2,3}-*\SKILL.md
│
└── AI-skills\                         <-- Thư mục git clone nằm gọn một chỗ
    ├── setup.ps1                      <-- Script cài đặt chuẩn Windows PowerShell
    ├── setup.bat                      <-- Script cài đặt chuẩn Windows CMD
    ├── setup.sh                       <-- Script cài đặt cho Git Bash / WSL
    ├── setup_bootstrap.py             <-- Bộ cài đặt & đồng bộ đa nền tảng (Windows / POSIX)
    ├── localsec\                      <-- Bộ máy Python CLI (manual_session.py, validators.py, workspace.py...)
    ├── skills\                        <-- Prompts & Registry gốc
    ├── schemas\                       <-- JSON Schemas (AI-skills/schemas/v3/*.schema.json)
    ├── contracts\                     <-- Contracts, v3-orchestration.json & 16 Attack-Class Companions
    ├── examples\                      <-- Repo mẫu (demo-go)
    ├── tests\                         <-- Unit Tests kiểm định toàn bộ cổng an toàn
    └── localsec.toml                  <-- Cấu hình mặc định của bộ tool
```

---

## 2. Cách Cài Đặt Vào Project Mới Trên Windows (PowerShell / CMD / Git Bash)

Đứng tại thư mục gốc của dự án cần kiểm toán (`<Project-Root>`):

### Cách A — Windows PowerShell (Khuyên dùng)
```powershell
# 1. Clone nhánh wins của bộ AI-skills vào trong <Project-Root>
git clone -b wins https://github.com/TimoMangCut/AI-skills.git

# 2. Chạy script cài đặt tự động trên PowerShell
.\AI-skills\setup.ps1
```

### Cách B — Windows Command Prompt (CMD)
```cmd
git clone -b wins https://github.com/TimoMangCut/AI-skills.git
AI-skills\setup.bat
```

### Cách C — Git Bash trên Windows
```bash
git clone -b wins https://github.com/TimoMangCut/AI-skills.git
sh AI-skills/setup.sh
```

Script `setup.ps1` / `setup.bat` thực hiện an toàn 5 việc:
1. Đồng bộ **16 skills** vào `<Project-Root>\.agents\skills\` và `<Project-Root>\.claude\skills\` mà **không xóa mất** các skill riêng sẵn có của dự án.
2. Tạo cầu nối `<Project-Root>\localsec\__init__.py` và thư mục tạm `<Project-Root>\.localsec\tmp\` để mọi lệnh `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...` chạy mượt trên cả **PowerShell**, **CMD**, và **Git Bash** mà không lỗi cú pháp `PYTHONPATH=...` hay đường dẫn `/tmp/`.
3. Nếu `<Project-Root>` đã có sẵn `AGENTS.md`, `SOUL.md` hoặc `CLAUDE.md`, script tự động **gộp (merge) có đánh dấu (`<!-- BEGIN AI-SKILLS:... -->`)** chứ không ghi đè làm mất nội dung cũ.
4. Tự động ghi các đường dẫn công cụ (`/AI-skills/`, `/localsec/`, `/.agents/...`, `/.claude/...`, `/.localsec/`, `/documents/`) vào `.git/info/exclude` của `<Project-Root>` để giữ `git status` hoàn toàn sạch sẽ.
5. Tự động chạy bộ kiểm định Unit Tests bằng Python hiện hành trên máy.

- **Khi muốn gỡ sạch khỏi `<Project-Root>` sau khi kiểm toán xong**:
  ```powershell
  .\AI-skills\setup.ps1 --uninstall
  # Hoặc trên CMD: AI-skills\setup.bat --uninstall
  ```

---

## 3. Cách Khởi Chạy Trên Antigravity Hoặc Claude Code (Windows — Ranh Giới Phiên `Repo x Phase`)

Mở `<Project-Root>` trong Antigravity IDE hoặc Claude Code và gọi tuần tự từng Phase trong **phiên hội thoại riêng (`Repo x Phase` Session Boundary)** để tối ưu ngữ cảnh và ngăn nhiễm chéo thiên kiến:

### Bước A — Chạy Phase 1 (Unified Reconnaissance v3.0 — Intent Before Code)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0) cho toàn bộ repositories theo đúng thứ tự Intent Before Code (1.1 -> 1.3 -> 1.2 -> 1.4 -> 1.5 -> 1.6):
Chạy inventory_repo và Bước 1.1 codebase_scout trước để lập Target Modules Map bao phủ 100% entrypoint/security files, chạy Bước 1.3 intent_invariant_modeler trước khi đọc code thực thi, kiểm thử Python extractor trên canary files ở Bước 1.2, đọc code 1 lượt kèm Safe Semantic Clustering ở Bước 1.4, chạy match_cross_repo_boundaries và đánh giá kiến trúc xuyên repo ở Bước 1.5, cuối cùng chạy Bước 1.6 coverage_and_evidence_auditor và cổng khóa sổ tất định finalize_v3_phase1 để xuất coverage_matrix.json và candidate_queue.json.
```

### Bước B — Chạy Phase 2 (Deep Analysis & Falsification v3.0 — Mở Phiên Mới)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0) trên candidate_queue.json từ Phase 1:
Chạy tuần tự 4 bước (2.1 -> 2.4): nạp nguyên văn các mô-đun Attack-Class Companion vào selected_attack_companions.json, truy vết sâu hops[] (kèm hop_kind) + dựng chuỗi tấn công + tìm Root-Cause cho 100% ứng viên, chạy prepare_blinded_chain_verifier và khởi chạy Subagent cô lập (chỉ truyền duy nhất file /tmp/blinded_chains_<repo_name>.json) để phản biện đối kháng ở chế độ Mù Kết luận trên đủ 6 vị trí control_search_checklist, và khóa sổ qua analysis_evidence_gate cùng cổng tất định finalize_v3_phase2.
```

### Bước C — Chạy Phase 3 (Contextual Risk & Exploitability Assessment v3.0 — Mở Phiên Mới)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability Assessment v3.0) cho 100% các chain_id sống sót từ Phase 2:
Chạy tuần tự 3 bước (3.1 -> 3.3): chứng minh minimum_actor và điều kiện tiên quyết yes/no/unknown, kiểm tra bằng chứng cấu hình các lớp kiểm soát ngoài code (Cloudflare WAF vs Bare ALB, VPC 10.x, mTLS, OT Interlock với status confirmed/hypothesis/absent), hiệu chuẩn rủi ro thực tế trên 5 trục impact_axes (S-F-O-P-C) theo rubric định lượng (overall_risk <= max_impact, tách biệt safety_owner với risk_owner), sau đó chạy cổng tất định finalize_v3_phase3 và render_v3_report.
```

👉 Tra cứu chi tiết từng sub-skill trong bộ 16 skills v3.0 và bảng lệnh CLI chuẩn Windows tại **[`.agents/README.md`](./.agents/README.md)**.
