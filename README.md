# AI-skills — LocalSec v3.0 Security Review Pipeline (Windows Edition — Antigravity & Claude Code)

Bộ **41 Skills (`.agents/skills/` & `.claude/skills/`) + Always-On Rules (`AGENTS.md`, `SOUL.md`, `CLAUDE.md`) + Python Epistemic Engine (`localsec`)** tối ưu hóa cho môi trường **Windows (PowerShell, CMD, Git Bash)** dùng để kiểm toán bảo mật mã nguồn & hệ sinh thái Cyber-Physical (Vingroup / VinSOC) qua **3 Phase chuẩn hóa v3.0**:
- **Phase 1**: Unified Reconnaissance (`/phase-1-orchestrator` — 6 bước v3.0: AI Scouting $\rightarrow$ Tailored Extractor $\rightarrow$ S-F-O-P-C Invariants $\rightarrow$ Single-Pass Semantic Clustering $\rightarrow$ Cross-Repo Review $\rightarrow$ Physical Visibility Tracker & Evidence Audit)
- **Phase 2**: Deep Analysis & Falsification (`/phase-2-orchestrator` — 4 bước v3.0: Candidate Intake + 16 Attack-Class Companions $\rightarrow$ Deep Trace & Chain Analyst $\rightarrow$ Context-Blinded Challenger $\rightarrow$ Empirical Refutations Ledger Gate)
- **Phase 3**: Contextual Risk & Exploitability Assessment (`/phase-3-orchestrator` — 3 bước v3.0: Actor & Attack Feasibility $\rightarrow$ Beyond-Code Controls Cloudflare/WAF/VPC/OT Interlock $\rightarrow$ 5-Axis S-F-O-P-C Risk Calibrator)

---

## 1. Cấu trúc Khi Clone Vào Một Project Cần Áp Dụng Trên Windows (`<Project-Root>`)

Khi áp dụng bộ Skills này vào một dự án thực tế (`<Project-Root>`), `.\AI-skills\setup.ps1` (PowerShell) hoặc `AI-skills\setup.bat` (CMD) **tự động đồng bộ `.agents/`, `.claude/`, `AGENTS.md`, `SOUL.md`, `CLAUDE.md` và cầu nối `localsec/` ra ngoài gốc Project** để cả **Antigravity** lẫn **Claude Code** trên Windows chạy trực tiếp lệnh `python -m localsec.manual_session ...` mà không cần biến môi trường POSIX `PYTHONPATH=...`:

```text
<Project-Root>\                        <-- Mở thư mục này trong Antigravity IDE hoặc Claude Code trên Windows
├── <service-repo-1>\                  <-- Các repo mã nguồn của dự án cần review
├── <service-repo-2>\
├── <docs-or-brd>\                     <-- Tài liệu nghiệp vụ BRD/BRS/Specs của dự án (nếu có)
├── documents\                         <-- Báo cáo đầu ra (Phase 1, 2, 3) sẽ tự động xuất ra đây
├── .localsec\                         <-- Trạng thái phiên làm việc, .localsec\tmp\ & mã bằng chứng ev_...
├── localsec\__init__.py               <-- [Auto-Bridge] Cầu nối package giúp `python -m localsec.manual_session` chạy trực tiếp trên PowerShell/CMD
│
├── AGENTS.md                          <-- [Copy/Merge từ AI-skills] Rule Refute-first & 5 trục S-F-O-P-C
├── SOUL.md                            <-- [Copy/Merge từ AI-skills] Lớp giá trị cốt lõi
├── CLAUDE.md                          <-- [Copy/Merge từ AI-skills] Entrypoint cho Claude Code (@SOUL.md, @AGENTS.md)
├── .agents\                           <-- [Copy từ AI-skills] 41 Skills & Rules chuẩn Antigravity
│   ├── README.md                      <-- Sổ tay tra cứu nhanh các lệnh & mẫu Prompt trên Windows
│   ├── rules\soul.md
│   └── skills\phase-{1,2,3}-*\SKILL.md
├── .claude\                           <-- [Copy từ AI-skills] 41 Skills chuẩn Claude Code
│   └── skills\phase-{1,2,3}-*\SKILL.md
│
└── AI-skills\                         <-- Thư mục git clone nằm gọn một chỗ
    ├── setup.ps1                      <-- Script cài đặt chuẩn Windows PowerShell
    ├── setup.bat                      <-- Script cài đặt chuẩn Windows CMD
    ├── setup.sh                       <-- Script cài đặt cho Git Bash / WSL
    ├── setup_bootstrap.py             <-- Bộ cài đặt & đồng bộ đa nền tảng (Windows / POSIX)
    ├── localsec\                      <-- Bộ máy Python CLI (manual_session.py, validators.py, workspace.py...)
    ├── skills\                        <-- Prompts & Registry gốc
    ├── schemas\                       <-- JSON Schemas (AI-skills/schemas/*.schema.json)
    ├── contracts\                     <-- Contracts, Schemas & 16 Attack-Class Companions (AI-skills/contracts/...)
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
1. Đồng bộ **41 skills** vào `<Project-Root>\.agents\skills\` và `<Project-Root>\.claude\skills\` mà **không xóa mất** các skill riêng sẵn có của dự án.
2. Tạo cầu nối `<Project-Root>\localsec\__init__.py` và thư mục tạm `<Project-Root>\.localsec\tmp\` để mọi lệnh `python -m localsec.manual_session ...` chạy mượt trên cả **PowerShell**, **CMD**, và **Git Bash** mà không lỗi cú pháp `PYTHONPATH=...` hay đường dẫn `/tmp/`.
3. Nếu `<Project-Root>` đã có sẵn `AGENTS.md`, `SOUL.md` hoặc `CLAUDE.md`, script tự động **gộp (merge) có đánh dấu (`<!-- BEGIN AI-SKILLS:... -->`)** chứ không ghi đè làm mất nội dung cũ.
4. Tự động ghi các đường dẫn công cụ (`/AI-skills/`, `/localsec/`, `/.agents/...`, `/.claude/...`, `/.localsec/`, `/documents/`) vào `.git/info/exclude` của `<Project-Root>` để giữ `git status` hoàn toàn sạch sẽ.
5. Tự động chạy bộ kiểm định Unit Tests bằng Python hiện hành trên máy.

- **Khi muốn gỡ sạch khỏi `<Project-Root>` sau khi kiểm toán xong**:
  ```powershell
  .\AI-skills\setup.ps1 --uninstall
  # Hoặc trên CMD: AI-skills\setup.bat --uninstall
  ```

---

## 3. Cách Khởi Chạy Trên Antigravity Hoặc Claude Code (Windows)

Mở `<Project-Root>` trong Antigravity IDE hoặc Claude Code và gọi tuần tự:

### Bước A — Chạy Phase 1 (Unified Reconnaissance v3.0)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0) cho toàn bộ repositories.
Áp dụng kỷ luật Refute-first: chạy Bước 1.1 codebase_scout trước để lập Target Modules Map và phân loại Repo Tier, kiểm thử Python extractor trên canary files ở Bước 1.2, dựng mô hình bất biến S-F-O-P-C ở Bước 1.3, đọc code 1 lượt kèm AI Semantic Clustering ở Bước 1.4, đánh giá kiến trúc xuyên repo ở Bước 1.5 và kiểm toán Visibility Tracker + Evidence Audit ở Bước 1.6.
```

### Bước B — Chạy Phase 2 (Deep Analysis & Falsification v3.0)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0) trên Candidate Queue từ Phase 1.
Chạy tuần tự 4 bước (2.1 -> 2.4): nạp nguyên văn các mô-đun Attack-Class Companion phù hợp, truy vết sâu hops[] + dựng chuỗi tấn công + tìm Root-Cause, chạy phản biện đối kháng ở chế độ Mù Kết luận (Context-Blinded), và qua cổng kiểm toán Empirical Refutations Ledger trước khi chuyển sang Phase 3.
```

### Bước C — Chạy Phase 3 (Contextual Risk & Exploitability Assessment v3.0)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability Assessment v3.0) cho các lỗ hổng đã chứng minh Reachable từ Phase 2.
Chạy tuần tự 3 bước (3.1 -> 3.3): chứng minh Actor/Role tối thiểu nào chạm được code path, kiểm tra bằng chứng cấu hình các lớp kiểm soát ngoài code (Cloudflare WAF vs Bare ALB, VPC 10.x, mTLS, OT Interlock), và hiệu chuẩn rủi ro thực tế trên 5 trục S-F-O-P-C (overall_risk <= max_impact, tách biệt Safety Owner với Security Risk Owner).
```

👉 Tra cứu chi tiết từng sub-skill riêng lẻ (41 skills) và bảng lệnh CLI chuẩn Windows tại **[`.agents/README.md`](./.agents/README.md)**.
