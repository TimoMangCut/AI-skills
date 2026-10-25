# AI-skills — LocalSec v3.0 Security Review Pipeline (macOS / Linux Edition — Antigravity & Claude Code)

Bộ **16 Skills v3.0 (`.agents/skills/` & `.claude/skills/`) + Always-On Rules (`AGENTS.md`, `SOUL.md`, `CLAUDE.md`) + Python Epistemic Engine (`localsec`)** dùng để kiểm toán bảo mật mã nguồn và kiến trúc bằng AI qua **3 Phase chuẩn hóa v3.0**:
- **Phase 1 — Unified Reconnaissance (`/phase-1-orchestrator` — 6 bước `1.1 -> 1.6`)**: AI Scouting (`codebase_scout`), Tailored Python Extractor (`extractor_tailor`), Mô hình hóa Ý định & Bất biến S-F-O-P-C (`intent_invariant_modeler`), Đọc mã nguồn 1 lượt kèm AI Semantic Clustering (`unified_surface_mapper`), Kiến trúc Xuyên Repo (`cross_repo_and_arch_review`), và Kiểm toán Độ phủ Vật lý `Visibility Tracker` + Bằng chứng `ev_...` (`coverage_and_evidence_auditor`).
- **Phase 2 — Deep Analysis & Falsification (`/phase-2-orchestrator` — 4 bước `2.1 -> 2.4`)**: Lọc trùng & nạp nguyên văn `Attack-Class Companions` (`candidate_intake_planner`), Truy vết sâu `hops[]` + Chuỗi tấn công + `Root-Cause` (`deep_trace_chain_analyst`), Phản biện đối kháng ở chế độ **Mù Kết luận (`blinded_counterevidence_challenger`)**, và Cổng Kiểm toán Bằng chứng kèm `Empirical Refutations Ledger` (`analysis_evidence_gate`).
- **Phase 3 — Contextual Risk & Exploitability Assessment (`/phase-3-orchestrator` — 3 bước `3.1 -> 3.3`)**: Chứng minh Actor/Role tối thiểu chạm được code path (`actor_and_feasibility_assessor`), Đối chiếu Kiểm soát Ngoài Code (`beyond_code_control_mapper` — Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC `10.x`, mTLS, OT Interlock), và Hiệu chuẩn Rủi ro 5 Trục **S-F-O-P-C** (`sfop_risk_calibrator`).

---

## 1. Cấu trúc Khi Clone Vào Một Project Cần Áp Dụng (`<Project-Root>`)

```text
<Project-Root>/                        <-- Mở thư mục này trong Antigravity IDE hoặc Claude Code
├── <service-repo-1>/                  <-- Các repo mã nguồn của dự án cần review
├── <service-repo-2>/
├── <docs-or-brd>/                     <-- Tài liệu nghiệp vụ BRD/BRS/Specs của dự án (nếu có)
├── documents/                         <-- Báo cáo đầu ra (Phase 1, 2, 3) sẽ tự động xuất ra đây
├── .localsec/                         <-- Trạng thái phiên làm việc & mã bằng chứng ev_... tự sinh tại đây
│
├── AGENTS.md                          <-- [Merge từ AI-skills] Rule Refute-first (Antigravity nạp)
├── SOUL.md                            <-- [Merge từ AI-skills] Lớp giá trị cốt lõi
├── CLAUDE.md                          <-- [Merge từ AI-skills] Entrypoint cho Claude Code (@SOUL.md, @AGENTS.md)
├── .agents/                           <-- [Copy từ AI-skills] 16 Skills v3.0 & Rules chuẩn Antigravity
│   ├── README.md                      <-- Sổ tay tra cứu nhanh các lệnh & mẫu Prompt
│   ├── rules/soul.md
│   └── skills/phase-{1,2,3}-*/SKILL.md
├── .claude/                           <-- [Copy từ AI-skills] 16 Skills v3.0 chuẩn Claude Code
│   └── skills/phase-{1,2,3}-*/SKILL.md
│
└── AI-skills/                         <-- Thư mục git clone nằm gọn một chỗ, AI tự ánh xạ vào đây
    ├── setup.sh                       <-- Script tự động đồng bộ 16 skills, AGENTS.md, SOUL.md, CLAUDE.md
    ├── localsec/                      <-- Bộ máy Python CLI (manual_session.py, orchestrator.py, validators.py, workspace.py...)
    ├── skills/                        <-- Prompts & Registry gốc
    ├── schemas/                       <-- JSON Schemas (AI-skills/schemas/*.schema.json)
    ├── contracts/                     <-- Contracts, Schemas & 16 Attack-Class Companions (AI-skills/contracts/...)
    ├── examples/                      <-- Repo mẫu (demo-go)
    ├── tests/                         <-- 39 Unit Tests kiểm định toàn bộ cổng an toàn v3.0
    └── localsec.toml                  <-- Cấu hình mặc định của bộ tool
```

---

## 2. Cách Cài Đặt Vào Project Mới (Chỉ 2 Lệnh)

Đứng tại thư mục gốc của dự án cần kiểm toán (`<Project-Root>`):

```bash
# 1. Clone nhánh mac của AI-skills vào trong <Project-Root>
git clone -b mac https://github.com/TimoMangCut/AI-skills.git

# 2. Chạy script cài đặt tự động
sh AI-skills/setup.sh
```

- **Khi muốn gỡ sạch khỏi `<Project-Root>` sau khi kiểm toán xong**:
  ```bash
  sh AI-skills/setup.sh --uninstall
  ```

---

## 3. Cách Khởi Chạy Trên Antigravity / Claude Code

Mở `<Project-Root>` trong Antigravity IDE hoặc Claude Code và gọi tuần tự:

### Bước A — Chạy Phase 1 (Unified Reconnaissance v3.0)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0 — 6 bước 1.1 -> 1.6) cho toàn bộ repositories.
Áp dụng kỷ luật Refute-first: AI khảo sát cấu trúc trước (codebase_scout), kiểm thử Python extractor trên canary files (extractor_tailor), mô hình hóa bất biến S-F-O-P-C, đọc code 1 lượt kèm AI Semantic Clustering, và vượt qua cổng Visibility Tracker (unvisited_target_modules == 0, shallow_grazing_files == 0).
```

### Bước B — Chạy Phase 2 (Deep Analysis & Falsification v3.0)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0 — 4 bước 2.1 -> 2.4) trên Candidate Queue từ Phase 1.
Nạp nguyên văn các mô-đun Attack-Class Companion phù hợp, truy vết sâu từng bước nhảy hops[] kèm Root-Cause, chạy phản biện đối kháng ở chế độ Mù Kết luận (blinded_counterevidence_challenger) và khóa sổ qua cổng analysis_evidence_gate.
```

### Bước C — Chạy Phase 3 (Contextual Risk & Exploitability Assessment v3.0)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability v3.0 — 3 bước 3.1 -> 3.3) cho các lỗ hổng đã chứng minh Reachable ở Phase 2.
Chứng minh Actor/Role tối thiểu chạm được code path, đối chiếu các lớp kiểm soát ngoài code (Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC 10.x, mTLS, OT Interlock) và hiệu chuẩn rủi ro thực tế trên 5 trục S-F-O-P-C (overall_risk <= max_impact).
```

👉 Tra cứu chi tiết từng sub-skill riêng lẻ (16 skills v3.0) và bảng lệnh CLI tại **[`.agents/README.md`](./.agents/README.md)**.
