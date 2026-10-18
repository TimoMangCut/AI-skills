# AI-skills — LocalSec 3-Phase Antigravity Security Review Pipeline

Bộ **28 Antigravity Skills + Always-On Rules (`AGENTS.md`, `SOUL.md`) + Python Epistemic Engine (`localsec`)** dùng để kiểm toán bảo mật mã nguồn thủ công bằng AI qua **3 Phase chuẩn hóa**:
- **Phase 1**: Manual Code Reconnaissance (`/phase-1-orchestrator` — 8 bước)
- **Phase 2**: Business-Aware Security Verification / BASV (`/phase-2-orchestrator` — 9 bước)
- **Phase 3**: Attack Chain & Root-Cause Analysis / ACA (`/phase-3-orchestrator` — 9 bước)

---

## 1. Cấu trúc Khi Clone Vào Một Project Cần Áp Dụng (`<Project-Root>`)

Khi bạn cần áp dụng bộ Skills này vào một dự án thực tế (`<Project-Root>`), bạn **chỉ cần đưa `.agents/`, `AGENTS.md`, `SOUL.md` ra ngoài gốc Project** để Antigravity nhận diện lệnh `/phase-*` và Rules, còn **toàn bộ Engine (`localsec/`), JSON Schemas (`schemas/`), Contracts (`contracts/`) vẫn nằm nguyên gọn gàng trong thư mục `AI-skills/`**:

```text
<Project-Root>/                        <-- Mở thư mục này trong Antigravity IDE (Working Directory)
├── <service-repo-1>/                  <-- Các repo mã nguồn của dự án cần review
├── <service-repo-2>/
├── <docs-or-brd>/                     <-- Tài liệu nghiệp vụ BRD/BRS/Specs của dự án (nếu có)
├── documents/                         <-- Báo cáo đầu ra (Phase 1, 2, 3) sẽ tự động xuất ra đây
├── .localsec/                         <-- Trạng thái phiên làm việc & mã bằng chứng ev_... tự sinh tại đây
│
├── AGENTS.md                          <-- [Copy từ AI-skills ra] Rule Refute-first (Antigravity tự động nạp)
├── SOUL.md                            <-- [Copy từ AI-skills ra] Lớp giá trị cốt lõi
├── .agents/                           <-- [Copy từ AI-skills ra] 28 Skills đã trỏ sẵn đường dẫn vào AI-skills/...
│   ├── README.md                      <-- Sổ tay tra cứu nhanh các lệnh & mẫu Prompt
│   ├── rules/soul.md
│   └── skills/phase-{1,2,3}-*/SKILL.md
│
└── AI-skills/                         <-- Thư mục git clone nằm gọn một chỗ, AI tự ánh xạ vào đây
    ├── setup.sh                       <-- Script tự động copy .agents, AGENTS.md, SOUL.md ra <Project-Root>
    ├── localsec/                      <-- Bộ máy Python CLI (manual_session.py, validators.py, workspace.py...)
    ├── skills/                        <-- Prompts & Registry gốc của Phase 1
    ├── schemas/                       <-- JSON Schemas của Phase 1 (AI-skills/schemas/*.schema.json)
    ├── contracts/                     <-- Contracts & Schemas của Phase 2 & Phase 3 (AI-skills/contracts/...)
    ├── examples/                      <-- Repo mẫu (demo-go)
    ├── tests/                         <-- Unit Tests kiểm định toàn bộ cổng an toàn
    └── localsec.toml                  <-- Cấu hình mặc định của bộ tool
```

### Tại sao thiết kế theo cấu trúc này?
1. **Không làm bẩn `<Project-Root>`**: Bạn không phải rải `localsec/`, `schemas/`, `contracts/`, `skills/`, `tests/`, `localsec.toml` ra ngoài thư mục gốc của dự án.
2. **Đường dẫn trong 28 file `SKILL.md` đã được chuẩn hóa sang `AI-skills/...`**:
   - Mọi liên kết Schema/Contract trong `.agents/skills/*/SKILL.md` đều chỉ thẳng vào `AI-skills/schemas/...` và `AI-skills/contracts/...`. AI đọc `SKILL.md` sẽ tìm đúng trong thư mục `AI-skills/` ngay trước mặt nó.
   - Mọi lệnh CLI trong `SKILL.md` đều dùng `PYTHONPATH=AI-skills:. python3 -m localsec.manual_session ...`.
   - Bản thân `AI-skills/localsec/manual_session.py` tự động nhận biết nó đang nằm trong `<Project-Root>/AI-skills/` để đọc các `<service-repo>` ở ngoài `<Project-Root>/` và ghi báo cáo ra `<Project-Root>/documents/`.

---

## 2. Cách Cài Đặt Vào Project Mới (Chỉ 2 Lệnh)

Đứng tại thư mục gốc của dự án cần kiểm toán (`<Project-Root>`):

```bash
# 1. Clone bộ AI-skills vào trong <Project-Root>
git clone https://github.com/TimoMangCut/AI-skills.git

# 2. Chạy script cài đặt (tự động copy .agents/, AGENTS.md, SOUL.md ra ngoài <Project-Root> và chạy test)
sh AI-skills/setup.sh
```

*(Hoặc nếu muốn copy thủ công không qua script: `cp -R AI-skills/.agents AI-skills/AGENTS.md AI-skills/SOUL.md .`)*

---

## 3. Cách Khởi Chạy Trên Antigravity

Mở `<Project-Root>` trong Antigravity IDE và gọi tuần tự:

### Bước A — Chạy Phase 1 (Manual Code Reconnaissance)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Manual Recon) cho toàn bộ repositories trên nhánh <prod|main> (nếu thiếu thì chọn nhánh cập nhật gần nhất và tách riêng Tier A vs Tier B).
Áp dụng kỷ luật Refute-first: không dùng SAST/grep, chỉ đọc file thủ công qua ManualWorkspace để sinh mã ev_..., chạy tuần tự đủ 8 bước (1.1 -> 1.8) kèm kiểm tra phase_status, và bắt buộc qua evidence_auditor hạ cấp fail-closed trước khi tổng hợp hệ thống.
```

### Bước B — Chạy Phase 2 (Business-Aware Security Verification)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Business-Aware Security Verification) nối tiếp kết quả Phase 1 trên toàn bộ repositories.
Chạy tuần tự đủ 9 bước (2.1 -> 2.9) kèm kiểm tra phase_status: đối chiếu nguồn sự thật nghiệp vụ (BRD/BRS/SQL/Specs), làm mù ngữ cảnh (Context-Blinding) khi chạy Challenger & Targeted Verifier, lập bản đồ liên kết giữa các service và chạy evidence_auditor trước khi tổng hợp.
```

### Bước C — Chạy Phase 3 (Attack Chain & Root-Cause Analysis)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Attack Chain Analysis) nối tiếp kết quả Phase 1 & 2 để xây dựng và kiểm chứng các chuỗi tấn công đa bước xuyên dịch vụ.
Chạy tuần tự đủ 9 bước (3.1 -> 3.9) kèm kiểm tra phase_status: mọi finding trước đó chỉ là manh mối, phải chứng minh từng mắt xích (step) và từng cạnh chuyển tiếp trạng thái (edge) bằng ev_..., làm mù kết luận khi verify/challenge, truy tới nguyên nhân gốc và tuyệt đối không gán confirmed nếu chỉ có kế hoạch request (request_plan_only).
```

👉 Tra cứu chi tiết từng sub-skill riêng lẻ (28 skills) và bảng lệnh CLI tại **[`.agents/README.md`](./.agents/README.md)**.
