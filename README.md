# LocalSec Antigravity Skills — 3-Phase AI Manual Security Review Pipeline

Bộ công cụ và **28 Antigravity Skills + Always-On Rules (`AGENTS.md`, `SOUL.md`)** độc lập, dùng để kiểm toán bảo mật mã nguồn thủ công bằng AI qua **3 Phase chuẩn hóa** (**Phase 1: Manual Recon**, **Phase 2: Business-Aware Security Verification (BASV)**, **Phase 3: Attack Chain & Root-Cause Analysis (ACA)**) với kỷ luật **Refute-first (Bác bỏ trước, khẳng định sau)**.

Bạn có thể `git clone` repository này ở bất kỳ đâu và sao chép vào thư mục gốc của bất kỳ dự án phần mềm nào để chạy ngay trên **Google Antigravity** (hoặc các AI coding agents tương thích chuẩn `.agents/`).

---

## 1. Cấu trúc Trọn Bộ Đóng Gói (Portable Bundle)

```text
localsec-antigravity-skills/
├── AGENTS.md                  # [Level Root Rule] Phương pháp luận Refute-first (Antigravity tự động nạp)
├── SOUL.md                    # [Level Root Rule] Lớp giá trị cốt lõi (Tiebreaker khi phân vân)
├── .agents/
│   ├── README.md              # Sổ tay vận hành chi tiết 28 Skills (3 Phase) & bảng tra cứu CLI
│   ├── rules/
│   │   └── soul.md            # Always-On Rule tích hợp SOUL vào Antigravity
│   └── skills/                # 28 Skills chuẩn Antigravity (3 Master Orchestrators + 25 Sub-skills)
│       ├── phase-1-*          # 9 Skills cho Phase 1 (Manual Code Reconnaissance)
│       ├── phase-2-*          # 9 Skills cho Phase 2 (Business-Aware Security Verification)
│       └── phase-3-*          # 10 Skills cho Phase 3 (Attack Chain & Root-Cause Analysis)
├── localsec/                  # Bộ máy Python CLI thực thi đọc file (ev_...), kiểm định Schema & Epistemic Gates
├── skills/                    # Prompts & Registry gốc của Phase 1
├── schemas/                   # JSON Schemas kiểm định đầu ra của Phase 1
├── contracts/                 # Hợp đồng, Prompts & JSON Schemas của Phase 2 (BASV) & Phase 3 (ACA)
├── examples/                  # Dự án mẫu (demo-go) để chạy thử nghiệm
├── tests/                     # 27 Unit Tests kiểm định toàn bộ cổng an toàn và Epistemic Gates
├── localsec.toml              # Cấu hình giới hạn đọc file và tham số pipeline
└── pyproject.toml             # Khai báo Python package (Python >= 3.11, không cần thư viện ngoài)
```

---

## 2. Cách Clone & Áp Dụng Vào Bất Kỳ Dự Án Nào

### Bước 1: Clone bộ Skills về máy
```bash
git clone https://github.com/TimoMangCut/AI-skills.git localsec-antigravity-skills
```

### Bước 2: Đưa bộ Skills vào thư mục dự án cần kiểm toán (`<target-project-root>`)
Chép các thành phần cốt lõi vào thư mục gốc chứa các repositories mã nguồn cần review:
```bash
cp -R localsec-antigravity-skills/.agents \
      localsec-antigravity-skills/AGENTS.md \
      localsec-antigravity-skills/SOUL.md \
      localsec-antigravity-skills/localsec \
      localsec-antigravity-skills/skills \
      localsec-antigravity-skills/schemas \
      localsec-antigravity-skills/contracts \
      localsec-antigravity-skills/tests \
      localsec-antigravity-skills/localsec.toml \
      <target-project-root>/
```

### Bước 3: Kiểm tra bộ cổng kiểm định (27 Unit Tests)
Yêu cầu duy nhất: **Python >= 3.11** (chỉ sử dụng thư viện chuẩn của Python, không cần `pip install` bất kỳ thư viện bên thứ ba nào).
```bash
cd <target-project-root>
python3 -m unittest discover -s tests -v
```

### Bước 4: Kích hoạt trong Antigravity
Mở `<target-project-root>` trong Antigravity IDE và gọi lần lượt 3 lệnh Master Orchestrator (hoặc từng sub-skill riêng lẻ):
1. **Phase 1 (Recon — 8 bước)**: `/phase-1-orchestrator`
2. **Phase 2 (BASV — 9 bước)**: `/phase-2-orchestrator`
3. **Phase 3 (Attack Chain — 9 bước)**: `/phase-3-orchestrator`

👉 Xem hướng dẫn chi tiết từng lệnh và mẫu Prompt kích hoạt tư duy phản biện tại **[`.agents/README.md`](./.agents/README.md)**.
