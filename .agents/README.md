# Hướng dẫn Sử dụng Bộ 16 Skills Bảo mật 3 Phase — LocalSec v3.0 (`.agents/skills/` & `.claude/skills/`)

Tài liệu này là sổ tay tra cứu nhanh cách vận hành hệ thống **LocalSec v3.0 AI Security Review Pipeline** qua **3 Phase chuẩn hóa** cho hệ sinh thái đa sản phẩm & Cyber-Physical (VinFast Connected Car, V-Green EV Charging OCPP/OCPI, VinEnergo BESS SCADA, VinRobotics `vla.cpp` C++/ZeroMQ/ROS2, WebApps/SPAs, Mobile Super-Apps, Multi-Cloud/Edge Cloudflare/Kong/KrakenD/On-Prem, CI/CD ADO/GitHub/ArgoCD, Data/AI Lakehouse, SAP/MuleSoft).

---

## 1. Tổng quan Kiến trúc 3 Phase (LocalSec v3.0 — 16 Skills Tinh Gọn)

Hệ thống gồm **16 Skills thuần v3.0** đồng bộ 100% giữa `.agents/skills/` (Antigravity) và `.claude/skills/` (Claude Code), chia thành **3 Master Orchestrators** và **13 Specialist Sub-skills** (đã loại bỏ hoàn toàn 25 skills v2 cũ để chống nhiễu ngữ cảnh và xung đột đánh số Phase):

| Phase | Master Orchestrator | Các bước cốt lõi (13 Sub-skills v3.0) | Mục tiêu cốt lõi |
|---|---|---|---|
| **Phase 1: Unified Reconnaissance** | `/phase-1-orchestrator` | **6 bước (`1.1 -> 1.6`)**: `codebase_scout` $\rightarrow$ `extractor_tailor` $\rightarrow$ `intent_invariant_modeler` $\rightarrow$ `unified_surface_mapper` $\rightarrow$ `cross_repo_and_arch_review` $\rightarrow$ `coverage_and_evidence_auditor` | Gộp Technical Recon + Business/Safety Intent Recon (S-F-O-P-C) trong **1 lượt đọc duy nhất (Single-Pass)**. AI khảo sát cấu trúc thư mục trước (`codebase_scout`), tinh chỉnh/kiểm thử Python extractor trên canary files (`extractor_tailor`), tự gom cụm ngữ nghĩa (`AI Semantic Clustering`) và kiểm toán độ phủ vật lý qua `Visibility Tracker` + `Coverage Ledger`. |
| **Phase 2: Deep Analysis & Falsification** | `/phase-2-orchestrator` | **4 bước (`2.1 -> 2.4`)**: `candidate_intake_planner` $\rightarrow$ `deep_trace_chain_analyst` $\rightarrow$ `blinded_counterevidence_challenger` $\rightarrow$ `analysis_evidence_gate` | Chỉ chạy trên `Candidate Queue` từ Phase 1. Tiêm nguyên văn khối `Attack-Class Companion` (16 mô-đun), truy vết sâu `hops[]`, dựng chuỗi tấn công đa bước, tìm nguyên nhân gốc (`Root-Cause`), và phản biện bác bỏ ở chế độ **Mù Kết luận (`Context-Blinded`)**. |
| **Phase 3: Contextual Risk & Exploitability** | `/phase-3-orchestrator` | **3 bước (`3.1 -> 3.3`)**: `actor_and_feasibility_assessor` $\rightarrow$ `beyond_code_control_mapper` $\rightarrow$ `sfop_risk_calibrator` | Sau khi chứng minh Reachable trong code: chứng minh **Actor/Role tối thiểu nào** chạm được code path, chi phí chiếm đoạt danh tính, các lớp phòng thủ ngoài code (Cloudflare WAF vs Bare ALB, VPC `10.x`, mTLS, OT Interlock), và hiệu chuẩn rủi ro thực tế trên **5 trục S-F-O-P-C** (`overall_risk <= max_impact`, `Safety Owner != Security Risk Owner`). |

---

## 2. Cách 1 (Khuyên dùng): Chạy Trọn Bộ Từng Phase Chỉ Với 1 Lệnh

### Bước A — Chạy Toàn bộ Phase 1 (Unified Reconnaissance v3.0)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0) cho toàn bộ repositories.
Áp dụng kỷ luật Refute-first: chạy tuần tự 6 bước (1.1 -> 1.6) từ codebase_scout, extractor_tailor, intent_invariant_modeler, unified_surface_mapper, cross_repo_and_arch_review đến coverage_and_evidence_auditor; đảm bảo Visibility Tracker đạt 0 unvisited_target_modules và 0 shallow_grazing_files.
```

### Bước B — Chạy Toàn bộ Phase 2 (Deep Analysis & Falsification v3.0)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0) nối tiếp Candidate Queue từ Phase 1.
Chạy tuần tự 4 bước (2.1 -> 2.4): nạp nguyên văn các khối Attack-Class Companion, truy vết sâu hops[] + dựng chuỗi tấn công + tìm Root-Cause, chạy phản biện đối kháng ở chế độ Mù Kết luận (Context-Blinded) và kiểm toán qua cổng analysis_evidence_gate.
```

### Bước C — Chạy Toàn bộ Phase 3 (Contextual Risk & Exploitability Assessment v3.0)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability Assessment v3.0) cho các chuỗi tấn công đã chứng minh Reachable từ Phase 2.
Chạy tuần tự 3 bước (3.1 -> 3.3): chứng minh Actor/Role tối thiểu chạm được code path, đối chiếu các lớp kiểm soát ngoài code (Cloudflare WAF vs Bare ALB, VPC 10.x, mTLS, OT Interlock) và hiệu chuẩn rủi ro 5 trục S-F-O-P-C.
```

---

## 3. Cách 2: Bảng Tra cứu Chi tiết 16 Skills Chuẩn v3.0

### PHASE 1 — Unified Reconnaissance (`/phase-1-*` — 7 Skills)

| Thứ tự | Lệnh Skill | Vai trò & Cổng kiểm định cốt lõi |
|---|---|---|
| **1.0** | `/phase-1-orchestrator` | Điều phối trọn bộ 6 bước Phase 1 Unified Reconnaissance v3.0. |
| **1.1** | `/phase-1-codebase-scout` | Khảo sát nhanh cấu trúc thư mục và 3–5 file mẫu để xác định Product Archetypes, Repo Tier (`tier_1`/`tier_2`/`tier_3`), quy ước code và lập `Target Modules Map`. |
| **1.2** | `/phase-1-extractor-tailor` | Đánh giá/tinh chỉnh Python structural extractor trên `canary_files` (`canary_verified = true`) hoặc chọn `SKIP_EXTRACTOR_DIRECT_READ`. |
| **1.3** | `/phase-1-intent-invariant-modeler` | Xây dựng mô hình Ý định Nghiệp vụ & Bất biến An toàn Vật lý (5 trục S-F-O-P-C) từ tài liệu/spec/manifest mà không suy diễn ngược từ code. |
| **1.4** | `/phase-1-unified-surface-mapper` | Đọc mã nguồn 1 lượt (Single-Pass), thực hiện AI Semantic Clustering, đối sánh Ý định vs Triển khai, ghi sổ `coverage_ledger.json` và lập `Candidate Queue`. |
| **1.5** | `/phase-1-cross-repo-and-arch-review` | Phát hiện lệch giả định tin cậy xuyên dịch vụ/xuyên repo và vẽ sơ đồ Mermaid phân biệt rõ cạnh đã xác nhận (`-->`) với cạnh giả thuyết (`-.->`). |
| **1.6** | `/phase-1-coverage-and-evidence-auditor` | Cổng kiểm toán độc lập kết hợp kiểm tra bằng chứng `ev_...` (Fail-Closed) và kiểm tra độ phủ vật lý `Visibility Tracker` chống đọc lướt (`Anti-Grazing`). |

### PHASE 2 — Deep Analysis & Falsification (`/phase-2-*` — 5 Skills)

| Thứ tự | Lệnh Skill | Vai trò & Cổng kiểm định cốt lõi |
|---|---|---|
| **2.0** | `/phase-2-orchestrator` | Điều phối trọn bộ 4 bước Phase 2 Deep Analysis & Falsification v3.0 trên `Candidate Queue`. |
| **2.1** | `/phase-2-candidate-intake-planner` | Tiếp nhận `Candidate Queue` từ Phase 1, xếp hạng ưu tiên và chọn các khối `Attack-Class Companion` nguyên văn. |
| **2.2** | `/phase-2-deep-trace-chain-analyst` | Truy vết sâu từng bước nhảy thực thi (`hops[]`), dựng chuỗi tấn công đa bước, truy nguyên nhân gốc (`Root-Cause`) và thiết kế chuỗi request kiểm định. |
| **2.3** | `/phase-2-blinded-counterevidence-challenger` | Xác minh độc lập từng mắt xích chuỗi tấn công trong chế độ **Mù Kết luận (`Context-Blinded`)** và săn tìm kiểm soát bù trừ trong code. |
| **2.4** | `/phase-2-analysis-evidence-gate` | Cổng kiểm toán bằng chứng độc lập và Sổ cái Phản biện Thực nghiệm (`Empirical Refutations Ledger`) trước khi chuyển sang Phase 3. |

### PHASE 3 — Contextual Risk & Exploitability Assessment (`/phase-3-*` — 4 Skills)

| Thứ tự | Lệnh Skill | Vai trò & Cổng kiểm định cốt lõi |
|---|---|---|
| **3.0** | `/phase-3-orchestrator` | Điều phối trọn bộ 3 bước Phase 3 Contextual Risk & Exploitability Assessment v3.0. |
| **3.1** | `/phase-3-actor-and-feasibility-assessor` | Chứng minh Actor/Role tối thiểu nào chạm được code path lỗi, chi phí chiếm đoạt danh tính và điều kiện vận hành tiên quyết. |
| **3.2** | `/phase-3-beyond-code-control-mapper` | Đánh giá các lớp kiểm soát ngoài mã nguồn (Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC `10.x`, AWS IoT Policy, mTLS, OT Interlock); chặn gán `blocks_exploit` cho kiểm soát `hypothesis`. |
| **3.3** | `/phase-3-sfop-risk-calibrator` | Hiệu chuẩn rủi ro thực tế trên 5 trục **S-F-O-P-C** (`overall_risk <= max_impact`) và tách biệt `safety_owner` khỏi `risk_owner`. |

---

## 4. Bảng Tra cứu Nhanh Các Lệnh CLI Chuẩn Windows (`python -m localsec.manual_session`)

Trên nhánh `wins`, `setup.ps1` / `setup.bat` tự động cài cầu nối package `localsec` và thư mục tạm `.localsec/tmp/` tại `<Project-Root>`, giúp mọi thao tác chạy trực tiếp qua `python -m localsec.manual_session` trên cả **PowerShell**, **CMD**, và **Git Bash** mà không cần khai báo biến môi trường POSIX inline:

```powershell
# 1. Các lệnh v3.0 cốt lõi (AI Scout, Tailored Extractor, Attack Companions, Visibility Tracker)
python -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout.json
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode USE_STANDARD_EXTRACTOR --canary-files <file1> <file2>
python -m localsec.manual_session select_attack_companions <repo_name> --archetypes connected_car_and_ota ev_charging_and_energy
python -m localsec.manual_session audit_visibility <repo_name>
python -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 2. Kiểm tra tiến độ hoàn thành các bước của một Phase (1, 2 hoặc 3)
python -m localsec.manual_session phase_status <repo_name> --phase 1
python -m localsec.manual_session phase_status <repo_name> --phase 2
python -m localsec.manual_session phase_status _analysis --phase 3

# 3. Duyệt thư mục và đọc file thủ công để sinh mã bằng chứng ev_...
python -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
python -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>

# 4. Đọc file liên repo (Federated Cross-Repo Read)
python -m localsec.manual_session read_file <repo_name> "<other_repo>:<rel_path>" <start_line> <end_line> --skill intent_invariant_modeler

# 5. Tạo gói ngữ cảnh làm mù (Context-Blinding)
python -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# 6. Nộp và kiểm định JSON đầu ra của một skill + Kiểm toán ngữ nghĩa
python -m localsec.manual_session submit_skill <repo_name> <skill_name> .localsec/tmp/<skill_name>.json
python -m localsec.manual_session verify_semantic_claims <repo_name>
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
