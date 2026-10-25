# Hướng dẫn Sử dụng Bộ 16 Skills Bảo mật 3 Phase — LocalSec v3.0 (`.agents/skills/` & `.claude/skills/`)

Tài liệu này là sổ tay tra cứu nhanh cách vận hành hệ thống **LocalSec v3.0 AI Security Review Pipeline** trên **macOS / Linux** qua **3 Phase chuẩn hóa** cho hệ sinh thái đa sản phẩm & Cyber-Physical (VinFast Connected Car, V-Green EV Charging OCPP/OCPI, VinEnergo BESS SCADA, VinRobotics `vla.cpp` C++/ZeroMQ/ROS2, WebApps/SPAs, Mobile Super-Apps, Multi-Cloud/Edge Cloudflare/Kong/KrakenD/On-Prem, CI/CD ADO/GitHub/ArgoCD, Data/AI Lakehouse, SAP/MuleSoft).

---

## 1. Tổng quan Kiến trúc 3 Phase (LocalSec v3.0) & Cơ chế Chống "Giả vờ Đủ Coverage"

Hệ thống gồm **16 Skills v3.0 thuần khiết** đồng bộ 100% giữa `.agents/skills/` (Antigravity) và `.claude/skills/` (Claude Code), chia thành **3 Master Orchestrators** và **13 Specialist Sub-skills**:

| Phase | Master Orchestrator | Các bước cốt lõi (v3.0) | Mục tiêu cốt lõi |
|---|---|---|---|
| **Phase 1: Unified Reconnaissance** | `/phase-1-orchestrator` | **6 bước (`1.1 -> 1.6`)**: `codebase_scout` $\rightarrow$ `extractor_tailor` $\rightarrow$ `intent_invariant_modeler` $\rightarrow$ `unified_surface_mapper` $\rightarrow$ `cross_repo_and_arch_review` $\rightarrow$ `coverage_and_evidence_auditor` | Gộp Technical Recon + Business/Safety Intent Recon (S-F-O-P-C) trong **1 lượt đọc duy nhất (Single-Pass)**. AI khảo sát cấu trúc thư mục trước (`codebase_scout`), tinh chỉnh/kiểm thử Python extractor trên canary files (`extractor_tailor`), tự gom cụm ngữ nghĩa (`AI Semantic Clustering`) và kiểm toán độ phủ vật lý qua `Visibility Tracker` + `Coverage Ledger`. |
| **Phase 2: Deep Analysis & Falsification** | `/phase-2-orchestrator` | **4 bước (`2.1 -> 2.4`)**: `candidate_intake_planner` $\rightarrow$ `deep_trace_chain_analyst` $\rightarrow$ `blinded_counterevidence_challenger` $\rightarrow$ `analysis_evidence_gate` | Chỉ chạy trên `Candidate Queue` từ Phase 1. Tiêm nguyên văn khối `Attack-Class Companion` (16 mô-đun), truy vết sâu `hops[]`, dựng chuỗi tấn công đa bước, tìm nguyên nhân gốc (`Root-Cause`), và phản biện bác bỏ ở chế độ **Mù Kết luận (`Context-Blinded`)**. |
| **Phase 3: Contextual Risk & Exploitability** | `/phase-3-orchestrator` | **3 bước (`3.1 -> 3.3`)**: `actor_and_feasibility_assessor` $\rightarrow$ `beyond_code_control_mapper` $\rightarrow$ `sfop_risk_calibrator` | Sau khi chứng minh Reachable trong code: chứng minh **Actor/Role tối thiểu nào** chạm được code path, chi phí chiếm đoạt danh tính, các lớp phòng thủ ngoài code (Cloudflare WAF vs Bare ALB, VPC `10.x`, mTLS, OT Interlock), và hiệu chuẩn rủi ro thực tế trên **5 trục S-F-O-P-C** (`overall_risk <= max_impact`, `Safety Owner != Security Risk Owner`). |

### Các Cổng Kiểm Định Tất Định (Deterministic Gates) trong LocalSec v3.0
1. **AI Scout Before Python (`phase-1-codebase-scout` + `phase-1-extractor-tailor`)**: Không bao giờ chạy mù một Python parser cứng nhắc trước khi AI hiểu cách tổ chức code của team. Mọi Python extractor phải vượt qua kiểm thử trên `canary_files` (`canary_verified = true`) hoặc chuyển sang `SKIP_EXTRACTOR_DIRECT_READ`.
2. **AI Semantic Clustering (`100% do AI quyết định`)**: AI nhóm các endpoint dùng chung middleware/guard vào `Shared-Control Group` (kèm `representative_deep_read_evidence_ids`) và dồn ngân sách đọc sâu cho `outliers`.
3. **Physical Visibility Tracker & Anti-Grazing (`audit_visibility`)**: Python chỉ đóng vai trò kế toán viên vật lý: đo tỷ lệ đọc thực tế trên `target_modules` (`unvisited_target_modules == 0`) và chặn hành vi đọc lướt $\le 8$ dòng đầu trên file dài $> 25$ dòng (`shallow_grazing_files == 0`).
4. **3 Luật Cứng S-F-O-P-C ở Phase 3**:
   - Kiểm soát ngoài code ở trạng thái `hypothesis` không được phép gán `mitigation_effect = "blocks_exploit"`.
   - `contextual_risk_rating` (`overall_risk`) $\le$ `max_impact` của 5 trục `Safety · Financial · Operational · Privacy · Compliance` (cấm cộng dồn đa trục).
   - Khi `safety != "negligible"`, bắt buộc khai báo `safety_owner` khác với `risk_owner`.

---

## 2. Cách 1 (Khuyên dùng): Chạy Trọn Bộ Từng Phase Chỉ Với 1 Lệnh

Khi áp dụng cho toàn bộ dự án, bạn chỉ cần gõ **1 lệnh Orchestrator cho mỗi Phase** kèm đoạn Prompt ngắn (2–3 dòng) để kích hoạt kỷ luật tư duy phản biện (*Refute-first*):

### Bước A — Chạy Toàn bộ Phase 1 (Unified Reconnaissance v3.0)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Unified Reconnaissance v3.0 — 6 bước 1.1 -> 1.6) cho toàn bộ repositories.
Áp dụng kỷ luật Refute-first: AI khảo sát cấu trúc trước (codebase_scout), kiểm thử Python extractor trên canary files (extractor_tailor), mô hình hóa bất biến S-F-O-P-C, đọc code 1 lượt kèm AI Semantic Clustering, và vượt qua cổng Visibility Tracker (unvisited_target_modules == 0, shallow_grazing_files == 0).
```

### Bước B — Chạy Toàn bộ Phase 2 (Deep Analysis & Falsification v3.0)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Deep Analysis & Falsification v3.0 — 4 bước 2.1 -> 2.4) trên Candidate Queue từ Phase 1.
Nạp nguyên văn các mô-đun Attack-Class Companion phù hợp, truy vết sâu từng bước nhảy hops[] kèm Root-Cause, chạy phản biện đối kháng ở chế độ Mù Kết luận (blinded_counterevidence_challenger) và khóa sổ qua cổng analysis_evidence_gate.
```

### Bước C — Chạy Toàn bộ Phase 3 (Contextual Risk & Exploitability Assessment v3.0)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Contextual Risk & Exploitability v3.0 — 3 bước 3.1 -> 3.3) cho các lỗ hổng đã chứng minh Reachable ở Phase 2.
Chứng minh Actor/Role tối thiểu chạm được code path, đối chiếu các lớp kiểm soát ngoài code (Cloudflare WAF, Bare ALB, Kong/KrakenD, VPC 10.x, mTLS, OT Interlock) và hiệu chuẩn rủi ro thực tế trên 5 trục S-F-O-P-C (overall_risk <= max_impact).
```

---

## 3. Cách 2: Danh mục Chi tiết 16 Skills v3.0

Khi bạn muốn **chạy lại hoặc kiểm tra sâu đúng 1 bước cụ thể** trên một repository, hãy gọi trực tiếp sub-skill đó kèm Prompt bổ trợ tương ứng:

### PHASE 1 — Unified Reconnaissance (`/phase-1-*` — 7 Skills)

| Thứ tự | Lệnh Skill | Mục tiêu & Cổng Kiểm Định Cốt Lõi |
|---|---|---|
| **1.0** | `/phase-1-orchestrator` | Điều phối tuần tự 6 bước `1.1 -> 1.6` của Phase 1 Unified Reconnaissance v3.0 trên toàn bộ repositories. |
| **1.1** | `/phase-1-codebase-scout` | Khảo sát cấu trúc thư mục và 3–5 file mẫu để xác định `Product Archetypes` (10 hình mẫu), `Repo Tier` (`Tier 1/2/3`), quy ước code của team và đăng ký `Target Modules Map` (`register_scout_map`). |
| **1.2** | `/phase-1-extractor-tailor` | Kiểm thử Python structural extractor trên `canary_files` (`run_tailored_extractor`) hoặc chọn `SKIP_EXTRACTOR_DIRECT_READ` nếu không khớp quy ước code để tránh thiên kiến SAST. |
| **1.3** | `/phase-1-intent-invariant-modeler` | Xây dựng mô hình Ý định Nghiệp vụ và Bất biến An toàn Vật lý trên 5 trục **S-F-O-P-C** từ tài liệu thiết kế/spec/manifest và phản biện tìm bất biến bị bỏ sót. |
| **1.4** | `/phase-1-unified-surface-mapper` | Đọc mã nguồn 1 lượt duy nhất (Single-Pass), tự thực hiện `AI Semantic Clustering` để gom cụm tương đương, đối sánh Ý định vs Triển khai, lập `Candidate Queue` và ghi sổ `Coverage Ledger`. |
| **1.5** | `/phase-1-cross-repo-and-arch-review` | Đánh giá kiến trúc bảo mật, phát hiện lệch giả định tin cậy xuyên dịch vụ/xuyên repo và vẽ sơ đồ Mermaid phân biệt rõ cạnh đã xác nhận (`Confirmed`) với cạnh giả thuyết (`Hypothesis`). |
| **1.6** | `/phase-1-coverage-and-evidence-auditor` | Cổng kiểm toán kép: kiểm tra độ phủ vật lý `Visibility Tracker` chống đọc lướt (`audit_visibility`) và kiểm toán độc lập từng claim đối chiếu với mã bằng chứng `ev_...` (hạ cấp fail-closed). |

---

### PHASE 2 — Deep Analysis & Falsification (`/phase-2-*` — 5 Skills)

| Thứ tự | Lệnh Skill | Mục tiêu & Cổng Kiểm Định Cốt Lõi |
|---|---|---|
| **2.0** | `/phase-2-orchestrator` | Điều phối tuần tự 4 bước `2.1 -> 2.4` của Phase 2 Deep Analysis & Falsification v3.0 trên `Candidate Queue`. |
| **2.1** | `/phase-2-candidate-intake-planner` | Khử trùng lặp `Candidate Queue` từ Phase 1, chia Batch đọc sâu và nạp nguyên văn các khối `Attack-Class Companion` (`select_attack_companions` từ 16 mô-đun chuẩn). |
| **2.2** | `/phase-2-deep-trace-chain-analyst` | Truy vết sâu từng bước nhảy thực thi (`hops[]`), dựng chuỗi tấn công đa bước, truy nguyên nhân gốc (`Root-Cause`) và thiết kế chuỗi request kiểm định giả lập an toàn. |
| **2.3** | `/phase-2-blinded-counterevidence-challenger` | Xác minh độc lập từng mắt xích chuỗi tấn công trong chế độ **Mù Kết luận (`Context-Blinded`)** và chủ động săn tìm bằng chứng phản bác hoặc kiểm soát bù trừ trong code. |
| **2.4** | `/phase-2-analysis-evidence-gate` | Cổng kiểm toán bằng chứng độc lập và lập Sổ cái Phản biện Thực nghiệm (`Empirical Refutations Ledger`) trước khi chuyển các lỗ hổng `Confirmed Reachable` sang Phase 3. |

---

### PHASE 3 — Contextual Risk & Exploitability Assessment (`/phase-3-*` — 4 Skills)

| Thứ tự | Lệnh Skill | Mục tiêu & Cổng Kiểm Định Cốt Lõi |
|---|---|---|
| **3.0** | `/phase-3-orchestrator` | Điều phối tuần tự 3 bước `3.1 -> 3.3` của Phase 3 Contextual Risk & Exploitability Assessment v3.0. |
| **3.1** | `/phase-3-actor-and-feasibility-assessor` | Chứng minh **Actor/Role tối thiểu nào** chạm được code path lỗi, chi phí chiếm đoạt danh tính (`Token/Cert/Key Acquisition Cost`) và các điều kiện vận hành thực tế. |
| **3.2** | `/phase-3-beyond-code-control-mapper` | Đối chiếu các lớp kiểm soát ngoài mã nguồn ứng dụng (Cloudflare WAF vs Bare ALB, Kong/KrakenD, VPC `10.x`, AWS IoT Policy, mTLS, OT Hardware Interlock); cấm dùng kiểm soát `hypothesis` để kết luận `blocks_exploit`. |
| **3.3** | `/phase-3-sfop-risk-calibrator` | Hiệu chuẩn mức độ rủi ro thực tế trên 5 trục **S-F-O-P-C**, tuân thủ luật cứng `overall_risk <= max_impact`, tách biệt `Safety Owner` với `Security Risk Owner` và kích hoạt `Gate 0 / Emergency Brake` khi có nguy cơ an toàn vật lý. |

---

## 4. Bảng Tra cứu Nhanh Các Lệnh CLI (`PYTHONPATH=AI-skills:. python3 -m localsec.manual_session`)

```bash
# 1. Các lệnh v3.0 cốt lõi (AI Scout, Tailored Extractor, Attack Companions, Visibility Tracker)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session register_scout_map <repo_name> /tmp/codebase_scout.json
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session run_tailored_extractor <repo_name> --mode USE_STANDARD_EXTRACTOR --canary-files <file1> <file2>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session select_attack_companions <repo_name> --archetypes connected_car_and_ota ev_charging_and_energy
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session audit_visibility <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 2. Kiểm tra tiến độ hoàn thành các bước của một Phase (1, 2 hoặc 3)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 1
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status <repo_name> --phase 2
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session phase_status _analysis --phase 3

# 3. Duyệt thư mục và đọc file thủ công để sinh mã bằng chứng ev_...
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>

# 4. Đọc file liên repo (Federated Cross-Repo Read) cho Phase 2 & Phase 3
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> "<other_repo>:<rel_path>" <start_line> <end_line> --skill intent_invariant_modeler

# 5. Đọc file giới hạn phạm vi (Bounded Read) cho bước kiểm chứng mù
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill blinded_counterevidence_challenger --allowed-paths <path1> <path2>

# 6. Liệt kê toàn bộ bằng chứng ev_... đã thu thập của một repo
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session list_evidence <repo_name>

# 7. Tạo gói ngữ cảnh làm mù (Context-Blinding) cho Phase 2 & Phase 3
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_challenger <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_targeted_verifier <repo_name>
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# 8. Nộp và kiểm định JSON đầu ra của một skill (Schema + Evidence IDs + Epistemic Gates)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session submit_skill <repo_name> <skill_name> /tmp/<skill_name>.json

# 9. Trích xuất danh sách claims để kiểm toán độc lập (Evidence Auditor)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_claims <repo_name>          # Phase 1
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_basv_claims <repo_name>     # Phase 2
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session extract_aca_claims _analysis        # Phase 3

# 10. Đóng gói và xuất báo cáo cuối cùng cho từng Phase
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_repo <repo_name>           # Phase 1 (từng repo)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_system                     # Phase 1 (toàn hệ thống)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_basv_repo <repo_name>      # Phase 2 (từng repo)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_basv_system                # Phase 2 (toàn hệ thống)
PYTHONPATH=AI-skills:. python3 -m localsec.manual_session finalize_aca _analysis              # Phase 3 (toàn dự án)
```

---

## 5. Hướng dẫn Áp Dụng Bộ Skills Vào Dự Án Mới (`<Project-Root>/AI-skills/`)

1. **Clone `AI-skills` vào trong `<Project-Root>` và chạy `setup.sh`**:
   ```bash
   cd <Project-Root>
   git clone -b mac https://github.com/TimoMangCut/AI-skills.git
   sh AI-skills/setup.sh
   ```
   - `setup.sh` đồng bộ 16 skills v3.0 vào `<Project-Root>/.agents/skills/` và `.claude/skills/` (giữ nguyên các skill riêng sẵn có của dự án), gộp an toàn `AGENTS.md` / `SOUL.md` / `CLAUDE.md` bằng thẻ `<!-- BEGIN AI-SKILLS:... -->`, và cấu hình `.git/info/exclude`.
   - Khi muốn gỡ bộ skills khỏi `<Project-Root>`: chạy `sh AI-skills/setup.sh --uninstall`.
2. **Kiểm tra bộ cổng kiểm định (Unit Tests)**:
   ```bash
   PYTHONPATH=AI-skills:. python3 -m unittest discover -s AI-skills/tests -v
   ```
   Đảm bảo toàn bộ unit tests đều `OK`.
3. **Khởi chạy tuần tự**:
   Mở `<Project-Root>` trong Antigravity IDE hoặc Claude Code và gọi lần lượt `/phase-1-orchestrator` $\rightarrow$ `/phase-2-orchestrator` $\rightarrow$ `/phase-3-orchestrator` theo đúng các mẫu Prompt ở **Mục 2**.
