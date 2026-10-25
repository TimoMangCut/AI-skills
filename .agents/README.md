# Hướng dẫn Sử dụng Bộ Skills Bảo mật 3 Phase — LocalSec v3.0 (`.agents/skills/` & `.claude/skills/`)

Tài liệu này là sổ tay tra cứu nhanh cách vận hành hệ thống **LocalSec v3.0 AI Security Review Pipeline** qua **3 Phase chuẩn hóa** cho hệ sinh thái đa sản phẩm & Cyber-Physical (VinFast Connected Car, V-Green EV Charging OCPP/OCPI, VinEnergo BESS SCADA, VinRobotics `vla.cpp` C++/ZeroMQ/ROS2, WebApps/SPAs, Mobile Super-Apps, Multi-Cloud/Edge Cloudflare/Kong/KrakenD/On-Prem, CI/CD ADO/GitHub/ArgoCD, Data/AI Lakehouse, SAP/MuleSoft).

---

## 1. Tổng quan Kiến trúc 3 Phase (LocalSec v3.0) & Cơ chế Chống "Giả vờ Đủ Coverage"

Hệ thống gồm **41 Skills** đồng bộ 100% giữa `.agents/skills/` (Antigravity) và `.claude/skills/` (Claude Code), chia thành **3 Master Orchestrators** và **38 Specialist Sub-skills** (bao gồm 13 skills tinh gọn v3.0 và 25 skills chi tiết v2.4 tương thích ngược):

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

### Bước A — Chạy Toàn bộ Phase 1 (Manual Code Reconnaissance)
```text
/phase-1-orchestrator Thực hiện Phase 1 (Manual Recon) cho toàn bộ repositories trên nhánh <prod|main> (nếu thiếu thì chọn nhánh cập nhật gần nhất và tách riêng Tier A vs Tier B).
Áp dụng kỷ luật Refute-first: không dùng SAST/grep, chỉ đọc file thủ công qua ManualWorkspace để sinh mã ev_..., chạy tuần tự đủ 8 bước (1.1 -> 1.8) kèm kiểm tra phase_status, và bắt buộc qua evidence_auditor hạ cấp fail-closed trước khi tổng hợp hệ thống.
```

### Bước B — Chạy Toàn bộ Phase 2 (Business-Aware Security Verification)
```text
/phase-2-orchestrator Thực hiện Phase 2 (Business-Aware Security Verification) nối tiếp kết quả Phase 1 trên toàn bộ repositories.
Chạy tuần tự đủ 9 bước (2.1 -> 2.9) kèm kiểm tra phase_status: đối chiếu nguồn sự thật nghiệp vụ (BRD/BRS/SQL/Specs), làm mù ngữ cảnh (Context-Blinding) khi chạy Challenger & Targeted Verifier, lập bản đồ liên kết giữa các service và chạy evidence_auditor trước khi tổng hợp.
```

### Bước C — Chạy Toàn bộ Phase 3 (Attack Chain & Root-Cause Analysis)
```text
/phase-3-orchestrator Thực hiện Phase 3 (Attack Chain Analysis) nối tiếp kết quả Phase 1 & 2 để xây dựng và kiểm chứng các chuỗi tấn công đa bước xuyên dịch vụ.
Chạy tuần tự đủ 9 bước (3.1 -> 3.9) kèm kiểm tra phase_status: mọi finding trước đó chỉ là manh mối, phải chứng minh từng mắt xích (step) và từng cạnh chuyển tiếp trạng thái (edge) bằng ev_..., làm mù kết luận khi verify/challenge, truy tới nguyên nhân gốc và tuyệt đối không gán confirmed nếu chỉ có kế hoạch request (request_plan_only).
```

---

## 3. Cách 2: Chạy Lẻ Từng Bước Chuyên Biệt (Granular Mode — 28 Skills)

Khi bạn muốn **chạy lại hoặc kiểm tra sâu đúng 1 bước cụ thể** trên một repository (ví dụ chỉ muốn kiểm tra lại phân quyền API hoặc chỉ muốn chạy lại bộ phản biện chuỗi tấn công), hãy gọi trực tiếp sub-skill đó kèm Prompt bổ trợ tương ứng:

### PHASE 1 — Manual Code Reconnaissance (`/phase-1-*`)

| Thứ tự | Lệnh Skill | Prompt Kích hoạt Tư duy Phản biện (2–3 dòng) |
|---|---|---|
| **1.0** | `/phase-1-orchestrator` | Thực hiện Phase 1 (Manual Recon) cho toàn bộ repositories trên nhánh `<prod\|main>`. Áp dụng kỷ luật Refute-first: chỉ đọc file qua `ManualWorkspace` để sinh mã `ev_...`, chạy tuần tự đủ 8 bước (`1.1 -> 1.8`) kèm `phase_status`, và bắt buộc chạy `evidence_auditor` hạ cấp fail-closed trước khi tổng hợp. |
| **1.1** | `/phase-1-repo-profile` | Khảo sát thủ công cấu trúc, manifest, cấu hình và điểm vào của repository. Đặt câu hỏi phản biện: *"Làm sao biết thành phần này thực sự chạy ở production chứ không phải dead code/template?"* Chỉ đánh dấu `observed` khi có `ev_...` trực tiếp; mọi suy đoán từ tên file phải gắn nhãn `hypothesis` hoặc `unknown`. |
| **1.2** | `/phase-1-api-authz` | Kiểm kê toàn bộ API/RPC entrypoints và truy vết cơ chế xác thực/phân quyền thực tế trong code. Bác bỏ giả định *"chắc middleware hoặc gateway đã chặn"*: nếu không đọc thấy decorator/middleware kiểm tra cả vai trò (RBAC) lẫn quyền sở hữu đối tượng (BOLA/IDOR) trong trích đoạn `ev_...`, phải ghi nhận rõ khoảng trống kiểm soát. |
| **1.3** | `/phase-1-dataflow` | Truy vết luồng dữ liệu từ điểm vào qua xử lý nội bộ tới DB, Queue và các lệnh gọi liên dịch vụ (HTTP/gRPC). Kiểm tra phản biện tại mỗi ranh giới tin cậy (Trust Boundary): danh tính người gọi (`identity_context`) có được truyền nguyên vẹn và xác thực lại ở đầu nhận hay bị tin tưởng mù quáng? |
| **1.4** | `/phase-1-threat-model` | Xây dựng mô hình mối đe dọa STRIDE và kịch bản lạm dụng nghiệp vụ từ kết quả `api_authz` và `dataflow`. Không liệt kê lý thuyết chung chung: mỗi kịch bản đe dọa phải chỉ rõ kẻ tấn công lợi dụng khe hở kiểm soát cụ thể nào trong code (`ev_...`), tài sản nào bị ảnh hưởng và cách kiểm chứng. |
| **1.5** | `/phase-1-architecture-review` | Đánh giá kiến trúc bảo mật, quản lý bí mật, tính nguyên tử giao dịch và khả năng truy vết kiểm toán (auditability). Tự phản biện: một cơ chế phòng thủ có trong thư viện dùng chung nhưng không được gắn vào pipeline khởi tạo (`Program.cs`/`main.go`) thì không được tính là kiểm soát đang hoạt động. |
| **1.6** | `/phase-1-evidence-auditor` | Đóng vai kiểm toán viên độc lập: đọc từng claim và đối chiếu từng chữ với trích đoạn mã nguồn trong `cited_evidence_catalog`. Không chấp nhận suy diễn hợp lý bề ngoài: nếu trích đoạn `ev_...` không trực tiếp chứng minh claim, bắt buộc phán quyết `partially_supported`, `unsupported` hoặc `inconclusive` để hệ thống tự động hạ cấp fail-closed. |
| **1.7** | `/phase-1-cross-repo-review` | Phân tích rủi ro liên dịch vụ trên toàn bộ các repositories đã hoàn tất khảo sát. Tập trung tìm sự bất đối xứng tin cậy: nơi Service A giả định Service B đã kiểm tra quyền/chữ ký, trong khi Service B lại mặc định mọi lệnh gọi nội bộ đều đáng tin cậy. |
| **1.8** | `/phase-1-diagram-author` | Vẽ sơ đồ Mermaid cho từng repository và toàn hệ thống từ kết quả đã qua kiểm toán. Mọi kết nối liên dịch vụ chưa xác minh đủ cả hai đầu phải được vẽ bằng nét đứt hoặc gắn nhãn `hypothesis`/`unknown`, tuyệt đối không vẽ thành luồng xác nhận giả tạo. |

---

### PHASE 2 — Business-Aware Security Verification (`/phase-2-*`)

| Thứ tự | Lệnh Skill | Prompt Kích hoạt Tư duy Phản biện (2–3 dòng) |
|---|---|---|
| **2.0** | `/phase-2-orchestrator` | Thực hiện Phase 2 (BASV) nối tiếp kết quả Phase 1 trên toàn bộ repositories. Chạy tuần tự đủ 9 bước (`2.1 -> 2.9`) kèm `phase_status`: truy tìm nguồn sự thật nghiệp vụ (BRD/BRS/SQL/Specs), làm mù ngữ cảnh (Context-Blinding) khi chạy Challenger & Targeted Verifier, kiểm chứng mối liên kết liên dịch vụ và chạy `evidence_auditor` trước khi tổng hợp. |
| **2.1** | `/phase-2-business-intent-modeler` | Trích xuất quy tắc nghiệp vụ và bất biến bảo mật (`invariants`) từ tài liệu BRD/BRS, đặc tả API, migration SQL và biểu mẫu. Nguyên tắc tối thượng: Code hiện tại KHÔNG phải là ý định thiết kế; nếu phải suy luận từ code (`implementation_inference`), tuyệt đối không được gán `authoritative_in_input`. |
| **2.2** | `/phase-2-business-invariant-challenger` | Phản biện mô hình nghiệp vụ dưới góc nhìn kẻ gian lận (Fraudster/Attacker) trong chế độ mù ngữ cảnh (`prepare_blinded_challenger`). Đặt câu hỏi cho mọi quy trình: *"Điều gì xảy ra nếu bước A bị gọi lặp, bỏ qua bước B, đảo thứ tự trạng thái, hoặc người tạo tự phê duyệt chính hồ sơ của mình?"* |
| **2.3** | `/phase-2-implementation-trace-verifier` | Truy vết từng bước thực thi trong code cho mỗi bất biến nghiệp vụ (`invariants`) và giả thuyết phản biện (`challenge_cases`). Kiểm tra đủ 5 chiều: xác thực/phân quyền, kiểm tra đầu vào, ràng buộc chuyển trạng thái (State Machine), tác động lưu trữ DB/gọi dịch vụ ngoài, và ghi vết audit. |
| **2.4** | `/phase-2-intent-implementation-comparator` | Đối sánh trực tiếp hành vi kỳ vọng (Expected Intent) với hành vi thực tế trong code (Observed Implementation). Tuân thủ cổng bằng chứng kép: chỉ được kết luận `mismatch` ở mức `observed`/`derived` khi có ĐỒNG THỜI cả `intent_evidence_ids` lẫn `implementation_evidence_ids`; nếu ý định mơ hồ phải gán `intent_ambiguous`. |
| **2.5** | `/phase-2-verification-planner` | Thiết kế các nhiệm vụ kiểm chứng mục tiêu (`tasks[]`) với câu hỏi hoàn toàn trung lập và danh sách đường dẫn `candidate_paths` cụ thể. Tuyệt đối không cài kết luận mỏ neo vào câu hỏi: hãy hỏi *"Hàm X kiểm tra điều kiện gì trước khi cập nhật trạng thái Y?"* thay vì *"Hãy xác nhận hàm X bị lỗi thiếu kiểm tra"*. |
| **2.6** | `/phase-2-targeted-verifier` | Chỉ đọc các file nằm trong danh sách cho phép (`--allowed-paths`) để trả lời câu hỏi kiểm chứng một cách khách quan. Bắt buộc tìm kiếm cả bằng chứng ủng hộ (`evidence_ids`) lẫn bằng chứng bác bỏ (`counter_evidence_ids` như guard ở tầng dưới, trigger SQL hoặc điều kiện chặn sớm). |
| **2.7** | `/phase-2-security-consequence-mapper` | Phân biệt rạch ròi giữa lỗi logic nghiệp vụ thuần túy (`business_correctness_only`) và lỗ hổng bảo mật có thể bị khai thác (`security_relevant`). Đánh giá mức độ nghiêm trọng theo ngữ cảnh thực tế: khả năng tự động hóa, vượt chốt kiểm soát tài chính/Maker-Checker, độ rộng vùng ảnh hưởng (blast radius) và các lớp phòng thủ bù trừ. |
| **2.8** | `/phase-2-business-aware-synthesizer` | Tổng hợp kết quả Phase 2 sau khi đã chạy `evidence_auditor`, tách bạch nghiêm ngặt giữa `Confirmed Mismatches` và `Potential/Unverified Mismatches`. Không một sai lệch nào được đưa vào nhóm `Confirmed` nếu chưa vượt qua đủ 6 cổng kiểm định bằng chứng và phản chứng. |

---

### PHASE 3 — Attack Chain & Root-Cause Analysis (`/phase-3-*`)

| Thứ tự | Lệnh Skill | Prompt Kích hoạt Tư duy Phản biện (2–3 dòng) |
|---|---|---|
| **3.0** | `/phase-3-orchestrator` | Thực hiện Phase 3 (Attack Chain Analysis) nối tiếp kết quả Phase 1 & 2 để xây dựng và kiểm chứng các chuỗi tấn công đa bước xuyên dịch vụ. Chạy tuần tự đủ 9 bước (`3.1 -> 3.9`) kèm `phase_status`: mọi finding trước đó chỉ là manh mối, phải chứng minh từng mắt xích (`step`) và từng cạnh chuyển tiếp trạng thái (`edge`) bằng `ev_...`, làm mù kết luận khi verify/challenge, và không gán `confirmed` nếu chỉ có `request_plan_only`. |
| **3.1** | `/phase-3-finding-intake` | Thu nạp các findings từ Phase 1 và mismatches từ Phase 2 dưới dạng các giả thuyết đầu vào (`candidate_claims`), tuyệt đối không mặc định chúng đã đúng. Xác định rõ cho mỗi ứng viên: điều kiện tiên quyết nào còn thiếu, dịch vụ/file nào cần đọc bổ sung, và những mắt xích nào có thể ghép nối thành một chuỗi tấn công hoàn chỉnh. |
| **3.2** | `/phase-3-code-trace-builder` | Truy vết thủ công đường đi thực thi trong mã nguồn từ điểm vào qua từng hàm gọi, middleware, lệnh gọi HTTP/gRPC liên dịch vụ tới câu lệnh lưu trữ DB. Không nhảy cóc qua các lớp trung gian: mỗi hop đánh dấu `directly_read` bắt buộc phải có `evidence_refs` (`ev_...`) chỉ rõ dữ liệu đầu vào biến đổi thế nào và nhánh kiểm tra nào đã thực thi hay bị bỏ qua. |
| **3.3** | `/phase-3-attack-chain-constructor` | Kết nối các điểm yếu rời rạc thành chuỗi tấn công có hướng từ quyền truy cập ban đầu của kẻ tấn công tới tác động nghiệp vụ tối đa có căn cứ. Chứng minh tính bắc cầu của từng cạnh nối: đầu ra, trạng thái hoặc đặc quyền thu được ở Bước $N$ phải khớp chính xác với điều kiện đầu vào cần thiết để kích hoạt Bước $N+1$. |
| **3.4** | `/phase-3-chain-step-verifier` | Kiểm chứng độc lập từng bước và từng cạnh nối của chuỗi tấn công từ ngữ cảnh đã cắt bỏ kết luận của Constructor (`prepare_blinded_chain_verifier`). Đọc lại mã nguồn độc lập để trả lời: bước này có thực sự chạm tới được với quyền của Actor không, và trạng thái tạo ra ở bước trước có thực sự được bước sau tiêu thụ như tuyên bố không? |
| **3.5** | `/phase-3-request-sequence-designer` | Thiết kế chuỗi request kiểm định giả thuyết sử dụng hoàn toàn biến giữ chỗ (`${BASE_URL}`, `${SYNTHETIC_TOKEN}`) và dữ liệu giả lập an toàn. Mỗi bước request phải định nghĩa rõ tiêu chí phân biệt: phản hồi/trạng thái nào chứng minh kiểm soát bảo mật hoạt động đúng (`expected_safe_outcome`) và dấu hiệu nào chứng minh lỗ hổng tồn tại (`expected_vulnerable_outcome`). |
| **3.6** | `/phase-3-request-reproduction-operator` | Kiểm tra điều kiện an toàn trước khi thực thi bất kỳ request nào qua `run_aca_request_plan`. Nếu không có môi trường local/test được phê duyệt tường minh (`operator_approved: true` trên localhost), bắt buộc giữ nguyên trạng thái `not_executed` — tuyệt đối không giả lập kết quả phản hồi động hay coi HTTP 200 đơn thuần là bằng chứng khai thác thành công. |
| **3.7** | `/phase-3-root-cause-mapper` | Không dừng lại ở vị trí phát sinh lỗi bề mặt (symptom location): hãy truy ngược về tận nguyên nhân gốc rễ trong kiến trúc, mẫu thiết kế phân quyền, ranh giới tin cậy hoặc máy trạng thái. Tìm xem cùng một khiếm khuyết gốc rễ đó đang đồng thời mở đường cho những chuỗi tấn công nào khác trên toàn hệ thống để đề xuất một điểm sửa chữa triệt để ở tầng gốc (`remediation_at_root`). |
| **3.8** | `/phase-3-counterevidence-challenger` | Đóng vai người bác bỏ chuỗi tấn công: chủ động đọc code để tìm các middleware, gateway filter, ràng buộc khóa ngoại/trigger SQL, hoặc điều kiện quyền hạn khiến chuỗi bị đứt gãy. Nếu phát hiện chốt chặn làm gãy một mắt xích, hãy hạ cấp kết luận về phạm vi hẹp nhất còn đúng sự thật, đồng thời kiểm tra xem có lối vào thay thế nào đi vòng qua chốt chặn đó không. |
| **3.9** | `/phase-3-chain-synthesizer` | Tổng hợp báo cáo chuỗi tấn công cấp dự án chỉ sau khi toàn bộ các mắt xích đã đi qua `counterevidence_challenger` và `aca_evidence_auditor`. Phân tầng trung thực giữa chuỗi đã xác nhận động (`confirmed`), chuỗi được chứng minh hoàn toàn bằng mã nguồn (`code_supported`), chuỗi mới xác nhận một phần (`partially_confirmed`), chuỗi giả thuyết (`hypothesized`) và chuỗi đã bị bác bỏ (`refuted`). |

---

## 4. Bảng Tra cứu Nhanh Các Lệnh CLI Chuẩn Windows (`python -m localsec.manual_session`)

Trên nhánh `wins`, `setup.ps1` / `setup.bat` tự động cài cầu nối package `localsec` và thư mục tạm `.localsec/tmp/` tại `<Project-Root>`, giúp mọi thao tác chạy trực tiếp qua `python -m localsec.manual_session` trên cả **PowerShell**, **CMD**, và **Git Bash** mà không cần khai báo biến môi trường POSIX inline:

```powershell
# 0. Các lệnh v3.0 cốt lõi (AI Scout, Tailored Extractor, Attack Companions, Visibility Tracker)
python -m localsec.manual_session register_scout_map <repo_name> .localsec/tmp/codebase_scout.json
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode USE_STANDARD_EXTRACTOR --canary-files <file1> <file2>
python -m localsec.manual_session select_attack_companions <repo_name> --archetypes connected_car_and_ota ev_charging_and_energy
python -m localsec.manual_session audit_visibility <repo_name>
python -m localsec.manual_session diff_prior_run <repo_name> --changed-files <file1>

# 1. Kiểm tra tiến độ hoàn thành các bước của một Phase (1, 2 hoặc 3)
python -m localsec.manual_session phase_status <repo_name> --phase 1
python -m localsec.manual_session phase_status <repo_name> --phase 2
python -m localsec.manual_session phase_status _analysis --phase 3

# 2. Duyệt thư mục và đọc file thủ công để sinh mã bằng chứng ev_...
python -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill codebase_scout
python -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>

# 3. Đọc file liên repo (Federated Cross-Repo Read) cho Phase 1, 2 & 3
python -m localsec.manual_session read_file <repo_name> "<other_repo>:<rel_path>" <start_line> <end_line> --skill intent_invariant_modeler

# 4. Đọc file giới hạn phạm vi (Bounded Read) cho targeted_verifier
python -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill targeted_verifier --allowed-paths <path1> <path2>

# 5. Liệt kê toàn bộ bằng chứng ev_... đã thu thập của một repo
python -m localsec.manual_session list_evidence <repo_name>

# 6. Tạo gói ngữ cảnh làm mù (Context-Blinding) cho Phase 2 & Phase 3
python -m localsec.manual_session prepare_blinded_challenger <repo_name>
python -m localsec.manual_session prepare_blinded_targeted_verifier <repo_name>
python -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# 7. Nộp và kiểm định JSON đầu ra của một skill (Schema + Evidence IDs + Epistemic Gates)
python -m localsec.manual_session submit_skill <repo_name> <skill_name> .localsec/tmp/<skill_name>.json

# 8. Trích xuất danh sách claims để kiểm toán độc lập (Evidence Auditor)
python -m localsec.manual_session extract_claims <repo_name>          # Phase 1
python -m localsec.manual_session extract_basv_claims <repo_name>     # Phase 2
python -m localsec.manual_session extract_aca_claims _analysis        # Phase 3

# 9. Đóng gói và xuất báo cáo cuối cùng cho từng Phase (chỉ chạy được khi phase_status báo FINALIZE_READY)
python -m localsec.manual_session finalize_repo <repo_name>           # Phase 1 (từng repo)
python -m localsec.manual_session finalize_system --cross-repo .localsec/tmp/cross_repo.json --sys-audit .localsec/tmp/sys_audit.json --diagrams .localsec/tmp/diagrams.json
python -m localsec.manual_session finalize_basv_repo <repo_name>      # Phase 2 (từng repo)
python -m localsec.manual_session finalize_basv_system                # Phase 2 (toàn hệ thống)
python -m localsec.manual_session finalize_aca _analysis              # Phase 3 (toàn dự án)
```

---

## 5. Hướng dẫn Áp Dụng Bộ Skills Vào Dự Án Mới Trên Windows (`<Project-Root>\AI-skills\`)

Khi bắt đầu kiểm toán bảo mật cho một dự án mới (`<Project-Root>`) trên Windows, thực hiện 3 bước sau tại `<Project-Root>`:

1. **Clone nhánh `wins` của `AI-skills` vào trong `<Project-Root>` và chạy `setup.ps1` (hoặc `setup.bat`)**:
   ```powershell
   cd <Project-Root>
   git clone -b wins https://github.com/TimoMangCut/AI-skills.git
   .\AI-skills\setup.ps1
   # Hoặc trên CMD:      AI-skills\setup.bat
   # Hoặc trên Git Bash: sh AI-skills/setup.sh
   ```
   - `setup.ps1` / `setup.bat` đồng bộ **41 skills** vào `<Project-Root>\.agents\skills\` và `<Project-Root>\.claude\skills\` (giữ nguyên các skill riêng sẵn có của dự án), tạo cầu nối `<Project-Root>\localsec\__init__.py` cùng `<Project-Root>\.localsec\tmp\`, gộp an toàn `AGENTS.md` / `SOUL.md` / `CLAUDE.md` bằng thẻ `<!-- BEGIN AI-SKILLS:... -->`, và tự động cấu hình `.git/info/exclude` để giữ sạch `git status` cho `<Project-Root>`.
   - Khi muốn gỡ bộ skills khỏi `<Project-Root>`: chạy `.\AI-skills\setup.ps1 --uninstall` (hoặc `AI-skills\setup.bat --uninstall`).
2. **Kiểm tra bộ cổng kiểm định (Unit Tests)**:
   ```powershell
   python -m unittest discover -s AI-skills/tests
   ```
   Đảm bảo toàn bộ unit tests đều `OK`.
3. **Khởi chạy tuần tự**:
   Mở `<Project-Root>` trong Antigravity IDE hoặc Claude Code trên Windows và gọi lần lượt `/phase-1-orchestrator` $\rightarrow$ `/phase-2-orchestrator` $\rightarrow$ `/phase-3-orchestrator`.


