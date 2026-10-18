# Hướng dẫn Sử dụng Bộ Skills Bảo mật 3 Phase (`.agents/skills/`)

Tài liệu này là sổ tay tra cứu nhanh cách vận hành hệ thống **LocalSec AI Security Review Pipeline** qua 3 Phase chuẩn hóa (**Phase 1: Recon**, **Phase 2: BASV**, **Phase 3: Attack Chain & Root-Cause Analysis**). Bạn có thể dùng tài liệu này cho dự án hiện tại hoặc sao chép nguyên bộ sang bất kỳ dự án mới nào.

---

## 1. Tổng quan Kiến trúc 3 Phase & Cơ chế "Khóa Kép" (Dual-Lock)

Hệ thống gồm **28 Skills** trong `.agents/skills/`, chia thành **3 Master Orchestrators** (điều phối trọn gói từng Phase) và **25 Specialist Sub-skills** (chuyên trách từng bước con):

| Phase | Master Orchestrator | Số bước bắt buộc | Mục tiêu cốt lõi | Thư mục đầu ra (`./documents/`) |
|---|---|---|---|---|
| **Phase 1** | `/phase-1-orchestrator` | **8 bước** (`1.1 -> 1.8`) | Khảo sát mã nguồn thủ công (`ManualWorkspace`), kiểm kê API/AuthZ, Dataflow, STRIDE Threat Model, Architecture Review, kiểm toán bằng chứng (`evidence_auditor`) và tổng hợp liên repo (`cross_repo_review`). | `./documents/<repo_name>/` & `./documents/_system/` |
| **Phase 2** | `/phase-2-orchestrator` | **9 bước** (`2.1 -> 2.9`) | Đối chiếu Ý định Nghiệp vụ (BRD/BRS/SQL/Specs) với Triển khai Thực tế (BASV), phản biện bất biến ở chế độ mù ngữ cảnh (`prepare_blinded_challenger`), kiểm chứng giới hạn đường dẫn (`targeted_verifier`), ánh xạ hậu quả bảo mật và kiểm toán bằng chứng kép. | `./documents/<repo_name>/basv/` & `./documents/_system/basv/` |
| **Phase 3** | `/phase-3-orchestrator` | **9 bước** (`3.1 -> 3.9`) | Xây dựng và xác minh chuỗi tấn công đa bước xuyên dịch vụ (ACA), truy vết từng hop thực thi (`code_trace_builder`), kiểm chứng mù từng mắt xích/cạnh nối (`chain_step_verifier`), thiết kế chuỗi request kiểm định, truy nguyên nhân gốc (`root_cause_mapper`) và săn tìm bằng chứng phản bác (`counterevidence_challenger`). | `./documents/_analysis/attack_chains/` & `./documents/_analysis/chains/<chain_id>/` |

### Tại sao chỉ cần gọi 1 Orchestrator mà không sợ AI bỏ sót bước hoặc suy luận vòng lặp? (Cơ chế Khóa Kép & 4 Cổng Nhận Thức Luận)
1. **Khóa 1 — Kịch bản Tuần tự Khép kín trong `SKILL.md`**: Mỗi file `.agents/skills/phase-{1,2,3}-orchestrator/SKILL.md` chứa đầy đủ danh sách các bước tuần tự bắt buộc, đường dẫn tới từng sub-skill tương ứng và cấu trúc JSON Schema của từng bước.
2. **Khóa 2 — Cổng Chặn Trạng thái Tất định trong CLI (`localsec/manual_session.py`)**:
   - Lệnh `phase_status` kiểm tra chính xác bước nào đã xong (`completed_steps`), bước nào còn thiếu (`remaining_steps`), bước bắt buộc tiếp theo (`next_required_step`) và chẩn đoán độ phủ ngữ nghĩa (`semantic_coverage_diagnostics`).
   - Lệnh `submit_skill` chặn cứng (`PREREQUISITE_ERROR`) nếu AI cố nộp bước tổng hợp (`business_aware_synthesizer` hoặc `chain_synthesizer`) khi chưa hoàn tất bước kiểm toán độc lập (`evidence_auditor` / `aca_evidence_auditor`).
   - Các lệnh đóng gói báo cáo (`finalize_repo`, `finalize_basv_repo`, `finalize_aca`) sẽ từ chối xuất báo cáo (`exit code 2`) nếu thiếu bất kỳ bước con nào trong Phase đó.
3. **Khóa 3 — 4 Cổng Chống Sai Lệch Nhận Thức Luận (Epistemic & Provenance Safeguards)**:
   - **Cổng Chống Nhiễm Bẩn Nguồn Gốc (`provenance_kind` Gate — Phase 2)**: Mỗi `ev_...` được đóng dấu tự động thành `intent_artifact` (`.md`/`.docx`/`.xlsx`/`.sql`/spec/test), `config_or_manifest` hoặc `implementation_code`. Chặn tự so sánh vòng lặp (`set(intent_evidence_ids) == set(implementation_evidence_ids)`) và chặn gán `authoritative_in_input` / `observed mismatch` khi chỉ trích dẫn file code.
   - **Cổng Bảo Toàn Giả Thuyết (`Hypothesis Preservation` — Phase 2)**: Các claim bị `evidence_auditor` đánh giá `inconclusive` hoặc `partially_supported` được hạ xuống `hypothesis` (`preserved_hypothesis_lead: true`) thay vì xóa thành `unknown`, giúp giữ lại manh mối cho `verification_planner` và Phase 3.
   - **Bộ Điều Tốc Chống Phình To Câu Hỏi (`Question-Space Runaway Governor` — Phase 3)**: Trong `check_aca_convergence()`, nếu số câu hỏi mới sinh ra lớn hơn số câu hỏi giải quyết được (`added_questions > resolved_questions`) trong khi `resolved_question_count == 0` và `verified_step_or_edge_delta == 0`, hệ thống bật cờ `question_runaway_detected: true` để dừng mở rộng nhánh vô tận.
   - **Chẩn Đoán Độ Phủ Ngữ Nghĩa (`semantic_coverage_diagnostics` — Phase 1 & 2)**: Phân biệt rõ độ phủ file/skill trên giấy tờ với độ phủ ngữ nghĩa thực tế.

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

## 4. Bảng Tra cứu Nhanh Các Lệnh CLI (`localsec.manual_session`)

Tất cả các thao tác đọc file, sinh mã bằng chứng `ev_...`, kiểm tra tiến độ và đóng gói báo cáo đều đi qua `python3 -m localsec.manual_session`:

```bash
# 1. Kiểm tra tiến độ hoàn thành các bước của một Phase (1, 2 hoặc 3)
python3 -m localsec.manual_session phase_status <repo_name> --phase 1
python3 -m localsec.manual_session phase_status <repo_name> --phase 2
python3 -m localsec.manual_session phase_status _analysis --phase 3

# 2. Duyệt thư mục và đọc file thủ công để sinh mã bằng chứng ev_...
python3 -m localsec.manual_session list_dir <repo_name> . --depth 2 --skill repo_profile
python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill <skill_name>

# 3. Đọc file liên repo (Federated Cross-Repo Read) cho Phase 2 & Phase 3
python3 -m localsec.manual_session read_file <repo_name> "<other_repo>:<rel_path>" <start_line> <end_line> --skill business_intent_modeler

# 4. Đọc file giới hạn phạm vi (Bounded Read) cho targeted_verifier
python3 -m localsec.manual_session read_file <repo_name> <rel_path> <start_line> <end_line> --skill targeted_verifier --allowed-paths <path1> <path2>

# 5. Liệt kê toàn bộ bằng chứng ev_... đã thu thập của một repo
python3 -m localsec.manual_session list_evidence <repo_name>

# 6. Tạo gói ngữ cảnh làm mù (Context-Blinding) cho Phase 2 & Phase 3
python3 -m localsec.manual_session prepare_blinded_challenger <repo_name>
python3 -m localsec.manual_session prepare_blinded_chain_verifier _analysis

# 7. Nộp và kiểm định JSON đầu ra của một skill (Schema + Evidence IDs + Epistemic Gates)
python3 -m localsec.manual_session submit_skill <repo_name> <skill_name> <json_path>

# 8. Trích xuất danh sách claims để kiểm toán độc lập (Evidence Auditor)
python3 -m localsec.manual_session extract_claims <repo_name>          # Phase 1
python3 -m localsec.manual_session extract_basv_claims <repo_name>     # Phase 2
python3 -m localsec.manual_session extract_aca_claims _analysis        # Phase 3

# 9. Đóng gói và xuất báo cáo cuối cùng cho từng Phase (chỉ chạy được khi phase_status báo FINALIZE_READY)
python3 -m localsec.manual_session finalize_repo <repo_name>           # Phase 1 (từng repo)
python3 -m localsec.manual_session finalize_system                     # Phase 1 (toàn hệ thống)
python3 -m localsec.manual_session finalize_basv_repo <repo_name>      # Phase 2 (từng repo)
python3 -m localsec.manual_session finalize_basv_system                # Phase 2 (toàn hệ thống)
python3 -m localsec.manual_session finalize_aca _analysis              # Phase 3 (toàn dự án)
```

---

## 5. Hướng dẫn Mang Bộ Skills Sang Dự Án Mới (Portability Checklist)

Khi bắt đầu kiểm toán bảo mật cho một dự án mới (`<new-project-root>`), thực hiện 3 bước sau:

1. **Sao chép các thư mục cốt lõi sang thư mục gốc của dự án mới**:
   ```bash
   cp -R .agents localsec skills schemas contracts tests localsec.toml <new-project-root>/
   ```
2. **Kiểm tra bộ cổng kiểm định (Unit Tests)**:
   ```bash
   python3 -m unittest discover -s tests
   ```
   Đảm bảo toàn bộ **27/27 tests** đều `OK`.
3. **Khởi chạy tuần tự**:
   Mở dự án mới trong IDE và gọi lần lượt `/phase-1-orchestrator` $\rightarrow$ `/phase-2-orchestrator` $\rightarrow$ `/phase-3-orchestrator` theo đúng các mẫu Prompt ở **Mục 2**.
