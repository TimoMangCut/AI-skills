# AGENTS.md — Phương pháp làm việc (tool-agnostic)

> Lớp "cách nghĩ". CLAUDE.md import file này. Bất kỳ AI tool nào cũng dùng chung được.

## Refute-first (bác bỏ trước, khẳng định sau)
Với MỌI tuyên bố — của người học, của vendor, của tài liệu, của chính AI ở bước trước — câu hỏi mặc định: **"làm sao biết điều này đúng?"**. Cố bác bỏ trước khi chấp nhận. Chỉ nâng một khẳng định lên "đúng" khi đã qua được nỗ lực bác bỏ.

## Phân tầng độ tin cậy (luôn dán nhãn)
- **[NỀN TẢNG]** — chuẩn ổn định (OWASP ASVS/MASVS/API Top10, ISO/SAE 21434, UNECE R155/R156, IEC 62443, NIST SSDF/AI RMF, SLSA). Tin cao.
- **[XU HƯỚNG]** — đang phát triển (ASPM, AI-in-AppSec, AI-in-OT-Control-Loop). Dùng được nhưng thận trọng, nêu rõ chưa chốt.
- **[MARKETING]** — số liệu do nhà cung cấp công bố ("97% accuracy"…). Coi là tuyên bố cần kiểm chứng độc lập, KHÔNG coi là sự thật.

## Confirmed vs Hypothesis & Chống "Giả vờ đủ Coverage"
Khi phân tích hệ thống, tách rõ:
- **Confirmed** — có bằng chứng trực tiếp (`ev_...` từ code, config, doc, log).
- **Hypothesis** — mới là suy đoán, cần verify. Ghi rõ "cần kiểm: …".
Không dùng "chắc là framework/WAF tự lo". Không kiểm được → nói không kiểm được.
Tuyệt đối không tự thu nhỏ mẫu số để báo cáo "100% coverage" giả tạo; mọi module/file trong `Target Modules Map` chưa được mở đọc phải hiển thị rõ là `UNVISITED` trong `Visibility Tracker`.

## Docs là ground truth
Tài liệu ứng dụng/kiến trúc cung cấp override kiến thức chung. Mâu thuẫn giữa doc và code/hành vi CHÍNH LÀ một finding. Doc thiếu → nêu giả định đang dùng + điều cần verify.

## Severity & Risk Thực tế theo Ngữ cảnh (5 Trục S-F-O-P-C)
Không gán severity từ CVSS suông và không đánh đồng "Reachable trong code" với "Exploitable ngoài thực tế".
- Đánh giá hậu quả trên 5 trục **S-F-O-P-C**: **Safety** (An toàn vật lý: xe điện, trạm sạc/pin, robot, y tế, lưới điện BESS, nhà máy thép/đường sắt) · **Financial** (Thanh toán, cước sạc/đổi pin, đối soát B2B, thuê bao OTA) · **Operational** (Đội xe, nhà máy, cổng bán hàng/đại lý, Identity/CI-CD/ERP/Data Lake) · **Privacy/Data** (PII, tọa độ GPS, camera, giọng nói, dataset huấn luyện) · **Compliance** (Luật BVDLCN 91/2025, Luật ANM 116/2025 (cần Pháp chế/Compliance xác nhận số hiệu và hiệu lực hiện hành), R155/R156, GDPR, TT 05/2025/TT-BCT (cần Pháp chế/Compliance xác nhận số hiệu và hiệu lực hiện hành)).
- Luôn áp trần cứng: **`overall_risk <= max_impact`**.
- Chứng minh rõ **Actor/Role nào** chạm được code path, **khả năng xảy ra (Attack Feasibility)**, và **kiểm soát ngoài code** (Cloudflare WAF vs Bare ALB, VPC nội bộ `10.x`, AWS IoT Policy, mTLS, OT Interlock).

## Kỷ luật khi dùng LLM/AI & Công cụ Python
LLM tối ưu **độ hợp lý bề ngoài**, không phải **độ đúng**; còn Python tĩnh dễ bị sai/thiếu khi gặp cách code riêng của từng team. Khi phối hợp AI và Python, luôn tuân thủ:
1. **AI đi trinh sát trước (`codebase_scout`), Python theo sau (`extractor_tailor`):** AI đọc cấu trúc thư mục và mẫu code để hiểu quy ước của team trước khi quyết định dùng, sửa hay bỏ qua script Python (tránh bị Bias vào kết quả SAST tĩnh sai).
2. **Gom cụm bằng Ngữ nghĩa (`AI Semantic Clustering`):** Do AI quyết định dựa trên hiểu biết về Middleware/Guard và nghiệp vụ; không dùng Python tự đoán lỗi.
3. **Đo độ phủ bằng Sự thật Vật lý (`Visibility Tracker`):** Python ghi nhận khách quan những thư mục/file nào trong `Target Modules Map` đã được mở đọc (`visited` vs `unvisited`) và chặn hành vi đọc lướt vài dòng đầu (`Anti-Grazing`).

## Quy trình 4 Phase Chuẩn hóa
1. **Phase 1 — Unified Reconnaissance:** Trinh sát cấu trúc & cách code (`1.1`) → Mô hình hóa Ý định & Bất biến S-F-O-P-C trước khi đọc code (`1.3`) → Tùy chỉnh/chạy Extractor (`1.2`) → Đọc code 1 lần gom cụm ngữ nghĩa & tìm điểm dị biệt (`1.4`) → Đánh giá Ranh giới Xuyên Repo (`1.5`) → Kiểm toán Độ phủ Thực đọc & Bằng chứng (`1.6`).
2. **Phase 2 — Deep Analysis & Falsification:** Lọc trùng & chia Batch Candidate (`2.1`) → Truy vết sâu Hops, Ghép chuỗi, Root Cause & Repro (`2.2`) → Phản biện đối kháng mù ngữ cảnh (`2.3`) → Cổng Kiểm toán Bằng chứng & Sổ cái Bác bỏ (`2.4`).
3. **Phase 3 — Contextual Risk & Exploitability Assessment:** Chứng minh Actor/Role & Độ khả thi khai thác (`3.1`) → Đối chiếu Kiểm soát Ngoài Code & Hạ tầng (`3.2`) → Hiệu chỉnh Risk Thực tế S-F-O-P-C, gán `Risk Owner` / `Safety Owner` & Phanh An toàn `Gate 0 / Emergency Brake` (`3.3`).
4. **Phase 4 — Final Synthesis & Canonical Report Generation (`/phase-4-orchestrator`):** Xuất kết quả đã khóa sổ của Phase 1–3 sang `documents/<repo>/`, `documents/_analysis/`, `documents/_system/`, `documents/_v3/` (`finalize_v3_phase4`), sau đó chạy luồng `/phase-4-consolidated-report` và `/phase-risk-assessment` với `python AI-skills/reporting/report.py` (`collect` → `4.2` kiến trúc → `4.3` hợp nhất F-xx → `4.4` tác động nghiệp vụ → `Phase Risk R.1–R.5` → `4.5` bản nháp → `4.6` rà soát độc lập → `4.7` chốt & `check --stage final` → `render`) để xuất `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md` và `documents/_report/DANH_GIA_RUI_RO.md`.

## Kỷ luật đầu ra
Deliverable-driven: mỗi phiên đẻ ra artifact. Không nịnh. Nêu trade-off. Gắn metric/impact khi có thể. Kết bằng self-check 3 điểm.

## Luật CLI cần biết (Đợt 7 — ghi lại từ thử nghiệm `vinfast-mcp`)

- **Bước cần ngữ cảnh sạch dùng subagent trên cả hai công cụ** (2.3, R.4, 4.6): Claude Code qua skill `context: fork` / Agent tool; Antigravity qua `invoke_subagent` (2.3: `TypeName: "localsec-blinded-challenger"`, Prompt mở đầu đúng bằng `/phase-2-blinded-counterevidence-challenger <repo>`; R.4/4.6: `TypeName: "self"`). Bước 2.3 bị chặn bằng cùng guard `localsec/claude_subagent_guard.py`: Claude qua hook trong `.claude/agents/localsec-blinded-challenger.md`, Antigravity qua `.agents/hooks.json` (`--platform antigravity`). Không có subagent thì mở hội thoại mới với đúng lời mở đầu đó. **Nếu hook báo lỗi hoặc bước 2.3 tự kiểm thấy đọc được file cấm (`guard_self_test: "not_blocked"`), dừng lại và báo người dùng chạy lại `setup` — tuyệt đối không tự sửa môi trường Python của máy (như ghi file `.pth` vào Python hệ thống).**
- **`read_file` trả tối đa 180 dòng mỗi lần** (`max_lines_per_read`). File dài phải đọc nhiều lần liên tiếp (`--start-line`/`--end-line`). Cổng Phase 1 tính độ phủ theo **dòng**: file bắt buộc (entrypoint + security) phải được đọc ≥ 90% số dòng (`mandatory_min_line_coverage`), không chỉ "đã mở".
- **`coverage_id`** có dạng `surface::boundary::subsystem::attack_class[::lifecycle]`, mỗi đoạn **mã hoá phần trăm theo RFC 3986**: `/` phải viết thành `%2F` (ví dụ `http_api::mcp_edge::apps%2Fmcp%2Fserver::BOLA_IDOR`). Hàm `localsec.orchestrator.build_coverage_id(...)` dựng đúng dạng này.
- **`run_tailored_extractor --patterns-file <file.json>`** nhận một danh sách `[{"name": "...", "regex": "..."}]`, hoặc object `{"patterns": [...]}`. Mỗi mẫu cần khoá `regex`.
- **Bước 2.4 (`analysis_evidence_gate`) là tuỳ chọn.** `finalize_v3_phase2` tự ghi file này, và `phase_status --phase 2` không còn đòi nó.
- **Cổng độ phủ theo module (Đợt 10 — V20):** ngoài file bắt buộc (≥ 90% số dòng), mỗi module trong `target_modules` phải được đọc ≥ `target_module_min_line_coverage` (mặc định **50%**) số dòng nguồn không tính test; module khai báo trong `ignored_modules` được miễn. Hai lệnh hỗ trợ:
  - `python -m localsec.manual_session coverage_status <repo>`: liệt kê file bắt buộc chưa đủ 90% và module chưa đủ ngưỡng.
  - `python -m localsec.manual_session read_files <repo> --module <đường dẫn module> --until-pct 50 --skill <skill>`: đọc theo lô, ưu tiên file bắt buộc chưa đọc, rồi tới file có tín hiệu rủi ro cao (đường dẫn auth/token/consent/state…, nội dung đọc header/gọi HTTP/ký token); file UI/catalog xếp sau; bỏ qua đoạn đã đọc; mỗi lượt trả khoảng 60 nghìn ký tự (`--max-chars`), mỗi đoạn có `ev_` như `read_file`. Gọi lại cùng lệnh tới khi `target_reached: true`. **Phải phân tích nội dung trả về**: cổng chỉ đếm dòng đã đọc, không đếm dòng đã hiểu.
- **Ghi nháp JSON bằng công cụ Write của agent,** không dùng heredoc của Git Bash: heredoc làm hỏng dấu `\` và chữ tiếng Việt trên Windows.

