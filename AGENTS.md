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
4. **Phase 4 — Final Synthesis & Canonical Report Generation (`/phase-4-orchestrator`):** Kết xuất cấu trúc chuẩn `documents/<repo>/`, `documents/_analysis/`, `documents/_system/`, `documents/_v3/<repo>/`, `documents/_report/work/risk/F-xx.json` + `_combinations.json` (đối soát parity với `derived_risk_rating` của Phase 3), và tổng hợp bộ báo cáo `documents/_report/00_manifest.md`, `BAO_CAO_TONG_HOP_BAO_MAT.md`, `DANH_GIA_RUI_RO.md` (`finalize_v3_phase4`).

## Kỷ luật đầu ra
Deliverable-driven: mỗi phiên đẻ ra artifact. Không nịnh. Nêu trade-off. Gắn metric/impact khi có thể. Kết bằng self-check 3 điểm.
