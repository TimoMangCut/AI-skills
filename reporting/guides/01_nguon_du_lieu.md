# 01 — Nguồn dữ liệu của Phase 4 và cách đọc

Phase 4 **không phân tích lại** và **không đọc mã nguồn**. Nó chỉ tổng hợp những gì Phase 1–3 đã khoá sổ (đã qua kiểm toán bằng chứng và bác bỏ). Cần bằng chứng mới thì ghi vào `gaps`, không tự đi kiểm.

## Bốn giai đoạn review ↔ artifact LocalSec

| Giai đoạn review | Artifact | Ghi chú |
|---|---|---|
| Recon | `documents/<repo>/01_repo_profile.md`, `02_techstack.json`, `03_api_inventory.*`, `04_auth_matrix.json`, `05_inbound_outbound.json`, `06_dataflow.md` | Mục đích, độ trọng yếu, năng lực nghiệp vụ, dữ liệu nhạy cảm, entrypoint, luồng vào/ra |
| Architecture review | `documents/<repo>/08_architecture_review.md`; cấp hệ thống: `documents/_system/02_cross_repo_review.json`, `03_cross_repo_review.md`, `_system/basv/01_service_interconnection_matrix.*`, `_system/diagrams/*.mmd` | Repo-level → cần tổng hợp lại thành kiến trúc toàn hệ thống |
| Threat modeling | `documents/<repo>/07_threat_model.md`; các threat nằm trong `09_findings.json` (`source: threat_model`) | Threat là giả thuyết cho tới khi có bằng chứng |
| Phân tích mã / static analysis | Phase 2 BASV: `documents/<repo>/basv/18_business_aware_synthesis.*`, `_system/basv/03_*`; Phase 3: `documents/_analysis/` (chuỗi, nguyên nhân gốc, phản chứng); SAST/SCA/DAST ngoài pipeline: `reports/`, review thủ công: `reviews/`, `independent-review/` | Phase 3 là bước bác bỏ cuối cùng |
| Kiểm toán bằng chứng (bác bỏ) | `13_evidence_audit.*`, `basv/17_*`, `_analysis/08_*`, `98_*` | Engine đã áp kết quả vào trạng thái: `unsupported` → `unknown` |

## Trạng thái nào là cuối cùng

1. **Chuỗi tấn công:** lấy `chain_verdict` trong `documents/_analysis/chains/chain_<ID>.json`, **không** lấy từ `99_project_chain_report.json` nếu hai file lệch nhau. File chuỗi được ghi sau cổng fail-closed `finalize_aca`. `python AI-skills/reporting/report.py collect` tự phát hiện chỗ lệch và liệt kê ở `inputs/00_manifest.md`; báo cáo phải nêu chỗ lệch này ở mục 7.
2. **Finding Phase 1:** trạng thái trong `09_findings.json` đã là trạng thái sau kiểm toán (`observed`/`derived` = có bằng chứng, `hypothesis` = giả thuyết, `unknown` = bị hạ cấp vì kiểm toán không ủng hộ).
3. **Mismatch Phase 2:** `confirmed_mismatches` có `outcome: confirmed` khi đã qua 6 cổng BASV. Nhưng chỉ được coi là **Đã xác nhận** khi `status` sau kiểm toán là `observed`/`derived`. Nếu `status` vẫn là `hypothesis` (thường kèm ghi chú "Evidence audit: no verdict returned by auditor") thì mục đó **chưa qua kiểm toán độc lập**: script gắn `chua_kiem_toan`, và F chứa nó không được `confirmed`. `potential_or_unverified_mismatches` là giả thuyết. Cờ `demoted_from_confirmed: true` nghĩa là đã bị hạ.
4. **Khi các phase mâu thuẫn:** phase sau và chặt hơn thắng cho *đúng phần nó kiểm*. Ví dụ: Phase 2 xác nhận "callback không kiểm chữ ký" (lỗi trong mã có thật), Phase 3 chỉ `hypothesized` vì chưa chứng minh được kẻ tấn công tới được route. Kết luận đúng là: lỗi trong mã **có thật**, khả năng khai thác **còn điều kiện chưa kiểm**, nên `confidence: evidence_backed`, không phải `confirmed`.

## Gợi ý xử lý (disposition) do script gán

| Mã | Ý nghĩa | Từ đâu |
|---|---|---|
| `xac_nhan` | Đã xác nhận | P2 confirmed có `status` observed/derived, P3 `confirmed`/`code_supported`/`demonstrated` |
| `xac_nhan_mot_phan` | Xác nhận một phần | P3 `partially_confirmed` |
| `chua_kiem_toan` | P2 xác nhận – chưa qua kiểm toán | P2 `outcome: confirmed` nhưng `status: hypothesis` |
| `co_bang_chung` | Có bằng chứng mã nguồn | P1 `observed`/`derived` |
| `can_xac_minh` | Giả thuyết | P1 `hypothesis`, P2 potential, P3 `hypothesized`, mọi kết quả công cụ (SAST/SCA/secret) chưa xác minh |
| `bac_bo` | Đã bác bỏ / hạ cấp | P1 `unknown`, P2 `unknown`, P3 `refuted` |

## Chuỗi Phase 3 ↔ mục gốc

`collect` đọc `originating_finding_ids` của từng chuỗi và đối chiếu sang SID (cột *Dựng từ* trong `inputs/03_findings_index.md`, cột *Chuỗi P3* trong `inputs/findings/<repo>.md`). Hệ quả:
- Mục gốc của một chuỗi nên được gom **cùng F** với chuỗi đó. `check` cảnh báo nếu chúng nằm ở hai F khác nhau.
- F gắn `confirmed` mà có nguồn thuộc một chuỗi `hypothesized`/`refuted` thì `check` báo lỗi. Lý do: lỗi trong mã có thể có thật, nhưng khả năng khai thác chưa được chứng minh. Chỉ bỏ qua được bằng `override_note` dẫn bằng chứng khai thác độc lập.
- ID nào trỏ tới artifact trung gian (`SC-*`, `CAND-*`, `SCN-*`…) mà không đối chiếu được thì được liệt kê, không đoán.

Gợi ý này là **tất định**. Muốn đi ngược (ví dụ đưa mục `bac_bo` vào một F, hoặc bác bỏ thêm một mục chưa bị bác bỏ) thì phải nêu lý do cụ thể. `check` sẽ chặn nếu thiếu lý do.

## SID — mã truy vết

Mọi mục gốc có một `sid` dạng `<phạm vi>:<ID gốc>`:
- `vfip-payment:TM-PAY-01` (threat), `vfip-payment:AR-03` (quan sát kiến trúc, đánh số theo thứ tự trong `09_findings.json`), `vfip-payment:CM-1` / `PM-3` (mismatch Phase 2)
- `_system:SR-04` (rủi ro hệ thống P1), `_system:SYS-CM-02` (mismatch hệ thống P2)
- `_analysis:C2` (chuỗi Phase 3)
- Kết quả công cụ do `collect` tự đăng ký từ `reports/` (repo `_ext`, file `inputs/findings/_ext.md`): SAST trong SARIF `ext:<file>#<số thứ tự>`; secret (gitleaks/trivy) `ext:<file>#<rule>@<file>:<dòng>`; SCA trivy gom theo thư viện `ext:<file>#pkg:<tên>@<phiên bản>`; misconfig `ext:<file>#misconfig:<ID>`. Mức lấy từ điểm CVSS trong thông điệp nếu có, không có thì lấy theo level của công cụ.
- Báo cáo thủ công ngoài pipeline (không phải đầu ra công cụ): `ext:<đường dẫn file>#<ID trong file>`, ví dụ `ext:reports/x/VERIFY-VINSOC-SAST.md#F-07`

Không được tự đặt SID. SID nào không có trong `inputs/findings/*.md` thì `check` báo lỗi "bịa".

## Ngữ cảnh nghiệp vụ — thứ tự tin cậy

1. Tài liệu nghiệp vụ do dự án cung cấp: `specs/`, thư mục tài liệu trong `documents/` không phải repo (ví dụ `documents/thu-tuc-phap-ly/`), BRD/BRS.
2. `documents/<repo>/basv/10_business_intent_model.md`, chỉ những mục `documented` / `authoritative_in_input`.
3. Trường `business_impact` của Phase 2 và `business_consequence` của chuỗi Phase 3.
4. Recon: `01_repo_profile.md` (Purpose, Criticality), `02_techstack.json` (`business_capabilities`, `sensitive_data`).
5. Suy luận của chính bạn. Bắt buộc ghi `basis: "Suy luận từ recon: …"`.

Project chưa có BRD (`inputs/00_manifest.md` ghi "Không có", hoặc ý định toàn `inferred`) vẫn làm được tác động nghiệp vụ, nhưng cơ sở phải là mức 3–5 và ghi rõ như vậy.

## Báo cáo tổng hợp cũ

`collect` liệt kê các báo cáo tổng hợp trước đây (ví dụ `BAO_CAO_TONG_HOP_*.md`). Chỉ đọc để tham khảo cách diễn đạt hoặc ý bị sót. **Không** coi đó là nguồn sự thật: nó có thể được viết trước khi khoá sổ. Mọi kết luận phải truy về SID.
