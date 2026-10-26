# Phase 4 — Báo cáo tổng hợp bảo mật

Tổng hợp kết quả **đã khoá sổ** của Phase 1 (Recon, architecture review, threat model), Phase 2 (BASV) và Phase 3 (Attack chain & root cause) thành một báo cáo Markdown tiếng Việt:

```
documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md
```

Báo cáo gồm: tóm tắt điều hành · **kiến trúc toàn hệ thống theo cụm nghiệp vụ** (sơ đồ, luồng nghiệp vụ xuyên service, mô hình tin cậy, thành phần dùng chung và ảnh hưởng dây chuyền, liên kết với project khác, bản đồ rủi ro theo cụm) · danh sách phát hiện cuối cùng `F-xx` đã hợp nhất, mỗi phát hiện có **tác động nghiệp vụ** · nguyên nhân gốc · lộ trình khắc phục · khoảng trống · phụ lục truy vết từng mục gốc.

## Vì sao có script riêng

Model (nhất là model chạy local) giỏi phán đoán nhưng dễ sót, dễ bịa và dễ tràn context khi phải đọc hàng trăm finding. Vì vậy phần **tất định** do `AI-skills/reporting/report.py` làm:

| Lệnh | Việc |
|---|---|
| `collect [--related ../project]` | Đọc `documents/` (và `reports/`, `reviews/`, `specs/`), chuẩn hoá mọi mục gốc thành SID, gán gợi ý xử lý từ trạng thái sau kiểm toán, đánh dấu mục bắt buộc gom (★), phát hiện artifact lệch nhau (ví dụ verdict chuỗi P3 trong `99_*` khác `chains/chain_*.json`), rút gọn thành các file nhỏ trong `documents/_report/inputs/` |
| `status` | Bước nào xong, bước nào tiếp theo (nguồn sự thật về tiến độ) |
| `catalog` | Danh mục `F-xx` hiện có, đề xuất `NEW:` chờ hợp nhất, tiến độ gom theo repo, lô tiếp theo |
| `promote NEW:<slug> F-xx` | Hợp nhất đề xuất F mới của các lô (chạy song song) vào một F trong mọi file map |
| `access --for F-xx` | (Phase Risk R.1, R.4) Phần chỉ mục truy cập liên quan tới một F: bí mật, client, scope, mạng, nguồn ID, chuỗi cung ứng của mọi repo — thay cho đọc nguyên `inputs/05_access_index.md` |
| `risk-digest` | (Phase Risk R.2) Bảng ghép chéo gọn: `yields` của mỗi F và mọi mắt xích chưa đạt |
| `check --stage risk-paths` / `--only F-xx` | Cổng R.1 (chưa đòi phần kết luận); chỉ in lỗi của một F |
| `render-risk [--draft]` | Dựng `documents/_report/DANH_GIA_RUI_RO.md` của Phase Risk: từng F với đường khai thác, kết luận từng mắt xích có/không/chưa rõ và vì sao, tổ hợp, câu hỏi chờ xác nhận theo người cần hỏi |
| `check --stage …` | Cổng fail-closed: mọi repo thuộc một cụm; mọi mục ★ (kể cả SAST/secret/SCA đã đăng ký) được gom hoặc loại trừ có lý do; SID không bịa; `confirmed` cần nguồn đã qua kiểm toán **và** không thuộc chuỗi P3 chưa xác nhận; mục đã bác bỏ không được dùng lại nếu không có lý do; loại trừ kết quả công cụ phải dẫn báo cáo xác minh; tác động nghiệp vụ không chung chung, không trùng, có cơ sở; roadmap phủ P0/P1 |
| `render [--draft]` | Dựng báo cáo (bản nháp cho bước 4.6, hoặc bản cuối sau khi có `review.json`) từ `work/` + `inputs/`: bảng tổng hợp, bản đồ rủi ro theo cụm, thẻ phát hiện, phụ lục truy vết/bác bỏ/chưa gom |

Phần **phán đoán** (chia cụm nghiệp vụ, gom nhóm, tác động nghiệp vụ, văn bản) do model ghi vào `documents/_report/work/`:

```
work/architecture.json   — cụm nghiệp vụ, thành phần dùng chung, project liên quan
work/architecture.md     — mục 2.1–2.6 của báo cáo
work/consolidation.json  — F-xx, loại trừ, tóm tắt, lộ trình, khoảng trống
work/map/<repo>.json     — gán từng SID của repo vào F-xx hoặc loại trừ hoặc đề xuất NEW:<slug> (mỗi lô một file)
work/review.json         — kết quả rà soát độc lập (4.6) + cách tác giả xử lý từng vấn đề (4.7)
work/risk/F-xx.json      — Phase Risk: đường khai thác, mắt xích, kết luận rủi ro của từng F
work/risk/_combinations.json — Phase Risk: tổ hợp phát hiện
work/risk_review.json    — Phase Risk R.4: thách thức độc lập hai chiều
runtime_facts.json       — (documents/_report/) sự thật runtime do người vận hành xác nhận, trích bằng fact:<id>
```

## Skills

| Skill | Bước |
|---|---|
| `/phase-4-consolidated-report` | Điểm vào, điều phối 4.1 → 4.7 (bảng "Ai làm / Cách gọi" cho công cụ có và không có subagent) |
| `/phase-4-architecture-synthesis` | 4.2 Kiến trúc theo cụm nghiệp vụ |
| `/phase-4-finding-consolidation` | 4.3 Hợp nhất phát hiện, theo lô từng repo |
| `/phase-4-business-impact` | 4.4 Tác động nghiệp vụ (rủi ro/ưu tiên tạm) |
| `/phase-risk-assessment` | **Phase Risk** (giữa 4.4 và 4.5): điểm vào R.1–R.5 |
| `/phase-risk-exploit-path` | R.1 Đường khai thác, kết luận từng mắt xích có/không/chưa rõ kèm lý do và bằng chứng |
| `/phase-risk-cross-link` | R.2 Ghép chéo: phát hiện này làm mắt xích của phát hiện kia đạt được |
| `/phase-risk-verdict` | R.3 Lập luận kết luận (mắt xích khó nhất, vì sao, điều gì làm rủi ro đổi) — rủi ro/ưu tiên do script suy ra; R.5 xử lý thách thức |
| `/phase-risk-challenge` | R.4 Thách thức độc lập hai chiều (context mới), ghi `work/risk_review.json` |
| `/phase-4-report-writer` | 4.5 Tóm tắt, lộ trình, khoảng trống, bản nháp; 4.7 xử lý rà soát, render cuối |
| `/phase-4-independent-review` | 4.6 Rà soát độc lập trong context mới (subagent hoặc cuộc hội thoại mới), ghi `work/review.json` |

Hướng dẫn chi tiết: `AI-skills/reporting/guides/01_nguon_du_lieu.md` … `AI-skills/reporting/guides/05_viet_bao_cao.md`; Phase Risk: `AI-skills/reporting/guides/06_rui_ro_thuc_te.md`. Mẫu: `templates/`.

Phase 4 không đi qua engine `lsec.py` (không `submit_skill`, không `ev_...` mới) vì nó không đọc mã nguồn; cổng kiểm của nó là `python3 AI-skills/reporting/report.py check`. Test: `tests/test_reporting.py`.

## Chạy nhanh

```bash
python3 AI-skills/reporting/report.py collect
python3 AI-skills/reporting/report.py status
# … model làm 4.2 → 4.4 theo /phase-4-consolidated-report, rồi Phase Risk theo /phase-risk-assessment, rồi 4.5 → 4.7 …
python3 AI-skills/reporting/report.py check --stage final
python3 AI-skills/reporting/report.py render
```
