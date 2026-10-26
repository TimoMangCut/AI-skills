---
name: phase-4-finding-consolidation
description: >-
  Phase 4.3 — Hợp nhất mọi finding đã qua kiểm toán/bác bỏ của Phase 1–3 (threat, quan sát kiến trúc, mismatch BASV, chuỗi tấn công, SAST/SCA/secret ngoài pipeline) thành danh sách phát hiện cuối F-xx — gom theo nguyên nhân gốc, khử trùng xuyên repo, loại trừ có lý do, truy vết từng SID; có chế độ lô cho subagent/phiên mới.
---

# `phase-4-finding-consolidation` (Phase 4.3)

Biến hàng trăm mục gốc thành danh sách phát hiện cuối `F-xx`, gọn, không trùng. Mỗi mục bắt buộc (★) phải đi vào đúng một F hoặc vào danh sách loại trừ có lý do.

**Quyền truy cập:** theo mục "Quyền truy cập của Phase 4" trong `.agents/skills/phase-4-consolidated-report/SKILL.md`. Tóm tắt: đọc `documents/`, `reports/`, `AI-skills/reporting/`; chỉ ghi `documents/_report/work/`; không đọc mã nguồn.

## Prompt kích hoạt
```text
/phase-4-finding-consolidation Hợp nhất phát hiện theo lô từng repo: gom cùng nguyên nhân gốc + cùng cách sửa, tách khác cách khai thác/khác cách sửa; giữ trạng thái sau kiểm toán, không nâng giả thuyết; ghi work/map/<repo>.json sau mỗi lô.
```

## Điều kiện
`report.py check --stage architecture` đạt (cần `domains`).

Đọc trước: `AI-skills/reporting/guides/03_hop_nhat_phat_hien.md` (bắt buộc) và phần disposition/SID/chuỗi của `guides/01_nguon_du_lieu.md`.

## 4.3a — Khung F (phiên chính)
Đọc `documents/_report/inputs/03_findings_index.md`, `inputs/findings/_analysis.md`, `inputs/findings/_system.md`. Tạo `documents/_report/work/consolidation.json` (mẫu `templates/consolidation.example.json`; chưa cần `business_impact`, `executive_summary`, `roadmap`, `gaps`) với F cho mỗi chuỗi P3, mỗi khuôn mẫu lặp/nguyên nhân gốc, mỗi mismatch hệ thống. Ghi `work/map/_analysis.json`, `work/map/_system.json`.

## 4.3b — Chế độ lô (một repo, hoặc `_ext`)
Chạy được trong subagent, phiên mới, hoặc ngay trong phiên chính. Đầu vào duy nhất là **tên lô**.
1. `python3 AI-skills/reporting/report.py catalog`: danh mục F hiện có và các đề xuất `NEW:` đã có.
2. Đọc `documents/_report/inputs/findings/<lô>.md`. Xử lý mọi dòng ★; dòng không ★ mức high thì nên xử lý. Cột *Chuỗi P3* cho biết mục thuộc chuỗi nào: gom cùng F với chuỗi đó.
3. Với mỗi dòng:
   - cùng gốc và cùng cách sửa với một F có sẵn → `"to": "F-xx"`;
   - vấn đề mới → `"to": "NEW:<slug>"` kèm `"proposal": {"title", "core_issue", "root_causes", "services"}`; nhiều mục cùng vấn đề mới thì dùng cùng một slug;
   - loại trừ → `"to": "excluded"` với `reason` + `note` cụ thể (luật ở guide 03).
4. Cần chi tiết thì mở file ở cột *Nguồn*, **đọc theo đoạn** quanh ID đó.
5. Ghi `documents/_report/work/map/<lô>.json` (mẫu `templates/map.example.json`). **Không** sửa `consolidation.json` và không đụng file map của lô khác: nhờ vậy nhiều lô chạy song song được.
6. Trả về tối đa 8 dòng: số mục đã gán, số đề xuất `NEW:`, số loại trừ theo lý do, các mục còn phân vân.

## 4.3c — Hợp nhất (phiên chính)
1. `report.py catalog`: xem đề xuất `NEW:` từ mọi lô. Gộp các đề xuất trùng ý, hoặc gán chúng vào F đã có.
2. Tạo F mới trong `consolidation.json` cho đề xuất đứng được, rồi chạy `python3 AI-skills/reporting/report.py promote NEW:<slug> F-xx` (lệnh tự sửa mọi file map).
3. Rà danh mục: gộp F trùng, tách F trộn nhiều vấn đề (`check` báo khi F có >25 nguồn hoặc >2 nguyên nhân gốc), đặt tiêu đề theo dạng *điểm yếu + hậu quả*.
4. `python3 AI-skills/reporting/report.py check --stage findings` tới khi `ĐẠT`.

## Kết quả công cụ và nguồn ngoài pipeline
`collect` đã đăng ký SAST (SARIF), secret và SCA/misconfig (trivy) thành lô `_ext`; xử lý lô này như một repo. Loại trừ dương tính giả phải dẫn báo cáo xác minh trong `reports/`. Báo cáo/review thủ công (`reports/*.md`, `reviews/`, `independent-review/`): finding còn đứng được thì gắn vào F bằng SID `ext:<đường dẫn>#<ID>`.

## Không được
- Tự đặt SID, hoặc đếm một SID hai lần.
- Gắn `confirmed` khi nguồn chưa qua kiểm toán hoặc thuộc chuỗi P3 chưa xác nhận.
- Loại trừ để cho qua cổng: `muc_thap` không dùng được cho mục critical; mọi loại trừ mục bắt buộc đều hiện ở Phụ lục B và được đếm ở tóm tắt.
- Gộp hai lỗ hổng khác nhau chỉ vì cùng repo/CWE; hoặc tách một vấn đề theo từng repo khi chúng cùng gốc và cùng cách sửa.
- Đọc mã nguồn để "kiểm lại". Nghi ngờ thì ghi `validation`, và ghi `gaps` ở bước 4.5.
