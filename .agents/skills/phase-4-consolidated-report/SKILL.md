---
name: phase-4-consolidated-report
description: >-
  Phase 4 — Lập Báo cáo tổng hợp bảo mật (tiếng Việt, Markdown) từ kết quả Phase 1–3 đã khoá sổ — kiến trúc toàn hệ thống theo cụm nghiệp vụ, danh sách phát hiện cuối cùng đã hợp nhất/bác bỏ, tác động nghiệp vụ từng phát hiện, lộ trình khắc phục, rà soát độc lập. Không phân tích lại, không đọc mã nguồn.
---

# `phase-4-consolidated-report` — Báo cáo tổng hợp (điểm vào duy nhất của Phase 4)

Gom kết quả Recon → Architecture review → Threat model → Phân tích mã (Phase 1 + 2 + 3, sau kiểm toán và bác bỏ) thành **một** báo cáo cuối: `documents/_report/BAO_CAO_TONG_HOP_BAO_MAT.md`.

## Prompt kích hoạt
```text
/phase-4-consolidated-report Lập báo cáo tổng hợp cho toàn bộ project từ kết quả Phase 1–3 đã khoá sổ.
Không phân tích lại, không đọc mã nguồn; mọi kết luận truy về SID; tác động nghiệp vụ cho từng phát hiện; kiến trúc tổng hợp theo cụm nghiệp vụ; rà soát độc lập trước khi chốt.
[Tuỳ chọn] Project liên quan: ../<project-khác>
```

## Quyền truy cập của Phase 4 (ngoại lệ có chủ đích so với Phase 1–3)
Áp dụng cho mọi skill `phase-4-*`. Rule "chỉ đọc qua `lsec.py read_file`" và "không sửa tay `documents/`" của Phase 1–3 **không** áp dụng cho Phase 4, vì Phase 4 không đọc mã nguồn mà chỉ đọc kết quả đã khoá sổ.
- **Đọc** bằng công cụ đọc file thường: `documents/` (đầu ra Phase 1–3), `reports/`, `reviews/`, `independent-review/`, `specs/`, thư mục tài liệu nghiệp vụ, `AI-skills/reporting/`. Không dùng `lsec.py read_file`/`list_dir` (CLI từ chối `documents/` và sẽ ghi sai độ phủ).
- **Ghi** chỉ trong `documents/_report/` (qua `AI-skills/reporting/report.py` hoặc ghi file trong `work/`). Không sửa bất kỳ file nào khác của `documents/`; không đụng `.localsec/`.
- **Không đọc mã nguồn** của các repo đang review (không Read/Grep/Glob/list_dir vào thư mục repo). Thiếu bằng chứng thì ghi vào `gaps`, không tự đi kiểm.

## Nguyên tắc
1. **Chỉ tổng hợp**, không phân tích lại. Trạng thái sau khoá sổ là chuẩn: chuỗi P3 lấy từ `chains/chain_<ID>.json`; P2 chỉ "đã xác nhận" khi đã qua kiểm toán.
2. **Fail-closed.** `python3 AI-skills/reporting/report.py check` chặn: nâng giả thuyết thành xác nhận, mã nguồn bịa, sót mục bắt buộc, loại trừ không có lý do, F quá lớn, tác động chung chung.
3. **Tác giả không tự kiểm.** Bước 4.6 chạy trong context mới (subagent hoặc phiên mới), không phải phiên đã viết báo cáo.
4. **Tiến độ nằm ở file.** Sau mỗi bước, mỗi lô, hoặc khi context bị nén / mở phiên mới: chạy `python3 AI-skills/reporting/report.py status`.
5. **Context nhỏ.** Không mở `inputs/inputs.json`; không đọc nguyên file >60 KB, chỉ đọc theo đoạn. Phiên chính chỉ điều phối và hợp nhất; việc đọc nhiều (lô theo repo, rà soát) giao cho subagent nếu công cụ có.

## Điều phối

| Bước | Việc | Ai làm | Cách gọi — công cụ có subagent (Claude Code, Antigravity) | Cách gọi — công cụ không có subagent (model local) | Cổng |
|---|---|---|---|---|---|
| 4.1 | Gom & rút gọn | script | `python3 AI-skills/reporting/report.py collect [--related ../<project>]` | như bên trái | `status` |
| 4.2 | Kiến trúc theo cụm nghiệp vụ | phiên chính | tự làm theo `.agents/skills/phase-4-architecture-synthesis/SKILL.md` | như bên trái | `check --stage architecture` |
| 4.3a | Khung F từ mức hệ thống | phiên chính | tự làm theo `.agents/skills/phase-4-finding-consolidation/SKILL.md` mục 4.3a | như bên trái | — |
| 4.3b | Gom theo lô (mỗi repo, cả `_ext`) | subagent mỗi lô | Agent tool, `general-purpose`, `model: sonnet`; prompt chỉ gồm: "Chế độ lô của `.agents/skills/phase-4-finding-consolidation/SKILL.md`, lô `<repo>`". Chạy nhiều lô song song được vì mỗi lô chỉ ghi `work/map/<repo>.json` | làm tuần tự trong phiên, mỗi lượt một lô; khi context gần đầy thì mở phiên mới và chạy `python3 AI-skills/reporting/report.py catalog` | `catalog` |
| 4.3c | Hợp nhất đề xuất F mới, rà danh mục | phiên chính | `python3 AI-skills/reporting/report.py catalog` → tạo F trong `consolidation.json` → `python3 AI-skills/reporting/report.py promote NEW:<slug> F-xx` | như bên trái | `check --stage findings` |
| 4.4 | Tác động nghiệp vụ (rủi ro/ưu tiên tạm) | phiên chính | tự làm theo `.agents/skills/phase-4-business-impact/SKILL.md` | như bên trái (mỗi lượt khoảng 5 F) | `check --stage impact` |
| Risk | **Phase Risk** — rủi ro thực tế: đường khai thác, từng mắt xích có/không/chưa rõ và vì sao, ghép chéo, đặt cạnh tác động 4.4 để chốt rủi ro, thách thức độc lập | theo `/phase-risk-assessment` | tự làm theo `.agents/skills/phase-risk-assessment/SKILL.md` (R.1, R.4 giao subagent) | như bên trái (R.4 trong cuộc hội thoại mới) | `check --stage risk` |
| 4.5 | Tóm tắt, lộ trình, khoảng trống, bản nháp | phiên chính | tự làm theo `.agents/skills/phase-4-report-writer/SKILL.md` mục 4.5, rồi `python3 AI-skills/reporting/report.py render --draft` | như bên trái | `status` báo 4.5 xong |
| 4.6 | Rà soát độc lập | **không phải phiên chính** | Agent tool, `general-purpose`, `model: sonnet`; prompt chỉ gồm: "Chạy theo `.agents/skills/phase-4-independent-review/SKILL.md`; `context: fresh_subagent`". Hơn khoảng 15 F thì chia lô theo cụm nghiệp vụ, mỗi lô một subagent, ghi `work/review/<lô>.json` | mở **cuộc hội thoại mới** cho mỗi lô, gọi `/phase-4-independent-review`, ghi `context: new_session` | `review.json` hoặc `review/<lô>.json` phủ đủ F |
| 4.7 | Xử lý review, chốt báo cáo | phiên chính | theo `.agents/skills/phase-4-report-writer/SKILL.md` mục 4.7 | như bên trái | `check --stage final` + `render` |

`work/` = `documents/_report/work/`. Mọi lệnh chạy từ `<Project-Root>` (trên Windows dùng `python`; trên macOS/Linux dùng `python3`). Subagent trả về thì xác nhận bằng `python3 AI-skills/reporting/report.py status`/`catalog`, không tin báo cáo suông.

### Vòng lặp chuẩn
```bash
python3 AI-skills/reporting/report.py status     # bước nào tiếp theo
python3 AI-skills/reporting/report.py catalog    # (4.3) danh mục F, đề xuất chờ hợp nhất, lô tiếp theo
python3 AI-skills/reporting/report.py check --stage <architecture|findings|impact|risk|final>
python3 AI-skills/reporting/report.py render --draft   # trước 4.6
python3 AI-skills/reporting/report.py render           # sau 4.7
```

## Tài liệu hướng dẫn (đọc đúng lúc, không đọc hết một lần)
- `AI-skills/reporting/guides/01_nguon_du_lieu.md`: artifact nào thuộc giai đoạn nào, trạng thái nào là cuối, SID, chuỗi ↔ nguồn gốc.
- `AI-skills/reporting/guides/02_kien_truc.md`: bước 4.2.
- `AI-skills/reporting/guides/03_hop_nhat_phat_hien.md`: bước 4.3 (chế độ lô, đề xuất `NEW:`).
- `AI-skills/reporting/guides/04_tac_dong_nghiep_vu.md`: bước 4.4.
- `AI-skills/reporting/guides/05_viet_bao_cao.md`: bước 4.5–4.7.
- `AI-skills/reporting/guides/06_rui_ro_thuc_te.md`: Phase Risk (đọc qua `/phase-risk-assessment`).
- Mẫu: `AI-skills/reporting/templates/`.

## Kết thúc
Báo cáo xong khi `python3 AI-skills/reporting/report.py status` ghi `next: xong`, tức đã qua `check --stage final` gồm cả rà soát độc lập. Báo cho người dùng: đường dẫn báo cáo; số phát hiện theo mức rủi ro × độ tin cậy; số mục bị loại trừ theo lý do; số vấn đề rà soát đã xử lý; 3 khoảng trống lớn nhất.
