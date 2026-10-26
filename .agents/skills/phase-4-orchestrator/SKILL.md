---
name: phase-4-orchestrator
description: >-
  Điểm vào Phase 4 của wins (Phase cuối, sau Phase đánh giá Risk): kiểm cổng Phase 1/2/3, xuất kết quả đã khoá sổ thành đầu vào của bộ báo cáo tổng hợp (`reporting/report.py`), rồi chuyển sang luồng /phase-4-consolidated-report (gồm Phase Risk /phase-risk-assessment) để ra BAO_CAO_TONG_HOP_BAO_MAT.md và DANH_GIA_RUI_RO.md có cổng kiểm. Kích hoạt khi người dùng gọi /phase-4-orchestrator.
---

# Phase 4 của wins — Xuất dữ liệu và lập báo cáo tổng hợp

Phase 4 không đọc mã nguồn và không tự viết báo cáo bằng script. Nó gồm hai phần:

1. **Xuất (script, 0 token):** `finalize_v3_phase4` chép kết quả `.localsec/runs/<run_id>/` thành các file trong `documents/` mà `reporting/report.py collect` đọc được.
2. **Lập báo cáo (model + cổng script):** chạy nguyên luồng của bộ báo cáo tổng hợp vendored trong `AI-skills/reporting/` và các skill `phase-4-*` / `phase-risk-*`. Mọi kết luận đi qua `python3 AI-skills/reporting/report.py check`; mức rủi ro do `reporting/risk.py` suy ra.

## Bước 4.0 — Kiểm cổng và xuất

```bash
python3 -m localsec.manual_session finalize_v3_phase4
```

- Dừng (`gate_passed: false`) nếu repo nào thiếu hoặc trượt `phase1/2/3_gate_receipt.json`. Chạy lại `finalize_v3_phase1/2/3` cho repo đó. Chỉ khi người dùng đồng ý xuất bản chưa khoá sổ mới thêm `--allow-unfinalized` (repo chưa đạt sẽ không có `12_analysis_status.json`, và `collect` ghi nhận là chưa xong).
- Dừng (`overwrite_blocked: true`) nếu một file đích trong `documents/` đã có mà không do wins sinh (ví dụ dự án đã chạy bộ khác). Báo người dùng danh sách `conflicting_files`. Chỉ dùng `--force-overwrite` khi người dùng xác nhận.
- Lệnh này **không** ghi `documents/_report/work/` và không ghi báo cáo cuối. `documents/_report/runtime_facts.json` được gộp (giữ fact đã có).

File được xuất:

| File | Nguồn wins |
|---|---|
| `documents/<repo>/01_repo_profile.md`, `02_techstack.json`, `05_inbound_outbound.json` | 1.1 codebase_scout, 1.3 unified_surface_mapper |
| `documents/<repo>/09_findings.json` | toàn bộ `candidate_queue` + phát hiện kiến trúc 1.5 |
| `documents/<repo>/basv/18_…`, `19_…` | `invariant_checks` của 1.3, bất biến 1.2; 19 chỉ khi cổng Phase 2 đạt |
| `documents/<repo>/12_analysis_status.json` | chỉ khi cả 3 cổng đạt |
| `documents/<repo>/16_code_coverage.json` | `mandatory_pct` = số dòng đã đọc / tổng dòng file bắt buộc |
| `documents/<repo>/evidence_index.json` | mọi `ev_` đã đọc, để `risk.py` nhận làm bằng chứng |
| `documents/_analysis/chains/chain_<repo>_<id>.json`, `06_root_cause_map.json`, `99_project_chain_report.json` | chuỗi Phase 2 + đối chiếu phản biện 2.3 |
| `documents/_system/02_cross_repo_review.json` | ghép ranh giới liên repo (trạng thái `hypothesis`) |
| `documents/_v3/wins_phase3_risk.json` | dữ liệu Phase 3 (3.1/3.2/3.3) theo chuỗi, chép nguyên |

## Bước 4.1 trở đi — Luồng báo cáo tổng hợp

```bash
python3 AI-skills/reporting/report.py collect
python3 AI-skills/reporting/report.py status
```

Sau đó gọi `/phase-4-consolidated-report` và làm đúng theo skill đó (4.2 kiến trúc → 4.3 hợp nhất F → 4.4 tác động → Phase Risk `/phase-risk-assessment` R.1–R.5 → 4.5 viết → 4.6 rà soát độc lập → 4.7), kết thúc bằng:

```bash
python3 AI-skills/reporting/report.py check --stage final
python3 AI-skills/reporting/report.py render
```

### Đối chiếu tên gọi khi đọc các skill vendored

Các skill `phase-4-*` / `phase-risk-*` và `AI-skills/reporting/guides/` được chép nguyên từ bộ báo cáo dùng chung, nên dùng tên nguồn của bộ đó. Với dữ liệu wins:

| Trong skill vendored | Ở wins |
|---|---|
| SID `P1` (`<repo>:<id>`, `09_findings.json`) | ứng viên Phase 1 của wins (`candidate_queue`) và phát hiện kiến trúc 1.5 |
| SID `P2` (`basv/18`) | bất biến bị thiếu/chưa rõ từ 1.2/1.3 |
| SID `P3` / chuỗi (`_analysis:<repo>:<id>`) | chuỗi Phase 2 của wins sau đối chiếu phản biện 2.3 |
| `lsec.py read_file` | `python3 -m localsec.manual_session read_file` (Phase 4 không đọc mã nguồn) |

### Dùng kết quả Phase 3 của wins trong Phase Risk

Ở R.1 (`/phase-risk-exploit-path`), đọc `documents/_v3/wins_phase3_risk.json` cho các chuỗi thuộc F đang viết:
- `preconditions` (3.1) → điều kiện của đường khai thác, giữ trạng thái và `evidence_ids`; điều kiện chưa có bằng chứng thì `chua_ro`.
- `beyond_code_controls` (3.2) → `blocking_controls`; kiểm soát không có bằng chứng thì `exists: chua_ro`.
- `impact_axes` (3.3) → cơ sở cho tác động 4.4.
- `key_questions` → câu hỏi mở.

Người nắm giữ (`holders`) và `actors_considered` theo từng loại người: chỉ ghi khi có cơ sở; dữ liệu wins hiện không có các trường này cho mọi chuỗi, nên phải lập luận và ghi lý do như skill R.1 yêu cầu. `risk.py` tự suy mức rủi ro; nếu khác `derived_risk_rating` của wins, giải thích ở R.3.

## Không làm

- Không sửa tay file do 4.0 xuất; muốn đổi thì sửa kết quả Phase 1–3 rồi chạy lại 4.0.
- Không viết `work/risk/F-xx.json`, `_combinations.json` hay báo cáo bằng script; chúng là đầu ra của các bước có model và có cổng kiểm.
