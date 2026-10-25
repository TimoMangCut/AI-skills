---
name: phase-3-root-cause-mapper
description: >-
  Phase 3.7 — Truy nguyên từ các triệu chứng bề mặt và các chuỗi tấn công về nguyên nhân gốc rễ trong kiến trúc, mô hình phân quyền hoặc máy trạng thái (root_cause_mapper). Kích hoạt khi người dùng gọi /phase-3-root-cause-mapper hoặc thực hiện bước này trong pipeline.
---

# `phase-3-root-cause-mapper` (PHASE-3 — Internal Skill ID: `root_cause_mapper`)

Phase 3.7 — Truy nguyên từ các triệu chứng bề mặt và các chuỗi tấn công về nguyên nhân gốc rễ trong kiến trúc, mô hình phân quyền hoặc máy trạng thái (`root_cause_mapper`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-3-root-cause-mapper Không dừng lại ở vị trí phát sinh lỗi bề mặt (symptom location): hãy truy ngược về tận nguyên nhân gốc rễ trong kiến trúc, mẫu thiết kế phân quyền, ranh giới tin cậy hoặc máy trạng thái.
Tìm xem cùng một khiếm khuyết gốc rễ đó đang đồng thời mở đường cho những chuỗi tấn công nào khác trên toàn hệ thống để đề xuất một điểm sửa chữa triệt để ở tầng gốc (`remediation_at_root`).
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Được phép đọc mã nguồn (`list_dir`, `read_file`) để xác minh mẫu lỗi lặp lại xuyên dịch vụ.
- Prompt & Contract gốc: `AI-skills/contracts/attack-chain-analysis-v1/prompts/root_cause_mapper.md` (Registry: `AI-skills/contracts/attack-chain-analysis-v1/registry.json`).
- Schema đích: `AI-skills/contracts/attack-chain-analysis-v1/schemas/root_cause.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python -m localsec.manual_session read_file _analysis "<repo_name>:<rel_path>" 1 160 --skill root_cause_mapper
python -m localsec.manual_session submit_skill _analysis root_cause_mapper <json_file> --artifact-id <rc_id>
```
