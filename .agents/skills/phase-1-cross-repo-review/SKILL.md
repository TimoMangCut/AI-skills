---
name: phase-1-cross-repo-review
description: Phase 1.7 — Tổng hợp rủi ro cấp hệ thống xuyên qua nhiều repositories, phát hiện lệch giả định tin cậy giữa bên gọi và bên nhận (`cross_repo_review`).
---

# `phase-1-cross-repo-review` (PHASE-1 — Internal Skill ID: `cross_repo_review`)

Phase 1.7 — Tổng hợp rủi ro cấp hệ thống xuyên qua nhiều repositories, phát hiện lệch giả định tin cậy giữa bên gọi và bên nhận (`cross_repo_review`).

## Prompt Kích hoạt Tư duy Phản biện (Critical-Thinking Booster — 2–4 dòng)
```text
/phase-1-cross-repo-review Phân tích rủi ro liên dịch vụ trên toàn bộ các repositories đã hoàn tất khảo sát.
Tập trung tìm sự bất đối xứng tin cậy: nơi Service A giả định Service B đã kiểm tra quyền/chữ ký, trong khi Service B lại mặc định mọi lệnh gọi nội bộ đều đáng tin cậy.
```

## Trách nhiệm & Cổng Kiểm định (Epistemic Gates)
- Tổng hợp `system_architecture`, `shared_trust_patterns`, `cross_repo_flows`, `cross_repo_findings`, và `priority_remediations`.
- Schema đích: `schemas/cross_repo_review.schema.json`.

## Lệnh Thực thi Chuẩn (Portable CLI)
```bash
python3 -m localsec.manual_session prepare_system_context
python3 -m localsec.manual_session finalize_system --cross-repo <path> --sys-audit <path> --diagrams <path>
```
