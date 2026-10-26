---
name: phase-4-architecture-synthesis
description: >-
  Phase 4.2 — Tổng hợp kiến trúc toàn hệ thống từ kết quả recon/architecture review của từng repo — chia cụm nghiệp vụ, sơ đồ, luồng nghiệp vụ xuyên service, mô hình tin cậy, thành phần dùng chung và ảnh hưởng dây chuyền, liên kết với project khác.
---

# `phase-4-architecture-synthesis` (Phase 4.2)

Dựng **một** bức tranh kiến trúc cho cả project: repo → service → cụm nghiệp vụ → liên kết giữa các cụm và với project khác. Đây là mục riêng, quan trọng nhất của báo cáo tổng hợp.

**Quyền truy cập:** theo mục "Quyền truy cập của Phase 4" trong `.agents/skills/phase-4-consolidated-report/SKILL.md`. Tóm tắt: đọc `documents/`, `reports/`, `specs/`, `AI-skills/reporting/`; chỉ ghi `documents/_report/work/`; không đọc mã nguồn.

## Prompt kích hoạt
```text
/phase-4-architecture-synthesis Tổng hợp kiến trúc toàn hệ thống theo cụm nghiệp vụ từ documents/_report/inputs; mọi cạnh và kiểm soát gắn nhãn có bằng chứng/giả thuyết; trả lời được "service nào bị chiếm thì cụm nào bị ảnh hưởng".
```

## Điều kiện
`python3 AI-skills/reporting/report.py status` đã ghi `4.1 collect: xong`. Chưa có thì chạy `collect` trước.

## Làm
1. Đọc `AI-skills/reporting/guides/02_kien_truc.md` (bắt buộc) và `AI-skills/reporting/templates/architecture.template.md`.
2. Đọc lần lượt: `documents/_report/inputs/01_services.md` → `02_edges.md` → phần nguyên nhân gốc/khuôn mẫu/rủi ro hệ thống của `03_findings_index.md` → `04_related_projects.md` (nếu có).
3. Với service trọng yếu và thành phần dùng chung: đọc theo đoạn `documents/<repo>/08_architecture_review.md`, `06_dataflow.md`, `documents/_system/03_cross_repo_review.md`, `documents/_system/diagrams/*.mmd`.
4. Ghi `documents/_report/work/architecture.json`: `project`, `domains` (mọi repo thuộc đúng một cụm), `shared_components`, `related_projects`. Mẫu: `templates/architecture.example.json`.
5. Ghi `documents/_report/work/architecture.md`: mục `### 2.1` → `### 2.6`, có một sơ đồ ```mermaid```. Heading không dùng `#`/`##`.
6. Chạy `python3 AI-skills/reporting/report.py check --stage architecture`; sửa tới khi `ĐẠT`.

## Không được
- Đọc mã nguồn, hoặc kết luận quan hệ service/project chỉ từ tên.
- Liệt kê lại finding: phần này nói về cấu trúc, kiểm soát và đường lan.
- Bỏ qua repo hạ tầng/rỗng. Chúng vẫn phải thuộc một cụm (ví dụ `Nền tảng & hạ tầng`).

## Đầu ra cho bước sau
`domains[].id` sẽ được bước 4.3 dùng để gắn phát hiện. `shared_components` sẽ được bước 4.4 dùng để đánh giá ảnh hưởng dây chuyền.
