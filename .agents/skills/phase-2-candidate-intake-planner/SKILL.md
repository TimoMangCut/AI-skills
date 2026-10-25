---
name: phase-2-candidate-intake-planner
description: >-
  Phase 2.1 — Tiếp nhận Candidate Queue từ Phase 1 Recon, chuẩn hóa giả thuyết chuỗi tấn công và chọn các khối Attack-Class Companion nguyên văn (candidate_intake_planner). Kích hoạt ở Bước 2.1 hoặc khi gọi /phase-2-candidate-intake-planner.
---

# Phase 2.1: Candidate Intake & Attack Companion Planner (`candidate_intake_planner`)

Bạn đang thực thi **Bước 2.1 (`candidate_intake_planner`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Thay vì quét lại toàn bộ mã nguồn từ đầu, Phase 2 **chỉ tập trung nguồn lực đọc sâu vào các mục trong `Candidate Queue`** phát sinh từ Phase 1 (các `outliers` từ gom cụm ngữ nghĩa, các điểm lệch giữa Ý định & Triển khai, và các điểm đứt gãy ranh giới tin cậy liên repo).

---

## 1. Quy tắc Thực thi Bắt buộc

1. **Lọc và Xếp hạng Ưu tiên `Candidate Queue`**:
   - Ưu tiên `P0`: Các ứng viên tác động trực tiếp đến trục **Safety (S)** (điều khiển xe, trạm sạc, BESS, robot, y tế) hoặc **Financial (F)** / **AuthZ BOLA đa thuê bao**.
   - Ưu tiên `P1`: Các ứng viên có chuỗi leo thang quyền hạn xuyên dịch vụ hoặc thực thi mã từ xa (RCE/Deserialization/SSRF).
2. **Tiêm Nguyên văn Khối `Attack-Class Companion` (`## [ BLOCK: ... ]`)**:
   - Chạy `select_attack_companions` để nạp nguyên văn các khối kiểm tra chuyên sâu từ `contracts/attack-taxonomy-v1/` (16 mô-đun).
   - **CẤM tóm tắt hoặc viết lại nội dung bên trong khối `## [ BLOCK: ... ]`**. Nếu loại trừ bất kỳ khối nào, phải ghi rõ lý do trong `excluded_blocks`.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Chọn các khối Attack-Class Companion nguyên văn cho từng repo liên quan
python3 -m localsec.manual_session select_attack_companions <repo_name>

# 2. Lưu danh sách Candidate Queue đã chuẩn hóa
python3 -m localsec.manual_session submit_skill _analysis candidate_intake_planner /tmp/candidate_intake_planner.json
```
