---
name: phase-1-extractor-tailor
description: >-
  Phase 1.2 Micro-Skill — Đánh giá và tinh chỉnh hoặc tạo mới Python structural extractor phù hợp với quy ước code của repo trên canary files, hoặc chọn SKIP_EXTRACTOR_DIRECT_READ để tránh thiên kiến SAST (extractor_tailor). Kích hoạt ở Bước 1.2 hoặc khi gọi /phase-1-extractor-tailor.
---

# Phase 1.2 Micro-Skill: Python Extractor Tailor (`extractor_tailor`)

Bạn đang thực thi **Micro-Skill `phase-1-extractor-tailor` (Bước 1.2)** trong bộ kỹ năng **LocalSec v3.0**.
Mục tiêu của bước này là giải quyết triệt để bài toán: **Python script cứng nhắc chạy trước dễ bỏ sót (FN) hoặc báo giả (FP) trước muôn vàn kiểu code của các team khác nhau, làm AI bị thiên kiến (anchoring bias) vào một mẫu số sai**.

Dựa vào kết quả `codebase_scout.json` từ Bước 1.1, bạn sẽ đánh giá xem quy ước code của repo có phù hợp để dùng Python trích xuất gợi ý cấu trúc (routes, IPC topics, decorators) hay không, kiểm thử bắt buộc trên `canary_files` trước, hoặc chủ động tắt extractor (`SKIP_EXTRACTOR_DIRECT_READ`).

---

## 1. Quy tắc Kỷ luật Bắt buộc (Anti-Anchoring & Canary Verification)

1. **Python Extractor chỉ là trợ lý gợi ý vị trí dòng, KHÔNG PHẢI công cụ SAST và KHÔNG PHẢI mẫu số tuyệt đối**:
   - Tuyệt đối không dùng Python để phán đoán lỗ hổng hay tự động gom cụm tương đương (việc gom cụm do AI thực hiện ở Bước 1.4).
2. **Ba chế độ quyết định (`mode`)**:
   - `USE_STANDARD_EXTRACTOR`: Dùng bộ regex/AST chuẩn khi repo viết theo chuẩn phổ thông (`@GetMapping`, `@Controller`, `router.POST`, `@app.route`, `@KafkaListener`) VÀ bắt buộc chạy thử khớp đúng 100% trên `canary_files` đã đọc ở Bước 1.1.
   - `TAILOR_CUSTOM_EXTRACTOR`: Khi team dùng DSL riêng, bảng đăng ký hàm trong C++ (`vla.cpp` ZMQ dispatch table), custom wrapper hoặc file cấu hình định tuyến riêng → AI cập nhật/sinh biểu thức trích xuất riêng khớp với cách code của team, chạy kiểm chứng trên `canary_files` trước khi quét các module mục tiêu.
   - `SKIP_EXTRACTOR_DIRECT_READ`: Khi code quá động (reflection, dynamic metaprogramming, Smali bytecode, macro C++ phức tạp) hoặc repo nhỏ (`tier_3`) → Bỏ qua Python extractor hoàn toàn để không làm nhiễu ngữ cảnh; AI đọc thủ công trực tiếp theo `target_modules`.
3. **Cổng kiểm định Canary (`canary_verified = true` bắt buộc)**:
   - Nếu chọn `USE_STANDARD_EXTRACTOR` hoặc `TAILOR_CUSTOM_EXTRACTOR` mà chạy trên `canary_files` trả về `0` kết quả hoặc thiếu route đã biết → Hệ thống tự động **TỪ CHỐI** (`canary_verified: false`). Bạn bắt buộc phải sửa lại pattern hoặc chuyển sang `SKIP_EXTRACTOR_DIRECT_READ`.

---

## 2. Giao thức Thực thi CLI

```bash
# Trường hợp 1: Kiểm thử và chạy extractor trên canary files đã biết từ Bước 1.1
python3 -m localsec.manual_session run_tailored_extractor <repo_name> \
  --mode USE_STANDARD_EXTRACTOR \
  --canary-files src/controllers/charging.controller.ts

# Trường hợp 2: Bỏ qua extractor để đọc trực tiếp (khi code động hoặc C++ macro phức tạp)
python3 -m localsec.manual_session run_tailored_extractor <repo_name> \
  --mode SKIP_EXTRACTOR_DIRECT_READ

# Hoặc lưu kết quả tùy chỉnh qua submit_skill
python3 -m localsec.manual_session submit_skill <repo_name> extractor_tailor /tmp/extractor_tailor_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON (`extractor_tailor.json`)

```json
{
  "mode": "TAILOR_CUSTOM_EXTRACTOR",
  "rationale": "Repo uses custom register_ocpp_action('BootNotification', handler_fn) instead of standard HTTP decorators; tailored regex verified against canary file src/ocpp/handlers/boot-notification.handler.ts.",
  "canary_files": [
    "src/ocpp/handlers/boot-notification.handler.ts"
  ],
  "canary_verified": true
}
```
