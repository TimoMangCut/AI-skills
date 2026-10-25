---
name: phase-1-extractor-tailor
description: >-
  Phase 1.2 Micro-Skill — Đánh giá và tinh chỉnh hoặc tạo mới Python structural extractor phù hợp với quy ước code của repo trên canary files, hoặc chọn SKIP_EXTRACTOR_DIRECT_READ để tránh thiên kiến SAST (extractor_tailor). Kích hoạt ở Bước 1.2 hoặc khi gọi /phase-1-extractor-tailor.
---

# Phase 1.2 Micro-Skill: Python Extractor Tailor (`extractor_tailor`)

> **Subagent Isolation Directive**: Run this micro-skill after Step 1.1 (`codebase_scout`) and Step 1.3 (`intent_invariant_modeler`) have completed.

Bạn đang thực thi **Micro-Skill `phase-1-extractor-tailor` (Bước 1.2)** trong bộ kỹ năng **LocalSec v3.0** (chạy sau khi đã hoàn tất Bước 1.1 `codebase_scout` và Bước 1.3 `intent_invariant_modeler` theo thứ tự `ARCH-3K`).
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/extractor_tailor.schema.json`.

Mục tiêu của bước này là giải quyết triệt để bài toán: **Python script cứng nhắc chạy trước dễ bỏ sót (FN) hoặc báo giả (FP) trước muôn vàn kiểu code của các team khác nhau, làm AI bị thiên kiến (anchoring bias) vào một mẫu số sai**.

---

## 1. Quy tắc Kỷ luật Bắt buộc (Anti-Anchoring & Canary Verification — `BUG-05`)

1. **Python Extractor chỉ là trợ lý gợi ý vị trí dòng, KHÔNG PHẢI công cụ SAST và KHÔNG PHẢI mẫu số tuyệt đối**:
   - Tuyệt đối không dùng Python để phán đoán lỗ hổng hay tự động gom cụm tương đương (việc gom cụm do AI thực hiện ở Bước 1.4).
2. **Ba chế độ quyết định (`mode` & `extractor_decision`)**:
   - `USE_STANDARD_EXTRACTOR`: Dùng bộ regex/AST chuẩn khi repo viết theo chuẩn phổ thông (`@GetMapping`, `@Controller`, `router.POST`, `@app.route`, `@on(Action.*)`) VÀ bắt buộc kiểm thử trên `canary_files` đạt số điểm khớp tối thiểu `--expected-canary-hits`.
   - `TAILOR_CUSTOM_EXTRACTOR`: Khi team dùng DSL riêng, bảng đăng ký hàm trong C++ (`vla.cpp` ZMQ dispatch table), custom wrapper hoặc file cấu hình định tuyến riêng → AI ghi biểu thức trích xuất riêng vào `.localsec/tmp/patterns.json` và truyền qua `--patterns-file .localsec/tmp/patterns.json --expected-canary-hits <N>`.
   - `SKIP_EXTRACTOR_DIRECT_READ`: Khi code quá động (reflection, dynamic metaprogramming, Smali bytecode, macro C++ phức tạp) hoặc repo nhỏ (`tier_3`) → Bỏ qua Python extractor hoàn toàn để không làm nhiễu ngữ cảnh; AI đọc thủ công trực tiếp theo `target_modules`.
3. **Cổng kiểm định Canary & Tự động Quét `target_modules` (`canary_verified = true` bắt buộc)**:
   - Khi chạy `run_tailored_extractor`, nếu số điểm khớp trên `canary_files` đạt `>= --expected-canary-hits` (`canary_verified: true`), **engine sẽ tự động quét toàn bộ các thư mục trong `target_modules`** và lưu danh sách gợi ý cấu trúc để hỗ trợ Bước 1.4.
   - Nếu số điểm khớp trên `canary_files` nhỏ hơn `--expected-canary-hits`, hệ thống tự động **TỪ CHỐI** (`canary_verified: false`). Bạn bắt buộc phải sửa lại `.localsec/tmp/patterns.json` hoặc chuyển sang `SKIP_EXTRACTOR_DIRECT_READ`.

---

## 2. Giao thức Thực thi CLI

```powershell
# Trường hợp 1: Dùng bộ extractor chuẩn kèm kiểm định số lượng canary hits tối thiểu
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode USE_STANDARD_EXTRACTOR --canary-files src/ocpp_controller.py --expected-canary-hits 1

# Trường hợp 2: Tinh chỉnh pattern riêng qua --patterns-file và kiểm định --expected-canary-hits
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode TAILOR_CUSTOM_EXTRACTOR --canary-files src/ocpp_controller.py --patterns-file .localsec/tmp/patterns.json --expected-canary-hits 1

# Trường hợp 3: Bỏ qua extractor để đọc trực tiếp (khi code động hoặc C++ macro phức tạp)
python -m localsec.manual_session run_tailored_extractor <repo_name> --mode SKIP_EXTRACTOR_DIRECT_READ

# Hoặc lưu kết quả tùy chỉnh qua submit_skill (đối chiếu AI-skills/schemas/v3/extractor_tailor.schema.json)
python -m localsec.manual_session submit_skill <repo_name> extractor_tailor .localsec/tmp/extractor_tailor_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/extractor_tailor.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "mode": "USE_STANDARD_EXTRACTOR",
    "extractor_decision": "USE_STANDARD_EXTRACTOR",
    "canary_files": [
      "src/ocpp_controller.py"
    ],
    "canary_verified": true,
    "expected_canary_hits": 1,
    "canary_hit_count": 1,
    "rationale": "Verified @on(Action.RemoteStartTransaction) on canary file"
  }
}
```
