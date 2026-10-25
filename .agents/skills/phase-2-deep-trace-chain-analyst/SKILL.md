---
name: phase-2-deep-trace-chain-analyst
description: >-
  Phase 2.2 — Truy vết sâu từng bước nhảy thực thi (hops[]), dựng chuỗi tấn công đa bước, truy nguyên nhân gốc (Root-Cause) và thiết kế chuỗi request kiểm định trong một lượt đọc liền mạch (deep_trace_chain_analyst). Kích hoạt ở Bước 2.2 hoặc khi gọi /phase-2-deep-trace-chain-analyst.
---

# Phase 2.2: Consolidated Deep Trace, Chain Constructor & Root-Cause Analyst (`deep_trace_chain_analyst`)

Bạn đang thực thi **Bước 2.2 (`deep_trace_chain_analyst`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Để tối ưu hóa chi phí (usage) mà vẫn giữ trọn chiều sâu kỹ thuật, bước này hợp nhất 4 tác vụ liên hoàn trong **một phiên đọc mã nguồn duy nhất** cho từng ứng viên trong `Candidate Queue`:

1. **Deep Code Hop Trace (`hops[]`)**:
   - Truy vết từng bước nhảy từ Entrypoint (Controller / WebSocket / MQTT / ZeroMQ / gRPC) $\rightarrow$ Middleware / Guard $\rightarrow$ Service $\rightarrow$ Sink (SQL / Redis / Kafka / CAN / Modbus / Shell / HTTP Client).
   - Mỗi hop `directly_read` bắt buộc đính kèm `ev_...` thực tế.
2. **Multi-Step Attack Chain Construction (`steps[]` & `linked_next_steps[]`)**:
   - Xác định rõ `preconditions`, `state_before`, `state_after`, `data_or_privilege_delta` và cạnh kích hoạt sang bước kế tiếp.
3. **Root-Cause Mapping**:
   - Gom các triệu chứng bề mặt về nguyên nhân gốc trong kiến trúc, mô hình phân quyền hoặc máy trạng thái để fix một lần ở gốc.
4. **Discriminating Request / Payload Sequence Design**:
   - Thiết kế chuỗi HTTP/RPC/MQTT/OCPP/ZeroMQ request phân biệt rõ hành vi an toàn và hành vi lỗi (mặc định ở chế độ `plan_only` / `not_executed` trừ khi có môi trường local được phê duyệt).

---

## Giao thức Thực thi CLI

```bash
# 1. Đọc sâu các dòng code dọc theo đường đi của chuỗi tấn công
python3 -m localsec.manual_session read_file <repo_name> <path> <start_line> <end_line> --skill deep_trace_chain_analyst

# 2. Lưu kết quả phân tích sâu
python3 -m localsec.manual_session submit_skill _analysis deep_trace_chain_analyst /tmp/deep_trace_chain_analyst.json
```
