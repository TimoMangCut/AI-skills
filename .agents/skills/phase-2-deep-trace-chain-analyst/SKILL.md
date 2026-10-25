---
name: phase-2-deep-trace-chain-analyst
description: >-
  Phase 2.2 — Truy vết sâu từng bước nhảy thực thi (hops[]), dựng chuỗi tấn công đa bước, truy nguyên nhân gốc (Root-Cause) và thiết kế chuỗi request kiểm định trong một lượt đọc liền mạch (deep_trace_chain_analyst). Kích hoạt ở Bước 2.2 hoặc khi gọi /phase-2-deep-trace-chain-analyst.
---

# Phase 2.2: Consolidated Deep Trace, Chain Constructor & Root-Cause Analyst (`deep_trace_chain_analyst`)

Bạn đang thực thi **Bước 2.2 (`deep_trace_chain_analyst`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`.

Bước này hợp nhất 5 yêu cầu kỹ thuật liên hoàn trong **một phiên đọc mã nguồn duy nhất** cho toàn bộ các ứng viên trong `candidate_queue.json`:

---

## 1. Năm Yêu cầu Kỹ thuật Bắt buộc (`ARCH-3G`, `DEPTH-4.2b`)

1. **Hạch toán 100% Ứng viên từ `candidate_queue.json` (`ARCH-3G`)**:
   - **Mọi `candidate_id`** trong `.localsec/runs/default/<repo_name>/candidate_queue.json` bắt buộc phải xuất hiện trong ít nhất một chuỗi thuộc `chains[].source_candidate_ids` **HOẶC** được giải trình trong `unexploitable_candidates[]` (kèm `candidate_id`, `reason`, và `evidence_ids` chứng minh kiểm soát ngăn chặn). Nghiêm cấm làm rơi ứng viên.
2. **Truy vết Bước nhảy Thực thi `hops[]` Kèm `hop_kind` & Bằng chứng Hai Đầu (`DEPTH-4.2b`)**:
   - Truy vết từng bước nhảy từ Entrypoint (Controller / WebSocket / MQTT / ZeroMQ / gRPC) $\rightarrow$ Middleware / Guard $\rightarrow$ Service $\rightarrow$ Sink (SQL / Redis / Kafka / CAN / Modbus / Shell / HTTP Client).
   - Mỗi phần tử trong `hops[]` **BẮT BUỘC** phải khai báo `hop_kind` thuộc tập:
     - `in_process`
     - `http`
     - `grpc`
     - `message_queue`
     - `zmq_or_ipc`
     - `db`
     - `file_or_hardware`
   - Với mọi bước nhảy xuyên dịch vụ (`http`, `grpc`, `message_queue`, `zmq_or_ipc`), bắt buộc đính kèm **cả mã bằng chứng `ev_...` phía gửi (`caller_evidence_id`) lẫn phía nhận (`callee_evidence_id`)** trong `evidence_ids`.
3. **Dựng Chuỗi Tấn công Đa bước (`steps[]` & `linked_next_steps[]`)**:
   - Xác định rõ `preconditions`, `state_before`, `state_after`, `data_or_privilege_delta` và cạnh kích hoạt sang bước kế tiếp.
4. **Truy Nguyên nhân Gốc rễ (`root_cause`)**:
   - Gom các triệu chứng bề mặt về nguyên nhân gốc trong kiến trúc, mô hình phân quyền hoặc máy trạng thái để sửa dứt điểm ở gốc.
5. **Thiết kế Chuỗi Request Kiểm định (`request_plan`)**:
   - Thiết kế chuỗi HTTP/RPC/MQTT/OCPP/ZeroMQ request phân biệt rõ hành vi an toàn và hành vi lỗi (mặc định ở chế độ `execution_mode: "plan_only"` / `"not_executed"`).

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Xem lại bằng chứng đã thu thập hoặc đọc sâu thêm các dòng code dọc theo đường đi của chuỗi tấn công
python -m localsec.manual_session show_evidence <repo_name> <ev_id>
python -m localsec.manual_session read_file <repo_name> <path> <start_line> <end_line> --skill deep_trace_chain_analyst

# 2. Lưu kết quả phân tích sâu (đối chiếu AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json)
python -m localsec.manual_session submit_skill <repo_name> deep_trace_chain_analyst .localsec/tmp/deep_trace_chain_analyst_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`)

```json
{
  "chains": [
    {
      "chain_id": "CHAIN-OCPP-STOP-01",
      "source_candidate_ids": ["CAND-OCPP-BOLA-01"],
      "title": "Cross-Tenant RemoteStopTransaction via Unchecked sessionId",
      "code_verified_severity": "high",
      "verification_status": "code_supported",
      "hops": [
        {
          "hop_number": 1,
          "hop_kind": "in_process",
          "from_symbol": "ChargingController.remoteStopSession",
          "to_symbol": "ChargingService.stopSessionById",
          "file": "src/controllers/charging.controller.ts",
          "evidence_ids": ["ev_..."]
        },
        {
          "hop_number": 2,
          "hop_kind": "http",
          "from_symbol": "ChargingService.stopSessionById",
          "to_symbol": "OcppGatewayClient.sendRemoteStop",
          "file": "src/services/charging.service.ts",
          "caller_evidence_id": "ev_...",
          "callee_evidence_id": "ev_...",
          "evidence_ids": ["ev_...", "ev_..."]
        }
      ],
      "steps": [
        {
          "step_id": "STEP-1",
          "description": "Attacker sends POST /api/v1/sessions/{victimSessionId}/remote-stop with valid B2C JWT",
          "preconditions": ["Valid B2C JWT", "Active victim sessionId"],
          "state_before": "Victim charging session is ACTIVE",
          "state_after": "CSMS sends RemoteStopTransaction to charge point and marks session STOPPING",
          "data_or_privilege_delta": "Unauthorized cross-user control over physical charging session",
          "linked_next_steps": [],
          "evidence_ids": ["ev_..."]
        }
      ],
      "root_cause": {
        "category": "missing_object_level_ownership_guard",
        "description": "ChargingService.stopSessionById queries session by primary key without scoping by currentUser.id",
        "remediation": "Enforce repository query WHERE id = :sessionId AND user_id = :currentUserId"
      },
      "request_plan": {
        "execution_mode": "plan_only",
        "discriminating_requests": [
          "POST /api/v1/sessions/10042/remote-stop Authorization: Bearer <userB_jwt>"
        ],
        "expected_safe_behavior": "HTTP 403 Forbidden when session.userId != userB.id",
        "expected_vulnerable_behavior": "HTTP 200 OK and RemoteStopTransaction dispatched"
      }
    }
  ],
  "unexploitable_candidates": []
}
```
