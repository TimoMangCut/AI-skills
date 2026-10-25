---
name: phase-2-deep-trace-chain-analyst
description: >-
  Phase 2.2 — Truy vết sâu từng bước nhảy thực thi (hops[]), dựng chuỗi tấn công đa bước, truy nguyên nhân gốc (Root-Cause) và thiết kế chuỗi request kiểm định trong một lượt đọc liền mạch (deep_trace_chain_analyst). Kích hoạt ở Bước 2.2 hoặc khi gọi /phase-2-deep-trace-chain-analyst.
---

# Phase 2.2: Consolidated Deep Trace, Chain Constructor & Root-Cause Analyst (`deep_trace_chain_analyst`)

> **Subagent Isolation Directive**: Trace all candidates from `candidate_queue.json` and `candidate_intake_planner.json` before invoking `prepare_blinded_chain_verifier` for Step 2.3.

Bạn đang thực thi **Bước 2.2 (`deep_trace_chain_analyst`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`.

Bước này hợp nhất 5 yêu cầu kỹ thuật liên hoàn trong **một phiên đọc mã nguồn duy nhất** cho toàn bộ các ứng viên trong `candidate_queue.json`.

---

## 1. Năm Yêu cầu Kỹ thuật Bắt buộc (`ARCH-3G`, `DEPTH-4.2b`, `R2-P0-01`, `R3-A4`)

1. **Hạch toán 100% Ứng viên từ `candidate_queue.json` & Luật Fail-Closed cho `unexploitable_candidates[]` (`ARCH-3G`, `R2-P0-01`, `R3-A4`)**:
   - **Mọi `candidate_id`** trong `.localsec/runs/default/<repo_name>/candidate_queue.json` bắt buộc phải xuất hiện trong ít nhất một chuỗi thuộc **`chains[].candidate_ids`** (TUYỆT ĐỐI KHÔNG dùng tên cũ `source_candidate_ids`) **HOẶC** được giải trình trong **`unexploitable_candidates[]`**. Nghiêm cấm làm rơi ứng viên.
   - **Cấu trúc bắt buộc của `unexploitable_candidates[]` (`R3-A4`)**: Mỗi phần tử trong `unexploitable_candidates[]` **BẮT BUỘC** phải là một object `{"candidate_id": "...", "reason": "...", "evidence_ids": ["ev_..."]}` có `reason` ($\ge 10$ ký tự) và `evidence_ids` khác rỗng chứng minh kiểm soát ngăn chặn. Truyền chuỗi trần (`"cand_..."`) hoặc thiếu `evidence_ids` sẽ bị validator từ chối ngay lập tức.
2. **Phán quyết Chuỗi `chain_verdict` (`R2-P0-01`)**:
   - Sử dụng trường **`"chain_verdict"`** thuộc enum `"confirmed" | "code_supported" | "partially_confirmed" | "hypothesized" | "refuted"` (TUYỆT ĐỐI KHÔNG dùng tên cũ `"verification_status"`).
   - Khi `request_plan.execution_status` là `"not_executed"` hoặc `"request_plan_only"`, giá trị tối đa của `chain_verdict` là **`"code_supported"`** (`request_plan_is_not_execution`).
3. **Truy vết Bước nhảy Thực thi `hops[]` Kèm `hop_kind` & Mảng Bằng chứng Hai Đầu (`DEPTH-4.2b`, `R2-P0-01`)**:
   - Mỗi phần tử trong `hops[]` bắt buộc khai báo `hop_id`, `hop_kind` (`"in_process" | "http" | "grpc" | "message_queue" | "zmq_or_ipc" | "db" | "file_or_hardware"`), `file`, và `evidence_ids`.
   - Sử dụng mảng **`"caller_evidence_ids": ["ev_001"]`** và **`"callee_evidence_ids": ["ev_002"]`** (TUYỆT ĐỐI KHÔNG dùng tên số ít `caller_evidence_id` / `callee_evidence_id`). Với mọi bước nhảy xuyên dịch vụ (`http`, `grpc`, `message_queue`, `zmq_or_ipc`), bắt buộc có cả `caller_evidence_ids` lẫn `callee_evidence_ids` khác rỗng.
4. **Truy Nguyên nhân Gốc rễ (`root_cause` & `remediation`)**:
   - Khai báo rõ `root_cause` và hướng khắc phục triệt để `remediation`.
5. **Thiết kế Chuỗi Request Kiểm định (`request_plan`)**:
   - Khai báo `request_plan` với `"execution_status": "not_executed"`, `"discriminating_requests": [...]`, `"expected_safe_behavior": "..."`, và `"expected_vulnerable_behavior": "..."`.

---

## 2. Giao thức Thực thi CLI

```powershell
# 1. Xem lại bằng chứng đã thu thập hoặc đọc sâu thêm các dòng code dọc theo đường đi của chuỗi tấn công
python -m localsec.manual_session show_evidence <repo_name> <ev_id>
python -m localsec.manual_session read_file <repo_name> src/ocpp_controller.py 1 120 --skill deep_trace_chain_analyst

# 2. Lưu kết quả phân tích sâu (đối chiếu AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json)
python -m localsec.manual_session submit_skill <repo_name> deep_trace_chain_analyst .localsec/tmp/deep_trace_chain_analyst_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON Chuẩn (`AI-skills/schemas/v3/deep_trace_chain_analyst.schema.json`)

```json
{
  "status": "ok",
  "result": {
    "chains": [
      {
        "chain_id": "CHAIN-OCPP-01",
        "candidate_ids": [
          "cand_111122223333",
          "cand_8cd467be41f0",
          "cand_d432d621c21e",
          "cand_74ef70e3b401",
          "cand_563ca97c8fcc",
          "cand_39f27929e8c3",
          "cand_8629bd86b767",
          "cand_2cbb767b759c",
          "cand_214cf9681c33",
          "cand_5a9af194a4df",
          "cand_0140b9ecdd23"
        ],
        "title": "Cross-Session RemoteStartTransaction via Unchecked sessionId",
        "chain_verdict": "code_supported",
        "severity": "high",
        "execution_status": "not_executed",
        "hops": [
          {
            "hop_id": "HOP-01",
            "hop_kind": "in_process",
            "repo_name": "csms-service",
            "file": "src/ocpp_controller.py",
            "function_or_symbol": "remote_start_session",
            "line_start": 10,
            "line_end": 28,
            "caller_evidence_ids": [
              "ev_001"
            ],
            "callee_evidence_ids": [
              "ev_002"
            ],
            "evidence_ids": [
              "ev_001",
              "ev_002"
            ]
          },
          {
            "hop_id": "HOP-02",
            "hop_kind": "http",
            "repo_name": "csms-service",
            "file": "src/ocpp_controller.py",
            "function_or_symbol": "dispatch_ocpp_remote_start",
            "line_start": 30,
            "line_end": 52,
            "caller_evidence_ids": [
              "ev_001"
            ],
            "callee_evidence_ids": [
              "ev_002"
            ],
            "evidence_ids": [
              "ev_001",
              "ev_002"
            ]
          }
        ],
        "steps": [
          {
            "step_id": "STEP-01",
            "description": "Authenticated user calls POST /api/v1/sessions/{sessionId}/remote-start with another user's sessionId",
            "preconditions": [
              "Valid user JWT",
              "Know target station_id or sessionId"
            ],
            "state_before": "Target connector is idle or reserved by another user",
            "state_after": "CSMS dispatches RemoteStartTransaction frame without verifying session owner",
            "evidence_ids": [
              "ev_001"
            ]
          }
        ],
        "root_cause": "remote_start_session loads session by sessionId without checking session.user_id against the authenticated caller",
        "remediation": "Enforce ownership check comparing session.user_id with authenticated JWT subject before dispatching RemoteStartTransaction",
        "request_plan": {
          "execution_status": "not_executed",
          "discriminating_requests": [
            "POST /api/v1/sessions/10042/remote-start Authorization: Bearer <userB_jwt>"
          ],
          "expected_safe_behavior": "HTTP 403 Forbidden when session.user_id != current_user.id",
          "expected_vulnerable_behavior": "HTTP 200 OK and RemoteStartTransaction command dispatched to station"
        },
        "evidence_ids": [
          "ev_001",
          "ev_002"
        ]
      }
    ],
    "unexploitable_candidates": [],
    "summary": "Verified 1 code-supported exploit chain CHAIN-OCPP-01 covering all 11 Phase 1 candidates."
  }
}
```
