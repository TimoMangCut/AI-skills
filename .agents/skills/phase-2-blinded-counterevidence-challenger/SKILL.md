---
name: phase-2-blinded-counterevidence-challenger
description: >-
  Phase 2.3 — Xác minh độc lập từng mắt xích chuỗi tấn công trong chế độ Mù Kết luận (Context-Blinded) và chủ động săn tìm bằng chứng phản bác hoặc kiểm soát bù trừ trong code (blinded_counterevidence_challenger). Kích hoạt ở Bước 2.3 hoặc khi gọi /phase-2-blinded-counterevidence-challenger.
---

# Phase 2.3: Context-Blinded Step Verifier & Counterevidence Challenger (`blinded_counterevidence_challenger`)

Bạn đang thực thi **Bước 2.3 (`blinded_counterevidence_challenger`)** trong **Phase 2: Deep Analysis & Falsification (LocalSec v3.0)**.
Trước khi nộp kết quả, hãy đối chiếu hợp đồng điều phối `AI-skills/contracts/v3-orchestration.json` và schema mục tiêu `AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json`.

Theo nguyên lý **Refute-First (Bác bỏ trước, khẳng định sau)**: một chuỗi tấn công chỉ đáng tin khi đã sống sót qua nỗ lực bác bỏ độc lập trong một phiên làm việc tách biệt (**Isolated Subagent / Fresh Context — `ARCH-3E`**).

---

## 1. Quy tắc Cô lập Ngữ cảnh & Danh sách 6 Vị trí Săn tìm Kiểm soát (`ARCH-3E`, `DEPTH-4.2d`)

1. **Bắt buộc Chạy Trong Subagent Độc lập / Fresh Context (`ARCH-3E`)**:
   - Đầu tiên, Orchestrator chạy `python -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>` để sinh gói `.localsec/tmp/blinded_chains_<repo_name>.json` đã cắt bỏ toàn bộ `chain_verdict`, `code_verified_severity`, `verification_status` và kết luận của Bước 2.2.
   - Bước 2.3 **BẮT BUỘC phải được thực thi trong một Subagent cô lập / Fresh Context** chỉ nhận duy nhất file `.localsec/tmp/blinded_chains_<repo_name>.json` (không được đọc file `.localsec/tmp/deep_trace_chain_analyst_<repo_name>.json`).
2. **Kiểm tra Bắt buộc Đủ 6 Vị trí Kiểm soát Bù trừ (`control_search_checklist` — `DEPTH-4.2d`)**:
   - Với mỗi chuỗi tấn công, bạn bắt buộc phải lục tìm bằng chứng phản bác trên **cả 6 vị trí kiểm soát cố định** dưới đây và ghi rõ `searched_paths` kèm `status` (`found_blocking_control` | `checked_not_blocking` | `not_applicable`) và `evidence_ids`:
     1. `global_middleware_or_filter` (Global Auth/Tenant Guard, Servlet Filter, Gin/NestJS/FastAPI Middleware)
     2. `gateway_or_ingress_config` (Kong/KrakenD/Envoy/Nginx/Ingress route auth & path rules)
     3. `service_or_domain_guard` (Kiểm tra quyền sở hữu hoặc trạng thái trong tầng Service/Domain)
     4. `orm_global_filter_or_scoped_query` (Global query filter theo `tenant_id` / `user_id` trong ORM/Repository)
     5. `db_constraint_rls_or_trigger` (Row-Level Security, Foreign Key/Unique Constraint, SQL Trigger)
     6. `upstream_caller_validation` (Kiểm tra tiền điều kiện ở dịch vụ gọi phía trước)
3. **Sổ cái Phản biện Thực nghiệm (`empirical_refutations[]`)**:
   - Ghi nhận mọi nỗ lực phản biện vào `empirical_refutations[]`: nêu rõ đã kiểm tra kiểm soát nào, ở file/dòng code nào (`ev_...` và `searched_paths`), và tại sao kiểm soát đó **chặn đứng** (`refuted_by_counterevidence`) hay **không chặn được** (` upheld_no_counterevidence`) chuỗi tấn công.

---

## 2. Giao thức Thực thi CLI

```bash
# 1. Tạo gói ngữ cảnh mù kết luận .localsec/tmp/blinded_chains_<repo_name>.json
python -m localsec.manual_session prepare_blinded_chain_verifier <repo_name>

# 2. (Trong Subagent cô lập) Đọc mã nguồn tại 6 vị trí control_search_checklist và exact_paths
python -m localsec.manual_session read_file <repo_name> <path> <start_line> <end_line> \
  --skill blinded_counterevidence_challenger \
  --allowed-paths <exact_paths>

# 3. Lưu kết quả phản biện đối kháng (đối chiếu AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json)
python -m localsec.manual_session submit_skill <repo_name> blinded_counterevidence_challenger .localsec/tmp/blinded_counterevidence_challenger_<repo_name>.json
```

---

## 3. Định dạng Đầu ra JSON (`AI-skills/schemas/v3/blinded_counterevidence_challenger.schema.json`)

```json
{
  "chain_challenges": [
    {
      "chain_id": "CHAIN-OCPP-STOP-01",
      "overall_challenge_outcome": "upheld_no_counterevidence",
      "control_search_checklist": {
        "global_middleware_or_filter": {
          "status": "checked_not_blocking",
          "searched_paths": ["src/middlewares/jwt-auth.guard.ts"],
          "evidence_ids": ["ev_..."],
          "notes": "JwtAuthGuard only verifies token signature, does not check session ownership"
        },
        "gateway_or_ingress_config": {
          "status": "checked_not_blocking",
          "searched_paths": ["deploy/kong.yml"],
          "evidence_ids": [],
          "notes": "Route passes sessionId path parameter directly to upstream"
        },
        "service_or_domain_guard": {
          "status": "checked_not_blocking",
          "searched_paths": ["src/services/charging.service.ts"],
          "evidence_ids": ["ev_..."],
          "notes": "stopSessionById loads session by id only"
        },
        "orm_global_filter_or_scoped_query": {
          "status": "checked_not_blocking",
          "searched_paths": ["src/repositories/session.repository.ts"],
          "evidence_ids": ["ev_..."],
          "notes": "No global tenant/user filter enabled on Session entity"
        },
        "db_constraint_rls_or_trigger": {
          "status": "checked_not_blocking",
          "searched_paths": ["src/migrations/001_init.sql"],
          "evidence_ids": [],
          "notes": "No RLS policy on charging_sessions table"
        },
        "upstream_caller_validation": {
          "status": "not_applicable",
          "searched_paths": ["src/controllers/charging.controller.ts"],
          "evidence_ids": ["ev_..."],
          "notes": "Directly exposed public HTTP endpoint"
        }
      },
      "step_verdicts": [
        {
          "step_id": "STEP-1",
          "verdict": "upheld",
          "evidence_ids": ["ev_..."],
          "notes": "Confirmed absence of userId ownership check before dispatching RemoteStopTransaction"
        }
      ],
      "empirical_refutations": [
        {
          "checked_control": "JwtAuthGuard & ChargingService.stopSessionById",
          "searched_paths": [
            "src/middlewares/jwt-auth.guard.ts",
            "src/services/charging.service.ts"
          ],
          "counterevidence_found": false,
          "evidence_ids": ["ev_..."],
          "conclusion": "No compensating ownership check exists in middleware, service, or repository layers."
        }
      ]
    }
  ]
}
```
