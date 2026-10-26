---
name: phase-4-business-impact
description: >-
  Phase 4.4 — Đánh giá tác động nghiệp vụ cho từng phát hiện F-xx (năng lực nghiệp vụ bị ảnh hưởng, kịch bản lạm dụng, hậu quả, khía cạnh, phạm vi lan xuyên cụm, cơ sở nhận định) (chỉ hậu quả, không tính khả năng khai thác — Phase Risk làm việc đó và suy ra mức rủi ro, ưu tiên cuối) — không bịa số tiền, không bịa điều luật.
---

# `phase-4-business-impact` (Phase 4.4)

Mỗi phát hiện phải trả lời: lỗi này làm hỏng việc kinh doanh nào, theo cách nào, nặng tới đâu, dựa trên cơ sở gì.

**Quyền truy cập:** theo mục "Quyền truy cập của Phase 4" trong `.agents/skills/phase-4-consolidated-report/SKILL.md`. Tóm tắt: đọc `documents/`, `specs/`, tài liệu nghiệp vụ, `AI-skills/reporting/`; chỉ ghi `documents/_report/work/`; không đọc mã nguồn.

## Prompt kích hoạt
```text
/phase-4-business-impact Viết business_impact cho từng F theo chuỗi điểm yếu → kịch bản lạm dụng → năng lực nghiệp vụ → hậu quả; ghi rõ cơ sở (BRD/BASV/recon/suy luận) và điều kiện; ghi risk = mức tác động và priority tạm theo bảng, giải thích mọi chỗ lệch so với nguồn.
```

## Điều kiện
`report.py check --stage findings` đạt.

## Làm
1. Đọc `AI-skills/reporting/guides/04_tac_dong_nghiep_vu.md` (bắt buộc).
2. Xác định nguồn ngữ cảnh nghiệp vụ trong `documents/_report/inputs/00_manifest.md`: tài liệu nghiệp vụ (`specs/`, thư mục tài liệu trong `documents/`), cột *Ý định* của `inputs/01_services.md`. Repo `inferred` hoặc không có BRD thì cơ sở là BASV/recon/suy luận, và phải ghi rõ như vậy.
3. Xử lý theo lô, mỗi lượt khoảng 5 F, theo thứ tự `catalog`. Với mỗi F:
   - đọc nguồn chính: trường *Tác động (nguồn)* trong `inputs/findings/<repo>.md`, `business_impact` của mismatch P2, `business_consequence` của chuỗi P3;
   - với service liên quan, đọc theo đoạn `documents/<repo>/basv/10_business_intent_model.md` (actors, workflows, invariants) và `01_repo_profile.md`;
   - dùng `work/architecture.json` (`domains`, `shared_components`) và `inputs/02_edges.md` để xác định `blast_radius`;
   - ghi `business_impact` (capability, scenario, consequence, dimensions, level, blast_radius, basis, conditions);
   - ghi `risk` = mức tác động, `priority` tạm theo bảng trong guide 04, `risk_rationale` nói vì sao mức tác động này. Không tính ai khai thác được hay khó dễ thế nào.
4. Chạy `python3 AI-skills/reporting/report.py check --stage impact` tới khi `ĐẠT`; đọc hết cảnh báo (nâng mức so với nguồn, ước lượng tiền, blast radius).
5. `risk`/`priority` ở bước này là **tạm**. Tác động nghiệp vụ là đầu ra chính của bước này; nó được giữ nguyên và là đầu vào của **Phase Risk** (`/phase-risk-assessment`). Phase Risk xét khả năng khai thác thực tế rồi chốt mức rủi ro và ưu tiên cuối.

## Không được
- Câu tác động chung chung, hoặc dùng lại một câu cho nhiều F.
- Con số tiền/khách hàng/giao dịch không có tài liệu nguồn; điều luật không được tài liệu dự án hoặc `SOUL.md` nêu.
- Viết hậu quả như đã xảy ra. Viết ở thể điều kiện và ghi `conditions`.
- Ghi `cross_domain`/`platform` khi không có cạnh hoặc thành phần dùng chung nối các cụm.
