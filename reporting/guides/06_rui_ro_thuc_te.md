# 06 — Đánh giá rủi ro thực tế (Phase Risk)

## Vì sao có phase này

Phase bác bỏ (1–3) chứng minh **điểm yếu có thật** bằng yêu cầu nghiệp vụ, code path, phản chứng, kiểm toán bằng chứng. Bước 4.4 trả lời **nếu bị khai thác thì mất gì** (tác động nghiệp vụ). Cả hai đều là điều kiện cần, chưa phải rủi ro.

"Code chạy tới được" khác với "trong thực tế có người khai thác được". Rủi ro do việc **đạt được các điều kiện mà con đường khai thác đòi hỏi** quyết định.

Phase này **không dùng khung chấm điểm** (CVSS, OWASP Risk Rating, DREAD…). Model chỉ làm một việc: với mỗi mắt xích, trả lời bằng lời **có đạt được không, vì sao có, vì sao không**, kèm bằng chứng. Khả thi, rủi ro, ưu tiên, tổ hợp và kết quả của từng câu trả lời đều do script suy ra (mục 5).

## 1. Đơn vị đánh giá

Mỗi phát hiện `F-xx` sau bước 4.3 có một file `documents/_report/work/risk/F-xx.json` (mẫu: `AI-skills/reporting/templates/risk.example.json`).

Trần mỗi F:
- tối đa 4 đường;
- mỗi đường tối đa 6 mắt xích và 4 kiểm soát;
- mỗi mắt xích tối đa 5 người nắm giữ;
- tối đa 10 câu hỏi;
- file tối đa khoảng 26 KB, mỗi `why` tối đa 700 ký tự.

| Trường | Ý nghĩa |
|---|---|
| `attack_paths` | Các đường khai thác (quan hệ HOẶC), mỗi đường là một cách **thực tế khác nhau** |
| `actors_considered` | Đã xét đủ năm loại người khai thác chưa |
| `yields` | Khai thác thành công thì kẻ tấn công có thêm gì (để ghép chéo ở R.2) |
| `detection` | Nếu khai thác xảy ra thì có bị phát hiện không |
| `open_questions` | Câu hỏi cho người trả lời được; `affects` là một mắt xích (`P1.C1`) hoặc danh sách mắt xích cùng phụ thuộc câu hỏi đó |
| `likelihood`, `rationale`, `escalation_triggers` | Lập luận kết luận (R.3) |

### Mỗi đường khai thác

| Trường | Nội dung |
|---|---|
| `actor` | **Ai trong thực tế** làm được, mô tả cụ thể: "khách hàng đã đăng nhập app", "đối tác giữ credential tích hợp", "nhân viên vận hành có quyền vào cluster", "người ngoài trên Internet". Không dùng nhãn chung kiểu "attacker". |
| `entry` | Kẻ tấn công chạm vào đâu (`surface`), và chạm được không (`reachable`) |
| `preconditions` | Các mắt xích (quan hệ VÀ) phải có / đạt / biết / xảy ra |
| `blocking_controls` | Thứ có thể chặn ngoài đoạn code lỗi; xem mục 3 |
| `effort` | Thời gian, kỹ năng, công cụ, chi phí; lặp hay tự động hoá được không |
| `reaches_impact` | `co` nếu đường dẫn tới đúng hậu quả 4.4. `khong` thì kèm `outcome` (hậu quả khác). Một đường khác hậu quả mà khai thác được thì `check` buộc quay lại 4.4 bổ sung hậu quả đó (hoặc tách F). |

### Loại mắt xích (`kind`)

| `kind` | Hỏi gì |
|---|---|
| `cham_toi` | Chạm tới được không: mạng, route có đăng ký, cổng mở, có chạy ở production |
| `danh_tinh` | Phải là ai: ẩn danh, khách hàng, đối tác, quản trị. Trở thành người đó khó hay dễ? |
| `nam_giu` | Phải nắm giữ gì: credential, khoá, token, thiết bị, phiên. **Phải có `holders`** (mục 2a) |
| `biet` | Phải biết gì: ID của người khác, định dạng, địa chỉ |
| `trang_thai` | Hệ thống phải ở trạng thái nào; có thắng được cửa sổ thời gian (race) không |
| `nguoi_khac` | Cần người khác làm gì: nạn nhân bấm link, vận hành chạy job, đối tác gửi dữ liệu |
| `quy_mo` | Phải lặp được / làm ở quy mô đủ gây hậu quả không (DoS, gian lận khuyến mãi, dò ID) |
| `khac` | Khác |

## 2. Kết luận cho từng mắt xích: `co` / `khong` / `chua_ro`

| Kết luận | Khi nào | Bắt buộc |
|---|---|---|
| `co` | Có bằng chứng mắt xích này đạt được trong thực tế | `why` ≥30 ký tự nói **vì sao đạt được**; `evidence` |
| `khong` | Có bằng chứng mắt xích này **không** đạt được | `why` ≥30 ký tự nói **vì sao không**; `evidence` |
| `chua_ro` | Đã tìm mà không đủ thông tin để kết luận | `why` nói thiếu thông tin gì; `searched` (đã tìm ở đâu); có câu hỏi trỏ đúng mắt xích, đặt trong `open_questions` hoặc trong `unlocks` của một câu hỏi quyết định |

**Không có bằng chứng thì không được viết `co` hay `khong`.**

`check` từ chối kết luận `co`/`khong` nếu lý do có một trong các thứ sau:
- câu phỏng đoán: "chắc là", "thường thì", "thông thường", "có lẽ", "hẳn là", "nhiều khả năng", "dường như", "về lý thuyết", "có thể là"… Lý do được chuẩn hoá trước khi so, nên viết không dấu hay thêm dấu cách cũng bị bắt;
- ghi chú quá trình ("R.5: …");
- chuỗi trông như giá trị bí mật.

Cũng đừng viết `co` dựa vào nhận định chung mà bằng chứng không nói tới, ví dụ "VIN đoán được" khi không có bằng chứng về cấu trúc VIN.

`chua_ro` không phải lối thoát. `searched` phải nói đã tìm ở đâu, và người thách thức (R.4) kiểm xem câu trả lời có nằm sẵn ở chỗ chưa tìm không.

Bằng chứng hợp lệ:
- `ev_...` có trong kết quả đã khoá sổ;
- SID (`repo:ID`) chưa bị bác bỏ;
- `F-xx` khác, không phải chính F này;
- `fact:<id>` trong `documents/_report/runtime_facts.json`, có `answer` và `source`;
- **file** có thật trong `documents/`, `reports/`, `specs/`. Thư mục không được tính, và không được trích `documents/_report/**` (đó là kết quả của chính báo cáo này).

### 2a. Mắt xích `nam_giu`: liệt kê người nắm giữ (`holders`)

Câu hỏi thật của "phải nắm giữ X" là: **ai đang giữ X, và người của đường này lấy được X từ ai**. Mỗi holder là một người hoặc nơi đang giữ X theo tài liệu:

```json
"holders": [
  {"who": "Client của payment hub — người giữ theo thiết kế", "how": "Cấp khi tích hợp", "attainable": "chua_ro", "why": "…", "searched": ["…"]},
  {"who": "Client kiểm thử seed trong migration", "how": "Đọc repo seed SQL", "attainable": "co", "why": "…", "evidence": ["repo:TM-DB-01"]}
]
```

- Tra **bắt buộc** bằng `python3 AI-skills/reporting/report.py access --for F-xx`. Lệnh trả về phần chỉ mục truy cập liên quan (bí mật, client, scope, mạng, nguồn ID, chuỗi cung ứng) của mọi repo. Mỗi nguồn liên quan là một holder.
- `attainable` của holder: người của đường này lấy được X **từ nguồn này** không.
- Kết luận của mắt xích phải khớp holders: có một nguồn `co` thì `co`; mọi nguồn `khong` thì `khong`; còn lại `chua_ro`.
- `holders` chỉ dùng cho `nam_giu`. "Chỗ đứng trong cluster" là `cham_toi`, không phải `nam_giu`.

### 2b. Đã xét mọi loại người khai thác (`actors_considered`)

Ghi đủ năm loại. Giá trị là danh sách đường (`["P1", "P3"]`), hoặc lý do ≥20 ký tự vì sao loại đó **không có khả năng** khai thác. Lý do phải nói về khả năng, không phải động cơ ("đối tác không có động cơ" không phải lý do).

| Khoá | Loại người |
|---|---|
| `ngoai` | Người ngoài, không có tài khoản |
| `nguoi_dung` | Người dùng/khách hàng đã có tài khoản |
| `doi_tac` | Đối tác/bên tích hợp giữ credential hợp pháp — **vượt phạm vi của mình** (thao tác trên tài sản không thuộc họ) |
| `noi_bo` | Nhân viên, vận hành, CI/CD có quyền hợp pháp |
| `thanh_phan_bi_chiem` | Thành phần bị chiếm: pod, máy chủ, thư viện, tài khoản dịch vụ |

Một đường có thể thuộc nhiều loại người. Gộp các loại đi cùng mắt xích vào một đường để giữ dưới trần.

### 2c. Ví dụ mắt xích cho các loại điểm yếu khác nhau (gợi ý, không phải danh mục phải điền)

- **IDOR theo ID:**
  - `danh_tinh`: chỉ cần tài khoản khách hàng tự đăng ký được;
  - `biet`: ID của người khác tuần tự hay ngẫu nhiên, có API nào liệt kê không;
  - `quy_mo`: dò hàng loạt có bị giới hạn không.
- **Race condition:**
  - `trang_thai`: cửa sổ thời gian bao lâu, gửi song song được bao nhiêu request; có bằng chứng (khoá, transaction, ràng buộc DB) chặn không;
  - `quy_mo`: lặp được bao nhiêu lần.
- **Logic nghiệp vụ** (khuyến mãi, hoàn tiền):
  - `danh_tinh`: tài khoản thường;
  - `trang_thai`: đơn ở trạng thái nào;
  - `quy_mo`: lặp được không, có hạn mức hay đối soát (kiểm soát có thật) không.
- **DoS:**
  - `cham_toi`: endpoint công khai;
  - `quy_mo`: một request gây tốn bao nhiêu, có rate limit (kiểm soát có thật) không.
- **Lỗi phía app/client:**
  - `cham_toi`: app phát hành trên store có chứa đoạn lỗi không;
  - `nguoi_khac`: nạn nhân phải cài, bấm hay ở cùng mạng không.
- **Chuỗi cung ứng:**
  - `nam_giu`: ai giữ quyền ghi registry/pipeline/khoá ký;
  - `cham_toi`: artifact có được dùng ở production không.

## 3. Kiểm soát (`blocking_controls`): chỉ tính khi có bằng chứng tồn tại

| Trường | Nội dung |
|---|---|
| `control` | Kiểm soát gì: gateway, allowlist, NetworkPolicy, đối soát, quy trình duyệt… |
| `exists` | `co` khi có bằng chứng kiểm soát này **tồn tại** (ghi kèm `exists_evidence`). `chua_ro` khi chỉ là "có thể có". |
| `effective` | Chỉ ghi khi `exists: co`: chặn được không (`co` / `khong` / `chua_ro`), kèm lý do và bằng chứng như mắt xích |

Kiểm soát `exists: chua_ro` **không được tính** khi suy khả thi. Nó vẫn hiện trong tài liệu với nhãn "giả định — không tính" để người đọc biết. Muốn nó được tính thì phải có bằng chứng, hoặc một `fact:` từ người vận hành.

Lý do: nếu kiểm soát giả định treo được đường khai thác thì mọi điểm yếu sẽ thành "chưa rõ", và phase này không kết luận được gì.

## 4. Phát hiện (`detection`) và `yields`

- **`detection`**: nếu khai thác xảy ra thì có bị phát hiện không (đối soát, cảnh báo, log được đọc, khách hàng khiếu nại), bao lâu thì phát hiện. Cùng quy tắc `co` / `khong` / `chua_ro`.
- **`yields`**: khai thác thành công thì kẻ tấn công có thêm gì (bí mật, quyền, chỗ đứng, dữ liệu, ID). Đây là đầu vào của R.2. Không cho gì thêm thì ghi một câu như vậy.

## 5. Script suy ra những gì (model không gán)

- **Khả thi của một đường:**
  - `khong` khi có một mắt xích `khong`, hoặc một kiểm soát *có thật* chặn được;
  - `co` khi entry và mọi mắt xích đều `co`, và mọi kiểm soát có thật đều không chặn;
  - còn lại `chua_ro`.
- **Khả thi của một điểm yếu**: chỉ xét các đường `reaches_impact: co`; có một đường khả thi thì điểm yếu khả thi.
- **Rủi ro và ưu tiên:**

  | Khả thi | Rủi ro | Ưu tiên |
  |---|---|---|
  | Khai thác được | bằng mức tác động 4.4 | critical→P0, high→P1, medium→P2, low→P3 |
  | Không khai thác được | low | P3 |
  | Chưa rõ (*tạm tính*) | bằng mức tác động 4.4 | hạ một bậc so với dòng trên |

- **Tổ hợp**: chỉ tổ hợp **khai thác được** kéo ưu tiên của bên cho và bên nhận lên mức của tổ hợp. Tổ hợp còn chưa rõ không kéo ưu tiên (nó có điều kiện); nó hiện trong bảng tổ hợp, và điều kiện của nó thường nằm trong câu hỏi quyết định.
- **Ghi đè** (`risk_override`: `risk`, `reason` ≥80 ký tự, `evidence`):
  - chỉ dùng khi đã khai thác được, và chỉ hạ đúng một bậc khi hậu quả thực tế nhỏ hơn 4.4;
  - còn mắt xích chưa rõ thì không được ghi đè;
  - tác động sai thì sửa ở 4.4.

Tác động 4.4 là đầu vào và **không** chứa yếu tố khả năng khai thác (xem `04_tac_dong_nghiep_vu.md`), nên khả năng không bị trừ hai lần.

## 6. Lập luận kết luận (R.3)

- `likelihood.hardest`: mắt xích khó vượt nhất trên đường dễ nhất; có thể là một kiểm soát (`P1.K1`).
- `likelihood.why`: ai vượt được mắt xích đó, bằng cách nào, vì sao.
- `rationale`: vì sao ra kết quả script suy ra (đường nào khai thác được / không / chưa rõ, mắt xích quyết định).
- `escalation_triggers` (bắt buộc khi chưa khai thác được): mắt xích hay kiểm soát nào đổi thì rủi ro thành gì.

## 7. Ghép chéo (R.2)

Làm trên `python3 AI-skills/reporting/report.py risk-digest`. Ghép khi thứ F-B **cho** (`yields`) đúng là thứ mắt xích của F-A **cần**:
- ghi `enabled_by: ["F-B"]` vào mắt xích;
- thêm `{"id": "X1", "giver": "F-B", "target": "F-A", "link": "F-A.P1.C1", "how": "…"}` vào `work/risk/_combinations.json`.

Script suy ra khả thi, rủi ro và ưu tiên của tổ hợp từ đường chứa `link`. Mắt xích `co` chỉ dựa vào một F chưa khai thác được thì bị chặn.

Về `giver` và `enabled_by` bằng SID:
- `giver` có thể là một SID chưa thuộc F nào; khi đó có cảnh báo nhắc quay lại 4.3;
- SID đã thuộc F thì phải ghi F đó;
- SID đã bị loại trừ ở 4.3 thì phải xem lại việc loại trừ.

## 8. Câu hỏi quyết định

Khi một sự thật chưa biết quyết định mắt xích `chua_ro` của **≥2 F** (bảng scope của gateway, chính sách mạng của cluster, một bí mật còn ở production không), ghi nó một lần vào `key_questions`:

```json
{"id": "Q1", "question": "…", "to": "platform_devops", "unlocks": ["F-02.P1.C1", "F-05.P1.C2"]}
```

- Script tính sẵn kết quả của từng F nếu câu trả lời là "có" và nếu là "không". `render-risk` đưa bảng này lên đầu tài liệu; báo cáo tổng hợp đặt nó ở mục 3.2.
- Mắt xích đã nằm trong `unlocks` không cần câu hỏi riêng trong file F.
- `to` thuộc danh sách cố định: `platform_devops`, `cloud`, `security`, `team_dev`, `mobile`, `nghiep_vu`, `van_hanh`, `doi_tac`, `tai_chinh`, `phap_che`. Đội cụ thể ghi vào `to_detail`.

## 9. Thông tin runtime

Phần lớn câu trả lời cho "ai giữ, mở ra đâu, cấu hình gì ở production" không nằm trong mã. Khi người vận hành trả lời:
1. ghi vào `documents/_report/runtime_facts.json` (`id`, `question`, `answer`, `source`, `date`; mẫu `AI-skills/reporting/templates/runtime_facts.example.json`);
2. trích bằng `fact:<id>` và đổi kết luận của mắt xích;
3. chạy lại R.3–R.5 cho các F đó.

## 10. Thách thức độc lập (R.4)

Một context mới (subagent, hoặc cuộc hội thoại mới) rà **theo lô** khoảng 8 F, đọc nguồn và `access --for`, rồi thách thức **cả hai chiều**:
- **dễ hơn đã nói**: đường hay người nắm giữ bị bỏ sót; mắt xích `khong` mà vượt được; `chua_ro` mà câu trả lời đã có trong tài liệu; tổ hợp chưa xét;
- **khó hơn đã nói**: mắt xích `co` mà bằng chứng không đủ; kiểm soát có thật đang chặn mà bị bỏ qua.

Mỗi lô ghi `work/risk_review/<lô>.json`. Mọi mục, kể cả `ok`, phải có:
- `check`;
- `note` ≥20 ký tự;
- `basis`: phiên bản của file F, lấy từ `work/risk_review_basis.json` do `render-risk --draft` ghi.

Tác giả trả lời bằng "Đã sửa:" hoặc "Giữ nguyên:", kèm nội dung cụ thể và bằng chứng. File F đổi sau rà soát mà không có "Đã sửa:" giải thích thì `check` báo cũ: chạy lại R.4 cho F đó bằng một lô mới (không ghi đè lô cũ).
