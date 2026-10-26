"""Phase rủi ro (R): đánh giá rủi ro THỰC TẾ của các điểm yếu đã đứng vững sau khi bác bỏ.

Phase bác bỏ (1–3) trả lời "điểm yếu có thật không"; bước 4.4 trả lời "nếu bị khai thác thì mất gì" (tác động nghiệp vụ).
Phase này trả lời "trong thực tế ai khai thác được, phải vượt qua những gì, vượt được không, vì sao" — không dùng khung
chấm điểm. Model chỉ kết luận từng mắt xích `co`/`khong`/`chua_ro` kèm lý do và bằng chứng. Mọi thứ còn lại do script
suy ra (tất định), model không tự gán:

- khả thi của đường = mắt xích + kiểm soát CÓ BẰNG CHỨNG TỒN TẠI (kiểm soát giả định không chặn được gì);
- khả thi của điểm yếu = các đường dẫn tới đúng hậu quả của 4.4 (`reaches_impact`);
- rủi ro: khả thi → bằng mức tác động 4.4; không khả thi → thấp; chưa rõ → mức tác động nhưng *tạm tính*, ưu tiên hạ một bậc
  (việc cần làm là trả lời câu hỏi quyết định);
- ưu tiên = theo rủi ro, rồi được tổ hợp khai thác được (điểm yếu này mở mắt xích của điểm yếu kia) kéo lên;
- câu hỏi quyết định: script tính sẵn kết quả nếu câu trả lời là "có" hoặc "không".

Dữ liệu (model ghi):
- `work/risk/<F-xx>.json`         — đường khai thác, mắt xích, kiểm soát, người nắm giữ, phát hiện, câu hỏi
- `work/risk/_combinations.json`  — tổ hợp xuyên phát hiện + câu hỏi quyết định
- `work/risk_review.json` hoặc `work/risk_review/<lô>.json` — thách thức độc lập hai chiều, tác giả trả lời
- `runtime_facts.json` (trong documents/_report/) — sự thật runtime do người vận hành xác nhận, tham chiếu `fact:<id>`
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

VERDICTS = {"co": "Có", "khong": "Không", "chua_ro": "Chưa rõ"}
RISK_LEVELS = ("critical", "high", "medium", "low")
RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RISK_VI = {"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình", "low": "Thấp"}
PRIORITY_OF = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
EV_RE = re.compile(r"\bev_[0-9a-f]{18}\b")
SID_RE = re.compile(r"^[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-#\[\]]+$")
FRAMEWORK_RE = re.compile(r"\bCVSS\b|\bAV:[NALP]\b|\bOWASP Risk\b|\bDREAD\b", re.I)
PROCESS_NOTE_RE = re.compile(r"\bR\.[1-5]\s*:")
SECRET_VALUE_RE = re.compile(r"(?:secret|password|passwd|mật khẩu|api[_ ]?key|token)\s*[:=]\s*[\"']?[A-Za-z0-9+/_\-]{8,}", re.I)

# Loại mắt xích: buộc nghĩ theo từng câu hỏi thực tế. `nam_giu` phải liệt kê người/nơi đang giữ thứ đó.
KINDS = {
    "cham_toi": "Chạm tới được",
    "danh_tinh": "Phải là ai",
    "nam_giu": "Phải nắm giữ (credential, khoá, token, thiết bị)",
    "biet": "Phải biết (ID, định dạng, địa chỉ)",
    "trang_thai": "Hệ thống phải ở trạng thái / thắng được thời điểm",
    "nguoi_khac": "Cần người khác làm",
    "quy_mo": "Phải lặp được / làm ở quy mô đủ gây hậu quả",
    "khac": "Khác",
}
# Mọi loại người có thể khai thác; mỗi F phải nói đã xét từng loại (đường nào, hoặc vì sao không áp dụng).
ACTOR_TYPES = {
    "ngoai": "Người ngoài, không có tài khoản",
    "nguoi_dung": "Người dùng/khách hàng đã có tài khoản",
    "doi_tac": "Đối tác/bên tích hợp giữ credential hợp pháp",
    "noi_bo": "Nhân viên, vận hành, CI/CD có quyền hợp pháp",
    "thanh_phan_bi_chiem": "Thành phần bị chiếm (pod, máy chủ, thư viện, tài khoản dịch vụ)",
}
# Người nhận câu hỏi: danh sách cố định để gom câu hỏi theo người (ghi chi tiết đội cụ thể vào `to_detail`).
RECIPIENTS = {
    "platform_devops": "Platform/DevOps",
    "cloud": "Cloud/hạ tầng (AWS, mạng)",
    "security": "Security",
    "team_dev": "Đội phát triển service liên quan",
    "mobile": "Đội mobile/app",
    "nghiep_vu": "Nghiệp vụ / chủ sản phẩm",
    "van_hanh": "Vận hành",
    "doi_tac": "Đối tác / bên tích hợp",
    "tai_chinh": "Kế toán / tài chính",
    "phap_che": "Pháp chế / tuân thủ",
}
# Trần mỗi F: giữ tài liệu đọc được và đủ nhỏ cho model local. Gộp loại người chung đường; câu hỏi chung đưa lên câu hỏi quyết định.
CAPS = {"paths": 4, "conds": 6, "holders": 5, "controls": 4, "questions": 10, "why": 700, "bytes": 26000}

# Câu phỏng đoán: có những cụm này thì chưa đủ để kết luận Có/Không — phải là `chua_ro`. So khớp sau khi chuẩn hoá
# (NFC, chữ thường, gộp khoảng trắng) và cả dạng bỏ dấu.
HEDGES = ["chắc là", "thường thì", "thông thường", "có lẽ", "hẳn là", "nhiều khả năng", "dường như", "về lý thuyết",
          "giả định là", "chắc chắn sẽ", "có thể là", "có thể đã", "có vẻ", "nhiều phần"]

# Chỉ mục truy cập (bước collect) — nhóm theo thứ R.1 cần đi tìm.
ACCESS_GROUPS = [
    ("bi_mat", "Bí mật, credential, khoá lộ hoặc nằm sai chỗ",
     r"client[_ ]?secret|secret|password|mật khẩu|credential|keystore|private key|khoá riêng|khóa riêng|api[_ ]?key|hardcod|seed|plaintext|văn bản rõ|bundle"),
    ("scope", "Scope, quyền của client, allowlist, giới hạn tốc độ",
     r"client_scope|scope|white_?list|allowlist|api_policy|is_required_access_token|x-forwarded-for|rate limit|granted_ip"),
    ("mang", "Đường vào mạng, phơi ra ngoài, quyền hạ tầng",
     r"networkpolicy|network policy|3306|jump|bastion|0\.0\.0\.0|ssrf|security group|ingress|loadbalancer|load balancer|internet|system:masters|kubectl|\biam\b"),
    ("id_du_lieu", "Nguồn ID, liệt kê, dữ liệu do người dùng kiểm soát",
     r"idor|bola|tuần tự|sequential|enumerat|liệt kê|đoán được|predictable|user_id|vin\b|mass assignment"),
    ("chuoi_cung_ung", "Phụ thuộc, build, phát hành",
     r"dependency|phụ thuộc|supply chain|pipeline|jenkins|ci/cd|artifact|registry|signing|ký ứng dụng|npm|maven|pom\.xml"),
]
_SECRET_WORD_RE = re.compile(r"secret|password|passwd|mật khẩu|mat khau|token|api[_ ]?key|private|khoá|khóa|credential|pwd", re.I)


def _strip_accents(s: str) -> str:
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return s.replace("đ", "d").replace("Đ", "D")


def _norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFC", s).lower().split())


_HEDGE_PATTERNS = [(h, re.compile(r"(?<!\w)" + re.escape(_strip_accents(_norm(h))) + r"(?!\w)")) for h in HEDGES]


def hedge_in(text: str) -> str | None:
    t = _strip_accents(_norm(text))
    for h, rx in _HEDGE_PATTERNS:
        if rx.search(t):
            return h
    return None


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def collect_evidence_ids(docs: Path) -> list[str]:
    """Mọi `ev_...` trong kết quả đã khoá sổ (index theo repo, cấp hệ thống, Phase 3), trừ thư mục báo cáo."""
    ids: set[str] = set()
    for p in docs.rglob("*.json"):
        rel = p.relative_to(docs).parts
        if rel and rel[0].startswith("_report"):
            continue
        try:
            ids.update(EV_RE.findall(p.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    return sorted(ids)


def load_risk(work: Path) -> tuple[dict[str, Any], Any]:
    rdir = work / "risk"
    items: dict[str, Any] = {}
    if rdir.is_dir():
        for p in sorted(rdir.glob("F-*.json")):
            items[p.stem] = load_json(p, None)
    combos = load_json(rdir / "_combinations.json", None) if rdir.is_dir() else None
    return items, combos


def file_hashes(work: Path) -> dict[str, str]:
    rdir = work / "risk"
    out = {}
    for p in sorted(rdir.glob("*.json")) if rdir.is_dir() else []:
        out[p.stem] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    return out


def _s(v: Any) -> str:
    return v.strip() if isinstance(v, str) else ""


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def affects_of(q: Any) -> list[str]:
    """`affects` của một câu hỏi: một mắt xích (`P1.C1`) hoặc danh sách mắt xích cùng phụ thuộc câu hỏi đó."""
    a = _d(q).get("affects")
    return [str(x) for x in a] if isinstance(a, list) else ([str(a)] if a else [])


def _why_ok(text: Any, n: int) -> bool:
    return len(_s(text)) >= n


# ----------------------------------------------------------------------------- suy ra (tất định)

def control_counts(b: Any) -> bool:
    """Chỉ kiểm soát có bằng chứng tồn tại mới được tính khi suy khả thi."""
    return isinstance(b, dict) and b.get("exists") == "co"


def path_feasibility(path: Any, override: dict[str, str] | None = None) -> str:
    """`khong` nếu một mắt xích chắc chắn không vượt được hoặc một kiểm soát (có thật) chặn được;
    `co` nếu mọi mắt xích vượt được và mọi kiểm soát có thật đều không chặn; còn lại `chua_ro`.
    `override` (mắt xích → kết luận) dùng để mô phỏng câu trả lời của câu hỏi quyết định."""
    p = _d(path)
    pid = p.get("id")
    ov = override or {}
    entry = ov.get(f"{pid}.entry", _d(p.get("entry")).get("reachable"))
    conds = [ov.get(f"{pid}.{_d(c).get('id')}", _d(c).get("attainable")) for c in _l(p.get("preconditions"))]
    blocks = [ov.get(f"{pid}.K{i}", _d(b).get("effective")) for i, b in enumerate(_l(p.get("blocking_controls")), start=1) if control_counts(b)]
    if entry == "khong" or "khong" in conds or "co" in blocks:
        return "khong"
    if entry == "co" and conds and all(c == "co" for c in conds) and all(b == "khong" for b in blocks):
        return "co"
    return "chua_ro"


def _reaching(item: Any) -> list[dict[str, Any]]:
    paths = [p for p in _l(_d(item).get("attack_paths")) if isinstance(p, dict)]
    return [p for p in paths if p.get("reaches_impact", "co") != "khong"]


def finding_feasibility(item: Any, override: dict[str, str] | None = None) -> str:
    vals = [path_feasibility(p, override) for p in _reaching(item)]
    if "co" in vals:
        return "co"
    if "chua_ro" in vals:
        return "chua_ro"
    return "khong" if vals else "chua_ro"


def provisional(item: Any) -> bool:
    return finding_feasibility(item) == "chua_ro"


def _shift(priority: str) -> str:
    return {"P0": "P1", "P1": "P2", "P2": "P3", "P3": "P3"}[priority]


def derive(item: Any, impact_level: str | None, override: dict[str, str] | None = None) -> dict[str, Any]:
    """Rủi ro và ưu tiên suy ra từ khả thi + mức tác động 4.4 (chưa tính tổ hợp)."""
    impact = impact_level if impact_level in RISK_RANK else "medium"
    feas = finding_feasibility(item, override)
    ov = _d(_d(item).get("risk_override"))
    if feas == "co":
        risk, prio, state = impact, PRIORITY_OF[impact], "khai_thac_duoc"
    elif feas == "khong":
        risk, prio, state = "low", "P3", "khong_khai_thac_duoc"
    else:
        risk, prio, state = impact, _shift(PRIORITY_OF[impact]), "tam_tinh"
    if ov.get("risk") in RISK_RANK and override is None:
        risk = ov["risk"]
        prio = PRIORITY_OF[risk] if feas != "chua_ro" else _shift(PRIORITY_OF[risk])
    return {"feasibility": feas, "risk": risk, "priority": prio, "state": state, "impact": impact, "lifted_by": []}


def derive_all(items: dict[str, Any], impacts: dict[str, Any], combos: Any) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Rủi ro/ưu tiên cuối của mọi F + trạng thái tổ hợp. Tổ hợp khai thác được kéo ưu tiên của cả bên cho và bên nhận lên."""
    derived = {fid: derive(it, impacts.get(fid)) for fid, it in items.items() if isinstance(it, dict)}
    out_combos = []
    for c in _l(_d(combos).get("combinations")):
        if not isinstance(c, dict):
            continue
        giver, target, link = c.get("giver"), c.get("target"), str(c.get("link") or "")
        t_item = items.get(target)
        pid = link.split(".")[1] if link.count(".") >= 2 else ""
        path = next((p for p in _l(_d(t_item).get("attack_paths")) if isinstance(p, dict) and p.get("id") == pid), None)
        feas = path_feasibility(path) if path else "chua_ro"
        lvls = [impacts.get(x) for x in (giver, target) if impacts.get(x) in RISK_RANK]
        risk = min(lvls, key=lambda x: RISK_RANK[x]) if lvls else "medium"
        prio = PRIORITY_OF[risk] if feas == "co" else _shift(PRIORITY_OF[risk]) if feas == "chua_ro" else None
        rc = dict(c, feasible=feas, risk=risk if feas != "khong" else "low", priority=prio)
        out_combos.append(rc)
        if prio and feas == "co":
            # Chỉ tổ hợp khai thác được mới kéo ưu tiên. Tổ hợp còn chưa rõ là có điều kiện: nó hiện trong bảng tổ hợp và
            # câu hỏi quyết định, không kéo ưu tiên (nếu không, mọi F bị kéo lên cùng một mức và ưu tiên mất ý nghĩa).
            for x in (giver, target):
                if x in derived and PRIORITY_RANK[prio] < PRIORITY_RANK[derived[x]["priority"]]:
                    derived[x]["priority"] = prio
                    derived[x]["lifted_by"].append(c.get("id"))
    return derived, out_combos


def key_question_outcomes(q: dict[str, Any], items: dict[str, Any], impacts: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """Với mỗi F mà câu hỏi mở: rủi ro/ưu tiên nếu trả lời làm các mắt xích thành `co`, và nếu thành `khong`."""
    by_f: dict[str, list[str]] = {}
    for u in _l(q.get("unlocks")):
        parts = str(u).split(".", 1)
        if len(parts) == 2:
            by_f.setdefault(parts[0], []).append(parts[1])
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for fid, links in by_f.items():
        it = items.get(fid)
        if not isinstance(it, dict):
            continue
        out[fid] = {ans: derive(it, impacts.get(fid), {lk: ans for lk in links}) for ans in ("co", "khong")}
    return out


# ----------------------------------------------------------------------------- kiểm tra

class RiskContext:
    def __init__(self, root: Path, out: Path, reg: dict[str, Any], fids: set[str], ev_ids: set[str],
                 sid_to_f: dict[str, str] | None = None, excluded: dict[str, str] | None = None,
                 key_unlocks: set[str] | None = None, feas: dict[str, str] | None = None) -> None:
        self.root, self.out, self.reg, self.fids, self.ev_ids = root, out, reg, fids, ev_ids
        self.sid_to_f = sid_to_f or {}
        self.excluded = excluded or {}
        self.key_unlocks = key_unlocks or set()
        self.feas = feas or {}
        facts = load_json(out / "runtime_facts.json", {})
        self.facts = {str(f.get("id")): f for f in (facts.get("facts", []) if isinstance(facts, dict) else [])
                      if isinstance(f, dict) and _why_ok(f.get("answer"), 5) and _why_ok(f.get("source"), 3)}

    def ref_problem(self, ref: Any, fid: str) -> str | None:
        """None nếu `ref` là bằng chứng hợp lệ; ngược lại là lý do bị từ chối."""
        if not isinstance(ref, str) or not ref.strip():
            return "không phải chuỗi"
        ref = ref.strip().strip("`")
        if EV_RE.fullmatch(ref):
            return None if ref in self.ev_ids else "ev_ không có trong kết quả đã khoá sổ"
        if re.fullmatch(r"F-\d{2,}", ref):
            if ref == fid:
                return "tự trích chính F này"
            return None if ref in self.fids else "F không tồn tại"
        if ref.startswith("fact:"):
            return None if ref[5:] in self.facts else "fact không có trong runtime_facts.json (cần `answer` và `source`)"
        if re.match(r"^(documents|reports|reviews|specs|independent-review)/", ref):
            path = ref.split("#", 1)[0]
            if path.startswith("documents/_report"):
                return "không trích kết quả của chính báo cáo này"
            return None if (self.root / path).is_file() else "không phải file có thật"
        if ref in self.reg:
            if _d(self.reg[ref]).get("disposition") == "bac_bo":
                return "mục đã bị bác bỏ"
            return None
        return "không phải ev_, SID, F-xx, fact:<id> hay file có thật"


def check_item(fid: str, item: Any, ctx: RiskContext, impact_level: str | None = None, phase: str = "full") -> tuple[list[str], list[str]]:
    """`phase="paths"`: chỉ phần của R.1 (đường, mắt xích, người nắm giữ, phát hiện, câu hỏi). `full`: thêm phần kết luận R.3."""
    errors: list[str] = []
    warnings: list[str] = []
    where = f"risk/{fid}.json"
    if not isinstance(item, dict):
        return [f"{where}: JSON hỏng hoặc không phải object."], []
    if item.get("finding") != fid:
        errors.append(f"{where}: `finding` phải là {fid}.")
    size = len(json.dumps(item, ensure_ascii=False, indent=2).encode("utf-8"))
    if size > CAPS["bytes"]:
        errors.append(f"{where}: {size // 1000} KB, vượt trần {CAPS['bytes'] // 1000} KB — gộp đường cùng mắt xích, rút gọn lý do, "
                      "đưa câu hỏi chung lên câu hỏi quyết định (`_combinations.json`).")
    questions = item.get("open_questions") if isinstance(item.get("open_questions"), list) else []
    if not isinstance(item.get("open_questions", []), list):
        errors.append(f"{where}: `open_questions` phải là danh sách.")
    if len(questions) > CAPS["questions"]:
        errors.append(f"{where}: {len(questions)} câu hỏi, vượt trần {CAPS['questions']} — câu hỏi chung cho nhiều mắt xích/F đưa lên `key_questions`.")
    affected = {a for q in questions for a in affects_of(q)}
    for q in questions:
        q = _d(q)
        if not _why_ok(q.get("question"), 15) or not affects_of(q):
            errors.append(f"{where}: mỗi `open_questions` cần `question` (≥15 ký tự) và `affects` (mắt xích nào).")
        if q.get("to") not in RECIPIENTS:
            errors.append(f"{where}: câu hỏi \"{_s(q.get('question'))[:50]}…\": `to` phải là một trong {', '.join(RECIPIENTS)} "
                          "(ghi đội cụ thể vào `to_detail`).")

    def text_rules(obj: dict[str, Any], label: str) -> None:
        why = obj.get("why")
        if why is not None and not isinstance(why, str):
            errors.append(f"{where} {label}: `why` phải là chuỗi.")
        w = _s(why)
        if len(w) > CAPS["why"]:
            errors.append(f"{where} {label}: `why` dài {len(w)} ký tự (trần {CAPS['why']}) — nói điều quyết định, chi tiết để ở nguồn.")
        if PROCESS_NOTE_RE.search(w):
            errors.append(f"{where} {label}: không ghi chú quá trình (\"R.x: …\") trong `why` — viết lại kết luận hiện tại.")
        if SECRET_VALUE_RE.search(w):
            errors.append(f"{where} {label}: `why` có vẻ chứa giá trị bí mật — không chép giá trị, chỉ nói nó nằm ở đâu.")

    def verdict(obj: Any, key: str, label: str, ident: str) -> None:
        if not isinstance(obj, dict):
            errors.append(f"{where} {label}: phải là object.")
            return
        v = obj.get(key)
        if v not in VERDICTS:
            errors.append(f"{where} {label}: `{key}` phải là co|khong|chua_ro.")
            return
        text_rules(obj, label)
        refs = obj.get("evidence") if isinstance(obj.get("evidence"), list) else []
        if not isinstance(obj.get("evidence", []), list):
            errors.append(f"{where} {label}: `evidence` phải là danh sách.")
        for r in refs:
            prob = ctx.ref_problem(r, fid)
            if prob:
                errors.append(f"{where} {label}: bằng chứng `{r}` bị từ chối — {prob}.")
        if v in {"co", "khong"}:
            if not _why_ok(obj.get("why"), 30):
                errors.append(f"{where} {label}: kết luận `{v}` cần `why` ≥30 ký tự nói cụ thể vì sao {'được' if v == 'co' else 'không được'}.")
            if not refs:
                errors.append(f"{where} {label}: kết luận `{v}` phải có `evidence`; không có bằng chứng thì là `chua_ro`.")
            h = hedge_in(_s(obj.get("why")))
            if h:
                errors.append(f"{where} {label}: kết luận `{v}` nhưng lý do dùng câu phỏng đoán \"{h}\" — "
                              "chưa chắc thì ghi `chua_ro` kèm câu hỏi, chắc thì viết lại bằng bằng chứng.")
        else:
            if not _why_ok(obj.get("why"), 20):
                errors.append(f"{where} {label}: `chua_ro` cần `why` nói còn thiếu thông tin gì.")
            searched = [x for x in _l(obj.get("searched")) if _why_ok(x, 5)]
            if not searched:
                errors.append(f"{where} {label}: `chua_ro` phải ghi `searched` — đã tìm ở đâu (file, SID, chỉ mục) mà không thấy câu trả lời.")
            if ident not in affected and f"{fid}.{ident}" not in ctx.key_unlocks:
                errors.append(f"{where} {label}: `chua_ro` phải có câu hỏi: một `open_questions` với `affects` = `{ident}`, "
                              f"hoặc `{fid}.{ident}` nằm trong `unlocks` của một câu hỏi quyết định.")

    raw_paths = item.get("attack_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        errors.append(f"{where}: cần `attack_paths` là danh sách ít nhất một đường khai thác thực tế.")
        raw_paths = []
    if len(raw_paths) > CAPS["paths"]:
        errors.append(f"{where}: {len(raw_paths)} đường, vượt trần {CAPS['paths']} — gộp các loại người đi cùng một đường "
                      "(actors_considered cho phép một đường thuộc nhiều loại), bỏ biến thể chỉ khác câu chữ.")
    paths = [p for p in raw_paths if isinstance(p, dict)]
    if len(paths) != len(raw_paths):
        errors.append(f"{where}: mỗi phần tử của `attack_paths` phải là object.")
    ids_seen: set[str] = set()
    for p in paths:
        pid = str(p.get("id") or "?")
        lab = f"đường {pid}"
        if pid in ids_seen or not re.fullmatch(r"P\d+", pid):
            errors.append(f"{where}: id đường khai thác phải dạng P1, P2… và không trùng.")
        ids_seen.add(pid)
        if not _why_ok(p.get("actor"), 20):
            errors.append(f"{where} {lab}: `actor` (≥20 ký tự) nói cụ thể AI trong thực tế có thể làm, không phải nhãn chung.")
        if not _why_ok(p.get("summary"), 20):
            errors.append(f"{where} {lab}: thiếu `summary`.")
        ri = p.get("reaches_impact")
        if ri not in {"co", "khong"}:
            errors.append(f"{where} {lab}: `reaches_impact` phải là co (đường này dẫn tới đúng hậu quả của 4.4) | khong.")
        elif ri == "khong" and not _why_ok(p.get("outcome"), 30):
            errors.append(f"{where} {lab}: đường không dẫn tới hậu quả 4.4 thì ghi `outcome` (≥30 ký tự) — nó dẫn tới hậu quả gì.")
        entry = p.get("entry")
        if not isinstance(entry, dict) or not _s(entry.get("surface")):
            errors.append(f"{where} {lab}: `entry` cần `surface` — kẻ tấn công chạm vào đâu.")
        verdict(entry, "reachable", f"{lab} entry", f"{pid}.entry")
        conds = p.get("preconditions") if isinstance(p.get("preconditions"), list) else []
        if not conds:
            errors.append(f"{where} {lab}: cần ít nhất một điều kiện (kể cả 'không cần xác thực' — kết luận `co` và vì sao).")
        if len(conds) > CAPS["conds"]:
            errors.append(f"{where} {lab}: {len(conds)} mắt xích, vượt trần {CAPS['conds']} — gộp mắt xích cùng một câu hỏi.")
        cids: set[str] = set()
        for c in conds:
            if not isinstance(c, dict):
                errors.append(f"{where} {lab}: mỗi điều kiện phải là object.")
                continue
            cid = str(c.get("id") or "?")
            if cid in cids or not re.fullmatch(r"C\d+", cid):
                errors.append(f"{where} {lab}: id điều kiện phải dạng C1, C2… và không trùng trong đường.")
            cids.add(cid)
            if not _why_ok(c.get("need"), 10):
                errors.append(f"{where} {lab}.{cid}: `need` — phải đạt/có/biết điều gì.")
            verdict(c, "attainable", f"{lab}.{cid}", f"{pid}.{cid}")
            kind = c.get("kind")
            if kind not in KINDS:
                errors.append(f"{where} {lab}.{cid}: `kind` phải là {'|'.join(KINDS)} (mắt xích này hỏi điều gì).")
            holders = c.get("holders")
            if holders is not None and kind != "nam_giu":
                errors.append(f"{where} {lab}.{cid}: `holders` chỉ dùng cho mắt xích `nam_giu`.")
            if kind == "nam_giu":
                holders = holders if isinstance(holders, list) else []
                if not holders:
                    errors.append(f"{where} {lab}.{cid}: mắt xích `nam_giu` phải có `holders` — liệt kê người/nơi đang giữ thứ đó "
                                  "theo tài liệu (app, seed SQL, bundle, đối tác, vận hành, cấu hình…), tra `report.py access --for {fid}`.")
                if len(holders) > CAPS["holders"]:
                    errors.append(f"{where} {lab}.{cid}: {len(holders)} người nắm giữ, vượt trần {CAPS['holders']} — gộp nguồn cùng loại.")
                for j, h in enumerate(holders, start=1):
                    if not isinstance(h, dict) or not _why_ok(h.get("who"), 5):
                        errors.append(f"{where} {lab}.{cid} H{j}: cần object có `who` (ai/nơi nào đang giữ).")
                        continue
                    verdict(h, "attainable", f"{lab}.{cid} H{j}", f"{pid}.{cid}")
                derived_h = holders_verdict(holders)
                if holders and c.get("attainable") in VERDICTS and c.get("attainable") != derived_h:
                    errors.append(f"{where} {lab}.{cid}: kết luận `{c.get('attainable')}` không khớp danh sách người nắm giữ (suy ra `{derived_h}`: "
                                  "có một nguồn lấy được → co; mọi nguồn đều không → khong; còn lại chua_ro).")
            enabled = c.get("enabled_by") if isinstance(c.get("enabled_by"), list) else []
            for e in enabled:
                if re.fullmatch(r"F-\d{2,}", str(e)):
                    if e not in ctx.fids or e == fid:
                        errors.append(f"{where} {lab}.{cid}: `enabled_by` `{e}` phải là F-xx khác tồn tại.")
                elif e in ctx.reg:
                    if e in ctx.sid_to_f:
                        owner = ctx.sid_to_f[e]
                        errors.append(f"{where} {lab}.{cid}: `enabled_by` `{e}` " + (f"là nguồn của chính {fid} — một điểm yếu không tự mở mắt xích của nó."
                                      if owner == fid else f"đã thuộc {owner} — ghi {owner}."))
                    elif e in ctx.excluded:
                        errors.append(f"{where} {lab}.{cid}: `enabled_by` `{e}` bị loại trừ ở 4.3 ({ctx.excluded[e]}) nhưng lại mở mắt xích của {fid} — "
                                      "xem lại việc loại trừ (gom vào F) rồi ghi F đó.")
                    else:
                        warnings.append(f"{where} {lab}.{cid}: `enabled_by` `{e}` chưa thuộc F nào — mục mở mắt xích của phát hiện khác thì nên gom thành F ở 4.3.")
                else:
                    errors.append(f"{where} {lab}.{cid}: `enabled_by` `{e}` phải là F-xx hoặc SID có thật.")
            # Mắt xích `co` chỉ dựa vào một F khác thì F đó phải khai thác được.
            f_en = [e for e in enabled if re.fullmatch(r"F-\d{2,}", str(e)) and e in ctx.fids and e != fid]
            if c.get("attainable") == "co" and f_en and ctx.feas:
                refs = [r for r in _l(c.get("evidence")) if isinstance(r, str)]
                independent = [r for r in refs if not re.fullmatch(r"F-\d{2,}", r.strip())]
                if not independent and all(ctx.feas.get(e) != "co" for e in f_en):
                    errors.append(f"{where} {lab}.{cid}: kết luận `co` chỉ dựa vào {', '.join(f_en)} mà các F đó chưa khai thác được "
                                  f"({', '.join(ctx.feas.get(e, '?') for e in f_en)}) — ghi `chua_ro`/`khong` cho khớp, hoặc dẫn bằng chứng độc lập.")
        controls = p.get("blocking_controls") if isinstance(p.get("blocking_controls"), list) else []
        if len(controls) > CAPS["controls"]:
            errors.append(f"{where} {lab}: {len(controls)} kiểm soát, vượt trần {CAPS['controls']}.")
        for i, b in enumerate(controls, start=1):
            if not isinstance(b, dict) or not _why_ok(b.get("control"), 10):
                errors.append(f"{where} {lab}: kiểm soát #{i} cần object có `control`.")
                continue
            ex = b.get("exists")
            if ex not in VERDICTS:
                errors.append(f"{where} {lab} K{i}: `exists` phải là co (có bằng chứng kiểm soát này tồn tại) | chua_ro | khong.")
            elif ex == "co":
                ev = [r for r in _l(b.get("exists_evidence")) if isinstance(r, str)]
                if not ev:
                    errors.append(f"{where} {lab} K{i}: `exists: co` cần `exists_evidence` — bằng chứng kiểm soát này có thật (cấu hình, mã, fact).")
                for r in ev:
                    prob = ctx.ref_problem(r, fid)
                    if prob:
                        errors.append(f"{where} {lab} K{i}: bằng chứng tồn tại `{r}` bị từ chối — {prob}.")
                verdict(b, "effective", f"{lab} K{i}", f"{pid}.K{i}")
            else:
                if b.get("effective") == "co":
                    errors.append(f"{where} {lab} K{i}: kiểm soát chưa có bằng chứng tồn tại thì không thể ghi `effective: co` — nó không chặn được gì.")
                text_rules(b, f"{lab} K{i}")
        if not _why_ok(p.get("effort"), 15):
            warnings.append(f"{where} {lab}: nên ghi `effort` — thực tế cần bỏ ra gì (thời gian, kỹ năng, công cụ, chi phí, lặp được không).")

    ac = item.get("actors_considered")
    if not isinstance(ac, dict):
        errors.append(f"{where}: thiếu `actors_considered` — với từng loại {', '.join(ACTOR_TYPES)}: đường nào, hoặc vì sao không áp dụng.")
    else:
        used: set[str] = set()
        for k, label in ACTOR_TYPES.items():
            v = ac.get(k)
            if isinstance(v, list) and v:
                bad = [x for x in v if x not in ids_seen]
                if bad:
                    errors.append(f"{where}: `actors_considered.{k}` trỏ tới đường không tồn tại {bad}.")
                used |= {x for x in v if isinstance(x, str)}
            elif not _why_ok(v, 20):
                errors.append(f"{where}: `actors_considered.{k}` ({label}) — ghi danh sách đường (P1…) hoặc lý do ≥20 ký tự vì sao loại người này "
                              "không áp dụng (lý do về khả năng, không phải về động cơ).")
        for pid in sorted(ids_seen - used):
            warnings.append(f"{where}: đường {pid} chưa được gắn vào loại người nào trong `actors_considered`.")

    if not isinstance(item.get("yields"), list) or not [y for y in item["yields"] if _why_ok(y, 5)]:
        errors.append(f"{where}: cần `yields` — khai thác thành công thì kẻ tấn công có thêm gì (bí mật, quyền, chỗ đứng, dữ liệu, ID…) "
                      "để R.2 ghép với mắt xích của F khác. Không cho gì thêm thì ghi rõ một câu như vậy.")

    det = item.get("detection")
    if isinstance(det, dict):
        verdict(det, "would_be_noticed", "phát hiện", "detection")
    else:
        errors.append(f"{where}: thiếu `detection` (object) — khai thác có bị phát hiện/đối soát ra không, vì sao.")

    if phase == "full":
        lk = item.get("likelihood")
        if not isinstance(lk, dict):
            errors.append(f"{where}: thiếu `likelihood` (object có `hardest` và `why`).")
            lk = {}
        if "level" in lk:
            warnings.append(f"{where}: `likelihood.level` không còn dùng — mức rủi ro do engine suy ra từ khả thi và tác động.")
        if not _why_ok(lk.get("why"), 40):
            errors.append(f"{where}: `likelihood.why` (≥40 ký tự) — lập luận bằng lời: mắt xích khó nhất là gì, ai vượt được, vì sao.")
        hardest = str(lk.get("hardest") or "")
        known = link_ids("", item)
        if f".{hardest}" not in known:
            errors.append(f"{where}: `likelihood.hardest` phải trỏ tới một mắt xích có thật (ví dụ `P1.C2`, `P1.entry`, hoặc kiểm soát `P1.K1`).")
        exp = derive(item, impact_level)
        for k in ("risk", "priority"):
            if k in item and item.get(k) != exp[k]:
                errors.append(f"{where}: `{k}` = {item.get(k)!r} nhưng engine suy ra {exp[k]!r} ({exp['state']}, tác động 4.4 {exp['impact']}) — "
                              "xoá trường này (engine tự điền) hoặc dùng `risk_override`.")
        ov = item.get("risk_override")
        if ov is not None:
            ov = _d(ov)
            base = derive({k: v for k, v in item.items() if k != "risk_override"}, impact_level)
            if ov.get("risk") not in RISK_RANK or not _why_ok(ov.get("reason"), 80) or not _l(ov.get("evidence")):
                errors.append(f"{where}: `risk_override` cần `risk`, `reason` (≥80 ký tự) và `evidence`.")
            elif base["feasibility"] == "chua_ro":
                errors.append(f"{where}: còn mắt xích chưa rõ thì không ghi đè rủi ro — trả lời câu hỏi trước.")
            elif base["feasibility"] == "co" and RISK_RANK[ov["risk"]] - RISK_RANK[base["risk"]] not in (1,):
                errors.append(f"{where}: khai thác được thì chỉ được hạ đúng một bậc so với tác động ({base['risk']}) và phải nói vì sao hậu quả thực tế nhỏ hơn 4.4.")
            for r in _l(ov.get("evidence")):
                prob = ctx.ref_problem(r, fid)
                if prob:
                    errors.append(f"{where}: bằng chứng ghi đè `{r}` bị từ chối — {prob}.")
        if not _why_ok(item.get("rationale"), 60):
            errors.append(f"{where}: `rationale` (≥60 ký tự) — vì sao mức này: đường nào khai thác được/không/chưa rõ, mắt xích quyết định.")
        if PROCESS_NOTE_RE.search(_s(item.get("rationale"))):
            errors.append(f"{where}: `rationale` không ghi chú quá trình (\"R.x: …\").")
        feas = finding_feasibility(item)
        trig = item.get("escalation_triggers")
        if feas != "co" and (not isinstance(trig, list) or not [t for t in trig if _why_ok(t, 20)] or any(not _why_ok(t, 20) for t in trig)):
            errors.append(f"{where}: cần `escalation_triggers` (mỗi mục ≥20 ký tự) — mắt xích/kiểm soát nào đổi thì rủi ro thành gì.")
        for p in paths:
            if p.get("reaches_impact") == "khong" and path_feasibility(p) == "co":
                errors.append(f"{where} đường {p.get('id')}: khai thác được nhưng dẫn tới hậu quả khác 4.4 ({_s(p.get('outcome'))[:60]}…) — "
                              "đưa hậu quả này vào tác động của 4.4 (hoặc tách F) rồi đổi `reaches_impact`.")
    if "business_impact" in item:
        warnings.append(f"{where}: tác động nghiệp vụ thuộc bước 4.4 (consolidation.json), không ghi trong file rủi ro — phần này bị bỏ qua.")
    if FRAMEWORK_RE.search(json.dumps(item, ensure_ascii=False)):
        errors.append(f"{where}: không dùng khung chấm điểm (CVSS/OWASP Risk/DREAD) — lập luận bằng điều kiện thực tế.")
    return errors, warnings


def holders_verdict(holders: list[Any]) -> str:
    vals = [_d(h).get("attainable") for h in holders]
    if "co" in vals:
        return "co"
    if vals and all(v == "khong" for v in vals):
        return "khong"
    return "chua_ro"


def link_ids(fid: str, item: Any) -> set[str]:
    """Mọi mắt xích có thể trỏ tới của một F: F-xx.P1.entry, F-xx.P1.C2, F-xx.P1.K1, F-xx.detection."""
    if not isinstance(item, dict):
        return set()
    out = {f"{fid}.detection"}
    for p in _l(item.get("attack_paths")):
        if not isinstance(p, dict):
            continue
        pid = p.get("id")
        out.add(f"{fid}.{pid}.entry")
        out |= {f"{fid}.{pid}.{_d(c).get('id')}" for c in _l(p.get("preconditions"))}
        out |= {f"{fid}.{pid}.K{i}" for i, _ in enumerate(_l(p.get("blocking_controls")), start=1)}
    return out


def _link_verdict(item: Any, link: str) -> str | None:
    """Kết luận hiện tại của một mắt xích (`P1.C2`, `P1.entry`, `P1.K1`, `detection`)."""
    it = _d(item)
    if link == "detection":
        return _d(it.get("detection")).get("would_be_noticed")
    parts = link.split(".")
    if len(parts) != 2:
        return None
    p = next((x for x in _l(it.get("attack_paths")) if _d(x).get("id") == parts[0]), None)
    if p is None:
        return None
    if parts[1] == "entry":
        return _d(p.get("entry")).get("reachable")
    if parts[1].startswith("K") and parts[1][1:].isdigit():
        ks = _l(p.get("blocking_controls"))
        i = int(parts[1][1:])
        return _d(ks[i - 1]).get("effective") if 0 < i <= len(ks) else None
    c = next((x for x in _l(p.get("preconditions")) if _d(x).get("id") == parts[1]), None)
    return _d(c).get("attainable") if c is not None else None


def check_combinations(combos: Any, items: dict[str, Any], ctx: RiskContext, impacts: dict[str, Any] | None = None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    impacts = impacts or {}
    if not isinstance(combos, dict) or not isinstance(combos.get("combinations"), list) or not _why_ok(combos.get("method_note"), 20):
        return ["risk/_combinations.json: cần {\"method_note\": \"đã xét những cặp nào, vì sao\", \"combinations\": [...], \"key_questions\": [...]} "
                "(danh sách có thể rỗng)."], []
    _, derived_combos = derive_all(items, impacts, combos)
    by_id = {c.get("id"): c for c in derived_combos}
    seen_ids: set[str] = set()
    for c in combos["combinations"]:
        if not isinstance(c, dict):
            errors.append("_combinations: mỗi tổ hợp phải là object.")
            continue
        cid = str(c.get("id") or "?")
        if cid in seen_ids or not re.fullmatch(r"X\d+", cid):
            errors.append(f"_combinations {cid}: id phải dạng X1, X2… và không trùng.")
        seen_ids.add(cid)
        giver, target, link = c.get("giver"), c.get("target"), str(c.get("link") or "")
        if target not in ctx.fids or target not in items:
            errors.append(f"_combinations {cid}: `target` phải là F-xx có file rủi ro.")
            continue
        if giver == target:
            errors.append(f"_combinations {cid}: `giver` và `target` phải khác nhau.")
        elif not (giver in ctx.fids or giver in ctx.reg):
            errors.append(f"_combinations {cid}: `giver` phải là F-xx hoặc SID có thật.")
        elif giver in ctx.reg and giver not in ctx.fids:
            warnings.append(f"_combinations {cid}: bên cho là SID `{giver}` chưa thuộc F nào — nếu đúng là nó mở mắt xích thì gom thành F ở 4.3.")
        if not link.startswith(f"{target}.") or link not in link_ids(target, items[target]):
            errors.append(f"_combinations {cid}: `link` phải là mắt xích có thật của {target} (dạng `{target}.P1.C2`).")
        else:
            local = link.split(".", 1)[1]
            p = next((x for x in _l(_d(items[target]).get("attack_paths")) if _d(x).get("id") == local.split(".")[0]), {})
            cond = next((x for x in _l(_d(p).get("preconditions")) if _d(x).get("id") == local.split(".")[1]), None)
            if cond is not None and giver not in _l(_d(cond).get("enabled_by")):
                errors.append(f"_combinations {cid}: mắt xích `{link}` chưa ghi `enabled_by: [\"{giver}\"]` — tổ hợp và mắt xích phải khớp nhau.")
        if not _why_ok(c.get("how"), 40):
            errors.append(f"_combinations {cid}: `how` (≥40 ký tự) — bên cho đưa cho kẻ tấn công cái gì, đúng là thứ mắt xích kia cần.")
        d = by_id.get(c.get("id"), {})
        for k in ("feasible", "risk"):
            if k in c and c.get(k) != d.get(k):
                errors.append(f"_combinations {cid}: `{k}` = {c.get(k)!r} nhưng engine suy ra {d.get(k)!r} — xoá trường này (engine tự tính).")
    known = set().union(*(link_ids(fid, it) for fid, it in items.items() if fid in ctx.fids)) if items else set()
    for q in _l(combos.get("key_questions")):
        q = _d(q)
        qid = q.get("id", "?")
        if not _why_ok(q.get("question"), 20) or q.get("to") not in RECIPIENTS:
            errors.append(f"_combinations key_questions {qid}: cần `question` (≥20 ký tự) và `to` thuộc {', '.join(RECIPIENTS)}.")
        unlocks = [str(u) for u in _l(q.get("unlocks"))]
        bad = [u for u in unlocks if u not in known]
        if bad:
            errors.append(f"_combinations key_questions {qid}: `unlocks` trỏ tới mắt xích không tồn tại: {', '.join(bad[:5])} (dạng `F-02.P1.C1`).")
        not_open = [u for u in unlocks if u not in bad and _link_verdict(items.get(u.split('.', 1)[0]), u.split('.', 1)[1]) != "chua_ro"]
        if not_open:
            errors.append(f"_combinations key_questions {qid}: chỉ đưa mắt xích đang `chua_ro` vào `unlocks`: {', '.join(not_open[:5])}.")
        if len({u.split('.')[0] for u in unlocks}) < 2:
            errors.append(f"_combinations key_questions {qid}: câu hỏi quyết định phải mở mắt xích của ≥2 F; câu hỏi của một F thì để trong `open_questions` của F đó.")
    linked = {(fid, e) for fid, it in items.items() if isinstance(it, dict)
              for p in _l(it.get("attack_paths")) for c in _l(_d(p).get("preconditions")) for e in _l(_d(c).get("enabled_by"))
              if re.fullmatch(r"F-\d{2,}", str(e))}
    covered = {(c.get("target"), c.get("giver")) for c in combos["combinations"] if isinstance(c, dict)}
    for fid, e in sorted(linked - covered):
        warnings.append(f"{fid} có mắt xích `enabled_by` {e} nhưng chưa có tổ hợp tương ứng trong _combinations.json.")
    return errors, warnings


# ----------------------------------------------------------------------------- chỉ mục truy cập

_ACCESS_LINE_RE = re.compile(r"client_scope|white_?list|oauth_client|is_required_access_token|api_policy|granted_ip|client_id\b", re.I)
_CLIENT_NEAR_RE = re.compile(r"(?i:client(?:_id)?)[^A-Za-z0-9]{1,40}?([A-Z][A-Z0-9]{5,})\b")
_CLIENT_STOP = {"README", "SELECT", "INSERT", "UPDATE", "DELETE", "HEADER", "BEARER", "CLIENT", "SECRET", "TOKEN", "HTTPS", "OAUTH",
                "VALUES", "SCOPE", "ACCESS", "SYSTEM", "STRING", "PUBLIC", "PRIVATE", "DEFAULT", "CONFIG", "PASSWORD"}


def _recon_access(docs: Path) -> tuple[dict[str, set[str]], dict[str, list[int]]]:
    """Tên client và các dòng cấu hình truy cập nêu trong tài liệu recon/BASV (không chép nội dung dòng).

    Dòng có từ chỉ bí mật (secret, password, mật khẩu, token, key…) chỉ lấy tên toàn chữ cái, để không chép giá trị bí mật.
    """
    names: dict[str, set[str]] = {}
    lines: dict[str, list[int]] = {}
    for p in sorted(docs.rglob("*.md")) if docs.is_dir() else []:
        relp = p.relative_to(docs)
        if relp.parts[0].startswith("_report"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if _ACCESS_LINE_RE.search(line):
                lines.setdefault(relp.as_posix(), []).append(i)
            secretish = bool(_SECRET_WORD_RE.search(line))
            for m in _CLIENT_NEAR_RE.finditer(line):
                tok = m.group(1)
                if tok in _CLIENT_STOP or len(tok) > 40 or (secretish and not tok.isalpha()):
                    continue
                names.setdefault(tok, set()).add(relp.parts[0])
    return names, lines


def _access_rows(findings: list[dict[str, Any]]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    live = [f for f in findings if f.get("disposition") != "bac_bo"]
    out = []
    for key, title, pat in ACCESS_GROUPS:
        rx = re.compile(pat, re.I)
        out.append((key, title, [f for f in live if rx.search(f"{f.get('title', '')} {f.get('impact', '')}")]))
    return out


def access_index(findings: list[dict[str, Any]], docs: Path | None = None) -> list[str]:
    """inputs/05_access_index.md — mọi mục (mọi repo) về bí mật, scope, đường vào mạng, nguồn ID, chuỗi cung ứng;
    cùng tên client và dòng cấu hình truy cập nêu trong tài liệu recon. Bản lọc cho một F: `report.py access --for F-xx`."""
    L = ["# Chỉ mục truy cập — đầu vào của Phase Risk", "",
         "Mọi mục của mọi repo nhắc tới bí mật/credential, scope của client, đường vào mạng, nguồn ID, chuỗi cung ứng (lọc theo từ khoá, tất định). "
         "File này lớn — **không đọc nguyên file**: dùng `python3 AI-skills/reporting/report.py access --for F-xx` để lấy phần liên quan tới một F. "
         "Mục đã bác bỏ không có ở đây.", ""]
    for _, title, rows in _access_rows(findings):
        L += [f"## {title} ({len(rows)})", "", "| SID | Xử lý gốc | Tiêu đề |", "|---|---|---|"]
        L += [f"| `{f['sid']}` | {f.get('disposition')} | {_cell(f.get('title'), 170)} |" for f in sorted(rows, key=lambda x: x["sid"])]
        L.append("")
    if docs is not None:
        L += _recon_section(docs, None)
    return L


def _recon_section(docs: Path, repos: set[str] | None) -> list[str]:
    names, lines = _recon_access(docs)
    L = [f"## Client được nhắc trong tài liệu recon ({len(names)})", "",
         "Mỗi client là một người nắm giữ tiềm năng: ai giữ credential của nó, nó có scope tới route nào.", "",
         "| Client | Nhắc tới ở |", "|---|---|"]
    L += [f"| `{k}` | {', '.join(sorted(v))} |" for k, v in sorted(names.items())]
    sel = {f: ns for f, ns in lines.items() if repos is None or f.split("/")[0] in repos or f.split("/")[0].startswith("_")}
    L += ["", f"## Dòng cấu hình truy cập trong tài liệu recon ({sum(len(v) for v in sel.values())} dòng"
          f"{'' if repos is None else ', chỉ repo của F và cấp hệ thống'})", "",
          "Dòng nhắc tới client_scope, client_id, allowlist, api_policy, is_required_access_token, oauth_client. Chỉ ghi số dòng; đọc đúng đoạn đó.", ""]
    L += [f"- `documents/{f}`: {', '.join(str(n) for n in ns[:40])}{' …' if len(ns) > 40 else ''}" for f, ns in sorted(sel.items())]
    L.append("")
    return L


_BROAD_RE = re.compile(r"client|oauth|scope|token|credential|seed|bundle|keystore|jwt|session|cookie", re.I)


def access_for(findings: list[dict[str, Any]], docs: Path | None, finding: dict[str, Any]) -> list[str]:
    """Phần của chỉ mục truy cập liên quan tới một F: mục của repo của F; mục ở repo khác nhưng nói về client/scope/token/seed
    (thứ thường mở mắt xích của F khác); toàn bộ nhóm scope và mạng (nhỏ); tên client; số dòng cấu hình của repo của F."""
    repos = set(finding.get("services") or [])
    srcs = set(finding.get("source_ids") or [])
    L = [f"# Chỉ mục truy cập cho {finding.get('id')} — {_cell(finding.get('title'), 120)}", "",
         f"Repo của F: {', '.join(sorted(repos)) or '(không ghi)'}. Mục của repo khác chỉ giữ khi nói về client, scope, token, credential, seed, "
         "phiên — thứ thường là người nắm giữ hoặc đường vào cho F này.", ""]
    for key, title, rows in _access_rows(findings):
        if key in {"bi_mat", "id_du_lieu", "chuoi_cung_ung"}:
            rows = [f for f in rows if f.get("repo") in repos or f.get("sid") in srcs or str(f.get("repo", "")).startswith("_")
                    or _BROAD_RE.search(f"{f.get('title', '')} {f.get('impact', '')}")]
        if not rows:
            continue
        L += [f"## {title} ({len(rows)})", "", "| SID | Xử lý gốc | Tiêu đề |", "|---|---|---|"]
        L += [f"| `{f['sid']}` | {f.get('disposition')} | {_cell(f.get('title'), 150)} |" for f in sorted(rows, key=lambda x: x["sid"])]
        L.append("")
    if docs is not None:
        L += _recon_section(docs, repos)
    return L


def risk_digest(findings: list[dict[str, Any]], items: dict[str, Any], derived: dict[str, Any]) -> list[str]:
    """Bảng gọn cho R.2: mỗi F một dòng `yields`, mỗi mắt xích chưa đạt một dòng — để ghép chéo mà không mở mọi file."""
    L = ["# Bảng ghép chéo (R.2)", "",
         "Ghép khi thứ một F *cho* (`yields`) đúng là thứ mắt xích của F khác *cần*. Ghi `enabled_by` vào mắt xích và một tổ hợp trong `_combinations.json`.", "",
         "## Mỗi F cho kẻ tấn công được gì", "", "| F | Khả thi | Cho được |", "|---|---|---|"]
    for f in findings:
        it = items.get(f["id"])
        if not isinstance(it, dict):
            continue
        d = derived.get(f["id"], {})
        L.append(f"| {f['id']} | {VERDICTS.get(d.get('feasibility'), '?')} | {_cell('; '.join(_s(y) for y in _l(it.get('yields'))), 200)} |")
    L += ["", "## Mắt xích chưa đạt (khong / chua_ro)", "", "| Mắt xích | Loại | Kết luận | Cần | Nhờ |", "|---|---|---|---|---|"]
    for f in findings:
        it = items.get(f["id"])
        for p in _l(_d(it).get("attack_paths")):
            p = _d(p)
            e = _d(p.get("entry"))
            if e.get("reachable") in {"khong", "chua_ro"}:
                L.append(f"| `{f['id']}.{p.get('id')}.entry` | cham_toi | {VERDICTS.get(e.get('reachable'))} | {_cell(e.get('surface'), 100)} | |")
            for c in _l(p.get("preconditions")):
                c = _d(c)
                if c.get("attainable") in {"khong", "chua_ro"}:
                    L.append(f"| `{f['id']}.{p.get('id')}.{c.get('id')}` | {c.get('kind', '?')} | {VERDICTS.get(c.get('attainable'))} | "
                             f"{_cell(c.get('need'), 120)} | {', '.join(_l(c.get('enabled_by')))} |")
    L.append("")
    return L


# ----------------------------------------------------------------------------- hiển thị

def _cell(v: Any, n: int = 200) -> str:
    s = " ".join(str(v or "").split())
    s = s if len(s) <= n else s[: n - 1] + "…"
    return s.replace("|", "\\|")


def state_text(d: dict[str, Any]) -> str:
    if not d:
        return "chưa đánh giá"
    base = {"khai_thac_duoc": "Khai thác được", "khong_khai_thac_duoc": "Không khai thác được", "tam_tinh": "Tạm tính (còn mắt xích chưa rõ)"}[d["state"]]
    lift = f"; ưu tiên được kéo lên bởi tổ hợp {', '.join(d['lifted_by'])}" if d.get("lifted_by") else ""
    return f"{base} → rủi ro {RISK_VI[d['risk']]}, {d['priority']}{lift}"


def item_markdown(fid: str, item: dict[str, Any], compact: bool = False, derived: dict[str, Any] | None = None) -> list[str]:
    d = derived or derive(item, None)
    lk = _d(item.get("likelihood"))
    L = [f"**Khả năng khai thác thực tế: {state_text(d)}.** {_s(lk.get('why'))} (mắt xích khó nhất: `{lk.get('hardest', '—')}`).", ""]
    for p in _l(item.get("attack_paths")):
        p = _d(p)
        pf = path_feasibility(p)
        e = _d(p.get("entry"))
        tag = "" if p.get("reaches_impact", "co") != "khong" else f" *(hậu quả khác 4.4: {_s(p.get('outcome'))})*"
        summary = _s(p.get("summary")).rstrip(".")
        L += [f"*Đường {p.get('id')} — {VERDICTS[pf]}{tag}:* {summary}. Ai: {_s(p.get('actor')).rstrip('.')}.", "",
              "| Mắt xích | Cần | Đạt được? | Vì sao |", "|---|---|---|---|",
              f"| entry | {_cell(e.get('surface'), 100)} | {VERDICTS.get(e.get('reachable'), '?')} | {_cell(e.get('why'), 160)} |"]
        for c in _l(p.get("preconditions")):
            c = _d(c)
            via = f" (nhờ {', '.join(str(x) for x in _l(c.get('enabled_by')))})" if c.get("enabled_by") else ""
            L.append(f"| {c.get('id')} | {_cell(c.get('need'), 120)} | {VERDICTS.get(c.get('attainable'), '?')}{via} | {_cell(c.get('why'), 160)} |")
            if not compact:
                for j, h in enumerate(_l(c.get("holders")), start=1):
                    h = _d(h)
                    L.append(f"| ↳ H{j} | {_cell(h.get('who'), 90)}{(' — ' + _cell(h.get('how'), 60)) if h.get('how') else ''} | "
                             f"{VERDICTS.get(h.get('attainable'), '?')} | {_cell(h.get('why'), 100)} |")
        for i, b in enumerate(_l(p.get("blocking_controls")), start=1):
            b = _d(b)
            if control_counts(b):
                eff = {"co": "Chặn được", "khong": "Không chặn"}.get(b.get("effective"), "Chưa rõ")
                L.append(f"| K{i} (chặn) | {_cell(b.get('control'), 100)} | {eff} | {_cell(b.get('why'), 140)} |")
            else:
                L.append(f"| K{i} (giả định) | {_cell(b.get('control'), 120)} | Chưa có bằng chứng tồn tại — không tính | {_cell(b.get('why'), 140)} |")
        if p.get("effort") and not compact:
            L.append(f"\nCông sức thực tế: {_s(p.get('effort'))}")
        L.append("")
    if not compact:
        ac = item.get("actors_considered")
        if isinstance(ac, dict):
            L += ["*Đã xét các loại người khai thác:* " + "; ".join(
                f"{ACTOR_TYPES[k]}: {', '.join(v) if isinstance(v, list) else 'không áp dụng — ' + _s(v)}"
                for k, v in ac.items() if k in ACTOR_TYPES), ""]
        if item.get("yields"):
            L += ["*Khai thác được thì kẻ tấn công có thêm:* " + "; ".join(_s(y) for y in _l(item.get("yields"))), ""]
    det = _d(item.get("detection"))
    if det:
        L += [f"*Bị phát hiện không:* {VERDICTS.get(det.get('would_be_noticed'), '?')} — {_s(det.get('why'))}", ""]
    if item.get("escalation_triggers"):
        L += ["*Rủi ro đổi khi:* " + "; ".join(_s(t) for t in _l(item.get("escalation_triggers"))), ""]
    if item.get("open_questions") and not compact:
        L += ["*Cần xác nhận:* " + "; ".join(f"{_s(_d(q).get('question'))} (hỏi {RECIPIENTS.get(_d(q).get('to'), _d(q).get('to'))}, "
                                             f"ảnh hưởng `{', '.join(affects_of(q))}`)" for q in _l(item.get("open_questions"))), ""]
    return L


def key_questions_table(combos: Any, items: dict[str, Any], impacts: dict[str, Any]) -> list[str]:
    keyq = [_d(q) for q in _l(_d(combos).get("key_questions"))]
    if not keyq:
        return []
    L = ["| ID | Câu hỏi | Hỏi ai | Nếu **có** | Nếu **không** |", "|---|---|---|---|---|"]
    for q in keyq:
        outc = key_question_outcomes(q, items, impacts)

        def fmt(ans: str) -> str:
            parts = []
            for fid, o in sorted(outc.items()):
                d = o[ans]
                parts.append(f"{fid}: {RISK_VI[d['risk']]}/{d['priority']}{' (vẫn tạm tính)' if d['state'] == 'tam_tinh' else ''}")
            return "; ".join(parts)
        L.append(f"| {q.get('id')} | {_cell(q.get('question'), 260)} | {RECIPIENTS.get(q.get('to'), q.get('to'))} | {fmt('co')} | {fmt('khong')} |")
    return L


def risk_document(project: str, findings: list[dict[str, Any]], items: dict[str, Any], combos: Any, draft: bool, today: str,
                  derived: dict[str, Any] | None = None, combos_derived: list[dict[str, Any]] | None = None,
                  impacts: dict[str, Any] | None = None) -> list[str]:
    impacts = impacts or {}
    if derived is None or combos_derived is None:
        derived, combos_derived = derive_all(items, impacts, combos)
    L = [f"# Đánh giá rủi ro thực tế — {project}", ""]
    if draft:
        L += ["> **BẢN NHÁP — chưa qua thách thức độc lập (bước R.4).**", ""]
    L += [f"> Ngày lập: {today}. Không dùng khung chấm điểm: mỗi mắt xích của đường khai thác được kết luận Có / Không / Chưa rõ kèm lý do và "
          "bằng chứng. Khả thi, mức rủi ro và ưu tiên do script suy ra: khai thác được → rủi ro bằng mức tác động nghiệp vụ (4.4); "
          "không khai thác được → Thấp; còn mắt xích chưa rõ → mức tác động nhưng *tạm tính*, ưu tiên hạ một bậc cho tới khi trả lời câu hỏi quyết định. "
          "Kiểm soát chỉ được tính khi có bằng chứng tồn tại.", ""]
    n = {s: sum(1 for f in findings if derived.get(f["id"], {}).get("state") == s) for s in ("khai_thac_duoc", "tam_tinh", "khong_khai_thac_duoc")}
    L += ["## Tóm tắt", "",
          f"- Khai thác được: **{n['khai_thac_duoc']}** phát hiện · Tạm tính: **{n['tam_tinh']}** · Không khai thác được: **{n['khong_khai_thac_duoc']}**."]
    feas_list = [f["id"] for f in findings if derived.get(f["id"], {}).get("state") == "khai_thac_duoc"]
    if feas_list:
        L.append(f"- Khai thác được ngay: {', '.join(feas_list)}.")
    hot = [c for c in combos_derived if c.get("feasible") == "co"]
    if hot:
        L.append(f"- Tổ hợp khai thác được: {', '.join(c.get('id', '?') for c in hot)}.")
    L.append("")
    kq = key_questions_table(combos, items, impacts)
    if kq:
        L += ["### Câu hỏi quyết định", "", "Mỗi câu trả lời đổi kết luận của nhiều phát hiện cùng lúc; hỏi trước mọi câu khác. "
              "Hai cột cuối là kết quả script tính sẵn cho từng câu trả lời.", ""] + kq + [""]
    L += ["## Tổng quan", "", "| ID | Điểm yếu | Tác động 4.4 | Khai thác thực tế | Mắt xích khó nhất | Rủi ro | Ưu tiên |", "|---|---|---|---|---|---|---|"]
    for f in findings:
        it = _d(items.get(f["id"]))
        d = derived.get(f["id"], {})
        st = {"khai_thac_duoc": "Có", "khong_khai_thac_duoc": "Không", "tam_tinh": "Chưa rõ (tạm tính)"}.get(d.get("state"), "—")
        L.append(f"| {f['id']} | {_cell(f.get('title'), 90)} | {RISK_VI.get(impacts.get(f['id']), '—')} | {st} | "
                 f"`{_d(it.get('likelihood')).get('hardest', '—')}` | {RISK_VI.get(d.get('risk'), '—')} | {d.get('priority', '—')} |")
    L.append("")
    if combos_derived:
        L += ["## Tổ hợp xuyên điểm yếu", "", "| ID | Bên cho → bên nhận | Mắt xích được mở | Cách ghép | Khả thi | Rủi ro | Ưu tiên |",
              "|---|---|---|---|---|---|---|"]
        L += [f"| {c.get('id')} | {c.get('giver')} → {c.get('target')} | `{c.get('link')}` | {_cell(c.get('how'), 140)} | "
              f"{VERDICTS.get(c.get('feasible'), '?')} | {RISK_VI.get(c.get('risk'), '—')} | {c.get('priority') or '—'} |" for c in combos_derived]
        L.append("")
    for f in findings:
        it = items.get(f["id"])
        if not isinstance(it, dict):
            continue
        L += [f"## {f['id']} · {f.get('title')}", "", f"**{state_text(derived.get(f['id'], {}))}.** {_s(it.get('rationale'))}", ""]
        L += item_markdown(f["id"], it, derived=derived.get(f["id"]))
    covered = {str(u) for q in _l(_d(combos).get("key_questions")) for u in _l(_d(q).get("unlocks"))}
    qs = [(f["id"], _d(q)) for f in findings for q in _l(_d(items.get(f["id"])).get("open_questions"))
          if any(f"{f['id']}.{a}" not in covered for a in affects_of(q))]
    if qs:
        L += ["## Câu hỏi khác (theo người cần hỏi)", ""]
        if covered:
            L += ["Câu hỏi về mắt xích đã nằm trong *Câu hỏi quyết định* không lặp lại ở đây.", ""]
        for to in sorted({str(q.get("to")) for _, q in qs}):
            L += [f"**{RECIPIENTS.get(to, to)}:**", ""] + [
                f"- [{fid} · `{', '.join(affects_of(q))}`] {_s(q.get('question'))}{(' (' + _s(q.get('to_detail')) + ')') if q.get('to_detail') else ''}"
                for fid, q in qs if str(q.get("to")) == to] + [""]
        L += ["Trả lời được xác nhận thì ghi vào `documents/_report/runtime_facts.json` (`id`, `answer`, `source`, `date`) và trích bằng `fact:<id>`.", ""]
    return L
