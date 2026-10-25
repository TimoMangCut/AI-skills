#!/usr/bin/env sh
# Bootstrap script: Run from <Project-Root> as `sh AI-skills/setup.sh` (or `sh AI-skills/setup.sh --uninstall`)
# - Syncs 28 Antigravity skills (.agents/skills/phase-*) and .agents/rules/soul.md without deleting existing project skills
# - Safely merges AGENTS.md and SOUL.md using bounded markers (never overwrites pre-existing project rules)
# - Automatically populates .git/info/exclude so `git status` in <Project-Root> stays clean

set -e

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(pwd)"
SKILL_FOLDER_NAME="$(basename "$SKILL_DIR")"
MODE="${1:-install}"

if [ "$SKILL_DIR" = "$PROJECT_ROOT" ]; then
    echo "[!] Bạn đang đứng bên trong thư mục $SKILL_FOLDER_NAME."
    echo "    Hãy cd ra thư mục gốc của Project cần áp dụng (<Project-Root>) rồi chạy:"
    echo "    sh $SKILL_FOLDER_NAME/setup.sh"
    exit 1
fi

python3 - "$SKILL_DIR" "$PROJECT_ROOT" "$SKILL_FOLDER_NAME" "$MODE" <<'PY'
import re
import shutil
import subprocess
import sys
from pathlib import Path

skill_dir = Path(sys.argv[1]).resolve()
project_root = Path(sys.argv[2]).resolve()
folder_name = sys.argv[3]
mode = sys.argv[4]


def _resolve_git_exclude(root: Path) -> Path | None:
    git_entry = root / ".git"
    if git_entry.is_dir():
        info_dir = git_entry / "info"
        info_dir.mkdir(parents=True, exist_ok=True)
        return info_dir / "exclude"
    if git_entry.is_file():
        txt = git_entry.read_text(encoding="utf-8", errors="replace").strip()
        if txt.startswith("gitdir:"):
            git_dir = (root / txt.split(":", 1)[1].strip()).resolve()
            info_dir = git_dir / "info"
            info_dir.mkdir(parents=True, exist_ok=True)
            return info_dir / "exclude"
    return None


def _is_git_tracked(root: Path, rel_path: str) -> bool:
    if not (root / ".git").exists():
        return False
    res = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", rel_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return res.returncode == 0


def _merge_marked_file(src_path: Path, dst_path: Path, marker_name: str) -> str:
    begin_tag = f"<!-- BEGIN AI-SKILLS:{marker_name} -->"
    end_tag = f"<!-- END AI-SKILLS:{marker_name} -->"
    src_text = src_path.read_text(encoding="utf-8").strip()
    block = f"{begin_tag}\n{src_text}\n{end_tag}\n"

    if not dst_path.is_file():
        dst_path.write_text(block, encoding="utf-8")
        return "created"

    existing = dst_path.read_text(encoding="utf-8")
    if existing.strip() == src_text:
        dst_path.write_text(block, encoding="utf-8")
        return "updated"

    pattern = re.compile(re.escape(begin_tag) + r".*?" + re.escape(end_tag) + r"\n?", re.DOTALL)
    if pattern.search(existing):
        updated = pattern.sub(lambda _: block, existing)
        dst_path.write_text(updated, encoding="utf-8")
        return "updated"

    # Pre-existing custom project file: preserve original content and append delimited block
    merged = existing.rstrip() + "\n\n" + block
    dst_path.write_text(merged, encoding="utf-8")
    return "merged_preserving_existing"


def _unmerge_marked_file(dst_path: Path, src_path: Path, marker_name: str) -> None:
    if not dst_path.is_file():
        return
    begin_tag = f"<!-- BEGIN AI-SKILLS:{marker_name} -->"
    end_tag = f"<!-- END AI-SKILLS:{marker_name} -->"
    existing = dst_path.read_text(encoding="utf-8")
    src_text = src_path.read_text(encoding="utf-8").strip()
    if existing.strip() == src_text:
        dst_path.unlink()
        return
    pattern = re.compile(r"\n*" + re.escape(begin_tag) + r".*?" + re.escape(end_tag) + r"\n?", re.DOTALL)
    remaining = pattern.sub("\n", existing).strip()
    if not remaining:
        dst_path.unlink()
    else:
        dst_path.write_text(remaining + "\n", encoding="utf-8")


def _update_git_exclude(root: Path, skill_folder: str, remove: bool = False) -> bool:
    exclude_file = _resolve_git_exclude(root)
    if exclude_file is None:
        return False
    begin_tag = "# BEGIN AI-SKILLS EXCLUDE"
    end_tag = "# END AI-SKILLS EXCLUDE"
    existing = exclude_file.read_text(encoding="utf-8") if exclude_file.is_file() else ""
    pattern = re.compile(r"\n*" + re.escape(begin_tag) + r".*?" + re.escape(end_tag) + r"\n?", re.DOTALL)
    cleaned = pattern.sub("\n", existing).rstrip()
    if remove:
        exclude_file.write_text((cleaned + "\n") if cleaned else "", encoding="utf-8")
        return True

    entries = [
        f"/{skill_folder}/",
        "/.agents/README.md",
        "/.agents/rules/soul.md",
        "/.agents/skills/phase-1-*",
        "/.agents/skills/phase-2-*",
        "/.agents/skills/phase-3-*",
        "/.claude/skills/phase-1-*",
        "/.claude/skills/phase-2-*",
        "/.claude/skills/phase-3-*",
        "/.localsec/",
        "/documents/",
    ]
    for root_doc in ("AGENTS.md", "SOUL.md", "CLAUDE.md"):
        if not _is_git_tracked(root, root_doc):
            entries.append(f"/{root_doc}")
    block = begin_tag + "\n" + "\n".join(entries) + "\n" + end_tag + "\n"
    new_content = (cleaned + "\n\n" + block) if cleaned else block
    exclude_file.write_text(new_content, encoding="utf-8")
    return True


if mode in ("--uninstall", "--clean", "uninstall", "clean"):
    agents_dir = project_root / ".agents"
    if (agents_dir / "skills").is_dir():
        for sp in (skill_dir / ".agents" / "skills").iterdir():
            if sp.is_dir():
                target_sp = agents_dir / "skills" / sp.name
                if target_sp.exists():
                    shutil.rmtree(target_sp)
    soul_rule = agents_dir / "rules" / "soul.md"
    if soul_rule.is_file():
        soul_rule.unlink()
    readme_ag = agents_dir / "README.md"
    if readme_ag.is_file():
        readme_ag.unlink()
    # Remove empty .agents subdirectories if no custom project skills/rules remain
    for sub in ("skills", "rules"):
        subdir = agents_dir / sub
        if subdir.is_dir() and not any(subdir.iterdir()):
            subdir.rmdir()
    if agents_dir.is_dir() and not any(agents_dir.iterdir()):
        agents_dir.rmdir()

    claude_dir = project_root / ".claude"
    if (claude_dir / "skills").is_dir():
        for sp in (skill_dir / ".agents" / "skills").iterdir():
            if sp.is_dir():
                target_sp = claude_dir / "skills" / sp.name
                if target_sp.exists():
                    shutil.rmtree(target_sp)
        if not any((claude_dir / "skills").iterdir()):
            (claude_dir / "skills").rmdir()
    if claude_dir.is_dir() and not any(claude_dir.iterdir()):
        claude_dir.rmdir()

    _unmerge_marked_file(project_root / "AGENTS.md", skill_dir / "AGENTS.md", "AGENTS.md")
    _unmerge_marked_file(project_root / "SOUL.md", skill_dir / "SOUL.md", "SOUL.md")
    if (skill_dir / "CLAUDE.md").is_file():
        _unmerge_marked_file(project_root / "CLAUDE.md", skill_dir / "CLAUDE.md", "CLAUDE.md")
    _update_git_exclude(project_root, folder_name, remove=True)
    print(f"[✓] Đã gỡ cài đặt các file AI-skills khỏi {project_root} (giữ nguyên mọi nội dung gốc của dự án).")
    sys.exit(0)

# 1. Sync .agents/ (Antigravity) and .claude/skills/ (Claude Code)
agents_dst = project_root / ".agents"
claude_dst = project_root / ".claude"
(agents_dst / "skills").mkdir(parents=True, exist_ok=True)
(agents_dst / "rules").mkdir(parents=True, exist_ok=True)
(claude_dst / "skills").mkdir(parents=True, exist_ok=True)
shutil.copy2(skill_dir / ".agents" / "README.md", agents_dst / "README.md")
if (skill_dir / ".agents" / "rules" / "soul.md").is_file():
    shutil.copy2(skill_dir / ".agents" / "rules" / "soul.md", agents_dst / "rules" / "soul.md")

copied_skills = 0
for sp in sorted((skill_dir / ".agents" / "skills").iterdir()):
    if sp.is_dir() and not sp.name.startswith("._"):
        for dst_root in (agents_dst / "skills", claude_dst / "skills"):
            target_sp = dst_root / sp.name
            if target_sp.exists():
                shutil.rmtree(target_sp)
            shutil.copytree(sp, target_sp, ignore=shutil.ignore_patterns("._*"))
        copied_skills += 1

# 2. If cloned under a custom folder name != AI-skills, rewrite references in copied .agents/ and .claude/skills/
if folder_name != "AI-skills":
    for root_target in (agents_dst, claude_dst / "skills"):
        for md in root_target.rglob("*.md"):
            if md.name.startswith("._"):
                continue
            txt = md.read_text(encoding="utf-8")
            md.write_text(txt.replace("AI-skills", folder_name), encoding="utf-8")

# 3. Non-destructively install or merge AGENTS.md, SOUL.md, and CLAUDE.md
agents_status = _merge_marked_file(skill_dir / "AGENTS.md", project_root / "AGENTS.md", "AGENTS.md")
soul_status = _merge_marked_file(skill_dir / "SOUL.md", project_root / "SOUL.md", "SOUL.md")
claude_status = (
    _merge_marked_file(skill_dir / "CLAUDE.md", project_root / "CLAUDE.md", "CLAUDE.md")
    if (skill_dir / "CLAUDE.md").is_file()
    else "skipped"
)

# 4. Update .git/info/exclude so target project git status stays clean
exclude_updated = _update_git_exclude(project_root, folder_name, remove=False)

print(f"[+] Đã đồng bộ {copied_skills} skills vào .agents/skills/ (Antigravity) và .claude/skills/ (Claude Code)")
print(f"[+] Trạng thái AGENTS.md: {agents_status} | SOUL.md: {soul_status} | CLAUDE.md: {claude_status}")
if exclude_updated:
    print(f"[+] Đã cập nhật .git/info/exclude để giữ sạch 'git status' cho Project.")
print(f"[+] Toàn bộ Engine & Schemas được giữ gọn trong: {skill_dir}")
PY

if [ "$MODE" = "--uninstall" ] || [ "$MODE" = "--clean" ] || [ "$MODE" = "uninstall" ] || [ "$MODE" = "clean" ]; then
    exit 0
fi

if [ "${AI_SKILLS_SKIP_TESTS:-0}" != "1" ]; then
    echo "[*] Đang kiểm tra kết nối CLI & Unit Tests..."
    PYTHONPATH="$SKILL_DIR:." python3 -m unittest discover -s "$SKILL_DIR/tests"
fi

echo "[✓] Sẵn sàng! Hãy mở $PROJECT_ROOT trong Antigravity hoặc Claude Code và chạy /phase-1-orchestrator, /phase-2-orchestrator, hoặc /phase-3-orchestrator."



