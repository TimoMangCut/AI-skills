#!/usr/bin/env sh
# Bootstrap script: Run from <Project-Root> as `sh AI-skills/setup.sh`
# Copies only Antigravity discovery files (.agents/, AGENTS.md, SOUL.md) to <Project-Root>
# while keeping localsec/, schemas/, contracts/, skills/, and localsec.toml cleanly inside AI-skills/.

set -e

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(pwd)"
SKILL_FOLDER_NAME="$(basename "$SKILL_DIR")"

if [ "$SKILL_DIR" = "$PROJECT_ROOT" ]; then
    echo "[!] Bạn đang đứng bên trong thư mục $SKILL_FOLDER_NAME."
    echo "    Hãy cd ra thư mục gốc của Project cần áp dụng (<Project-Root>) rồi chạy:"
    echo "    sh $SKILL_FOLDER_NAME/setup.sh"
    exit 1
fi

mkdir -p "$PROJECT_ROOT/.agents/skills"
cp "$SKILL_DIR/.agents/README.md" "$PROJECT_ROOT/.agents/README.md"
for skill_path in "$SKILL_DIR/.agents/skills/"*; do
    if [ -d "$skill_path" ]; then
        skill_name="$(basename "$skill_path")"
        rm -rf "$PROJECT_ROOT/.agents/skills/$skill_name"
        cp -R "$skill_path" "$PROJECT_ROOT/.agents/skills/$skill_name"
    fi
done

if [ "$SKILL_FOLDER_NAME" != "AI-skills" ]; then
    python3 - "$PROJECT_ROOT/.agents" "$SKILL_FOLDER_NAME" <<'PY'
import sys
from pathlib import Path

agents_dir = Path(sys.argv[1])
folder_name = sys.argv[2]
for md in agents_dir.rglob("*.md"):
    txt = md.read_text(encoding="utf-8")
    md.write_text(txt.replace("AI-skills", folder_name), encoding="utf-8")
PY
fi

cp "$SKILL_DIR/AGENTS.md" "$PROJECT_ROOT/AGENTS.md"
cp "$SKILL_DIR/SOUL.md" "$PROJECT_ROOT/SOUL.md"

echo "[+] Đã đồng bộ .agents/ (28 skills), AGENTS.md và SOUL.md ra thư mục gốc Project: $PROJECT_ROOT"
echo "[+] Toàn bộ Engine & Schemas được giữ gọn trong: $SKILL_DIR"
echo "[*] Đang kiểm tra kết nối CLI & Unit Tests..."

PYTHONPATH="$SKILL_DIR:." python3 -m unittest discover -s "$SKILL_DIR/tests"

echo "[✓] Sẵn sàng! Hãy mở $PROJECT_ROOT trong Antigravity và chạy /phase-1-orchestrator, /phase-2-orchestrator, hoặc /phase-3-orchestrator."

