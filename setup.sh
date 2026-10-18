#!/usr/bin/env sh
# Bootstrap script: Run from <Project-Root> as `sh AI-skills/setup.sh`
# Copies only Antigravity discovery files (.agents/, AGENTS.md, SOUL.md) to <Project-Root>
# while keeping localsec/, schemas/, contracts/, skills/, and localsec.toml cleanly inside AI-skills/.

set -e

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(pwd)"

if [ "$SKILL_DIR" = "$PROJECT_ROOT" ]; then
    echo "[!] Bạn đang đứng bên trong thư mục AI-skills."
    echo "    Hãy cd ra thư mục gốc của Project cần áp dụng (<Project-Root>) rồi chạy:"
    echo "    sh AI-skills/setup.sh"
    exit 1
fi

cp -R "$SKILL_DIR/.agents" "$PROJECT_ROOT/.agents"
cp "$SKILL_DIR/AGENTS.md" "$PROJECT_ROOT/AGENTS.md"
cp "$SKILL_DIR/SOUL.md" "$PROJECT_ROOT/SOUL.md"

echo "[+] Đã cài đặt .agents/, AGENTS.md và SOUL.md ra thư mục gốc Project: $PROJECT_ROOT"
echo "[+] Toàn bộ Engine & Schemas được giữ gọn trong: $SKILL_DIR"
echo "[*] Đang kiểm tra kết nối CLI & Unit Tests..."

PYTHONPATH="$SKILL_DIR:." python3 -m unittest discover -s "$SKILL_DIR/tests"

echo "[✓] Sẵn sàng! Hãy mở $PROJECT_ROOT trong Antigravity và chạy /phase-1-orchestrator, /phase-2-orchestrator, hoặc /phase-3-orchestrator."
