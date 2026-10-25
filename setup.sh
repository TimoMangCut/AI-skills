#!/usr/bin/env sh
# Bootstrap script (Git Bash on Windows / POSIX sh):
# Run from <Project-Root> as `sh AI-skills/setup.sh` (or `sh AI-skills/setup.sh --uninstall`)
# Native Windows PowerShell alternative: `.\AI-skills\setup.ps1`
# Native Windows CMD alternative:        `AI-skills\setup.bat`

set -e

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(pwd)"
SKILL_FOLDER_NAME="$(basename "$SKILL_DIR")"
MODE="${1:-install}"

if [ "$SKILL_DIR" = "$PROJECT_ROOT" ]; then
    echo "[!] Bạn đang đứng bên trong thư mục $SKILL_FOLDER_NAME."
    echo "    Hãy cd ra thư mục gốc của Project cần áp dụng (<Project-Root>) rồi chạy:"
    echo "    - PowerShell (Windows): .\\$SKILL_FOLDER_NAME\\setup.ps1"
    echo "    - CMD (Windows):        $SKILL_FOLDER_NAME\\setup.bat"
    echo "    - Git Bash / POSIX:     sh $SKILL_FOLDER_NAME/setup.sh"
    exit 1
fi

if command -v python >/dev/null 2>&1 && python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
    PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v py >/dev/null 2>&1; then
    PYTHON_BIN="py -3"
else
    echo "[!] Không tìm thấy Python 3.10+ (python / python3 / py -3)."
    exit 1
fi

$PYTHON_BIN "$SKILL_DIR/setup_bootstrap.py" "$SKILL_DIR" "$PROJECT_ROOT" "$SKILL_FOLDER_NAME" "$MODE"
