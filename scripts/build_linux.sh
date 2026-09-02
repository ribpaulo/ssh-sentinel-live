#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$PROJECT_DIR/.venv/bin/python"
else
    PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

"$PYTHON_BIN" -m PyInstaller --clean --noconfirm ssh-sentinel.spec

echo ""
echo "Linux build created: $PROJECT_DIR/dist/ssh-sentinel"
echo "Run: ./dist/ssh-sentinel"
