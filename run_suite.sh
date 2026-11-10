#!/usr/bin/env bash
# Quick launcher for QCVN 11 Camera Audit Suite on Linux/macOS
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$DIR")"

if [ -f "$DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$DIR/.venv/bin/python"
elif [ -f "$PARENT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$PARENT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
else
    PYTHON_BIN="python"
fi

exec "$PYTHON_BIN" "$DIR/toolkit_menu.py" "$@"
