#!/usr/bin/env bash
# Khởi chạy Giao diện Ứng dụng Đo kiểm An toàn Camera IP (QCVN 11:2026/BCA)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$DIR")"

# Tự động nhận diện môi trường ảo Python
if [ -f "$DIR/.venv/bin/python" ]; then
    VENV_PY="$DIR/.venv/bin/python"
elif [ -f "$PARENT_DIR/.venv/bin/python" ]; then
    VENV_PY="$PARENT_DIR/.venv/bin/python"
elif command -v python3 > /dev/null 2>&1; then
    VENV_PY="python3"
else
    VENV_PY="python"
fi

PORT=8765
SERVER_URL="http://127.0.0.1:${PORT}"

# Chế độ dòng lệnh (CLI/TUI) nếu người dùng truyền cờ --cli hoặc --tui
if [ "$1" = "--cli" ] || [ "$1" = "--tui" ]; then
    shift
    printf "\033]0;Camera Security Auditor (TUI)\007"
    exec "$VENV_PY" "$DIR/toolkit_app.py" "$@"
fi

# 1. Kiểm tra Backend Web Server đã chạy hay chưa
if ! curl -s --max-time 0.8 "${SERVER_URL}/api/status" > /dev/null 2>&1; then
    nohup "$VENV_PY" "$DIR/toolkit_web_server.py" > /tmp/toolkit_web_server.log 2>&1 &
    # Đợi server sẵn sàng tối đa 3 giây
    for i in {1..15}; do
        if curl -s --max-time 0.5 "${SERVER_URL}/api/status" > /dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
fi

export FONTCONFIG_PATH=/etc/fonts

# 2. Khởi chạy Giao diện App Window độc lập (Native App Mode)
CHROME_FLAGS="--no-first-run --no-default-browser-check --disable-features=Translate --disable-sync"

if [ -x "/usr/bin/vivaldi" ]; then
    exec /usr/bin/vivaldi --app="${SERVER_URL}" --class=camera-security-auditor "$@"
elif [ -x "/usr/bin/google-chrome" ]; then
    exec /usr/bin/google-chrome --app="${SERVER_URL}" --class=camera-security-auditor --user-data-dir="/tmp/camera_auditor_chrome_profile" $CHROME_FLAGS "$@"
elif [ -x "/usr/bin/chromium" ]; then
    exec /usr/bin/chromium --app="${SERVER_URL}" --class=camera-security-auditor --user-data-dir="/tmp/camera_auditor_chrome_profile" $CHROME_FLAGS "$@"
elif [ -x "/usr/bin/epiphany" ]; then
    exec /usr/bin/epiphany --application-mode "${SERVER_URL}" "$@"
elif command -v xdg-open > /dev/null 2>&1; then
    exec xdg-open "${SERVER_URL}"
else
    # Fallback cuối cùng nếu không có trình duyệt đồ họa
    exec "$VENV_PY" "$DIR/toolkit_app.py" "$@"
fi
