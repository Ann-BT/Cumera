#!/usr/bin/env bash
# ==============================================================================
# Script khởi tạo môi trường tự động cho Linux & macOS
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "  CÀI ĐẶT MÔI TRƯỜNG: BỘ ĐO KIỂM AN TOÀN CAMERA (QCVN 11)"
echo "=========================================================="

# Kiểm tra Python 3
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[-] Lỗi: Không tìm thấy Python 3 trên hệ thống!"
    echo "    Vui lòng cài đặt Python >= 3.9 (ví dụ: sudo apt install python3 python3-venv python3-pip)"
    exit 1
fi

PY_VER=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[*] Phát hiện Python phiên bản: $PY_VER"

# Tạo virtualenv .venv nếu chưa có
if [ ! -d ".venv" ]; then
    echo "[*] Đang khởi tạo môi trường ảo Python (.venv)..."
    $PYTHON_CMD -m venv .venv
fi

# Cài đặt thư viện
echo "[*] Đang cài đặt các thư viện từ requirements.txt..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

# Khởi tạo config.json từ template nếu chưa có
if [ ! -f "config.json" ] && [ -f "config.example.json" ]; then
    echo "[*] Khởi tạo config.json từ file mẫu config.example.json..."
    cp config.example.json config.json
fi

# Khởi tạo thư mục captures nếu chưa có
mkdir -p captures/evidence/ComMech captures/evidence/AuthMech

# Đăng ký icon và ứng dụng Cumera vào hệ thống Linux
if [ -d "$HOME/.local/share/applications" ]; then
    echo "[*] Đang đăng ký ứng dụng Cumera vào hệ thống Desktop Linux..."
    mkdir -p "$HOME/.local/share/icons/hicolor/256x256/apps"
    cp -f assets/icon.png "$HOME/.local/share/icons/cumera.png" 2>/dev/null || true
    cp -f assets/icon.png "$HOME/.local/share/icons/hicolor/256x256/apps/cumera.png" 2>/dev/null || true
    cat << EOF > "$HOME/.local/share/applications/cumera.desktop"
[Desktop Entry]
Name=Cumera
GenericName=Camera Cybersecurity Audit Suite
Comment=Bộ công cụ đo kiểm an toàn bảo mật & mật mã camera IP (QCVN 11:2026/BCA)
Exec=$DIR/run_app.sh
Icon=cumera
Terminal=false
Type=Application
Categories=Network;Security;Utility;
Keywords=cumera;camera;audit;qcvn11;security;
StartupWMClass=cumera
EOF
    rm -f "$HOME/.local/share/applications/qcvn11-camera-auditor.desktop"
    update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi

# Phân quyền thực thi cho các script
chmod +x run_app.sh run_suite.sh setup.sh *.py 2>/dev/null || true

echo ""
echo "[OK] Hoàn tất cài đặt môi trường thành công!"
echo "Bạn có thể khởi chạy bộ công cụ bằng một trong các cách sau:"
echo "    1. Giao diện Đồ họa Desktop (Khuyên dùng):  ./run_app.sh"
echo "    2. Giao diện Terminal TUI:                  ./run_app.sh --cli"
echo "    3. Menu điều khiển dòng lệnh CLI:           ./run_suite.sh"
echo "=========================================================="
