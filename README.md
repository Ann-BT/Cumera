# Cumera

Cumera là bộ công cụ kiểm tra bảo mật mạng, phân tích giao thức truyền thông và đánh giá cấu hình thiết bị mạng & IoT.

## Cài đặt & Khởi chạy

### Windows

1. **Cài đặt lần đầu**: Nhấp đúp file `setup.bat`.
2. **Khởi chạy ứng dụng**:
   - Nhấp đúp `run_app.bat` hoặc icon **Cumera** trên Desktop (chạy cửa sổ ứng dụng riêng biệt).
3. **Cập nhật ứng dụng**:
   - Nhấn nút **[Cập nhật]** trực tiếp trên thanh công cụ của ứng dụng.
   - Hoặc nhấp đúp file `update.bat`.

### Linux / macOS

1. **Cài đặt**:
   ```bash
   ./setup.sh
   ```
2. **Khởi chạy**:
   ```bash
   ./run_app.sh
   ```
   *(Giao diện dòng lệnh: `./run_app.sh --cli` hoặc `./run_suite.sh`)*
3. **Cập nhật**:
   - Nhấn nút **[Cập nhật]** trên giao diện ứng dụng hoặc chạy `git pull origin main`.

## Tính năng chính

- Dò quét toàn diện cổng mạng và nhận diện dịch vụ TCP/UDP.
- Đánh giá độ an toàn của cấu hình xác thực và giao thức mã hóa (TLS, SSH).
- Phân tích luồng truyền thông mạng và xuất bằng chứng gói tin PCAP.
- Tự động kiểm tra và cập nhật ứng dụng trực tiếp từ GitHub.
