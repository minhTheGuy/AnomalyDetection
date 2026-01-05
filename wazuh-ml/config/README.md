# Tệp Cấu hình

Thư mục này chứa các tệp cấu hình và tập lệnh thiết lập cho Hybrid NIDS.

## Các Tập Tin

- `action_config.env.example` - Ví dụ về biến môi trường cho cấu hình hành động
- `setup_actions.sh` - Tập lệnh thiết lập tương tác cho webhook, email, và wazuh
- `whitelist.txt` - Danh sách trắng các địa chỉ IP (không bao giờ bị chặn)
- `wazuh-ml.service` - Tệp dịch vụ systemd cho triển khai production
- `wazuh-ml.logrotate` - Cấu hình xoay vòng log

## Thiết lập Nhanh

### 1. Chạy Thiết lập Tương tác

```bash
bash config/setup_actions.sh
```

Điều này sẽ:
- Hỏi bạn về cấu hình webhook, email, và wazuh
- Tạo tệp `.env` với các cài đặt của bạn
- Cung cấp hướng dẫn sử dụng

### 2. Thiết lập Thủ công

```bash
# Sao chép tệp ví dụ
cp config/action_config.env.example .env

# Chỉnh sửa với cài đặt của bạn
nano .env
```

**Lưu ý:** Tệp `.env` được tự động tải bởi `python-dotenv` khi bạn chạy detection pipeline. Không cần phải source thủ công!

### 3. Sử dụng Cấu hình

```bash
# Chỉ cần chạy tập lệnh - .env được tải tự động!
python scripts/detection_pipeline.py --continuous \
    --action alert --action webhook --action email --action wazuh

python detection_pipeline.py --continuous --host 172.16.158.100 --user admin --interface em1     --action log --action alert --action email --action wazuh
```

Tập lệnh tự động tải các biến môi trường từ `.env` bằng cách sử dụng `python-dotenv`, vì vậy bạn không cần phải `source .env` (điều này có thể xung đột với việc kích hoạt môi trường ảo của bạn).

## Tài liệu

Xem [docs/ACTION_CONFIGURATION.md](../docs/ACTION_CONFIGURATION.md) để biết hướng dẫn cấu hình đầy đủ.
