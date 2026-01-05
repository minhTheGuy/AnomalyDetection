# Wazuh-ML: Hệ thống NIDS Lai 3 Lớp

**Hệ thống Phát hiện Xâm nhập Mạng** thời gian thực kết hợp Học máy với phản ứng tự động.

## 🎯 Tính năng

- **Kiến trúc Phát hiện 3 Lớp**
  - Lớp 1: Isolation Forest (bộ lọc bất thường nhanh)
  - Lớp 2: VAE (Variational Auto Encoder) (phát hiện zero-day, Chọn lọc Đặc trưng + Cửa sổ trượt)
  - Lớp 3: XGBoost (phân loại tấn công đã biết, độ chính xác 95%+)

- **Giám sát Thời gian thực**: Thu thập qua SSH + tcpdump từ pfSense
- **Phân tích Luồng**: CICFlowMeter trích xuất 80+ đặc trưng mạng
- **Phản ứng Tự động**: Chặn IP, cảnh báo, webhook, tích hợp Wazuh
- **Phát hiện Tấn công**: DDoS, Port Scan, Brute Force, Web Attacks, Zero-day

## Startup

```bash
# 1. Cài đặt môi trường
source ~/mlenv/bin/activate
cd ./wazuh-ml  # Di chuyển đến thư mục dự án
pip install -r requirements.txt

# 2. Huấn luyện mô hình
jupyter notebook notebooks/train_cicids_final.ipynb      # XGBoost
jupyter notebook notebooks/train_anomaly_detector.ipynb  # VAE (với cửa sổ trượt)

# 3. Chạy phát hiện
python scripts/detection_pipeline.py --continuous --action alert
```

## Cấu trúc Dự án

```
wazuh-ml/
├── scripts/
│   ├── detection_pipeline.py      # Phát hiện chính (3 lớp)
│   ├── capture_labeled_traffic.py # Thu thập để tái huấn luyện
│   └── nids/                      # Các module cốt lõi
├── tests/                         # Kiểm thử Đơn vị & Tích hợp
│   ├── test_flows_detection.py
│   └── test_actions.py
├── notebooks/
│   ├── train_cicids_final.ipynb     # Huấn luyện XGBoost
│   └── train_anomaly_detector.ipynb # Huấn luyện & Phân tích VAE
├── data/
│   ├── cicids/                    # Dữ liệu huấn luyện CIC-IDS-2017
│   ├── models/                    # Mô hình đã huấn luyện (*_latest.*)
│   ├── captured/                  # Thu thập thời gian thực
│   └── labeled/                   # Dữ liệu huấn luyện đã gán nhãn
├── logs/                          # Cảnh báo & thống kê
├── config/                        # systemd, whitelist
└── docs/                          # Tài liệu
```

## Uses

### Phân tích tệp PCAP
```bash
python scripts/detection_pipeline.py --pcap capture.pcap
```

### Phát hiện thời gian thực với tính năng chặn
```bash
python scripts/detection_pipeline.py --continuous --action alert --action block
```

## Hiệu suất Mô hình

| Mô hình | Precision | Recall | F1-Score | Mục đích |
|-------|-----------|--------|----------|---------|
| Isolation Forest | 0.97 | 0.30 | 0.46 | Bộ lọc nhanh |
| **Optimized VAE** | **0.79** | **0.36*** | **0.49*** | Zero-day (với Ngữ cảnh) |
| XGBoost | 0.95+ | 0.95+ | 0.95+ | Tấn công đã biết |

*\*Chỉ số VAE trước khi tối ưu hóa cửa sổ trượt. Mong đợi độ thu hồi (recall) cao hơn với mô hình cửa sổ trượt mới.*

## Cấu hình

### Cài đặt Nhanh

**Script cài đặt tương tác:**
```bash
bash config/setup_actions.sh
```

**Hoặc sử dụng biến môi trường qua file .env:**
```bash
# Sao chép mẫu và chỉnh sửa
cp config/action_config.env.example .env
nano .env

# Chạy script - file .env được tự động tải bởi python-dotenv
python scripts/detection_pipeline.py --continuous --action alert
```

**Hoặc export trực tiếp (nếu muốn):**
```bash
export WEBHOOK_URL="https://your-server.com/api/alerts"
export EMAIL_TO="admin@example.com"
export WAZUH_API_URL="https://wazuh-manager:55000"
```

Xem [ACTION_CONFIGURATION.md](docs/ACTION_CONFIGURATION.md) để biết hướng dẫn cấu hình đầy đủ.

## Tài liệu

- [PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md) - Tài liệu đầy đủ
- [ACTION_CONFIGURATION.md](docs/ACTION_CONFIGURATION.md) - **Cài đặt Webhook, Email, Wazuh**
- [TESTING_ACTIONS.md](docs/TESTING_ACTIONS.md) - **Cách kiểm tra tính năng phản ứng**
- [WAZUH_SUPPRESS_RULES.md](docs/WAZUH_SUPPRESS_RULES.md) - **Chặn các quy tắc Wazuh ồn ào (ví dụ: xác thực SSH)**
- [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) - Cài đặt môi trường Production
- [MODEL_IMPROVEMENTS.md](docs/MODEL_IMPROVEMENTS.md) - Hướng dẫn tinh chỉnh

## 📂 Quản lý Dữ liệu

Để giữ cho repository sạch sẽ và nhẹ, các tệp sau đã được thêm vào `.gitignore` và sẽ **không** được đẩy lên git:

- **Bộ dữ liệu**: `data/cicids/`, `data/raw/`, `data/processed/`
- **Mô hình**: Tệp nhị phân lớn (`*.keras`, `*.pkl`) trong `data/models/`
- **Tệp Thu thập**: `data/captured/` (pcap và flows)
- **Log & Báo cáo**: `logs/`, `data/reports/`
- **Môi trường ảo**: `.venv`, `mlenv/`, `.env`

Khi clone dự án, cấu trúc thư mục sẽ được giữ nguyên (nhờ các tệp `.gitkeep`), nhưng bạn cần tải dữ liệu huấn luyện hoặc huấn luyện lại mô hình cục bộ.

## Cấu hình Mạng

| Thành phần | Địa chỉ IP |
|-----------|------------|
| pfSense Firewall | 172.16.158.100 |
| Wazuh Server | 172.16.158.150 |
| Gateway (whitelisted) | 172.16.158.1 |

---

*Được xây dựng với XGBoost, TensorFlow, và CICFlowMeter*
