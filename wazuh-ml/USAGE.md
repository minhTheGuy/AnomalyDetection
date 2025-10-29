# Wazuh ML - Hướng dẫn sử dụng nâng cao

## 🚀 Quick Start

### 1. Cài đặt dependencies

```bash
cd wazuh-ml
source ../mlenv/bin/activate
pip install -r requirements.txt
```

### 2. Chạy pipeline cơ bản

```bash
# Bước 1: Export dữ liệu từ Wazuh
python export_from_es.py

# Bước 2: Train model (với hyperparameter tuning)
python train_model.py

# Bước 3: Detect anomalies
python detect_anomaly.py
```

---

## 📊 Các tính năng mới

### ✨ Feature Engineering

File: `feature_engineering.py`

**Time Features:**
- `hour`, `day_of_week`, `minute` - Thời gian trong ngày/tuần
- `is_night`, `is_weekend`, `is_business_hours` - Phân loại thời gian

**Network Features:**
- `is_well_known_port`, `is_registered_port`, `is_dynamic_port` - Phân loại port
- `log_bytes`, `log_length` - Log transformation
- `is_internal_src/dst`, `is_internal_communication` - Internal/external traffic

**Event Features:**
- `event_desc_length`, `event_word_count` - Độ dài mô tả
- `danger_keyword_count` - Số từ nguy hiểm
- `is_auth_event`, `is_fim_event` - Loại event
- `severity_category` - Phân loại mức độ nghiêm trọng

**Sequence Features:**
- `time_delta` - Thời gian giữa các event
- `events_in_window` - Số event trong window
- `is_burst` - Phát hiện đột biến
- `event_velocity` - Tốc độ thay đổi

**Aggregated Features:**
- `agent_event_count`, `is_rare_agent` - Thống kê agent
- `src_ip_count`, `is_rare_src_ip` - Thống kê IP
- `agent_avg_rule_level` - Rule level trung bình

### 🔧 Hyperparameter Tuning

File: `train_model.py`

**Grid Search Parameters:**
```python
{
    'contamination': [0.03, 0.05, 0.07],      # Tỷ lệ anomaly
    'n_estimators': [100, 200, 300],          # Số trees
    'max_samples': ['auto', 256],             # Số samples cho mỗi tree
    'max_features': [0.8, 1.0]                # Tỷ lệ features
}
```

**Chạy với tuning:**
```bash
python train_model.py
```

**Chạy không tuning (nhanh hơn):**
```python
# Sửa trong train_model.py
train_model_with_tuning(enable_tuning=False)
```

### 🔄 Auto-Retrain

File: `auto_retrain.py`

**Tự động retrain khi:**
- Model file không tồn tại
- CSV data mới hơn model
- Model quá cũ (> 7 ngày mặc định)

**Cách sử dụng:**
```bash
# Retrain tự động (nếu cần)
python auto_retrain.py

# Force retrain
python auto_retrain.py --force

# Không fetch data mới
python auto_retrain.py --no-fetch

# Không hyperparameter tuning (nhanh hơn)
python auto_retrain.py --no-tuning

# Tùy chỉnh max age
python auto_retrain.py --max-age-days 14
```

### ⚡ Real-time Detection

File: `realtime_detector.py`

**Tính năng:**
- Poll Wazuh Indexer định kỳ
- Phát hiện anomaly ngay lập tức
- Graceful shutdown (Ctrl+C)
- Statistics tracking

**Cách sử dụng:**
```bash
# Chạy với cấu hình mặc định (poll mỗi 60s, lookback 5 phút)
python realtime_detector.py

# Tùy chỉnh interval và lookback
python realtime_detector.py --interval 30 --lookback 10

# Chạy trong nền
nohup python realtime_detector.py > realtime.log 2>&1 &
```

---

## 🤖 Automation Setup

### Systemd Service + Cron Jobs

**Cài đặt:**
```bash
# Chạy script setup (cần sudo)
sudo bash setup_automation.sh
```

**Systemd Service (Real-time Detector):**
```bash
# Start service
sudo systemctl start wazuh-ml-realtime

# Stop service
sudo systemctl stop wazuh-ml-realtime

# Check status
sudo systemctl status wazuh-ml-realtime

# Enable auto-start on boot
sudo systemctl enable wazuh-ml-realtime

# View logs
sudo journalctl -u wazuh-ml-realtime -f
```

**Cron Jobs:**
- **Auto-retrain:** Daily at 2:00 AM
- **Data export:** Every 6 hours

```bash
# Xem cron jobs
crontab -l

# Xem logs
tail -f logs/auto_retrain.log
tail -f logs/export.log
```

---

## 📈 Model Evaluation

### Metrics

Sau khi train, model sẽ hiển thị:
- Total samples
- Anomalies detected (count + ratio)
- Score range, mean, std
- Top anomalies

### Model Info

```python
import joblib
bundle = joblib.load('data/model_isoforest.pkl')

print(bundle.keys())
# ['model', 'encoders', 'best_params', 'metrics', 
#  'tuning_results', 'feature_names', 'training_date']

print(bundle['best_params'])
print(bundle['metrics'])
```

---

## 🔍 Troubleshooting

### Import errors

```bash
# Activate virtual environment
source ../mlenv/bin/activate

# Install missing packages
pip install -r requirements.txt
```

### Connection errors

```bash
# Check Wazuh Indexer
curl -k -u mlreader1234:MLreader123@ https://172.16.158.150:9200

# Verify config.py credentials
cat config.py
```

### Model not found

```bash
# Train model first
python train_model.py
```

### Real-time detector not detecting

```bash
# Check if there are new events
python export_from_es.py

# Check model is loaded
ls -lh data/model_isoforest.pkl

# Increase lookback window
python realtime_detector.py --lookback 30
```

---

## 📝 Best Practices

### 1. Regular Retraining

- Retrain model weekly với dữ liệu mới
- Monitor anomaly ratio (nên giữ 3-7%)

### 2. Feature Selection

- Kiểm tra feature importance
- Loại bỏ features không đóng góp

### 3. Hyperparameter Tuning

- Chạy tuning khi có dataset mới
- So sánh metrics trước/sau tuning

### 4. Real-time Monitoring

- Dùng systemd service cho production
- Monitor logs thường xuyên
- Setup alerting cho critical anomalies

---

## 🔗 Pipeline Flow

```
┌─────────────────┐
│ Wazuh Indexer   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ export_from_es  │ ◄──── Cron: Every 6h
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ feature_eng     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ preprocessing   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ train_model     │ ◄──── auto_retrain (Daily 2AM)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ detect_anomaly  │ ◄──── realtime_detector (Continuous)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ push_alert      │ ──► Wazuh Dashboard
└─────────────────┘
```

---

## 📚 Files Overview

| File | Purpose |
|------|---------|
| `config.py` | Configuration (URLs, credentials, paths) |
| `export_from_es.py` | Export logs from Wazuh Indexer |
| `feature_engineering.py` | **NEW** Advanced feature extraction |
| `preprocessing.py` | **UPDATED** Data cleaning & encoding |
| `train_model.py` | **UPDATED** Model training with tuning |
| `detect_anomaly.py` | Batch anomaly detection |
| `auto_retrain.py` | (working) |
| `realtime_detector.py` | **NEW** Real-time detection |
| `push_alert.py` | Send alerts to Wazuh |
| `setup_automation.sh` | (working) |

---

**Last Updated:** October 28, 2025
