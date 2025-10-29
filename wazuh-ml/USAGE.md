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
│ export_from_es  │ ◄──── Cron: Every 6h (planning)
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
│ train_model     │ ◄──── auto_retrain (planning)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ detect_anomaly  │ ◄──── realtime_detector (planning)
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
