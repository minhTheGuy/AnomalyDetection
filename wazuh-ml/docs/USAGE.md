# Wazuh ML - Hướng dẫn sử dụng nâng cao

## Quick Start

### 1. Cài đặt dependencies

```bash
cd wazuh-ml
source ../mlenv/bin/activate
pip install -r requirements.txt
```

### 1.1. Cấu hình secrets qua môi trường (.env)

Tạo file `.env` (tham khảo `.env.example`) tại thư mục `wazuh-ml/`:

```env
# Wazuh Indexer (OpenSearch)
WAZUH_INDEXER_URL=https://172.16.158.150:9200
WAZUH_INDEX_PATTERN=wazuh-alerts-*
INDEXER_USER=mlreader1234
INDEXER_PASS=REPLACE_ME

# Wazuh Manager API (push alerts)
WAZUH_MANAGER_API=https://172.16.158.150:55000
WAZUH_MANAGER_USER=wazuh
WAZUH_MANAGER_PASS=REPLACE_ME

# SSL options
# VERIFY_SSL=true để bật kiểm tra chứng chỉ trong production
VERIFY_SSL=false
# Nếu VERIFY_SSL=true và dùng cert self-signed, chỉ định CA bundle (PEM)
# CA_BUNDLE_PATH=/path/to/ca.pem

# Data paths (tùy chọn)
RAW_JSON_PATH=data/security_logs_raw.json
CSV_PATH=data/security_logs.csv
ANALYZED_CSV_PATH=data/security_logs_analyzed.csv
MODEL_PATH=data/model_isoforest.pkl

# Training options
# MODEL_TYPE: ensemble | single (mặc định: ensemble)
MODEL_TYPE=ensemble
# Nếu dùng single (IsolationForest), có chuẩn hóa đầu vào không? (mặc định: true)
SINGLE_IF_NORMALIZE=true
```

---

## Chọn loại mô hình và chuẩn hóa

### Ensemble (mặc định)
- Đặt trong `.env`:
```env
MODEL_TYPE=ensemble
```
- Gồm 3 thuật toán: IsolationForest + LOF + One-Class SVM, có voting (2/3 hoặc 3/3 trong quá trình train).
- Phù hợp để giảm false positive và có đồng thuận mô hình.

### IsolationForest đơn (single) với chuẩn hóa
- Đặt trong `.env`:
```env
MODEL_TYPE=single
SINGLE_IF_NORMALIZE=true
```
- Khi `SINGLE_IF_NORMALIZE=true`, dữ liệu đầu vào sẽ được chuẩn hóa bằng StandardScaler trong quá trình train và được áp dụng cùng scaler khi detect.
- Nếu muốn tắt chuẩn hóa: `SINGLE_IF_NORMALIZE=false`.

Gợi ý: Dùng `ensemble` cho production; `single` cho môi trường test/nhanh hoặc khi tài nguyên hạn chế.

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

## Các tính năng mới

### Feature Engineering

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

### Hyperparameter Tuning

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

## Model Evaluation

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

## Traffic Scenarios (Benign/Attack) + Auto-labeling

Chạy:

```bash
cd wazuh-ml/scenarios
chmod +x benign.sh attacks.sh wan_attacks.sh run_all.sh

# Sinh traffic benign
./benign.sh

# Sinh traffic attack (nhẹ, có kiểm soát)
./attacks.sh

# Sinh traffic attack từ phía WAN vào pfSense (mặc định WAN_IP=192.168.180.129)
WAN_IP=192.168.180.129 ./wan_attacks.sh

# Orchestrate tất cả và export logs (lặp 3 vòng, nghỉ 30s giữa các bước)
./run_all.sh --loops 3 --sleep 30 --wan 192.168.180.129
```

Kết quả nhãn lưu tại: `wazuh-ml/data/labels/labels.csv` với các cột:
`run_id,type,start_ts,end_ts,src_ip,notes`

Bạn có thể dùng `start_ts/end_ts` để lọc log tương ứng trong `security_logs.csv` để phân loại hoặc cập nhật whitelist/suspicious patterns.

Automation gợi ý (cron):
```cron
# Mỗi đêm 2h chạy 1 vòng sinh traffic nhẹ và export logs
0 2 * * * cd /home/dangminh0113/Desktop/DACNTT/wazuh-ml/scenarios && ./run_all.sh --loops 1 --sleep 20 --wan 192.168.180.129 >> /tmp/traffic.log 2>&1
```

---

## LLM Investigation (optional)

Thiết lập `.env`:
```env
LLM_PROVIDER=openai   # hoặc local
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=REPLACE_ME
LLM_MAX_EVENTS=100
```

Chạy phân tích:
```bash
cd wazuh-ml
python llm_analyze.py --since 2025-11-01T00:00:00 --limit 10 --window 15 --out data/anomaly_reports

# Gửi tóm tắt ngắn lên Wazuh (tùy chọn)
python llm_analyze.py --limit 5 --post-alert
```

Kết quả: file Markdown trong `data/anomaly_reports/` chứa Summary, Root Cause, FP Risk, Evidence, Actions.

## Best Practices

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

## Pipeline Flow

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

## Files Overview

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
| `llm_analyze.py` | Generate LLM investigation reports for anomalies |
| `scenarios/run_all.sh` | Orchestrate benign/attack/WAN traffic + export logs |
