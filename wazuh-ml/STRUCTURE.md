# Cấu Trúc Thư Mục - Giải Thích

## Tổ Chức Theo Chức Năng

### `core/` - Core Configuration
Các file cấu hình chính của hệ thống:
- `config.py`: Tất cả cấu hình (paths, API endpoints, model settings)
- `env.example`: Template cho file .env

### `data_processing/` - Xử Lý Dữ Liệu
Các module xử lý và chuẩn bị dữ liệu:
- `export_from_es.py`: Export logs từ Wazuh Indexer/OpenSearch
- `preprocessing.py`: Tiền xử lý, encode text, chọn features
- `feature_engineering.py`: Tạo features từ raw data (time, network, event, sequence, aggregated)

### `training/` - Training Models
Các script để train ML models:
- `train_model.py`: Train anomaly detection model (Isolation Forest/Ensemble)
- `train_classifier.py`: Train classification model (Attack types & Event categories)
- `train_all_models.py`: Train cả 2 models cùng lúc
- `auto_retrain.py`: Tự động retrain khi có data mới

### `detection/` - Anomaly Detection
Các module phát hiện anomalies:
- `detect_anomaly.py`: Main detection script với classification
- `ensemble_detector.py`: Ensemble model (IF + LOF + SVM)
- `anomaly_tuning.py`: Filter và tuning để giảm false positives
- `realtime_detector.py`: Real-time monitoring và detection

### `classification/` - Classification
Các module phân loại sự kiện:
- `classification.py`: Module phân loại (attack types, event categories)
- `classify_events.py`: Script phân loại events

### `llm/` - LLM Analysis
Phân tích và giải thích bằng LLM:
- `llm_analyze.py`: Phân tích anomalies và tạo reports

### `utils/` - Utilities
Các utility functions:
- `push_alert.py`: Gửi alerts về Wazuh Manager
- `evaluate.py`: Đánh giá models
- `main.py`: FastAPI server cho API endpoints

### `docs/` - Documentation
Tài liệu:
- `USAGE.md`: Hướng dẫn sử dụng
- `CLASSIFICATION.md`: Tài liệu classification model
- `FEATURES_EXPLANATION.md`: Giải thích tất cả features

### `scripts/` - Scripts
Các scripts automation:
- `setup_automation.sh`: Setup automation
- `scenarios/`: Attack scenarios để test

### `tests/` - Tests
Unit tests:
- `test_anomaly_tuning.py`: Test anomaly tuning

### `data/` - Data Files
Dữ liệu và models:
- `security_logs.csv`: Raw logs
- `security_logs_analyzed.csv`: Logs đã được phân tích
- `model_isoforest.pkl`: Trained anomaly detection model
- `classifier_model.pkl`: Trained classification model

## Workflow

```
1. data_processing/export_from_es.py
   ↓
2. data_processing/feature_engineering.py
   ↓
3. training/train_model.py + training/train_classifier.py
   ↓
4. detection/detect_anomaly.py
   ↓
5. classification/classify_events.py (optional)
   ↓
6. llm/llm_analyze.py (optional)
```

## Cách Sử Dụng

### Từ root directory:

```bash
# Sử dụng helper script
python run.py export
python run.py train-all
python run.py detect
python run.py classify

# Hoặc chạy trực tiếp
python data_processing/export_from_es.py
python training/train_all_models.py
python detection/detect_anomaly.py
python classification/classify_events.py
```

### Import trong code:

```python
# Tất cả imports đã được cập nhật với relative paths
from core.config import CSV_PATH, MODEL_PATH
from data_processing.preprocessing import preprocess_dataframe
from detection.detect_anomaly import detect
from classification.classification import create_classification_labels
```

## Lợi Ích

1. **Tổ chức rõ ràng**: Mỗi module có thư mục riêng
2. **Dễ maintain**: Dễ tìm và sửa code
3. **Scalable**: Dễ thêm features mới
4. **Professional**: Cấu trúc chuẩn Python project

