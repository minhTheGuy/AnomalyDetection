# Wazuh ML Security Analytics

Hệ thống Machine Learning để phát hiện và phân loại các sự kiện bảo mật bất thường từ Wazuh logs.

## Cấu Trúc Thư Mục

```
wazuh-ml/
├── core/                    # Core configuration
│   ├── config.py           # Cấu hình chính
│   └── env.example         # Template cho .env file
│
├── data_processing/         # Xử lý dữ liệu
│   ├── export_from_es.py   # Export logs từ Wazuh Indexer
│   ├── preprocessing.py    # Tiền xử lý dữ liệu
│   └── feature_engineering.py  # Feature engineering
│
├── training/                # Training models
│   ├── train_model.py      # Train anomaly detection model
│   ├── train_classifier.py # Train classification model
│   ├── train_all_models.py # Train cả 2 models
│   └── auto_retrain.py     # Tự động retrain
│
├── detection/               # Anomaly detection
│   ├── detect_anomaly.py   # Phát hiện anomalies
│   ├── ensemble_detector.py # Ensemble model (IF + LOF + SVM)
│   ├── anomaly_tuning.py   # Tinh chỉnh để giảm false positives
│   └── realtime_detector.py # Real-time detection
│
├── classification/          # Classification
│   ├── classification.py   # Module phân loại
│   └── classify_events.py  # Script phân loại events
│
├── llm/                     # LLM analysis
│   └── llm_analyze.py      # Phân tích anomalies bằng LLM
│
├── utils/                   # Utilities
│   ├── push_alert.py       # Gửi alerts về Wazuh
│   ├── evaluate.py         # Đánh giá models
│   └── main.py             # FastAPI server
│
├── docs/                    # Documentation
│   ├── USAGE.md            # Hướng dẫn sử dụng
│   ├── CLASSIFICATION.md   # Tài liệu classification
│   └── FEATURES_EXPLANATION.md  # Giải thích features
│
├── scripts/                 # Scripts
│   ├── setup_automation.sh # Setup automation
│   └── scenarios/          # Attack scenarios
│
├── tests/                   # Tests
│   └── test_anomaly_tuning.py
│
├── data/                    # Data files
│   ├── security_logs.csv
│   ├── security_logs_analyzed.csv
│   ├── model_isoforest.pkl
│   └── classifier_model.pkl
│
└── requirements.txt         # Python dependencies
```

## Quick Start

### 1. Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Copy và cấu hình .env
cp core/env.example .env
# Chỉnh sửa .env với thông tin Wazuh của bạn
```

### 2. Sử dụng main.py (Khuyến nghị)

```bash
# Hiển thị menu tương tác
python main.py --menu

# Hoặc chạy trực tiếp các commands
python main.py export              # Export logs
python main.py train-all           # Train cả 2 models
python main.py detect              # Detect anomalies
python main.py classify            # Classify events
python main.py realtime            # Real-time detection
python main.py evaluate            # Evaluate models
python main.py llm                 # LLM analysis
```

### 3. Hoặc chạy trực tiếp từ các modules

```bash
# Export Data
python data_processing/export_from_es.py

# Train Models
python training/train_all_models.py        # Train cả 2 models
python training/train_model.py             # Anomaly detection only
python training/train_classifier.py        # Classification only

# Detect Anomalies
python detection/detect_anomaly.py

# Classify Events
python classification/classify_events.py
```

## Modules

### Core
- **config.py**: Cấu hình chính (paths, API endpoints, model settings)

### Data Processing
- **export_from_es.py**: Export logs từ Wazuh Indexer/OpenSearch
- **preprocessing.py**: Tiền xử lý và encode dữ liệu
- **feature_engineering.py**: Tạo features từ raw data

### Training
- **train_model.py**: Train anomaly detection model (Isolation Forest/Ensemble)
- **train_classifier.py**: Train classification model (Attack types & Event categories)
- **train_all_models.py**: Train cả 2 models cùng lúc
- **auto_retrain.py**: Tự động retrain khi có data mới

### Detection
- **detect_anomaly.py**: Phát hiện anomalies với classification
- **ensemble_detector.py**: Ensemble model (IF + LOF + SVM)
- **anomaly_tuning.py**: Filter và tuning để giảm false positives
- **realtime_detector.py**: Real-time monitoring và detection

### Classification
- **classification.py**: Module phân loại (attack types, event categories)
- **classify_events.py**: Script phân loại events

### LLM
- **llm_analyze.py**: Phân tích và giải thích anomalies bằng LLM

### Utils
- **push_alert.py**: Gửi alerts về Wazuh Manager
- **evaluate.py**: Đánh giá models
- **main.py**: FastAPI server cho API endpoints

## Cấu Hình

Chỉnh sửa `core/config.py` hoặc tạo file `.env`:

```env
# Wazuh Indexer
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEX_PATTERN=wazuh-alerts-*
INDEXER_USER=admin
INDEXER_PASS=admin

# Model paths
CSV_PATH=data/security_logs.csv
MODEL_PATH=data/model_isoforest.pkl
CLASSIFIER_MODEL_PATH=data/classifier_model.pkl

# Model settings
MODEL_TYPE=ensemble  # 'ensemble' | 'single'
ENABLE_CLASSIFICATION=true
```

## Documentation

- [USAGE.md](docs/USAGE.md) - Hướng dẫn sử dụng chi tiết
- [CLASSIFICATION.md](docs/CLASSIFICATION.md) - Tài liệu classification model
- [FEATURES_EXPLANATION.md](docs/FEATURES_EXPLANATION.md) - Giải thích tất cả features

## Testing

```bash
pytest tests/
```

## Workflow

1. **Export** logs từ Wazuh → `data/security_logs.csv`
2. **Feature Engineering** → Tạo 71 features từ raw data
3. **Train Models** → Anomaly detection + Classification
4. **Detect** → Phát hiện và phân loại anomalies
5. **Analyze** → LLM phân tích và giải thích (optional)

## Features

- ✅ Anomaly Detection (Isolation Forest / Ensemble)
- ✅ Feature Engineering (71 features)
- ✅ Classification (Attack types & Event categories)
- ✅ LLM Analysis (Explain anomalies)
- ✅ Real-time Detection
- ✅ Auto Retrain

## License

MIT

