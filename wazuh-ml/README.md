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
│
├── training/                # Training models
│   ├── train_model.py      # Train ensemble anomaly detection
│   ├── train_autoencoder.py # Train reconstruction-based autoencoder
│   ├── train_classifier.py # Train classification model
│   ├── train_all_models.py # Train nhiều models cùng lúc
│   ├── auto_retrain.py     # Tự động retrain
│   └── feature_selection.py  # Feature selection (RFE)
│
├── detection/               # Anomaly detection
│   ├── detect_anomaly.py   # Phát hiện anomalies
│   ├── anomaly_tuning.py   # Tinh chỉnh để giảm false positives
│   └── realtime_detector.py # Real-time detection
│
├── classification/          # Classification
│   ├── classification.py   # Module phân loại
│   └── classify_events.py  # Script phân loại events
│
├── actions/                 # Action & Response System
│   ├── action_generator.py # Generate actions từ anomalies
│   ├── action_executor.py  # Execute actions (block IP/Port, notify)
│   ├── action_manager.py   # Quản lý actions
│   └── pfsense_integration.py  # Tích hợp với pfSense firewall
│
├── threat_intelligence/     # Threat Intelligence Feeds
│   └── feeds.py            # Tích hợp AbuseIPDB, VirusTotal, local feeds
│
├── llm/                    # AI-assisted investigation
│   ├── llm_analyze.py      # Generate investigation reports via LLM
│   └── provider.py         # DeepSeek/OpenAI adapters
│
├── utils/                   # Utilities
│   ├── evaluate.py         # Đánh giá models
│   ├── visualization.py    # Tạo visualizations (plots, charts)
│   └── main.py             # FastAPI server
│
├── tests/                   # Tests
│   ├── run_tests.py        # Test runner
│   ├── test_anomaly_detection.py  # Test anomaly detection
│   ├── test_anomaly_tuning.py     # Test anomaly tuning
│   ├── test_classification.py     # Test classification
│   └── test_integration.py        # Integration tests
│
├── data/                    # Data files
│   ├── security_logs.csv   # Raw security logs
│   ├── security_logs_raw.json  # Raw JSON logs
│   ├── security_logs_analyzed.csv  # Analyzed logs
│   ├── anomalies.csv       # Detected anomalies
│   ├── actions.csv         # Generated actions
│   ├── action_results.csv  # Action execution results
│   ├── action_logs.jsonl   # Action logs (JSONL format)
│   ├── model_isoforest.pkl # Anomaly detection model
│   ├── classifier_model.pkl  # Classification model
│   ├── feature_selector.pkl  # Feature selector
│   ├── labels/             # Classification labels
│   │   └── labels.csv
│   ├── threat_intel/       # Threat intelligence data
│   └── visualizations/     # Generated visualizations
│       ├── feature_importance.png
│       ├── confusion_matrix_count.png
│       ├── confusion_matrix_normalized.png
│       ├── classification_report.png
│       ├── class_distribution.png
│       └── roc_curves.png
│
├── main.py                  # Main entry point
├── requirements.txt         # Python dependencies
└── STRUCTURE.md             # Cấu trúc chi tiết
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
python main.py export              # Export logs từ Wazuh Indexer
python main.py train-all           # Train cả 2 models
python main.py detect              # Detect anomalies
python main.py classify            # Classify events
python main.py realtime            # Real-time detection
python main.py evaluate            # Evaluate models
python main.py test                # Run tests
python main.py threat-intel        # Check threat intelligence
python main.py generate-actions    # Generate actions from anomalies
python main.py transfer-learning   # Bootstrap model với Transfer Learning
python main.py feedback-loop       # Chạy Feedback Loop (Detect → Analyze → Tune → Retrain → Test)
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
- **feature_engineering.py**: Tạo features từ raw data (71 features)

### Training
- **train_model.py**: Train anomaly detection model (Isolation Forest/Ensemble)
- **train_classifier.py**: Train classification model (Attack types & Event categories)
- **train_all_models.py**: Train cả 2 models cùng lúc
- **auto_retrain.py**: Tự động retrain khi có data mới
- **feature_selection.py**: Feature selection với RFE (Recursive Feature Elimination)
- **transfer_learning.py**: Transfer Learning để bootstrap models từ pre-trained
- **feedback_loop.py**: Feedback Loop hoàn chỉnh (Detect → Analyze → Tune → Retrain → Test)

### Detection
- **detect_anomaly.py**: Phát hiện anomalies với classification
- **anomaly_tuning.py**: Filter và tuning để giảm false positives
- **realtime_detector.py**: Real-time monitoring và detection

### Classification
- **classification.py**: Module phân loại (attack types, event categories)
- **classify_events.py**: Script phân loại events

### Actions & Response
- **action_generator.py**: Tự động generate actions từ detected anomalies
- **action_executor.py**: Execute actions (block IP/Port trên pfSense, Telegram notify)
- **action_manager.py**: Quản lý và điều phối actions
- **pfsense_integration.py**: Tích hợp với pfSense firewall (SSH + pfctl hoặc API)

### Threat Intelligence
- **feeds.py**: Tích hợp threat intelligence feeds (AbuseIPDB, VirusTotal, local feeds)

### LLM
- **llm/provider.py**: Abstraction cho OpenAI/DeepSeek
- **llm/llm_analyze.py**: Sinh báo cáo SOC bằng LLM

### Utils
- **evaluate.py**: Đánh giá models
- **visualization.py**: Tạo visualizations (feature importance, confusion matrix, ROC curves)
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
MODEL_TYPE=ensemble  # 'ensemble' | 'single' | 'autoencoder'
ENABLE_CLASSIFICATION=true

# Action & Response
ENABLE_ACTIONS=true
ENABLE_AUTO_BLOCK=true
ENABLE_TELEGRAM=false
MIN_SEVERITY_FOR_BLOCK=3  # 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL

# pfSense Integration
ENABLE_PFSENSE=true
PFSENSE_METHOD=ssh  # 'ssh' | 'api'
PFSENSE_SSH_HOST=172.16.158.100
PFSENSE_SSH_USER=admin
PFSENSE_SSH_PASS=your_password

# Telegram (optional)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# LLM / DeepSeek (optional)
LLM_PROVIDER=deepseek
LLM_MODEL=deepseek-reasoner
DEEPSEEK_API_KEY=replace-me
DEEPSEEK_API_BASE=https://api.deepseek.com/v1
LLM_MAX_EVENTS=100
LLM_MAX_TOKENS=800
```

## Documentation

Xem các file trong thư mục `docs/` để biết thêm chi tiết:
- **USAGE.md** - Hướng dẫn sử dụng chi tiết
- **CLASSIFICATION.md** - Tài liệu classification model
- **FEATURES_EXPLANATION.md** - Giải thích tất cả features
- **ACTIONS_RESPONSE.md** - Action & Response System
- **PFSENSE_INTEGRATION.md** - Hướng dẫn tích hợp pfSense
- **ADVANCED_FEATURES.md** - Tính năng nâng cao
- **VISUALIZATION.md** - Tài liệu visualization
- **TRANSFER_LEARNING.md** - Transfer Learning để bootstrap models
- **FEEDBACK_LOOP.md** - Feedback Loop hoàn chỉnh

## Testing

```bash
# Chạy tất cả tests
python main.py test

# Hoặc chạy trực tiếp
python tests/run_tests.py

# Chạy test cụ thể
python -m unittest tests.test_anomaly_detection
python -m unittest tests.test_classification
python -m unittest tests.test_integration
```

## Workflow

1. **Export** logs từ Wazuh Indexer → `data/security_logs.csv`
2. **Feature Engineering** → Tạo 71 features từ raw data
3. **Train Models** → Anomaly detection (Isolation Forest/Ensemble) + Classification
   - Hoặc **Transfer Learning** → Bootstrap từ pre-trained model
4. **Detect** → Phát hiện và phân loại anomalies
5. **Generate Actions** → Tự động generate actions (block IP/Port, notify)
6. **Execute Actions** → Thực thi actions trên pfSense firewall
7. **Feedback Loop** → Analyze → Tune → Retrain → Test (cải thiện liên tục)
8. **Visualize** → Xem visualizations (feature importance, confusion matrix, ROC curves)

## Features

- ✅ **Anomaly Detection** - Isolation Forest / Ensemble (IF + LOF + SVM)
- ✅ **Feature Engineering** - 71 features từ raw logs
- ✅ **Classification** - Attack types & Event categories
- ✅ **Action & Response System** - Tự động generate và execute actions
- ✅ **pfSense Integration** - Block IP/Port trên pfSense firewall (SSH + pfctl)
- ✅ **Threat Intelligence** - Tích hợp AbuseIPDB, VirusTotal, local feeds
- ✅ **Visualization** - Feature importance, confusion matrix, ROC curves
- ✅ **Real-time Detection** - Real-time monitoring và detection
- ✅ **Auto Retrain** - Tự động retrain khi có data mới
- ✅ **Autoencoder Detection** - Reconstruction-based anomaly scoring
- ✅ **LLM Investigation** - DeepSeek/OpenAI phân tích log theo ngữ cảnh
- ✅ **Transfer Learning** - Bootstrap models từ pre-trained hoặc public datasets
- ✅ **Feedback Loop** - Chu trình hoàn chỉnh: Detect → Analyze → Tune → Retrain → Test
- ✅ **Test Automation** - Unit tests và integration tests

## License

MIT

