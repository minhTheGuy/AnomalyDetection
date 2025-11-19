# Cấu Trúc Thư Mục - Giải Thích

## Tổ Chức Theo Chức Năng

### `core/` - Core Configuration
Các file cấu hình chính của hệ thống:
- `config.py`: Tất cả cấu hình (paths, API endpoints, model settings, action parameters)
- `env.example`: Template cho file .env

### `data_processing/` - Xử Lý Dữ Liệu
Các module xử lý và chuẩn bị dữ liệu:
- `export_from_es.py`: Export logs từ Wazuh Indexer/OpenSearch
- `preprocessing.py`: Tiền xử lý, encode text, chọn features, scaling
- `feature_engineering.py`: Tạo features từ raw data (time, network, event, sequence, aggregated)
- `common.py`: Utilities chung cho data processing (align features, load data)
- `generate_synthetic_data.py`: Tạo dữ liệu synthetic để test và training

### `training/` - Training Models
Các script để train ML models:
- `train_model.py`: Train anomaly detection model (Isolation Forest, LOF, One-Class SVM, Ensemble)
- `train_classifier.py`: Train classification model (Attack types & Event categories)
- `train_autoencoder.py`: Train autoencoder model cho anomaly detection
- `train_all_models.py`: Train tất cả models cùng lúc (anomaly + classifier + autoencoder)
- `auto_retrain.py`: Tự động retrain khi có data mới
- `transfer_learning.py`: Transfer learning từ source domain sang target domain
- `feedback_loop.py`: Feedback loop để cải thiện models (Detect → Analyze → Tune → Retrain)
- `feature_selection.py`: Feature selection sử dụng RFE/RFECV
- `common.py`: Utilities chung cho training (load data, align features, save models)

### `detection/` - Anomaly Detection
Các module phát hiện anomalies:
- `detect_anomaly.py`: Main detection script - phát hiện anomalies từ logs
- `anomaly_tuning.py`: Filter và tuning để giảm false positives, dynamic thresholding
- `anomaly_patterns.py`: Pattern matching cho các loại attacks phổ biến
- `realtime_detector.py`: Real-time monitoring và detection từ Wazuh Indexer

### `classification/` - Classification
Các module phân loại sự kiện:
- `classification.py`: Module phân loại (attack types, event categories) với confidence scores
- `classify_events.py`: Script phân loại events từ anomalies
- `patterns.py`: Pattern matching rules cho classification

### `llm/` - LLM Analysis
Phân tích và giải thích bằng LLM (DeepSeek-R1):
- `llm_analyze.py`: Phân tích anomalies và tạo reports chi tiết
- `provider.py`: LLM provider abstraction - gọi DeepSeek-R1 API

### `actions/` - Action & Response System
Hệ thống tự động phản ứng với threats:
- `action_manager.py`: Quản lý và điều phối actions
- `action_generator.py`: Tạo actions dựa trên anomalies và classifications
- `action_executor.py`: Thực thi actions (block IP/Port, alert, escalate)
- `pfsense_integration.py`: Tích hợp với pfSense để block IP/Port qua SSH hoặc API
- `README.md`: Tài liệu về action system

### `threat_intelligence/` - Threat Intelligence
Tích hợp threat intelligence feeds:
- `feeds.py`: Quản lý threat intelligence feeds (AbuseIPDB, VirusTotal, local feeds)

### `utils/` - Utilities
Các utility functions:
- `common.py`: Common utilities (print headers, safe load/save, file operations)
- `evaluate.py`: Đánh giá models (metrics, performance analysis)
- `visualization.py`: Tạo visualizations (confusion matrix, ROC curves, feature importance)
- `main.py`: FastAPI server cho API endpoints

### `docs/` - Documentation
Tài liệu chi tiết:
- `USAGE.md`: Hướng dẫn sử dụng
- `CLASSIFICATION.md`: Tài liệu classification model
- `FEATURES_EXPLANATION.md`: Giải thích tất cả features
- `ACTIONS_RESPONSE.md`: Tài liệu về action & response system
- `ADVANCED_FEATURES.md`: Các tính năng nâng cao
- `FEEDBACK_LOOP.md`: Tài liệu về feedback loop
- `MODEL_IMPROVEMENTS.md`: Cải tiến models
- `PFSENSE_INTEGRATION.md`: Tích hợp pfSense
- `SYNTHETIC_DATA.md`: Tạo synthetic data
- `TRAINING_EVALUATION.md`: Đánh giá training
- `TRANSFER_LEARNING.md`: Transfer learning
- `VISUALIZATION.md`: Visualization
- `DOMAIN_ADAPTATION_ANALYSIS.md`: Phân tích domain adaptation

### `scripts/` - Scripts
Các scripts automation:
- `setup_automation.sh`: Setup automation
- `scenarios/`: Attack scenarios để test
  - `attacks.sh`: Simulate attacks
  - `benign.sh`: Simulate benign traffic
  - `wan_attacks.sh`: WAN attacks scenarios
  - `run_all.sh`: Run all scenarios
  - `USAGE.md`: Hướng dẫn sử dụng scenarios

### `tests/` - Tests
Unit tests và integration tests:
- `test_anomaly_detection.py`: Test anomaly detection
- `test_anomaly_tuning.py`: Test anomaly tuning
- `test_classification.py`: Test classification
- `test_integration.py`: Integration tests
- `run_tests.py`: Script chạy tất cả tests

### `data/` - Data Files
Dữ liệu và models:
- `security_logs.csv`: Raw logs từ Wazuh
- `security_logs_analyzed.csv`: Logs đã được phân tích
- `security_logs_raw.json`: Raw JSON logs
- `anomalies.csv`: Detected anomalies
- `actions.csv`: Generated actions
- `action_results.csv`: Action execution results
- `action_logs.jsonl`: Action logs
- `model_isoforest.pkl`: Trained ensemble anomaly detection model
- `model_isoforest_autoencoder.pkl`: Trained autoencoder model
- `model_isoforest_iforest.pkl`: Isolation Forest model
- `model_isoforest_lof.pkl`: LOF model
- `model_isoforest_svm.pkl`: One-Class SVM model
- `classifier_model.pkl`: Trained classification model
- `feature_selector.pkl`: Feature selector model
- `anomaly_reports/`: LLM-generated anomaly analysis reports
- `visualizations/`: Generated visualization files
- `labels/labels.csv`: Manual labels cho training
- `threat_intel/`: Threat intelligence data
- `scheduled_rules.json/`: Scheduled pfSense rules
- `tuning_history.json`: Anomaly tuning history
- `performance_analysis.json`: Model performance analysis
- `feedback_loop_iteration_*.json`: Feedback loop iterations

### Root Files
- `main.py`: Main entry point - menu-driven interface
- `README.md`: Project overview và quick start
- `requirements.txt`: Python dependencies
- `STRUCTURE.md`: Tài liệu này
- `TEST_RESULTS.md`: Kết quả tests

## Workflow

```
1. data_processing/export_from_es.py
   ↓ Export logs từ Wazuh Indexer
2. data_processing/feature_engineering.py
   ↓ Tạo features (time, network, event, sequence, aggregated)
3. data_processing/preprocessing.py
   ↓ Tiền xử lý, encode, scale, select features
4. training/train_model.py + training/train_autoencoder.py
   ↓ Train anomaly detection models
5. training/train_classifier.py
   ↓ Train classification models
6. detection/detect_anomaly.py
   ↓ Phát hiện anomalies
7. classification/classify_events.py (optional)
   ↓ Phân loại anomalies
8. llm/llm_analyze.py (optional)
   ↓ Phân tích bằng LLM và tạo reports
9. actions/action_manager.py (optional)
   ↓ Tạo và thực thi actions
```

## Lợi Ích

1. **Tổ chức rõ ràng**: Mỗi module có thư mục riêng theo chức năng
2. **Dễ maintain**: Dễ tìm và sửa code
3. **Scalable**: Dễ thêm features mới
4. **Professional**: Cấu trúc chuẩn Python project
5. **Modular**: Các module độc lập, có thể sử dụng riêng lẻ
6. **Testable**: Có đầy đủ tests cho các components chính
