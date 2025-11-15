# Classification Model Documentation

## Tổng quan

Module classification được thêm vào để phân loại sự kiện bảo mật thành các loại tấn công và danh mục sự kiện. Đây là **Giai đoạn 3** của dự án.

## Tính năng

### 1. Phân loại Attack Types (Loại tấn công)

Model phân loại sự kiện thành các loại tấn công sau:

- **brute_force**: Tấn công brute force, failed password, authentication failure
- **port_scan**: Port scanning, network scanning, nmap
- **sql_injection**: SQL injection attacks
- **xss**: Cross-site scripting attacks
- **dos_ddos**: Denial of service attacks, flooding
- **malware**: Malware, virus, trojan, ransomware
- **privilege_escalation**: Privilege escalation attempts
- **data_exfiltration**: Data exfiltration, data leaks
- **web_attack**: Web attacks, web vulnerabilities
- **suspicious_activity**: Suspicious or anomalous activities
- **benign**: Sự kiện bình thường, không phải tấn công

### 2. Phân loại Event Categories (Danh mục sự kiện)

Model phân loại sự kiện thành các danh mục:

- **authentication**: Login, logout, authentication events
- **file_integrity**: File integrity monitoring, file changes
- **network**: Network events, connections, firewall
- **system**: System events, processes, services
- **compliance**: Compliance checks, CIS benchmarks
- **vulnerability**: Vulnerability detections, CVEs
- **malware_detection**: Malware detection events
- **web**: Web server events, HTTP/HTTPS
- **other**: Các sự kiện khác

## Cấu trúc Files

```
wazuh-ml/
├── classification.py          # Module phân loại (pattern matching, label extraction)
├── train_classifier.py        # Script huấn luyện classification models
├── classify_events.py         # Script phân loại sự kiện mới
├── train_all_models.py        # Script train cả anomaly + classification
└── data/
    └── classifier_model.pkl   # Trained classification models
```

## Sử dụng

### 1. Train Classification Model

```bash
# Train chỉ classification model
python train_classifier.py

# Train cả anomaly detection và classification
python train_all_models.py

# Train không tuning (nhanh hơn)
python train_all_models.py --no-tuning
```

### 2. Phân loại sự kiện

```bash
# Phân loại sự kiện từ CSV
python classify_events.py

# Hoặc sử dụng trong code
from classification.classify_events import classify
results = classify()
```

### 3. Tích hợp với Anomaly Detection

Classification được tích hợp tự động vào `detect_anomaly.py`. Khi chạy detection, các anomalies sẽ được phân loại:

```bash
python detect_anomaly.py
```

Kết quả sẽ bao gồm:
- `predicted_attack_type`: Loại tấn công được dự đoán
- `attack_type_confidence`: Độ tin cậy của prediction
- `predicted_event_category`: Danh mục sự kiện
- `event_category_confidence`: Độ tin cậy của prediction

## Cấu hình

Trong `config.py` hoặc `.env`:

```python
# Đường dẫn đến classification model
CLASSIFIER_MODEL_PATH = "data/classifier_model.pkl"

# Bật/tắt classification trong detect_anomaly.py
ENABLE_CLASSIFICATION = true  # true | false
```

## Model Architecture

### Classification Models

- **Algorithm**: Random Forest Classifier
- **Hyperparameter Tuning**: GridSearchCV với 5-fold cross-validation
- **Features**: Sử dụng cùng features như anomaly detection model
- **Evaluation Metrics**: 
  - Accuracy
  - F1-macro score
  - Classification report (precision, recall, F1 per class)

### Label Extraction

Labels được tạo tự động từ:
1. **Event descriptions**: Pattern matching với regex
2. **Rule groups**: Mapping trực tiếp từ Wazuh rule groups
3. **Fallback**: Nếu không match, gán "benign" hoặc "other"

## Workflow

```
1. Data Collection (CSV)
   ↓
2. Feature Engineering
   ↓
3. Label Extraction (classification.py)
   ↓
4. Train Classifiers (train_classifier.py)
   ├── Attack Type Classifier
   └── Event Category Classifier
   ↓
5. Save Models (classifier_model.pkl)
   ↓
6. Inference (classify_events.py hoặc detect_anomaly.py)
```

## Ví dụ Output

```
ATTACK TYPES:
  benign              : 1234 events (avg confidence: 95.23%)
  brute_force         :   45 events (avg confidence: 87.12%)
  port_scan           :   12 events (avg confidence: 92.45%)
  sql_injection       :    3 events (avg confidence: 78.90%)

EVENT CATEGORIES:
  authentication      :  234 events (avg confidence: 91.23%)
  file_integrity      :  156 events (avg confidence: 88.45%)
  network             :  123 events (avg confidence: 85.67%)
  system              :  456 events (avg confidence: 93.21%)
```

## Tích hợp với Anomaly Detection

Khi chạy `detect_anomaly.py` với `ENABLE_CLASSIFICATION=true`:

1. Anomaly detection chạy trước
2. Classification chạy trên tất cả events
3. Anomalies được hiển thị kèm classification results
4. Summary statistics cho attack types và categories trong anomalies

## Cải tiến tương lai

- [ ] Thêm more attack types (phishing, APT, etc.)
- [ ] Fine-tune với labeled data từ security experts
- [ ] Ensemble classification models
- [ ] Real-time classification streaming
- [ ] Confidence threshold filtering
- [ ] Multi-label classification (một event có thể thuộc nhiều categories)
