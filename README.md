# Xây dựng hệ thống phát hiện bất thường (Anomaly Detection) cho Wazuh + Suricata + pfSense

Hệ thống này kết hợp hạ tầng firewall/IDS (pfSense + Suricata) với bộ Wazuh All-in-One và một pipeline Machine Learning chuyên biệt để:

- Thu thập, làm giàu và chuẩn hóa log bảo mật (trên 70 features/record).
- Huấn luyện song song mô hình phát hiện bất thường (ensemble Isolation Forest + LOF + One-Class SVM + Autoencoder) và mô hình phân loại (attack type, event category).
- Tự động hóa vòng đời vận hành: phát hiện → phân loại → sinh hành động → phản hồi về Wazuh/pfSense → feedback loop/tự động retrain.
- Phân tích chuyên sâu bằng threat intelligence và LLM để hỗ trợ giảng dạy SOC mini lab.

---

## 1. Môi trường lab

### **2.1. Hạ tầng lab:**

#### **A. pfSense Firewall/Router**

![pfSense Dashboard](imgs/systems/pfsense_dashboard.png)

**Thông tin hệ thống:**
- **Phiên bản:** pfSense 2.7.2-RELEASE (amd64)
- **Nền tảng:** FreeBSD 14.0-CURRENT
- **Deployment:** VMware Virtual Machine
- **CPU:** AMD Ryzen 5 5500U (2 cores)
- **Netgate Device ID:** 897b19f8b56db4a14c13

**Cấu hình Network:**
- **WAN Interface (em0):** 192.168.180.129/24 (kết nối Internet qua VMware NAT)
- **LAN Interface (em1):** 172.16.158.100/24 (mạng nội bộ)
- **DNS Servers:** 127.0.0.1, 192.168.180.2, 8.8.8.8

![pfSense VMware Console](imgs/systems/pfsense_core.png)

**Tính năng đã triển khai:**
- Suricata IDS/IPS (phát hiện xâm nhập)
- Firewall rules cho WAN/LAN
- Traffic monitoring và logging

---

#### **B. Wazuh All-in-One Server**

![Wazuh Services Status](imgs/systems/wazuh_services.png)

**Thông tin hệ thống:**
- **IP Address:** 172.16.158.150
- **Platform:** VMware Virtual Machine
- **OS:** Ubuntu/Debian-based Linux

**Các service đang chạy:**

1. **Wazuh Manager** (`wazuh-manager.service`)
   - Status: ✅ Active (running)
   - PID: 114087
   - Memory: ~1.0G
   - Modules:
     - `wazuh-syscheckd` - File Integrity Monitoring
     - `wazuh-remoted` - Agent communication
     - `wazuh-logcollector` - Log collection
     - `wazuh-monitord` - Health monitoring
     - `wazuh-analysisd` - Event analysis
     - `wazuh-modulesd` - Inventory & Content Manager

2. **Wazuh Indexer** (`wazuh-indexer.service`)
   - Status: ✅ Active (running)
   - PID: 125107 (Java)
   - Memory: ~1.5G
   - CPU: 3min 27.261s
   - Documentation: https://documentation.wazuh.com

3. **Wazuh Dashboard** (`wazuh-dashboard.service`)
   - Status: ✅ Active (running)
   - PID: 114087 (Node.js)
   - Memory: ~202.9M
   - Port: 443 (HTTPS)
   - Max HTTP header size: 65536

![Wazuh Web Dashboard](imgs/systems/wazuh_dashboard.png.png)

**Dashboard Overview (Last 24 Hours):**
- **Active Agents:** 1
- **Disconnected Agents:** 0
- **Alerts Summary:**
  - Critical (Level 15+): 0
  - High (Level 12-14): 0
  - Medium (Level 7-11): 20
  - Low (Level 0-6): 302

**Modules được sử dụng:**
- **Endpoint Security:**
  - Configuration Assessment
  - Malware Detection
  - File Integrity Monitoring (FIM)
- **Threat Intelligence:**
  - Threat Hunting
  - Vulnerability Detection
  - MITRE ATT&CK Framework
- **Security Operations:**
  - IT Hygiene
  - PCI DSS Compliance
- **Cloud Security:**
  - Docker Monitoring
  - AWS, Google Cloud, GitHub integration

---

#### **C. Machine Learning Environment (Ubuntu Desktop)**

**Vai trò:** Máy Ubuntu vật lý dùng để chạy toàn bộ pipeline `wazuh-ml` — thu thập log, tiền xử lý, huấn luyện và triển khai hành động tự động cho pfSense/Wazuh.

**Thông tin hệ thống:**
- **Platform:** Ubuntu Desktop 22.04 LTS (bare-metal)
- **Python Version:** 3.12.x
- **Virtual Environment:** `mlenv` (tạo bằng `python3 -m venv mlenv` và kích hoạt với `source mlenv/bin/activate`)
- **IDE/Notebook:** Visual Studio Code + Jupyter (mở trực tiếp thư mục `wazuh-ml/`)

**Thư viện & công cụ chính** (đồng bộ `wazuh-ml/requirements.txt`):
```txt
pandas, numpy, scikit-learn, joblib, requests, urllib3,
matplotlib, python-dateutil, python-dotenv, pytest,
openai, fastapi, uvicorn, torch, torchmetrics
```

**Thư mục pipeline liên quan:**
- `wazuh-ml/data/*`: dữ liệu thô, features, artifacts mô hình (`.pkl`, `.json`)
- `wazuh-ml/data_processing/*`: scripts export từ Wazuh Indexer + tiền xử lý
- `wazuh-ml/training/*` & `wazuh-ml/detection/*`: train, tuning, real-time detector
- `wazuh-ml/actions/*`: điều phối phản hồi (Wazuh Manager API, pfSense)

**Network Access:**
- Kết nối tới Wazuh Indexer: `https://172.16.158.150:9200`
- Kết nối tới Wazuh Manager API: `https://172.16.158.150:55000`

---

### **2.2. Sơ đồ mạng**

```
Internet
   |
   | (WAN: 192.168.180.129/24)
   |
[pfSense Firewall]
   |
   | (LAN: 172.16.158.100/24)
   |
   +--- 172.16.158.1    (Gateway)
   +--- 172.16.158.150  (Wazuh Server)
   +--- 172.16.158.x    (Agents + ML Machine)
```

---

### **2.3. Công cụ và thư viện:**

* Python 3.12.x cùng môi trường `mlenv` (venv) thống nhất cho toàn bộ pipeline.
* IDE: Visual Studio Code + Jupyter Notebook để debug và chạy scripts CLI.
* Dependencies chính: `pandas`, `numpy`, `scikit-learn`, `joblib`, `requests`, `urllib3`, `matplotlib`, `python-dotenv`, `torch`, `torchmetrics`, `fastapi`, `uvicorn`, `openai`, `pytest` (xem chi tiết tại `wazuh-ml/requirements.txt`).

---

## 3. Kiến trúc pipeline xử lý dữ liệu

### **Các bước chính:**

1. **Thu thập log từ Wazuh Indexer** (OpenSearch API) → `wazuh-ml/data/security_logs_raw.json`.
2. **Tiền xử lý & feature engineering** bằng `wazuh-ml/data_processing/*` → sinh `security_logs.csv`, `security_logs_analyzed.csv`.
3. **Huấn luyện & tuning** (Isolation Forest, classifier, autoencoder) trong `wazuh-ml/training/*` → artifacts `.pkl`, `.json`.
4. **Phát hiện realtime** với `wazuh-ml/detection/realtime_detector.py` và ghi log vào `data/anomalies.csv`, `data/action_logs.jsonl`.
5. **Phản hồi tự động** qua `wazuh-ml/actions/*` (điều phối rule, pfSense API, Wazuh Manager).

### **Cấu trúc thư mục dự án:**

> Tham khảo chi tiết hơn trong `wazuh-ml/README.md` để biết hướng dẫn sử dụng và mô tả từng module.

```text
wazuh-ml/
├── main.py
├── requirements.txt
├── core/, data_processing/, training/, detection/, actions/, docs/, utils/, tests/
└── data/
    ├── security_logs_raw.json
    ├── security_logs.csv
    ├── security_logs_analyzed.csv
    ├── anomalies.csv
    └── *.pkl / *.json model artifacts
```

---

## 4. Quy trình thực hiện chi tiết

### **Bước 1: Thu thập log từ Wazuh Indexer**

* Tài khoản read-only `mlreader1234` gọi API `_search` tới Indexer:
  ```
  https://172.16.158.150:9200/wazuh-alerts-*/_search
  ```
* `wazuh-ml/data_processing/export_from_es.py` tự động tải dữ liệu, lưu `data/security_logs_raw.json` và chuẩn hóa sang `data/security_logs.csv`.

### **Bước 2: Tiền xử lý & feature engineering**

* `wazuh-ml/data_processing/preprocessing.py` + `feature_engineering.py`:
  * Làm sạch giá trị null, ép kiểu port/protocol.
  * Chuẩn hóa timestamp, trích xuất field MITRE, geo.
  * Mã hóa categorical (LabelEncoder / OneHot) cho agent, rule, src/dst.
* Kết quả lưu tại `data/security_logs_analyzed.csv` + ma trận features phục vụ training.

### **Bước 3: Huấn luyện & tuning mô hình**

* Các script trong `wazuh-ml/training/` (`train_model.py`, `train_classifier.py`, `train_autoencoder.py`, `feature_selection.py`) huấn luyện Isolation Forest, RandomForest classifier, Autoencoder.
* Tự động log metric vào `data/performance_analysis.json`, lưu model (`model_isoforest_*.pkl`) cùng encoder/feature selector (`*.pkl`).
* `training/feedback_loop.py` ghi lại lịch sử tối ưu trong `data/tuning_history.json`.

### **Bước 4: Phát hiện và giám sát realtime**

* `wazuh-ml/detection/realtime_detector.py`/`detect_anomaly.py` load model mới nhất, chấm điểm log live hoặc batch.
* Output:
  * `data/anomalies.csv`, `data/anomaly_reports/*` chứa chi tiết sự kiện, score, rule tham chiếu.
  * `data/action_logs.jsonl` theo dõi các hành động tự động.

### **Bước 5: Tự động phản hồi / gửi cảnh báo**

* `wazuh-ml/actions/action_manager.py` và `action_executor.py` quyết định phản hồi dựa trên mức độ rủi ro:
  * POST cảnh báo vào Wazuh Manager API:
    ```
    https://172.16.158.150:55000/events
    ```
  * Push rule vào pfSense hoặc block IP qua `actions/pfsense_integration.py`.
* Cảnh báo ML hiển thị lại trên Wazuh Dashboard (tab *Security events* và *Custom widgets*).


## 6. Hướng phát triển tiếp theo

✅ **Đã hoàn thành**
- [x] Thu thập log tự động từ Wazuh Indexer (API + script `export_from_es.py`)
- [x] Pipeline tiền xử lý/feature engineering + training Isolation Forest & classifier
- [x] Phát hiện anomaly realtime + ghi log phản hồi (`anomalies.csv`, `action_logs.jsonl`)
- [x] Tích hợp phản hồi cơ bản với Wazuh Manager & pfSense
- [x] Tài liệu hoá kiến trúc + hướng dẫn vận hành (`README.md`, `wazuh-ml/docs/*`)

🚀 **Đang/Chuẩn bị triển khai**
- [ ] Đóng gói job bằng systemd/cron + health-check
- [ ] Mở rộng Active Response (chặn ip động, rollback pfSense rule)
- [ ] Bổ sung mô hình Deep Learning (Autoencoder sequence, LSTM)
- [ ] Dashboard ML metrics (Grafana/Streamlit) + cảnh báo SLA
- [ ] Feature engineering nâng cao (temporal patterns, sequence context, TI enrichment)

---

## 7. Tài liệu tham khảo

- [Wazuh Documentation](https://documentation.wazuh.com)
- [pfSense Documentation](https://docs.netgate.com/pfsense)
- [Scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [OpenSearch API](https://opensearch.org/docs/latest/api-reference/)

---

**Tác giả:** Dang Minh  
**Ngày cập nhật:** October 28, 2025