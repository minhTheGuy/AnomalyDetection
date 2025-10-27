# Xây dựng hệ thống phát hiện bất thường (Anomaly Detection) cho Wazuh + Suricata + pfSense

---

## 1. Mục tiêu dự án

Xây dựng một hệ thống Machine Learning giúp:

* Tự động phát hiện các hành vi bất thường (anomalies) trong log bảo mật thu thập bởi **Wazuh Server** (Suricata + pfSense).
* Ghi lại log bất thường và có thể **gửi cảnh báo ngược trở lại Wazuh Dashboard**.
* Mở rộng khả năng phân tích hành vi trong hệ thống SOC mini.
* Tự động cập nhật dữ liệu và chạy mô hình Machine-Learning mà không cần can thiệp thủ công
* Tự động hóa các rules và phản ứng lại các anomalies bằng active response.

---

## 2. Môi trường triển khai

### **Hạ tầng lab:**

* 01 máy ảo **pfSense** (có Suricata IDS cấu hình sẵn).
* 01 máy ảo **Wazuh all-in-one** (gồm: Manager, Indexer, Dashboard).
* 01 máy thật (Ubuntu) dùng để chạy môi trường Python và huấn luyện mô hình ML.

### **Công cụ và thư viện:**

* Python 3.12, thư viện: `pandas`, `numpy`, `scikit-learn`, `joblib`, `requests`.
* Visual Studio Code (hoặc Jupyter Notebook) cho việc lập trình và huấn luyện.
* Môi trường ảo: `mlenv` (được tạo bằng `python3 -m venv mlenv`).

---

## 3. Kiến trúc pipeline xử lý dữ liệu

### **Các bước chính:**

1. **Thu thập log từ Wazuh Indexer** (qua API OpenSearch) → lưu JSON và CSV.
2. **Tiền xử lý và mã hóa dữ liệu** (làm sạch, chuyển đổi text thành mã số).
3. **Huấn luyện mô hình Isolation Forest** để nhận diện các sự kiện hiếm.
4. **Phát hiện anomaly trong log mới** và ghi ra báo cáo.
5. (Tùy chọn) **Đẩy cảnh báo ML ngược lại Wazuh Dashboard**.

### **Cấu trúc thư mục dự án:**

```text
wazuh-ml/
├── config.py
├── export_from_es.py
├── preprocessing.py
├── train_model.py
├── detect_anomaly.py
├── push_alert.py
├── requirements.txt
└── data/
    ├── security_logs_raw.json
    ├── security_logs.csv
    ├── security_logs_analyzed.csv
    └── model_isoforest.pkl
```

---

## 4. Quy trình thực hiện chi tiết

### **Bước 1: Kết nối và thu log từ Wazuh Indexer**reload

* Cấu hình tài khoản đọc-only (`mlreader1234`).
* Gọi API `_search` tới Indexer qua HTTPS:

  ```bash
  curl -u mlreader1234:MLreader123@ -k https://172.16.158.150:9200/wazuh-alerts-*/_search?size=10000
  ```
* Script `export_from_es.py` tự động:

  * Truy xuất log mới nhất.
  * Lưu JSON thô (`security_logs_raw.json`).
  * Chuyển sang bảng CSV (`security_logs.csv`).

### **Bước 2: Tiền xử lý dữ liệu**

* Xóa giá trị rỗng, ép kiểu số cho port.
* Mã hóa cột text bằng `LabelEncoder` (event_desc, agent).
* Chọn các thuộc tính huấn luyện:

  ```python
  [src_port, dst_port, event_code, agent_code]
  ```

### **Bước 3: Huấn luyện mô hình Isolation Forest**

* Dùng thuật toán **IsolationForest** (thuộc scikit-learn).
* Tỉ lệ anomaly (`contamination`) = 0.05.
* Lưu model và encoder vào file `model_isoforest.pkl`.
* Xuất kết quả phân tích ra `security_logs_analyzed.csv`.

### **Bước 4: Phát hiện anomaly mới**

* Script `detect_anomaly.py` tải lại model.
* Chấm điểm log mới và phân loại:

  * `1` → bình thường.
  * `-1` → bất thường.
* Xuất danh sách anomaly cùng điểm số (`anomaly_score`).

### **Bước 5: Gửi cảnh báo ngược lại Wazuh** *(tùy chọn)*

* Gọi API Wazuh Manager:

  ```python
  curl -X POST https://localhost:55000/manager/logs \
       -u wazuh:wazuh -k \
       -H 'Content-Type: application/json' \
       -d '{"log": "ML anomaly detected from 172.16.158.1"}'
  ```
* Các log này sẽ hiển thị trong Dashboard dưới tab *Security events*.

---

## 5. Kết quả và phân tích

Sau khi huấn luyện và chạy `detect_anomaly.py`:

```
🔎 Số sự kiện bất thường: 29
```

**Một số sự kiện đáng chú ý:**

| Loại sự kiện                                     | Mô tả                                     | Nhận định                                              |
| ------------------------------------------------ | ----------------------------------------- | ------------------------------------------------------ |
| `sshd: authentication success`                   | Đăng nhập SSH thành công từ 172.16.158.1  | Có thể là hoạt động quản trị; cần whitelist nếu hợp lệ |
| `Integrity checksum changed`                     | File hệ thống bị thay đổi                 | Cảnh báo nghiêm trọng, cần kiểm tra FIM                |
| `Host-based anomaly detection (rootcheck)`       | Kiểm tra bất thường nội bộ                | Có thể là hành động an toàn định kỳ                    |
| `sshd: Attempt to login using non-existent user` | Đăng nhập thất bại với user không tồn tại | Dấu hiệu dò quét/brute-force                           |
| `Wazuh agent started/stopped`                    | Agent khởi động lại                       | Có thể là reboot hoặc tấn công service                 |

**Mức độ hiệu quả:**

* Tổng số log: ~718
* Bị gắn nhãn bất thường: 29 (~4%) → tỷ lệ hợp lý.
* Phát hiện đúng các hành vi hiếm và nghi ngờ.

---

## 6. Hướng phát triển tiếp theo

✅ **Hoàn thiện:**

* Pipeline tự động hoạt động ổn định (Export → Train → Detect → Alert).

🚀 **Mở rộng tương lai:**

1. Huấn luyện riêng cho từng loại sự kiện (SSH, Suricata, FIM…).
2. Thêm tính năng tự động phản ứng (active-response):

   * Chặn IP trên pfSense khi phát hiện tấn công SSH.
   * Chạy các
3. Tích hợp visualization:

   * Dùng Matplotlib hoặc Grafana để hiển thị phân bố anomaly_score.
4. Cải thiện feature set:

   * Thêm thời gian (giờ/ngày), số lượng login theo IP, tần suất event.

5. Tự động hóa bằng systemd service
   * Tự động cập nhật dữ liệu và chạy mô hình Machine-Learning mà không cần can thiệp thủ công bằng Systemd
