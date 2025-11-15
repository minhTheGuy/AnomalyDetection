# Giải Thích Chi Tiết Các Đặc Trưng (Features)

Tài liệu này giải thích từng feature trong file `security_logs_analyzed.csv`.

## TÓM TẮT CÁC NHÓM FEATURES

1. **Raw Data (34 fields)**: Dữ liệu gốc từ Wazuh
2. **Time Features (6)**: hour, day_of_week, minute, is_night, is_weekend, is_business_hours
3. **Network Features (12)**: Port classification, packet size, flow stats, IP analysis
4. **Syscheck Features (7)**: File integrity monitoring indicators
5. **Alert Features (8)**: Suricata/IDS alert indicators
6. **Event Description Features (5)**: Text analysis, keyword detection
7. **Severity Features (4)**: Rule level classification
8. **Sequence Features (5)**: Time-based sequence analysis
9. **Aggregated Features (6)**: Agent and IP statistics
10. **Encoded Features (16)**: Text/categorical → numeric encoding
11. **Anomaly Results (6)**: Ensemble model predictions

**Tổng cộng**: ~111 columns (bao gồm cả raw data và features)
**Features được chọn cho ML**: 71 features (loại bỏ raw text/categorical, chỉ giữ encoded và engineered features)

---

## 1. RAW DATA FIELDS (Dữ liệu gốc từ Wazuh)

### 1.1. Timestamp & Agent Info
- **timestamp**: Thời gian xảy ra sự kiện (ISO format)
- **agent**: Tên agent Wazuh gửi log (ví dụ: `wazuh-server`, `pfsense.home.arpa`)
- **agent_ip**: IP address của agent

### 1.2. Rule Information
- **rule_id**: ID của rule Wazuh phát hiện sự kiện
- **rule_level**: Mức độ nghiêm trọng (0-20), càng cao càng nguy hiểm
- **rule_groups**: Nhóm rule (ví dụ: `ossec`, `sca`, `sshd`, `authentication_success`)
- **event_desc**: Mô tả chi tiết sự kiện (text)

### 1.3. Decoder & Location
- **decoder**: Decoder được dùng để parse log (ví dụ: `ossec`, `sca`, `suricata`)
- **location**: Vị trí log được thu thập

---

## 2. SYSCHECK FIELDS (File Integrity Monitoring)

### 2.1. File Change Events
- **syscheck_event**: Loại thay đổi file (`added`, `modified`, `deleted`)
- **syscheck_path**: Đường dẫn file bị thay đổi
- **syscheck_size**: Kích thước file sau khi thay đổi (bytes)
- **syscheck_sha256**: Hash SHA256 của file
- **syscheck_uname**: Username sở hữu file
- **syscheck_mtime**: Thời gian modify cuối cùng

### 2.2. Rootcheck/Audit
- **data_file**: File liên quan (từ rootcheck/audit)
- **data_title**: Tiêu đề sự kiện audit

---

## 3. NETWORK FIELDS (Suricata/IDS)

### 3.1. Basic Network Info
- **event_type**: Loại event (`alert`, `flow`, etc.)
- **app_proto**: Application protocol (ví dụ: `http`, `ssl`, `dns`)
- **proto**: Transport protocol (`tcp`, `udp`, `icmp`)
- **src_ip**: IP nguồn
- **src_port**: Port nguồn
- **dst_ip**: IP đích
- **dst_port**: Port đích

### 3.2. Suricata Alert Info
- **alert_severity**: Mức độ nghiêm trọng alert (0-3)
- **alert_signature**: Tên signature phát hiện (ví dụ: "ET MALWARE")
- **alert_category**: Danh mục alert (ví dụ: "A Network Trojan was detected")

### 3.3. Flow Statistics
- **bytes_toserver**: Bytes gửi đến server
- **bytes_toclient**: Bytes gửi đến client
- **pkts_toserver**: Số packets gửi đến server
- **pkts_toclient**: Số packets gửi đến client
- **bytes**: Tổng bytes (tính từ flow stats)
- **length**: Độ dài packet/file (từ syscheck hoặc network)

### 3.4. Full Log
- **full_log**: Toàn bộ log message gốc (có thể rất dài)

---

## 4. TIME FEATURES (Từ timestamp)

### 4.1. Time Components
- **hour**: Giờ trong ngày (0-23)
- **day_of_week**: Ngày trong tuần (0=Monday, 6=Sunday)
- **minute**: Phút trong giờ (0-59)

### 4.2. Time Categories
- **is_night**: =1 nếu là ban đêm (22h-6h), =0 nếu không
- **is_weekend**: =1 nếu là cuối tuần (Saturday/Sunday), =0 nếu không
- **is_business_hours**: =1 nếu là giờ làm việc (9h-17h, Mon-Fri), =0 nếu không

**Mục đích**: Phát hiện sự kiện bất thường về thời gian (ví dụ: tấn công ban đêm, hoạt động cuối tuần)

---

## 5. NETWORK FEATURES (Từ network data)

### 5.1. Port Classification
- **is_well_known_port**: =1 nếu port < 1024 (system ports), =0 nếu không
- **is_registered_port**: =1 nếu port 1024-49151, =0 nếu không
- **is_dynamic_port**: =1 nếu port >= 49152 (ephemeral), =0 nếu không
- **port_range**: Phân loại port (`web`, `https`, `system`, `registered`, `dynamic`)
- **is_ephemeral_src**: =1 nếu source port >= 32768 (ephemeral), =0 nếu không

**Mục đích**: Phát hiện kết nối bất thường (ví dụ: kết nối đến port lạ)

### 5.2. Packet/File Size Features
- **log_bytes**: Log transform của bytes (log1p) để giảm skewness
- **packet_size_category**: Phân loại kích thước (`tiny`, `small`, `medium`, `large`)
- **log_length**: Log transform của length

**Mục đích**: Phát hiện traffic/file size bất thường

### 5.3. Flow Statistics Features
- **total_packets**: Tổng số packets (pkts_toserver + pkts_toclient)
- **packet_ratio**: Tỷ lệ packets to server (pkts_toserver / total_packets)

**Mục đích**: Phát hiện pattern traffic bất thường (ví dụ: DDoS, scanning)

### 5.4. IP Address Features
- **is_internal_src**: =1 nếu source IP là private (10.x, 172.16.x, 192.168.x), =0 nếu không
- **is_internal_dst**: =1 nếu destination IP là private, =0 nếu không
- **is_internal_communication**: =1 nếu cả src và dst đều là internal, =0 nếu không

**Mục đích**: Phân biệt internal vs external traffic, phát hiện lateral movement

---

## 6. SYSCHECK FEATURES (File Integrity Monitoring)

### 6.1. File Event Indicators
- **is_syscheck_event**: =1 nếu là syscheck event, =0 nếu không
- **is_file_added**: =1 nếu file được thêm, =0 nếu không
- **is_file_modified**: =1 nếu file được sửa, =0 nếu không
- **is_file_deleted**: =1 nếu file bị xóa, =0 nếu không

**Mục đích**: Phát hiện thay đổi file bất thường (malware, backdoor)

### 6.2. Path Analysis
- **syscheck_path_length**: Độ dài đường dẫn file
- **is_system_path**: =1 nếu path chứa `/etc`, `/usr`, `/bin`, `/sbin`, `/var`, `/opt`, =0 nếu không
- **is_user_path**: =1 nếu path chứa `/home` hoặc `/root`, =0 nếu không

**Mục đích**: Phát hiện thay đổi file ở vị trí nhạy cảm (system files)

---

## 7. ALERT FEATURES (Suricata/IDS)

### 7.1. Alert Indicators
- **is_high_severity_alert**: =1 nếu alert_severity >= 2, =0 nếu không
- **has_alert_category**: =1 nếu có alert category, =0 nếu không
- **alert_signature_length**: Độ dài alert signature
- **has_alert_signature**: =1 nếu có alert signature, =0 nếu không

**Mục đích**: Phát hiện alerts nghiêm trọng từ IDS

### 7.2. Event Type Indicators
- **is_alert_event**: =1 nếu event_type = 'alert', =0 nếu không
- **is_flow_event**: =1 nếu event_type = 'flow', =0 nếu không

**Mục đích**: Phân loại loại event

### 7.3. Application Protocol Features
- **has_app_proto**: =1 nếu có app_proto, =0 nếu không
- **is_http_proto**: =1 nếu app_proto chứa 'http', =0 nếu không
- **is_ssl_proto**: =1 nếu app_proto chứa 'ssl' hoặc 'tls', =0 nếu không

**Mục đích**: Phát hiện web attacks, SSL/TLS anomalies

---

## 8. EVENT DESCRIPTION FEATURES

### 8.1. Text Analysis
- **event_desc_length**: Độ dài mô tả event (số ký tự)
- **event_word_count**: Số từ trong mô tả

**Mục đích**: Phát hiện mô tả bất thường (quá ngắn/dài)

### 8.2. Keyword Detection
- **danger_keyword_count**: Số từ khóa nguy hiểm tìm thấy (failed, error, attack, denied, malicious, etc.)
- **is_auth_event**: =1 nếu chứa từ khóa authentication (login, logout, auth, password), =0 nếu không
- **is_fim_event**: =1 nếu chứa từ khóa file integrity (file, changed, modified, deleted), =0 nếu không

**Mục đích**: Phát hiện sự kiện liên quan đến authentication/file integrity

---

## 9. SEVERITY FEATURES (Từ rule_level)

### 9.1. Severity Categories
- **severity_category**: Phân loại mức độ (`info`, `low`, `medium`, `high`, `critical`)
  - info: level 0-3
  - low: level 4-7
  - medium: level 8-11
  - high: level 12-15
  - critical: level 16-20

### 9.2. Severity Indicators
- **is_critical**: =1 nếu rule_level >= 15, =0 nếu không
- **is_high**: =1 nếu rule_level 11-14, =0 nếu không
- **is_medium**: =1 nếu rule_level 7-10, =0 nếu không

**Mục đích**: Ưu tiên các sự kiện nghiêm trọng

---

## 10. SEQUENCE FEATURES (Phân tích chuỗi thời gian)

### 10.1. Time-based Sequence
- **time_delta**: Khoảng thời gian (giây) giữa event này và event trước đó của cùng agent
- **events_in_window**: Số events trong cửa sổ thời gian 10 phút gần nhất
- **avg_event_frequency**: Tần suất event trung bình (events/phút)

**Mục đích**: Phát hiện burst traffic, scanning, brute force

### 10.2. Burst Detection
- **is_burst**: =1 nếu events_in_window > mean + 2*std (đột biến), =0 nếu không
- **event_velocity**: Tốc độ thay đổi số events (derivative của events_in_window)

**Mục đích**: Phát hiện tấn công DDoS, scanning, brute force

---

## 11. AGGREGATED FEATURES (Thống kê tổng hợp)

### 11.1. Agent Statistics
- **agent_event_count**: Tổng số events của agent này trong dataset
- **is_rare_agent**: =1 nếu agent có < 5 events (hiếm), =0 nếu không
- **agent_avg_rule_level**: Rule level trung bình của agent này
- **rule_level_deviation**: Độ lệch rule_level so với trung bình của agent

**Mục đích**: Phát hiện agent bất thường, hoạt động khác pattern thông thường

### 11.2. IP Statistics
- **src_ip_count**: Số lần xuất hiện của source IP này
- **is_rare_src_ip**: =1 nếu src_ip có < 3 events (hiếm), =0 nếu không

**Mục đích**: Phát hiện IP bất thường (scanner, attacker)

---

## 12. ENCODED FEATURES (Text → Number)

Các text/categorical fields được encode thành số để ML model có thể sử dụng:

- **agent_code**: Mã hóa của agent name
- **proto_code**: Mã hóa của protocol
- **event_desc_code**: Mã hóa của event description
- **decoder_code**: Mã hóa của decoder
- **location_code**: Mã hóa của location
- **syscheck_event_code**: Mã hóa của syscheck event type
- **syscheck_path_code**: Mã hóa của syscheck path
- **alert_signature_code**: Mã hóa của alert signature
- **alert_category_code**: Mã hóa của alert category
- **event_type_code**: Mã hóa của event type
- **app_proto_code**: Mã hóa của app protocol
- **data_file_code**: Mã hóa của data file
- **data_title_code**: Mã hóa của data title
- **port_range_code**: Mã hóa của port range category
- **severity_category_code**: Mã hóa của severity category
- **packet_size_category_code**: Mã hóa của packet size category

**Mục đích**: Chuyển đổi text/categorical thành số để ML model có thể xử lý

---

## 13. ANOMALY DETECTION RESULTS

### 13.1. Ensemble Model Results
- **anomaly_label**: Nhãn anomaly (-1 = anomaly, 1 = normal)
- **anomaly_score**: Điểm số anomaly (càng thấp càng bất thường)
- **anomaly_votes**: Số models đồng ý đây là anomaly (0-3)
- **iforest_vote**: Vote từ Isolation Forest (-1 hoặc 1)
- **lof_vote**: Vote từ Local Outlier Factor (-1 hoặc 1)
- **svm_vote**: Vote từ One-Class SVM (-1 hoặc 1)

**Mục đích**: Kết quả từ ensemble anomaly detection model

---

## LƯU Ý

- Các features có prefix `is_` là binary (0 hoặc 1)
- Các features có suffix `_code` là encoded versions của text fields
- Các features có suffix `_length`, `_count` là numeric
- `anomaly_score` càng thấp (âm) càng bất thường
- `anomaly_votes` = 3 nghĩa là cả 3 models đều đồng ý đây là anomaly (rất đáng tin)

