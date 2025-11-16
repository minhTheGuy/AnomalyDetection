# Phân Tích: Sử Dụng KDD Cup 99 Dataset Cho Wazuh Anomaly Detection

## 📋 Câu Hỏi

**Có thể dùng [KDD Cup 99 dataset](https://raw.githubusercontent.com/jvmolu/Network-Anomaly-Detection/refs/heads/main/archive/Train_data.csv) để train model, sau đó detect anomaly trên Wazuh data không?**

---

## 🔍 So Sánh Dataset Structures

### 1. KDD Cup 99 Dataset Features (41 features)

**Basic Connection Features:**
- `duration`: Thời gian kết nối (seconds)
- `protocol_type`: tcp, udp, icmp
- `service`: http, ftp, telnet, smtp, etc.
- `flag`: SF, S0, REJ, etc. (connection status)
- `src_bytes`, `dst_bytes`: Bytes gửi/nhận
- `land`: 0/1 (same source/dest IP)
- `wrong_fragment`, `urgent`, `hot`: Network flags

**Content Features:**
- `num_failed_logins`: Số lần login failed
- `logged_in`: 0/1 (login thành công)
- `num_compromised`: Số lần compromised
- `root_shell`, `su_attempted`: Privilege escalation
- `num_root`, `num_file_creations`, `num_shells`: System access
- `num_access_files`, `num_outbound_cmds`: File/command access
- `is_host_login`, `is_guest_login`: Login type

**Traffic Features (Time-based):**
- `count`: Số connections từ same host trong time window
- `srv_count`: Số connections đến same service
- `serror_rate`, `srv_serror_rate`: SYN error rates
- `rerror_rate`, `srv_rerror_rate`: REJ error rates
- `same_srv_rate`, `diff_srv_rate`: Service concentration
- `srv_diff_host_rate`: Host diversity

**Host-based Features:**
- `dst_host_count`: Connections đến destination host
- `dst_host_srv_count`: Connections đến same service
- `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`: Service patterns
- `dst_host_same_src_port_rate`: Port patterns
- `dst_host_srv_diff_host_rate`: Host diversity
- `dst_host_serror_rate`, `dst_host_srv_serror_rate`: Error rates
- `dst_host_rerror_rate`, `dst_host_srv_rerror_rate`: REJ rates

**Label:**
- `class`: `normal` hoặc `anomaly`

---

### 2. Wazuh Dataset Features (~89 features sau feature engineering)

**Raw Fields:**
- `timestamp`, `agent`, `agent_ip`
- `rule_id`, `rule_level`, `rule_groups`, `event_desc`
- `decoder`, `location`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `proto`, `app_proto`, `event_type`
- `bytes_toserver`, `bytes_toclient`, `pkts_toserver`, `pkts_toclient`
- `alert_severity`, `alert_signature`, `alert_category`
- `syscheck_event`, `syscheck_path`, `syscheck_size`, `syscheck_sha256`
- `full_log`

**Engineered Features:**
- Time features: `hour`, `day_of_week`, `is_night`, `is_weekend`
- Network features: `is_well_known_port`, `is_internal_src`, `total_packets`, `packet_ratio`
- Event features: `event_desc_length`, `danger_keyword_count`, `is_auth_event`, `is_fim_event`
- Sequence features: `time_since_last_event`, `event_frequency`
- Aggregated features: `agent_event_count`, `src_ip_count`

---

## ⚖️ So Sánh Chi Tiết

### ✅ Features Có Thể Map Trực Tiếp

| KDD Cup 99 | Wazuh Equivalent | Notes |
|------------|------------------|-------|
| `protocol_type` | `proto` | ✅ Direct match (tcp, udp, icmp) |
| `src_bytes` | `bytes_toserver` | ⚠️ Similar but not exact |
| `dst_bytes` | `bytes_toclient` | ⚠️ Similar but not exact |
| `service` | `app_proto` | ⚠️ Partial (http, ftp, smtp) |
| `flag` | `event_type` | ❌ Different semantics |
| `num_failed_logins` | Pattern từ `event_desc` | ⚠️ Need extraction |
| `logged_in` | Pattern từ `event_desc` | ⚠️ Need extraction |

### ❌ Features Không Có Trong Wazuh

**KDD Cup 99 có nhưng Wazuh không có:**
- `duration`: Wazuh không track connection duration
- `land`: Wazuh không có field này
- `wrong_fragment`, `urgent`, `hot`: Network flags không có
- `num_compromised`, `root_shell`, `su_attempted`: System-level metrics
- `num_root`, `num_file_creations`, `num_shells`: System access counts
- `num_access_files`, `num_outbound_cmds`: File/command counts
- `is_host_login`, `is_guest_login`: Login type flags
- **Time-window features**: `count`, `srv_count`, `serror_rate`, etc. (cần aggregation)
- **Host-based features**: `dst_host_count`, `dst_host_srv_count`, etc. (cần aggregation)

### ✅ Features Wazuh Có Nhưng KDD Cup 99 Không Có

**Wazuh-specific:**
- `rule_level`, `rule_id`, `rule_groups`: Wazuh rule system
- `event_desc`: Rich text descriptions
- `alert_signature`, `alert_category`: Suricata/IDS alerts
- `syscheck_*`: File integrity monitoring
- `agent`, `agent_ip`: Multi-agent architecture
- `decoder`, `location`: Log parsing metadata

---

## 🎯 Đánh Giá Tính Khả Thi

### ❌ **KHÔNG HOẠT ĐỘNG TRỰC TIẾP**

**Lý do:**

1. **Feature Mismatch (70% features khác nhau)**
   - KDD Cup 99: 41 features, chủ yếu network connection statistics
   - Wazuh: 89 features, mix của network, file integrity, authentication, alerts
   - Chỉ ~30% features có thể map được

2. **Domain Difference**
   - **KDD Cup 99**: Network connection-level data (mỗi record = 1 connection)
   - **Wazuh**: Event-level data (mỗi record = 1 security event)
   - Different data granularity và semantics

3. **Missing Critical Features**
   - KDD Cup 99 cần time-window aggregation (count, srv_count, rates)
   - Wazuh không có sẵn các features này
   - Cần tính toán từ raw data (phức tạp)

4. **Different Anomaly Types**
   - **KDD Cup 99**: Network intrusions (DoS, Probe, R2L, U2R)
   - **Wazuh**: Security events (malware, brute force, file changes, alerts)
   - Overlap nhưng không giống hệt

---

## ✅ Giải Pháp Khả Thi

### Option 1: Feature Engineering + Domain Adaptation (Khuyến nghị)

**Cách làm:**
1. **Extract tương đương từ Wazuh data:**
   ```python
   # Map KDD features từ Wazuh
   - protocol_type → proto
   - src_bytes → bytes_toserver
   - dst_bytes → bytes_toclient
   - service → app_proto
   - num_failed_logins → extract từ event_desc (regex)
   - logged_in → extract từ event_desc
   ```

2. **Tính toán time-window features:**
   ```python
   # Aggregate trong time window (ví dụ: 2 seconds)
   - count → số events từ same src_ip trong window
   - srv_count → số events đến same dst_port trong window
   - serror_rate → tỷ lệ events có flag "S0" hoặc "REJ"
   - rerror_rate → tỷ lệ events có flag "REJ"
   ```

3. **Tạo missing features với default values:**
   ```python
   # Features không có trong Wazuh → set default
   - land → 0 (assume no land attacks)
   - wrong_fragment → 0
   - urgent, hot → 0
   - num_compromised, root_shell, etc. → 0 hoặc extract từ event_desc
   ```

4. **Train model với adapted features:**
   - Train trên KDD Cup 99
   - Transform Wazuh data → KDD format
   - Predict với trained model

**Ưu điểm:**
- ✅ Có thể sử dụng được
- ✅ Tận dụng KDD Cup 99 dataset lớn
- ✅ Model đã được validate

**Nhược điểm:**
- ⚠️ Feature engineering phức tạp
- ⚠️ Mất mát thông tin (Wazuh-specific features bị bỏ qua)
- ⚠️ Performance có thể kém hơn model train trực tiếp trên Wazuh

---

### Option 2: Transfer Learning (Advanced)

**Cách làm:**
1. Pre-train trên KDD Cup 99
2. Fine-tune trên Wazuh data (small dataset)
3. Sử dụng shared feature space

**Ưu điểm:**
- ✅ Tận dụng knowledge từ KDD Cup 99
- ✅ Adapt được với Wazuh domain

**Nhược điểm:**
- ⚠️ Phức tạp hơn
- ⚠️ Cần Wazuh labeled data để fine-tune

---

### Option 3: Train Trực Tiếp Trên Wazuh (Khuyến nghị nhất)

**Cách làm:**
1. Sử dụng Wazuh data hiện có
2. Train model với Wazuh-specific features
3. Không cần domain adaptation

**Ưu điểm:**
- ✅ Tận dụng tất cả Wazuh features
- ✅ Model phù hợp với domain
- ✅ Performance tốt hơn

**Nhược điểm:**
- ⚠️ Cần đủ Wazuh data để train
- ⚠️ Cần labeled data (hoặc unsupervised)

---

## 📊 So Sánh Performance Dự Kiến

| Approach | Accuracy | Complexity | Recommendation |
|----------|----------|------------|----------------|
| **Direct KDD → Wazuh** | ❌ 30-50% | Low | ❌ Không khuyến nghị |
| **Feature Engineering** | ⚠️ 60-75% | Medium | ⚠️ Có thể thử |
| **Transfer Learning** | ✅ 75-85% | High | ✅ Tốt nếu có labeled data |
| **Train on Wazuh** | ✅ 85-95% | Medium | ✅ **Khuyến nghị nhất** |

---

## 🚀 Khuyến Nghị

### Nếu muốn dùng KDD Cup 99:

1. **Tạo feature adapter module:**
   ```python
   # wazuh-ml/adapters/kdd_adapter.py
   def wazuh_to_kdd_format(wazuh_df):
       # Transform Wazuh → KDD format
       # Calculate time-window features
       # Map missing features
       return kdd_df
   ```

2. **Train model trên KDD Cup 99:**
   ```python
   # Train với KDD dataset
   model = train_kdd_model(kdd_data)
   ```

3. **Predict với Wazuh data:**
   ```python
   # Transform Wazuh → KDD
   wazuh_kdd = wazuh_to_kdd_format(wazuh_df)
   # Predict
   predictions = model.predict(wazuh_kdd)
   ```

### Nếu có đủ Wazuh data:

**✅ Khuyến nghị train trực tiếp trên Wazuh data** (như hiện tại)

- Model đã đạt 100% accuracy trên test set
- Features phù hợp với domain
- Không cần domain adaptation

---

## 📝 Kết Luận

**Trả lời ngắn gọn:**
- ❌ **Không hoạt động trực tiếp** do feature mismatch
- ⚠️ **Có thể hoạt động** nếu làm feature engineering + domain adaptation
- ✅ **Khuyến nghị**: Train trực tiếp trên Wazuh data (như hiện tại)

**Lý do:**
- Wazuh model hiện tại đã đạt 100% accuracy
- Features phù hợp với domain
- Không cần phức tạp hóa với domain adaptation

**Nếu vẫn muốn thử:**
- Implement feature adapter
- Test performance
- So sánh với model hiện tại

---

## 🔗 References

- [KDD Cup 99 Dataset](https://raw.githubusercontent.com/jvmolu/Network-Anomaly-Detection/refs/heads/main/archive/Train_data.csv)
- [KDD Cup 99 Paper](https://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html)
- [Domain Adaptation in ML](https://en.wikipedia.org/wiki/Domain_adaptation)

