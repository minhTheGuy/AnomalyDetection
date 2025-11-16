# Synthetic Data Generation

Script để tạo synthetic data giống format của Wazuh logs để augment training dataset.

## Sử dụng

### 1. Qua main.py

```bash
# Generate với default settings (5000 events, 70% benign, 7 days)
python main.py generate-data

# Generate với custom settings
python main.py generate-data --num-events 10000 --benign-ratio 0.8 --days 14

# Hoặc qua menu
python main.py --menu
# Chọn option 10
```

### 2. Trực tiếp

```bash
python data_processing/generate_synthetic_data.py --num-events 5000 --benign-ratio 0.7 --days 7
```

## Options

- `--num-events`: Tổng số events cần generate (default: 5000)
- `--benign-ratio`: Tỷ lệ benign events (0.0-1.0, default: 0.7)
- `--days`: Số ngày để span events (default: 7)
- `--output`: Đường dẫn file output (default: `data/security_logs_raw.json`)

## Các loại events được generate

### Benign Events (70% mặc định)

1. **SSH Authentication Success**
   - Rule ID: 5715
   - Level: 3
   - Groups: syslog, sshd, authentication_success

2. **Network Events (DNS, HTTP, HTTPS)**
   - Flow events với normal traffic
   - Internal và external connections
   - Normal packet sizes

3. **Syscheck Events (File Integrity)**
   - File modified events
   - File added events
   - System files và config files

### Attack Events (30% mặc định)

1. **Brute Force Attacks**
   - SSH authentication failures
   - Rule level: 5-9
   - Multiple failed login attempts

2. **Port Scanning**
   - TCP port scans
   - Various target ports (SSH, HTTP, PostgreSQL, etc.)
   - Suricata alerts

3. **Malware Alerts**
   - High severity alerts (level 12-15)
   - Known malware IPs
   - Suspicious C2 communications

4. **Suspicious Syscheck Events**
   - File additions in suspicious locations
   - Unusual file modifications

## Output Format

File output có format giống như Elasticsearch response từ Wazuh Indexer:

```json
{
  "took": 24,
  "timed_out": false,
  "_shards": {...},
  "hits": {
    "total": {"value": 5000, "relation": "eq"},
    "hits": [
      {
        "_index": "wazuh-alerts-4.x-2025.10.21",
        "_id": "synth_123456",
        "_score": 1.0,
        "_source": {
          "agent": {"name": "...", "ip": "..."},
          "@timestamp": "...",
          "rule": {...},
          "data": {...},
          ...
        }
      }
    ]
  }
}
```

## Workflow

1. Generate synthetic data:
   ```bash
   python main.py generate-data --num-events 10000
   ```

2. Convert JSON to CSV:
   ```bash
   python data_processing/export_from_es.py
   # Hoặc nếu muốn dùng file JSON vừa generate:
   # Sửa RAW_JSON_PATH trong config hoặc copy file
   ```

3. Train models với data mới:
   ```bash
   python main.py train-all
   ```

## Tips

- **Tăng số lượng events**: Dùng `--num-events 20000` để có dataset lớn hơn
- **Điều chỉnh tỷ lệ**: Dùng `--benign-ratio 0.8` nếu muốn nhiều benign events hơn
- **Kết hợp với real data**: Merge synthetic data với real data từ Wazuh để có dataset đa dạng hơn
- **Validate**: Sau khi generate, kiểm tra file JSON và chạy export để đảm bảo format đúng

## Lưu ý

- Synthetic data chỉ là approximation của real data
- Nên kết hợp với real data từ Wazuh để có model tốt hơn
- Các IP addresses và signatures được generate ngẫu nhiên, không phải real threats

