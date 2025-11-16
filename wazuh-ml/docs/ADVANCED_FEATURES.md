# Advanced Features Documentation

## 📋 Tổng Quan

Tài liệu này mô tả các tính năng nâng cao của Wazuh ML system:

1. **Test Automation** - Automated testing framework
2. **Threat Intelligence Feeds** - Tích hợp threat intelligence
3. **pfSense Integration** - Tự động block IP/Port trên pfSense firewall
4. **Enhanced Synthetic Data** - Cải thiện synthetic data generation

---

## 🧪 1. Test Automation

### Tổng Quan

Test automation framework cho phép chạy unit tests và integration tests để đảm bảo chất lượng code.

### Cấu Trúc Tests

```
tests/
├── __init__.py
├── test_anomaly_detection.py    # Tests cho anomaly detection
├── test_classification.py        # Tests cho classification patterns
├── test_integration.py           # Integration tests
└── run_tests.py                  # Test runner
```

### Chạy Tests

#### Chạy Tất Cả Tests

```bash
python main.py test
# hoặc
python tests/run_tests.py
```

#### Chạy Test Module Cụ Thể

```bash
python main.py test --test-module test_anomaly_detection
python main.py test --test-module test_classification
python main.py test --test-module test_integration
```

#### Chạy Trực Tiếp Với unittest

```bash
python -m unittest tests.test_anomaly_detection
python -m unittest tests.test_classification
python -m unittest tests.test_integration
```

### Test Coverage

- **Unit Tests**: Test từng module riêng lẻ
- **Integration Tests**: Test end-to-end workflows
- **Pattern Tests**: Test classification patterns

### Thêm Tests Mới

Tạo file test mới trong `tests/`:

```python
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestMyFeature(unittest.TestCase):
    def test_something(self):
        # Your test code
        self.assertEqual(1 + 1, 2)

if __name__ == '__main__':
    unittest.main()
```

---

## 🛡️ 2. Threat Intelligence Feeds

### Tổng Quan

Tích hợp các nguồn threat intelligence để enhance detection capabilities:
- **AbuseIPDB**: IP reputation checking
- **VirusTotal**: File hash reputation checking
- **Local Feed**: Custom threat intelligence lists

### Cấu Hình

#### Environment Variables

Thêm vào `.env`:

```bash
# AbuseIPDB API Key (optional)
ABUSEIPDB_API_KEY=your_api_key_here

# VirusTotal API Key (optional)
VIRUSTOTAL_API_KEY=your_api_key_here
```

#### Local Threat Lists

Tạo file `data/threat_intel/malicious_ips.txt`:

```
# Malicious IPs (one per line)
192.168.1.100
10.0.0.50
# Comments start with #
```

Tạo file `data/threat_intel/malicious_hashes.txt`:

```
# Malicious file hashes (SHA256, one per line)
abc123def456...
789ghi012jkl...
```

### Sử Dụng

#### Check IP Reputation

```bash
python main.py threat-intel --ip 192.168.1.100
```

#### Check File Hash

```bash
python main.py threat-intel --hash abc123def456...
```

#### Check Cả IP và Hash

```bash
python main.py threat-intel --ip 192.168.1.100 --hash abc123def456...
```

### Programmatic Usage

```python
from threat_intelligence.feeds import get_threat_intel_manager

manager = get_threat_intel_manager()

# Check IP
if manager.is_malicious_ip("192.168.1.100"):
    print("IP is malicious!")

# Check hash
if manager.is_malicious_hash("abc123..."):
    print("File hash is malicious!")

# Enrich log
enriched_log = manager.enrich_log(log_dict)

# Add detected threat
manager.add_detected_threat(ip="192.168.1.100", file_hash="abc123...")
```

### Tích Hợp Vào Detection

Threat intelligence có thể được tích hợp vào detection pipeline để:
- Boost anomaly scores cho malicious IPs/hashes
- Add context vào alerts
- Auto-add detected threats vào local feed

---

## 🛡️ 3. pfSense Integration

### Tổng Quan

Tự động block IP/Port trên pfSense firewall khi phát hiện threats:
- Tự động block IPs nghi ngờ
- Block ports bị scan
- Tích hợp với pfSense qua SSH hoặc API
- Real-time response

### Sử Dụng

Xem chi tiết trong [PFSENSE_INTEGRATION.md](PFSENSE_INTEGRATION.md)

#### Cấu Hình

```bash
# Enable pfSense integration
ENABLE_PFSENSE=true
PFSENSE_METHOD=ssh
PFSENSE_SSH_HOST=172.16.158.100
PFSENSE_SSH_USER=admin
PFSENSE_SSH_PASS=your_password
```

#### Auto Block

Khi phát hiện anomaly với severity >= HIGH:
- Tự động SSH vào pfSense
- Thêm IP vào firewall table `blocked_ips`
- pfSense tự động block traffic

```bash
# Detect và auto block
python main.py detect
```

---

## 🎲 4. Enhanced Synthetic Data

### Tổng Quan

Enhanced synthetic data generation với:
- Advanced attack patterns
- Realistic network traffic
- Diverse event types

### Sử Dụng

```bash
# Generate với default settings
python main.py generate-data

# Custom parameters
python main.py generate-data \
  --num-events 10000 \
  --benign-ratio 0.8 \
  --days 14 \
  --output data/custom_data.json \
  --csv-output data/custom_data.csv
```

### Attack Patterns

Synthetic data generator tạo các attack patterns:
- **Brute Force**: Multiple failed login attempts
- **Port Scans**: Sequential port scanning
- **Malware**: Suspicious file downloads
- **DoS/DDoS**: Flood attacks
- **SQL Injection**: Web attack patterns
- **XSS**: Cross-site scripting attempts

### Customization

Có thể customize trong `data_processing/generate_synthetic_data.py`:
- Agent configurations
- IP ranges
- Port ranges
- Attack signatures
- Event distributions

---

## 🔧 Integration Examples

### Full Workflow

```bash
# 1. Generate synthetic data
python main.py generate-data --num-events 10000

# 2. Train models
python main.py train-all

# 3. Detect anomalies
python main.py detect

# 4. Check threat intelligence
python main.py threat-intel --ip 192.168.1.100

# 5. Generate rules
# Actions sẽ tự động block trên pfSense (nếu enabled)

# 6. Run tests
python main.py test
```

### Automated Pipeline

```bash
#!/bin/bash
# automated_pipeline.sh

# Generate data
python main.py generate-data --num-events 5000

# Train models
python main.py train-all --no-tuning

# Detect anomalies
python main.py detect

# Actions sẽ tự động block trên pfSense (nếu enabled)

# Run tests
python main.py test
```

---

## 📊 Best Practices

### Test Automation

1. **Run tests trước khi commit**: `python main.py test`
2. **Test specific modules**: Focus on changed code
3. **Integration tests**: Test full workflows

### Threat Intelligence

1. **Cache results**: Reduce API calls
2. **Update local feeds**: Regularly update malicious IPs/hashes
3. **Combine sources**: Use multiple feeds for better coverage

### pfSense Integration

1. **Test blocking**: Test với test IPs trước khi enable auto block
2. **Monitor blocks**: Review blocked IPs thường xuyên
3. **Whitelist**: Maintain whitelist cho trusted IPs

### Synthetic Data

1. **Balance data**: Maintain realistic benign/attack ratio
2. **Diverse patterns**: Include various attack types
3. **Realistic timestamps**: Use realistic time distributions

---

## 🚀 Future Enhancements

- [ ] CI/CD integration cho tests
- [ ] More threat intelligence feeds (Shodan, AlienVault, etc.)
- [ ] Advanced synthetic data scenarios
- [ ] Performance benchmarking
- [ ] Auto unblock IPs sau X giờ
- [ ] Whitelist management cho pfSense
- [ ] Block statistics và reporting

---

## 📝 References

- [pfSense Documentation](https://docs.netgate.com/pfsense/)
- [AbuseIPDB API](https://www.abuseipdb.com/api)
- [VirusTotal API](https://developers.virustotal.com/reference)
- [Python unittest](https://docs.python.org/3/library/unittest.html)

