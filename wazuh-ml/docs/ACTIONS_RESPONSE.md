# Action/Response System Documentation

## 📋 Tổng Quan

Hệ thống Action/Response tự động tạo và thực thi các phản ứng khi phát hiện anomalies và classify chúng. Hệ thống hỗ trợ:

- **Block IP/Port**: Tự động block các IP hoặc ports nghi ngờ
- **Telegram Notifications**: Gửi thông báo real-time qua Telegram
- **Alerts**: Tạo alerts cho security team
- **Logging**: Ghi log tất cả actions
- **Escalation**: Escalate các threats nghiêm trọng

---

## 🎯 Các Loại Actions

### 1. LOG
- **Mô tả**: Ghi log tất cả anomalies
- **Khi nào**: Luôn luôn được thực thi
- **Severity**: Tất cả

### 2. ALERT
- **Mô tả**: Tạo alert cho security team
- **Khi nào**: Severity >= MEDIUM
- **Severity**: MEDIUM, HIGH, CRITICAL

### 3. NOTIFY_TELEGRAM
- **Mô tả**: Gửi thông báo qua Telegram
- **Khi nào**: Severity >= MIN_SEVERITY_FOR_NOTIFY (default: MEDIUM)
- **Severity**: MEDIUM, HIGH, CRITICAL
- **Yêu cầu**: Telegram bot token và chat ID

### 4. BLOCK_IP
- **Mô tả**: Block IP address
- **Khi nào**: 
  - Severity >= MIN_SEVERITY_FOR_BLOCK (default: HIGH)
  - External IP hoặc attack type nghiêm trọng (malware, dos_ddos, brute_force, privilege_escalation)
- **Severity**: HIGH, CRITICAL
- **Yêu cầu**: ENABLE_AUTO_BLOCK = true

### 5. BLOCK_PORT
- **Mô tả**: Block port
- **Khi nào**: Severity CRITICAL và attack type là dos_ddos hoặc port_scan
- **Severity**: CRITICAL

### 6. ESCALATE
- **Mô tả**: Escalate đến security manager
- **Khi nào**: Severity CRITICAL
- **Severity**: CRITICAL

---

## ⚙️ Cấu Hình

### Environment Variables (.env)

```bash
# Enable actions system
ENABLE_ACTIONS=true

# Auto execute actions (false = chỉ generate, true = generate và execute)
AUTO_EXECUTE_ACTIONS=false

# Enable auto block
ENABLE_AUTO_BLOCK=false

# Telegram configuration
ENABLE_TELEGRAM=true
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# Severity thresholds (1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
MIN_SEVERITY_FOR_BLOCK=3  # HIGH
MIN_SEVERITY_FOR_NOTIFY=2  # MEDIUM

# Output paths
ACTIONS_CSV_PATH=data/actions.csv
ACTION_RESULTS_CSV_PATH=data/action_results.csv
```

### Severity Mapping

| Attack Type | Severity |
|-------------|----------|
| malware | CRITICAL |
| privilege_escalation | CRITICAL |
| data_exfiltration | CRITICAL |
| dos_ddos | HIGH |
| brute_force | HIGH |
| sql_injection | HIGH |
| xss | MEDIUM |
| port_scan | MEDIUM |
| web_attack | MEDIUM |
| suspicious_activity | LOW |
| benign | LOW |

| Rule Level | Severity |
|------------|----------|
| >= 15 | CRITICAL |
| >= 12 | HIGH |
| >= 7 | MEDIUM |
| < 7 | LOW |

---

## 🚀 Sử Dụng

### 1. Tự Động Trong Detection Pipeline

Khi `ENABLE_ACTIONS=true`, actions sẽ tự động được generate sau khi detect anomalies:

```bash
python main.py detect
```

Actions sẽ được generate và execute (nếu `AUTO_EXECUTE_ACTIONS=true`) hoặc chỉ generate (nếu `AUTO_EXECUTE_ACTIONS=false`).

### 2. Manual Generation

Generate actions từ anomalies CSV:

```bash
# Chỉ generate (không execute)
python main.py generate-actions

# Generate và execute
python main.py generate-actions --execute

# Custom anomalies file
python main.py generate-actions --anomalies-csv data/custom_anomalies.csv --execute
```

### 3. Menu

```bash
python main.py --menu
# Chọn option 13: Generate actions from anomalies
```

---

## 📱 Telegram Setup

### 1. Tạo Telegram Bot

1. Mở Telegram và tìm [@BotFather](https://t.me/botfather)
2. Gửi `/newbot` và làm theo hướng dẫn
3. Lưu bot token (ví dụ: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### 2. Lấy Chat ID

**Cách 1: Qua Bot**
1. Tìm bot bạn vừa tạo trên Telegram
2. Gửi message bất kỳ
3. Truy cập: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
4. Tìm `"chat":{"id":123456789}` trong response

**Cách 2: Qua @userinfobot**
1. Tìm [@userinfobot](https://t.me/userinfobot) trên Telegram
2. Gửi `/start`
3. Bot sẽ trả về ID của bạn

### 3. Cấu Hình

Thêm vào `.env`:

```bash
ENABLE_TELEGRAM=true
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789
```

### 4. Test

```bash
python main.py generate-actions --execute
```

Nếu có anomalies với severity >= MEDIUM, bạn sẽ nhận được notification trên Telegram.

---

## 📊 Output Files

### actions.csv

Chứa tất cả actions được generate:

| Column | Description |
|--------|-------------|
| anomaly_index | Index của anomaly trong anomalies.csv |
| action_type | Loại action (block_ip, notify_telegram, etc.) |
| target | Target của action (IP, port, etc.) |
| reason | Lý do tạo action |
| severity | Severity level (LOW, MEDIUM, HIGH, CRITICAL) |
| severity_value | Severity value (1-4) |
| params | JSON params cho action |

### action_results.csv

Chứa kết quả execution (nếu execute):

| Column | Description |
|--------|-------------|
| anomaly_index | Index của anomaly |
| action_index | Index của action |
| success | Thành công hay không |
| message | Message từ execution |
| timestamp | Thời gian execution |
| action_type | Loại action |

### action_logs.jsonl

Log file chứa tất cả actions và results (JSON Lines format).

---

## 🔧 Customization

### Thêm Action Type Mới

1. Thêm vào `ActionType` enum trong `actions/action_generator.py`:

```python
class ActionType(Enum):
    # ... existing types ...
    CUSTOM_ACTION = "custom_action"
```

2. Implement execution trong `actions/action_executor.py`:

```python
def _execute_custom_action(self, action: Dict) -> Dict:
    # Your implementation
    return {'success': True, 'message': '...'}
```

3. Thêm vào `execute_action()` method:

```python
elif action_type == ActionType.CUSTOM_ACTION:
    result = self._execute_custom_action(action)
```

### Thay Đổi Severity Mapping

Sửa `get_severity_from_attack_type()` trong `actions/action_generator.py`:

```python
def get_severity_from_attack_type(self, attack_type: str) -> SeverityLevel:
    severity_map = {
        'your_attack_type': SeverityLevel.CRITICAL,
        # ...
    }
    return severity_map.get(attack_type.lower(), SeverityLevel.MEDIUM)
```

### Thay Đổi Action Logic

Sửa `generate_actions()` trong `actions/action_generator.py` để thay đổi khi nào actions được generate.

---

## 🛡️ Security Considerations

### Auto Block

⚠️ **CẢNH BÁO**: Auto block có thể block legitimate traffic nếu:
- False positives từ ML model
- Internal IPs bị misclassified
- Legitimate services bị block

**Khuyến nghị**:
- Chỉ enable trong production sau khi test kỹ
- Bắt đầu với `MIN_SEVERITY_FOR_BLOCK=4` (CRITICAL only)
- Monitor và review blocks thường xuyên
- Có whitelist cho trusted IPs

### Telegram Security

- **Không commit** bot token vào git
- Sử dụng environment variables
- Rotate tokens định kỳ
- Chỉ share chat ID với trusted users

---

## 📝 Examples

### Example 1: Generate Actions Only

```bash
# Disable auto execute
export AUTO_EXECUTE_ACTIONS=false

# Detect anomalies
python main.py detect

# Review actions
cat data/actions.csv

# Execute manually nếu OK
python main.py generate-actions --execute
```

### Example 2: Full Auto Response

```bash
# Enable everything
export ENABLE_ACTIONS=true
export AUTO_EXECUTE_ACTIONS=true
export ENABLE_AUTO_BLOCK=true
export ENABLE_TELEGRAM=true
export TELEGRAM_BOT_TOKEN=your_token
export TELEGRAM_CHAT_ID=your_chat_id

# Detect và auto respond
python main.py detect
```

### Example 3: Custom Severity Thresholds

```bash
# Chỉ block CRITICAL, notify từ MEDIUM
export MIN_SEVERITY_FOR_BLOCK=4  # CRITICAL only
export MIN_SEVERITY_FOR_NOTIFY=2  # MEDIUM

python main.py detect
```

---

## 🐛 Troubleshooting

### Telegram Not Working

1. **Check bot token**: Đảm bảo token đúng
2. **Check chat ID**: Đảm bảo chat ID đúng
3. **Test API**: 
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getMe"
   ```
4. **Check logs**: Xem `data/action_logs.jsonl` để debug

### Actions Not Generated

1. **Check ENABLE_ACTIONS**: Phải = true
2. **Check anomalies**: Đảm bảo có anomalies được detect
3. **Check severity**: Actions chỉ generate nếu severity đủ cao
4. **Check config**: Review action_config trong code

### Block Not Working

1. **Check ENABLE_AUTO_BLOCK**: Phải = true
2. **Check severity**: Phải >= MIN_SEVERITY_FOR_BLOCK
3. **Check IP**: Phải là external IP hoặc attack type nghiêm trọng
4. **Implement block logic**: Hiện tại chỉ log, cần implement actual block (iptables, firewall, etc.)

---

## 🔗 Integration với Wazuh

Actions có thể được tích hợp với Wazuh Manager API để:
- Block IPs qua Wazuh active response
- Send alerts đến Wazuh dashboard
- Update Wazuh rules

Cần implement trong `_execute_block_ip()` và `_execute_alert()` methods.

---

## 📚 References

- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [Action System Design](docs/ACTIONS_RESPONSE.md)

