# Actions Module - Hướng Dẫn Sử Dụng

## 📋 Tổng Quan

Module `actions` cung cấp hệ thống tự động tạo và thực thi các hành động (actions) dựa trên các anomalies được phát hiện. Hệ thống hỗ trợ nhiều loại actions như block/reject IP, block port, alert, và tích hợp với pfSense firewall.

## 🏗️ Kiến Trúc

Module bao gồm 4 thành phần chính:

1. **ActionGenerator** - Tự động tạo actions dựa trên anomalies
2. **ActionExecutor** - Thực thi các actions
3. **ActionManager** - Quản lý và điều phối toàn bộ quy trình
4. **pfSense Integration** - Tích hợp với pfSense firewall

```
┌─────────────┐
│  Anomalies  │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│ ActionGenerator  │ ──► Tạo actions
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  ActionManager   │ ──► Quản lý quy trình
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ ActionExecutor   │ ──► Thực thi actions
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  pfSense/Logs    │ ──► Kết quả
└──────────────────┘
```

## 🎯 Các Loại Actions

### 1. **LOG** - Ghi log
- **Mô tả**: Luôn luôn được tạo để ghi lại anomaly
- **Tự động**: Có
- **Tham số**: `event_desc`, `agent`, `timestamp`, `anomaly_score`

### 2. **ALERT** - Cảnh báo
- **Mô tả**: Gửi cảnh báo đến security team
- **Điều kiện**: Severity >= MEDIUM
- **Tự động**: Có
- **Tham số**: `attack_type`, `event_desc`, `agent`, `src_ip`, `dst_ip`, `confidence`

### 3. **BLOCK_IP** - Chặn IP
- **Mô tả**: Chặn IP trên pfSense firewall
- **Điều kiện**: 
  - `enable_auto_block = True`
  - Severity >= `min_severity_for_block` (default: HIGH)
  - IP là external hoặc attack type nghiêm trọng
- **Tự động**: Có (nếu enabled)
- **Tham số**: 
  - `ip`: IP address
  - `action`: 'block' hoặc 'reject' (default: 'block')
  - `duration`: Thời gian block (seconds, 0 = permanent)
  - `interface`: Interface name (default: 'lan')
  - `table_name`: pfSense table name (default: 'blocked_ips')

### 4. **BLOCK_PORT** - Chặn Port
- **Mô tả**: Chặn port trên pfSense firewall
- **Điều kiện**: 
  - Severity = CRITICAL
  - Attack type: 'dos_ddos' hoặc 'port_scan'
- **Tự động**: Có
- **Tham số**: 
  - `port`: Port number
  - `ip`: Optional IP address
  - `action`: 'block' hoặc 'reject' (default: 'block')
  - `duration`: Thời gian block (seconds)
  - `interface`: Interface name (default: 'lan')

### 5. **REJECT_IP** - Từ chối IP
- **Mô tả**: Từ chối kết nối từ IP (reject thay vì block)
- **Tự động**: Không (phải tạo thủ công)
- **Tham số**: Tương tự BLOCK_IP

### 6. **REJECT_PORT** - Từ chối Port
- **Mô tả**: Từ chối kết nối đến port
- **Tự động**: Không (phải tạo thủ công)
- **Tham số**: Tương tự BLOCK_PORT

### 7. **ESCALATE** - Nâng cấp
- **Mô tả**: Nâng cấp cảnh báo đến security manager
- **Điều kiện**: Severity = CRITICAL
- **Tự động**: Có
- **Tham số**: `attack_type`, `event_desc`, `agent`

## 🚀 Cách Sử Dụng

### 1. Cấu Hình Cơ Bản

```python
from actions.action_manager import ActionManager

# Cấu hình
config = {
    'enable_auto_block': True,
    'min_severity_for_block': 3,  # HIGH
    'min_severity_for_notify': 2,  # MEDIUM
    'enable_pfsense': True,
    'pfsense_method': 'ssh',  # 'ssh' hoặc 'api'
    'action_log_path': 'data/action_logs.jsonl'
}

# Khởi tạo ActionManager
manager = ActionManager(config)
```

### 2. Xử Lý Anomalies

```python
import pandas as pd

# DataFrame chứa anomalies (từ detection module)
anomalies_df = pd.DataFrame([
    {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'dst_port': 80,
        'predicted_attack_type': 'dos_ddos',
        'attack_type_confidence': 0.95,
        'anomaly_score': 0.85,
        'rule_level': 15,
        'event_desc': 'DoS attack detected',
        'agent': 'wazuh-agent-01',
        'timestamp': '2024-01-01T10:00:00'
    }
])

# Process anomalies: generate và execute actions
result = manager.process_anomalies(anomalies_df, execute=True)

# Kết quả
print(f"Total actions: {result['summary']['total_actions']}")
print(f"Success: {result['summary']['success_count']}")
print(f"Failed: {result['summary']['fail_count']}")
```

### 3. Chỉ Generate Actions (Không Execute)

```python
# Chỉ generate actions, không thực thi
result = manager.process_anomalies(anomalies_df, execute=False)

# Xem actions được generate
actions_df = result['actions']
print(actions_df[['action_type', 'target', 'reason', 'severity']])
```

### 4. Execute Actions Thủ Công

```python
from actions.action_executor import ActionExecutor

executor = ActionExecutor(config)

# Action dict
action = {
    'type': 'block_ip',
    'target': '192.168.1.100',
    'reason': 'Manual block',
    'severity': 'HIGH',
    'params': {
        'ip': '192.168.1.100',
        'action': 'block',
        'duration': 3600,  # 1 hour
        'interface': 'lan',
        'table_name': 'blocked_ips'
    }
}

# Execute action
result = executor.execute_action(action)
print(result)
```

### 5. Process Scheduled Unblocks

```python
# Process các scheduled unblocks đã đến thời gian
results = executor.process_scheduled_unblocks()

for result in results:
    print(f"Unblocked: {result.get('rule_id')} - {result.get('message')}")
```

## ⚙️ Cấu Hình Chi Tiết

### Environment Variables

```bash
# Enable pfSense integration
export ENABLE_PFSENSE=true
export PFSENSE_METHOD=ssh  # 'ssh' hoặc 'api'

# pfSense SSH configuration
export PFSENSE_SSH_HOST=192.168.1.1
export PFSENSE_SSH_USER=admin
export PFSENSE_SSH_PASS=your_password

# pfSense API configuration (nếu dùng API)
export PFSENSE_HOST=https://192.168.1.1
export PFSENSE_USERNAME=admin
export PFSENSE_PASSWORD=your_password
export PFSENSE_VERIFY_SSL=false
```

### Config Dictionary

```python
config = {
    # Auto block settings
    'enable_auto_block': True,  # Enable tự động block IP
    'min_severity_for_block': 3,  # 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    'min_severity_for_notify': 2,
    
    # pfSense settings
    'enable_pfsense': True,
    'pfsense_method': 'ssh',  # 'ssh' hoặc 'api'
    
    # Logging
    'action_log_path': 'data/action_logs.jsonl'
}
```

## 🔧 Tích Hợp với pfSense

### 1. Cấu Hình pfSense

#### Tạo Firewall Table

1. Login vào pfSense web interface
2. Firewall → Aliases → Tables
3. Add table:
   - **Name**: `blocked_ips`
   - **Description**: `Blocked IPs from Wazuh ML`
4. Save

#### Tạo Firewall Rule

1. Firewall → Rules → LAN (hoặc interface tương ứng)
2. Add rule:
   - **Action**: Block
   - **Interface**: LAN
   - **Protocol**: Any
   - **Source**: Single host or alias → `blocked_ips` table
   - **Description**: `Wazuh ML Blocked IPs`
3. Save và Apply changes

#### Enable SSH (nếu dùng SSH method)

1. System → Advanced → Admin Access
2. Enable SSH: ✅ **Enable Secure Shell**
3. Save

### 2. Block vs Reject

- **Block**: Drop packets silently (không phản hồi)
- **Reject**: Drop packets và gửi RST/ICMP unreachable

```python
# Block IP (silent drop)
action = {
    'type': 'block_ip',
    'params': {'ip': '1.2.3.4', 'action': 'block'}
}

# Reject IP (send RST)
action = {
    'type': 'reject_ip',
    'params': {'ip': '1.2.3.4', 'action': 'reject'}
}
```

### 3. Schedule Rules (Tự Động Unblock)

Hệ thống hỗ trợ tự động unblock sau một khoảng thời gian:

```python
# Block IP với duration (tự động unblock sau 1 giờ)
action = {
    'type': 'block_ip',
    'params': {
        'ip': '1.2.3.4',
        'action': 'block',
        'duration': 3600  # seconds
    }
}

# Execute action
result = executor.execute_action(action)

# Process scheduled unblocks (chạy định kỳ)
results = executor.process_scheduled_unblocks()
```

Scheduled rules được lưu trong `data/scheduled_rules.json` và có thể được process tự động bằng cron job hoặc scheduled task.

## 📊 Ví Dụ Sử Dụng

### Ví Dụ 1: Detect và Auto Block

```python
from actions.action_manager import ActionManager
import pandas as pd

# Cấu hình
config = {
    'enable_auto_block': True,
    'min_severity_for_block': 3,
    'enable_pfsense': True,
    'pfsense_method': 'ssh'
}

# Khởi tạo
manager = ActionManager(config)

# Anomalies từ detection
anomalies_df = pd.DataFrame([
    {
        'src_ip': '203.0.113.1',  # External IP
        'predicted_attack_type': 'brute_force',
        'rule_level': 12,
        'anomaly_score': 0.9,
        'event_desc': 'Brute force attack',
        'agent': 'wazuh-01',
        'timestamp': '2024-01-01T10:00:00'
    }
])

# Process: generate và execute
result = manager.process_anomalies(anomalies_df, execute=True)

# Kết quả
print(f"Actions generated: {result['summary']['total_actions']}")
print(f"Success: {result['summary']['success_count']}")
```

### Ví Dụ 2: Manual Block IP

```python
from actions.action_executor import ActionExecutor

executor = ActionExecutor({'enable_pfsense': True, 'pfsense_method': 'ssh'})

action = {
    'type': 'block_ip',
    'target': '203.0.113.1',
    'reason': 'Manual block - suspicious activity',
    'severity': 'HIGH',
    'params': {
        'ip': '203.0.113.1',
        'action': 'block',
        'duration': 7200,  # 2 hours
        'interface': 'wan',
        'table_name': 'blocked_ips'
    }
}

result = executor.execute_action(action)
if result['success']:
    print(f"✅ {result['message']}")
    if 'scheduled_unblock' in result.get('block_info', {}):
        print(f"⏰ Will unblock at: {result['block_info']['scheduled_unblock']['unblock_time']}")
```

### Ví Dụ 3: Block Port

```python
action = {
    'type': 'block_port',
    'target': '10.0.0.1:80',
    'reason': 'Block port 80 due to DoS attack',
    'severity': 'CRITICAL',
    'params': {
        'port': 80,
        'ip': '10.0.0.1',  # Optional: block port for specific IP
        'action': 'block',
        'duration': 3600,
        'interface': 'lan'
    }
}

result = executor.execute_action(action)
```

### Ví Dụ 4: List Blocked IPs

```python
from actions.pfsense_integration import PfSenseSSH

pfsense = PfSenseSSH()
blocked_ips = pfsense.list_blocked_ips_pfctl('blocked_ips')

print(f"Blocked IPs ({len(blocked_ips)}):")
for ip in blocked_ips:
    print(f"  - {ip}")
```

### Ví Dụ 5: Unblock IP

```python
from actions.pfsense_integration import PfSenseSSH

pfsense = PfSenseSSH()
result = pfsense.unblock_ip_pfctl('203.0.113.1', 'blocked_ips')

if result['success']:
    print(f"✅ {result['message']}")
```

## 📝 Action Logs

Tất cả actions và kết quả được log vào file JSONL:

```python
# File: data/action_logs.jsonl
# Format:
{
    "action": {
        "type": "block_ip",
        "target": "203.0.113.1",
        "reason": "...",
        "params": {...}
    },
    "result": {
        "success": true,
        "message": "...",
        "timestamp": "2024-01-01T10:00:00"
    },
    "logged_at": "2024-01-01T10:00:00"
}
```

## 🔍 Debugging

### Kiểm Tra Actions Được Generate

```python
result = manager.process_anomalies(anomalies_df, execute=False)
actions_df = result['actions']

# Xem chi tiết
print(actions_df[['action_type', 'target', 'reason', 'severity']].to_string())
```

### Kiểm Tra Execution Results

```python
result = manager.process_anomalies(anomalies_df, execute=True)
results_df = result['results']

# Xem kết quả
print(results_df[['action_type', 'success', 'message']].to_string())

# Xem failed actions
failed = results_df[~results_df['success']]
print(f"Failed actions: {len(failed)}")
```

### Kiểm Tra Scheduled Rules

```python
import json

with open('data/scheduled_rules.json', 'r') as f:
    schedules = json.load(f)

print(f"Scheduled rules: {len(schedules)}")
for schedule in schedules:
    print(f"  - {schedule['rule_id']}: unblock at {schedule['unblock_time']}")
```

## ⚠️ Lưu Ý

1. **Security**: 
   - Sử dụng SSH keys thay vì password khi có thể
   - Restrict SSH access từ trusted IPs
   - Rotate credentials định kỳ

2. **Performance**:
   - Process scheduled unblocks định kỳ (cron job)
   - Monitor action logs để tránh spam
   - Set duration hợp lý để tránh block vĩnh viễn nhầm

3. **Testing**:
   - Test với test IPs trước khi deploy production
   - Verify pfSense rules hoạt động đúng
   - Monitor action logs để debug

## 📚 API Reference

### ActionManager

```python
class ActionManager:
    def __init__(self, config: Optional[Dict] = None)
    def process_anomalies(anomalies_df: pd.DataFrame, execute: Optional[bool] = None) -> Dict
    def save_actions(actions_df: pd.DataFrame, output_path: str)
    def save_results(results_df: pd.DataFrame, output_path: str)
```

### ActionExecutor

```python
class ActionExecutor:
    def __init__(self, config: Optional[Dict] = None)
    def execute_action(action: Dict) -> Dict
    def execute_actions_batch(actions_df: pd.DataFrame) -> pd.DataFrame
    def process_scheduled_unblocks() -> List[Dict]
```

### ActionGenerator

```python
class ActionGenerator:
    def __init__(self, config: Optional[Dict] = None)
    def generate_actions(anomaly_row: pd.Series) -> List[Dict]
    def generate_actions_batch(anomalies_df: pd.DataFrame) -> pd.DataFrame
```

### PfSenseSSH

```python
class PfSenseSSH:
    def block_ip_pfctl(ip: str, table_name: str = 'blocked_ips', action: str = 'block', interface: str = 'lan') -> Dict
    def unblock_ip_pfctl(ip: str, table_name: str = 'blocked_ips') -> Dict
    def block_port_pfctl(port: int, ip: Optional[str] = None, action: str = 'block', interface: str = 'lan') -> Dict
    def list_blocked_ips_pfctl(table_name: str = 'blocked_ips') -> List[str]
```

## 🔗 Liên Kết

- [pfSense Integration Documentation](../docs/PFSENSE_INTEGRATION.md)
- [Main README](../README.md)

