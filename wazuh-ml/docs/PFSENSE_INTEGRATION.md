# pfSense Integration Documentation

## 📋 Tổng Quan

Hệ thống có thể tích hợp với pfSense để tự động block IP/Port khi phát hiện threats. Có 2 phương pháp:

1. **pfSense Web API** - Qua web interface (phức tạp hơn)
2. **pfSense SSH + pfctl** - Qua SSH sử dụng pfctl commands (đơn giản hơn, khuyến nghị)

---

## ⚙️ Cấu Hình

### Method 1: SSH + pfctl (Khuyến nghị)

Đơn giản và hiệu quả hơn, sử dụng SSH để chạy pfctl commands.

#### 1. Enable SSH trên pfSense

1. Login vào pfSense web interface
2. System → Advanced → Admin Access
3. Enable SSH: ✅ **Enable Secure Shell**
4. Save

#### 2. Tạo SSH User (nếu cần)

1. System → User Manager
2. Add user với SSH access
3. Hoặc sử dụng admin user (nếu đã enable SSH)

#### 3. Cấu Hình Environment Variables

Thêm vào `.env`:

```bash
# Enable pfSense integration
ENABLE_PFSENSE=true
PFSENSE_METHOD=ssh

# SSH configuration
PFSENSE_SSH_HOST=192.168.1.1
PFSENSE_SSH_USER=admin
PFSENSE_SSH_PASS=your_password
```

#### 4. Install Dependencies

```bash
pip install paramiko
```

#### 5. Tạo Firewall Table trên pfSense

Trên pfSense, tạo một firewall table để chứa blocked IPs:

1. Firewall → Aliases → Tables
2. Add table:
   - **Name**: `blocked_ips`
   - **Description**: `Blocked IPs from Wazuh ML`
3. Save

#### 6. Tạo Firewall Rule

1. Firewall → Rules → LAN (hoặc interface tương ứng)
2. Add rule:
   - **Action**: Block
   - **Interface**: LAN (hoặc interface cần block)
   - **Protocol**: Any
   - **Source**: Single host or alias → `blocked_ips` table
   - **Description**: `Wazuh ML Blocked IPs`
3. Save và Apply changes

---

### Method 2: Web API

Phức tạp hơn, cần parse CSRF tokens và HTML forms.

#### Cấu Hình

```bash
ENABLE_PFSENSE=true
PFSENSE_METHOD=api
PFSENSE_HOST=https://192.168.1.1
PFSENSE_USERNAME=admin
PFSENSE_PASSWORD=your_password
PFSENSE_VERIFY_SSL=false  # Set true nếu có valid SSL cert
```

**Lưu ý**: Method này chưa được implement đầy đủ, khuyến nghị dùng SSH method.

---

## 🚀 Sử Dụng

### 1. Enable trong Action System

```bash
# .env
ENABLE_ACTIONS=true
ENABLE_AUTO_BLOCK=true
ENABLE_PFSENSE=true
PFSENSE_METHOD=ssh
```

### 2. Test Block IP

```bash
# Detect anomalies và auto block
python main.py detect

# Hoặc generate actions và execute
python main.py generate-actions --execute
```

### 3. Verify trên pfSense

1. Firewall → Aliases → Tables → `blocked_ips`
2. Xem danh sách blocked IPs
3. Hoặc SSH vào pfSense và chạy:
   ```bash
   pfctl -t blocked_ips -T show
   ```

---

## 🔧 Cách Hoạt Động

### Khi Anomaly Được Phát Hiện

1. **Action Generator** tạo `BLOCK_IP` action nếu:
   - Severity >= HIGH (default)
   - IP là external hoặc attack type nghiêm trọng
   - `ENABLE_AUTO_BLOCK=true`

2. **Action Executor** thực thi block:
   - Nếu `ENABLE_PFSENSE=true`:
     - SSH vào pfSense
     - Chạy: `pfctl -t blocked_ips -T add <IP>`
   - Nếu không: Chỉ log action

3. **Firewall Rule** trên pfSense tự động block traffic từ IPs trong table `blocked_ips`

---

## 📝 Unblock IP

Để unblock IP, có thể:

### Method 1: Qua Code

```python
from actions.pfsense_integration import PfSenseSSH

pfsense = PfSenseSSH()
result = pfsense.unblock_ip_pfctl('192.168.1.100')
print(result)
```

### Method 2: Qua SSH

```bash
ssh admin@192.168.1.1
pfctl -t blocked_ips -T delete 192.168.1.100
```

### Method 3: Qua pfSense Web Interface

1. Firewall → Aliases → Tables → `blocked_ips`
2. Remove IP từ table

---

## ⚠️ Security Considerations

### SSH Security

1. **Sử dụng SSH keys** thay vì password:
   ```bash
   ssh-keygen -t rsa
   ssh-copy-id admin@192.168.1.1
   ```

2. **Restrict SSH access**:
   - Chỉ allow từ trusted IPs
   - Disable root login
   - Use strong passwords

3. **Rotate credentials** định kỳ

### Firewall Rules

1. **Test rules** trước khi apply
2. **Monitor blocked IPs** để tránh false positives
3. **Whitelist trusted IPs** để tránh block nhầm
4. **Set expiration** cho blocks (tự động unblock sau X giờ)

---

## 🐛 Troubleshooting

### SSH Connection Failed

1. **Check SSH enabled**: System → Advanced → Admin Access
2. **Check credentials**: Username/password đúng
3. **Check network**: Có thể connect đến pfSense
4. **Check firewall**: Port 22 không bị block

### IP Not Blocked

1. **Check table exists**: Firewall → Aliases → Tables
2. **Check firewall rule**: Rule phải reference table `blocked_ips`
3. **Check pfctl command**: SSH vào và test manually:
   ```bash
   pfctl -t blocked_ips -T add 1.1.1.1
   pfctl -t blocked_ips -T show
   ```

### False Positives

1. **Increase severity threshold**: `MIN_SEVERITY_FOR_BLOCK=4` (CRITICAL only)
2. **Review anomalies** trước khi auto block
3. **Whitelist internal IPs** trong code
4. **Monitor và adjust** thresholds

---

## 📊 Monitoring

### Check Blocked IPs

```bash
# SSH vào pfSense
ssh admin@192.168.1.1
pfctl -t blocked_ips -T show
```

### View Action Logs

```bash
# Xem action logs
cat data/action_logs.jsonl | jq '.action.params.ip' | sort | uniq
```

### pfSense Logs

1. Status → System Logs → Firewall
2. Filter: `blocked_ips`
3. Xem blocked traffic

---

## 🔗 References

- [pfSense Documentation](https://docs.netgate.com/pfsense/)
- [pfctl Manual](https://www.freebsd.org/cgi/man.cgi?query=pfctl)
- [Paramiko Documentation](https://www.paramiko.org/)

---

## 💡 Future Enhancements

- [ ] Auto unblock sau X giờ
- [ ] Whitelist management
- [ ] Block statistics và reporting
- [ ] Integration với pfSense API (full implementation)
- [ ] Support cho multiple pfSense instances
- [ ] Rate limiting để tránh spam blocks

