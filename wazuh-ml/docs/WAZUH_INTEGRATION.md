# Wazuh Integration Guide

This guide explains how to integrate the Hybrid NIDS ML system with Wazuh SIEM.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WAZUH + HYBRID NIDS INTEGRATION                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌─────────────────┐     ┌──────────────────────────┐ │
│  │   pfSense    │────▶│   Hybrid NIDS   │────▶│    Wazuh Manager         │ │
│  │  (Network)   │     │   ML Pipeline   │     │                          │ │
│  └──────────────┘     └────────┬────────┘     │  - Custom Decoder        │ │
│                                │              │  - Custom Rules          │ │
│                                │              │  - Active Response       │ │
│  ┌──────────────┐              │              │  - Dashboard             │ │
│  │  Wazuh Agent │──────────────┼─────────────▶│                          │ │
│  │   (HIDS)     │              │              └────────────┬─────────────┘ │
│  └──────────────┘              │                           │               │
│                                │                           ▼               │
│                         ┌──────┴──────┐          ┌─────────────────┐       │
│                         │ Correlation │◀─────────│  Wazuh API      │       │
│                         │   Engine    │          │  (Alerts Feed)  │       │
│                         └─────────────┘          └─────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Integration Methods

### Method 1: Log File Monitoring (Recommended for Testing)

The simplest method - NIDS writes JSON logs that Wazuh agent monitors.

**Pros:** Easy setup, no special permissions needed  
**Cons:** Slight delay (agent poll interval)

### Method 2: Wazuh Agent Socket (Recommended for Production)

Direct communication with Wazuh agent via Unix socket.

**Pros:** Instant delivery, low overhead  
**Cons:** Requires agent on same host, permission configuration

### Method 3: Wazuh API (Remote Integration)

Push alerts directly to Wazuh Manager via REST API.

**Pros:** Works remotely, no agent needed on NIDS host  
**Cons:** Requires API credentials, network access to manager

---

## Installation Steps

### Step 1: Install Wazuh Agent on NIDS Host

```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# Install agent
apt-get update
apt-get install wazuh-agent

# Configure agent (replace MANAGER_IP)
sed -i 's/MANAGER_IP/YOUR_WAZUH_MANAGER_IP/' /var/ossec/etc/ossec.conf

# Start agent
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### Step 2: Copy Custom Decoder to Wazuh Manager

```bash
# On Wazuh Manager
scp config/wazuh/hybrid_nids_decoder.xml root@WAZUH_MANAGER:/var/ossec/etc/decoders/

# Verify decoder
/var/ossec/bin/wazuh-logtest
# Paste a sample log line to test
```

### Step 3: Copy Custom Rules to Wazuh Manager

```bash
# On Wazuh Manager
scp config/wazuh/hybrid_nids_rules.xml root@WAZUH_MANAGER:/var/ossec/etc/rules/

# Restart Wazuh Manager
systemctl restart wazuh-manager
```

### Step 4: Configure Log Monitoring on Agent

Add to `/var/ossec/etc/ossec.conf` on the NIDS host:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/hybrid-nids/alerts.json</location>
  <label key="source">hybrid-nids</label>
</localfile>
```

Then restart the agent:
```bash
systemctl restart wazuh-agent
```

### Step 5: Configure NIDS for Wazuh

Set environment variables:

```bash
# For API method
export WAZUH_API_URL="https://YOUR_WAZUH_MANAGER:55000"
export WAZUH_API_USER="wazuh"
export WAZUH_API_PASSWORD="your_password"

# Or configure in code
python scripts/detection_pipeline.py --continuous \
    --action wazuh \
    --action alert \
    --action block
```

---

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WAZUH_API_URL` | Wazuh Manager API URL | None |
| `WAZUH_API_USER` | API username | wazuh |
| `WAZUH_API_PASSWORD` | API password | None |

### Action Configuration

```python
from nids import DetectionPipeline, ActionType

action_config = {
    'enabled_actions': [ActionType.LOG, ActionType.ALERT, ActionType.WAZUH],
    'wazuh': {
        'method': 'auto',  # 'socket', 'api', 'log', or 'auto'
        'socket_path': '/var/ossec/queue/sockets/queue',
        'api_url': 'https://wazuh-manager:55000',
        'api_user': 'wazuh',
        'api_password': 'secret',
        'log_path': '/var/log/hybrid-nids/alerts.json',
        'alerts_path': '/var/ossec/logs/alerts/alerts.json',  # For HIDS correlation
        'lookback_minutes': 5,  # How far back to look for HIDS alerts
    }
}

pipeline = DetectionPipeline(
    pfsense_host='192.168.1.1',
    pfsense_user='admin',
    action_config=action_config
)
```

---

## Custom Rules Reference

### Rule ID Ranges

| Range | Purpose |
|-------|---------|
| 100100-100109 | Base rules and threat levels |
| 100110-100119 | Detection layer specific rules |
| 100120-100129 | Attack type specific rules |
| 100130-100139 | Confidence-based rules |
| 100140-100149 | Correlation rules |
| 100150-100159 | Active response trigger rules |

### Key Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100100 | 3 | Base rule for all NIDS detections |
| 100104 | 13 | CRITICAL threat level |
| 100120 | 12 | DoS/DDoS attack detected |
| 100126 | 10 | Zero-day/anomaly detected |
| 100142 | 14 | Attack chain: Scan → Attack |
| 100150 | 14 | Auto-block trigger for critical threats |

---

## HIDS Correlation

The system can correlate network-based detections with Wazuh host-based alerts:

### Correlation Types

1. **IP Match**: Same source IP appears in both NIDS and HIDS alerts
2. **Attack Pattern**: Related attack types (e.g., network brute force + SSH failures)
3. **Attack Chain**: Escalating alerts from same source

### Example: Detecting Malware Installed via Phishing

```
1. [HIDS] Wazuh detects: New file created in /tmp
2. [HIDS] Wazuh detects: Suspicious process spawned
3. [NIDS] ML detects: Anomalous outbound traffic to unknown IP
4. [CORRELATED] Attack chain: Possible malware C2 communication
```

### Enable Correlation

```python
from nids import HIDSCorrelator, WazuhAlertParser

# Configure parser
config = {
    'alerts_path': '/var/ossec/logs/alerts/alerts.json',
    'lookback_minutes': 10
}

# Create correlator
correlator = HIDSCorrelator(config)

# In your detection loop
result = nids.analyze(pcap_file)
correlated = correlator.correlate(result.detections)

for alert in correlated:
    print(f"[{alert.correlation_type}] {alert.description}")
    print(f"  Recommended: {alert.recommended_action}")
```

---

## Testing the Integration

### 1. Test Decoder

On Wazuh Manager:
```bash
/var/ossec/bin/wazuh-logtest
```

Paste this sample log:
```json
{"timestamp":"2026-01-01T12:00:00","hybrid_nids":{"src_ip":"192.168.1.100","dst_ip":"10.0.0.1","src_port":54321,"dst_port":80,"protocol":"TCP","attack_type":"DDOS","confidence":0.95,"threat_level":"CRITICAL","threat_level_value":4,"detection_layer":"xgboost","flow_id":"12345","anomaly_score":null}}
```

Expected output:
```
**Phase 3: Completed filtering (rules).
        id: '100104'
        level: '13'
        description: 'Hybrid NIDS [CRITICAL]: DDOS from 192.168.1.100 to 10.0.0.1'
```

### 2. Test End-to-End

```bash
# Start detection with Wazuh action
python scripts/detection_pipeline.py --realtime --interval 30 --action wazuh --action alert

# Check Wazuh Manager for alerts
tail -f /var/ossec/logs/alerts/alerts.json | grep hybrid_nids
```

### 3. Test Correlation

```bash
# Generate some HIDS alerts (e.g., failed SSH)
ssh invalid@localhost

# Run detection
python -c "
from nids import HIDSCorrelator
correlator = HIDSCorrelator()
alerts = correlator.parser.get_recent_alerts(5)
print(f'Found {len(alerts)} HIDS alerts')
for a in alerts:
    print(f'  [{a.rule_level}] {a.rule_description}')
"
```

---

## Troubleshooting

### Issue: Alerts not appearing in Wazuh

1. Check agent is connected: `wazuh-control status`
2. Verify log file exists: `ls -la /var/log/hybrid-nids/`
3. Check agent is monitoring log: `grep hybrid-nids /var/ossec/etc/ossec.conf`
4. Test decoder: `/var/ossec/bin/wazuh-logtest`

### Issue: Socket permission denied

```bash
# Add NIDS user to ossec group
usermod -a -G ossec YOUR_USER

# Or adjust socket permissions
chmod 660 /var/ossec/queue/sockets/queue
```

### Issue: API authentication failed

1. Verify API is enabled on manager
2. Check credentials: `curl -u wazuh:password https://manager:55000/`
3. Verify SSL certificate or use `verify=False` for self-signed

---

## Dashboard Visualization

After integration, you'll see NIDS detections in Wazuh Dashboard:

1. **Security Events** → Filter by `rule.groups: hybrid_nids`
2. **Create custom dashboard** for ML detections
3. **Set up email alerts** for critical rules (100104, 100150)

### Sample Dashboard Queries

```
# All NIDS detections
rule.groups: hybrid_nids

# Critical threats only  
rule.id: 100104

# Zero-day/anomaly detections
rule.id: 100126 OR nids.layer: isolation_forest

# Attack chains
rule.id: 100142
```
