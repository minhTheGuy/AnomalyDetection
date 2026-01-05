# Action Trigger Conditions

This document explains when each action (email, webhook, Wazuh) is triggered in the detection pipeline.

## Action Trigger Summary

| Action | Trigger Condition | Threat Level Required |
|--------|------------------|---------------------|
| **LOG** | Always | None (all detections) |
| **ALERT** | Console output | MEDIUM or higher |
| **BLOCK** | IP blocking | HIGH or CRITICAL (configurable) |
| **WEBHOOK** | HTTP POST | MEDIUM or higher |
| **EMAIL** | Email notification | CRITICAL only |
| **WAZUH** | SIEM integration | None (all detections) |

## Detailed Trigger Conditions

### 1. LOG Action
**When:** Always triggered for every detection
- **Condition:** `ActionType.LOG in enabled_actions`
- **Threat Level:** None (all threat levels)
- **Purpose:** Log all detections to file for audit trail
- **Output:** `logs/action_logs.jsonl`

```python
# Always executed if LOG action is enabled
if ActionType.LOG in self.enabled_actions:
    self._action_log(d)
```

### 2. ALERT Action
**When:** Medium threat level or higher
- **Condition:** `ActionType.ALERT in enabled_actions AND threat_level >= MEDIUM`
- **Threat Level:** MEDIUM (2), HIGH (3), CRITICAL (4)
- **Purpose:** Print colored alerts to console
- **Output:** Console (stdout)

```python
# Triggered for MEDIUM, HIGH, CRITICAL
if ActionType.ALERT in self.enabled_actions and lvl >= ThreatLevel.MEDIUM.value:
    self._action_alert(d)
```

### 3. BLOCK Action
**When:** High threat level or higher (configurable)
- **Condition:** `ActionType.BLOCK in enabled_actions AND threat_level >= block_threshold`
- **Default Threshold:** HIGH (3)
- **Configurable:** Via `--block-threshold` or `BLOCK_THRESHOLD` env var
- **Purpose:** Block source IP on pfSense firewall
- **Duration:** Configurable (default: 300 seconds)

```python
# Triggered for HIGH or CRITICAL (by default)
if ActionType.BLOCK in self.enabled_actions and lvl >= self.block_threshold.value:
    self._action_block(d)
```

### 4. WEBHOOK Action
**When:** Medium threat level or higher
- **Condition:** `ActionType.WEBHOOK in enabled_actions AND threat_level >= MEDIUM`
- **Threat Level:** MEDIUM (2), HIGH (3), CRITICAL (4)
- **Purpose:** Send HTTP POST to external webhook endpoint
- **Output:** HTTP POST to `WEBHOOK_URL`
- **Payload:** JSON with detection details

```python
# Triggered for MEDIUM, HIGH, CRITICAL
if ActionType.WEBHOOK in self.enabled_actions and lvl >= ThreatLevel.MEDIUM.value:
    self._action_webhook(d)
```

**Webhook Payload:**
```json
{
  "timestamp": "2026-01-03T13:25:24",
  "source": "hybrid-nids",
  "detection": {
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "attack_type": "DoS",
    "confidence": 0.95,
    "threat_level": "HIGH",
    "layer": "xgboost"
  }
}
```

### 5. EMAIL Action
**When:** Critical threat level only
- **Condition:** `ActionType.EMAIL in enabled_actions AND threat_level == CRITICAL`
- **Threat Level:** CRITICAL (4) only
- **Purpose:** Send email alert for critical threats
- **Output:** Email to configured recipients
- **Subject:** "Hybrid NIDS Alert: [attack_type]"

```python
# Triggered ONLY for CRITICAL
if ActionType.EMAIL in self.enabled_actions and lvl >= ThreatLevel.CRITICAL.value:
    self._action_email(d)
```

**Email Content:**
- **Subject:** `Hybrid NIDS Alert: {attack_type}`
- **Body:** Formatted detection details including:
  - Source/Destination IPs
  - Attack type
  - Confidence score
  - Threat level
  - Detection layer
  - Timestamp

### 6. WAZUH Action
**When:** All detections (no threat level filter)
- **Condition:** `ActionType.WAZUH in enabled_actions`
- **Threat Level:** None (all threat levels: LOW, MEDIUM, HIGH, CRITICAL)
- **Purpose:** Send all detections to Wazuh SIEM for correlation
- **Output:** Wazuh Manager (socket/API/log file)
- **Method:** Auto-detected (socket > API > log file)

```python
# Triggered for ALL detections (no threshold)
if ActionType.WAZUH in self.enabled_actions:
    self._action_wazuh(d)
```

**Why all detections?**
- Wazuh needs all data for correlation with HIDS alerts
- Low-level detections might correlate with high-level HIDS events
- Enables comprehensive threat intelligence

## Threat Level Values

```python
class ThreatLevel(Enum):
    LOW = 1        # Informational
    MEDIUM = 2     # Suspicious
    HIGH = 3       # Dangerous
    CRITICAL = 4   # Immediate threat
```

## Example Scenarios

### Scenario 1: Port Scan (MEDIUM threat)
- ✅ LOG: Written to file
- ✅ ALERT: Printed to console
- ❌ BLOCK: Not triggered (below HIGH threshold)
- ✅ WEBHOOK: Sent to webhook URL
- ❌ EMAIL: Not triggered (below CRITICAL)
- ✅ WAZUH: Sent to Wazuh Manager

### Scenario 2: DoS Attack (HIGH threat)
- ✅ LOG: Written to file
- ✅ ALERT: Printed to console
- ✅ BLOCK: IP blocked on pfSense (if enabled)
- ✅ WEBHOOK: Sent to webhook URL
- ❌ EMAIL: Not triggered (below CRITICAL)
- ✅ WAZUH: Sent to Wazuh Manager

### Scenario 3: Critical Infiltration (CRITICAL threat)
- ✅ LOG: Written to file
- ✅ ALERT: Printed to console
- ✅ BLOCK: IP blocked on pfSense
- ✅ WEBHOOK: Sent to webhook URL
- ✅ EMAIL: Email sent to administrators
- ✅ WAZUH: Sent to Wazuh Manager

### Scenario 4: Low Anomaly (LOW threat)
- ✅ LOG: Written to file
- ❌ ALERT: Not triggered (below MEDIUM)
- ❌ BLOCK: Not triggered
- ❌ WEBHOOK: Not triggered (below MEDIUM)
- ❌ EMAIL: Not triggered (below CRITICAL)
- ✅ WAZUH: Sent to Wazuh Manager (all detections)

## Configuration

### Enable Actions
```bash
# Enable specific actions
python scripts/detection_pipeline.py \
    --continuous \
    --action log \
    --action alert \
    --action webhook \
    --action email \
    --action wazuh
```

### Configure Thresholds
```bash
# Set block threshold to CRITICAL only
python scripts/detection_pipeline.py \
    --continuous \
    --action block \
    --block-threshold CRITICAL
```

### Environment Variables
```bash
# Webhook
WEBHOOK_URL=https://your-server.com/webhook

# Email
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-password
EMAIL_FROM=nids@example.com
EMAIL_TO=admin@example.com

# Wazuh
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=your-password
```

## Action Execution Order

Actions are executed in this order for each detection:

1. **LOG** (always first, for audit trail)
2. **ALERT** (console output)
3. **BLOCK** (firewall blocking)
4. **WEBHOOK** (external notification)
5. **EMAIL** (critical alerts only)
6. **WAZUH** (SIEM integration)

## Notes

- **All actions are independent**: Each action checks its own conditions
- **No action blocking**: If one action fails, others still execute
- **Error handling**: Failed actions log errors but don't stop the pipeline
- **Rate limiting**: Consider implementing rate limits for webhook/email in production
- **Wazuh always receives all detections**: This enables better correlation

## Troubleshooting

### Webhook not triggered
- Check if threat level is MEDIUM or higher
- Verify `WEBHOOK_URL` is configured
- Check webhook endpoint is accessible

### Email not sent
- Check if threat level is CRITICAL
- Verify email configuration (SMTP settings)
- Check email credentials

### Wazuh not receiving data
- Verify Wazuh action is enabled
- Check Wazuh connection (socket/API/log)
- Review Wazuh logs for errors

