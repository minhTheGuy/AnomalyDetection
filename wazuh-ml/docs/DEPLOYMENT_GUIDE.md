# Wazuh-ML: Deployment Guide

Production deployment and operation guide for the 3-Layer Hybrid NIDS.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Running Detection](#3-running-detection)
4. [Production Deployment](#4-production-deployment)
5. [Monitoring & Maintenance](#5-monitoring--maintenance)
6. [Wazuh Integration](#6-wazuh-integration)

---

## 1. Prerequisites

### System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 22.04 LTS |
| Python | 3.10+ (3.12 recommended) |
| RAM | 8 GB minimum (16 GB for training) |
| GPU | Optional (NVIDIA for faster VAE training) |
| pfSense | 2.6+ with SSH enabled |

### Network Configuration

| Host | IP Address | Purpose |
|------|------------|---------|
| pfSense Firewall | 172.16.158.100 | Traffic capture via SSH |
| Wazuh Server | 172.16.158.150 | Alert indexing (optional) |
| Gateway | 172.16.158.1 | Whitelisted by default |

---

## 2. Installation

### 2.1 Clone and Setup

```bash
# 2. Clone repository to /opt
cd /opt
sudo git clone https://github.com/your-repo/wazuh-ml.git
cd wazuh-ml

# 3. Setup virtual environment
sudo python3 -m venv mlenv
source mlenv/bin/activate
pip install -r requirements.txt
pip install -r requirements.txt

# Verify CICFlowMeter
cicflowmeter --help
```

### 2.2 Configure SSH Access to pfSense

```bash
# Generate SSH key (if not exists)
ssh-keygen -t rsa -b 4096

# Copy key to pfSense
ssh-copy-id admin@172.16.158.100

# Test connection
ssh admin@172.16.158.100 "echo 'SSH OK'"
```

### 2.3 Verify Models Exist

```bash
ls -la data/models/

# Should contain:
# - isolation_forest_latest.pkl
# - autoencoder_latest.keras
# - vae_encoder_latest.keras
# - vae_decoder_latest.keras
# - cicflowmeter_model_retrained_*.pkl
```

If models are missing, run training:

```bash
# Train anomaly detectors (IForest + VAE)
python scripts/train_anomaly_detector.py --sample-size 300000

# Train XGBoost classifier
jupyter notebook notebooks/train_cicids_final.ipynb
```

---

## 3. Running Detection

### 3.1 Command Reference

```bash
python scripts/detection_pipeline.py [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--pcap FILE` | Analyze PCAP file | - |
| `--data FILE` | Analyze flow CSV | - |
| `--realtime` | Single capture cycle | - |
| `--continuous` | Loop forever | - |
| `--streaming` | Threaded real-time | - |
| `--interval N` | Capture duration (sec) | 60 |
| `--threshold N` | XGBoost confidence | 0.5 |
| `--anomaly-threshold N` | IForest threshold | 0.45 |
| `--action ACTION` | Response action | log |

### 3.2 Detection Modes

**Single PCAP Analysis**
```bash
python scripts/detection_pipeline.py --pcap /path/to/capture.pcap
```

**Real-time Single Cycle**
```bash
python scripts/detection_pipeline.py --realtime --interval 60
```

**Continuous Monitoring**
```bash
python scripts/detection_pipeline.py --continuous --interval 60 \
    --action log --action alert
```

**Streaming Mode (Threaded)**
```bash
python scripts/detection_pipeline.py --streaming --interval 15 \
    --action alert --action block
```

### 3.3 Response Actions

| Action | Effect |
|--------|--------|
| `log` | Write to `logs/realtime_alerts.jsonl` |
| `alert` | Generate alert (console + log) |
| `block` | Block IP on pfSense firewall |
| `webhook` | POST to configured webhook URL |
| `email` | Send email notification |

**Example with Multiple Actions:**
```bash
python scripts/detection_pipeline.py --continuous \
    --action log --action alert --action block --action webhook
```

---

## 4. Production Deployment

### 4.1 systemd Service

Create service file at `/etc/systemd/system/wazuh-ml.service`:

```ini
[Unit]
Description=Wazuh-ML 3-Layer Hybrid NIDS
After=network.target
Documentation=file:///home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml/docs/PROJECT_GUIDE.md

[Service]
Type=simple
User=dangminh0113
WorkingDirectory=/home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml
Environment="PATH=/home/dangminh0113/mlenv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PFSENSE_HOST=172.16.158.100"
Environment="PFSENSE_USER=admin"
Environment="PFSENSE_INTERFACE=em1"
ExecStart=/home/dangminh0113/mlenv/bin/python scripts/detection_pipeline.py \
    --continuous --interval 60 --action log --action alert
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 4.2 Enable and Start

```bash
# Copy service file
sudo cp config/wazuh-ml.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable wazuh-ml

# Start service
sudo systemctl start wazuh-ml

# Check status
sudo systemctl status wazuh-ml
```

### 4.3 Service Management

```bash
# View logs
sudo journalctl -u wazuh-ml -f

# Restart service
sudo systemctl restart wazuh-ml

# Stop service
sudo systemctl stop wazuh-ml

# Disable auto-start
sudo systemctl disable wazuh-ml
```

### 4.4 Log Rotation

Copy logrotate config:

```bash
sudo cp config/wazuh-ml.logrotate /etc/logrotate.d/wazuh-ml
```

Content of `wazuh-ml.logrotate`:

```
/home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml/logs/*.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 dangminh0113 dangminh0113
}
```

---

## 5. Monitoring & Maintenance

### 5.1 View Real-time Alerts

```bash
# Follow alert log (with JSON formatting)
tail -f logs/realtime_alerts.jsonl | jq .

# Count detections by type
cat logs/realtime_alerts.jsonl | jq -r '.attack_type' | sort | uniq -c

# Last 10 detections
tail -10 logs/realtime_alerts.jsonl | jq -r '[.timestamp, .attack_type, .source_ip] | @tsv'
```

### 5.2 Detection Statistics

```bash
# View stats
cat logs/detection_stats.json | jq .

# Example output:
{
  "total_captures": 1523,
  "total_flows_analyzed": 45892,
  "attacks_detected": 342,
  "attacks_by_type": {
    "DDoS": 156,
    "Port Scan": 89,
    "Brute Force": 45
  }
}
```

### 5.3 Model Retraining

**When to Retrain:**
- New attack types encountered
- High false positive rate
- Significant network changes

**Retrain Anomaly Models:**
```bash
source ~/mlenv/bin/activate
cd /home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml

# Include new labeled data
python scripts/train_anomaly_detector.py --sample-size 300000

# Restart service
sudo systemctl restart wazuh-ml
```

**Retrain XGBoost:**
```bash
jupyter notebook notebooks/train_cicids_final.ipynb
# Run all cells, then restart service
```

### 5.4 Disk Space Management

```bash
# Check log sizes
du -sh logs/

# Clean old captures
rm -rf data/captured/pcap/*.pcap
rm -rf data/captured/flows/*.csv

# Keep only latest models
rm data/models/*_202501*.pkl data/models/*_202501*.keras
```

---

## 6. Wazuh Integration

### 6.1 Configure Wazuh Connection

```bash
python scripts/detection_pipeline.py --continuous \
    --wazuh-host 172.16.158.150 \
    --wazuh-port 9200 \
    --wazuh-user admin \
    --wazuh-pass 'your_password' \
    --action alert
```

### 6.2 Environment Variables

Add to service file or `.bashrc`:

```bash
export WAZUH_HOST="172.16.158.150"
export WAZUH_PORT="9200"
export WAZUH_USER="admin"
export WAZUH_PASS="your_password"
```

### 6.3 Wazuh Dashboard

Access alerts at: `https://172.16.158.150:5601`

- Navigate to **Discover** → Select `wazuh-ml-*` index
- Filter by `rule.groups: "wazuh-ml"`
- View attack details in alert documents

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────┐
│                   DEPLOYMENT QUICK REFERENCE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  START MANUALLY                                                 │
│  $ source ~/mlenv/bin/activate                                  │
│  $ cd /home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml            │
│  $ python scripts/detection_pipeline.py --continuous           │
│                                                                 │
│  SERVICE COMMANDS                                               │
│  $ sudo systemctl start wazuh-ml                               │
│  $ sudo systemctl stop wazuh-ml                                │
│  $ sudo systemctl status wazuh-ml                              │
│  $ sudo journalctl -u wazuh-ml -f                              │
│                                                                 │
│  VIEW ALERTS                                                    │
│  $ tail -f logs/realtime_alerts.jsonl | jq .                   │
│                                                                 │
│  RETRAIN MODELS                                                 │
│  $ python scripts/train_anomaly_detector.py --sample-size 300k │
│  $ sudo systemctl restart wazuh-ml                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

*Last updated: January 1, 2026*
