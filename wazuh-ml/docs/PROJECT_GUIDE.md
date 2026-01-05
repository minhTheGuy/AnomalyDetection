# Wazuh-ML: 3-Layer Hybrid Network Intrusion Detection System

## Complete Project Documentation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Installation & Setup](#3-installation--setup)
4. [Model Training](#4-model-training)
5. [Running Detection](#5-running-detection)
6. [Configuration Reference](#6-configuration-reference)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Project Overview

### What is This Project?

A **3-Layer Hybrid Network Intrusion Detection System (NIDS)** that combines multiple detection approaches:

| Layer | Model | Type | Purpose | Recall |
|-------|-------|------|---------|--------|
| **Layer 1** | Isolation Forest | Unsupervised | Fast initial anomaly filter | ~30% |
| **Layer 2** | VAE (Variational Autoencoder) | Unsupervised | Zero-day attack detection | ~55% |
| **Layer 3** | XGBoost Classifier | Supervised | Known attack pattern recognition | ~95% |

### Why 3 Layers?

```
Traffic Flow:
                                                              
  [Network Traffic] ──▶ [Layer 1: IForest] ──▶ [Layer 2: VAE] ──▶ [Layer 3: XGBoost]
                              │                      │                    │
                              ▼                      ▼                    ▼
                         Fast Filter           Zero-day             Known Attack
                         (Anomaly Score)       Detection            Classification
```

- **Layer 1 (Isolation Forest)**: Fastest screening, filters obvious normal traffic
- **Layer 2 (VAE)**: Probabilistic anomaly detection, catches zero-day attacks
- **Layer 3 (XGBoost)**: High-accuracy classification of known attack types

### Detected Attack Types

| Attack Type | Source | Detection Layer |
|-------------|--------|-----------------|
| DDoS | CIC-IDS-2017 | Layer 3 (XGBoost) |
| DoS (Hulk, SlowHTTPTest, GoldenEye) | CIC-IDS-2017 | Layer 3 |
| Port Scan | CIC-IDS-2017 | Layer 3 |
| Brute Force (FTP, SSH) | CIC-IDS-2017 | Layer 3 |
| Web Attacks (XSS, SQL Injection) | CIC-IDS-2017 | Layer 3 |
| Infiltration | CIC-IDS-2017 | Layer 3 |
| Botnet | CIC-IDS-2017 | Layer 3 |
| **Zero-day / Unknown** | Any | Layer 1 & 2 (Anomaly) |

---

## 2. System Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        NETWORK SETUP                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────┐         ┌──────────────┐        ┌─────────────┐ │
│   │ Attacker │ ──────▶ │   pfSense    │ ─────▶ │   Target    │ │
│   │  (Kali)  │         │   Firewall   │        │   Server    │ │
│   │172.16.158│         │172.16.158.100│        │172.16.158.x │ │
│   │   .130   │         │  em0 / em1   │        │             │ │
│   └──────────┘         └──────┬───────┘        └─────────────┘ │
│                               │                                 │
│                               │ SSH (tcpdump)                   │
│                               ▼                                 │
│                        ┌──────────────┐                         │
│                        │  Detection   │                         │
│                        │    Host      │                         │
│                        │   (Ubuntu)   │                         │
│                        │  ML Pipeline │                         │
│                        └──────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Detection Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DETECTION PIPELINE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌─────────────┐    ┌─────────────────────────────────────┐│
│  │ tcpdump  │───▶│CICFlowMeter │───▶│            3-LAYER NIDS             ││
│  │ (pfSense)│PCAP│ (80+ feat)  │ CSV│                                     ││
│  └──────────┘    └─────────────┘    │  ┌─────────┐  ┌─────┐  ┌─────────┐ ││
│                                      │  │ IForest │─▶│ VAE │─▶│ XGBoost │ ││
│                                      │  │  (L1)   │  │(L2) │  │  (L3)   │ ││
│                                      │  └─────────┘  └─────┘  └─────────┘ ││
│                                      └──────────────────┬──────────────────┘│
│                                                         │                   │
│  ┌──────────────────────────────────────────────────────▼──────────────────┐│
│  │                           ACTIONS                                       ││
│  │  ┌─────┐  ┌───────┐  ┌───────┐  ┌─────────┐  ┌───────┐  ┌───────────┐  ││
│  │  │ LOG │  │ ALERT │  │ BLOCK │  │ WEBHOOK │  │ EMAIL │  │   WAZUH   │  ││
│  │  │     │  │ (JSONL)│ │(pfSense)│ │ (HTTP)  │  │(SMTP) │  │(Indexer)  │  ││
│  │  └─────┘  └───────┘  └───────┘  └─────────┘  └───────┘  └───────────┘  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Project File Structure

```
wazuh-ml/
├── scripts/
│   ├── detection_pipeline.py      # Main detection script
│   ├── train_anomaly_detector.py  # Train IForest, Autoencoder, VAE
│   ├── capture_labeled_traffic.py # Capture traffic for retraining
│   └── nids/                      # Core detection modules
│       ├── __init__.py
│       ├── config.py              # Configuration constants
│       ├── models.py              # Data classes (FlowDetection, etc)
│       ├── layers.py              # Detection layers (IForest, VAE, XGBoost)
│       ├── pipeline.py            # Detection pipeline orchestration
│       ├── capture.py             # Traffic capture from pfSense
│       ├── actions.py             # Response actions (block, alert, etc)
│       └── stats.py               # Statistics tracking
│
├── notebooks/
│   └── train_cicids_final.ipynb   # Train XGBoost classifier (Jupyter)
│
├── data/
│   ├── cicids/                    # CIC-IDS-2017 training CSVs (8 files)
│   ├── models/                    # Trained models
│   │   ├── isolation_forest_latest.pkl
│   │   ├── autoencoder_latest.keras
│   │   ├── vae_encoder_latest.keras
│   │   ├── vae_decoder_latest.keras
│   │   ├── vae_meta_latest.pkl
│   │   └── cicflowmeter_model_retrained_*.pkl
│   ├── captured/                  # Real-time captured data
│   │   ├── pcap/                  # Raw packet captures
│   │   └── flows/                 # Extracted flow CSVs
│   └── labeled/                   # Manually labeled training data
│       └── flows/                 # Labeled flow CSVs
│
├── logs/
│   ├── realtime_alerts.jsonl      # Detection alerts (JSON Lines)
│   ├── detection_stats.json       # Statistics
│   └── action_logs.jsonl          # Action execution logs
│
├── config/
│   ├── wazuh-ml.service           # systemd service file
│   ├── wazuh-ml.logrotate         # Log rotation config
│   └── whitelist.txt              # Whitelisted IPs
│
├── docs/
│   ├── PROJECT_GUIDE.md           # This document
│   ├── DEPLOYMENT_GUIDE.md        # Production deployment
│   ├── MODEL_IMPROVEMENTS.md      # Model tuning guide
│   └── WAZUH_INTEGRATION.md       # Wazuh setup
│
├── requirements.txt               # Python dependencies
└── README.md                      # Quick start guide
```

---

## 3. Installation & Setup

### 3.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Python | 3.10+ | 3.12 |
| RAM | 8 GB | 16 GB |
| GPU | None | NVIDIA (for VAE training) |
| Disk | 20 GB | 50 GB |
| pfSense | 2.6+ | 2.7+ |

### 3.2 Install Python Environment

```bash
# Create virtual environment
python3 -m venv ~/mlenv
source ~/mlenv/bin/activate

# Navigate to project
cd /home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml

# Install dependencies
pip install -r requirements.txt
```

### 3.3 Install CICFlowMeter

CICFlowMeter extracts 80+ network flow features from PCAP files.

```bash
# Install via pip (recommended)
pip install cicflowmeter

# Verify installation
cicflowmeter --help
```

### 3.4 Configure pfSense SSH Access

```bash
# Generate SSH key (if not exists)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# Copy to pfSense
ssh-copy-id admin@172.16.158.100

# Test connection
ssh admin@172.16.158.100 "echo 'SSH OK'"
```

### 3.5 Environment Variables

Create a `.env` file or export:

```bash
export PFSENSE_HOST="172.16.158.100"
export PFSENSE_USER="admin"
export PFSENSE_PORT="22"
export PFSENSE_INTERFACE="em1"
```

---

## 4. Model Training

### 4.1 Training Overview

| Model | Script/Notebook | Training Data | Output |
|-------|-----------------|---------------|--------|
| XGBoost | `notebooks/train_cicids_final.ipynb` | CIC-IDS-2017 (labeled) | `cicflowmeter_model_*.pkl` |
| Isolation Forest | `scripts/train_anomaly_detector.py` | BENIGN traffic only | `isolation_forest_latest.pkl` |
| Autoencoder | `scripts/train_anomaly_detector.py` | BENIGN traffic only | `autoencoder_latest.keras` |
| VAE | `scripts/train_anomaly_detector.py` | BENIGN traffic only | `vae_encoder/decoder_latest.keras` |

### 4.2 Train XGBoost Classifier

```bash
# Open Jupyter notebook
source ~/mlenv/bin/activate
cd /opt/wazuh-ml
jupyter notebook notebooks/train_cicids_final.ipynb
```

**Training Steps:**
1. Load CIC-IDS-2017 CSVs from `data/cicids/`
2. Clean data (remove inf/nan, encode labels)
3. Feature selection (33 features with |correlation| > 0.01)
4. Balance classes (undersample BENIGN, oversample rare attacks)
5. Train XGBoost with hyperparameter tuning
6. Save model to `data/models/`

### 4.3 Train Anomaly Detection Models

```bash
source ~/mlenv/bin/activate
cd /home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml

# Train all models (IForest, Autoencoder, VAE)
python scripts/train_anomaly_detector.py --sample-size 300000 --threshold-pct 90

# Train only VAE
python scripts/train_anomaly_detector.py --vae-only --sample-size 300000

# Skip VAE (faster)
python scripts/train_anomaly_detector.py --skip-vae
```

**Command Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--sample-size N` | Training samples (max 2.2M) | 100,000 |
| `--threshold-pct N` | Anomaly threshold percentile | 90 |
| `--contamination F` | IForest contamination ratio | 0.01 |
| `--latent-dim N` | VAE latent space dimension | 16 |
| `--beta F` | VAE KL divergence weight | 1.0 |
| `--vae-only` | Train only VAE | False |
| `--skip-vae` | Skip VAE training | False |
| `--skip-autoencoder` | Skip Autoencoder training | False |

### 4.4 Model Performance Summary

| Model | Precision | Recall | F1-Score | Best For |
|-------|-----------|--------|----------|----------|
| Isolation Forest | 0.97 | 0.30 | 0.46 | Fast initial filter |
| Autoencoder (90th pct) | 0.82 | 0.46 | 0.59 | Basic anomaly detection |
| **VAE (90th pct)** | 0.84 | **0.55** | **0.67** | Zero-day detection |
| XGBoost | 0.95+ | 0.95+ | 0.95+ | Known attack classification |

**Key Insight**: VAE with 90th percentile threshold provides the best balance of precision and recall for unsupervised anomaly detection.

---

## 5. Running Detection

### 5.1 Quick Start

```bash
source ~/mlenv/bin/activate
cd /home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml

# Single detection cycle (15 seconds)
python scripts/detection_pipeline.py --realtime

# Continuous monitoring
python scripts/detection_pipeline.py --continuous --interval 60 --action alert
```

### 5.2 Detection Modes

| Mode | Command | Description |
|------|---------|-------------|
| **PCAP Analysis** | `--pcap file.pcap` | Analyze existing PCAP file |
| **Single Capture** | `--realtime` | One capture cycle, then exit |
| **Continuous** | `--continuous` | Loop forever with interval |
| **Streaming** | `--streaming` | Threaded real-time processing |

### 5.3 Command Options

```bash
python scripts/detection_pipeline.py [OPTIONS]

# Input sources
--pcap FILE            # Analyze PCAP file
--data FILE            # Analyze flow CSV
--realtime             # Single capture from pfSense
--continuous           # Continuous monitoring loop
--streaming            # Threaded streaming mode

# Detection settings
--interval N           # Capture duration in seconds (default: 60)
--threshold N          # XGBoost confidence threshold (default: 0.5)
--anomaly-threshold N  # IForest score threshold (default: 0.45)

# Response actions (can specify multiple)
--action log           # Write to log file
--action alert         # Generate alert
--action block         # Block IP on pfSense
--action webhook       # Send to webhook URL
--action email         # Send email notification

# Wazuh integration
--wazuh-host HOST      # Wazuh indexer host
--wazuh-port PORT      # Wazuh indexer port
--wazuh-user USER      # Wazuh username
--wazuh-pass PASS      # Wazuh password
```

### 5.4 Example Commands

```bash
# Analyze a PCAP file
python scripts/detection_pipeline.py --pcap data/captured/pcap/capture.pcap

# Real-time with alerts and blocking
python scripts/detection_pipeline.py --continuous --interval 60 \
    --action log --action alert --action block

# Stream mode with Wazuh integration
python scripts/detection_pipeline.py --streaming --interval 15 \
    --action alert --wazuh-host 172.16.158.150

# High-sensitivity detection (lower thresholds)
python scripts/detection_pipeline.py --continuous \
    --threshold 0.3 --anomaly-threshold 0.35 --action alert
```

### 5.5 Output Format

Detection results are logged to `logs/realtime_alerts.jsonl`:

```json
{
  "timestamp": "2026-01-01T22:59:03.123456",
  "detection_type": "attack",
  "attack_type": "DDoS",
  "confidence": 0.97,
  "layer": "layer3_xgboost",
  "source_ip": "172.16.158.130",
  "dest_ip": "172.16.158.100",
  "dest_port": 80,
  "protocol": "TCP",
  "flow_count": 3996,
  "action_taken": ["alert", "block"]
}
```

---

## 6. Configuration Reference

### 6.1 Whitelist Configuration

Edit `config/whitelist.txt` to exclude IPs from detection:

```
# Whitelisted IPs (one per line)
172.16.158.1      # Gateway
172.16.158.100    # pfSense
10.0.0.0/8        # Internal network (CIDR supported)
```

### 6.2 Model Paths (config.py)

```python
# scripts/nids/config.py
MODELS_DIR = PROJECT_DIR / 'data' / 'models'
CLASSIFIER_PATH = MODELS_DIR / 'cicflowmeter_model_retrained_*.pkl'
IFOREST_PATH = MODELS_DIR / 'isolation_forest_latest.pkl'
VAE_ENCODER_PATH = MODELS_DIR / 'vae_encoder_latest.keras'
VAE_DECODER_PATH = MODELS_DIR / 'vae_decoder_latest.keras'
```

### 6.3 Detection Thresholds

| Threshold | Default | Description |
|-----------|---------|-------------|
| `XGBOOST_THRESHOLD` | 0.5 | Minimum confidence for classification |
| `IFOREST_THRESHOLD` | 0.45 | IForest anomaly score cutoff |
| `VAE_THRESHOLD` | 0.0888 | VAE reconstruction error threshold (90th pct) |
| `AUTOENCODER_THRESHOLD` | 0.0458 | Autoencoder threshold (90th pct) |

### 6.4 Selected Features (33 features)

The models use these 33 features from CICFlowMeter:

```
Flow Duration, Bwd Packet Length Max, Bwd Packet Length Mean,
Bwd Packet Length Std, Flow IAT Mean, Flow IAT Std, Flow IAT Max,
Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max,
Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd Packets/s,
Max Packet Length, Packet Length Mean, Packet Length Std,
Packet Length Variance, FIN Flag Count, PSH Flag Count, ACK Flag Count,
Average Packet Size, Avg Bwd Segment Size, Init_Win_bytes_forward,
Active Mean, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min
```

---

## 7. Troubleshooting

### 7.1 Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `SSH connection failed` | pfSense SSH not configured | Enable SSH in pfSense System > Advanced |
| `CICFlowMeter not found` | Not installed | `pip install cicflowmeter` |
| `Model file not found` | Models not trained | Run training scripts first |
| `No flows extracted` | No traffic or short capture | Increase `--interval` value |
| `GPU not detected` | CUDA not installed | Install CUDA for TensorFlow |
| `NaN in VAE training` | Extreme outliers in data | Data preprocessing clips outliers automatically |

### 7.2 Check Model Files

```bash
ls -la data/models/
# Should contain:
# - isolation_forest_latest.pkl
# - autoencoder_latest.keras
# - vae_encoder_latest.keras
# - vae_decoder_latest.keras
# - cicflowmeter_model_retrained_*.pkl
```

### 7.3 View Logs

```bash
# Real-time alerts
tail -f logs/realtime_alerts.jsonl | jq .

# Detection statistics
cat logs/detection_stats.json | jq .

# Action logs
tail -f logs/action_logs.jsonl | jq .
```

### 7.4 Test Detection

```bash
# Test with existing labeled data
python scripts/detection_pipeline.py --pcap data/labeled/flows/Port_Scan_*.csv

# Test with DDoS traffic
python scripts/detection_pipeline.py --data data/labeled/flows/DDoS_*.csv
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                    WAZUH-ML QUICK REFERENCE                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ACTIVATE ENVIRONMENT                                           │
│  $ source ~/mlenv/bin/activate                                  │
│  $ cd /home/dangminh0113/Desktop/DACNTT_V2/wazuh-ml            │
│                                                                 │
│  TRAIN MODELS                                                   │
│  $ jupyter notebook notebooks/train_cicids_final.ipynb  # XGB  │
│  $ python scripts/train_anomaly_detector.py             # VAE  │
│                                                                 │
│  RUN DETECTION                                                  │
│  $ python scripts/detection_pipeline.py --continuous           │
│                                                                 │
│  USEFUL OPTIONS                                                 │
│  --interval 60        # Capture duration (seconds)             │
│  --action alert       # Enable alerting                        │
│  --action block       # Enable IP blocking                     │
│  --threshold 0.5      # XGBoost confidence                     │
│                                                                 │
│  VIEW LOGS                                                      │
│  $ tail -f logs/realtime_alerts.jsonl | jq .                   │
│                                                                 │
│  NETWORK                                                        │
│  pfSense:  172.16.158.100 (admin@em1)                          │
│  Wazuh:    172.16.158.150:9200                                 │
│  Gateway:  172.16.158.1 (whitelisted)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

*Last updated: January 1, 2026*
