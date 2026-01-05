"""
nids - 3-Layer Hybrid Network Intrusion Detection System

Layers:
    1. Suricata (Signature-based NIDS)
    2. XGBoost (Supervised classification)
    3. Isolation Forest (Unsupervised anomaly detection)

Actions:
    - log: Write detections to JSON log file
    - alert: Print colored alerts to console
    - block: Block source IPs via pfSense easyrule
    - webhook: Send detections to external webhook
    - email: Send email alerts for critical threats
    - wazuh: Integrate with Wazuh SIEM (socket/API/log)

Wazuh Integration:
    - WazuhClient: Send ML detections to Wazuh Manager
    - WazuhAlertParser: Parse Wazuh HIDS alerts
    - HIDSCorrelator: Correlate host-based and network-based detections
"""

from .models import ActionType, ThreatLevel, FlowDetection, DetectionResult
from .config import (
    PROJECT_DIR, DATA_DIR, MODELS_DIR, PCAP_DIR, FLOWS_DIR, LOGS_DIR,
    FEATURE_MAPPING
)
from .action_config import (
    ActionConfigBuilder,
    WebhookConfig,
    EmailConfig,
    WazuhConfig
)
from .stats import StatsTracker, stats
from .capture import PfSenseCapture, extract_flows
from .layers import SuricataSNIDS, XGBoostClassifier, AnomalyDetector
from .actions import ActionHandler
from .pipeline import HybridNIDS, DetectionPipeline
from .wazuh import (
    WazuhClient, 
    WazuhAlertParser, 
    WazuhAlert,
    WazuhIndexerClient,
    HIDSCorrelator, 
    CorrelatedAlert,
    create_wazuh_integration
)


__all__ = [
    # Models
    'ActionType',
    'ThreatLevel', 
    'FlowDetection',
    'DetectionResult',
    
    # Config
    'PROJECT_DIR',
    'DATA_DIR',
    'MODELS_DIR',
    'PCAP_DIR',
    'FLOWS_DIR',
    'LOGS_DIR',
    'FEATURE_MAPPING',
    
    # Action Config
    'WebhookConfig',
    'EmailConfig',
    'WazuhConfig',
    'ActionConfigBuilder',
    
    # Stats
    'StatsTracker',
    'stats',
    
    # Capture
    'PfSenseCapture',
    'extract_flows',
    
    # Detection layers
    'SuricataSNIDS',
    'XGBoostClassifier',
    'AnomalyDetector',
    
    # Actions
    'ActionHandler',
    
    # Pipeline
    'HybridNIDS',
    'DetectionPipeline',
    
    # Wazuh Integration
    'WazuhClient',
    'WazuhAlertParser',
    'WazuhAlert',
    'WazuhIndexerClient',
    'HIDSCorrelator',
    'CorrelatedAlert',
    'create_wazuh_integration',
]

__version__ = '1.1.0'
