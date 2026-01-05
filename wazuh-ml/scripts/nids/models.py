"""
models.py - Data classes for detection results
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class ActionType(Enum):
    LOG = "log"
    ALERT = "alert"
    BLOCK = "block"
    WEBHOOK = "webhook"
    EMAIL = "email"
    WAZUH = "wazuh"


class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class FlowDetection:
    """Detection result for a single flow"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    attack_type: str
    confidence: float
    layer: str  # 'suricata', 'xgboost', 'isolation_forest'
    threat_level: ThreatLevel = ThreatLevel.LOW
    anomaly_score: Optional[float] = None
    flow_count: int = 1  # Number of flows aggregated into this detection


@dataclass
class DetectionResult:
    """Complete detection result for a capture session"""
    timestamp: datetime
    total_flows: int
    detections: List[FlowDetection]  # Deduplicated detections with flow_count
    processing_time: float
    filtered_count: int = 0  # Detections removed by whitelist
    raw_detections: List[FlowDetection] = field(default_factory=list)  # Original detections before dedup
    
    def get_attack_ips(self) -> List[str]:
        """Get unique source IPs of detected attacks"""
        return list(set(d.src_ip for d in self.detections))
    
    def get_total_attack_flows(self) -> int:
        """Get total number of attack flows (sum of all flow_counts)"""
        return sum(d.flow_count for d in self.detections)
