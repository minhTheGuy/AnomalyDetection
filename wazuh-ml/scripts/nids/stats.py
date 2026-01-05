"""
stats.py - Statistics tracking for detection sessions
"""

import json
import threading
from datetime import datetime
from typing import Dict, List

from .config import LOGS_DIR
from .models import DetectionResult


class StatsTracker:
    """Track detection statistics across sessions"""
    
    def __init__(self):
        self.stats_file = LOGS_DIR / 'detection_stats.json'
        self.lock = threading.Lock()
        self.session_start = datetime.now()
        self.cycles = 0
        self.total_flows = 0
        self.total_attacks = 0
        self.blocked_ips: Dict[str, datetime] = {}
    
    def update(self, result: DetectionResult):
        """Update statistics with detection result"""
        with self.lock:
            self.cycles += 1
            self.total_flows += result.total_flows
            self.total_attacks += len(result.detections)
    
    def record_block(self, ip: str):
        """Record an IP block"""
        with self.lock:
            self.blocked_ips[ip] = datetime.now()
    
    def record_unblock(self, ip: str):
        """Record an IP unblock"""
        with self.lock:
            self.blocked_ips.pop(ip, None)
    
    def is_blocked(self, ip: str, cooldown: int = 300) -> bool:
        """Check if IP is in cooldown period"""
        with self.lock:
            if ip in self.blocked_ips:
                return (datetime.now() - self.blocked_ips[ip]).seconds < cooldown
            return False
    
    def get_expired(self, duration: int) -> List[str]:
        """Get IPs that have exceeded block duration"""
        with self.lock:
            return [ip for ip, t in self.blocked_ips.items() 
                    if (datetime.now() - t).seconds > duration]
    
    def save(self):
        """Save statistics to file"""
        with self.lock:
            data = {
                'session_start': self.session_start.isoformat(),
                'cycles': self.cycles,
                'total_flows': self.total_flows,
                'total_attacks': self.total_attacks,
                'blocked_ips': list(self.blocked_ips.keys())
            }
            with open(self.stats_file, 'w') as f:
                json.dump(data, f, indent=2)


# Global stats instance
stats = StatsTracker()
