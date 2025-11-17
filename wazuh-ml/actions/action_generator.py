"""
Action Generator - Tự động tạo actions dựa trên detected anomalies
"""
from typing import Dict, List, Optional
from enum import Enum
import pandas as pd

PRIVATE_PREFIXES = tuple([
    '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
])

ATTACK_SEVERITY_MAP = {
    'malware': 4,
    'privilege_escalation': 4,
    'data_exfiltration': 4,
    'dos_ddos': 3,
    'brute_force': 3,
    'sql_injection': 3,
    'xss': 2,
    'port_scan': 2,
    'web_attack': 2,
    'suspicious_activity': 1,
    'benign': 1,
    'unknown': 1,
}

BLOCK_REQUIRED_ATTACKS = {'malware', 'dos_ddos', 'brute_force', 'privilege_escalation'}


class ActionType(Enum):
    """Các loại actions có thể thực hiện"""
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    REJECT_IP = "reject_ip"
    REJECT_PORT = "reject_port"
    ALERT = "alert"
    NOTIFY_EMAIL = "notify_email"
    QUARANTINE = "quarantine"
    LOG = "log"
    ESCALATE = "escalate"


class SeverityLevel(Enum):
    """Mức độ nghiêm trọng"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ActionGenerator:
    """Generator cho actions dựa trên anomaly và classification"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize action generator
        
        Args:
            config: Configuration dict với các settings:
                - enable_auto_block: bool (default: False)
                - min_severity_for_block: int (1-4, default: 3)
                - min_severity_for_notify: int (1-4, default: 2)
        """
        self.config = config or {}
        self.enable_auto_block = self.config.get('enable_auto_block', False)
        self.min_severity_for_block = self._severity_from_int(self.config.get('min_severity_for_block', 3))
        self.min_severity_for_notify = self._severity_from_int(self.config.get('min_severity_for_notify', 2))
    
    @staticmethod
    def _severity_from_int(value: int) -> SeverityLevel:
        return {
            1: SeverityLevel.LOW,
            2: SeverityLevel.MEDIUM,
            3: SeverityLevel.HIGH,
            4: SeverityLevel.CRITICAL,
        }.get(int(value), SeverityLevel.HIGH)
        
    def get_severity_from_anomaly(self, anomaly_row: pd.Series) -> SeverityLevel:
        """Xác định severity level từ anomaly"""
        rule_level = int(anomaly_row.get('rule_level') or 0)
        if rule_level >= 15:
            return SeverityLevel.CRITICAL
        if rule_level >= 12:
            return SeverityLevel.HIGH
        if rule_level >= 7:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW
    
    def get_severity_from_attack_type(self, attack_type: str) -> SeverityLevel:
        """Xác định severity level từ attack type"""
        score = ATTACK_SEVERITY_MAP.get((attack_type or '').lower(), 2)
        return self._severity_from_int(score)
    
    def generate_actions(self, anomaly_row: pd.Series) -> List[Dict]:
        """
        Generate actions cho một anomaly
        
        Args:
            anomaly_row: Pandas Series chứa anomaly data
            
        Returns:
            List of action dicts với format:
            {
                'type': ActionType,
                'target': str (IP, port, etc.),
                'reason': str,
                'severity': SeverityLevel,
                'params': dict (additional parameters)
            }
        """
        actions = []
        attack_type = anomaly_row.get('predicted_attack_type', 'unknown')
        severity = max(
            self.get_severity_from_anomaly(anomaly_row),
            self.get_severity_from_attack_type(attack_type),
            key=lambda lvl: lvl.value
        )
        
        context = self._extract_context(anomaly_row)
        actions.append(self._log_action(severity, context))
        
        if severity.value >= self.min_severity_for_notify.value:
            actions.append(self._alert_action(severity, attack_type, context))
        
        if self._should_block_ip(severity, attack_type, context['src_ip']):
            actions.append(self._create_block_ip_action(context['src_ip'], attack_type, context['event_desc'], severity))
        
        if self._should_block_port(severity, attack_type, context['dst_port']):
            actions.append(self._create_block_port_action(context['dst_port'], context['dst_ip'], attack_type, severity))
        
        if severity == SeverityLevel.CRITICAL:
            actions.append(self._escalate_action(severity, attack_type, context))
        
        return actions
    
    @staticmethod
    def _extract_context(anomaly_row: pd.Series) -> Dict:
        return {
            'src_ip': anomaly_row.get('src_ip'),
            'dst_ip': anomaly_row.get('dst_ip'),
            'dst_port': anomaly_row.get('dst_port'),
            'event_desc': anomaly_row.get('event_desc', 'Unknown event'),
            'agent': anomaly_row.get('agent', 'Unknown agent'),
            'timestamp': anomaly_row.get('timestamp', 'Unknown time'),
            'anomaly_score': float(anomaly_row.get('anomaly_score') or 0),
            'confidence': float(anomaly_row.get('attack_type_confidence') or 0),
        }
    
    @staticmethod
    def _log_action(severity: SeverityLevel, context: Dict) -> Dict:
        return {
            'type': ActionType.LOG,
            'target': 'system',
            'reason': f'Anomaly detected: {context["event_desc"]}',
            'severity': severity,
            'params': {
                'event_desc': context['event_desc'],
                'agent': context['agent'],
                'timestamp': context['timestamp'],
                'anomaly_score': context['anomaly_score'],
            }
        }
    
    @staticmethod
    def _alert_action(severity: SeverityLevel, attack_type: str, context: Dict) -> Dict:
        return {
            'type': ActionType.ALERT,
            'target': 'security_team',
            'reason': f'{attack_type.upper()} detected: {context["event_desc"]}',
            'severity': severity,
            'params': {
                'attack_type': attack_type,
                'event_desc': context['event_desc'],
                'agent': context['agent'],
                'src_ip': context['src_ip'],
                'dst_ip': context['dst_ip'],
                'confidence': context['confidence'],
            }
        }
    
    def _escalate_action(self, severity: SeverityLevel, attack_type: str, context: Dict) -> Dict:
        return {
            'type': ActionType.ESCALATE,
            'target': 'security_manager',
            'reason': f'CRITICAL: {attack_type} detected - Immediate attention required',
            'severity': severity,
            'params': {
                'attack_type': attack_type,
                'event_desc': context['event_desc'],
                'agent': context['agent'],
            }
        }
    
    def _should_block_ip(self, severity: SeverityLevel, attack_type: str, ip: Optional[str]) -> bool:
        if not (self.enable_auto_block and ip and pd.notna(ip)):
            return False
        external_ip = not str(ip).startswith(PRIVATE_PREFIXES)
        attack_requires_block = attack_type in BLOCK_REQUIRED_ATTACKS
        return (severity.value >= self.min_severity_for_block.value) and (external_ip or attack_requires_block)
    
    @staticmethod
    def _should_block_port(severity: SeverityLevel, attack_type: str, port: Optional[str]) -> bool:
        return (
            severity == SeverityLevel.CRITICAL
            and pd.notna(port)
            and port
            and attack_type in {'dos_ddos', 'port_scan'}
        )
    
    def _create_block_ip_action(self, src_ip: str, attack_type: str, event_desc: str, severity: SeverityLevel) -> Dict:
        """Helper: Tạo BLOCK_IP action"""
        return {
            'type': ActionType.BLOCK_IP,
            'target': str(src_ip),
            'reason': f'Block IP {src_ip} on pfSense due to {attack_type} attack',
            'severity': severity,
            'params': {
                'ip': str(src_ip),
                'attack_type': attack_type,
                'duration': 3600,  # 1 hour default
                'reason': event_desc,
                'action': 'block',  # default action
            }
        }
    
    def _create_block_port_action(self, dst_port, dst_ip, attack_type: str, severity: SeverityLevel) -> Dict:
        """Helper: Tạo BLOCK_PORT action"""
        return {
            'type': ActionType.BLOCK_PORT,
            'target': f'{dst_ip}:{dst_port}' if pd.notna(dst_ip) else str(dst_port),
            'reason': f'Block port {dst_port} on pfSense due to {attack_type}',
            'severity': severity,
            'params': {
                'port': int(dst_port) if pd.notna(dst_port) else None,
                'ip': str(dst_ip) if pd.notna(dst_ip) else None,
                'attack_type': attack_type,
                'duration': 3600,  # 1 hour default
                'action': 'block',  # default action
            }
        }
    
    def generate_actions_batch(self, anomalies_df: pd.DataFrame) -> pd.DataFrame:
        records = []
        for idx, row in anomalies_df.iterrows():
            for action in self.generate_actions(row):
                records.append({
                    'anomaly_index': idx,
                    'action_type': action['type'].value,
                    'target': action['target'],
                    'reason': action['reason'],
                    'severity': action['severity'].name,
                    'severity_value': action['severity'].value,
                    'params': action['params'],
                })
        return pd.DataFrame(records)

