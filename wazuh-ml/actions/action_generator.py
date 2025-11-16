"""
Action Generator - Tự động tạo actions dựa trên detected anomalies
"""
from typing import Dict, List, Optional, Tuple
from enum import Enum
import pandas as pd


def _is_external_ip(ip: str) -> bool:
    """Check if IP is external (not private)"""
    if not ip or pd.isna(ip):
        return False
    ip_str = str(ip)
    private_prefixes = [
        '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
    ]
    return not any(ip_str.startswith(prefix) for prefix in private_prefixes)


class ActionType(Enum):
    """Các loại actions có thể thực hiện"""
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    ALERT = "alert"
    NOTIFY_TELEGRAM = "notify_telegram"
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
                - enable_telegram: bool (default: False)
                - telegram_chat_id: str
                - telegram_bot_token: str
                - min_severity_for_block: int (1-4, default: 3)
                - min_severity_for_notify: int (1-4, default: 2)
        """
        self.config = config or {}
        self.enable_auto_block = self.config.get('enable_auto_block', False)
        self.enable_telegram = self.config.get('enable_telegram', False)
        
        # Convert int sang enum SeverityLevel
        min_block_int = self.config.get('min_severity_for_block', 3)  # HIGH
        min_notify_int = self.config.get('min_severity_for_notify', 2)  # MEDIUM
        
        # Map int sang enum SeverityLevel
        severity_map = {
            1: SeverityLevel.LOW,
            2: SeverityLevel.MEDIUM,
            3: SeverityLevel.HIGH,
            4: SeverityLevel.CRITICAL
        }
        self.min_severity_for_block = severity_map.get(min_block_int, SeverityLevel.HIGH)
        self.min_severity_for_notify = severity_map.get(min_notify_int, SeverityLevel.MEDIUM)
        
    def get_severity_from_anomaly(self, anomaly_row: pd.Series) -> SeverityLevel:
        """Xác định severity level từ anomaly"""
        # Dựa vào rule_level
        rule_level = anomaly_row.get('rule_level', 0)
        if pd.isna(rule_level):
            rule_level = 0
        else:
            rule_level = int(rule_level)
        
        if rule_level >= 15:
            return SeverityLevel.CRITICAL
        elif rule_level >= 12:
            return SeverityLevel.HIGH
        elif rule_level >= 7:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def get_severity_from_attack_type(self, attack_type: str) -> SeverityLevel:
        """Xác định severity level từ attack type"""
        severity_map = {
            'malware': SeverityLevel.CRITICAL,
            'dos_ddos': SeverityLevel.HIGH,
            'brute_force': SeverityLevel.HIGH,
            'sql_injection': SeverityLevel.HIGH,
            'xss': SeverityLevel.MEDIUM,
            'port_scan': SeverityLevel.MEDIUM,
            'privilege_escalation': SeverityLevel.CRITICAL,
            'data_exfiltration': SeverityLevel.CRITICAL,
            'web_attack': SeverityLevel.MEDIUM,
            'suspicious_activity': SeverityLevel.LOW,
            'benign': SeverityLevel.LOW,
            'unknown': SeverityLevel.LOW,
        }
        return severity_map.get(attack_type.lower(), SeverityLevel.MEDIUM)
    
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
        
        # Xác định severity
        rule_severity = self.get_severity_from_anomaly(anomaly_row)
        attack_type = anomaly_row.get('predicted_attack_type', 'unknown')
        attack_severity = self.get_severity_from_attack_type(attack_type)
        
        # Lấy severity cao hơn
        severity = max(rule_severity, attack_severity, key=lambda x: x.value)
        
        # Extract thông tin
        src_ip = anomaly_row.get('src_ip')
        dst_ip = anomaly_row.get('dst_ip')
        dst_port = anomaly_row.get('dst_port')
        event_desc = anomaly_row.get('event_desc', 'Unknown event')
        agent = anomaly_row.get('agent', 'Unknown agent')
        timestamp = anomaly_row.get('timestamp', 'Unknown time')
        anomaly_score = anomaly_row.get('anomaly_score', 0)
        confidence = anomaly_row.get('attack_type_confidence', 0)
        
        # 1. LOG action (luôn luôn)
        actions.append({
            'type': ActionType.LOG,
            'target': 'system',
            'reason': f'Anomaly detected: {event_desc}',
            'severity': severity,
            'params': {
                'event_desc': event_desc,
                'agent': agent,
                'timestamp': timestamp,
                'anomaly_score': float(anomaly_score) if pd.notna(anomaly_score) else 0,
            }
        })
        
        # 2. ALERT action (nếu severity >= MEDIUM)
        if severity.value >= SeverityLevel.MEDIUM.value:
            actions.append({
                'type': ActionType.ALERT,
                'target': 'security_team',
                'reason': f'{attack_type.upper()} detected: {event_desc}',
                'severity': severity,
                'params': {
                    'attack_type': attack_type,
                    'event_desc': event_desc,
                    'agent': agent,
                    'src_ip': src_ip if pd.notna(src_ip) else None,
                    'dst_ip': dst_ip if pd.notna(dst_ip) else None,
                    'confidence': float(confidence) if pd.notna(confidence) else 0,
                }
            })
        
        # 3. NOTIFY_TELEGRAM (nếu enabled và severity >= min_severity_for_notify)
        if self.enable_telegram and severity.value >= self.min_severity_for_notify.value:
            actions.append({
                'type': ActionType.NOTIFY_TELEGRAM,
                'target': 'telegram',
                'reason': f'{attack_type.upper()} Alert: {event_desc}',
                'severity': severity,
                'params': {
                    'message': self._format_telegram_message(anomaly_row, attack_type, severity),
                    'chat_id': self.config.get('telegram_chat_id'),
                    'bot_token': self.config.get('telegram_bot_token'),
                }
            })
        
        # 4. BLOCK_IP trên pfSense (nếu enabled và severity >= min_severity_for_block và có src_ip)
        if (self.enable_auto_block and 
            severity.value >= self.min_severity_for_block.value and 
            pd.notna(src_ip) and src_ip):
            
            # Chỉ block nếu là external IP hoặc attack type nghiêm trọng
            if _is_external_ip(src_ip) or attack_type in ['malware', 'dos_ddos', 'brute_force', 'privilege_escalation']:
                actions.append({
                    'type': ActionType.BLOCK_IP,
                    'target': str(src_ip),
                    'reason': f'Block IP {src_ip} on pfSense due to {attack_type} attack',
                    'severity': severity,
                    'params': {
                        'ip': str(src_ip),
                        'attack_type': attack_type,
                        'duration': 3600,  # 1 hour default
                        'reason': event_desc,
                    }
                })
        
        # 5. BLOCK_PORT trên pfSense (nếu severity CRITICAL và có dst_port)
        if (severity == SeverityLevel.CRITICAL and 
            pd.notna(dst_port) and dst_port and
            attack_type in ['dos_ddos', 'port_scan']):
            actions.append({
                'type': ActionType.BLOCK_PORT,
                'target': f'{dst_ip}:{dst_port}' if pd.notna(dst_ip) else str(dst_port),
                'reason': f'Block port {dst_port} on pfSense due to {attack_type}',
                'severity': severity,
                'params': {
                    'port': int(dst_port) if pd.notna(dst_port) else None,
                    'ip': str(dst_ip) if pd.notna(dst_ip) else None,
                    'attack_type': attack_type,
                    'duration': 3600,  # 1 hour default
                }
            })
        
        # 6. ESCALATE (nếu severity CRITICAL)
        if severity == SeverityLevel.CRITICAL:
            actions.append({
                'type': ActionType.ESCALATE,
                'target': 'security_manager',
                'reason': f'CRITICAL: {attack_type} detected - Immediate attention required',
                'severity': severity,
                'params': {
                    'attack_type': attack_type,
                    'event_desc': event_desc,
                    'agent': agent,
                }
            })
        
        return actions
    
    def _format_telegram_message(self, anomaly_row: pd.Series, attack_type: str, severity: SeverityLevel) -> str:
        """Format message cho Telegram"""
        emoji_map = {
            SeverityLevel.CRITICAL: '🔴',
            SeverityLevel.HIGH: '🟠',
            SeverityLevel.MEDIUM: '🟡',
            SeverityLevel.LOW: '🟢',
        }
        
        emoji = emoji_map.get(severity, '⚪')
        event_desc = anomaly_row.get('event_desc', 'Unknown event')
        agent = anomaly_row.get('agent', 'Unknown')
        src_ip = anomaly_row.get('src_ip', 'N/A')
        dst_ip = anomaly_row.get('dst_ip', 'N/A')
        timestamp = anomaly_row.get('timestamp', 'Unknown time')
        confidence = anomaly_row.get('attack_type_confidence', 0)
        anomaly_score = anomaly_row.get('anomaly_score', 0)
        
        message = f"""{emoji} *{severity.name} Alert*

*Attack Type:* {attack_type.upper()}
*Description:* {event_desc}
*Agent:* {agent}
*Source IP:* {src_ip}
*Destination IP:* {dst_ip}
*Time:* {timestamp}
*Confidence:* {confidence:.2%}
*Anomaly Score:* {anomaly_score:.2f}

_Generated by Wazuh ML System - Actions executed on pfSense Firewall_"""
        
        return message
    
    def generate_actions_batch(self, anomalies_df: pd.DataFrame) -> pd.DataFrame:
        """
        Generate actions cho nhiều anomalies
        
        Args:
            anomalies_df: DataFrame chứa anomalies
            
        Returns:
            DataFrame với columns: anomaly_index, action_type, target, reason, severity, params
        """
        all_actions = []
        
        for idx, row in anomalies_df.iterrows():
            actions = self.generate_actions(row)
            for action in actions:
                all_actions.append({
                    'anomaly_index': idx,
                    'action_type': action['type'].value,
                    'target': action['target'],
                    'reason': action['reason'],
                    'severity': action['severity'].name,
                    'severity_value': action['severity'].value,
                    'params': action['params'],
                })
        
        return pd.DataFrame(all_actions)

