"""
Module phân loại sự kiện bảo mật thành các loại tấn công và danh mục sự kiện
"""

import pandas as pd
import numpy as np
import re
from typing import Dict, List, Tuple, Optional

# Định nghĩa các pattern để phân loại attack types
ATTACK_PATTERNS = {
    'brute_force': [
        r'failed password', r'authentication failure', r'invalid user',
        r'login attempt', r'brute force', r'too many attempts',
        r'connection closed', r'connection reset', r'too many authentication failures'
    ],
    'port_scan': [
        r'port scan', r'nmap', r'syn scan', r'xmas scan', r'fin scan',
        r'null scan', r'port sweep', r'network scan', r'host scan',
        r'multiple connection attempts', r'connection attempts from'
    ],
    'sql_injection': [
        r'sql injection', r'union select', r"or 1=1", r"' or '1'='1",
        r'select.*from', r'insert.*into', r'delete.*from', r'drop table',
        r'exec.*xp_', r'information_schema'
    ],
    'xss': [
        r'cross.site.scripting', r'xss', r'<script', r'javascript:',
        r'onerror=', r'onclick=', r'eval\(', r'document\.cookie'
    ],
    'dos_ddos': [
        r'denial of service', r'dos', r'ddos', r'flood', r'syn flood',
        r'icmp flood', r'udp flood', r'connection flood', r'resource exhaustion',
        r'too many connections', r'rate limit exceeded'
    ],
    'malware': [
        r'malware', r'virus', r'trojan', r'ransomware', r'backdoor',
        r'rootkit', r'worm', r'spyware', r'adware', r'exploit',
        r'payload', r'shellcode'
    ],
    'privilege_escalation': [
        r'privilege escalation', r'sudo', r'su ', r'root access',
        r'administrator access', r'permission denied', r'access denied',
        r'unauthorized access', r'elevated privileges'
    ],
    'data_exfiltration': [
        r'data exfiltration', r'data leak', r'large data transfer',
        r'unusual data volume', r'external data transfer', r'bulk download',
        r'data export', r'sensitive data'
    ],
    'web_attack': [
        r'web attack', r'http attack', r'https attack', r'web vulnerability',
        r'nikto', r'sqlmap', r'gobuster', r'dirb', r'burp', r'owasp',
        r'path traversal', r'directory traversal', r'file inclusion',
        r'command injection', r'remote code execution'
    ],
    'suspicious_activity': [
        r'suspicious', r'anomalous', r'unusual', r'abnormal', r'atypical',
        r'irregular', r'strange', r'odd behavior', r'unexpected'
    ]
}

# Định nghĩa event categories dựa trên rule groups và event descriptions
EVENT_CATEGORY_PATTERNS = {
    'authentication': [
        r'login', r'logout', r'authentication', r'auth', r'session',
        r'password', r'credential', r'user account', r'sshd', r'su ',
        r'sudo', r'kerberos', r'ldap'
    ],
    'file_integrity': [
        r'file integrity', r'file changed', r'file modified', r'file deleted',
        r'file created', r'integrity checksum', r'fim', r'file monitoring',
        r'file access', r'permission changed'
    ],
    'network': [
        r'network', r'connection', r'port', r'protocol', r'ip address',
        r'firewall', r'packet', r'traffic', r'network interface',
        r'network scan', r'network activity'
    ],
    'system': [
        r'system', r'process', r'service', r'daemon', r'kernel',
        r'system call', r'process execution', r'service started',
        r'service stopped', r'system event'
    ],
    'compliance': [
        r'cis', r'benchmark', r'compliance', r'policy', r'audit',
        r'security policy', r'configuration', r'hardening'
    ],
    'vulnerability': [
        r'vulnerability', r'cve', r'exploit', r'security flaw',
        r'weakness', r'security issue', r'patch', r'update required'
    ],
    'malware_detection': [
        r'malware', r'virus', r'trojan', r'threat', r'infection',
        r'antivirus', r'security scan', r'threat detection'
    ],
    'web': [
        r'http', r'https', r'web', r'apache', r'nginx', r'web server',
        r'web application', r'url', r'request', r'response'
    ]
}


def extract_attack_type(event_desc: str) -> str:
    """
    Phân loại loại tấn công dựa trên event description
    
    Args:
        event_desc: Mô tả sự kiện
        
    Returns:
        Loại tấn công (brute_force, port_scan, sql_injection, etc.)
        hoặc 'benign' nếu không phát hiện tấn công (lưu lượng bình thường)
    """
    if pd.isna(event_desc) or not event_desc:
        return 'unknown'
    
    event_desc_lower = str(event_desc).lower()
    
    # Kiểm tra từng loại tấn công
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, event_desc_lower, re.IGNORECASE):
                return attack_type
    
    return 'benign'


def extract_event_category(event_desc: str, rule_groups: Optional[str] = None) -> str:
    """
    Phân loại danh mục sự kiện dựa trên event description và rule groups
    
    Args:
        event_desc: Mô tả sự kiện
        rule_groups: Rule groups từ Wazuh (có thể là string hoặc list)
        
    Returns:
        Danh mục sự kiện
    """
    if pd.isna(event_desc) or not event_desc:
        event_desc = ""
    
    event_desc_lower = str(event_desc).lower()
    
    # Kiểm tra rule_groups trước (nếu có)
    if rule_groups and pd.notna(rule_groups):
        rule_groups_str = str(rule_groups).lower()
        # Map rule groups trực tiếp
        if 'authentication' in rule_groups_str or 'auth' in rule_groups_str:
            return 'authentication'
        elif 'ossec' in rule_groups_str or 'syscheck' in rule_groups_str:
            return 'file_integrity'
        elif 'network' in rule_groups_str or 'ids' in rule_groups_str:
            return 'network'
        elif 'system' in rule_groups_str or 'syslog' in rule_groups_str:
            return 'system'
        elif 'sca' in rule_groups_str or 'compliance' in rule_groups_str:
            return 'compliance'
        elif 'vulnerability' in rule_groups_str:
            return 'vulnerability'
        elif 'malware' in rule_groups_str:
            return 'malware_detection'
        elif 'web' in rule_groups_str or 'apache' in rule_groups_str:
            return 'web'
    
    # Nếu không có rule_groups, dùng pattern matching trên event_desc
    for category, patterns in EVENT_CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, event_desc_lower, re.IGNORECASE):
                return category
    
    return 'other'


def create_classification_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Tạo labels cho classification từ DataFrame
    
    Args:
        df: DataFrame với event_desc và rule_groups
        
    Returns:
        DataFrame với các cột classification labels
    """
    df = df.copy()
    
    print("Creating classification labels...")
    
    # Extract attack type
    if 'event_desc' in df.columns:
        df['attack_type'] = df['event_desc'].apply(extract_attack_type)
    else:
        df['attack_type'] = 'unknown'
    
    # Extract event category
    rule_groups_col = 'rule_groups' if 'rule_groups' in df.columns else None
    if 'event_desc' in df.columns:
        if rule_groups_col:
            df['event_category'] = df.apply(
                lambda row: extract_event_category(
                    row.get('event_desc', ''),
                    row.get(rule_groups_col, None)
                ),
                axis=1
            )
        else:
            df['event_category'] = df['event_desc'].apply(extract_event_category)
    else:
        df['event_category'] = 'other'
    
    # Thống kê
    print(f"   Attack types distribution:")
    attack_counts = df['attack_type'].value_counts()
    for attack_type, count in attack_counts.items():
        print(f"     {attack_type:20s}: {count:4d} ({count/len(df)*100:.1f}%)")
    
    print(f"\n   Event categories distribution:")
    category_counts = df['event_category'].value_counts()
    for category, count in category_counts.items():
        print(f"     {category:20s}: {count:4d} ({count/len(df)*100:.1f}%)")
    
    return df


def get_classification_features(df: pd.DataFrame, feature_names: List[str]) -> pd.DataFrame:
    """
    Lấy features cho classification (có thể dùng chung với anomaly detection)
    
    Args:
        df: DataFrame đã được feature engineering
        feature_names: Danh sách tên features từ anomaly model
        
    Returns:
        Feature matrix cho classification
    """
    # Sử dụng cùng features như anomaly detection
    available_features = [f for f in feature_names if f in df.columns]
    X = df[available_features].fillna(0)
    
    # Đảm bảo có đủ features
    for f in feature_names:
        if f not in X.columns:
            X[f] = 0
    
    # Chỉ giữ features đúng thứ tự
    X = X[feature_names]
    
    return X


if __name__ == "__main__":
    # Test với sample data
    print("Testing classification module...")
    
    sample_data = {
        'event_desc': [
            'sshd: authentication failure for user root',
            'Port scan detected from 192.168.1.100',
            'SQL injection attempt detected in web request',
            'File integrity checksum changed: /etc/passwd',
            'Wazuh server started.',
            'CIS Ubuntu Linux 24.04 LTS Benchmark: Ensure mounting of cramfs filesystems is disabled.'
        ],
        'rule_groups': [
            'sshd,authentication_failure',
            'ids,network',
            'web,attack',
            'ossec,syscheck',
            'ossec',
            'sca,compliance'
        ]
    }
    
    df = pd.DataFrame(sample_data)
    df = create_classification_labels(df)
    
    print("\n" + "="*60)
    print("CLASSIFICATION RESULTS")
    print("="*60)
    print(df[['event_desc', 'attack_type', 'event_category']].to_string(index=False))

