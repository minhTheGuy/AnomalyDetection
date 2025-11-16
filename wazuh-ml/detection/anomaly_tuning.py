"""
Module tinh chỉnh anomaly detection để giảm false positives
"""
import pandas as pd
import numpy as np
from utils.common import print_header, safe_load_csv


class AnomalyFilter:
    """Filter và điều chỉnh anomaly scores để giảm false positives"""
    
    def __init__(self):
        # Whitelist: Các sự kiện được coi là bình thường
        self.whitelisted_patterns = {
            'ssh_internal_admin': {
                'description': 'SSH login từ admin nội bộ',
                'conditions': {
                    'event_desc': ['sshd: authentication success'],
                    'src_ip': ['172.16.158.1', '172.16.158.100'],
                    'is_business_hours': [1],
                }
            },
            'dns_queries_internal': {
                'description': 'Internal DNS queries/responses',
                'conditions': {'proto': ['udp'], 'dst_port': [53], 'is_internal_src': [1], 'is_internal_dst': [1]}
            },
            'icmp_ping_internal': {
                'description': 'ICMP echo internal monitoring',
                'conditions': {'event_desc': ['icmp echo request', 'icmp echo reply'], 'is_internal_communication': [1]}
            },
            'ntp_sync': {'description': 'NTP time synchronization', 'conditions': {'dst_port': [123], 'proto': ['udp']}},
            'dhcp_activity': {'description': 'DHCP client/server traffic', 'conditions': {'dst_port': [67, 68], 'proto': ['udp']}},
            'pfSense_webui': {
                'description': 'pfSense WebUI access from admin',
                'conditions': {'dst_ip': ['172.16.158.100', '172.16.158.1'], 'dst_port': [443, 4443], 'is_internal_src': [1]}
            },
            'system_update': {
                'description': 'System updates và package management',
                'conditions': {'event_desc': ['apt user-agent', 'package management'], 'rule_level': [0, 1, 2, 3, 4]}
            },
            'scheduled_integrity_check': {
                'description': 'FIM checks định kỳ',
                'conditions': {'event_desc': ['integrity checksum changed'], 'hour': [2, 3], 'rule_level': list(range(8))}
            },
            'compliance_check': {
                'description': 'CIS compliance checks',
                'conditions': {'event_desc': ['cis', 'benchmark', 'status changed from failed to passed']}
            }
        }
        
        # Suspicious patterns (tăng score)
        self.suspicious_patterns = {
            'brute_force': {
                'description': 'Brute force attempts',
                'conditions': {'event_desc': ['non-existent user', 'failed password', 'invalid user']},
                'score_multiplier': 2.0
            },
            'port_scan': {
                'description': 'Potential port scanning activity',
                'conditions': {'event_desc': ['port scan', 'nmap', 'syn scan', 'xmas scan']},
                'score_multiplier': 2.0
            },
            'external_rdp_attempt': {
                'description': 'RDP access attempts from external source',
                'conditions': {'is_internal_src': [0], 'dst_port': [3389]},
                'score_multiplier': 2.5
            },
            'http_scan_tools': {
                'description': 'Web scanning tools detected',
                'conditions': {'event_desc': ['nikto', 'sqlmap', 'gobuster', 'dirb']},
                'score_multiplier': 2.2
            },
            'web_sql_injection_signatures': {
                'description': 'Possible SQL injection payload patterns',
                'conditions': {'event_desc': ["sql injection", "union select", "or 1=1", "' or '1'='1"]},
                'score_multiplier': 2.8
            },
            'ssh_password_spray': {
                'description': 'Multiple SSH auth failures',
                'conditions': {'event_desc': ['failed password', 'authentication failure']},
                'score_multiplier': 2.3
            },
            'high_egress_to_external': {
                'description': 'High egress bytes to external destination',
                'conditions': {'is_internal_src': [1], 'is_internal_dst': [0], 'bytes': [1000000]},
                'score_multiplier': 1.8
            },
            'lateral_movement': {
                'description': 'Internal-to-internal lateral movement',
                'conditions': {'is_internal_src': [1], 'is_internal_dst': [1], 'dst_port': [445, 3389, 5985, 5986]},
                'score_multiplier': 2.2
            },
            'night_activity': {
                'description': 'Activity vào ban đêm',
                'conditions': {'is_night': [1], 'rule_level': list(range(5, 16))},
                'score_multiplier': 1.5
            },
            'external_access': {
                'description': 'Access từ external IPs',
                'conditions': {'is_internal_src': [0], 'rule_level': list(range(5, 16))},
                'score_multiplier': 1.8
            },
            'high_severity': {'description': 'High/Critical severity events', 'conditions': {'is_critical': [1]}, 'score_multiplier': 2.5},
            'burst_activity': {'description': 'Burst of events', 'conditions': {'is_burst': [1]}, 'score_multiplier': 1.3}
        }
    
    def _match_pattern(self, row, conditions):
        """Kiểm tra xem row có match với pattern conditions không"""
        for col, values in conditions.items():
            if col not in row.index:
                continue
            
            row_value = row[col]
            
            # String matching (contains)
            if isinstance(values[0], str):
                if not any(str(v).lower() in str(row_value).lower() for v in values):
                    return False
            # Numeric matching
            else:
                try:
                    # Single numeric threshold → treat as >=
                    if len(values) == 1 and isinstance(values[0], (int, float)):
                        if float(row_value) < float(values[0]):
                            return False
                    else:
                        if row_value not in values:
                            return False
                except Exception:
                    return False
        
        return True
    
    def _apply_patterns(self, df, patterns, result_col, reason_col, default_value):
        """Helper: Áp dụng patterns lên DataFrame"""
        df = df.copy()
        df[result_col] = default_value
        df[reason_col] = ''
        
        for pattern_name, pattern_config in patterns.items():
            conditions = pattern_config['conditions']
            description = pattern_config['description']
            
            # Vectorized matching
            mask = df.apply(lambda row: self._match_pattern(row, conditions), axis=1)
            
            if result_col == 'is_whitelisted':
                df.loc[mask, result_col] = True
                df.loc[mask, reason_col] = description
            elif result_col == 'score_multiplier':
                multiplier = pattern_config.get('score_multiplier', 1.0)
                # Chỉ update nếu multiplier cao hơn
                update_mask = mask & (df[result_col] < multiplier)
                df.loc[update_mask, result_col] = multiplier
                df.loc[update_mask, reason_col] = description
        
        return df
    
    def apply_whitelist(self, df):
        """Áp dụng whitelist để loại bỏ false positives"""
        return self._apply_patterns(df, self.whitelisted_patterns, 'is_whitelisted', 'whitelist_reason', False)
    
    def apply_suspicious_boost(self, df):
        """Tăng anomaly score cho các pattern đáng ngờ"""
        df = self._apply_patterns(df, self.suspicious_patterns, 'score_multiplier', 'suspicious_reason', 1.0)
        df['anomaly_score_original'] = df['anomaly_score']
        df['anomaly_score'] = df['anomaly_score'] * df['score_multiplier']
        return df
    
    def filter_anomalies(self, df, remove_whitelisted=True, apply_boost=True):
        """Áp dụng toàn bộ filters"""
        df = df.copy()
        df = self.apply_whitelist(df)
        
        if apply_boost:
            df = self.apply_suspicious_boost(df)
        
        # Filter anomalies
        if remove_whitelisted:
            df['anomaly_label_filtered'] = df.apply(
                lambda row: -1 if (row['anomaly_label'] == -1 and not row['is_whitelisted']) else 1,
                axis=1
            )
        else:
            df['anomaly_label_filtered'] = df['anomaly_label']
        
        return df


def compute_dynamic_threshold(scores, target_anomaly_rate=0.03, min_rate=0.01, max_rate=0.10):
    """Tính dynamic threshold dựa theo percentile với guardrails"""
    n = len(scores)
    if n == 0:
        return None
    target = max(min_rate, min(max_rate, target_anomaly_rate))
    return float(np.percentile(scores, target * 100.0))


def apply_threshold_to_labels(df, threshold, label_col='anomaly_label', score_col='anomaly_score'):
    """Áp dụng threshold động để (re)label anomalies"""
    if threshold is None or score_col not in df.columns:
        return df
    df = df.copy()
    df[label_col] = df[score_col].apply(lambda s: -1 if s <= threshold else 1)
    return df


def analyze_anomaly_distribution(df):
    """Phân tích phân bố của anomalies"""
    print_header("ANOMALY DISTRIBUTION ANALYSIS", width=70)
    
    anomalies = df[df['anomaly_label'] == -1]
    
    if len(anomalies) == 0:
        print("No anomalies detected!")
        return
    
    # By severity
    if 'severity_category' in df.columns:
        print("\nBy Severity:")
        for severity, count in anomalies['severity_category'].value_counts().items():
            print(f"  {severity:10s}: {count:3d} ({count/len(anomalies)*100:.1f}%)")
    
    # By time of day
    if 'hour' in df.columns:
        print("\nBy Time:")
        for hour, count in anomalies['hour'].value_counts().sort_index().items():
            bar = "█" * int(count / len(anomalies) * 50)
            print(f"  {int(hour):02d}:00 - {count:3d} {bar}")
    
    # By agent
    if 'agent' in df.columns:
        print("\nBy Agent:")
        for agent, count in anomalies['agent'].value_counts().head(5).items():
            print(f"  {agent:20s}: {count:3d} ({count/len(anomalies)*100:.1f}%)")
    
    # By event type
    if 'event_desc' in df.columns:
        print("\nTop Event Types:")
        for event, count in anomalies['event_desc'].value_counts().head(10).items():
            print(f"  {event[:60]:60s}: {count:3d}")
    
    # Score distribution
    if 'anomaly_score' in df.columns:
        print("\nScore Distribution:")
        scores = anomalies['anomaly_score']
        print(f"  Min:    {scores.min():.4f}")
        print(f"  Q1:     {scores.quantile(0.25):.4f}")
        print(f"  Median: {scores.median():.4f}")
        print(f"  Q3:     {scores.quantile(0.75):.4f}")
        print(f"  Max:    {scores.max():.4f}")


def recommend_threshold(df, target_anomaly_rate=0.02):
    """Đề xuất threshold dựa trên phân bố scores"""
    scores = df['anomaly_score'].values
    scores_sorted = np.sort(scores)
    
    threshold_idx = int(len(scores) * target_anomaly_rate)
    recommended_threshold = scores_sorted[threshold_idx]
    
    print_header("THRESHOLD RECOMMENDATION")
    print(f"Target anomaly rate: {target_anomaly_rate*100:.1f}%")
    print(f"Recommended threshold: {recommended_threshold:.4f}")
    print(f"Expected anomalies: {threshold_idx}")
    
    print("\nThreshold Impact:")
    for percentile in [0.01, 0.02, 0.03, 0.05, 0.07, 0.10]:
        threshold = scores_sorted[int(len(scores) * percentile)]
        n_anomalies = (scores <= threshold).sum()
        print(f"  {percentile*100:4.1f}% → threshold={threshold:7.4f} → {n_anomalies:3d} anomalies")
    
    return recommended_threshold


