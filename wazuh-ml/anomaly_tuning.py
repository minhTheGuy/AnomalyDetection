#!/usr/bin/env python3
# anomaly_tuning.py
"""
Module tinh chỉnh anomaly detection để giảm false positives
"""

import pandas as pd
import numpy as np
from datetime import datetime

class AnomalyFilter:
    """Filter và điều chỉnh anomaly scores để giảm false positives"""
    
    def __init__(self):
        # Whitelist: Các sự kiện được coi là bình thường
        self.whitelisted_patterns = {
            'ssh_internal_admin': {
                'description': 'SSH login từ admin nội bộ',
                'conditions': {
                    'event_desc': ['sshd: authentication success'],
                    'src_ip': ['172.16.158.1', '172.16.158.100'],  # Admin IPs
                    'is_business_hours': [1],  # Chỉ trong giờ làm việc
                }
            },
            'dns_queries_internal': {
                'description': 'Internal DNS queries/responses',
                'conditions': {
                    'proto': ['udp'],
                    'dst_port': [53],
                    'is_internal_src': [1],
                    'is_internal_dst': [1]
                }
            },
            'icmp_ping_internal': {
                'description': 'ICMP echo internal monitoring',
                'conditions': {
                    'event_desc': ['icmp echo request', 'icmp echo reply'],
                    'is_internal_communication': [1]
                }
            },
            'ntp_sync': {
                'description': 'NTP time synchronization',
                'conditions': {
                    'dst_port': [123],
                    'proto': ['udp']
                }
            },
            'dhcp_activity': {
                'description': 'DHCP client/server traffic',
                'conditions': {
                    'dst_port': [67, 68],
                    'proto': ['udp']
                }
            },
            'pfSense_webui': {
                'description': 'pfSense WebUI access from admin',
                'conditions': {
                    'dst_ip': ['172.16.158.100', '172.16.158.1'],
                    'dst_port': [443, 4443],
                    'is_internal_src': [1]
                }
            },
            'system_update': {
                'description': 'System updates và package management',
                'conditions': {
                    'event_desc': ['apt user-agent', 'package management'],
                    'rule_level': [0, 1, 2, 3, 4]  # Low severity
                }
            },
            'scheduled_integrity_check': {
                'description': 'FIM checks định kỳ',
                'conditions': {
                    'event_desc': ['integrity checksum changed'],
                    'hour': [2, 3],  # Scheduled at 2-3 AM
                    'rule_level': [0, 1, 2, 3, 4, 5, 6, 7]
                }
            },
            'compliance_check': {
                'description': 'CIS compliance checks',
                'conditions': {
                    'event_desc': ['cis', 'benchmark', 'status changed from failed to passed']
                }
            }
        }
        
        # Suspicious patterns (tăng score)
        self.suspicious_patterns = {
            'brute_force': {
                'description': 'Brute force attempts',
                'conditions': {
                    'event_desc': ['non-existent user', 'failed password', 'invalid user'],
                },
                'score_multiplier': 2.0
            },
            'port_scan': {
                'description': 'Potential port scanning activity',
                'conditions': {
                    'event_desc': ['port scan', 'nmap', 'syn scan', 'xmas scan'],
                },
                'score_multiplier': 2.0
            },
            'external_rdp_attempt': {
                'description': 'RDP access attempts from external source',
                'conditions': {
                    'is_internal_src': [0],
                    'dst_port': [3389]
                },
                'score_multiplier': 2.5
            },
            'http_scan_tools': {
                'description': 'Web scanning tools detected (nikto/sqlmap/gobuster/dirb)',
                'conditions': {
                    'event_desc': ['nikto', 'sqlmap', 'gobuster', 'dirb']
                },
                'score_multiplier': 2.2
            },
            'web_sql_injection_signatures': {
                'description': 'Possible SQL injection payload patterns',
                'conditions': {
                    'event_desc': ["sql injection", "union select", "or 1=1", "' or '1'='1"]
                },
                'score_multiplier': 2.8
            },
            'ssh_password_spray': {
                'description': 'Multiple SSH auth failures indicative of password spraying',
                'conditions': {
                    'event_desc': ['failed password', 'authentication failure']
                },
                'score_multiplier': 2.3
            },
            'high_egress_to_external': {
                'description': 'High egress bytes to external destination',
                'conditions': {
                    'is_internal_src': [1],
                    'is_internal_dst': [0],
                    'bytes': [1000000]  # handled as >= in match
                },
                'score_multiplier': 1.8
            },
            'lateral_movement': {
                'description': 'Internal-to-internal lateral movement on high ports',
                'conditions': {
                    'is_internal_src': [1],
                    'is_internal_dst': [1],
                    'dst_port': [445, 3389, 5985, 5986]
                },
                'score_multiplier': 2.2
            },
            'night_activity': {
                'description': 'Activity vào ban đêm (ngoại trừ scheduled tasks)',
                'conditions': {
                    'is_night': [1],
                    'rule_level': [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                },
                'score_multiplier': 1.5
            },
            'external_access': {
                'description': 'Access từ external IPs',
                'conditions': {
                    'is_internal_src': [0],  # External source
                    'rule_level': [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                },
                'score_multiplier': 1.8
            },
            'high_severity': {
                'description': 'High/Critical severity events',
                'conditions': {
                    'is_critical': [1],
                },
                'score_multiplier': 2.5
            },
            'burst_activity': {
                'description': 'Burst of events',
                'conditions': {
                    'is_burst': [1],
                },
                'score_multiplier': 1.3
            }
        }
    
    def match_pattern(self, row, conditions):
        """
        Kiểm tra xem row có match với pattern conditions không
        
        Args:
            row: DataFrame row
            conditions: Dictionary với pattern conditions
        
        Returns:
            True nếu match, False nếu không
        """
        for col, values in conditions.items():
            if col not in row.index:
                continue
            
            row_value = row[col]
            
            # String matching (contains)
            if isinstance(values[0], str):
                if not any(str(v).lower() in str(row_value).lower() for v in values):
                    return False
            # Numeric exact/greater-equal matching
            else:
                try:
                    # If values contain a single numeric threshold and the row_value is numeric, treat as >= threshold
                    if len(values) == 1 and (isinstance(values[0], (int, float))):
                        try:
                            rv = float(row_value)
                            if rv < float(values[0]):
                                return False
                        except Exception:
                            return False
                    else:
                        if row_value not in values:
                            return False
                except Exception:
                    return False
        
        return True
    
    def apply_whitelist(self, df):
        """
        Áp dụng whitelist để loại bỏ false positives
        
        Args:
            df: DataFrame với anomaly predictions
        
        Returns:
            DataFrame với whitelist flags
        """
        df = df.copy()
        df['is_whitelisted'] = False
        df['whitelist_reason'] = ''
        
        for pattern_name, pattern_config in self.whitelisted_patterns.items():
            conditions = pattern_config['conditions']
            description = pattern_config['description']
            
            for idx, row in df.iterrows():
                if self.match_pattern(row, conditions):
                    df.at[idx, 'is_whitelisted'] = True
                    df.at[idx, 'whitelist_reason'] = description
        
        return df
    
    def apply_suspicious_boost(self, df):
        """
        Tăng anomaly score cho các pattern đáng ngờ
        
        Args:
            df: DataFrame với anomaly scores
        
        Returns:
            DataFrame với adjusted scores
        """
        df = df.copy()
        df['score_multiplier'] = 1.0
        df['suspicious_reason'] = ''
        
        for pattern_name, pattern_config in self.suspicious_patterns.items():
            conditions = pattern_config['conditions']
            multiplier = pattern_config.get('score_multiplier', 1.0)
            description = pattern_config['description']
            
            for idx, row in df.iterrows():
                if self.match_pattern(row, conditions):
                    # Áp dụng multiplier cao nhất nếu match nhiều patterns
                    if multiplier > df.at[idx, 'score_multiplier']:
                        df.at[idx, 'score_multiplier'] = multiplier
                        df.at[idx, 'suspicious_reason'] = description
        
        # Adjust anomaly score
        df['anomaly_score_original'] = df['anomaly_score']
        df['anomaly_score'] = df['anomaly_score'] * df['score_multiplier']
        
        return df
    
    def filter_anomalies(self, df, remove_whitelisted=True, apply_boost=True):
        """
        Áp dụng toàn bộ filters
        
        Args:
            df: DataFrame với anomaly predictions
            remove_whitelisted: Loại bỏ whitelisted events khỏi anomalies
            apply_boost: Tăng score cho suspicious events
        
        Returns:
            Filtered DataFrame
        """
        df = df.copy()
        
        # Apply whitelist
        df = self.apply_whitelist(df)
        
        # Apply suspicious boost
        if apply_boost:
            df = self.apply_suspicious_boost(df)
        
        # Filter anomalies
        if remove_whitelisted:
            # Chỉ giữ anomalies không bị whitelist
            df['anomaly_label_filtered'] = df.apply(
                lambda row: -1 if (row['anomaly_label'] == -1 and not row['is_whitelisted']) else 1,
                axis=1
            )
        else:
            df['anomaly_label_filtered'] = df['anomaly_label']
        
        return df


def compute_dynamic_threshold(scores, target_anomaly_rate=0.03, min_rate=0.01, max_rate=0.10):
    """
    Tính dynamic threshold dựa theo percentile với guardrails
    - scores: array-like, càng âm càng bất thường
    - Trả về ngưỡng score, tại đó khoảng target_rate mẫu sẽ bị coi là anomaly
    """
    import numpy as np
    n = len(scores)
    if n == 0:
        return None
    # Clamp target rate
    target = max(min_rate, min(max_rate, target_anomaly_rate))
    percentile = target * 100.0
    threshold = np.percentile(scores, percentile)
    return float(threshold)


def apply_threshold_to_labels(df, threshold, label_col='anomaly_label', score_col='anomaly_score'):
    """
    Áp dụng threshold động để (re)label anomalies
    Note: score càng âm = càng anomaly → anomaly nếu score <= threshold
    """
    if threshold is None or score_col not in df.columns:
        return df
    df = df.copy()
    df[label_col] = df[score_col].apply(lambda s: -1 if s <= threshold else 1)
    return df


def analyze_anomaly_distribution(df):
    """
    Phân tích phân bố của anomalies
    
    Args:
        df: DataFrame với anomaly predictions
    """
    print("\n" + "="*70)
    print("📊 ANOMALY DISTRIBUTION ANALYSIS")
    print("="*70)
    
    anomalies = df[df['anomaly_label'] == -1]
    
    if len(anomalies) == 0:
        print("No anomalies detected!")
        return
    
    # By severity
    print("\n🔴 By Severity:")
    if 'severity_category' in df.columns:
        severity_dist = anomalies['severity_category'].value_counts()
        for severity, count in severity_dist.items():
            print(f"  {severity:10s}: {count:3d} ({count/len(anomalies)*100:.1f}%)")
    
    # By time of day
    print("\n⏰ By Time:")
    if 'hour' in df.columns:
        hour_dist = anomalies['hour'].value_counts().sort_index()
        for hour, count in hour_dist.items():
            bar = "█" * int(count / len(anomalies) * 50)
            print(f"  {int(hour):02d}:00 - {count:3d} {bar}")
    
    # By agent
    print("\n💻 By Agent:")
    if 'agent' in df.columns:
        agent_dist = anomalies['agent'].value_counts()
        for agent, count in agent_dist.head(5).items():
            print(f"  {agent:20s}: {count:3d} ({count/len(anomalies)*100:.1f}%)")
    
    # By event type
    print("\n📝 Top Event Types:")
    if 'event_desc' in df.columns:
        event_dist = anomalies['event_desc'].value_counts()
        for event, count in event_dist.head(10).items():
            print(f"  {event[:60]:60s}: {count:3d}")
    
    # Score distribution
    print("\n📈 Score Distribution:")
    if 'anomaly_score' in df.columns:
        scores = anomalies['anomaly_score']
        print(f"  Min:    {scores.min():.4f}")
        print(f"  Q1:     {scores.quantile(0.25):.4f}")
        print(f"  Median: {scores.median():.4f}")
        print(f"  Q3:     {scores.quantile(0.75):.4f}")
        print(f"  Max:    {scores.max():.4f}")


def recommend_threshold(df, target_anomaly_rate=0.02):
    """
    Đề xuất threshold dựa trên phân bố scores
    
    Args:
        df: DataFrame với anomaly scores
        target_anomaly_rate: Tỷ lệ anomaly mong muốn (default 2%)
    
    Returns:
        Recommended threshold
    """
    scores = df['anomaly_score'].values
    scores_sorted = np.sort(scores)
    
    # Tính threshold tại target percentile
    threshold_idx = int(len(scores) * target_anomaly_rate)
    recommended_threshold = scores_sorted[threshold_idx]
    
    print("\n" + "="*70)
    print("💡 THRESHOLD RECOMMENDATION")
    print("="*70)
    print(f"Target anomaly rate: {target_anomaly_rate*100:.1f}%")
    print(f"Recommended threshold: {recommended_threshold:.4f}")
    print(f"Expected anomalies: {threshold_idx}")
    
    # Test với các threshold khác nhau
    print("\n📊 Threshold Impact:")
    for percentile in [0.01, 0.02, 0.03, 0.05, 0.07, 0.10]:
        threshold = scores_sorted[int(len(scores) * percentile)]
        n_anomalies = (scores <= threshold).sum()
        print(f"  {percentile*100:4.1f}% → threshold={threshold:7.4f} → {n_anomalies:3d} anomalies")
    
    return recommended_threshold


if __name__ == "__main__":
    # Test với data thực
    print("Testing Anomaly Tuning Module...")
    
    from config import ANALYZED_CSV_PATH
    
    if not pd.io.common.file_exists(ANALYZED_CSV_PATH):
        print("❌ No analyzed data found. Run train_model.py first.")
        exit(1)
    
    df = pd.read_csv(ANALYZED_CSV_PATH)
    print(f"Loaded {len(df)} records")
    
    # Analyze distribution
    analyze_anomaly_distribution(df)
    
    # Recommend threshold
    recommend_threshold(df, target_anomaly_rate=0.02)
    
    # Apply filters
    print("\n" + "="*70)
    print("🔧 APPLYING FILTERS")
    print("="*70)
    
    filter_engine = AnomalyFilter()
    df_filtered = filter_engine.filter_anomalies(df)
    
    before = (df['anomaly_label'] == -1).sum()
    after = (df_filtered['anomaly_label_filtered'] == -1).sum()
    whitelisted = df_filtered['is_whitelisted'].sum()
    
    print(f"\n📊 Filtering Results:")
    print(f"  Before filtering: {before} anomalies")
    print(f"  Whitelisted:      {whitelisted} events")
    print(f"  After filtering:  {after} anomalies")
    print(f"  Reduction:        {before - after} ({(before-after)/before*100:.1f}%)")
    
    print("\n✅ Filtered anomalies:")
    filtered_anomalies = df_filtered[df_filtered['anomaly_label_filtered'] == -1]
    if len(filtered_anomalies) > 0:
        display_cols = ['timestamp', 'agent', 'rule_level', 'event_desc', 'anomaly_score', 'suspicious_reason']
        display_cols = [c for c in display_cols if c in filtered_anomalies.columns]
        print(filtered_anomalies[display_cols].head(10).to_string(index=False))
