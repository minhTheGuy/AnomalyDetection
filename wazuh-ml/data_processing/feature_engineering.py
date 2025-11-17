"""
Module trích xuất các đặc trưng nâng cao cho anomaly detection
"""

import numpy as np
import pandas as pd

from utils.common import print_header


def _ensure_numeric(series, default=0):
    return pd.to_numeric(series, errors="coerce").fillna(default)


def _apply_keyword_flags(df, column, keyword_sets):
    col = df.get(column, pd.Series(dtype=str)).astype(str).str.lower()
    for new_col, keywords in keyword_sets.items():
        df[new_col] = col.apply(lambda text: int(any(k in text for k in keywords)))
    return df

def extract_time_features(df):
    """
    Trích xuất các đặc trưng thời gian từ timestamp
    
    Args:
        df: DataFrame với cột 'timestamp'
    
    Returns:
        DataFrame với các cột time features mới
    """
    df = df.copy()
    
    # Chuyển đổi timestamp sang datetime
    if 'timestamp' in df.columns:
        ts = pd.to_datetime(df['timestamp'], errors='coerce')
        df['timestamp'] = ts
        df['hour'] = ts.dt.hour.fillna(0).astype(int)
        df['day_of_week'] = ts.dt.dayofweek.fillna(0).astype(int)
        df['minute'] = ts.dt.minute.fillna(0).astype(int)
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = (
            df['hour'].between(9, 17) & (df['day_of_week'] < 5)
        ).astype(int)
    
    return df


def extract_network_features(df):
    """
    Trích xuất đặc trưng mạng nâng cao
    
    Args:
        df: DataFrame với các cột network (src_port, dst_port, bytes, etc.)
    
    Returns:
        DataFrame với các network features mới
    """
    df = df.copy()
    
    # Đảm bảo các cột số tồn tại
    if 'dst_port' in df.columns:
        df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)
        
        # Phân loại port
        df['is_well_known_port'] = ((df['dst_port'] > 0) & (df['dst_port'] < 1024)).astype(int)
        df['is_registered_port'] = ((df['dst_port'] >= 1024) & (df['dst_port'] < 49152)).astype(int)
        df['is_dynamic_port'] = (df['dst_port'] >= 49152).astype(int)
        
        # Port range (binning)
        df['port_range'] = pd.cut(
            df['dst_port'], 
            bins=[-1, 80, 443, 1024, 49152, 65535],
            labels=['web', 'https', 'system', 'registered', 'dynamic'],
            include_lowest=True
        ).astype(str)
    
    if 'src_port' in df.columns:
        df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0)
        df['is_ephemeral_src'] = (df['src_port'] >= 32768).astype(int)
    
    # Tính toán bytes features - ưu tiên từ flow stats, sau đó từ bytes field
    if 'bytes_toserver' in df.columns or 'bytes_toclient' in df.columns:
        df['bytes_toserver'] = _ensure_numeric(df.get('bytes_toserver', 0))
        df['bytes_toclient'] = _ensure_numeric(df.get('bytes_toclient', 0))
        if 'bytes' not in df.columns or df['bytes'].isna().all():
            df['bytes'] = df['bytes_toserver'] + df['bytes_toclient']
    
    if 'bytes' in df.columns:
        df['bytes'] = _ensure_numeric(df['bytes'])
        df['log_bytes'] = np.log1p(df['bytes'])  # log transform để giảm skewness
        
        # Phân loại kích thước packet
        df['packet_size_category'] = pd.cut(
            df['bytes'],
            bins=[0, 64, 512, 1500, 65535],
            labels=['tiny', 'small', 'medium', 'large'],
            include_lowest=True
        ).astype(str)
    
    # Length từ syscheck size hoặc length field
    if 'syscheck_size' in df.columns:
        df['syscheck_size'] = _ensure_numeric(df['syscheck_size'])
        if 'length' not in df.columns or df['length'].isna().all():
            df['length'] = df['syscheck_size']
    
    if 'length' in df.columns:
        df['length'] = _ensure_numeric(df['length'])
        df['log_length'] = np.log1p(df['length'])
    
    # Flow stats features (nếu có)
    if 'pkts_toserver' in df.columns or 'pkts_toclient' in df.columns:
        df['pkts_toserver'] = _ensure_numeric(df.get('pkts_toserver', 0))
        df['pkts_toclient'] = _ensure_numeric(df.get('pkts_toclient', 0))
        df['total_packets'] = df['pkts_toserver'] + df['pkts_toclient']
        df['packet_ratio'] = np.where(
            df['total_packets'] > 0,
            df['pkts_toserver'] / df['total_packets'],
            0
        )
    
    # Kiểm tra internal/external IP
    if 'src_ip' in df.columns and 'dst_ip' in df.columns:
        def is_private(ip_str):
            s = str(ip_str)
            return s.startswith(('10.', '172.16.', '192.168.'))
        df['is_internal_src'] = df['src_ip'].apply(lambda x: int(is_private(x)))
        df['is_internal_dst'] = df['dst_ip'].apply(lambda x: int(is_private(x)))
        df['is_internal_communication'] = (df['is_internal_src'] & df['is_internal_dst']).astype(int)
    
    return df


def extract_event_features(df):
    """
    Trích xuất đặc trưng từ event description, rule info, và các fields mới (syscheck, alert)
    
    Args:
        df: DataFrame với cột 'event_desc', 'rule_level', và các fields mới
    
    Returns:
        DataFrame với event features mới
    """
    df = df.copy()
    
    # Syscheck (File Integrity Monitoring) features
    if 'syscheck_event' in df.columns:
        se_lower = df['syscheck_event'].astype(str).str.lower()
        df['is_syscheck_event'] = se_lower.notna().astype(int)
        df['is_file_added'] = (se_lower == 'added').astype(int)
        df['is_file_modified'] = (se_lower == 'modified').astype(int)
        df['is_file_deleted'] = (se_lower == 'deleted').astype(int)
    
    if 'syscheck_path' in df.columns:
        df['syscheck_path_length'] = df['syscheck_path'].astype(str).str.len()
        # Phân loại path types (sử dụng non-capturing group để tránh warning)
        df['is_system_path'] = df['syscheck_path'].astype(str).str.contains(
            r'(?:/etc|/usr|/bin|/sbin|/var|/opt)', case=False, na=False, regex=True
        ).astype(int)
        df['is_user_path'] = df['syscheck_path'].astype(str).str.contains(
            r'(?:/home|/root)', case=False, na=False, regex=True
        ).astype(int)
    
    # Suricata alert features
    if 'alert_severity' in df.columns:
        df['alert_severity'] = pd.to_numeric(df['alert_severity'], errors='coerce').fillna(0)
        df['is_high_severity_alert'] = (df['alert_severity'] >= 2).astype(int)
    
    if 'alert_category' in df.columns:
        df['has_alert_category'] = df['alert_category'].notna().astype(int)
    
    if 'alert_signature' in df.columns:
        df['alert_signature_length'] = df['alert_signature'].astype(str).str.len()
        df['has_alert_signature'] = df['alert_signature'].notna().astype(int)
    
    # Event type features
    if 'event_type' in df.columns:
        df['is_alert_event'] = (df['event_type'].astype(str).str.lower() == 'alert').astype(int)
        df['is_flow_event'] = (df['event_type'].astype(str).str.lower() == 'flow').astype(int)
    
    # App protocol features
    if 'app_proto' in df.columns:
        proto_lower = df['app_proto'].astype(str).str.lower()
        df['has_app_proto'] = proto_lower.notna().astype(int)
        df['is_http_proto'] = proto_lower.str.contains('http', na=False).astype(int)
        df['is_ssl_proto'] = proto_lower.str.contains('ssl|tls', na=False).astype(int)
    
    if 'event_desc' in df.columns:
        event_desc = df['event_desc'].astype(str)
        lower_desc = event_desc.str.lower()
        df['event_desc_length'] = event_desc.str.len()
        df['event_word_count'] = event_desc.str.split().str.len()
        danger_keywords = [
            'failed', 'error', 'attack', 'denied', 'unauthorized',
            'malicious', 'suspicious', 'breach', 'intrusion', 'exploit',
            'backdoor', 'trojan', 'virus', 'malware', 'ransomware',
            'brute', 'scan', 'flood', 'injection', 'overflow'
        ]
        df['danger_keyword_count'] = lower_desc.apply(lambda x: sum(k in x for k in danger_keywords))
        df = _apply_keyword_flags(df, 'event_desc', {
            'is_auth_event': ['login', 'logout', 'authentication', 'auth', 'session', 'password'],
            'is_fim_event': ['file', 'changed', 'modified', 'deleted', 'integrity', 'checksum'],
        })
    
    if 'rule_level' in df.columns:
        df['rule_level'] = _ensure_numeric(df['rule_level'])
        df['severity_category'] = pd.cut(
            df['rule_level'],
            bins=[0, 3, 7, 11, 15, 20],
            labels=['info', 'low', 'medium', 'high', 'critical'],
            include_lowest=True
        ).astype(str)
        df['is_critical'] = (df['rule_level'] >= 15).astype(int)
        df['is_high'] = df['rule_level'].between(11, 14).astype(int)
        df['is_medium'] = df['rule_level'].between(7, 10).astype(int)
    
    return df


def create_sequence_features(df, window_minutes=10):
    """
    Tạo đặc trưng chuỗi thời gian (sequence analysis)
    
    Args:
        df: DataFrame với 'timestamp', 'agent'
        window_minutes: Kích thước cửa sổ thời gian (phút)
    
    Returns:
        DataFrame với sequence features
    """
    df = df.copy()
    
    if 'timestamp' not in df.columns or 'agent' not in df.columns:
        return df
    
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.sort_values('timestamp')
    df['time_delta'] = df.groupby('agent')['timestamp'].diff().dt.total_seconds().fillna(0)

    rolling_counts = (
        df.set_index('timestamp')
          .groupby('agent')
          .rolling(f'{window_minutes}min')
          .size()
          .reset_index(level=0, drop=True)
          .reindex(df.index, fill_value=0)
    )
    df['events_in_window'] = rolling_counts.astype(int)
    df['avg_event_frequency'] = df['events_in_window'] / max(window_minutes, 1)

    threshold = df['events_in_window'].mean() + 2 * df['events_in_window'].std()
    df['is_burst'] = (df['events_in_window'] > threshold).astype(int)
    df['event_velocity'] = df.groupby('agent')['events_in_window'].diff().fillna(0)
    
    return df


def create_aggregated_features(df):
    """
    Tạo các đặc trưng tổng hợp (aggregated features)
    
    Args:
        df: DataFrame
    
    Returns:
        DataFrame với aggregated features
    """
    df = df.copy()
    
    # Đếm số lần xuất hiện của mỗi agent
    if 'agent' in df.columns:
        agent_counts = df['agent'].value_counts().to_dict()
        df['agent_event_count'] = df['agent'].map(agent_counts)
        df['is_rare_agent'] = (df['agent_event_count'] < 5).astype(int)
    
    # Đếm số lần xuất hiện của mỗi src_ip
    if 'src_ip' in df.columns:
        ip_counts = df['src_ip'].value_counts().to_dict()
        df['src_ip_count'] = df['src_ip'].map(ip_counts)
        df['is_rare_src_ip'] = (df['src_ip_count'] < 3).astype(int)
    
    # Tỷ lệ rule_level trung bình cho mỗi agent
    if 'agent' in df.columns and 'rule_level' in df.columns:
        agent_avg_level = df.groupby('agent')['rule_level'].transform('mean')
        df['agent_avg_rule_level'] = agent_avg_level
        df['rule_level_deviation'] = abs(df['rule_level'] - agent_avg_level)
    
    return df


def engineer_all_features(df):
    """
    Áp dụng tất cả feature engineering
    
    Args:
        df: Raw DataFrame
    
    Returns:
        DataFrame với tất cả features đã được engineering
    """
    print_header("FEATURE ENGINEERING", width=60)
    
    initial_cols = df.shape[1]
    
    print("  Extracting time features...")
    df = extract_time_features(df)
    
    print("  Extracting network features...")
    df = extract_network_features(df)
    
    print("  Extracting event features...")
    df = extract_event_features(df)
    
    print("  Creating sequence features...")
    df = create_sequence_features(df)
    
    print("  Creating aggregated features...")
    df = create_aggregated_features(df)
    
    final_cols = df.shape[1]
    print(f"\nFeatures added: {final_cols - initial_cols} (Total: {final_cols})")
    
    return df
