"""
Module phân loại sự kiện bảo mật thành các loại tấn công và danh mục sự kiện
"""
import pandas as pd
import re
from typing import List, Optional
from classification.patterns import (
    ATTACK_PATTERNS,
    EVENT_CATEGORY_PATTERNS,
    ATTACK_PRIORITY_ORDER
)


def extract_attack_type(event_desc: str) -> str:
    """
    Phân loại loại tấn công dựa trên event description
    
    Args:
        event_desc: Mô tả sự kiện
        
    Returns:
        Loại tấn công hoặc 'benign' nếu không phát hiện tấn công
    """
    if pd.isna(event_desc) or not event_desc:
        return 'unknown'
    
    event_desc_lower = str(event_desc).lower()
    
    # Check priority attacks first (malware trước port_scan để tránh false positives)
    for attack_type in ATTACK_PRIORITY_ORDER:
        if attack_type in ATTACK_PATTERNS:
            for pattern in ATTACK_PATTERNS[attack_type]:
                if re.search(pattern, event_desc_lower, re.IGNORECASE):
                    return attack_type
    
    # Check remaining attack types
    for attack_type, patterns in ATTACK_PATTERNS.items():
        if attack_type not in ATTACK_PRIORITY_ORDER:
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
        rule_group_mapping = {
            'authentication': ['authentication', 'auth'],
            'file_integrity': ['ossec', 'syscheck'],
            'network': ['network', 'ids'],
            'system': ['system', 'syslog'],
            'compliance': ['sca', 'compliance'],
            'vulnerability': ['vulnerability'],
            'malware_detection': ['malware'],
            'web': ['web', 'apache']
        }
        
        for category, keywords in rule_group_mapping.items():
            if any(kw in rule_groups_str for kw in keywords):
                return category
    
    # Nếu không có rule_groups, dùng pattern matching trên event_desc
    for category, patterns in EVENT_CATEGORY_PATTERNS.items():
        if any(re.search(pattern, event_desc_lower, re.IGNORECASE) for pattern in patterns):
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
