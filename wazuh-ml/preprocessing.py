# preprocessing.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

def preprocess_dataframe(df: pd.DataFrame):
    """
    Làm sạch dữ liệu log, encode các cột dạng text, và chọn các feature cho ML.
    Hỗ trợ cả features cơ bản và features từ feature_engineering.
    """
    df = df.copy()
    
    # 🔹 Loại bỏ dòng không có event_desc hoặc rule_level
    df = df.dropna(subset=["event_desc"])

    # 🔹 Ép kiểu các cột số (numeric features)
    numeric_cols = ["src_port", "dst_port", "bytes", "length", "rule_level"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # 🔹 Chuẩn hoá các cột text
    text_cols = ["agent", "integration", "rule_category", "proto", "event_desc"]
    for col in text_cols:
        if col in df.columns:
            df[col] = df[col].astype(str).fillna("unknown").str.strip().str.lower()

    # 🔹 Encode từng cột text thành số
    encoders = {}
    for col in text_cols:
        if col in df.columns:
            enc = LabelEncoder()
            df[f"{col}_code"] = enc.fit_transform(df[col])
            encoders[col] = enc
    
    # 🔹 Encode categorical columns từ feature engineering
    categorical_feature_cols = ['port_range', 'severity_category', 'packet_size_category']
    for col in categorical_feature_cols:
        if col in df.columns:
            enc = LabelEncoder()
            df[f"{col}_code"] = enc.fit_transform(df[col].astype(str))
            encoders[col] = enc

    # 🔹 Chọn các feature đầu vào cho ML model
    # Basic features (luôn có)
    feature_cols = [
        "src_port", "dst_port", "bytes", "length", "rule_level",
        "agent_code", "integration_code", "rule_category_code", 
        "proto_code", "event_desc_code"
    ]
    
    # Time features (từ feature_engineering)
    time_features = [
        "hour", "day_of_week", "minute", 
        "is_night", "is_weekend", "is_business_hours"
    ]
    
    # Network features (từ feature_engineering)
    network_features = [
        "is_well_known_port", "is_registered_port", "is_dynamic_port",
        "is_ephemeral_src", "log_bytes", "log_length",
        "port_range_code", "packet_size_category_code",
        "is_internal_src", "is_internal_dst", "is_internal_communication"
    ]
    
    # Event features (từ feature_engineering)
    event_features = [
        "event_desc_length", "event_word_count", "danger_keyword_count",
        "is_auth_event", "is_fim_event",
        "severity_category_code", "is_critical", "is_high", "is_medium"
    ]
    
    # Sequence features (từ feature_engineering)
    sequence_features = [
        "time_delta", "events_in_window", "avg_event_frequency", 
        "is_burst", "event_velocity"
    ]
    
    # Aggregated features (từ feature_engineering)
    aggregated_features = [
        "agent_event_count", "is_rare_agent",
        "src_ip_count", "is_rare_src_ip",
        "agent_avg_rule_level", "rule_level_deviation"
    ]
    
    # Thêm tất cả features có sẵn
    all_possible_features = (
        feature_cols + time_features + network_features + 
        event_features + sequence_features + aggregated_features
    )
    
    # Chỉ giữ các cột thực sự tồn tại trong DataFrame
    feature_cols_final = [col for col in all_possible_features if col in df.columns]
    
    # Tạo feature matrix
    X = df[feature_cols_final].fillna(0)
    
    print(f"✅ Preprocessing completed:")
    print(f"   - Total features selected: {len(feature_cols_final)}")
    print(f"   - Shape: {X.shape}")
    
    return df, X, encoders
