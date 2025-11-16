import pandas as pd
from sklearn.preprocessing import LabelEncoder

def preprocess_dataframe(df: pd.DataFrame):
    """
    Làm sạch dữ liệu log, encode các cột dạng text, và chọn các feature cho ML.
    Hỗ trợ cả features cơ bản và features từ feature_engineering.
    """
    df = df.copy()
    
    # Loại bỏ dòng không có event_desc hoặc rule_level
    df = df.dropna(subset=["event_desc"])

    # Ép kiểu các cột số (numeric features)
    numeric_cols = [
        "src_port", "dst_port", "bytes", "length", "rule_level",
        "bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient",
        "syscheck_size", "alert_severity", "agent_ip"
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Chuẩn hoá các cột text
    text_cols = [
        "agent", "proto", "event_desc", "decoder", "location",
        "syscheck_event", "syscheck_path", "alert_signature", "alert_category",
        "event_type", "app_proto", "data_file", "data_title"
    ]
    for col in text_cols:
        if col in df.columns:
            df[col] = df[col].astype(str).fillna("unknown").str.strip().str.lower()
        else:
            # Nếu column không tồn tại, tạo với giá trị mặc định (chỉ cho các fields cơ bản)
            if col in ["agent", "proto", "event_desc"]:
                df[col] = "unknown"

    # Encode từng cột text thành số
    encoders = {}
    for col in text_cols:
        if col in df.columns:
            enc = LabelEncoder()
            df[f"{col}_code"] = enc.fit_transform(df[col])
            encoders[col] = enc
    
    # Encode categorical columns từ feature engineering
    categorical_feature_cols = ['port_range', 'severity_category', 'packet_size_category']
    for col in categorical_feature_cols:
        if col in df.columns:
            enc = LabelEncoder()
            df[f"{col}_code"] = enc.fit_transform(df[col].astype(str))
            encoders[col] = enc

    # Chọn các feature đầu vào cho ML model
    # Basic features
    feature_cols = [
        "src_port", "dst_port", "bytes", "length", "rule_level",
        "agent_code", "proto_code", "event_desc_code"
    ]
    
    # Optional encoded text features
    optional_text_features = ["decoder_code", "alert_category_code", "event_type_code", "app_proto_code"]
    for feat in optional_text_features:
        if feat in df.columns:
            feature_cols.append(feat)
    
    # Time features
    time_features = [
        "hour", "day_of_week", "minute", 
        "is_night", "is_weekend", "is_business_hours"
    ]
    
    # Network features
    network_features = [
        "is_well_known_port", "is_registered_port", "is_dynamic_port",
        "is_ephemeral_src", "log_bytes", "log_length",
        "port_range_code", "packet_size_category_code",
        "is_internal_src", "is_internal_dst", "is_internal_communication",
        "bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient",
        "total_packets", "packet_ratio"
    ]
    
    # Event features
    event_features = [
        "event_desc_length", "event_word_count", "danger_keyword_count",
        "is_auth_event", "is_fim_event",
        "severity_category_code", "is_critical", "is_high", "is_medium",
        # Syscheck features
        "is_syscheck_event", "is_file_added", "is_file_modified", "is_file_deleted",
        "syscheck_path_length", "is_system_path", "is_user_path",
        # Alert features
        "is_high_severity_alert", "has_alert_category", "alert_signature_length", "has_alert_signature",
        # Event type features
        "is_alert_event", "is_flow_event", "has_app_proto", "is_http_proto", "is_ssl_proto"
    ]
    
    # Sequence features
    sequence_features = [
        "time_delta", "events_in_window", "avg_event_frequency", 
        "is_burst", "event_velocity"
    ]
    
    # Aggregated features
    aggregated_features = [
        "agent_event_count", "is_rare_agent",
        "src_ip_count", "is_rare_src_ip",
        "agent_avg_rule_level", "rule_level_deviation"
    ]
    
    # Thêm tất cả features
    all_possible_features = (
        feature_cols + time_features + network_features + 
        event_features + sequence_features + aggregated_features
    )
    
    # Chỉ giữ các cột thực sự tồn tại trong DataFrame
    feature_cols_final = [col for col in all_possible_features if col in df.columns]
    
    # Tạo feature matrix
    X = df[feature_cols_final].fillna(0)
    
    print(f"Preprocessing completed:")
    print(f"   - Total features selected: {len(feature_cols_final)}")
    print(f"   - Shape: {X.shape}")
    
    return df, X, encoders
