"""
Phát hiện anomalies và phân loại attack types và event categories
"""

import pandas as pd
import numpy as np
from core.config import (
    CSV_PATH,
    MODEL_PATH,
    TARGET_ANOMALY_RATE,
    MIN_ANOMALY_RATE,
    MAX_ANOMALY_RATE,
    MODEL_TYPE,
)
from utils.common import print_header, print_section, safe_load_joblib, safe_load_csv
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from detection.anomaly_tuning import (
    AnomalyFilter,
    analyze_anomaly_distribution,
    compute_dynamic_threshold,
    apply_threshold_to_labels,
)


def _predict_ensemble(models, scaler, X, voting_threshold=2):
    """
    Predict với voting mechanism (không dùng class)
    
    Returns:
        predictions, votes, anomaly_votes, scores
    """
    X_scaled = scaler.transform(X)
    
    # Dự đoán từng model
    votes = {}
    votes['iforest'] = models['iforest'].predict(X_scaled)
    votes['lof'] = models['lof'].predict(X_scaled)
    votes['svm'] = models['svm'].predict(X_scaled)
    
    # Đếm số votes cho anomaly (-1)
    vote_matrix = np.array([votes['iforest'], votes['lof'], votes['svm']])
    anomaly_votes = (vote_matrix == -1).sum(axis=0)
    
    # Final decision based on voting threshold
    predictions = np.where(
        anomaly_votes >= voting_threshold,
        -1,  # Anomaly
        1    # Normal
    )
    
    # Tính anomaly scores
    scores = []
    scores.append(models['iforest'].decision_function(X_scaled))
    scores.append(models['lof'].score_samples(X_scaled))
    scores.append(models['svm'].decision_function(X_scaled))
    avg_score = np.mean(scores, axis=0)
    
    return predictions, votes, anomaly_votes, avg_score


def _get_model_agreement(anomaly_votes):
    """Phân tích mức độ đồng thuận giữa các models"""
    agreement_stats = {
        'unanimous_anomaly': (anomaly_votes == 3).sum(),
        'majority_anomaly': (anomaly_votes >= 2).sum(),
        'split_decision': (anomaly_votes == 1).sum(),
        'unanimous_normal': (anomaly_votes == 0).sum()
    }
    return agreement_stats


def _apply_model_predictions(df, X, bundle, model_type, models, detector, scaler, voting_threshold):
    if model_type == "ensemble":
        predictions, votes, anomaly_votes, scores = _predict_ensemble(models, scaler, X, voting_threshold)
        df = df.assign(
            anomaly_label=predictions,
            anomaly_score=scores,
            anomaly_votes=anomaly_votes,
            iforest_vote=votes["iforest"],
            lof_vote=votes["lof"],
            svm_vote=votes["svm"],
        )
        return df, _get_model_agreement(anomaly_votes)

    if model_type == "single":
        X_infer = scaler.transform(X) if scaler is not None else X
        df["anomaly_label"] = detector.predict(X_infer)
        df["anomaly_score"] = detector.decision_function(X_infer)
        return df, None

    if model_type == "autoencoder":
        if detector is None or scaler is None:
            raise RuntimeError("Autoencoder bundle missing required components")
        X_scaled = scaler.transform(X)
        reconstruction = detector.predict(X_scaled)
        errors = np.mean((reconstruction - X_scaled) ** 2, axis=1)
        threshold = bundle.get("autoencoder_threshold") or float(np.quantile(errors, 0.95))
        df["reconstruction_error"] = errors
        df["anomaly_score"] = -errors
        df["anomaly_label"] = np.where(errors >= threshold, -1, 1)
        return df, None

    raise RuntimeError(f"Unsupported model type: {model_type}")


def _load_model_and_prepare_data(logs, feature_names):
    """Helper: Load model và prepare data"""
    bundle = safe_load_joblib(MODEL_PATH)
    if bundle is None:
        print("Error: Could not load model")
        return None, None, None, None, None, None, None, None, None
    
    model_type = bundle.get("model_type", MODEL_TYPE or "single")
    
    if model_type == "ensemble":
        print("Ensemble model detected (IF + LOF + SVM)")
        models = bundle["models"]
        scaler = bundle["scaler"]
        voting_threshold = bundle.get("voting_threshold", 2)
        detector = None
    elif model_type == "single":
        print("Single model detected (Isolation Forest)")
        detector = bundle["model"]
        models = None
        scaler = bundle.get("scaler")
        voting_threshold = None
    elif model_type == "autoencoder":
        print("Autoencoder model detected")
        detector = bundle["autoencoder"]
        models = None
        scaler = bundle.get("scaler")
        voting_threshold = None
    else:
        raise ValueError(f"Unsupported model_type: {model_type}")
    
    encoders = bundle["encoders"]
    feature_names_model = bundle.get("feature_names", feature_names or [])
    
    print(f"Model trained with {len(feature_names_model)} features")
    
    # Load data
    if logs is not None:
        print(f"Đang xử lý {len(logs)} log từ input...")
        df = pd.DataFrame(logs)
    else:
        print("Đang đọc dữ liệu từ:", CSV_PATH)
        df = safe_load_csv(CSV_PATH)
        if df is None or len(df) == 0:
            print("Error: Could not load data")
            return None, None, None, None, None, None, None, None, None
    
    print(f"Loaded {len(df)} records")
    
    # Feature engineering và preprocessing
    print("Applying feature engineering...")
    df = engineer_all_features(df)
    
    print("Preprocessing data...")
    df, X, _ = preprocess_dataframe(df)
    
    # Align features
    print("Aligning features with training data...")
    for col in feature_names_model:
        if col not in X.columns:
            X[col] = 0
            print(f"   Added missing feature: {col}")
    
    X = X[feature_names_model]
    print(f"   Final feature matrix: {X.shape}")
    
    return bundle, models, detector, scaler, encoders, df, X, model_type, voting_threshold


def _apply_dynamic_threshold(df):
    scores = df.get("anomaly_score")
    if scores is None or scores is False:
        return df
    threshold = compute_dynamic_threshold(
        scores.values,
        target_anomaly_rate=TARGET_ANOMALY_RATE,
        min_rate=MIN_ANOMALY_RATE,
        max_rate=MAX_ANOMALY_RATE,
    )
    print(f"Applying dynamic threshold: {threshold:.4f}")
    return apply_threshold_to_labels(df, threshold, label_col="anomaly_label", score_col="anomaly_score")


def _apply_filters(df):
    print("Applying anomaly filters...")
    filter_engine = AnomalyFilter()
    return filter_engine.filter_anomalies(df, remove_whitelisted=True, apply_boost=True)


def _report_detection(df, anomalies_filtered, model_type, agreement):
    anomalies_raw = df[df["anomaly_label"] == -1]
    whitelisted_count = df["is_whitelisted"].sum()

    print_header("KẾT QUẢ PHÁT HIỆN")
    print(f"Tổng số sự kiện:           {len(df)}")
    print(f"Anomalies (raw):           {len(anomalies_raw)} ({len(anomalies_raw)/len(df)*100:.2f}%)")
    print(f"Whitelisted (false +):     {whitelisted_count} ({whitelisted_count/len(df)*100:.2f}%)")
    print(f"Anomalies (filtered):      {len(anomalies_filtered)} ({len(anomalies_filtered)/len(df)*100:.2f}%)")
    print(f"Normal events:             {len(df) - len(anomalies_filtered)}")

    if model_type == "ensemble" and agreement:
        print("\nENSEMBLE AGREEMENT:")
        print(f"Unanimous (3/3): {agreement['unanimous_anomaly']}")
        print(f"Majority (2/3+): {agreement['majority_anomaly']}")
        print(f"Split (1/3):     {agreement['split_decision']}")

    analyze_anomaly_distribution(df)


def _print_anomaly_lists(anomalies, model_type):
    if anomalies.empty:
        print("\nKhông phát hiện sự kiện bất thường mới.")
        return

    print_header("LISTS OF ANOMALIES")
    display_cols = [
        "timestamp",
        "agent",
        "rule_level",
        "proto",
        "src_ip",
        "dst_ip",
        "bytes",
        "event_desc",
        "anomaly_score",
    ]
    if "predicted_attack_type" in anomalies.columns:
        display_cols.append("predicted_attack_type")
    if "predicted_event_category" in anomalies.columns:
        display_cols.append("predicted_event_category")
    if model_type == "ensemble" and "anomaly_votes" in anomalies.columns:
        display_cols.append("anomaly_votes")
    display_cols = [c for c in display_cols if c in anomalies.columns]

    pd.set_option("display.max_colwidth", 60)
    if model_type == "ensemble" and "anomaly_votes" in anomalies.columns:
        unanimous = anomalies[anomalies["anomaly_votes"] == 3]
        if not unanimous.empty:
            print(f"UNANIMOUS ANOMALIES (3/3) - {len(unanimous)} events:\n")
            print(unanimous.sort_values("anomaly_score")[display_cols].to_string(index=False))
            majority = anomalies[anomalies["anomaly_votes"] == 2]
            if not majority.empty:
                print(f"\nMAJORITY ANOMALIES (2/3):\n")
                print(majority.sort_values("anomaly_score")[display_cols].to_string(index=False))
            return
    print(anomalies.sort_values("anomaly_score")[display_cols].to_string(index=False))


def detect(logs=None):
    print("Đang tải mô hình đã huấn luyện...")
    result = _load_model_and_prepare_data(logs, None)
    if result[0] is None:
        return []
    
    bundle, models, detector, scaler, encoders, df, X, model_type, voting_threshold = result
    feature_names = bundle.get("feature_names", [])

    print("Đang dự đoán anomaly...")
    df, agreement = _apply_model_predictions(df, X, bundle, model_type, models, detector, scaler, voting_threshold)
    df = _apply_dynamic_threshold(df)

    df = _apply_filters(df)

    anomalies_filtered = df[df["anomaly_label_filtered"] == -1]
    _report_detection(df, anomalies_filtered, model_type, agreement)
    _print_anomaly_lists(anomalies_filtered, model_type)
    print()

    print()
    return anomalies_filtered.to_dict(orient="records")
