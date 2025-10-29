# detect_anomaly.py
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from config import CSV_PATH, MODEL_PATH
from push_alert import send_alert
from feature_engineering import engineer_all_features
from preprocessing import preprocess_dataframe
from anomaly_tuning import AnomalyFilter, analyze_anomaly_distribution
from ensemble_detector import EnsembleAnomalyDetector  # Import ensemble class

def detect():
    print("Đang tải mô hình đã huấn luyện...")
    bundle = joblib.load(MODEL_PATH)
    
    # Check model type
    model_type = bundle.get("model_type", "single")
    
    if model_type == "ensemble":
        print("   ✅ Ensemble model detected (IF + LOF + SVM)")
        detector = bundle["detector"]
        voting_threshold = bundle.get("voting_threshold", 2)
        print(f"   Voting threshold: {voting_threshold}/3")
        is_ensemble = True
    else:
        print("   ✅ Single model detected (Isolation Forest)")
        detector = bundle["model"]
        is_ensemble = False
    
    encoders = bundle["encoders"]
    feature_names = bundle.get("feature_names", [])
    
    print(f"   Model trained with {len(feature_names)} features")

    # Đọc log mới nhất
    print("Đang đọc dữ liệu từ:", CSV_PATH)
    df = pd.read_csv(CSV_PATH)
    print(f"   Loaded {len(df)} records")

    # Feature engineering (giống như khi train)
    print("Applying feature engineering...")
    df = engineer_all_features(df)

    # Preprocessing (giống như khi train)
    print("Preprocessing data...")
    df, X, _ = preprocess_dataframe(df)
    
    # Đảm bảo có đủ features như khi train
    print("Aligning features with training data...")
    for col in feature_names:
        if col not in X.columns:
            X[col] = 0
            print(f"   Added missing feature: {col}")
    
    # Chỉ giữ features đã train (đúng thứ tự)
    X = X[feature_names]
    print(f"   Final feature matrix: {X.shape}")

    # Dự đoán bất thường
    print("Đang dự đoán anomaly...")
    
    if is_ensemble:
        # Ensemble prediction
        predictions, votes, anomaly_votes = detector.predict(X)
        scores = detector.decision_function(X)
        
        df["anomaly_label"] = predictions
        df["anomaly_score"] = scores
        df["anomaly_votes"] = anomaly_votes
        df["iforest_vote"] = votes['iforest']
        df["lof_vote"] = votes['lof']
        df["svm_vote"] = votes['svm']
        
        # Get agreement stats
        agreement = detector.get_model_agreement(X)
    else:
        # Single model prediction
        df["anomaly_label"] = detector.predict(X)
        df["anomaly_score"] = detector.decision_function(X)

    # Apply filtering để giảm false positives
    print("🔧 Applying anomaly filters...")
    filter_engine = AnomalyFilter()
    df = filter_engine.filter_anomalies(df, remove_whitelisted=True, apply_boost=True)

    anomalies_raw = df[df["anomaly_label"] == -1]
    anomalies_filtered = df[df["anomaly_label_filtered"] == -1]
    whitelisted_count = df['is_whitelisted'].sum()
    
    print(f"\n{'='*70}")
    print(f"KẾT QUẢ PHÁT HIỆN")
    print(f"{'='*70}")
    print(f"Tổng số sự kiện:           {len(df)}")
    print(f"Anomalies (raw):           {len(anomalies_raw)} ({len(anomalies_raw)/len(df)*100:.2f}%)")
    print(f"Whitelisted (false +):     {whitelisted_count} ({whitelisted_count/len(df)*100:.2f}%)")
    print(f"Anomalies (filtered):      {len(anomalies_filtered)} ({len(anomalies_filtered)/len(df)*100:.2f}%)")
    print(f"Normal events:             {len(df) - len(anomalies_filtered)}")
    
    # Show ensemble-specific stats
    if is_ensemble:
        print(f"\n🤝 ENSEMBLE AGREEMENT:")
        print(f"  Unanimous (3/3):         {agreement['unanimous_anomaly']}")
        print(f"  Majority (2/3+):         {agreement['majority_anomaly']}")
        print(f"  Split (1/3):             {agreement['split_decision']}")
    
    # Analyze distribution
    analyze_anomaly_distribution(df)

    anomalies = anomalies_filtered
    if len(anomalies) > 0:
        print(f"\n{'='*70}")
        print(f"TOP 15 SỰ KIỆN BẤT THƯỜNG")
        print(f"{'='*70}\n")
        
        # Chọn columns để hiển thị
        display_cols = ['timestamp', 'agent', 'rule_level', 'proto', 'src_ip', 'dst_ip', 
                        'bytes', 'event_desc', 'anomaly_score']
        
        # Add ensemble-specific columns if available
        if is_ensemble and 'anomaly_votes' in anomalies.columns:
            display_cols.append('anomaly_votes')
        
        display_cols = [c for c in display_cols if c in anomalies.columns]
        
        pd.set_option('display.max_colwidth', 60)
        
        # Show unanimous anomalies first (if ensemble)
        if is_ensemble and 'anomaly_votes' in anomalies.columns:
            unanimous = anomalies[anomalies['anomaly_votes'] == 3]
            if len(unanimous) > 0:
                print(f"🚨 UNANIMOUS ANOMALIES (3/3 models agree) - {len(unanimous)} events:\n")
                top_unanimous = unanimous.nsmallest(10, "anomaly_score")
                print(top_unanimous[display_cols].to_string(index=False))
                
                if len(anomalies) > len(unanimous):
                    print(f"\nMAJORITY ANOMALIES (2/3 models agree):\n")
                    majority = anomalies[anomalies['anomaly_votes'] == 2]
                    if len(majority) > 0:
                        top_majority = majority.nsmallest(5, "anomaly_score")
                        print(top_majority[display_cols].to_string(index=False))
            else:
                # No unanimous, show top by score
                top_anomalies = anomalies.nsmallest(15, "anomaly_score")
                print(top_anomalies[display_cols].to_string(index=False))
        else:
            # Single model - show top by score
            top_anomalies = anomalies.nsmallest(15, "anomaly_score")
            print(top_anomalies[display_cols].to_string(index=False))

        # # Uncomment để gửi cảnh báo ngược vào Wazuh Dashboard
        # print("\n Đang gửi cảnh báo lên Wazuh...")
        # for _, row in anomalies.iterrows():
        #     msg = (
        #         f"[ML Anomaly] {row.get('agent', 'unknown')} - "
        #         f"{row.get('event_desc', 'N/A')[:60]} "
        #         f"(level={row.get('rule_level', 0)}, "
        #         f"score={row.get('anomaly_score', 0):.3f})"
        #     )
        #     try:
        #         send_alert(msg)
        #     except Exception as e:
        #         print(f"    Failed to send alert: {e}")
        # print("Đã gửi tất cả cảnh báo ML lên Wazuh Dashboard!")
    else:
        print("\n✅ Không phát hiện sự kiện bất thường mới.")
    
    print(f"\n{'='*70}\n")

if __name__ == "__main__":
    detect()
