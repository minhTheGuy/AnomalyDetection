# detect_anomaly.py
import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from core.config import CSV_PATH, MODEL_PATH, CLASSIFIER_MODEL_PATH
from core.config import DYNAMIC_THRESHOLD_ENABLE, TARGET_ANOMALY_RATE, MIN_ANOMALY_RATE, MAX_ANOMALY_RATE, MODEL_TYPE, ENABLE_CLASSIFICATION
from utils.push_alert import send_alert
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from detection.anomaly_tuning import AnomalyFilter, analyze_anomaly_distribution, compute_dynamic_threshold, apply_threshold_to_labels
from detection.ensemble_detector import EnsembleAnomalyDetector

# from push_alert import send_alert

def detect(logs=None):
    print("Đang tải mô hình đã huấn luyện...")
    bundle = joblib.load(MODEL_PATH)
    
    # Check model type
    model_type = bundle.get("model_type", MODEL_TYPE or "single")
    
    if model_type == "ensemble":
        print("Ensemble model detected (IF + LOF + SVM)")
        detector = bundle["detector"]
        voting_threshold = bundle.get("voting_threshold", 2)
        print(f"Voting threshold: {voting_threshold}/3")
        is_ensemble = True
    else:
        print("Single model detected (Isolation Forest)")
        detector = bundle["model"]
        is_ensemble = False
        scaler = bundle.get("scaler")
    
    encoders = bundle["encoders"]
    feature_names = bundle.get("feature_names", [])
    
    print(f"Model trained with {len(feature_names)} features")

    # Đọc log từ input logs hoặc từ CSV_PATH
    if logs is not None:
        print(f"Đang xử lý {len(logs)} log từ input...")
        df = pd.DataFrame(logs)
    else:
        print("Đang đọc dữ liệu từ:", CSV_PATH)
        df = pd.read_csv(CSV_PATH)
        
    print(f"Loaded {len(df)} records")

    # Feature engineering
    print("Applying feature engineering...")
    df = engineer_all_features(df)

    # Preprocessing
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
        # Apply scaler if provided (single-model normalization)
        X_infer = X
        if not is_ensemble and scaler is not None:
            try:
                X_infer = scaler.transform(X)
                print("Applied saved StandardScaler to features")
            except Exception as e:
                print(f"Failed to apply scaler: {e}")
                X_infer = X
        df["anomaly_label"] = detector.predict(X_infer)
        df["anomaly_score"] = detector.decision_function(X_infer)

    # Nếu bật dynamic threshold, (re)label theo threshold động trước khi filter
    if DYNAMIC_THRESHOLD_ENABLE:
        print("\nApplying dynamic thresholding...")
        # Compute threshold từ toàn bộ scores hiện tại
        scores_for_threshold = df.get('anomaly_score')
        if scores_for_threshold is not None and scores_for_threshold is not False:
            thr = compute_dynamic_threshold(
                scores_for_threshold.values,
                target_anomaly_rate=TARGET_ANOMALY_RATE,
                min_rate=MIN_ANOMALY_RATE,
                max_rate=MAX_ANOMALY_RATE
            )
            print(f"Threshold: {thr:.4f} (target={TARGET_ANOMALY_RATE:.2%}, bounds {MIN_ANOMALY_RATE:.2%}-{MAX_ANOMALY_RATE:.2%})")
            df = apply_threshold_to_labels(df, thr, label_col='anomaly_label', score_col='anomaly_score')

    # Classification (nếu được bật) - chạy TRƯỚC khi filter để có classification cho tất cả events
    if ENABLE_CLASSIFICATION:
        try:
            print("\nRunning classification on events...")
            classifier_bundle = joblib.load(CLASSIFIER_MODEL_PATH)
            
            attack_classifier = classifier_bundle.get("attack_classifier")
            attack_encoder = classifier_bundle.get("attack_encoder")
            category_classifier = classifier_bundle.get("category_classifier")
            category_encoder = classifier_bundle.get("category_encoder")
            classifier_feature_names = classifier_bundle.get("feature_names", feature_names)
            
            # Đảm bảo X có đủ features cho classifier
            X_classify = X.copy()
            for col in classifier_feature_names:
                if col not in X_classify.columns:
                    X_classify[col] = 0
            X_classify = X_classify[classifier_feature_names]
            
            # Attack type classification
            if attack_classifier:
                attack_predictions = attack_classifier.predict(X_classify.values)
                attack_probas = attack_classifier.predict_proba(X_classify.values)
                df['predicted_attack_type'] = attack_encoder.inverse_transform(attack_predictions)
                df['attack_type_confidence'] = np.max(attack_probas, axis=1)
            
            # Event category classification
            if category_classifier:
                category_predictions = category_classifier.predict(X_classify.values)
                category_probas = category_classifier.predict_proba(X_classify.values)
                df['predicted_event_category'] = category_encoder.inverse_transform(category_predictions)
                df['event_category_confidence'] = np.max(category_probas, axis=1)
            
            print("Classification completed")
        except FileNotFoundError:
            print(f"Classification model not found at {CLASSIFIER_MODEL_PATH}")
            print("Run train_classifier.py to enable classification")
        except Exception as e:
            print(f"Classification failed: {e}")

    # Apply filtering để giảm false positives
    print("Applying anomaly filters...")
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
        print(f"\nENSEMBLE AGREEMENT:")
        print(f"Unanimous (3/3):         {agreement['unanimous_anomaly']}")
        print(f"Majority (2/3+):         {agreement['majority_anomaly']}")
        print(f" plit (1/3):             {agreement['split_decision']}")
    
    # Analyze distribution
    analyze_anomaly_distribution(df)

    anomalies = anomalies_filtered
    if len(anomalies) > 0:
        print(f"\n{'='*70}")
        print(f"LISTS OF ANOMALIES")
        print(f"{'='*70}\n")
        
        # Chọn columns để hiển thị
        display_cols = ['timestamp', 'agent', 'rule_level', 'proto', 'src_ip', 'dst_ip', 
                        'bytes', 'event_desc', 'anomaly_score']
        
        # Add classification columns if available
        if 'predicted_attack_type' in anomalies.columns:
            display_cols.append('predicted_attack_type')
        if 'predicted_event_category' in anomalies.columns:
            display_cols.append('predicted_event_category')
        
        # Add ensemble-specific columns if available
        if is_ensemble and 'anomaly_votes' in anomalies.columns:
            display_cols.append('anomaly_votes')
        
        display_cols = [c for c in display_cols if c in anomalies.columns]
        
        pd.set_option('display.max_colwidth', 60)
        
        # Show unanimous anomalies first (if ensemble)
        if is_ensemble and 'anomaly_votes' in anomalies.columns:
            unanimous = anomalies[anomalies['anomaly_votes'] == 3]
            if len(unanimous) > 0:
                print(f"UNANIMOUS ANOMALIES (3/3 models agree) - {len(unanimous)} events:\n")
                top_unanimous = unanimous.sort_values("anomaly_score", ascending=True)
                print(top_unanimous[display_cols].to_string(index=False))
                
                if len(anomalies) > len(unanimous):
                    print(f"\nMAJORITY ANOMALIES (2/3 models agree):\n")
                    majority = anomalies[anomalies['anomaly_votes'] == 2]
                    if len(majority) > 0:
                        top_majority = majority.sort_values("anomaly_score", ascending=True)
                        print(top_majority[display_cols].to_string(index=False))
            else:
                # No unanimous, show top by score
                top_anomalies = anomalies.sort_values("anomaly_score", ascending=True)
                print(top_anomalies[display_cols].to_string(index=False))
        else:
            # Single model - show top by score
            top_anomalies = anomalies.sort_values("anomaly_score", ascending=True)
            print(top_anomalies[display_cols].to_string(index=False))

        # gửi cảnh báo ngược vào Wazuh Dashboard
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
        print("\nKhông phát hiện sự kiện bất thường mới.")
    
    # Hiển thị classification summary cho anomalies
    if ENABLE_CLASSIFICATION and len(anomalies) > 0:
        if 'predicted_attack_type' in anomalies.columns:
            print(f"\n{'='*70}")
            print(f"ANOMALY CLASSIFICATION SUMMARY")
            print(f"{'='*70}")
            
            attack_dist = anomalies['predicted_attack_type'].value_counts()
            
            # Tách riêng attack types và non-attack events
            attack_types = {k: v for k, v in attack_dist.items() if k != 'benign' and k != 'unknown'}
            non_attack = {k: v for k, v in attack_dist.items() if k in ['benign', 'unknown']}
            
            if attack_types:
                print(f"\nAttack Types Detected:")
                for attack_type, count in attack_types.items():
                    print(f"  {attack_type:20s}: {count:4d} anomalies")
            
            if non_attack:
                print(f"\nℹNon-Attack Events (Anomalous but not attacks):")
                for event_type, count in non_attack.items():
                    label = "Normal traffic (benign)" if event_type == 'benign' else "Unknown type"
                    print(f"  {label:20s}: {count:4d} anomalies")
            
            if 'predicted_event_category' in anomalies.columns:
                print(f"\nEvent Categories in Anomalies:")
                category_dist = anomalies['predicted_event_category'].value_counts()
                for category, count in category_dist.items():
                    print(f"  {category:20s}: {count:4d} anomalies")
            print(f"{'='*70}")
    
    print(f"\n{'='*70}\n")

    return anomalies_filtered.to_dict(orient="records")

if __name__ == "__main__":
    detect()
