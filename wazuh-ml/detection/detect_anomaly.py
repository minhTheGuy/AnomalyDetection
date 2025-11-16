"""
Phát hiện anomalies
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from core.config import CSV_PATH, MODEL_PATH, CLASSIFIER_MODEL_PATH
from core.config import DYNAMIC_THRESHOLD_ENABLE, TARGET_ANOMALY_RATE, MIN_ANOMALY_RATE, MAX_ANOMALY_RATE, MODEL_TYPE, ENABLE_CLASSIFICATION
from core.config import ENABLE_ACTIONS, AUTO_EXECUTE_ACTIONS, ACTIONS_CSV_PATH, ACTION_RESULTS_CSV_PATH
from utils.push_alert import send_alert
from utils.common import print_header, print_section, safe_load_joblib, safe_load_csv
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from detection.anomaly_tuning import AnomalyFilter, analyze_anomaly_distribution, compute_dynamic_threshold, apply_threshold_to_labels
from detection.ensemble_detector import EnsembleAnomalyDetector


def _load_model_and_prepare_data(logs, feature_names):
    """Helper: Load model và prepare data"""
    bundle = safe_load_joblib(MODEL_PATH)
    if bundle is None:
        print("Error: Could not load model")
        return None, None, None, None, None, None
    
    model_type = bundle.get("model_type", MODEL_TYPE or "single")
    
    if model_type == "ensemble":
        print("Ensemble model detected (IF + LOF + SVM)")
        detector = bundle["detector"]
        voting_threshold = bundle.get("voting_threshold", 2)
        print(f"Voting threshold: {voting_threshold}/3")
        is_ensemble = True
        scaler = None
    else:
        print("Single model detected (Isolation Forest)")
        detector = bundle["model"]
        is_ensemble = False
        scaler = bundle.get("scaler")
    
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
            return None, None, None, None, None, None
    
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
    
    return bundle, detector, scaler, encoders, df, X, is_ensemble


def _run_classification(df, X, feature_names):
    """Helper: Chạy classification trên events"""
    if not ENABLE_CLASSIFICATION:
        return df
    
    try:
        print("\nRunning classification on events...")
        classifier_bundle = safe_load_joblib(CLASSIFIER_MODEL_PATH)
        if classifier_bundle is None:
            print(f"Classification model not found at {CLASSIFIER_MODEL_PATH}")
            return df
        
        attack_classifier = classifier_bundle.get("attack_classifier")
        attack_encoder = classifier_bundle.get("attack_encoder")
        category_classifier = classifier_bundle.get("category_classifier")
        category_encoder = classifier_bundle.get("category_encoder")
        classifier_feature_names = classifier_bundle.get("feature_names", feature_names)
        feature_selector = classifier_bundle.get("feature_selector")
        selected_feature_names = classifier_bundle.get("selected_feature_names", classifier_feature_names)
        
        # Prepare features for classification
        if feature_selector is not None and selected_feature_names:
            from training.feature_selection import apply_feature_selection
            X_classify = apply_feature_selection(X, feature_selector, selected_feature_names)
        else:
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
            
            # Pattern matching fallback
            from classification.classification import extract_attack_type
            if 'event_desc' in df.columns:
                pattern_based_types = df['event_desc'].apply(extract_attack_type)
                mask_override = (df['predicted_attack_type'] == 'benign') & (pattern_based_types != 'benign')
                if mask_override.sum() > 0:
                    df.loc[mask_override, 'predicted_attack_type'] = pattern_based_types[mask_override]
                    df.loc[mask_override, 'attack_type_confidence'] = 0.75
                    print(f"  Override {mask_override.sum()} predictions từ 'benign' → attack types (dùng pattern matching)")
        
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
    
    return df


def detect(logs=None):
    print("Đang tải mô hình đã huấn luyện...")
    result = _load_model_and_prepare_data(logs, None)
    if result[0] is None:
        return []
    
    bundle, detector, scaler, encoders, df, X, is_ensemble = result
    feature_names = bundle.get("feature_names", [])

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
    df = _run_classification(df, X, feature_names)

    # Apply filtering để giảm false positives
    print("Applying anomaly filters...")
    filter_engine = AnomalyFilter()
    df = filter_engine.filter_anomalies(df, remove_whitelisted=True, apply_boost=True)

    anomalies_raw = df[df["anomaly_label"] == -1]
    anomalies_filtered = df[df["anomaly_label_filtered"] == -1]
    whitelisted_count = df['is_whitelisted'].sum()
    
    print_header("KẾT QUẢ PHÁT HIỆN")
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
        print_header("LISTS OF ANOMALIES")
        
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
            print_header("ANOMALY CLASSIFICATION SUMMARY")
            
            attack_dist = anomalies['predicted_attack_type'].value_counts()
            
            # Tách riêng attack types và non-attack events
            attack_types = {k: v for k, v in attack_dist.items() if k != 'benign' and k != 'unknown'}
            non_attack = {k: v for k, v in attack_dist.items() if k in ['benign', 'unknown']}
            
            # Tính tổng
            total_attack_anomalies = sum(attack_types.values())
            total_benign_anomalies = sum(non_attack.values())
            
            print(f"\nTỔNG QUAN:")
            print(f"  Total Anomalies:        {len(anomalies)}")
            print(f"  Attack Anomalies:     {total_attack_anomalies} ({total_attack_anomalies/len(anomalies)*100:.1f}%)")
            print(f"  ℹBenign Anomalies:     {total_benign_anomalies} ({total_benign_anomalies/len(anomalies)*100:.1f}%)")
            
            if attack_types:
                print_header("ATTACK ANOMALIES DETECTED (Cần xử lý ngay)")
                for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                    confidence_avg = anomalies[anomalies['predicted_attack_type'] == attack_type]['attack_type_confidence'].mean() if 'attack_type_confidence' in anomalies.columns else None
                    conf_str = f" (confidence: {confidence_avg:.2f})" if confidence_avg else ""
                    print(f"  {attack_type:25s}: {count:4d} anomalies{conf_str}")
                
                # Hiển thị top attack events
                print(f"\n  Top Attack Events:")
                attack_anomalies = anomalies[anomalies['predicted_attack_type'].isin(attack_types.keys())]
                if 'event_desc' in attack_anomalies.columns:
                    top_attack_events = attack_anomalies['event_desc'].value_counts().head(5)
                    for event, count in top_attack_events.items():
                        event_short = str(event)[:65] if len(str(event)) > 65 else str(event)
                        print(f"    • {event_short:65s}: {count:3d}")
            
            if non_attack:
                print_header("BENIGN ANOMALIES (Bất thường nhưng không phải tấn công)")
                for event_type, count in non_attack.items():
                    label = "Normal traffic (benign)" if event_type == 'benign' else "Unknown type"
                    print(f"  {label:25s}: {count:4d} anomalies")
                
                # Hiển thị top benign events
                print(f"\n  Top Benign Events:")
                benign_anomalies = anomalies[anomalies['predicted_attack_type'].isin(non_attack.keys())]
                if 'event_desc' in benign_anomalies.columns:
                    top_benign_events = benign_anomalies['event_desc'].value_counts().head(5)
                    for event, count in top_benign_events.items():
                        event_short = str(event)[:65] if len(str(event)) > 65 else str(event)
                        print(f"    • {event_short:65s}: {count:3d}")
            
            if 'predicted_event_category' in anomalies.columns:
                print_header("EVENT CATEGORIES IN ANOMALIES")
                category_dist = anomalies['predicted_event_category'].value_counts()
                for category, count in sorted(category_dist.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {category:25s}: {count:4d} anomalies")
    
    # Action generation và execution
    if ENABLE_ACTIONS and len(anomalies_filtered) > 0:
        try:
            print_header("ACTION GENERATION & EXECUTION")
            from actions.action_manager import ActionManager
            from core.config import (
                ENABLE_AUTO_BLOCK, ENABLE_TELEGRAM, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
                MIN_SEVERITY_FOR_BLOCK, MIN_SEVERITY_FOR_NOTIFY
            )
            
            action_config = {
                'enable_auto_block': ENABLE_AUTO_BLOCK,
                'enable_telegram': ENABLE_TELEGRAM,
                'telegram_bot_token': TELEGRAM_BOT_TOKEN,
                'telegram_chat_id': TELEGRAM_CHAT_ID,
                'min_severity_for_block': MIN_SEVERITY_FOR_BLOCK,
                'min_severity_for_notify': MIN_SEVERITY_FOR_NOTIFY,
                'auto_execute': AUTO_EXECUTE_ACTIONS,
            }
            
            action_manager = ActionManager(action_config)
            result = action_manager.process_anomalies(anomalies_filtered, execute=AUTO_EXECUTE_ACTIONS)
            
            # Save actions
            if len(result['actions']) > 0:
                action_manager.save_actions(result['actions'], ACTIONS_CSV_PATH)
            
            # Save results nếu đã execute
            if len(result['results']) > 0:
                action_manager.save_results(result['results'], ACTION_RESULTS_CSV_PATH)
            
            # Print summary
            summary = result['summary']
            print(f"\nAction Summary:")
            print(f"  Total anomalies: {summary['total_anomalies']}")
            print(f"  Total actions generated: {summary['total_actions']}")
            if summary['executed']:
                print(f"  Actions executed: {summary['success_count']} success, {summary['fail_count']} failed")
            
        except Exception as e:
            print(f"\n   Action generation failed: {e}")
            import traceback
            traceback.print_exc()
    
    print()

    return anomalies_filtered.to_dict(orient="records")

if __name__ == "__main__":
    detect()
