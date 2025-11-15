"""
Module phân loại sự kiện bảo mật sử dụng trained classification models
"""

import pandas as pd
import numpy as np
import joblib
from core.config import CSV_PATH
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from classification.classification import get_classification_features

CLASSIFIER_MODEL_PATH = "data/classifier_model.pkl"


def classify(logs=None, classifier_path=CLASSIFIER_MODEL_PATH):
    """
    Phân loại sự kiện bảo mật thành attack types và event categories
    
    Args:
        logs: List of log dictionaries (optional, nếu None sẽ đọc từ CSV)
        classifier_path: Path đến trained classifier model
        
    Returns:
        DataFrame với classification results
    """
    print("Đang tải classification model...")
    try:
        bundle = joblib.load(classifier_path)
    except FileNotFoundError:
        print(f"  Classification model not found at {classifier_path}")
        print("   Please run train_classifier.py first to train the models.")
        return None
    
    attack_classifier = bundle.get("attack_classifier")
    attack_encoder = bundle.get("attack_encoder")
    category_classifier = bundle.get("category_classifier")
    category_encoder = bundle.get("category_encoder")
    encoders = bundle.get("encoders", {})
    feature_names = bundle.get("feature_names", [])
    
    if attack_classifier is None and category_classifier is None:
        print("  No classifiers found in model bundle")
        return None
    
    print(f"    Model trained with {len(feature_names)} features")
    if attack_classifier:
        print(f"    Attack type classifier: {len(attack_encoder.classes_)} classes")
    if category_classifier:
        print(f"    Event category classifier: {len(category_encoder.classes_)} classes")
    
    # Đọc dữ liệu
    if logs is not None:
        print(f"\nĐang xử lý {len(logs)} log từ input...")
        df = pd.DataFrame(logs)
    else:
        print(f"\nĐang đọc dữ liệu từ: {CSV_PATH}")
        df = pd.read_csv(CSV_PATH)
    
    print(f"    Loaded {len(df)} records")
    
    # Feature engineering
    print("\nApplying feature engineering...")
    df = engineer_all_features(df)
    
    # Preprocessing
    print("Preprocessing data...")
    df, X, _ = preprocess_dataframe(df)
    
    # Đảm bảo có đủ features
    print("Aligning features with training data...")
    for col in feature_names:
        if col not in X.columns:
            X[col] = 0
            print(f"   Added missing feature: {col}")
    
    # Chỉ giữ features đã train (đúng thứ tự)
    X = X[feature_names]
    print(f"    Final feature matrix: {X.shape}")
    
    # Classification
    print("\nClassifying events...")
    
    results = {}
    
    # Attack type classification
    if attack_classifier:
        print("   Classifying attack types...")
        attack_predictions = attack_classifier.predict(X.values)
        attack_probas = attack_classifier.predict_proba(X.values)
        
        df['predicted_attack_type'] = attack_encoder.inverse_transform(attack_predictions)
        
        # Lấy confidence (probability) cho prediction
        df['attack_type_confidence'] = np.max(attack_probas, axis=1)
        
        # Lấy top 3 predictions với probabilities
        top3_indices = np.argsort(attack_probas, axis=1)[:, -3:][:, ::-1]
        df['attack_type_top3'] = [
            [
                (attack_encoder.classes_[idx], attack_probas[i, idx])
                for idx in top3_indices[i]
            ]
            for i in range(len(df))
        ]
        
        results['attack_type'] = {
            'predictions': df['predicted_attack_type'].tolist(),
            'confidences': df['attack_type_confidence'].tolist()
        }
    
    # Event category classification
    if category_classifier:
        print("   Classifying event categories...")
        category_predictions = category_classifier.predict(X.values)
        category_probas = category_classifier.predict_proba(X.values)
        
        df['predicted_event_category'] = category_encoder.inverse_transform(category_predictions)
        
        # Lấy confidence
        df['event_category_confidence'] = np.max(category_probas, axis=1)
        
        # Lấy top 3 predictions
        top3_indices = np.argsort(category_probas, axis=1)[:, -3:][:, ::-1]
        df['event_category_top3'] = [
            [
                (category_encoder.classes_[idx], category_probas[i, idx])
                for idx in top3_indices[i]
            ]
            for i in range(len(df))
        ]
        
        results['event_category'] = {
            'predictions': df['predicted_event_category'].tolist(),
            'confidences': df['event_category_confidence'].tolist()
        }
    
    # Hiển thị kết quả
    print(f"\n{'='*70}")
    print(f"KẾT QUẢ PHÂN LOẠI")
    print(f"{'='*70}")
    
    if attack_classifier:
        attack_dist = df['predicted_attack_type'].value_counts()
        
        # Tách riêng attack types và non-attack events
        attack_types = {k: v for k, v in attack_dist.items() if k != 'benign' and k != 'unknown'}
        non_attack = {k: v for k, v in attack_dist.items() if k in ['benign', 'unknown']}
        
        if attack_types:
            print(f"\nATTACK TYPES DETECTED:")
            for attack_type, count in attack_types.items():
                avg_conf = df[df['predicted_attack_type'] == attack_type]['attack_type_confidence'].mean()
                print(f"  {attack_type:20s}: {count:4d} events (avg confidence: {avg_conf:.2%})")
        
        if non_attack:
            print(f"\nNON-ATTACK EVENTS (Normal/Unknown):")
            for event_type, count in non_attack.items():
                avg_conf = df[df['predicted_attack_type'] == event_type]['attack_type_confidence'].mean()
                label = "Normal traffic (benign)" if event_type == 'benign' else "Unknown type"
                print(f"  {label:20s}: {count:4d} events (avg confidence: {avg_conf:.2%})")
    
    if category_classifier:
        print(f"\nEVENT CATEGORIES:")
        category_dist = df['predicted_event_category'].value_counts()
        for category, count in category_dist.items():
            avg_conf = df[df['predicted_event_category'] == category]['event_category_confidence'].mean()
            print(f"  {category:20s}: {count:4d} events (avg confidence: {avg_conf:.2%})")
    
    # Hiển thị top events với low confidence (cần review)
    if attack_classifier:
        low_conf_attacks = df[df['attack_type_confidence'] < 0.5]
        if len(low_conf_attacks) > 0:
            print(f"\nLow confidence attack type predictions ({len(low_conf_attacks)} events):")
            display_cols = ['timestamp', 'event_desc', 'predicted_attack_type', 'attack_type_confidence']
            display_cols = [c for c in display_cols if c in low_conf_attacks.columns]
            print(low_conf_attacks[display_cols].head(10).to_string(index=False))
    
    print(f"\n{'='*70}\n")
    
    return df


if __name__ == "__main__":
    classify()

