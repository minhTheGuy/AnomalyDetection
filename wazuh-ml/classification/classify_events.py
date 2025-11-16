"""
Module phân loại sự kiện bảo mật sử dụng trained classification models
"""
import pandas as pd
import numpy as np
from core.config import CSV_PATH, CLASSIFIER_MODEL_PATH
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from classification.classification import get_classification_features, extract_attack_type
from utils.common import safe_load_joblib, safe_load_csv, print_header


def _load_classifier_bundle(classifier_path=CLASSIFIER_MODEL_PATH):
    """Helper: Load classifier bundle"""
    bundle = safe_load_joblib(classifier_path)
    if bundle is None:
        print(f"  Classification model not found at {classifier_path}")
        print("   Please run train_classifier.py first to train the models.")
        return None
    
    attack_classifier = bundle.get("attack_classifier")
    attack_encoder = bundle.get("attack_encoder")
    category_classifier = bundle.get("category_classifier")
    category_encoder = bundle.get("category_encoder")
    feature_names = bundle.get("feature_names", [])
    feature_selector = bundle.get("feature_selector")
    selected_feature_names = bundle.get("selected_feature_names", feature_names)
    
    if attack_classifier is None and category_classifier is None:
        print("  No classifiers found in model bundle")
        return None
    
    return {
        'bundle': bundle,
        'attack_classifier': attack_classifier,
        'attack_encoder': attack_encoder,
        'category_classifier': category_classifier,
        'category_encoder': category_encoder,
        'feature_names': feature_names,
        'feature_selector': feature_selector,
        'selected_feature_names': selected_feature_names
    }


def _prepare_features_for_classification(df, feature_names, feature_selector=None, selected_feature_names=None):
    """Helper: Prepare features cho classification từ raw DataFrame"""
    # Feature engineering
    df = engineer_all_features(df)
    
    # Preprocessing
    df, X, _ = preprocess_dataframe(df)
    
    # Align features
    X_classify = _align_features(X, feature_names, feature_selector, selected_feature_names)
    
    return df, X_classify


def _align_features(X, feature_names, feature_selector=None, selected_feature_names=None):
    """Helper: Align features với model (từ preprocessed X)"""
    if feature_selector is not None and selected_feature_names:
        from training.feature_selection import apply_feature_selection
        return apply_feature_selection(X, feature_selector, selected_feature_names)
    else:
        X_classify = X.copy()
        for col in feature_names:
            if col not in X_classify.columns:
                X_classify[col] = 0
        return X_classify[feature_names]


def _classify_attack_type(df, X, classifier, encoder):
    """Helper: Classify attack types"""
    predictions = classifier.predict(X.values)
    probas = classifier.predict_proba(X.values)
    
    df['predicted_attack_type'] = encoder.inverse_transform(predictions)
    df['attack_type_confidence'] = np.max(probas, axis=1)
    
    # Pattern matching fallback
    if 'event_desc' in df.columns:
        pattern_based_types = df['event_desc'].apply(extract_attack_type)
        mask_override = (df['predicted_attack_type'] == 'benign') & (pattern_based_types != 'benign')
        if mask_override.sum() > 0:
            df.loc[mask_override, 'predicted_attack_type'] = pattern_based_types[mask_override]
            df.loc[mask_override, 'attack_type_confidence'] = 0.75
            print(f"  Override {mask_override.sum()} predictions từ 'benign' → attack types (pattern matching)")
    
    # Top 3 predictions
    top3_indices = np.argsort(probas, axis=1)[:, -3:][:, ::-1]
    df['attack_type_top3'] = [
        [(encoder.classes_[idx], probas[i, idx]) for idx in top3_indices[i]]
        for i in range(len(df))
    ]
    
    return df


def _classify_event_category(df, X, classifier, encoder):
    """Helper: Classify event categories"""
    predictions = classifier.predict(X.values)
    probas = classifier.predict_proba(X.values)
    
    df['predicted_event_category'] = encoder.inverse_transform(predictions)
    df['event_category_confidence'] = np.max(probas, axis=1)
    
    # Top 3 predictions
    top3_indices = np.argsort(probas, axis=1)[:, -3:][:, ::-1]
    df['event_category_top3'] = [
        [(encoder.classes_[idx], probas[i, idx]) for idx in top3_indices[i]]
        for i in range(len(df))
    ]
    
    return df


def _print_classification_results(df, attack_classifier, category_classifier):
    """Helper: Print classification results"""
    print_header("KẾT QUẢ PHÂN LOẠI", width=70)
    
    if attack_classifier:
        attack_dist = df['predicted_attack_type'].value_counts()
        attack_types = {k: v for k, v in attack_dist.items() if k not in ['benign', 'unknown']}
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
    
    # Low confidence warnings
    if attack_classifier:
        low_conf = df[df['attack_type_confidence'] < 0.5]
        if len(low_conf) > 0:
            print(f"\nLow confidence attack type predictions ({len(low_conf)} events):")
            display_cols = ['timestamp', 'event_desc', 'predicted_attack_type', 'attack_type_confidence']
            display_cols = [c for c in display_cols if c in low_conf.columns]
            print(low_conf[display_cols].head(10).to_string(index=False))
    
    print()


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
    classifier_data = _load_classifier_bundle(classifier_path)
    if classifier_data is None:
        return None
    
    attack_classifier = classifier_data['attack_classifier']
    attack_encoder = classifier_data['attack_encoder']
    category_classifier = classifier_data['category_classifier']
    category_encoder = classifier_data['category_encoder']
    feature_names = classifier_data['feature_names']
    feature_selector = classifier_data['feature_selector']
    selected_feature_names = classifier_data['selected_feature_names']
    
    print(f"    Model trained with {len(feature_names)} features")
    if attack_classifier:
        print(f"    Attack type classifier: {len(attack_encoder.classes_)} classes")
    if category_classifier:
        print(f"    Event category classifier: {len(category_encoder.classes_)} classes")
    
    # Load data
    if logs is not None:
        print(f"\nĐang xử lý {len(logs)} log từ input...")
        df = pd.DataFrame(logs)
    else:
        print(f"\nĐang đọc dữ liệu từ: {CSV_PATH}")
        df = safe_load_csv(CSV_PATH)
        if df is None or len(df) == 0:
            print("Error: Could not load data")
            return None
    
    print(f"    Loaded {len(df)} records")
    
    # Prepare features
    print("\nPreparing features for classification...")
    df, X_classify = _prepare_features_for_classification(
        df, feature_names, feature_selector, selected_feature_names
    )
    print(f"    Final feature matrix: {X_classify.shape}")
    
    # Classification
    print("\nClassifying events...")
    
    if attack_classifier:
        print("   Classifying attack types...")
        df = _classify_attack_type(df, X_classify, attack_classifier, attack_encoder)
    
    if category_classifier:
        print("   Classifying event categories...")
        df = _classify_event_category(df, X_classify, category_classifier, category_encoder)
    
    # Print results
    _print_classification_results(df, attack_classifier, category_classifier)
    
    return df
