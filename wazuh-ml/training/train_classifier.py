# train_classifier.py
"""
Huấn luyện classification model để phân loại sự kiện bảo mật
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from core.config import CSV_PATH, MODEL_PATH
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from classification.classification import create_classification_labels

# Path cho classification model
CLASSIFIER_MODEL_PATH = "data/classifier_model.pkl"


def train_attack_type_classifier(X, y_attack, feature_names):
    """
    Huấn luyện classifier cho attack types
    
    Args:
        X: Feature matrix
        y_attack: Attack type labels
        feature_names: Tên các features
        
    Returns:
        Trained classifier model
    """
    print(f"\n{'='*60}")
    print(f"🎯 TRAINING ATTACK TYPE CLASSIFIER")
    print(f"{'='*60}")
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_attack)
    
    print(f"Classes: {label_encoder.classes_}")
    print(f"Class distribution:")
    class_counts = pd.Series(y_attack).value_counts()
    for cls, count in class_counts.items():
        print(f"  {cls:20s}: {count:4d}")
    
    # Kiểm tra xem có thể dùng stratify không (mỗi class cần >= 2 samples)
    min_class_count = class_counts.min()
    use_stratify = min_class_count >= 2
    
    if not use_stratify:
        print(f"\n⚠️  Warning: Some classes have < 2 samples (min: {min_class_count})")
        print("   Using non-stratified split")
    
    # Split data
    split_kwargs = {
        'test_size': 0.2,
        'random_state': 42
    }
    if use_stratify:
        split_kwargs['stratify'] = y_encoded
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, **split_kwargs
    )
    
    print(f"\nTraining set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Hyperparameter tuning với GridSearchCV
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }
    
    # Xác định số folds cho CV (tối đa 5, nhưng phải <= số samples của class nhỏ nhất)
    unique, counts = np.unique(y_train, return_counts=True)
    min_class_samples = counts.min()
    cv_folds = min(5, min_class_samples)
    
    if cv_folds < 2:
        print(f"\n⚠️  Warning: Too few samples for cross-validation (min class: {min_class_samples})")
        print("   Using simple train/validation split instead of CV")
        cv_folds = 2  # Minimum for CV
    
    print(f"\n🔍 Hyperparameter tuning (CV folds: {cv_folds})...")
    base_classifier = RandomForestClassifier(random_state=42, n_jobs=-1)
    grid_search = GridSearchCV(
        base_classifier, param_grid, cv=cv_folds, scoring='f1_macro', n_jobs=-1, verbose=1
    )
    grid_search.fit(X_train, y_train)
    
    best_classifier = grid_search.best_estimator_
    print(f"\n✅ Best parameters: {grid_search.best_params_}")
    
    # Evaluate
    y_pred = best_classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"\nClassification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    ))
    
    # Cross-validation score (với số folds phù hợp)
    unique, counts = np.unique(y_encoded, return_counts=True)
    min_class_samples = counts.min()
    cv_folds_final = min(5, min_class_samples)
    if cv_folds_final < 2:
        cv_folds_final = 2
    
    cv_scores = cross_val_score(best_classifier, X, y_encoded, cv=cv_folds_final, scoring='f1_macro')
    print(f"\nCross-validation F1-macro ({cv_folds_final}-fold): {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    return best_classifier, label_encoder


def train_event_category_classifier(X, y_category, feature_names):
    """
    Huấn luyện classifier cho event categories
    
    Args:
        X: Feature matrix
        y_category: Event category labels
        feature_names: Tên các features
        
    Returns:
        Trained classifier model
    """
    print(f"\n{'='*60}")
    print(f"📂 TRAINING EVENT CATEGORY CLASSIFIER")
    print(f"{'='*60}")
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_category)
    
    print(f"Classes: {label_encoder.classes_}")
    print(f"Class distribution:")
    class_counts = pd.Series(y_category).value_counts()
    for cls, count in class_counts.items():
        print(f"  {cls:20s}: {count:4d}")
    
    # Kiểm tra xem có thể dùng stratify không (mỗi class cần >= 2 samples)
    min_class_count = class_counts.min()
    use_stratify = min_class_count >= 2
    
    if not use_stratify:
        print(f"\n⚠️  Warning: Some classes have < 2 samples (min: {min_class_count})")
        print("   Using non-stratified split")
    
    # Split data
    split_kwargs = {
        'test_size': 0.2,
        'random_state': 42
    }
    if use_stratify:
        split_kwargs['stratify'] = y_encoded
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, **split_kwargs
    )
    
    print(f"\nTraining set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Hyperparameter tuning
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }
    
    # Xác định số folds cho CV (tối đa 5, nhưng phải <= số samples của class nhỏ nhất)
    unique, counts = np.unique(y_train, return_counts=True)
    min_class_samples = counts.min()
    cv_folds = min(5, min_class_samples)
    
    if cv_folds < 2:
        print(f"\n⚠️  Warning: Too few samples for cross-validation (min class: {min_class_samples})")
        print("   Using simple train/validation split instead of CV")
        cv_folds = 2  # Minimum for CV
    
    print(f"\n🔍 Hyperparameter tuning (CV folds: {cv_folds})...")
    base_classifier = RandomForestClassifier(random_state=42, n_jobs=-1)
    grid_search = GridSearchCV(
        base_classifier, param_grid, cv=cv_folds, scoring='f1_macro', n_jobs=-1, verbose=1
    )
    grid_search.fit(X_train, y_train)
    
    best_classifier = grid_search.best_estimator_
    print(f"\n✅ Best parameters: {grid_search.best_params_}")
    
    # Evaluate
    y_pred = best_classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"\nClassification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    ))
    
    # Cross-validation score (với số folds phù hợp)
    unique, counts = np.unique(y_encoded, return_counts=True)
    min_class_samples = counts.min()
    cv_folds_final = min(5, min_class_samples)
    if cv_folds_final < 2:
        cv_folds_final = 2
    
    cv_scores = cross_val_score(best_classifier, X, y_encoded, cv=cv_folds_final, scoring='f1_macro')
    print(f"\nCross-validation F1-macro ({cv_folds_final}-fold): {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    return best_classifier, label_encoder


def train_classification_models(enable_tuning=True):
    """
    Huấn luyện cả hai classification models (attack type và event category)
    
    Args:
        enable_tuning: True để bật hyperparameter tuning
    """
    print(f"\n{'='*60}")
    print(f"🚀 CLASSIFICATION MODEL TRAINING")
    print(f"{'='*60}\n")
    
    # Đọc dữ liệu
    print("📘 Reading data from CSV...")
    df = pd.read_csv(CSV_PATH)
    print(f"  ✓ Loaded {len(df)} records")
    
    # Feature engineering
    print("\n🔧 Applying feature engineering...")
    df = engineer_all_features(df)
    
    # Tạo classification labels
    print("\n🏷️  Creating classification labels...")
    df = create_classification_labels(df)
    
    # Preprocessing
    print("\n🧹 Preprocessing and encoding...")
    df, X, encoders = preprocess_dataframe(df)
    
    # Lấy feature names
    feature_names = list(X.columns)
    print(f"  ✓ Using {len(feature_names)} features")
    
    # Train attack type classifier
    if 'attack_type' in df.columns:
        attack_classifier, attack_encoder = train_attack_type_classifier(
            X.values, df['attack_type'], feature_names
        )
    else:
        print("⚠️  No attack_type column found, skipping attack type classifier")
        attack_classifier, attack_encoder = None, None
    
    # Train event category classifier
    if 'event_category' in df.columns:
        category_classifier, category_encoder = train_event_category_classifier(
            X.values, df['event_category'], feature_names
        )
    else:
        print("⚠️  No event_category column found, skipping event category classifier")
        category_classifier, category_encoder = None, None
    
    # Save models
    classifier_bundle = {
        "attack_classifier": attack_classifier,
        "attack_encoder": attack_encoder,
        "category_classifier": category_classifier,
        "category_encoder": category_encoder,
        "encoders": encoders,
        "feature_names": feature_names,
        "training_date": pd.Timestamp.now().isoformat(),
        "n_features": X.shape[1],
        "n_samples": X.shape[0]
    }
    
    joblib.dump(classifier_bundle, CLASSIFIER_MODEL_PATH)
    print(f"\n✅ Saved classification models → {CLASSIFIER_MODEL_PATH}")
    
    print(f"\n{'='*60}")
    print(f"✅ CLASSIFICATION TRAINING COMPLETED")
    print(f"{'='*60}\n")
    
    return classifier_bundle


if __name__ == "__main__":
    train_classification_models(enable_tuning=True)

