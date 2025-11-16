"""
Huấn luyện classification model để phân loại event categories và attack types
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score
from core.config import CSV_PATH
from classification.classification import create_classification_labels
from training.common import (
    load_and_prepare_data,
    prepare_train_test_split,
    get_cv_folds,
    create_classifier_bundle
)
from training.feature_selection import (
    select_features_rfe, 
    get_feature_importance,
    save_feature_selector
)
from utils.visualization import create_training_visualizations
from utils.common import print_header, safe_save_joblib

# Path cho classification model
CLASSIFIER_MODEL_PATH = "data/classifier_model.pkl"
FEATURE_SELECTOR_PATH = "data/feature_selector.pkl"
ENABLE_FEATURE_SELECTION = True  # False để tắt feature selection
ENABLE_VISUALIZATION = True  # False để tắt visualization


def _train_classifier_common(
    X: np.ndarray,
    y: pd.Series,
    feature_names: list,
    model_name: str,
    enable_tuning: bool = True
) -> tuple:
    """
    Common logic để train classifier (attack type hoặc event category)
    
    Args:
        X: Feature matrix
        y: Labels
        feature_names: Feature names
        model_name: Tên model (cho visualization)
        enable_tuning: Có tuning không
        
    Returns:
        (classifier, label_encoder)
    """
    print_header(f"TRAINING {model_name.upper()}", width=60)
    
    # Prepare train/test split
    X_train, X_test, y_train, y_test, label_encoder = prepare_train_test_split(
        pd.DataFrame(X), y
    )
    
    print(f"Classes: {label_encoder.classes_}")
    print(f"Class distribution:")
    class_counts = pd.Series(y).value_counts()
    for cls, count in class_counts.items():
        print(f"  {cls:20s}: {count:4d}")
    
    print(f"\nTraining set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Hyperparameter tuning
    if enable_tuning:
        param_grid = {
            'n_estimators': [100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [1, 2]
        }
        
        cv_folds = get_cv_folds(y_train)
        print(f"\n  Hyperparameter tuning (CV folds: {cv_folds})...")
        
        base_classifier = RandomForestClassifier(random_state=42, n_jobs=-1)
        grid_search = GridSearchCV(
            base_classifier, param_grid, cv=cv_folds, 
            scoring='f1_macro', n_jobs=-1, verbose=1
        )
        grid_search.fit(X_train, y_train)
        best_classifier = grid_search.best_estimator_
        print(f"\nBest parameters: {grid_search.best_params_}")
    else:
        best_classifier = RandomForestClassifier(random_state=42, n_jobs=-1)
        best_classifier.fit(X_train, y_train)
    
    # Evaluate
    y_pred = best_classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print_header("EVALUATION RESULTS", width=60)
    print(f"Accuracy: {accuracy:.4f}")
    print(f"\nClassification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    ))
    
    # Cross-validation
    cv_folds_final = get_cv_folds(y_train)
    cv_scores = cross_val_score(
        best_classifier, X_train, y_train, 
        cv=cv_folds_final, scoring='f1_macro'
    )
    print(f"\nCross-validation F1-macro ({cv_folds_final}-fold): "
          f"{cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Feature importances
    feature_importances = (best_classifier.feature_importances_ 
                          if hasattr(best_classifier, 'feature_importances_') else None)
    
    # Visualizations
    if ENABLE_VISUALIZATION:
        try:
            y_proba_test = best_classifier.predict_proba(X_test)
            create_training_visualizations(
                y_train=y_train,
                y_test=y_test,
                y_pred_train=best_classifier.predict(X_train),
                y_pred_test=y_pred,
                y_proba_test=y_proba_test,
                class_names=label_encoder.classes_,
                feature_names=feature_names,
                feature_importances=feature_importances,
                model_name=model_name
            )
        except Exception as e:
            print(f"\nWarning: Could not create visualizations: {e}")
    
    return best_classifier, label_encoder


def train_attack_type_classifier(X, y_attack, feature_names, enable_tuning=True):
    """
    Huấn luyện classifier cho attack types
    
    Args:
        X: Feature matrix
        y_attack: Attack type labels
        feature_names: Tên các features
        enable_tuning: Có tuning không
        
    Returns:
        Trained classifier model và label encoder
    """
    return _train_classifier_common(
        X, y_attack, feature_names, 
        "Attack Type Classifier", 
        enable_tuning
    )


def train_event_category_classifier(X, y_category, feature_names, enable_tuning=True):
    """
    Huấn luyện classifier cho event categories
    
    Args:
        X: Feature matrix
        y_category: Event category labels
        feature_names: Tên các features
        enable_tuning: Có tuning không
        
    Returns:
        Trained classifier model và label encoder
    """
    return _train_classifier_common(
        X, y_category, feature_names,
        "Event Category Classifier",
        enable_tuning
    )


def train_classification_models(enable_tuning=True):
    """
    Huấn luyện cả hai classification models (attack type và event category)
    
    Args:
        enable_tuning: True để bật hyperparameter tuning
    """
    print_header("CLASSIFICATION MODEL TRAINING", width=60)
    
    # Load và prepare data
    print("Reading data from CSV...")
    df, X, encoders = load_and_prepare_data(CSV_PATH, engineer_features=True)
    print(f"  Loaded {len(df)} records")
    
    # Tạo classification labels
    print("\nCreating classification labels...")
    df = create_classification_labels(df)
    
    # Re-preprocess sau khi có labels
    from data_processing.preprocessing import preprocess_dataframe
    df, X, encoders = preprocess_dataframe(df)
    
    # Lấy feature names
    feature_names = list(X.columns)
    print(f"  Using {len(feature_names)} features")
    
    # Feature Selection (optional)
    feature_selector = None
    selected_feature_names = feature_names
    if ENABLE_FEATURE_SELECTION and 'attack_type' in df.columns:
        print_header("FEATURE SELECTION", width=60)
        
        # Hiển thị feature importance trước
        importance_df = get_feature_importance(X, df['attack_type'], top_n=20)
        
        # Chọn features với RFE
        # Tự động chọn số features tối ưu (khoảng 30-70% số features ban đầu)
        n_features_to_select = max(30, int(len(feature_names) * 0.5))
        n_features_to_select = min(n_features_to_select, len(feature_names) - 5)
        
        X_selected, feature_selector, selected_feature_names = select_features_rfe(
            X, 
            df['attack_type'],
            n_features=n_features_to_select
        )
        
        # Cập nhật X và feature_names
        X = X_selected
        feature_names = selected_feature_names
        
        # Lưu feature selector
        save_feature_selector(feature_selector, selected_feature_names, FEATURE_SELECTOR_PATH)
    else:
        print(f"\nFeature selection disabled or no attack_type labels")
    
    # Train attack type classifier
    if 'attack_type' in df.columns:
        attack_classifier, attack_encoder = train_attack_type_classifier(
            X.values, df['attack_type'], feature_names, enable_tuning
        )
    else:
        print("No attack_type column found, skipping attack type classifier")
        attack_classifier, attack_encoder = None, None
    
    # Train event category classifier
    if 'event_category' in df.columns:
        category_classifier, category_encoder = train_event_category_classifier(
            X.values, df['event_category'], feature_names, enable_tuning
        )
    else:
        print("No event_category column found, skipping event category classifier")
        category_classifier, category_encoder = None, None
    
    # Save models
    classifier_bundle = create_classifier_bundle(
        attack_classifier=attack_classifier,
        attack_encoder=attack_encoder,
        category_classifier=category_classifier,
        category_encoder=category_encoder,
        encoders=encoders,
        feature_names=feature_names,
        feature_selector=feature_selector,
        selected_feature_names=selected_feature_names,
        X=X
    )
    
    if safe_save_joblib(classifier_bundle, CLASSIFIER_MODEL_PATH):
        print(f"\nSaved classification models → {CLASSIFIER_MODEL_PATH}")
    
    print_header("CLASSIFICATION TRAINING COMPLETED", width=60)
    
    return classifier_bundle



