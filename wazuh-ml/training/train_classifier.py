"""
Huấn luyện classification model để phân loại event categories và attack types
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import GridSearchCV, cross_val_score

from classification import create_classification_labels
from core.config import CSV_PATH
from training.common import (
    create_classifier_bundle,
    get_cv_folds,
    load_and_prepare_data,
    prepare_train_test_split,
)
from training.feature_selection import (
    get_feature_importance,
    save_feature_selector,
    select_features_rfe,
)
from utils.common import print_header, safe_save_joblib
from training.ann_classifier import train_binary_ann_classifier
from utils.visualization import create_training_visualizations

CLASSIFIER_MODEL_PATH = "data/classifier_model.pkl"
FEATURE_SELECTOR_PATH = "data/feature_selector.pkl"
ANN_MODEL_PATH = "data/ann_classifier.keras"
ENABLE_FEATURE_SELECTION = True  # False để tắt feature selection
ENABLE_VISUALIZATION = True  # False để tắt visualization
ENABLE_BINARY_ANN = True


def _train_classifier_common(
    X: np.ndarray,
    y: pd.Series,
    feature_names: list,
    model_name: str,
) -> tuple:
    """
    Common logic để train classifier (attack type hoặc event category)
    
    Args:
        X: Feature matrix
        y: Labels
        feature_names: Feature names
        model_name: Tên model (cho visualization)
        
    Returns:
        (classifier, label_encoder)
    """
    print_header(f"TRAINING {model_name.upper()}", width=60)

    X_train, X_test, y_train, y_test, label_encoder = prepare_train_test_split(pd.DataFrame(X), y)
    print(f"Classes: {label_encoder.classes_.tolist()}")
    print("\n".join(f"  {cls:20s}: {count}" for cls, count in pd.Series(y).value_counts().items()))
    print(f"\nTraining set={X_train.shape[0]}, Test set={X_test.shape[0]}")

    param_grid = {
        "n_estimators": [100, 200],
        "max_depth": [10, 20, None],
        "min_samples_split": [2, 5],
        "min_samples_leaf": [1, 2],
    }
    cv_folds = get_cv_folds(y_train)
    print(f"\n  Hyperparameter tuning (CV folds: {cv_folds})...")
    # k-fold cross-validation
    grid = GridSearchCV(
        RandomForestClassifier(random_state=42, n_jobs=-1),
        param_grid,
        cv=cv_folds,
        scoring="f1_macro",
        n_jobs=-1,
        verbose=1,
    )
    grid.fit(X_train, y_train)
    classifier = grid.best_estimator_
    print(f"Best params: {grid.best_params_}")

    y_pred = classifier.predict(X_test)
    print_header("EVALUATION RESULTS", width=60)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0,
        )
    )

    cv_folds = get_cv_folds(y_train)
    cv_scores = cross_val_score(
        classifier,
        X_train,
        y_train,
        cv=cv_folds,
        scoring="f1_macro",
    )
    print(
        f"\nCross-validation F1-macro ({cv_folds}-fold): "
        f"{cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})"
    )

    feature_importances = getattr(classifier, "feature_importances_", None)
    if ENABLE_VISUALIZATION:
        try:
            create_training_visualizations(
                y_train=y_train,
                y_test=y_test,
                y_pred_train=classifier.predict(X_train),
                y_pred_test=y_pred,
                y_proba_test=classifier.predict_proba(X_test),
                class_names=label_encoder.classes_,
                feature_names=feature_names,
                feature_importances=feature_importances,
                model_name=model_name,
            )
        except Exception as exc:
            print(f"\nWarning: Could not create visualizations: {exc}")

    return classifier, label_encoder


def train_attack_type_classifier(X, y_attack, feature_names):
    """
    Huấn luyện classifier cho attack types
    
    Args:
        X: Feature matrix
        y_attack: Attack type labels
        feature_names: Tên các features
        
    Returns:
        Trained classifier model và label encoder
    """
    return _train_classifier_common(
        X, y_attack, feature_names,
        "Attack Type Classifier",
    )


def train_event_category_classifier(X, y_category, feature_names):
    """
    Huấn luyện classifier cho event categories
    
    Args:
        X: Feature matrix
        y_category: Event category labels
        feature_names: Tên các features
        
    Returns:
        Trained classifier model và label encoder
    """
    return _train_classifier_common(
        X, y_category, feature_names,
        "Event Category Classifier",
    )


def train_classification_models():
    """
    Huấn luyện cả hai classification models (attack type và event category)
    
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
    if ENABLE_FEATURE_SELECTION and "attack_type" in df.columns:
        print_header("FEATURE SELECTION", width=60)

        get_feature_importance(X, df["attack_type"], top_n=20)
        n_features_to_select = max(30, int(len(feature_names) * 0.5))
        n_features_to_select = min(n_features_to_select, len(feature_names) - 5)

        X_selected, feature_selector, selected_feature_names = select_features_rfe(
            X,
            df["attack_type"],
            n_features=n_features_to_select,
        )

        X = X_selected
        feature_names = selected_feature_names
        save_feature_selector(feature_selector, selected_feature_names, FEATURE_SELECTOR_PATH)
    else:
        print(f"\nFeature selection disabled or no attack_type labels")
    
    binary_classifier_meta = None

    # Train attack type classifier
    if "attack_type" in df.columns:
        attack_classifier, attack_encoder = train_attack_type_classifier(
            X.values,
            df["attack_type"],
            feature_names,
        )
    else:
        print("No attack_type column found, skipping attack type classifier")
        attack_classifier, attack_encoder = None, None
    
    # Train event category classifier
    if "event_category" in df.columns:
        category_classifier, category_encoder = train_event_category_classifier(
            X.values,
            df["event_category"],
            feature_names,
        )
    else:
        print("No event_category column found, skipping event category classifier")
        category_classifier, category_encoder = None, None
    
    # Train binary ANN classifier (normal vs anomaly)
    if ENABLE_BINARY_ANN and "binary_label" in df.columns:
        print_header("BINARY ANN CLASSIFIER", width=60)
        label_mapping = {"normal": 1, "anomaly": 0}
        y_binary = df["binary_label"].map(label_mapping).fillna(0).astype(int).values

        ann_result = train_binary_ann_classifier(
            X.values,
            y_binary,
            feature_names,
            model_output_path=ANN_MODEL_PATH,
        )

        binary_classifier_meta = {
            "model_path": ann_result.model_path,
            "scaler": ann_result.scaler,
            "history": ann_result.history,
            "metrics": ann_result.metrics,
            "feature_names": feature_names,
            "decision_threshold": ann_result.decision_threshold,
        }

        print(
            f"\nBinary ANN accuracy: {binary_classifier_meta['metrics']['accuracy']:.4f}, "
            f"ROC-AUC: {binary_classifier_meta['metrics']['roc_auc']:.4f}"
        )
        print(f"Saved ANN model → {ANN_MODEL_PATH}")
    else:
        print("\nBinary ANN classifier skipped (missing labels or disabled)")

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
        X=X,
        binary_classifier_meta=binary_classifier_meta,
    )
    
    if safe_save_joblib(classifier_bundle, CLASSIFIER_MODEL_PATH):
        print(f"\nSaved classification models → {CLASSIFIER_MODEL_PATH}")
    
    print_header("CLASSIFICATION TRAINING COMPLETED", width=60)
    
    return classifier_bundle



