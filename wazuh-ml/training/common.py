"""
Common utilities cho training modules
"""

import os
import pandas as pd
import numpy as np
from typing import Tuple, Optional, Dict, List
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from core.config import CSV_PATH, MODEL_PATH
from utils.common import safe_load_csv, safe_load_joblib, safe_save_joblib


def load_and_prepare_data(
    csv_path: str = CSV_PATH,
    engineer_features: bool = True
) -> Tuple[pd.DataFrame, pd.DataFrame, dict]:
    """
    Load data và prepare cho training
    
    Args:
        csv_path: Path đến CSV file
        engineer_features: Có apply feature engineering không
        
    Returns:
        Tuple of (df, X, encoders)
    """
    df = safe_load_csv(csv_path)
    if df is None or len(df) == 0:
        raise ValueError(f"Could not load data from {csv_path}")
    
    if engineer_features:
        from data_processing.feature_engineering import engineer_all_features
        df = engineer_all_features(df)
    
    from data_processing.preprocessing import preprocess_dataframe
    df, X, encoders = preprocess_dataframe(df)
    return df, X, encoders


def prepare_train_test_split(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = 0.2,
    random_state: int = 42
) -> Tuple:
    """
    Prepare train/test split với stratify nếu có thể
    
    Args:
        X: Feature matrix
        y: Labels
        test_size: Test size ratio
        random_state: Random seed
        
    Returns:
        X_train, X_test, y_train, y_test, label_encoder
    """
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Check if can use stratify
    class_counts = pd.Series(y).value_counts()
    min_class_count = class_counts.min()
    use_stratify = min_class_count >= 2
    
    split_kwargs = {
        'test_size': test_size,
        'random_state': random_state
    }
    if use_stratify:
        split_kwargs['stratify'] = y_encoded
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, **split_kwargs
    )
    
    return X_train, X_test, y_train, y_test, label_encoder


def get_cv_folds(y: np.ndarray, max_folds: int = 5) -> int:
    """
    Tính số CV folds phù hợp dựa trên class distribution
    
    Args:
        y: Encoded labels
        max_folds: Số folds tối đa
        
    Returns:
        Số folds phù hợp (tối thiểu 2)
    """
    unique, counts = np.unique(y, return_counts=True)
    min_class_samples = counts.min()
    cv_folds = min(max_folds, min_class_samples)
    return max(2, cv_folds)  # Minimum 2 folds


def get_file_age(filepath: str) -> Optional[datetime]:
    """
    Lấy thời gian modified của file
    
    Args:
        filepath: Path đến file
        
    Returns:
        datetime object hoặc None nếu file không tồn tại
    """
    if os.path.exists(filepath):
        timestamp = os.path.getmtime(filepath)
        return datetime.fromtimestamp(timestamp)
    return None


def get_model_info(model_path: str = MODEL_PATH) -> Optional[Dict]:
    """
    Lấy thông tin model hiện tại
    
    Args:
        model_path: Path đến model file
        
    Returns:
        Dictionary với model info hoặc None
    """
    if not os.path.exists(model_path):
        return None
    
    bundle = safe_load_joblib(model_path)
    if bundle is None:
        return None
    
    return {
        'training_date': bundle.get('training_date', 'Unknown'),
        'n_samples': bundle.get('n_samples', 'Unknown'),
        'n_features': bundle.get('n_features', 'Unknown'),
        'best_params': bundle.get('best_params', {}),
        'metrics': bundle.get('metrics', {}),
        'model_type': bundle.get('model_type', 'unknown')
    }


def create_ensemble_bundle(
    models: Dict,
    scaler,
    voting_threshold: int,
    encoders: Dict,
    feature_names: List[str],
    best_params: Dict,
    tuning_results: List = None,
    X: pd.DataFrame = None
) -> Dict:
    """
    Tạo ensemble model bundle
    
    Args:
        models: Dict chứa models (iforest, lof, svm)
        scaler: StandardScaler
        voting_threshold: Voting threshold
        encoders: Encoders dict
        feature_names: List feature names
        best_params: Best parameters dict
        tuning_results: Tuning results (optional)
        X: Feature matrix (optional, để lấy shape)
        
    Returns:
        Model bundle dictionary
    """
    bundle = {
        'models': models,
        'scaler': scaler,
        'voting_threshold': voting_threshold,
        'encoders': encoders,
        'best_params': best_params,
        'feature_names': feature_names,
        'training_date': pd.Timestamp.now().isoformat(),
        'model_type': 'ensemble',
    }
    
    if tuning_results is not None:
        bundle['tuning_results'] = tuning_results
    
    if X is not None:
        bundle['n_features'] = X.shape[1]
        bundle['n_samples'] = X.shape[0]
    
    return bundle


def create_classifier_bundle(
    attack_classifier,
    attack_encoder,
    category_classifier,
    category_encoder,
    encoders: Dict,
    feature_names: List[str],
    feature_selector=None,
    selected_feature_names: List[str] = None,
    X: pd.DataFrame = None
) -> Dict:
    """
    Tạo classifier bundle
    
    Args:
        attack_classifier: Attack type classifier
        attack_encoder: Attack type encoder
        category_classifier: Event category classifier
        category_encoder: Event category encoder
        encoders: Encoders dict
        feature_names: List feature names
        feature_selector: Feature selector (optional)
        selected_feature_names: Selected feature names (optional)
        X: Feature matrix (optional, để lấy shape)
        
    Returns:
        Classifier bundle dictionary
    """
    bundle = {
        "attack_classifier": attack_classifier,
        "attack_encoder": attack_encoder,
        "category_classifier": category_classifier,
        "category_encoder": category_encoder,
        "encoders": encoders,
        "feature_names": feature_names,
        "training_date": pd.Timestamp.now().isoformat(),
    }
    
    if feature_selector is not None:
        bundle["feature_selector"] = feature_selector
        bundle["selected_feature_names"] = selected_feature_names or feature_names
    
    if X is not None:
        bundle["n_features"] = X.shape[1]
        bundle["n_samples"] = X.shape[0]
    
    return bundle


def create_autoencoder_bundle(
    autoencoder,
    scaler,
    threshold: float,
    encoders: Dict,
    feature_names: List[str],
    *,
    X: pd.DataFrame | None = None,
    contamination: float = 0.05,
) -> Dict:
    """
    Tạo bundle cho autoencoder anomaly detector.
    """
    bundle = {
        "model_type": "autoencoder",
        "autoencoder": autoencoder,
        "scaler": scaler,
        "autoencoder_threshold": threshold,
        "encoders": encoders,
        "feature_names": feature_names,
        "training_date": pd.Timestamp.now().isoformat(),
        "contamination": contamination,
    }

    if X is not None:
        bundle["n_features"] = X.shape[1]
        bundle["n_samples"] = X.shape[0]

    return bundle


def _align_features_to_source(
    X_target: pd.DataFrame,
    source_features: List[str],
    feature_mapping: Dict[str, str] = None
) -> pd.DataFrame:
    """
    Align target features với source features
    
    Args:
        X_target: Target feature matrix
        source_features: Source feature names
        feature_mapping: Mapping dict (source_feat -> target_feat)
        
    Returns:
        Aligned feature matrix
    """
    X_aligned = pd.DataFrame(index=X_target.index)
    feature_mapping = feature_mapping or {}
    
    for source_feat in source_features:
        if source_feat in feature_mapping:
            target_feat = feature_mapping[source_feat]
            if target_feat in X_target.columns:
                X_aligned[source_feat] = X_target[target_feat]
            else:
                X_aligned[source_feat] = 0
        elif source_feat in X_target.columns:
            X_aligned[source_feat] = X_target[source_feat]
        else:
            X_aligned[source_feat] = 0
    
    # Fill missing source features
    for source_feat in source_features:
        if source_feat not in X_aligned.columns:
            X_aligned[source_feat] = 0
    
    return X_aligned

