"""
Common utilities cho training modules
"""

import pandas as pd
import numpy as np
from typing import Tuple, Optional
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from core.config import CSV_PATH
from utils.common import safe_load_csv


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

