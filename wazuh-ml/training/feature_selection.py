"""
Feature Selection Module
Sử dụng RFE (Recursive Feature Elimination) để chọn features quan trọng nhất
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.feature_selection import RFE, RFECV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from typing import List, Optional, Tuple
from utils.common import safe_load_joblib, safe_save_joblib


def select_features_rfe(
    X: pd.DataFrame,
    y: pd.Series,
    n_features: Optional[int] = None,
    estimator=None,
    step: int = 1,
    verbose: int = 0
) -> Tuple[pd.DataFrame, object, List[str]]:
    """
    Chọn features quan trọng nhất sử dụng RFE
    
    Args:
        X: Feature matrix
        y: Target labels
        n_features: Số features muốn chọn (None = auto select với RFECV)
        estimator: Base estimator (default: RandomForestClassifier)
        step: Số features loại bỏ mỗi lần
        verbose: Verbosity level
        
    Returns:
        Tuple of (X_selected, selector, selected_feature_names)
    """
    if estimator is None:
        estimator = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            max_depth=10
        )
    
    feature_names = list(X.columns)
    
    if n_features is None:
        # Sử dụng RFECV để tự động chọn số features tối ưu
        print("Using RFECV to automatically select optimal number of features...")
        
        # Đảm bảo có đủ samples cho CV
        unique, counts = np.unique(y, return_counts=True)
        min_class_samples = counts.min()
        cv_folds = min(5, min_class_samples)
        
        if cv_folds < 2:
            print(f"   Warning: Quá ít samples cho RFECV (min class: {min_class_samples})")
            print("   Sử dụng RFE với n_features = min(50, n_features//2)")
            n_features = min(50, len(feature_names) // 2)
            selector = RFE(estimator, n_features_to_select=n_features, step=step, verbose=verbose)
        else:
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            selector = RFECV(
                estimator,
                step=step,
                cv=cv,
                scoring='f1_macro',
                n_jobs=-1,
                verbose=verbose,
                min_features_to_select=10  # Tối thiểu 10 features
            )
    else:
        print(f"Using RFE to select top {n_features} features...")
        selector = RFE(estimator, n_features_to_select=n_features, step=step, verbose=verbose)
    
    # Fit selector
    print(f"   Training on {len(X)} samples with {len(feature_names)} features...")
    selector.fit(X.values, y)
    
    # Get selected features
    selected_mask = selector.support_
    selected_feature_names = [name for name, selected in zip(feature_names, selected_mask) if selected]
    
    if hasattr(selector, 'n_features_'):
        print(f"Selected {selector.n_features_} features out of {len(feature_names)}")
    else:
        print(f"Selected {len(selected_feature_names)} features out of {len(feature_names)}")
    
    # Transform X
    X_selected = X[selected_feature_names]
    
    # Print feature rankings
    if hasattr(selector, 'ranking_'):
        print(f"\nFeature Rankings (top 20):")
        rankings = pd.DataFrame({
            'feature': feature_names,
            'rank': selector.ranking_,
            'selected': selected_mask
        }).sort_values('rank')
        
        for idx, row in rankings.head(20).iterrows():
            status = "Selected" if row['selected'] else "Not Selected"
            print(f"  {status} Rank {row['rank']:3d}: {row['feature']}")
    
    return X_selected, selector, selected_feature_names


def get_feature_importance(
    X: pd.DataFrame,
    y: pd.Series,
    estimator=None,
    top_n: int = 20
) -> pd.DataFrame:
    """
    Lấy feature importance từ Random Forest
    
    Args:
        X: Feature matrix
        y: Target labels
        estimator: Base estimator (default: RandomForestClassifier)
        top_n: Số features top để hiển thị
        
    Returns:
        DataFrame với feature importance
    """
    if estimator is None:
        estimator = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
    
    print(f"Computing feature importance...")
    estimator.fit(X.values, y)
    
    importance_df = pd.DataFrame({
        'feature': X.columns,
        'importance': estimator.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\nTop {top_n} Most Important Features:")
    for idx, row in importance_df.head(top_n).iterrows():
        print(f"  {row['feature']:40s}: {row['importance']:.4f}")
    
    return importance_df


def save_feature_selector(selector: object, feature_names: List[str], path: str):
    """Lưu feature selector để dùng sau"""
    bundle = {
        'selector': selector,
        'selected_features': feature_names
    }
    if safe_save_joblib(bundle, path):
        print(f"Saved feature selector to {path}")


def load_feature_selector(path: str) -> Tuple[object, List[str]]:
    """Load feature selector"""
    bundle = safe_load_joblib(path)
    if bundle is None:
        raise ValueError(f"Could not load feature selector from {path}")
    return bundle['selector'], bundle['selected_features']


def apply_feature_selection(
    X: pd.DataFrame,
    selector: object,
    selected_features: List[str]
) -> pd.DataFrame:
    """
    Áp dụng feature selection đã train vào data mới
    
    Args:
        X: Feature matrix mới
        selector: Trained selector
        selected_features: List features đã chọn
        
    Returns:
        X với chỉ các features đã chọn
    """
    # Đảm bảo có đủ features
    missing_features = set(selected_features) - set(X.columns)
    if missing_features:
        print(f"Warning: Missing {len(missing_features)} features, filling with 0")
        for feat in missing_features:
            X[feat] = 0
    
    # Chỉ giữ selected features
    X_selected = X[selected_features].copy()
    
    return X_selected

