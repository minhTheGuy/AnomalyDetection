# train_model.py
import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import ParameterGrid
from sklearn.preprocessing import StandardScaler
from config import CSV_PATH, MODEL_PATH, ANALYZED_CSV_PATH, ANOMALIES_CSV_PATH, MODEL_TYPE, SINGLE_IF_NORMALIZE
from preprocessing import preprocess_dataframe
from feature_engineering import engineer_all_features
from ensemble_detector import train_ensemble_model

def evaluate_model(model, X, df=None):
    """
    Đánh giá model với các metrics
    
    Args:
        model: Trained IsolationForest model
        X: Feature matrix
        df: Optional DataFrame for additional analysis
    
    Returns:
        Dictionary với evaluation metrics
    """
    predictions = model.predict(X)
    scores = model.decision_function(X)
    
    anomaly_count = (predictions == -1).sum()
    anomaly_ratio = anomaly_count / len(predictions)
    
    print(f"\n{'='*60}")
    print(f"MODEL EVALUATION")
    print(f"{'='*60}")
    print(f"Total samples:        {len(predictions)}")
    print(f"Anomalies detected:   {anomaly_count} ({anomaly_ratio:.2%})")
    print(f"Normal samples:       {(predictions == 1).sum()}")
    print(f"Score range:          [{scores.min():.3f}, {scores.max():.3f}]")
    print(f"Mean score:           {scores.mean():.3f}")
    print(f"Std deviation:        {scores.std():.3f}")
    
    # Phân tích anomalies nếu có DataFrame
    if df is not None:
        anomalies_df = df[predictions == -1]
        if len(anomalies_df) > 0:
            print(f"\nAnomaly Statistics:")
            if 'rule_level' in anomalies_df.columns:
                print(f"  Average rule level:   {anomalies_df['rule_level'].mean():.2f}")
            if 'severity_category' in anomalies_df.columns:
                print(f"  Severity distribution:")
                for cat, count in anomalies_df['severity_category'].value_counts().head(3).items():
                    print(f"    {cat}: {count}")
    
    return {
        'anomaly_count': anomaly_count,
        'anomaly_ratio': anomaly_ratio,
        'score_mean': scores.mean(),
        'score_std': scores.std(),
        'score_min': scores.min(),
        'score_max': scores.max()
    }


def hyperparameter_tuning(X, df, param_grid):
    """
    Tìm hyperparameters tốt nhất bằng grid search
    
    Args:
        X: Feature matrix
        df: DataFrame (for additional analysis)
        param_grid: Dictionary với parameter ranges
    
    Returns:
        best_model, best_params, results_list
    """
    print(f"\n{'='*60}")
    print(f"🔍 HYPERPARAMETER TUNING")
    print(f"{'='*60}")
    print(f"Grid size: {len(list(ParameterGrid(param_grid)))} combinations")
    
    best_score = float('-inf')
    best_params = None
    best_model = None
    results = []
    
    for i, params in enumerate(ParameterGrid(param_grid), 1):
        print(f"\n[{i}/{len(list(ParameterGrid(param_grid)))}] Testing: {params}")
        
        try:
            model = IsolationForest(**params, random_state=42)
            model.fit(X)
            
            scores = model.decision_function(X)
            predictions = model.predict(X)
            
            # Metrics
            score_std = scores.std()
            anomaly_ratio = (predictions == -1).sum() / len(predictions)
            
            # Penalty nếu anomaly ratio quá xa contamination
            target_contamination = params['contamination']
            ratio_penalty = abs(anomaly_ratio - target_contamination)
            
            # Combined score (ưu tiên phân tán tốt và tỷ lệ hợp lý)
            combined_score = score_std - (ratio_penalty * 10)
            
            results.append({
                'params': params,
                'combined_score': combined_score,
                'anomaly_ratio': anomaly_ratio,
                'score_std': score_std,
                'score_mean': scores.mean()
            })
            
            print(f"  ➜ Score: {combined_score:.4f} | Anomalies: {anomaly_ratio:.2%} | Std: {score_std:.4f}")
            
            if combined_score > best_score:
                best_score = combined_score
                best_params = params
                best_model = model
                print(f"  New best score!")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
            continue
    
    print(f"\n{'='*60}")
    print(f"✅ BEST PARAMETERS FOUND")
    print(f"{'='*60}")
    for key, value in best_params.items():
        print(f"{key:20s}: {value}")
    print(f"{'Combined score':20s}: {best_score:.4f}")
    
    return best_model, best_params, results


def train_model_with_tuning(enable_tuning=True):
    """
    Train model với feature engineering và hyperparameter tuning
    
    Args:
        enable_tuning: True để bật hyperparameter tuning, False để dùng default params
    """
    # If ensemble is requested by config, delegate to ensemble training
    if MODEL_TYPE == "ensemble":
        return train_ensemble_model()
    print(f"\n{'='*60}")
    print(f"🚀 ANOMALY DETECTION MODEL TRAINING")
    print(f"{'='*60}\n")
    
    # Đọc dữ liệu
    print("📘 Reading data from CSV...")
    df = pd.read_csv(CSV_PATH)
    print(f"  ✓ Loaded {len(df)} records")
    
    # Feature engineering
    print("\n🔧 Applying feature engineering...")
    df = engineer_all_features(df)
    
    # Preprocessing
    print("\n🧹 Preprocessing and encoding...")
    df, X, encoders = preprocess_dataframe(df)
    
    # Optional normalization for single IsolationForest
    scaler = None
    if SINGLE_IF_NORMALIZE:
        print("\n📏 Applying StandardScaler normalization (single-model IF)...")
        scaler = StandardScaler()
        X_for_fit = scaler.fit_transform(X)
    else:
        X_for_fit = X

    if enable_tuning:
        # Hyperparameter grid
        param_grid = {
            'contamination': [0.03, 0.05, 0.07],
            'n_estimators': [100, 200, 300],
            'max_samples': ['auto', 256],
            'max_features': [0.8, 1.0]
        }
        
        # Tuning
        best_model, best_params, tuning_results = hyperparameter_tuning(X_for_fit, df, param_grid)
    else:
        # Use default parameters
        print("\nTraining with default parameters...")
        best_params = {
            'contamination': 0.05,
            'n_estimators': 200,
            'max_samples': 'auto',
            'max_features': 1.0
        }
        best_model = IsolationForest(**best_params, random_state=42)
        best_model.fit(X_for_fit)
        tuning_results = []
    
    # Evaluate best model
    metrics = evaluate_model(best_model, X_for_fit, df)
    
    # Predict on all data
    print(f"\nMaking predictions...")
    df["anomaly_label"] = best_model.predict(X_for_fit)
    df["anomaly_score"] = best_model.decision_function(X_for_fit)
    
    # Save analyzed results
    df.to_csv(ANALYZED_CSV_PATH, index=False)
    print(f"✅ Saved analysis results → {ANALYZED_CSV_PATH}")

    # Save anomalies only
    try:
        anomalies_out = df[df["anomaly_label"] == -1].copy()
        anomalies_out.to_csv(ANOMALIES_CSV_PATH, index=False)
        print(f"✅ Saved anomalies only → {ANOMALIES_CSV_PATH} ({len(anomalies_out)} rows)")
    except Exception as e:
        print(f"⚠️  Failed to save anomalies CSV: {e}")
    
    # Save model bundle
    model_bundle = {
        "model": best_model,
        "encoders": encoders,
        "best_params": best_params,
        "metrics": metrics,
        "tuning_results": tuning_results,
        "feature_names": list(X.columns),
        "training_date": pd.Timestamp.now().isoformat(),
        "n_features": X.shape[1],
        "n_samples": X.shape[0],
        "model_type": "single",
        "scaler": scaler
    }
    
    joblib.dump(model_bundle, MODEL_PATH)
    print(f"✅ Saved trained model → {MODEL_PATH}")
    
    # Display top anomalies
    print(f"\n{'='*60}")
    print(f" TOP 15 ANOMALIES DETECTED")
    print(f"{'='*60}")
    anomalies = df[df["anomaly_label"] == -1].nsmallest(15, "anomaly_score")
    
    if len(anomalies) > 0:
        display_cols = []
        for col in ['timestamp', 'agent', 'rule_level', 'event_desc', 'anomaly_score']:
            if col in anomalies.columns:
                display_cols.append(col)
        
        pd.set_option('display.max_colwidth', 50)
        print(anomalies[display_cols].to_string(index=False))
    else:
        print("No anomalies detected!")
    
    print(f"\n{'='*60}")
    print(f"✅ TRAINING COMPLETED SUCCESSFULLY")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    # Set enable_tuning=False để training nhanh hơn (dùng default params)
    train_model_with_tuning(enable_tuning=True)
