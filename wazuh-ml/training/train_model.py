"""
Train ensemble anomaly detection model (IF + LOF + SVM)
Train 3 models riêng biệt và lưu chúng
"""
import pandas as pd
import numpy as np
import os
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import ParameterGrid
from core.config import CSV_PATH, MODEL_PATH, ANALYZED_CSV_PATH, ANOMALIES_CSV_PATH
from training.common import (
    load_and_prepare_data,
    create_ensemble_bundle
)
from utils.common import print_header, print_section, safe_load_csv, safe_save_joblib, safe_save_csv


def train_models(X, contamination=0.05, voting_threshold=2):
    """
    Train 3 models: Isolation Forest, LOF, One-Class SVM
    
    Args:
        X: Feature matrix
        contamination: Tỷ lệ anomaly dự kiến
        voting_threshold: Số models phải đồng ý (2/3 hoặc 3/3)
    
    Returns:
        models dict, scaler, voting_threshold
    """
    print_header("ENSEMBLE TRAINING")
    
    # Normalize data (quan trọng cho LOF và SVM)
    print("\nNormalizing data...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print(f"  Shape: {X_scaled.shape}")
    print(f"  Mean: {X_scaled.mean():.4f}, Std: {X_scaled.std():.4f}")
    
    models = {}
    
    # 1. Isolation Forest
    print("\n[1/3] Training Isolation Forest...")
    models['iforest'] = IsolationForest(
        contamination=contamination,
        n_estimators=200,
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    models['iforest'].fit(X_scaled)
    pred_if = models['iforest'].predict(X_scaled)
    print(f"  Isolation Forest trained")
    print(f"  Detected anomalies: {(pred_if == -1).sum()} ({(pred_if == -1).sum()/len(pred_if):.2%})")
    
    # 2. Local Outlier Factor
    print("\n[2/3] Training Local Outlier Factor...")
    models['lof'] = LocalOutlierFactor(
        contamination=contamination,
        n_neighbors=20,
        novelty=True,  # Cho phép predict trên data mới
        n_jobs=-1
    )
    models['lof'].fit(X_scaled)
    pred_lof = models['lof'].predict(X_scaled)
    print(f"  LOF trained")
    print(f"  Detected anomalies: {(pred_lof == -1).sum()} ({(pred_lof == -1).sum()/len(pred_lof):.2%})")
    
    # 3. One-Class SVM
    print("\n[3/3] Training One-Class SVM...")
    models['svm'] = OneClassSVM(
        nu=contamination,  # nu ≈ contamination
        kernel='rbf',
        gamma='auto'
    )
    models['svm'].fit(X_scaled)
    pred_svm = models['svm'].predict(X_scaled)
    print(f"  One-Class SVM trained")
    print(f"  Detected anomalies: {(pred_svm == -1).sum()} ({(pred_svm == -1).sum()/len(pred_svm):.2%})")
    
    print("\nAll models trained successfully!")
    
    return models, scaler, voting_threshold


def predict_ensemble(models, scaler, X, voting_threshold=2):
    """
    Predict với voting mechanism
    
    Args:
        models: Dict chứa 3 models (iforest, lof, svm)
        scaler: StandardScaler đã fit
        X: Feature matrix
        voting_threshold: Số models phải đồng ý (2/3 hoặc 3/3)
    
    Returns:
        predictions, votes, anomaly_votes, scores
    """
    X_scaled = scaler.transform(X)
    
    # Dự đoán từng model
    votes = {}
    votes['iforest'] = models['iforest'].predict(X_scaled)
    votes['lof'] = models['lof'].predict(X_scaled)
    votes['svm'] = models['svm'].predict(X_scaled)
    
    # Đếm số votes cho anomaly (-1)
    vote_matrix = np.array([votes['iforest'], votes['lof'], votes['svm']])
    anomaly_votes = (vote_matrix == -1).sum(axis=0)
    
    # Final decision based on voting threshold
    predictions = np.where(
        anomaly_votes >= voting_threshold,
        -1,  # Anomaly
        1    # Normal
    )
    
    # Tính anomaly scores
    scores = []
    scores.append(models['iforest'].decision_function(X_scaled))
    scores.append(models['lof'].score_samples(X_scaled))
    scores.append(models['svm'].decision_function(X_scaled))
    avg_score = np.mean(scores, axis=0)
    
    return predictions, votes, anomaly_votes, avg_score


def get_model_agreement(predictions, votes, anomaly_votes):
    """Phân tích mức độ đồng thuận giữa các models"""
    agreement_stats = {
        'unanimous_anomaly': (anomaly_votes == 3).sum(),
        'majority_anomaly': (anomaly_votes >= 2).sum(),
        'split_decision': (anomaly_votes == 1).sum(),
        'unanimous_normal': (anomaly_votes == 0).sum()
    }
    return agreement_stats


def hyperparameter_tuning_ensemble(X, contamination_range=[0.03, 0.05, 0.07], voting_thresholds=[2, 3]):
    """
    Tìm best contamination và voting threshold cho ensemble
    
    Returns:
        best_models, best_scaler, best_params, results
    """
    print_header("ENSEMBLE HYPERPARAMETER TUNING")
    
    best_score = float('-inf')
    best_params = None
    best_models = None
    best_scaler = None
    results = []
    
    total_combinations = len(contamination_range) * len(voting_thresholds)
    current = 0
    
    for contamination in contamination_range:
        for voting_threshold in voting_thresholds:
            current += 1
            print(f"\n[{current}/{total_combinations}] Testing contamination={contamination}, voting={voting_threshold}/3")
            
            models, scaler, _ = train_models(X, contamination=contamination, voting_threshold=voting_threshold)
            
            predictions, votes, anomaly_votes, scores = predict_ensemble(models, scaler, X, voting_threshold)
            
            # Metrics
            anomaly_count = (predictions == -1).sum()
            anomaly_ratio = anomaly_count / len(predictions)
            score_std = scores.std()
            
            # Agreement analysis
            agreement = get_model_agreement(predictions, votes, anomaly_votes)
            
            # Combined score (ưu tiên high agreement + reasonable ratio)
            combined_score = (
                score_std * 10 +
                agreement['unanimous_anomaly'] * 0.5 +
                agreement['majority_anomaly'] * 0.3 -
                abs(anomaly_ratio - contamination) * 20
            )
            
            print(f"  Anomalies: {anomaly_count} ({anomaly_ratio:.2%})")
            print(f"  Unanimous (3/3): {agreement['unanimous_anomaly']}")
            print(f"  Majority (2/3+): {agreement['majority_anomaly']}")
            print(f"  Combined Score: {combined_score:.4f}")
            
            result = {
                'contamination': contamination,
                'voting_threshold': voting_threshold,
                'score': combined_score,
                'anomaly_count': anomaly_count,
                'anomaly_ratio': anomaly_ratio,
                'agreement': agreement
            }
            results.append(result)
            
            if combined_score > best_score:
                best_score = combined_score
                best_params = {
                    'contamination': contamination,
                    'voting_threshold': voting_threshold
                }
                best_models = models
                best_scaler = scaler
                print(f"  New best score!")
    
    print_header("BEST PARAMETERS FOUND")
    print(f"Contamination:     {best_params['contamination']}")
    print(f"Voting threshold:  {best_params['voting_threshold']}/3")
    print(f"Combined score:    {best_score:.4f}")
    
    return best_models, best_scaler, best_params, results


def train_model_with_tuning(enable_tuning=True):
    """
    Train ensemble model (IF + LOF + SVM) với feature engineering và hyperparameter tuning
    
    Args:
        enable_tuning: True để bật hyperparameter tuning, False để dùng default params
    """
    print_header("ENSEMBLE ANOMALY DETECTION - TRAINING")
    
    # Load và prepare data
    print("\nLoading data...")
    df, X, encoders = load_and_prepare_data(CSV_PATH, engineer_features=True)
    print(f"  ✓ Loaded {len(df)} records")
    print(f"  Features: {X.shape[1]}")
    print(f"  Samples: {X.shape[0]}")
    
    if enable_tuning:
        # Hyperparameter tuning
        best_models, best_scaler, best_params, tuning_results = hyperparameter_tuning_ensemble(
            X,
            contamination_range=[0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10],
            voting_thresholds=[2, 3]
        )
    else:
        # Use default parameters
        print("\nTraining with default parameters...")
        best_params = {
            'contamination': 0.05,
            'voting_threshold': 2
        }
        best_models, best_scaler, _ = train_models(
            X,
            contamination=best_params['contamination'],
            voting_threshold=best_params['voting_threshold']
        )
        tuning_results = []
    
    # Final predictions
    print_header("FINAL ENSEMBLE PREDICTIONS")
    
    predictions, votes, anomaly_votes, scores = predict_ensemble(
        best_models, best_scaler, X, best_params['voting_threshold']
    )
    agreement = get_model_agreement(predictions, votes, anomaly_votes)
    
    # Add results to dataframe
    df['anomaly_label'] = predictions
    df['anomaly_score'] = scores
    df['anomaly_votes'] = anomaly_votes
    df['iforest_vote'] = votes['iforest']
    df['lof_vote'] = votes['lof']
    df['svm_vote'] = votes['svm']
    
    # Statistics
    total_anomalies = (predictions == -1).sum()
    print(f"\nRESULTS:")
    print(f"  Total records:           {len(df)}")
    print(f"  Anomalies detected:      {total_anomalies} ({total_anomalies/len(df):.2%})")
    print(f"  Normal events:           {len(df) - total_anomalies} ({(len(df) - total_anomalies)/len(df):.2%})")
    
    print(f"\nMODEL AGREEMENT:")
    print(f"  Unanimous anomaly (3/3): {agreement['unanimous_anomaly']}")
    print(f"  Majority anomaly (≥2/3): {agreement['majority_anomaly']}")
    print(f"  Split decision (1/3):    {agreement['split_decision']}")
    print(f"  Unanimous normal (0/3):  {agreement['unanimous_normal']}")
    
    # Score distribution
    print(f"\nSCORE DISTRIBUTION:")
    print(f"  Min:    {scores.min():.4f}")
    print(f"  Q1:     {np.percentile(scores, 25):.4f}")
    print(f"  Median: {np.median(scores):.4f}")
    print(f"  Q3:     {np.percentile(scores, 75):.4f}")
    print(f"  Max:    {scores.max():.4f}")
    
    # Save analyzed data
    if safe_save_csv(df, ANALYZED_CSV_PATH):
        print(f"\nResults saved → {ANALYZED_CSV_PATH}")

    # Save anomalies only
    anomalies_out = df[df['anomaly_label'] == -1].copy()
    if safe_save_csv(anomalies_out, ANOMALIES_CSV_PATH):
        print(f"Anomalies only saved → {ANOMALIES_CSV_PATH} ({len(anomalies_out)} rows)")
    
    # Save model bundle
    model_bundle = create_ensemble_bundle(
        models=best_models,
        scaler=best_scaler,
        voting_threshold=best_params['voting_threshold'],
        encoders=encoders,
        feature_names=X.columns.tolist(),
        best_params=best_params,
        tuning_results=tuning_results,
        X=X
    )
    
    # Save ensemble bundle
    if safe_save_joblib(model_bundle, MODEL_PATH):
        print(f"\nEnsemble bundle saved → {MODEL_PATH}")
    
    # Save individual models (IF, LOF, SVM)
    base_dir = os.path.dirname(MODEL_PATH)
    base_name = os.path.basename(MODEL_PATH).replace('.pkl', '')
    
    if_path = os.path.join(base_dir, f'{base_name}_iforest.pkl')
    lof_path = os.path.join(base_dir, f'{base_name}_lof.pkl')
    svm_path = os.path.join(base_dir, f'{base_name}_svm.pkl')
    
    safe_save_joblib(best_models['iforest'], if_path)
    safe_save_joblib(best_models['lof'], lof_path)
    safe_save_joblib(best_models['svm'], svm_path)
    
    print(f"  Individual models saved:")
    print(f"    - IForest: {if_path}")
    print(f"    - LOF:     {lof_path}")
    print(f"    - SVM:     {svm_path}")
    
    # Show top anomalies by confidence
    print_header("TOP ANOMALIES BY CONFIDENCE")
    
    # Unanimous anomalies (3/3 votes)
    unanimous = df[df['anomaly_votes'] == 3].copy()
    if len(unanimous) > 0:
        print(f"\nUNANIMOUS ANOMALIES (3/3 models agree) - {len(unanimous)} events:")
        print_section("")
        top_unanimous = unanimous.nsmallest(10, 'anomaly_score')
        
        display_cols = ['timestamp', 'agent', 'rule_level', 'event_desc', 'anomaly_score', 'anomaly_votes']
        display_cols = [c for c in display_cols if c in top_unanimous.columns]
        
        pd.set_option('display.max_colwidth', 50)
        print(top_unanimous[display_cols].to_string(index=False))
    
    # Majority anomalies (2/3 votes)
    majority = df[df['anomaly_votes'] == 2].copy()
    if len(majority) > 0:
        print(f"\nMAJORITY ANOMALIES (2/3 models agree) - {len(majority)} events:")
        print_section("")
        top_majority = majority.nsmallest(10, 'anomaly_score')
        
        display_cols = ['timestamp', 'agent', 'rule_level', 'event_desc', 'anomaly_score', 'anomaly_votes']
        display_cols = [c for c in display_cols if c in top_majority.columns]
        
        print(top_majority[display_cols].to_string(index=False))
    
    # Model-specific insights
    print_header("MODEL-SPECIFIC INSIGHTS")
    
    anomalies = df[df['anomaly_label'] == -1]
    
    only_if = ((anomalies['iforest_vote'] == -1) & 
               (anomalies['lof_vote'] == 1) & 
               (anomalies['svm_vote'] == 1)).sum()
    
    only_lof = ((anomalies['iforest_vote'] == 1) & 
                (anomalies['lof_vote'] == -1) & 
                (anomalies['svm_vote'] == 1)).sum()
    
    only_svm = ((anomalies['iforest_vote'] == 1) & 
                (anomalies['lof_vote'] == 1) & 
                (anomalies['svm_vote'] == -1)).sum()
    
    print(f"\nOnly detected by Isolation Forest:  {only_if}")
    print(f"Only detected by LOF:               {only_lof}")
    print(f"Only detected by SVM:               {only_svm}")
    
    print_header("TRAINING COMPLETED SUCCESSFULLY")
