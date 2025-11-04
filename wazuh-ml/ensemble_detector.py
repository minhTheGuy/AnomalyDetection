#!/usr/bin/env python3
# ensemble_detector.py
"""
Ensemble Anomaly Detection cho Wazuh Logs
Sử dụng 3 thuật toán: Isolation Forest, LOF, One-Class SVM với voting mechanism
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import ParameterGrid
from config import CSV_PATH, MODEL_PATH, ANALYZED_CSV_PATH, ANOMALIES_CSV_PATH
from preprocessing import preprocess_dataframe
from feature_engineering import engineer_all_features


class EnsembleAnomalyDetector:
    """
    Ensemble của 3 models:
    - Isolation Forest: Tốt cho high-dimensional data
    - LOF: Tốt cho density-based anomalies
    - One-Class SVM: Tốt cho non-linear boundaries
    """
    
    def __init__(self, voting_threshold=2):
        """
        Args:
            voting_threshold: Số models phải đồng ý (2/3 hoặc 3/3)
                             2 = majority voting (recommended)
                             3 = unanimous voting (strict)
        """
        self.voting_threshold = voting_threshold
        self.models = {}
        self.scaler = StandardScaler()
        self.fitted = False
        
    def fit(self, X, contamination=0.05):
        """
        Train tất cả models
        
        Args:
            X: Feature matrix
            contamination: Tỷ lệ anomaly dự kiến
        """
        print("\n" + "="*70)
        print("🔧 ENSEMBLE TRAINING")
        print("="*70)
        
        # Normalize data (quan trọng cho LOF và SVM)
        print("\nNormalizing data...")
        X_scaled = self.scaler.fit_transform(X)
        print(f"  Shape: {X_scaled.shape}")
        print(f"  Mean: {X_scaled.mean():.4f}, Std: {X_scaled.std():.4f}")
        
        # 1. Isolation Forest
        print("\n[1/3] Training Isolation Forest...")
        self.models['iforest'] = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.models['iforest'].fit(X_scaled)
        pred_if = self.models['iforest'].predict(X_scaled)
        print(f"  ✅ Isolation Forest trained")
        print(f"     Detected anomalies: {(pred_if == -1).sum()} ({(pred_if == -1).sum()/len(pred_if):.2%})")
        
        # 2. Local Outlier Factor
        print("\n[2/3] Training Local Outlier Factor...")
        self.models['lof'] = LocalOutlierFactor(
            contamination=contamination,
            n_neighbors=20,
            novelty=True,  # Cho phép predict trên data mới
            n_jobs=-1
        )
        self.models['lof'].fit(X_scaled)
        pred_lof = self.models['lof'].predict(X_scaled)
        print(f"  ✅ LOF trained")
        print(f"     Detected anomalies: {(pred_lof == -1).sum()} ({(pred_lof == -1).sum()/len(pred_lof):.2%})")
        
        # 3. One-Class SVM
        print("\n[3/3] Training One-Class SVM...")
        self.models['svm'] = OneClassSVM(
            nu=contamination,  # nu ≈ contamination
            kernel='rbf',
            gamma='auto'
        )
        self.models['svm'].fit(X_scaled)
        pred_svm = self.models['svm'].predict(X_scaled)
        print(f"  ✅ One-Class SVM trained")
        print(f"     Detected anomalies: {(pred_svm == -1).sum()} ({(pred_svm == -1).sum()/len(pred_svm):.2%})")
        
        self.fitted = True
        print("\n✅ All models trained successfully!")
        
        return self
    
    def predict(self, X):
        """
        Voting mechanism: Anomaly nếu >= voting_threshold models đồng ý
        
        Returns:
            predictions: Array of -1 (anomaly) or 1 (normal)
            votes: Dict với chi tiết vote từng model
            anomaly_votes: Số models vote anomaly cho mỗi sample
        """
        if not self.fitted:
            raise RuntimeError("Models chưa được train! Gọi fit() trước.")
        
        X_scaled = self.scaler.transform(X)
        
        # Dự đoán từng model
        votes = {}
        votes['iforest'] = self.models['iforest'].predict(X_scaled)
        votes['lof'] = self.models['lof'].predict(X_scaled)
        votes['svm'] = self.models['svm'].predict(X_scaled)
        
        # Đếm số votes cho anomaly (-1)
        vote_matrix = np.array([votes['iforest'], votes['lof'], votes['svm']])
        anomaly_votes = (vote_matrix == -1).sum(axis=0)
        
        # Final decision based on voting threshold
        predictions = np.where(
            anomaly_votes >= self.voting_threshold,
            -1,  # Anomaly
            1    # Normal
        )
        
        return predictions, votes, anomaly_votes
    
    def decision_function(self, X):
        """
        Tính anomaly score trung bình từ 3 models
        Score càng âm = càng bất thường
        """
        X_scaled = self.scaler.transform(X)
        
        scores = []
        
        # Isolation Forest (scores càng âm = càng anomaly)
        scores.append(self.models['iforest'].decision_function(X_scaled))
        
        # LOF (negative_outlier_factor: scores càng âm = càng anomaly)
        scores.append(self.models['lof'].score_samples(X_scaled))
        
        # SVM (scores càng âm = càng anomaly)
        scores.append(self.models['svm'].decision_function(X_scaled))
        
        # Average score
        avg_score = np.mean(scores, axis=0)
        
        return avg_score
    
    def get_model_agreement(self, X):
        """
        Phân tích mức độ đồng thuận giữa các models
        
        Returns:
            Dictionary với thống kê agreement
        """
        _, votes, anomaly_votes = self.predict(X)
        
        agreement_stats = {
            'unanimous_anomaly': (anomaly_votes == 3).sum(),  # Cả 3 đồng ý anomaly
            'majority_anomaly': (anomaly_votes >= 2).sum(),   # 2/3 hoặc 3/3 đồng ý
            'split_decision': (anomaly_votes == 1).sum(),     # Chỉ 1/3 đồng ý
            'unanimous_normal': (anomaly_votes == 0).sum()    # Cả 3 đồng ý normal
        }
        
        return agreement_stats


def hyperparameter_tuning_ensemble(X, contamination_range=[0.03, 0.05, 0.07], voting_thresholds=[2, 3]):
    """
    Tìm best contamination và voting threshold cho ensemble
    
    Args:
        X: Feature matrix
        contamination_range: List of contamination values to test
        voting_thresholds: List of voting thresholds to test
    
    Returns:
        best_detector, best_params, results
    """
    print("\n" + "="*70)
    print("🔍 ENSEMBLE HYPERPARAMETER TUNING")
    print("="*70)
    
    best_score = float('-inf')
    best_params = None
    best_detector = None
    results = []
    
    total_combinations = len(contamination_range) * len(voting_thresholds)
    current = 0
    
    for contamination in contamination_range:
        for voting_threshold in voting_thresholds:
            current += 1
            print(f"\n[{current}/{total_combinations}] Testing contamination={contamination}, voting={voting_threshold}/3")
            
            detector = EnsembleAnomalyDetector(voting_threshold=voting_threshold)
            detector.fit(X, contamination=contamination)
            
            predictions, _, anomaly_votes = detector.predict(X)
            scores = detector.decision_function(X)
            
            # Metrics
            anomaly_count = (predictions == -1).sum()
            anomaly_ratio = anomaly_count / len(predictions)
            score_std = scores.std()
            
            # Agreement analysis
            agreement = detector.get_model_agreement(X)
            
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
                best_detector = detector
                print(f"  ✨ New best score!")
    
    print("\n" + "="*70)
    print("✅ BEST PARAMETERS FOUND")
    print("="*70)
    print(f"Contamination:     {best_params['contamination']}")
    print(f"Voting threshold:  {best_params['voting_threshold']}/3")
    print(f"Combined score:    {best_score:.4f}")
    
    return best_detector, best_params, results


def train_ensemble_model():
    """
    Main training function với ensemble approach
    """
    print("="*70)
    print("ENSEMBLE ANOMALY DETECTION - TRAINING")
    print("="*70)
    
    # Load data
    print("\nLoading data...")
    df = pd.read_csv(CSV_PATH)
    print(f"  ✓ Loaded {len(df)} records from {CSV_PATH}")
    
    # Feature engineering
    print("\nFeature engineering...")
    df = engineer_all_features(df)
    
    # Preprocessing
    print("\nPreprocessing...")
    df, X, encoders = preprocess_dataframe(df)
    print(f"  ✓ Features: {X.shape[1]}")
    print(f"  ✓ Samples: {X.shape[0]}")
    
    # Hyperparameter tuning
    best_detector, best_params, tuning_results = hyperparameter_tuning_ensemble(
        X,
        contamination_range=[0.03, 0.05, 0.07],
        voting_thresholds=[2, 3]
    )
    
    # Final predictions
    print("\n" + "="*70)
    print("FINAL ENSEMBLE PREDICTIONS")
    print("="*70)
    
    predictions, votes, anomaly_votes = best_detector.predict(X)
    scores = best_detector.decision_function(X)
    agreement = best_detector.get_model_agreement(X)
    
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
    df.to_csv(ANALYZED_CSV_PATH, index=False)
    print(f"\nResults saved → {ANALYZED_CSV_PATH}")

    # Save anomalies only
    try:
        anomalies_out = df[df['anomaly_label'] == -1].copy()
        anomalies_out.to_csv(ANOMALIES_CSV_PATH, index=False)
        print(f"Anomalies only saved → {ANOMALIES_CSV_PATH} ({len(anomalies_out)} rows)")
    except Exception as e:
        print(f"⚠️  Failed to save anomalies CSV: {e}")
    
    # Save model bundle
    model_bundle = {
        'detector': best_detector,
        'encoders': encoders,
        'best_params': best_params,
        'tuning_results': tuning_results,
        'feature_names': X.columns.tolist(),
        'training_date': pd.Timestamp.now().isoformat(),
        'model_type': 'ensemble',
        'n_features': X.shape[1],
        'n_samples': X.shape[0]
    }
    
    joblib.dump(model_bundle, MODEL_PATH)
    print(f"Model saved → {MODEL_PATH}")
    
    # Show top anomalies by confidence
    print("\n" + "="*70)
    print("TOP ANOMALIES BY CONFIDENCE")
    print("="*70)
    
    # Unanimous anomalies (3/3 votes)
    unanimous = df[df['anomaly_votes'] == 3].copy()
    if len(unanimous) > 0:
        print(f"\nUNANIMOUS ANOMALIES (3/3 models agree) - {len(unanimous)} events:")
        print("-"*70)
        top_unanimous = unanimous.nsmallest(10, 'anomaly_score')
        
        display_cols = ['timestamp', 'agent', 'rule_level', 'event_desc', 'anomaly_score', 'anomaly_votes']
        display_cols = [c for c in display_cols if c in top_unanimous.columns]
        
        pd.set_option('display.max_colwidth', 50)
        print(top_unanimous[display_cols].to_string(index=False))
    
    # Majority anomalies (2/3 votes)
    majority = df[df['anomaly_votes'] == 2].copy()
    if len(majority) > 0:
        print(f"\nMAJORITY ANOMALIES (2/3 models agree) - {len(majority)} events:")
        print("-"*70)
        top_majority = majority.nsmallest(10, 'anomaly_score')
        
        display_cols = ['timestamp', 'agent', 'rule_level', 'event_desc', 'anomaly_score', 'anomaly_votes']
        display_cols = [c for c in display_cols if c in top_majority.columns]
        
        print(top_majority[display_cols].to_string(index=False))
    
    # Model-specific insights
    print("\n" + "="*70)
    print("🔬 MODEL-SPECIFIC INSIGHTS")
    print("="*70)
    
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
    
    print(f"\nOnly detected by Isolation Forest: {only_if}")
    print(f"Only detected by LOF:               {only_lof}")
    print(f"Only detected by SVM:               {only_svm}")
    
    print("\n" + "="*70)
    print("✅ TRAINING COMPLETED SUCCESSFULLY")
    print("="*70)


if __name__ == "__main__":
    train_ensemble_model()
