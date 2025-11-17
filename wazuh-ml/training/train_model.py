"""
Train ensemble anomaly detection model (IF + LOF + One-Class SVM)
Train 3 models riêng biệt và lưu chúng
"""
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from core.config import (
    ANALYZED_CSV_PATH,
    ANOMALIES_CSV_PATH,
    CSV_PATH,
    MODEL_PATH,
)
from training.common import load_and_prepare_data, create_ensemble_bundle
from utils.common import print_header, print_section, safe_save_csv, safe_save_joblib

MODEL_BUILDERS = {
    "iforest": lambda c: IsolationForest(
        contamination=c, n_estimators=200, max_samples="auto", random_state=42, n_jobs=-1
    ),
    "lof": lambda c: LocalOutlierFactor(
        contamination=c, n_neighbors=20, novelty=True, n_jobs=-1
    ),
    "svm": lambda c: OneClassSVM(nu=c, kernel="rbf", gamma="auto"),
}

MODEL_LABELS = {
    "iforest": "Isolation Forest",
    "lof": "Local Outlier Factor",
    "svm": "One-Class SVM",
}


def _train_single_model(name, X_scaled, contamination):
    print(f"\nTraining {MODEL_LABELS[name]}...")
    model = MODEL_BUILDERS[name](contamination)
    model.fit(X_scaled)
    preds = model.predict(X_scaled)
    print(
        f"  Done. Detected {(preds == -1).sum()} anomalies "
        f"({(preds == -1).mean():.2%}) on training data."
    )
    return model


def train_models(X, contamination=0.05, voting_threshold=2):
    print_header("ENSEMBLE TRAINING")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print(
        f"\nNormalized data shape={X_scaled.shape}, "
        f"mean={X_scaled.mean():.4f}, std={X_scaled.std():.4f}"
    )
    models = {name: _train_single_model(name, X_scaled, contamination) for name in MODEL_BUILDERS}
    print("\nAll base models trained successfully!")
    return models, scaler, voting_threshold


def predict_ensemble(models, scaler, X, voting_threshold=2):
    X_scaled = scaler.transform(X)
    votes = {name: mdl.predict(X_scaled) for name, mdl in models.items()}
    vote_matrix = np.array(list(votes.values()))
    anomaly_votes = (vote_matrix == -1).sum(axis=0)
    predictions = np.where(anomaly_votes >= voting_threshold, -1, 1)
    scores = np.mean(
        [
            models["iforest"].decision_function(X_scaled),
            models["lof"].score_samples(X_scaled),
            models["svm"].decision_function(X_scaled),
        ],
        axis=0,
    )
    return predictions, votes, anomaly_votes, scores


def get_model_agreement(_, __, anomaly_votes):
    return {
        "unanimous_anomaly": (anomaly_votes == 3).sum(),
        "majority_anomaly": (anomaly_votes >= 2).sum(),
        "split_decision": (anomaly_votes == 1).sum(),
        "unanimous_normal": (anomaly_votes == 0).sum(),
    }


def _score_configuration(X, contamination, voting_threshold):
    models, scaler, _ = train_models(X, contamination=contamination, voting_threshold=voting_threshold)
    predictions, votes, anomaly_votes, scores = predict_ensemble(models, scaler, X, voting_threshold)
    anomaly_ratio = (predictions == -1).mean()
    agreement = get_model_agreement(predictions, votes, anomaly_votes)
    combined_score = (
        scores.std() * 10
        + agreement["unanimous_anomaly"] * 0.5
        + agreement["majority_anomaly"] * 0.3
        - abs(anomaly_ratio - contamination) * 20
    )
    print(
        f"  Score={combined_score:.4f} | anomalies={anomaly_ratio:.2%} | "
        f"unanimous={agreement['unanimous_anomaly']} | majority={agreement['majority_anomaly']}"
    )
    return combined_score, models, scaler, {
        "contamination": contamination,
        "voting_threshold": voting_threshold,
        "score": combined_score,
        "anomaly_ratio": anomaly_ratio,
        "agreement": agreement,
    }


def hyperparameter_tuning_ensemble(X, contamination_range=None, voting_thresholds=None):
    contamination_range = contamination_range or [0.03, 0.05, 0.07]
    voting_thresholds = voting_thresholds or [2, 3]
    print_header("ENSEMBLE HYPERPARAMETER TUNING")

    best_score, best_models, best_scaler, best_params = float("-inf"), None, None, None
    results = []

    for idx, (contamination, voting_threshold) in enumerate(
        [(c, v) for c in contamination_range for v in voting_thresholds], start=1
    ):
        print(f"\n[{idx}/{len(contamination_range)*len(voting_thresholds)}] contamination={contamination}, voting={voting_threshold}/3")
        score, models, scaler, info = _score_configuration(X, contamination, voting_threshold)
        results.append(info)
        if score > best_score:
            best_score, best_models, best_scaler, best_params = score, models, scaler, info
            print("  New best configuration!")

    print_header("BEST PARAMETERS FOUND")
    print(f"Contamination: {best_params['contamination']}, Voting: {best_params['voting_threshold']}/3, Score: {best_score:.4f}")
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
    
    print_header("FINAL ENSEMBLE PREDICTIONS")
    predictions, votes, anomaly_votes, scores = predict_ensemble(
        best_models, best_scaler, X, best_params["voting_threshold"]
    )
    agreement = get_model_agreement(predictions, votes, anomaly_votes)

    df = df.assign(
        anomaly_label=predictions,
        anomaly_score=scores,
        anomaly_votes=anomaly_votes,
        iforest_vote=votes["iforest"],
        lof_vote=votes["lof"],
        svm_vote=votes["svm"],
    )

    total_anomalies = (predictions == -1).sum()
    print(
        f"\nRESULTS: {total_anomalies} anomalies ({total_anomalies/len(df):.2%}) "
        f"| Majority={agreement['majority_anomaly']} | Unanimous={agreement['unanimous_anomaly']}"
    )
    percentiles = np.percentile(scores, [0, 25, 50, 75, 100])
    print(
        "Score distribution:"
        f" min={percentiles[0]:.4f} Q1={percentiles[1]:.4f} median={percentiles[2]:.4f}"
        f" Q3={percentiles[3]:.4f} max={percentiles[4]:.4f}"
    )
    
    # Save analyzed data
    if safe_save_csv(df, ANALYZED_CSV_PATH):
        print(f"\nResults saved → {ANALYZED_CSV_PATH}")

    # Save anomalies only
    anomalies_out = df[df['anomaly_label'] == -1].copy()
    if safe_save_csv(anomalies_out, ANOMALIES_CSV_PATH):
        print(f"Anomalies only saved → {ANOMALIES_CSV_PATH} ({len(anomalies_out)} rows)")
    
    model_bundle = create_ensemble_bundle(
        models=best_models,
        scaler=best_scaler,
        voting_threshold=best_params["voting_threshold"],
        encoders=encoders,
        feature_names=X.columns.tolist(),
        best_params=best_params,
        tuning_results=tuning_results,
        X=X,
    )
    if safe_save_joblib(model_bundle, MODEL_PATH):
        print(f"\nEnsemble bundle saved → {MODEL_PATH}")

    base_dir = os.path.dirname(MODEL_PATH)
    base_name = os.path.basename(MODEL_PATH).replace(".pkl", "")
    for suffix, model in best_models.items():
        path = os.path.join(base_dir, f"{base_name}_{suffix}.pkl")
        safe_save_joblib(model, path)
        print(f"  Saved {suffix.upper()} → {path}")
    
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
