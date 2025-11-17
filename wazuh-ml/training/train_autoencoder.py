"""
Train autoencoder-based anomaly detector for Wazuh logs.
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from core.config import CSV_PATH, MODEL_PATH
from training.common import load_and_prepare_data, create_autoencoder_bundle
from utils.common import print_header, safe_save_joblib


def _build_autoencoder(n_features: int, hidden_ratio: float, max_iter: int, learning_rate: float) -> MLPRegressor:
    hidden_dim = max(4, int(n_features * hidden_ratio))
    # Decoder layer equals n_features to reconstruct original input
    hidden_layers = (hidden_dim, n_features)
    return MLPRegressor(
        hidden_layer_sizes=hidden_layers,
        activation="relu",
        solver="adam",
        random_state=42,
        max_iter=max_iter,
        learning_rate_init=learning_rate,
        verbose=False,
    )


def train_autoencoder_model(
    *,
    contamination: float = 0.05,
    hidden_ratio: float = 0.5,
    max_iter: int = 250,
    learning_rate: float = 0.001,
    output_path: str | None = None,
    engineer_features: bool = True,
):
    """
    Train autoencoder using MLPRegressor to learn normal behaviour reconstruction.
    """
    print_header("AUTOENCODER TRAINING")
    print(f"Loading data from {CSV_PATH} ...")
    df, X, encoders = load_and_prepare_data(CSV_PATH, engineer_features=engineer_features)
    feature_names = list(X.columns)
    n_samples, n_features = X.shape

    print(f"  Samples:  {n_samples}")
    print(f"  Features: {n_features}")
    print(f"  Contamination target: {contamination:.2%}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X.values)

    autoencoder = _build_autoencoder(n_features, hidden_ratio, max_iter, learning_rate)
    print("\nTraining autoencoder ...")
    autoencoder.fit(X_scaled, X_scaled)
    reconstruction = autoencoder.predict(X_scaled)
    errors = np.mean((reconstruction - X_scaled) ** 2, axis=1)
    threshold_error = float(np.quantile(errors, 1 - contamination))

    print("\nReconstruction error statistics:")
    print(f"  Min:    {errors.min():.6f}")
    print(f"  Mean:   {errors.mean():.6f}")
    print(f"  Median: {np.median(errors):.6f}")
    print(f"  Max:    {errors.max():.6f}")
    print(f"  Threshold (>{(1 - contamination) * 100:.1f}th percentile): {threshold_error:.6f}")

    bundle = create_autoencoder_bundle(
        autoencoder=autoencoder,
        scaler=scaler,
        threshold=threshold_error,
        encoders=encoders,
        feature_names=feature_names,
        X=X,
        contamination=contamination,
    )

    out_path = output_path or MODEL_PATH.replace(".pkl", "_autoencoder.pkl")
    if safe_save_joblib(bundle, out_path):
        print(f"\nAutoencoder model saved → {out_path}")

    # Persist reconstruction errors for inspection
    df_out = df.copy()
    df_out["reconstruction_error"] = errors
    anomalies = df_out[df_out["reconstruction_error"] >= threshold_error]
    print(f"Detected {len(anomalies)} potential anomalies (>= threshold) in training data")

    return {
        "model_path": out_path,
        "threshold": threshold_error,
        "training_samples": n_samples,
        "features": n_features,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Train autoencoder anomaly detector")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected anomaly ratio (default 0.05)")
    parser.add_argument(
        "--hidden-ratio",
        type=float,
        default=0.5,
        help="Hidden layer size as a ratio of feature count (default 0.5)",
    )
    parser.add_argument("--max-iter", type=int, default=250, help="Max training iterations (default 250)")
    parser.add_argument("--learning-rate", type=float, default=0.001, help="Learning rate (default 0.001)")
    parser.add_argument("--output", type=str, default=None, help="Output path for the bundle")
    parser.add_argument("--no-feature-engineering", action="store_true", help="Skip feature engineering step")
    return parser.parse_args()


def main():
    args = parse_args()
    train_autoencoder_model(
        contamination=args.contamination,
        hidden_ratio=args.hidden_ratio,
        max_iter=args.max_iter,
        learning_rate=args.learning_rate,
        output_path=args.output,
        engineer_features=not args.no_feature_engineering,
    )


if __name__ == "__main__":
    main()


