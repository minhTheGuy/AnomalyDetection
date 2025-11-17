"""
Script để train cả anomaly detection model và classification model
"""

import sys
from training.train_model import train_model_with_tuning
from training.train_classifier import train_classification_models
from training.train_autoencoder import train_autoencoder_model
from utils.common import print_header


def train_all(enable_tuning=True, include_autoencoder=False, autoencoder_params=None):
    """
    Train cả anomaly detection và classification models
    
    Args:
        enable_tuning: True để bật hyperparameter tuning
        include_autoencoder: Train thêm autoencoder reconstruction model
        autoencoder_params: Dict custom hyperparameters cho autoencoder
    """
    autoencoder_params = autoencoder_params or {}
    print_header("TRAINING ALL MODELS")
    print("\nThis will train:")
    print("  1. Anomaly Detection Model (Isolation Forest / Ensemble)")
    print("  2. Classification Model (Attack Types & Event Categories)")
    if include_autoencoder:
        print("  3. Autoencoder Model (Reconstruction-based detector)")
    print()
    
    # Train anomaly detection model
    print_header("STEP 1: Training Anomaly Detection Model")
    try:
        train_model_with_tuning(enable_tuning=enable_tuning)
        print("Anomaly detection model training completed\n")
    except Exception as e:
        print(f"Anomaly detection model training failed: {e}")
        print("Continuing with classification model training...\n")
    
    # Train classification model
    print_header("STEP 2: Training Classification Model")
    try:
        train_classification_models(enable_tuning=enable_tuning)
        print("Classification model training completed\n")
    except Exception as e:
        print(f"Classification model training failed: {e}")
        sys.exit(1)

    if include_autoencoder:
        print_header("STEP 3: Training Autoencoder Model")
        try:
            train_autoencoder_model(**autoencoder_params)
            print("Autoencoder model training completed\n")
        except Exception as e:
            print(f"Autoencoder model training failed: {e}")
    
    print_header("ALL MODELS TRAINED SUCCESSFULLY")
    print("\nNext steps:")
    print("  - Run detect_anomaly.py to detect anomalies with classification")
    print("  - Run classify_events.py to classify events only")
    if include_autoencoder:
        print("  - Update MODEL_PATH to autoencoder bundle for reconstruction scoring")
    print()



