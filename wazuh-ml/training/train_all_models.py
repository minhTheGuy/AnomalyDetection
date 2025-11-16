"""
Script để train cả anomaly detection model và classification model
"""

import sys
from training.train_model import train_model_with_tuning
from training.train_classifier import train_classification_models
from utils.common import print_header

def train_all(enable_tuning=True):
    """
    Train cả anomaly detection và classification models
    
    Args:
        enable_tuning: True để bật hyperparameter tuning
    """
    print_header("TRAINING ALL MODELS")
    print("\nThis will train:")
    print("  1. Anomaly Detection Model (Isolation Forest / Ensemble)")
    print("  2. Classification Model (Attack Types & Event Categories)")
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
    
    print_header("ALL MODELS TRAINED SUCCESSFULLY")
    print("\nNext steps:")
    print("  - Run detect_anomaly.py to detect anomalies with classification")
    print("  - Run classify_events.py to classify events only")
    print()



