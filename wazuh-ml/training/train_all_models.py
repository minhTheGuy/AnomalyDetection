# train_all_models.py
"""
Script để train cả anomaly detection model và classification model
"""

import sys
from training.train_model import train_model_with_tuning
from training.train_classifier import train_classification_models

def train_all(enable_tuning=True):
    """
    Train cả anomaly detection và classification models
    
    Args:
        enable_tuning: True để bật hyperparameter tuning
    """
    print("="*70)
    print("🚀 TRAINING ALL MODELS")
    print("="*70)
    print("\nThis will train:")
    print("  1. Anomaly Detection Model (Isolation Forest / Ensemble)")
    print("  2. Classification Model (Attack Types & Event Categories)")
    print("\n" + "="*70 + "\n")
    
    # Train anomaly detection model
    print("\n" + "="*70)
    print("STEP 1: Training Anomaly Detection Model")
    print("="*70)
    try:
        train_model_with_tuning(enable_tuning=enable_tuning)
        print("✅ Anomaly detection model training completed\n")
    except Exception as e:
        print(f"❌ Anomaly detection model training failed: {e}")
        print("Continuing with classification model training...\n")
    
    # Train classification model
    print("\n" + "="*70)
    print("STEP 2: Training Classification Model")
    print("="*70)
    try:
        train_classification_models(enable_tuning=enable_tuning)
        print("✅ Classification model training completed\n")
    except Exception as e:
        print(f"❌ Classification model training failed: {e}")
        sys.exit(1)
    
    print("="*70)
    print("✅ ALL MODELS TRAINED SUCCESSFULLY")
    print("="*70)
    print("\nNext steps:")
    print("  - Run detect_anomaly.py to detect anomalies with classification")
    print("  - Run classify_events.py to classify events only")
    print("="*70 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train all ML models")
    parser.add_argument(
        "--no-tuning",
        action="store_true",
        help="Disable hyperparameter tuning (faster training)"
    )
    args = parser.parse_args()
    
    train_all(enable_tuning=not args.no_tuning)

