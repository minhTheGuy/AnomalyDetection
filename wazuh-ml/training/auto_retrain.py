"""
Script tự động retrain model khi có dữ liệu mới
Kiểm tra ngày modified của file CSV, nếu mới hơn model thì retrain
"""

import os
import sys
import time
from datetime import datetime, timedelta
import joblib
from pathlib import Path
from core.config import CSV_PATH, MODEL_PATH, ANALYZED_CSV_PATH
from data_processing.export_from_es import fetch_logs
from training.train_model import train_model_with_tuning
from utils.common import print_header, safe_load_joblib

def get_file_age(filepath):
    """
    Lấy thời gian modified của file
    
    Returns:
        datetime object hoặc None nếu file không tồn tại
    """
    if os.path.exists(filepath):
        timestamp = os.path.getmtime(filepath)
        return datetime.fromtimestamp(timestamp)
    return None


def should_retrain(force=False, max_age_days=7):
    """
    Kiểm tra xem có cần retrain model không
    
    Args:
        force: Bắt buộc retrain
        max_age_days: Số ngày tối đa trước khi retrain tự động
    
    Returns:
        (should_retrain: bool, reason: str)
    """
    if force:
        return True, "Force retrain requested"
    
    # Kiểm tra file tồn tại
    if not os.path.exists(MODEL_PATH):
        return True, "Model file not found"
    
    if not os.path.exists(CSV_PATH):
        return False, "No CSV data available"
    
    # Lấy thời gian modified
    csv_age = get_file_age(CSV_PATH)
    model_age = get_file_age(MODEL_PATH)
    
    if csv_age is None or model_age is None:
        return True, "Cannot determine file ages"
    
    # CSV mới hơn model → cần retrain
    if csv_age > model_age:
        time_diff = csv_age - model_age
        return True, f"New data available (CSV updated {time_diff} ago)"
    
    # Model quá cũ (> max_age_days) → nên retrain
    now = datetime.now()
    model_days_old = (now - model_age).days
    
    if model_days_old > max_age_days:
        return True, f"Model is {model_days_old} days old (max: {max_age_days})"
    
    return False, f"Model is up-to-date ({model_days_old} days old)"


def get_model_info():
    """
    Lấy thông tin model hiện tại
    
    Returns:
        Dictionary với model info
    """
    if not os.path.exists(MODEL_PATH):
        return None
    
    bundle = safe_load_joblib(MODEL_PATH)
    if bundle is None:
        return None
    return {
        'training_date': bundle.get('training_date', 'Unknown'),
        'n_samples': bundle.get('n_samples', 'Unknown'),
        'n_features': bundle.get('n_features', 'Unknown'),
        'best_params': bundle.get('best_params', {}),
        'metrics': bundle.get('metrics', {})
    }


def auto_retrain(fetch_new_data=True, force=False, enable_tuning=True, max_age_days=7):
    """
    Tự động retrain model nếu cần
    
    Args:
        fetch_new_data: True để fetch log mới từ Wazuh trước khi train
        force: Bắt buộc retrain
        enable_tuning: Bật hyperparameter tuning
        max_age_days: Số ngày tối đa trước khi tự động retrain
    
    Returns:
        True nếu đã retrain, False nếu không
    """
    print_header("AUTO-RETRAIN CHECKER")
    
    # Hiển thị thông tin model hiện tại
    print("\n  Current Model Info:")
    model_info = get_model_info()
    if model_info:
        print(f"  Training date:  {model_info['training_date']}")
        print(f"  Samples:        {model_info['n_samples']}")
        print(f"  Features:       {model_info['n_features']}")
        if model_info['metrics']:
            print(f"  Anomaly ratio:  {model_info['metrics'].get('anomaly_ratio', 'N/A'):.2%}")
    else:
        print("  No existing model found")
    
    # Kiểm tra có cần retrain không
    print("\n  Checking if retrain is needed...")
    should_train, reason = should_retrain(force=force, max_age_days=max_age_days)
    print(f"  Reason: {reason}")
    
    if not should_train:
        print("\n  Model is up-to-date. No retrain needed.")
        return False
    
    print("\n  Retrain is needed!")
    
    # Fetch new data nếu được yêu cầu
    if fetch_new_data:
        print("\n  Fetching new data from Wazuh Indexer...")
        try:
            fetch_logs()
            print("  New data fetched successfully")
        except Exception as e:
            print(f"  Error fetching data: {e}")
            print("   Continuing with existing data...")
    
    # Retrain model
    print("\n  Starting model retraining...")
    start_time = time.time()
    
    try:
        train_model_with_tuning(enable_tuning=enable_tuning)
        
        elapsed = time.time() - start_time
        print(f"\n  Retrain completed successfully in {elapsed:.2f} seconds")
        
        # Hiển thị thông tin model mới
        print("\n  New Model Info:")
        new_model_info = get_model_info()
        if new_model_info:
            print(f"  Training date:  {new_model_info['training_date']}")
            print(f"  Samples:        {new_model_info['n_samples']}")
            print(f"  Features:       {new_model_info['n_features']}")
            if new_model_info['metrics']:
                print(f"  Anomaly ratio:  {new_model_info['metrics'].get('anomaly_ratio', 'N/A'):.2%}")
        
        return True
        
    except Exception as e:
        print(f"\n  Error during retraining: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Auto-retrain ML model for anomaly detection")
    parser.add_argument("--force", action="store_true", help="Force retrain even if not needed")
    parser.add_argument("--no-fetch", action="store_true", help="Don't fetch new data before training")
    parser.add_argument("--no-tuning", action="store_true", help="Disable hyperparameter tuning (faster)")
    parser.add_argument("--max-age-days", type=int, default=7, help="Max age in days before auto-retrain (default: 7)")
    
    args = parser.parse_args()
    
    success = auto_retrain(
        fetch_new_data=not args.no_fetch,
        force=args.force,
        enable_tuning=not args.no_tuning,
        max_age_days=args.max_age_days
    )
    
    sys.exit(0 if success else 1)
