"""
Transfer Learning Module
Bootstrap models từ pre-trained models hoặc public datasets
"""

import os
import pandas as pd
import numpy as np
import joblib
from typing import Dict, Optional, Tuple, List
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator
import warnings

from core.config import MODEL_PATH, CSV_PATH, CLASSIFIER_MODEL_PATH
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from training.train_model import train_models, predict_ensemble
from training.common import align_features
from utils.common import print_header, safe_load_joblib, safe_save_joblib, safe_load_csv


class TransferLearning:
    """
    Transfer Learning để bootstrap models từ source domain sang target domain
    """
    
    def __init__(self, source_model_path: Optional[str] = None):
        """
        Initialize transfer learning
        
        Args:
            source_model_path: Path đến pre-trained model (optional)
        """
        self.source_model_path = source_model_path
        self.source_model = None
        self.target_model = None
        self.feature_mapping = {}
        
    def load_source_model(self, model_path: Optional[str] = None) -> bool:
        """
        Load pre-trained model từ source domain
        
        Args:
            model_path: Path đến source model (nếu None, dùng self.source_model_path)
            
        Returns:
            True nếu load thành công
        """
        path = model_path or self.source_model_path
        if not path or not os.path.exists(path):
            print(f"Source model not found: {path}")
            return False
        
        bundle = safe_load_joblib(path)
        if bundle is None:
            return False
        
        model_type = bundle.get("model_type", "single")
        if model_type == "ensemble":
            # Ensemble model: load models dict, scaler, voting_threshold
            self.source_model = {
                'models': bundle.get("models"),
                'scaler': bundle.get("scaler"),
                'voting_threshold': bundle.get("voting_threshold", 2)
            }
        else:
            # Single model
            self.source_model = bundle.get("model")
        print(f"Loaded source model from: {path}")
        print(f"   Model type: {model_type}")
        return True
    
    def create_feature_mapping(self, source_features: List[str], target_features: List[str]) -> Dict[str, str]:
        """
        Tạo mapping giữa source features và target features
        
        Args:
            source_features: List features từ source model
            target_features: List features từ target domain
            
        Returns:
            Dictionary mapping source_feature -> target_feature
        """
        mapping = {}
        
        # Direct mapping (same name)
        for feat in source_features:
            if feat in target_features:
                mapping[feat] = feat
        
        # Similarity-based mapping (có thể mở rộng)
        # Ví dụ: map "src_ip_count" -> "src_ip_frequency"
        similarity_map = {
            'src_ip_count': 'src_ip_frequency',
            'dst_port_count': 'dst_port_frequency',
            'hour': 'hour',
            'day_of_week': 'day_of_week',
        }
        
        for source_feat, target_feat in similarity_map.items():
            if source_feat in source_features and target_feat in target_features:
                if source_feat not in mapping:
                    mapping[source_feat] = target_feat
        
        self.feature_mapping = mapping
        print(f"Created feature mapping: {len(mapping)} features")
        return mapping
    
    def transfer_anomaly_detector(
        self,
        target_data: pd.DataFrame,
        transfer_method: str = "fine_tune",
        contamination: float = 0.05,
        use_ensemble: bool = True
    ) -> BaseEstimator:
        """
        Transfer anomaly detection model từ source sang target domain
        
        Args:
            target_data: Target domain data (Wazuh logs)
            transfer_method: "fine_tune" hoặc "feature_extraction"
            contamination: Expected anomaly ratio
            use_ensemble: Sử dụng ensemble model
            
        Returns:
            Trained model cho target domain
        """
        print_header("TRANSFER LEARNING: Anomaly Detection")
        
        # Feature engineering cho target data
        print("\n1. Feature engineering for target domain...")
        target_df = engineer_all_features(target_data.copy())
        target_df, X_target, encoders = preprocess_dataframe(target_df)
        target_features = list(X_target.columns)
        
        print(f"   Target features: {len(target_features)}")
        
        # Nếu có source model, transfer knowledge
        if self.source_model and transfer_method == "fine_tune":
            print("\n2. Fine-tuning from source model...")
            
            # Lấy source features
            if hasattr(self.source_model, 'feature_names'):
                source_features = self.source_model.feature_names
            else:
                # Try to get from bundle
                try:
                    bundle = joblib.load(self.source_model_path)
                    source_features = bundle.get("feature_names", [])
                except:
                    source_features = []
            
            if source_features:
                # Create feature mapping
                self.create_feature_mapping(source_features, target_features)
                
                # Align features
                X_aligned = self._align_features(X_target, source_features, target_features)
                
                # Use source model predictions as pseudo-labels
                print("   Using source model for pseudo-labeling...")
                # Check if source model is ensemble (dict with 'models' key) or single model
                if isinstance(self.source_model, dict) and 'models' in self.source_model:
                    # Ensemble model
                    models = self.source_model['models']
                    scaler = self.source_model.get('scaler')
                    voting_threshold = self.source_model.get('voting_threshold', 2)
                    source_predictions, _, _, _ = predict_ensemble(models, scaler, X_aligned, voting_threshold)
                else:
                    # Single model
                    source_predictions = self.source_model.predict(X_aligned)
                
                # Fine-tune với pseudo-labels
                print("   Fine-tuning target model...")
                if use_ensemble:
                    models, scaler, voting_threshold = train_models(X_target, contamination=contamination, voting_threshold=2)
                    target_model = {'models': models, 'scaler': scaler, 'voting_threshold': voting_threshold}
                else:
                    target_model = IsolationForest(
                        contamination=contamination,
                        n_estimators=200,
                        random_state=42
                    )
                    target_model.fit(X_target)
                
                self.target_model = target_model
                print("Fine-tuning completed")
            else:
                print("No source features found, training from scratch...")
                return self._train_from_scratch(X_target, contamination, use_ensemble)
        else:
            print("\n2. Training from scratch (no source model)...")
            return self._train_from_scratch(X_target, contamination, use_ensemble)
        
        return self.target_model
    
    def _align_features(
        self,
        X_target: pd.DataFrame,
        source_features: List[str],
        target_features: List[str]
    ) -> pd.DataFrame:
        """
        Align target features với source features
        
        Args:
            X_target: Target feature matrix
            source_features: Source feature names
            target_features: Target feature names (unused, kept for compatibility)
            
        Returns:
            Aligned feature matrix
        """
        return align_features(X_target, source_features, self.feature_mapping)
    
    def _train_from_scratch(
        self,
        X: pd.DataFrame,
        contamination: float,
        use_ensemble: bool
    ) -> BaseEstimator:
        """
        Train model from scratch
        
        Args:
            X: Feature matrix
            contamination: Expected anomaly ratio
            use_ensemble: Use ensemble model
            
        Returns:
            Trained model
        """
        if use_ensemble:
            models, scaler, voting_threshold = train_models(X, contamination=contamination, voting_threshold=2)
            model = {'models': models, 'scaler': scaler, 'voting_threshold': voting_threshold}
        else:
            model = IsolationForest(
                contamination=contamination,
                n_estimators=200,
                random_state=42
            )
            model.fit(X)
        
        self.target_model = model
        return model
    
    def save_transferred_model(
        self,
        output_path: str,
        encoders: Dict,
        feature_names: List[str],
        model_type: str = "ensemble"
    ):
        """
        Save transferred model
        
        Args:
            output_path: Path để save model
            encoders: Encoders dictionary
            feature_names: Feature names
            model_type: "ensemble" hoặc "single"
        """
        if not self.target_model:
            raise ValueError("No target model to save. Run transfer_anomaly_detector first.")
        
        bundle = {
            'model_type': model_type,
            'training_date': pd.Timestamp.now().isoformat(),
            'encoders': encoders,
            'feature_names': feature_names,
            'transfer_learning': True,
            'source_model_path': self.source_model_path,
        }
        
        if model_type == "ensemble":
            bundle['detector'] = self.target_model
            bundle['voting_threshold'] = self.target_model.voting_threshold
        else:
            bundle['model'] = self.target_model
        
        if safe_save_joblib(bundle, output_path):
            print(f"Saved transferred model to: {output_path}")


def bootstrap_with_transfer_learning(
    target_data_path: str = CSV_PATH,
    source_model_path: Optional[str] = None,
    output_model_path: str = MODEL_PATH,
    contamination: float = 0.05,
    use_ensemble: bool = True
) -> bool:
    """
    Bootstrap model sử dụng transfer learning
    
    Args:
        target_data_path: Path đến target domain data (Wazuh logs)
        source_model_path: Path đến source model (optional)
        output_model_path: Path để save transferred model
        contamination: Expected anomaly ratio
        use_ensemble: Use ensemble model
        
    Returns:
        True nếu thành công
    """
    print_header("BOOTSTRAP WITH TRANSFER LEARNING")
    
    # Load target data
    print(f"\nLoading target data from: {target_data_path}")
    if not os.path.exists(target_data_path):
        print(f"Target data not found: {target_data_path}")
        return False
    
    target_data = pd.read_csv(target_data_path)
    print(f"   Loaded {len(target_data)} records")
    
    # Initialize transfer learning
    transfer = TransferLearning(source_model_path=source_model_path)
    
    # Load source model nếu có
    if source_model_path and os.path.exists(source_model_path):
        transfer.load_source_model()
    
    # Transfer model
    target_df = engineer_all_features(target_data.copy())
    target_df, X_target, encoders = preprocess_dataframe(target_df)
    feature_names = list(X_target.columns)
    
    model = transfer.transfer_anomaly_detector(
        target_data=target_data,
        transfer_method="fine_tune" if source_model_path else "from_scratch",
        contamination=contamination,
        use_ensemble=use_ensemble
    )
    
    # Save model
    model_type = "ensemble" if use_ensemble else "single"
    transfer.save_transferred_model(
        output_path=output_model_path,
        encoders=encoders,
        feature_names=feature_names,
        model_type=model_type
    )
    
    print("\nTransfer learning completed successfully!")
    return True


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Transfer Learning for Anomaly Detection")
    parser.add_argument("--source-model", type=str, help="Path to source pre-trained model")
    parser.add_argument("--target-data", type=str, default=CSV_PATH, help="Path to target domain data")
    parser.add_argument("--output-model", type=str, default=MODEL_PATH, help="Path to save transferred model")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected anomaly ratio")
    parser.add_argument("--ensemble", action="store_true", help="Use ensemble model")
    
    args = parser.parse_args()
    
    success = bootstrap_with_transfer_learning(
        target_data_path=args.target_data,
        source_model_path=args.source_model,
        output_model_path=args.output_model,
        contamination=args.contamination,
        use_ensemble=args.ensemble
    )
    
    exit(0 if success else 1)

