"""
Unit tests cho anomaly detection
"""
import unittest
import pandas as pd
import numpy as np
import os
import sys
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.detect_anomaly import _predict_ensemble
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe


class TestAnomalyDetection(unittest.TestCase):
    """Tests for the current ensemble prediction helpers"""
    
    @classmethod
    def setUpClass(cls):
        """Prepare synthetic dataset and trained base models"""
        cls.test_data = pd.DataFrame({
            'timestamp': pd.date_range('2025-01-01', periods=200, freq='1h'),
            'agent': ['test-agent'] * 200,
            'rule_level': np.random.randint(0, 15, 200),
            'src_ip': [f'10.0.0.{i%255}' for i in range(200)],
            'dst_ip': [f'172.16.0.{i%255}' for i in range(200)],
            'src_port': np.random.randint(1024, 65535, 200),
            'dst_port': np.random.choice([22, 80, 443, 3306, 5432], 200),
            'proto': np.random.choice(['tcp', 'udp', 'icmp'], 200),
            'event_desc': ['test event'] * 200,
            'bytes_toserver': np.random.randint(0, 10000, 200),
            'bytes_toclient': np.random.randint(0, 10000, 200),
        })
        
        engineered = engineer_all_features(cls.test_data.copy())
        _, X, _ = preprocess_dataframe(engineered)
        cls.X = X
        
        scaler = StandardScaler().fit(X)
        X_scaled = scaler.transform(X)
        cls.scaler = scaler
        
        models = {
            'iforest': IsolationForest(
                contamination=0.1,
                random_state=42
            ).fit(X_scaled),
            'lof': LocalOutlierFactor(
                n_neighbors=20,
                novelty=True
            ).fit(X_scaled),
            'svm': OneClassSVM(
                nu=0.1,
                kernel='rbf',
                gamma='scale'
            ).fit(X_scaled),
        }
        cls.models = models
    
    def test_predict_ensemble_shapes(self):
        predictions, votes, anomaly_votes, scores = _predict_ensemble(
            self.models, self.scaler, self.X, voting_threshold=2
        )
        self.assertEqual(len(predictions), len(self.X))
        self.assertEqual(len(anomaly_votes), len(self.X))
        self.assertEqual(scores.shape[0], len(self.X))
        self.assertSetEqual(set(votes.keys()), {'iforest', 'lof', 'svm'})
    
    def test_predict_ensemble_threshold_effect(self):
        preds_majority, *_ = _predict_ensemble(
            self.models, self.scaler, self.X, voting_threshold=2
        )
        preds_unanimous, *_ = _predict_ensemble(
            self.models, self.scaler, self.X, voting_threshold=3
        )
        rate_majority = (preds_majority == -1).mean()
        rate_unanimous = (preds_unanimous == -1).mean()
        self.assertGreater(rate_majority, rate_unanimous)
        self.assertGreater(rate_majority, 0)
    
    def test_predict_ensemble_vote_consistency(self):
        _, votes, anomaly_votes, _ = _predict_ensemble(
            self.models, self.scaler, self.X, voting_threshold=2
        )
        reconstructed_votes = (votes['iforest'] == -1).astype(int)
        reconstructed_votes += (votes['lof'] == -1).astype(int)
        reconstructed_votes += (votes['svm'] == -1).astype(int)
        np.testing.assert_array_equal(reconstructed_votes, anomaly_votes)


class TestFeatureEngineering(unittest.TestCase):
    """Test cases cho feature engineering"""
    
    def test_time_features(self):
        """Test time feature extraction"""
        df = pd.DataFrame({
            'timestamp': pd.date_range('2025-01-01', periods=10, freq='1H')
        })
        
        df = engineer_all_features(df)
        
        self.assertIn('hour', df.columns)
        self.assertIn('day_of_week', df.columns)
        self.assertIn('is_night', df.columns)
        
    def test_network_features(self):
        """Test network feature extraction"""
        df = pd.DataFrame({
            'src_port': [22, 80, 443, 3306],
            'dst_port': [22, 80, 443, 3306],
            'src_ip': ['192.168.1.1', '10.0.0.1', '172.16.0.1', '1.1.1.1'],
            'dst_ip': ['192.168.1.2', '10.0.0.2', '172.16.0.2', '8.8.8.8'],
        })
        
        df = engineer_all_features(df)
        
        self.assertIn('is_well_known_port', df.columns)
        self.assertIn('is_internal_src', df.columns)
        self.assertIn('is_internal_dst', df.columns)

