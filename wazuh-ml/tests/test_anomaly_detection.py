"""
Unit tests cho anomaly detection
"""
import unittest
import pandas as pd
import numpy as np
import os
import sys
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.ensemble_detector import EnsembleAnomalyDetector
from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe


class TestAnomalyDetection(unittest.TestCase):
    """Test cases cho anomaly detection"""
    
    @classmethod
    def setUpClass(cls):
        """Setup test data"""
        cls.test_data = pd.DataFrame({
            'timestamp': pd.date_range('2025-01-01', periods=100, freq='1h'),
            'agent': ['test-agent'] * 100,
            'rule_level': np.random.randint(0, 15, 100),
            'src_ip': [f'192.168.1.{i%255}' for i in range(100)],
            'dst_ip': [f'10.0.0.{i%255}' for i in range(100)],
            'src_port': np.random.randint(1024, 65535, 100),
            'dst_port': np.random.choice([22, 80, 443, 3306, 5432], 100),
            'proto': np.random.choice(['tcp', 'udp', 'icmp'], 100),
            'event_desc': ['test event'] * 100,
            'bytes_toserver': np.random.randint(0, 10000, 100),
            'bytes_toclient': np.random.randint(0, 10000, 100),
        })
        
        # Apply feature engineering
        cls.test_data = engineer_all_features(cls.test_data)
        
    def test_ensemble_detector_initialization(self):
        """Test ensemble detector initialization"""
        detector = EnsembleAnomalyDetector()
        self.assertIsNotNone(detector)
        self.assertFalse(detector.fitted)
        self.assertEqual(len(detector.models), 0)
        
    def test_ensemble_detector_training(self):
        """Test ensemble detector training"""
        detector = EnsembleAnomalyDetector(voting_threshold=2)
        
        # Preprocess data
        df_processed, X, _ = preprocess_dataframe(self.test_data.copy())
        
        # Train
        detector.fit(X, contamination=0.1)
        
        # Check models are trained
        self.assertTrue(detector.fitted)
        self.assertIn('iforest', detector.models)
        self.assertIn('lof', detector.models)
        self.assertIn('svm', detector.models)
        self.assertIsNotNone(detector.scaler)
        
    def test_ensemble_detector_prediction(self):
        """Test ensemble detector prediction"""
        detector = EnsembleAnomalyDetector(voting_threshold=2)
        
        # Preprocess data
        df_processed, X, _ = preprocess_dataframe(self.test_data.copy())
        
        # Train
        detector.fit(X, contamination=0.1)
        
        # Predict
        predictions, votes, anomaly_votes = detector.predict(X)
        
        # Check predictions
        self.assertEqual(len(predictions), len(X))
        self.assertTrue(all(p in [-1, 1] for p in predictions))
        self.assertEqual(len(votes), 3)  # iforest, lof, svm
        
    def test_ensemble_detector_save_load(self):
        """Test save and load model"""
        detector = EnsembleAnomalyDetector(voting_threshold=2)
        
        # Preprocess data
        df_processed, X, _ = preprocess_dataframe(self.test_data.copy())
        
        # Train
        detector.fit(X, contamination=0.1)
        
        # Save
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            temp_path = f.name
            detector.save(temp_path)
            
            # Load
            detector2 = EnsembleAnomalyDetector()
            detector2.load(temp_path)
            
            # Check models are loaded
            self.assertTrue(detector2.fitted)
            self.assertIn('iforest', detector2.models)
            self.assertIn('lof', detector2.models)
            self.assertIn('svm', detector2.models)
            
            # Cleanup
            os.unlink(temp_path)


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


if __name__ == '__main__':
    unittest.main()

