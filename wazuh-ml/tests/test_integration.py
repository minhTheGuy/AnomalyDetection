"""
Integration tests cho end-to-end workflows
"""
import unittest
import pandas as pd
import numpy as np
import os
import sys
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_processing.feature_engineering import engineer_all_features
from data_processing.preprocessing import preprocess_dataframe
from detection.ensemble_detector import EnsembleAnomalyDetector


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        """Setup test data"""
        self.test_data = pd.DataFrame({
            'timestamp': pd.date_range('2025-01-01', periods=200, freq='1h'),
            'agent': ['test-agent'] * 200,
            'rule_level': np.random.randint(0, 15, 200),
            'src_ip': [f'192.168.1.{i%255}' for i in range(200)],
            'dst_ip': [f'10.0.0.{i%255}' for i in range(200)],
            'src_port': np.random.randint(1024, 65535, 200),
            'dst_port': np.random.choice([22, 80, 443, 3306, 5432], 200),
            'proto': np.random.choice(['tcp', 'udp', 'icmp'], 200),
            'event_desc': ['test event'] * 200,
            'bytes_toserver': np.random.randint(0, 10000, 200),
            'bytes_toclient': np.random.randint(0, 10000, 200),
        })
        
    def test_full_pipeline(self):
        """Test full pipeline: feature engineering -> preprocessing -> detection"""
        # Feature engineering
        df_engineered = engineer_all_features(self.test_data.copy())
        self.assertGreater(len(df_engineered.columns), len(self.test_data.columns))
        
        # Preprocessing
        df_processed, X, _ = preprocess_dataframe(df_engineered.copy())
        self.assertIsNotNone(df_processed)
        self.assertIsNotNone(X)
        
        # Detection
        detector = EnsembleAnomalyDetector(voting_threshold=2)
        detector.fit(X, contamination=0.1)
        
        predictions, votes, anomaly_votes = detector.predict(X)
        self.assertEqual(len(predictions), len(X))
        
        # Check anomaly rate
        anomaly_rate = (predictions == -1).sum() / len(predictions)
        self.assertGreater(anomaly_rate, 0)
        self.assertLess(anomaly_rate, 0.5)  # Should be reasonable


if __name__ == '__main__':
    unittest.main()

