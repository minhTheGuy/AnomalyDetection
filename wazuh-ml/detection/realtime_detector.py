"""
Real-time anomaly detection - Monitor Wazuh Indexer và phát hiện anomalies ngay lập tức
"""
import time
import requests
import urllib3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import signal
import sys
from core.config import (
    WAZUH_INDEXER_URL,
    WAZUH_INDEX_PATTERN,
    INDEXER_USER,
    INDEXER_PASS,
    MODEL_PATH,
    MODEL_TYPE,
    get_requests_verify
)
from data_processing.common import parse_hits_to_dataframe
from detection.detect_anomaly import _predict_ensemble
from utils.common import print_header, safe_load_joblib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global flag for graceful shutdown
running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n\nShutdown signal received. Stopping...")
    running = False

signal.signal(signal.SIGINT, signal_handler)


class RealtimeDetector:
    """Real-time anomaly detector"""
    
    def __init__(self, poll_interval=60, lookback_minutes=5):
        """
        Initialize detector
        
        Args:
            poll_interval: Seconds between polls
            lookback_minutes: How far back to look for new events
        """
        self.poll_interval = poll_interval
        self.lookback_minutes = lookback_minutes
        self.last_check_time = None
        self.total_processed = 0
        self.total_anomalies = 0
        self.autoencoder_threshold = None
        print("Initializing Real-time Anomaly Detector")
        self._init_model()
        
    def _init_model(self):
        """Load trained model"""
        try:
            bundle = safe_load_joblib(MODEL_PATH)
            if bundle is None:
                raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
            
            self.bundle = bundle
            model_type = bundle.get("model_type", MODEL_TYPE or "ensemble")
            self.model_type = model_type
            self.autoencoder_threshold = None
            
            if model_type == "ensemble":
                self.models = bundle["models"]
                self.scaler = bundle["scaler"]
                self.voting_threshold = bundle.get("voting_threshold", 2)
                self.detector = None
            elif model_type == "autoencoder":
                self.detector = bundle["autoencoder"]
                self.models = None
                self.scaler = bundle.get("scaler")
                self.voting_threshold = None
                self.autoencoder_threshold = bundle.get("autoencoder_threshold")
            else:
                raise ValueError(
                    f"Unsupported model_type '{model_type}'. Use 'ensemble' or 'autoencoder'."
                )
            
            self.encoders = bundle["encoders"]
            self.feature_names = bundle.get("feature_names", [])
            
            training_date = bundle.get('training_date', 'Unknown')
            n_features = bundle.get('n_features', 'Unknown')
            
            print(f"Model loaded successfully")
            print(f"   Training date: {training_date}")
            print(f"   Features: {n_features}")
            print(f"   Model type: {model_type}")
            
        except Exception as e:
            print(f"Error loading model: {e}")
            print("   Please train a model first using train_model.py")
            sys.exit(1)
    
    def fetch_recent_events(self):
        now = datetime.utcnow()
        from_time = self.last_check_time or (now - timedelta(minutes=self.lookback_minutes))
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": from_time.isoformat() + "Z",
                                    "lte": now.isoformat() + "Z"
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"timestamp": "asc"}],
            "_source": [
                "@timestamp", "timestamp", "agent.name", "agent.ip",
                "rule.id", "rule.level", "rule.groups", "rule.description",
                "decoder.name", "location",
                "syscheck.event", "syscheck.path", "syscheck.size_after",
                "syscheck.sha256_after", "syscheck.uname_after", "syscheck.mtime_after",
                "data.file", "data.title",
                "data.event_type", "data.app_proto", "data.proto",
                "data.src_ip", "data.src_port", "data.dest_ip", "data.dest_port",
                "data.alert.severity", "data.alert.signature", "data.alert.category",
                "data.flow.bytes_toserver", "data.flow.bytes_toclient",
                "data.flow.pkts_toserver", "data.flow.pkts_toclient",
                "full_log"
            ]
        }
        
        try:
            response = requests.post(
                f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search",
                auth=(INDEXER_USER, INDEXER_PASS),
                json=query,
                verify=get_requests_verify(),
                timeout=30,
            )
            response.raise_for_status()
            self.last_check_time = now
            return parse_hits_to_dataframe(response.json().get("hits", {}).get("hits", []))
        except Exception as e:
            print(f"Error fetching events: {e}")
            return pd.DataFrame()
    
    def detect_anomalies(self, df):
        if df.empty:
            return pd.DataFrame()
        
        # Sử dụng logic từ detect_anomaly.py
        from data_processing.feature_engineering import engineer_all_features
        from data_processing.preprocessing import preprocess_dataframe
        
        # Feature engineering
        df = engineer_all_features(df)
        
        # Preprocessing
        df, X, _ = preprocess_dataframe(df)
        
        # Align features
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0
        
        X = X[self.feature_names]
        
        # Predict
        if self.model_type == "ensemble":
            predictions, votes, anomaly_votes, scores = _predict_ensemble(
                self.models, self.scaler, X, self.voting_threshold
            )
            df["anomaly_label"] = predictions
            df["anomaly_score"] = scores
            df["anomaly_votes"] = anomaly_votes
        elif self.model_type == "autoencoder":
            if self.detector is None or self.scaler is None:
                raise RuntimeError("Autoencoder bundle missing detector/scaler")
            X_scaled = self.scaler.transform(X)
            reconstruction = self.detector.predict(X_scaled)
            errors = np.mean((reconstruction - X_scaled) ** 2, axis=1)
            threshold = self.autoencoder_threshold
            if threshold is None:
                threshold = float(np.quantile(errors, 0.95))
            df["reconstruction_error"] = errors
            df["anomaly_score"] = -errors
            df["anomaly_label"] = np.where(errors >= threshold, -1, 1)
        else:
            raise RuntimeError(f"Unsupported model type: {self.model_type}")
        
        return df
    
    def process_anomalies(self, anomalies_df):
        """
        Process detected anomalies
        
        Args:
            anomalies_df: DataFrame with anomalies
        """
        for _, row in anomalies_df.iterrows():
            timestamp = row.get('timestamp', 'N/A')
            agent = row.get('agent', 'unknown')
            rule_level = row.get('rule_level', 0)
            event_desc = row.get('event_desc', 'N/A')
            score = row.get('anomaly_score', 0)
            
            alert_msg = (
                f"[ML Anomaly] {agent} - Level {rule_level} - "
                f"{str(event_desc)[:60]} (score: {score:.3f})"
            )
            
            print(f"  {timestamp} - {alert_msg}")
            self.total_anomalies += 1
    
    def run(self):
        print_header("REAL-TIME ANOMALY DETECTOR STARTED")
        print(f"Poll interval:     {self.poll_interval}s")
        print(f"Lookback window:   {self.lookback_minutes} minutes")
        print(f"Press Ctrl+C to stop\n")
        
        iteration = 0
        
        while running:
            iteration += 1
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Iteration #{iteration}")
            
            try:
                print("  Fetching recent events...")
                df = self.fetch_recent_events()
                
                if df.empty:
                    print(f"  ℹNo new events found")
                else:
                    print(f"  Found {len(df)} new events")
                    
                    print("  Analyzing events...")
                    df = self.detect_anomalies(df)
                    
                    if df.empty:
                        print("  Detection failed")
                    else:
                        anomalies = df[df['anomaly_label'] == -1]
                        self.total_processed += len(df)
                        
                        if len(anomalies) > 0:
                            print(f"  Detected {len(anomalies)} anomalies:")
                            self.process_anomalies(anomalies)
                        else:
                            print(f"  All events are normal")
                
                # Statistics
                print(f"  Stats: {self.total_processed} processed, {self.total_anomalies} anomalies")
                
            except Exception as e:
                print(f"   Error in iteration: {e}")
                import traceback
                traceback.print_exc()
            
            # Sleep until next poll
            if running:
                print(f"  Sleeping for {self.poll_interval}s...")
                time.sleep(self.poll_interval)
        
        print_header("DETECTOR STOPPED")
        print(f"Total events processed: {self.total_processed}")
        print(f"Total anomalies found:  {self.total_anomalies}")


if __name__ == "__main__":
    detector = RealtimeDetector()
    detector.run()
