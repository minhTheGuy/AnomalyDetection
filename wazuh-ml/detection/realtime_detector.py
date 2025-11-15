"""
Real-time anomaly detection - Monitor Wazuh Indexer và phát hiện anomalies ngay lập tức
"""

import time
import json
import requests
import urllib3
import pandas as pd
import joblib
from datetime import datetime, timedelta
import signal
import sys
import os
from core.config import (
    WAZUH_INDEXER_URL,
    WAZUH_INDEX_PATTERN,
    INDEXER_USER,
    INDEXER_PASS,
    MODEL_PATH,
    get_requests_verify
)
from data_processing.preprocessing import preprocess_dataframe
from data_processing.feature_engineering import engineer_all_features
from utils.push_alert import send_alert

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
        self.model = None
        self.encoders = None
        self.feature_names = None
        self.last_check_time = None
        self.total_processed = 0
        self.total_anomalies = 0
        
        print("Initializing Real-time Anomaly Detector")
        self.load_model()
    
    def load_model(self):
        """Load trained model"""
        try:
            print(f"Loading model from {MODEL_PATH}...")
            bundle = joblib.load(MODEL_PATH)
            
            self.model = bundle['model']
            self.encoders = bundle['encoders']
            self.feature_names = bundle.get('feature_names', [])
            
            training_date = bundle.get('training_date', 'Unknown')
            n_features = bundle.get('n_features', 'Unknown')
            
            print(f"✅ Model loaded successfully")
            print(f"   Training date: {training_date}")
            print(f"   Features: {n_features}")
            
        except Exception as e:
            print(f"Error loading model: {e}")
            print("   Please train a model first using train_model.py")
            sys.exit(1)
    
    def fetch_recent_events(self):
        """
        Fetch recent events from Wazuh Indexer
        
        Returns:
            List of event dictionaries
        """
        # Calculate time range
        now = datetime.utcnow()
        if self.last_check_time:
            from_time = self.last_check_time
        else:
            from_time = now - timedelta(minutes=self.lookback_minutes)
        
        # Elasticsearch query
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
                "timestamp", "agent.name", "rule.id", "rule.level",
                "rule.description", "data.proto", "data.src_ip", "data.src_port",
                "data.dest_ip", "data.dest_port", "data.flow.bytes_toserver", "data.flow.bytes_toclient",
                "syscheck.size_after"
            ]
        }
        
        try:
            url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"
            response = requests.post(
                url,
                auth=(INDEXER_USER, INDEXER_PASS),
                json=query,
                verify=get_requests_verify(),
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            
            events = []
            for hit in hits:
                src = hit["_source"]
                
                # Parse event (tương tự export_from_es.py)
                dat = src.get('data', {}) or {}
                rule = src.get('rule', {}) or {}
                agent = src.get('agent', {}) or {}
                syscheck = src.get('syscheck', {}) or {}
                flow = dat.get('flow', {}) or {}
                
                # Tính bytes từ flow stats nếu có
                bytes_total = None
                if flow.get("bytes_toserver") is not None or flow.get("bytes_toclient") is not None:
                    bytes_total = (flow.get("bytes_toserver") or 0) + (flow.get("bytes_toclient") or 0)
                
                event = {
                    'timestamp': src.get('@timestamp') or src.get('timestamp', ''),
                    'agent': agent.get('name', 'unknown'),
                    'rule_id': rule.get('id', ''),
                    'rule_level': rule.get('level', 0),
                    'rule_groups': rule.get('groups'),
                    'event_desc': rule.get('description', ''),
                    'proto': dat.get('proto') or dat.get('protocol', ''),
                    'src_ip': dat.get('src_ip') or dat.get('srcip', ''),
                    'src_port': dat.get('src_port') or dat.get('srcport', 0),
                    'dst_ip': dat.get('dest_ip') or dat.get('destip') or dat.get('dst_ip') or dat.get('dstip', ''),
                    'dst_port': dat.get('dest_port') or dat.get('destport') or dat.get('dst_port') or dat.get('dstport', 0),
                    'bytes': bytes_total or 0,
                    'length': syscheck.get('size_after') or 0
                }
                
                events.append(event)
            
            # Update last check time
            self.last_check_time = now
            
            return events
            
        except Exception as e:
            print(f"Error fetching events: {e}")
            return []
    
    def detect_anomalies(self, events):
        """
        Detect anomalies in events
        
        Args:
            events: List of event dictionaries
        
        Returns:
            DataFrame with anomaly predictions
        """
        if not events:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(events)
        
        # Feature engineering
        df = engineer_all_features(df)
        
        # Preprocessing
        df, X, _ = preprocess_dataframe(df)
        
        # Ensure same features as training
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0
        
        X = X[self.feature_names]
        
        # Predict
        predictions = self.model.predict(X)
        scores = self.model.decision_function(X)
        
        df['anomaly_label'] = predictions
        df['anomaly_score'] = scores
        
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
            
            # Format alert message
            alert_msg = (
                f"[ML Anomaly] {agent} - Level {rule_level} - "
                f"{event_desc[:60]} (score: {score:.3f})"
            )
            
            print(f"  {timestamp} - {alert_msg}")
            
            # Send to Wazuh (optional - uncomment to enable)
            # try:
            #     send_alert(alert_msg)
            # except Exception as e:
            #     print(f"     ⚠️  Failed to send alert: {e}")
            
            self.total_anomalies += 1
    
    def run(self):
        """Run detector in continuous mode"""
        print(f"\n{'='*70}")
        print(f" REAL-TIME ANOMALY DETECTOR STARTED")
        print(f"{'='*70}")
        print(f"Poll interval:     {self.poll_interval}s")
        print(f"Lookback window:   {self.lookback_minutes} minutes")
        print(f"Press Ctrl+C to stop\n")
        
        iteration = 0
        
        while running:
            iteration += 1
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Iteration #{iteration}")
            
            try:
                # Fetch recent events
                print("  Fetching recent events...")
                events = self.fetch_recent_events()
                
                if not events:
                    print(f"  ℹ️  No new events found")
                else:
                    print(f"  ✓ Found {len(events)} new events")
                    
                    # Detect anomalies
                    print("  🔎 Analyzing events...")
                    df = self.detect_anomalies(events)
                    
                    if df.empty:
                        print("  ⚠️  Detection failed")
                    else:
                        anomalies = df[df['anomaly_label'] == -1]
                        self.total_processed += len(df)
                        
                        if len(anomalies) > 0:
                            print(f"  🔥 Detected {len(anomalies)} anomalies:")
                            self.process_anomalies(anomalies)
                        else:
                            print(f"  ✅ All events are normal")
                
                # Statistics
                print(f"  📊 Stats: {self.total_processed} processed, {self.total_anomalies} anomalies")
                
            except Exception as e:
                print(f"   Error in iteration: {e}")
                import traceback
                traceback.print_exc()
            
            # Sleep until next poll
            if running:
                print(f"  ⏳ Sleeping for {self.poll_interval}s...")
                time.sleep(self.poll_interval)
        
        print(f"\n{'='*70}")
        print(f"✅ DETECTOR STOPPED")
        print(f"{'='*70}")
        print(f"Total events processed: {self.total_processed}")
        print(f"Total anomalies found:  {self.total_anomalies}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Real-time anomaly detection for Wazuh")
    parser.add_argument("--interval", type=int, default=60, help="Poll interval in seconds (default: 60)")
    parser.add_argument("--lookback", type=int, default=5, help="Lookback window in minutes (default: 5)")
    
    args = parser.parse_args()
    
    detector = RealtimeDetector(
        poll_interval=args.interval,
        lookback_minutes=args.lookback
    )
    
    detector.run()
