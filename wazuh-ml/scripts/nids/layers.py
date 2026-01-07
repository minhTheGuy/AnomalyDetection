"""layers.py - 3-layer hybrid NIDS: Suricata (L1), XGBoost (L2), Isolation Forest (L3)"""

import json, subprocess, logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import numpy as np
import pandas as pd
import joblib
from .config import MODELS_DIR
from .models import FlowDetection, ThreatLevel

logger = logging.getLogger(__name__)


class SuricataSNIDS:
    """Layer 1: Suricata signature-based detection via pfSense SSH"""
    
    def __init__(self, pfsense_host: str = None, pfsense_user: str = None,
                 pfsense_key: str = None, interface: str = None,
                 eve_log_path: str = '/var/log/suricata'):
        import os
        # Use provided interface or fall back to environment variable or default
        if interface is None:
            interface = os.getenv('PFSENSE_INTERFACE', 'em1')
        self.host, self.user = pfsense_host, pfsense_user
        # Expand ~ to home directory and check if file exists
        if pfsense_key:
            pfsense_key = str(Path(pfsense_key).expanduser())
            if not Path(pfsense_key).exists():
                logger.warning(f"SSH key file not found: {pfsense_key}. SSH will use default authentication methods.")
                self.key_file = None
            else:
                self.key_file = pfsense_key
        else:
            self.key_file = None
        self.interface = interface
        self.eve_log_path = f"{eve_log_path}/{interface}/eve.json"
        self.available = False
        self._validate_connection()
    
    def _validate_connection(self):
        """Validate SSH and Suricata availability"""
        if not self.host or not self.user:
            logger.info("Suricata L1: No pfSense configured")
            return
        try:
            # Find Suricata directory
            cmd = self._ssh_cmd([f"ls -d /var/log/suricata/suricata_{self.interface}* 2>/dev/null | head -1"])
            result = subprocess.run(cmd, capture_output=True, timeout=10, text=True)
            if result.returncode == 0 and result.stdout.strip():
                eve_path = f"{result.stdout.strip()}/eve.json"
                check = subprocess.run(self._ssh_cmd([f'test -f {eve_path} && echo OK']), capture_output=True, timeout=10)
                if check.returncode == 0 and b'OK' in check.stdout:
                    self.eve_log_path, self.available = eve_path, True
                    logger.info(f"Suricata L1: Connected, eve.json at {eve_path}")
                    return
            # Fallback paths
            for path in ['/var/log/suricata/eve.json', f'/var/log/suricata/{self.interface}/eve.json']:
                r = subprocess.run(self._ssh_cmd([f'test -f {path} && echo OK']), capture_output=True, timeout=10)
                if r.returncode == 0 and b'OK' in r.stdout:
                    self.eve_log_path, self.available = path, True
                    return
        except Exception as e:
            logger.warning(f"Suricata L1: Connection failed - {e}")
    
    def configure(self, host: str, user: str, key_file: str = None, interface: str = None):
        """Configure pfSense connection"""
        self.host, self.user = host, user
        # Expand ~ to home directory and check if file exists
        if key_file:
            key_file = str(Path(key_file).expanduser())
            if not Path(key_file).exists():
                logger.warning(f"SSH key file not found: {key_file}. SSH will use default authentication methods.")
                self.key_file = None
            else:
                self.key_file = key_file
        else:
            self.key_file = None
        if interface:
            self.interface, self.eve_log_path = interface, f"/var/log/suricata/{interface}/eve.json"
        self._validate_connection()
    
    def _ssh_cmd(self, remote_cmd: list) -> list:
        cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes']
        # Only add -i if key_file exists and is accessible
        if self.key_file and Path(self.key_file).exists():
            cmd.extend(['-i', self.key_file])
        return cmd + [f'{self.user}@{self.host}'] + remote_cmd
    
    def analyze(self, pcap_file: Path = None, time_window: int = 120) -> List[Dict]:
        """Fetch recent Suricata alerts from pfSense"""
        if not self.available:
            if self.host and self.user: self._validate_connection()
            if not self.available: return []
        
        try:
            cutoff = (datetime.now() - timedelta(seconds=time_window)).strftime('%Y-%m-%dT%H:%M:%S')
            cmd = self._ssh_cmd([f'tail -500 {self.eve_log_path} 2>/dev/null | grep \'"event_type":"alert"\' || true'])
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0: return []
            
            alerts = []
            for line in result.stdout.decode().strip().split('\n'):
                if not line.strip(): continue
                try:
                    event = json.loads(line)
                    if event.get('timestamp', '') >= cutoff:
                        alert = self._parse_eve_alert(event)
                        if alert: alerts.append(alert)
                except json.JSONDecodeError: continue
            
            if alerts: logger.info(f"Suricata L1: {len(alerts)} alerts in last {time_window}s")
            return alerts
        except subprocess.TimeoutExpired:
            logger.error("Suricata timeout")
            return []
        except Exception as e:
            logger.error(f"Suricata error: {e}")
            return []
    
    def _parse_eve_alert(self, event: Dict) -> Optional[Dict]:
        """Parse Suricata EVE JSON alert"""
        try:
            a = event.get('alert', {})
            return {'signature_id': str(a.get('signature_id', 'unknown')), 'message': a.get('signature', 'Unknown'),
                'category': a.get('category', 'Unknown'), 'severity': a.get('severity', 3),
                'src_ip': event.get('src_ip', 'unknown'), 'dst_ip': event.get('dest_ip', 'unknown'),
                'src_port': event.get('src_port', 0), 'dst_port': event.get('dest_port', 0),
                'protocol': event.get('proto', 'unknown'), 'timestamp': event.get('timestamp', ''), 'layer': 'suricata'}
        except: return None


def _extract_ip_info(row) -> dict:
    """Extract IP/port from dataframe row"""
    return {
        'src_ip': str(row.get('src_ip', row.get('source_ip', row.get('src', 'unknown')))),
        'dst_ip': str(row.get('dst_ip', row.get('destination_ip', row.get('dst', 'unknown')))),
        'src_port': int(row.get('src_port', row.get('source_port', row.get('sport', 0)))),
        'dst_port': int(row.get('dst_port', row.get('destination_port', row.get('dport', 0)))),
        'protocol': str(row.get('protocol', row.get('proto', 'unknown')))
    }


class XGBoostClassifier:
    """Layer 2: XGBoost supervised classifier with sliding window support"""
    
    def __init__(self, model_path: Optional[Path] = None, artifacts_path: Optional[Path] = None):
        from .config import XGBOOST_MODEL_PATH, ARTIFACTS_PATH
        self.model_path = model_path or XGBOOST_MODEL_PATH
        self.artifacts_path = artifacts_path or ARTIFACTS_PATH
        self.model = self.scaler = self.label_encoder = self.feature_names = self.target_names = None
        self.window_size = 1  # Default to single-flow mode
        self._load_model()
    
    def _load_model(self):
        try:
            if self.model_path.exists():
                data = joblib.load(self.model_path)
                self.model, self.feature_names = data.get('model'), data.get('feature_columns')
                self.target_names, self.label_mapping = data.get('target_names'), data.get('label_mapping', {})
                self.window_size = data.get('window_size', 1)  # Load window size from metadata
                logger.info(f"Loaded XGBoost from {self.model_path.name}" + 
                           (f" (window={self.window_size})" if self.window_size > 1 else ""))
                if self.artifacts_path.exists():
                    arts = joblib.load(self.artifacts_path)
                    self.scaler = arts.get('scaler')
                    self.feature_names = self.feature_names or arts.get('feature_columns')
        except Exception as e:
            logger.error(f"XGBoost load error: {e}")
    
    def _create_windows(self, data: np.ndarray) -> np.ndarray:
        """Create sliding windows from sequential data."""
        if self.window_size <= 1:
            return data
        
        n_samples = len(data)
        if n_samples < self.window_size:
            padding = np.tile(data[0:1], (self.window_size - n_samples, 1))
            data = np.vstack([padding, data])
            n_samples = len(data)
        
        windows = []
        for i in range(n_samples - self.window_size + 1):
            window = data[i:i + self.window_size]
            windows.append(window.flatten())
        
        return np.array(windows)
    
    def predict(self, df: pd.DataFrame) -> List[FlowDetection]:
        if self.model is None: return []
        try:
            X = self._prepare_features(df)
            if X is None or len(X) == 0: return []
            X_scaled = self.scaler.transform(X) if self.scaler else (X.values if hasattr(X, 'values') else X)
            
            # Apply sliding window if configured
            X_windowed = self._create_windows(X_scaled)
            if len(X_windowed) == 0: return []
            
            preds, probs = self.model.predict(X_windowed), self.model.predict_proba(X_windowed)
            labels = [self.target_names[int(p)] for p in preds] if self.target_names else [str(p) for p in preds]
            
            detections = []
            for window_idx, (label, prob) in enumerate(zip(labels, probs)):
                confidence = float(max(prob))
                if str(label).upper() != 'BENIGN':
                    # Use window_idx as the flow reference
                    flow_idx = min(window_idx + self.window_size - 1, len(df) - 1)
                    ip = _extract_ip_info(df.iloc[flow_idx])
                    detections.append(FlowDetection(
                        flow_id=str(window_idx), src_ip=ip['src_ip'], dst_ip=ip['dst_ip'],
                        src_port=ip['src_port'], dst_port=ip['dst_port'], protocol=ip['protocol'],
                        attack_type=str(label).upper(), confidence=confidence, layer='xgboost',
                        threat_level=self._get_threat_level(str(label), confidence)))
            
            if detections: 
                logger.info(f"XGBoost: {len(detections)} attacks" + 
                           (f" (windows={len(preds)})" if self.window_size > 1 else ""))
            return detections
        except Exception as e:
            logger.error(f"XGBoost error: {e}")
            return []
    
    def _prepare_features(self, df: pd.DataFrame) -> Optional[pd.DataFrame]:
        if self.feature_names is None:
            X = df.select_dtypes(include=[np.number])
        else:
            for col in set(self.feature_names) - set(df.columns): 
                df[col] = 0
            X = df[self.feature_names].copy()
        
        # Clean infinity and NaN values
        X = X.replace([np.inf, -np.inf], 0).fillna(0)
        return X
    
    def _get_threat_level(self, attack: str, conf: float) -> ThreatLevel:
        attack = attack.lower()
        if any(t in attack for t in ['dos', 'ddos', 'infiltration', 'botnet']) and conf > 0.8: return ThreatLevel.CRITICAL
        if any(t in attack for t in ['dos', 'ddos', 'infiltration', 'botnet']): return ThreatLevel.HIGH
        if any(t in attack for t in ['portscan', 'bruteforce', 'patator']): return ThreatLevel.MEDIUM
        return ThreatLevel.LOW


class AnomalyDetector:
    """Layer 3: Isolation Forest anomaly detection"""
    
    def __init__(self, model_path: Optional[Path] = None, threshold: float = -0.5):
        from .config import IFOREST_MODEL_PATH
        self.model_path = model_path or IFOREST_MODEL_PATH
        self.threshold, self.model, self.scaler, self.feature_names = threshold, None, None, None
        self._load_model()
    
    def _load_model(self):
        try:
            if self.model_path.exists():
                data = joblib.load(self.model_path)
                # Handle both object save (old) and dict save (new)
                if isinstance(data, dict):
                    self.model, self.scaler = data.get('model'), data.get('scaler')
                    self.feature_names = data.get('feature_columns')
                    self.log_columns = data.get('log_columns', [])
                    self.threshold = data.get('score_threshold_optimal', data.get('threshold', self.threshold))
                else:
                    self.model = data
                    # scaler/features might be missing if saved as raw model object.
                    # This fallback might fail if features aren't aligned, but we support legacy if possible.
                    self.log_columns = []
                
                logger.info(f"Loaded IForest from {self.model_path.name} (thresh={self.threshold:.3f})")
        except Exception as e:
            logger.error(f"IForest load error: {e}")
    
    def detect(self, df: pd.DataFrame) -> List[FlowDetection]:
        """Detect anomalies in flows"""
        if self.model is None: return []
        try:
            X = self._prepare_features(df)
            if X is None or len(X) == 0: return []
            X_scaled = self.scaler.transform(X) if self.scaler else (X.values if hasattr(X, 'values') else X)
            scores, preds = self.model.decision_function(X_scaled), self.model.predict(X_scaled)
            
            detections = []
            for i, (score, pred) in enumerate(zip(scores, preds)):
                if pred == -1 or score < self.threshold:
                    ip = _extract_ip_info(df.iloc[i])
                    detections.append(FlowDetection(
                        flow_id=str(i), src_ip=ip['src_ip'], dst_ip=ip['dst_ip'],
                        src_port=ip['src_port'], dst_port=ip['dst_port'], protocol=ip['protocol'],
                        attack_type='ANOMALY', confidence=min(1.0, max(0.0, -score)),
                        layer='isolation_forest', threat_level=self._get_threat_level(score), anomaly_score=float(score)))
            if detections: logger.info(f"IForest: {len(detections)} anomalies")
            return detections
        except Exception as e:
            logger.error(f"IForest error: {e}")
            return []
    
    def _prepare_features(self, df: pd.DataFrame) -> Optional[pd.DataFrame]:
        if self.feature_names is None:
            X = df.select_dtypes(include=[np.number])
        else:
            for col in set(self.feature_names) - set(df.columns): df[col] = 0
            X = df[self.feature_names].copy()
            
        # Apply log transform if needed
        if hasattr(self, 'log_columns') and self.log_columns:
            for col in self.log_columns:
                if col in X.columns:
                    X[col] = np.log1p(X[col])
        return X
    
    def _get_threat_level(self, score: float) -> ThreatLevel:
        if score < -0.7: return ThreatLevel.CRITICAL
        if score < -0.5: return ThreatLevel.HIGH
        if score < -0.3: return ThreatLevel.MEDIUM
        return ThreatLevel.LOW


class VAEDetector:
    """Layer 3+: Variational Autoencoder for advanced anomaly detection with sliding window support"""
    
    def __init__(self, model_path: Optional[Path] = None, threshold: float = None):
        self.model_path = model_path or MODELS_DIR / 'vae_meta_latest.pkl'
        self.encoder = self.decoder = self.scaler = None
        self.feature_names = None
        self.threshold = threshold
        self.beta = 1.0
        self.input_dim = None
        self.window_size = 1  # Default to single-flow mode
        self._load_model()
    
    def _load_model(self):
        try:
            if self.model_path.exists():
                meta = joblib.load(self.model_path)
                self.scaler = meta.get('scaler')
                self.feature_names = meta.get('feature_columns')
                self.log_columns = meta.get('log_columns', [])
                self.threshold = self.threshold or meta.get('threshold', meta.get('threshold_mse_99', 0.5))
                self.beta = meta.get('beta', 1.0)
                self.input_dim = meta.get('input_dim')
                self.threshold_combined = meta.get('threshold_combined_99')
                self.window_size = meta.get('window_size', 1)  # Load window size from metadata
                
                # Load Keras models - try from meta first, then default paths
                encoder_path = meta.get('encoder_path')
                decoder_path = meta.get('decoder_path')
                
                if encoder_path:
                    encoder_path = Path(encoder_path)
                else:
                    encoder_path = MODELS_DIR / 'vae_encoder_latest.keras'
                
                if decoder_path:
                    decoder_path = Path(decoder_path)
                else:
                    decoder_path = MODELS_DIR / 'vae_decoder_latest.keras'
                
                if encoder_path.exists() and decoder_path.exists():
                    from tensorflow import keras
                    # Import Sampling layer and pass as custom_objects for model loading
                    from .vae_utils import Sampling
                    custom_objects = {'Sampling': Sampling}
                    self.encoder = keras.models.load_model(encoder_path, custom_objects=custom_objects)
                    self.decoder = keras.models.load_model(decoder_path, custom_objects=custom_objects)
                    logger.info(f"Loaded VAE from {self.model_path.name} (thresh={self.threshold:.4f}, window={self.window_size})")
                else:
                    logger.warning(f"VAE model files not found: {encoder_path}, {decoder_path}")
        except Exception as e:
            logger.error(f"VAE load error: {e}")
    
    def _create_windows(self, data: np.ndarray) -> np.ndarray:
        """Create sliding windows from sequential data.
        
        Args:
            data: Scaled feature array of shape (N, F) where N=samples, F=features
            
        Returns:
            Windowed array of shape (N - window_size + 1, window_size * F)
        """
        if self.window_size <= 1:
            return data
        
        n_samples = len(data)
        if n_samples < self.window_size:
            # Not enough samples for windowing - pad with first sample
            padding = np.tile(data[0:1], (self.window_size - n_samples, 1))
            data = np.vstack([padding, data])
            n_samples = len(data)
        
        windows = []
        for i in range(n_samples - self.window_size + 1):
            window = data[i:i + self.window_size]
            windows.append(window.flatten())
        
        return np.array(windows)
    
    def detect(self, df: pd.DataFrame, use_combined_score: bool = False) -> List[FlowDetection]:
        """Detect anomalies using VAE reconstruction error with sliding window support"""
        if self.encoder is None or self.decoder is None:
            return []
        
        try:
            X = self._prepare_features(df)
            if X is None or len(X) == 0:
                return []
            
            X_scaled = self.scaler.transform(X) if self.scaler else X.values
            
            # Apply sliding window transformation
            X_windowed = self._create_windows(X_scaled)
            if len(X_windowed) == 0:
                return []
            
            # Get reconstruction error
            z_mean, z_log_var, z = self.encoder.predict(X_windowed, verbose=0)
            reconstructions = self.decoder.predict(z, verbose=0)
            
            # Calculate MSE per window
            mse = np.mean(np.power(X_windowed - reconstructions, 2), axis=1)
            
            # Optionally calculate combined score (MSE + KL)
            if use_combined_score and self.threshold_combined:
                kl_per_sample = -0.5 * np.sum(
                    1 + z_log_var - np.square(z_mean) - np.exp(z_log_var), axis=1
                )
                scores = mse + self.beta * kl_per_sample / (self.input_dim or X_windowed.shape[1])
                threshold = self.threshold_combined
            else:
                scores = mse
                threshold = self.threshold
            
            # Map window indices back to flow indices
            # Each window i corresponds to flows [i, i+window_size-1]
            detections = []
            
            for window_idx, score in enumerate(scores):
                if score > threshold:
                    # Use window_idx as flow reference
                    flow_idx = min(window_idx + self.window_size - 1, len(df) - 1)
                    ip = _extract_ip_info(df.iloc[flow_idx])
                    confidence = min(1.0, score / (threshold * 3))
                    
                    detections.append(FlowDetection(
                        flow_id=str(window_idx),
                        src_ip=ip['src_ip'],
                        dst_ip=ip['dst_ip'],
                        src_port=ip['src_port'],
                        dst_port=ip['dst_port'],
                        protocol=ip['protocol'],
                        attack_type='VAE_ANOMALY',
                        confidence=float(confidence),
                        layer='vae',
                        threat_level=self._get_threat_level(score, threshold),
                        anomaly_score=float(score)
                    ))
            
            if detections:
                logger.info(f"VAE: {len(detections)} anomalies (threshold={threshold:.4f}, windows={len(scores)})")
            
            return detections
            
        except Exception as e:
            logger.error(f"VAE detection error: {e}")
            return []
    
    def _prepare_features(self, df: pd.DataFrame) -> Optional[pd.DataFrame]:
        if self.feature_names is None:
            X = df.select_dtypes(include=[np.number])
        else:
            for col in set(self.feature_names) - set(df.columns):
                df[col] = 0
            X = df[self.feature_names].copy()
            
        # Apply log transform if needed
        if hasattr(self, 'log_columns') and self.log_columns:
            for col in self.log_columns:
                if col in X.columns:
                    X[col] = np.log1p(X[col])
        return X
    
    def _get_threat_level(self, score: float, threshold: float) -> ThreatLevel:
        ratio = score / threshold if threshold > 0 else 1.0
        if ratio > 5.0: return ThreatLevel.CRITICAL
        if ratio > 3.0: return ThreatLevel.HIGH
        if ratio > 1.5: return ThreatLevel.MEDIUM
        return ThreatLevel.LOW
