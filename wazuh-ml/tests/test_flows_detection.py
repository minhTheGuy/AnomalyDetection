#!/usr/bin/env python3
"""
test_flows_detection.py - Test detection pipeline with CSV flows file

This script loads a flows CSV file and runs it through the detection pipeline
to test both XGBoost classification and anomaly detection models.

Usage:
    python scripts/test_flows_detection.py --flows data/test/test_flows.csv
    python scripts/test_flows_detection.py --flows data/test/test_flows.csv --action alert --action webhook
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List
import pandas as pd

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    project_root = Path(__file__).parent.parent
    env_file = project_root / '.env'
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass

# Import from modular nids package
from nids import (
    ActionType,
    HybridNIDS,
    DetectionResult,
)
from nids.action_config import ActionConfigBuilder

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def load_flows_csv(csv_path: Path) -> pd.DataFrame:
    """Load flows from CSV file"""
    logger.info(f"Loading flows from: {csv_path}")
    
    if not csv_path.exists():
        raise FileNotFoundError(f"Flows CSV not found: {csv_path}")
    
    # Read CSV, skipping comment lines and handling errors
    # Use engine='python' for better error handling and to handle variable field counts
    try:
        # Try reading with error handling
        df = pd.read_csv(csv_path, comment='#', low_memory=False, on_bad_lines='skip', engine='python')
    except TypeError:
        # Fallback for older pandas versions
        try:
            df = pd.read_csv(csv_path, comment='#', low_memory=False, error_bad_lines=False, warn_bad_lines=True, engine='python')
        except:
            df = pd.read_csv(csv_path, comment='#', low_memory=False, engine='python', sep=',', quotechar='"')
    except Exception as e:
        logger.warning(f"CSV read error: {e}, trying alternative method")
        # Last resort: read line by line and pad missing fields
        import csv
        rows = []
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            header = next(reader)
            expected_cols = len(header)
            for row in reader:
                # Skip comment lines
                if row and row[0].startswith('#'):
                    continue
                # Pad row if it has fewer fields than header
                while len(row) < expected_cols:
                    row.append('0')
                # Truncate if it has more fields
                if len(row) > expected_cols:
                    row = row[:expected_cols]
                rows.append(row)
        df = pd.DataFrame(rows, columns=header)
    
    # Normalize column names (lowercase, underscores)
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    
    # Map column names from CICFlowMeter format to CIC-IDS-2017 format
    # This is needed because XGBoost was trained on CIC-IDS-2017 data
    from nids.config import FEATURE_MAPPING_REVERSE
    df = df.rename(columns=FEATURE_MAPPING_REVERSE)
    
    # Clean data - remove any rows that are completely empty
    df = df.dropna(how='all')
    
    # Clean data
    df = df.replace([float('inf'), float('-inf')], 0)
    df = df.fillna(0)
    
    logger.info(f"Loaded {len(df)} flows from CSV")
    logger.debug(f"Column names after mapping: {list(df.columns[:10])}...")
    return df


def analyze_flows(flows_df: pd.DataFrame, actions: List[ActionType] = None,
                 threshold: float = 0.5, action_config: dict = None,
                 anomaly_model: str = 'vae', debug: bool = False) -> DetectionResult:
    """Analyze flows through detection pipeline"""
    logger.info("Initializing Hybrid NIDS...")
    
    # Initialize NIDS
    nids = HybridNIDS(anomaly_threshold=-threshold, anomaly_model=anomaly_model)
    
    # Add debug logging for XGBoost predictions
    if debug:
        logger.info("DEBUG: Checking XGBoost predictions...")
        try:
            from nids.layers import XGBoostClassifier
            from nids.config import XGBOOST_MODEL_PATH
            xgb = XGBoostClassifier(model_path=XGBOOST_MODEL_PATH)
            if xgb.model is not None:
                import numpy as np
                X = xgb._prepare_features(flows_df)
                if X is not None and len(X) > 0:
                    X_scaled = xgb.scaler.transform(X) if xgb.scaler else X.values
                    preds = xgb.model.predict(X_scaled)
                    probs = xgb.model.predict_proba(X_scaled)
                    labels = [xgb.target_names[int(p)] for p in preds] if xgb.target_names else [str(p) for p in preds]
                    logger.info(f"DEBUG: XGBoost predictions for {len(preds)} flows:")
                    for i, (label, prob) in enumerate(zip(labels, probs)):
                        confidence = float(max(prob))
                        logger.info(f"  Flow {i}: {label} (confidence: {confidence:.2%})")
        except Exception as e:
            logger.warning(f"DEBUG: Could not check XGBoost predictions: {e}")
    
    # Create a dummy PCAP path (won't be used since we pass flows_df)
    from nids.config import PCAP_DIR
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    dummy_pcap = PCAP_DIR / "test_dummy.pcap"
    
    # Analyze flows (pass flows_df to skip PCAP extraction)
    logger.info("Running detection pipeline...")
    result = nids.analyze(dummy_pcap, flows_df=flows_df)
    
    # Process actions if config provided
    if action_config:
        from nids import ActionHandler
        handler = ActionHandler(config=action_config)
        handler.process(result)
    
    return result


def print_results(result: DetectionResult, flows_file: Path):
    """Print detection results in a formatted way"""
    print(f"\n{'='*70}")
    print(f"  DETECTION TEST RESULTS: {flows_file.name}")
    print(f"{'='*70}")
    print(f"  Total flows analyzed: {result.total_flows}")
    print(f"  Processing time: {result.processing_time:.2f}s")
    print(f"  Filtered (whitelist): {result.filtered_count}")
    
    # Calculate total attack flows
    total_attack_flows = sum(d.flow_count for d in result.detections)
    print(f"  Detections: {len(result.detections)} unique attacks ({total_attack_flows} flows)")
    
    if result.detections:
        print(f"\n  {'─'*68}")
        print(f"  DETECTED ATTACKS:")
        print(f"  {'─'*68}")
        
        # Group by threat level
        by_level = {}
        for d in result.detections:
            level = d.threat_level.name
            if level not in by_level:
                by_level[level] = []
            by_level[level].append(d)
        
        # Print by threat level (CRITICAL first)
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if level in by_level:
                print(f"\n  [{level}] {len(by_level[level])} unique attacks:")
                for d in sorted(by_level[level], key=lambda x: -x.confidence):
                    print(f"    • {d.attack_type:20s} | "
                          f"Confidence: {d.confidence:.2%} | "
                          f"Layer: {d.layer:15s} | "
                          f"Flows: {d.flow_count}")
                    print(f"      {d.src_ip}:{d.src_port} → {d.dst_ip}:{d.dst_port} ({d.protocol})")
        
        # Summary by layer
        print(f"\n  {'─'*68}")
        print(f"  DETECTION BY LAYER:")
        print(f"  {'─'*68}")
        by_layer = {}
        for d in result.detections:
            layer = d.layer
            if layer not in by_layer:
                by_layer[layer] = {'count': 0, 'flows': 0}
            by_layer[layer]['count'] += 1
            by_layer[layer]['flows'] += d.flow_count
        
        for layer in sorted(by_layer.keys()):
            info = by_layer[layer]
            print(f"    {layer:20s}: {info['count']:3d} unique attacks, {info['flows']:3d} flows")
        
        # Summary by attack type
        print(f"\n  {'─'*68}")
        print(f"  ATTACK TYPE SUMMARY:")
        print(f"  {'─'*68}")
        by_attack = {}
        for d in result.detections:
            attack = d.attack_type
            if attack not in by_attack:
                by_attack[attack] = {'count': 0, 'flows': 0, 'max_conf': 0.0}
            by_attack[attack]['count'] += 1
            by_attack[attack]['flows'] += d.flow_count
            by_attack[attack]['max_conf'] = max(by_attack[attack]['max_conf'], d.confidence)
        
        for attack in sorted(by_attack.keys(), key=lambda x: -by_attack[x]['flows']):
            info = by_attack[attack]
            print(f"    {attack:20s}: {info['count']:3d} detections, {info['flows']:3d} flows, "
                  f"max confidence: {info['max_conf']:.2%}")
    else:
        print(f"\n  ✓ No attacks detected (all flows are benign)")
    
    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Test detection pipeline with CSV flows file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic test
  python scripts/test_flows_detection.py --flows data/test/test_flows.csv
  
  # With actions enabled
  python scripts/test_flows_detection.py --flows data/test/test_flows.csv \\
      --action alert --action webhook --action email --action wazuh
  
  # Custom threshold
  python scripts/test_flows_detection.py --flows data/test/test_flows.csv \\
      --threshold 0.3
  
  # Use Isolation Forest instead of VAE
  python scripts/test_flows_detection.py --flows data/test/test_flows.csv \\
      --anomaly-model isolation_forest
  
  # Debug mode (show XGBoost predictions)
  python scripts/test_flows_detection.py --flows data/test/test_flows.csv \\
      --debug
        """
    )
    
    parser.add_argument('--flows', type=Path, required=True,
                       help='Path to flows CSV file')
    parser.add_argument('--threshold', type=float, default=0.5,
                       help='Anomaly detection threshold (default: 0.5)')
    parser.add_argument('--anomaly-model', type=str, choices=['vae', 'isolation_forest', 'iforest'],
                       default='vae', help='Anomaly detection model to use (default: vae)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging (show XGBoost predictions)')
    
    # Add all action configuration arguments using ActionConfigBuilder
    ActionConfigBuilder.add_all_arguments(parser)
    
    args = parser.parse_args()
    
    # Build action config
    action_config = None
    if args.actions:
        action_config = ActionConfigBuilder.build_from_args(args)
        logger.info(f"Actions enabled: {args.actions}")
    
    try:
        # Load flows
        flows_df = load_flows_csv(args.flows)
        
        # Convert actions to ActionType enum
        action_types = []
        if args.actions:
            for action_str in args.actions:
                try:
                    action_types.append(ActionType(action_str))
                except ValueError:
                    logger.warning(f"Invalid action: {action_str}")
        
        # Normalize anomaly model name
        anomaly_model = args.anomaly_model
        if anomaly_model == 'iforest':
            anomaly_model = 'isolation_forest'
        
        # Analyze flows
        result = analyze_flows(
            flows_df=flows_df,
            actions=action_types,
            threshold=args.threshold,
            action_config=action_config,
            anomaly_model=anomaly_model,
            debug=args.debug
        )
        
        # Print results
        print_results(result, args.flows)
        
        # Exit code based on detections
        if result.detections:
            print("⚠️  ATTACKS DETECTED - Test completed successfully")
            sys.exit(0)
        else:
            print("✓ No attacks detected - All flows appear benign")
            sys.exit(0)
            
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

