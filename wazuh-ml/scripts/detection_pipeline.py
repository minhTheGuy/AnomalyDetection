"""
detection_pipeline.py - 3-Layer Hybrid NIDS Entry Point

This is the main entry point for the Hybrid Network Intrusion Detection System.
All core functionality is now organized in the nids/ module.

Layers:
    1. Suricata (SNIDS) - Signature-based detection
    2. XGBoost (Classifier) - Known attack pattern detection  
    3. VAE (Anomaly) - Zero-day detection using Variational Autoencoder

Actions: log, alert, block (pfSense), webhook, email, wazuh

Usage:
    # Analyze PCAP file
    python detection_pipeline.py --pcap capture.pcap
    
    # Real-time with blocking
    python detection_pipeline.py --realtime --interval 60 --action block
    
    # Continuous detection
    python detection_pipeline.py --continuous --action alert --action block

See nids/ module for implementation details.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List

# Load environment variables from .env file (python-dotenv)
# This loads automatically before any imports that might need env vars
try:
    from dotenv import load_dotenv
    # Try loading .env from project root
    project_root = Path(__file__).parent.parent
    env_file = project_root / '.env'
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass  # python-dotenv not installed

# Import from modular nids package
from nids import (
    ActionType,
    HybridNIDS,
    DetectionPipeline,
    DetectionResult,
    PCAP_DIR,
)
from nids.action_config import ActionConfigBuilder


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def analyze_pcap(pcap_file: Path, actions: List[ActionType], 
                 threshold: float = 0.5, action_config: dict = None) -> DetectionResult:
    """Analyze a single PCAP file"""
    logger.info(f"Analyzing PCAP: {pcap_file}")
    
    # Initialize NIDS
    nids = HybridNIDS(anomaly_threshold=-threshold, anomaly_model='vae')
    
    # Extract flows and analyze
    result = nids.analyze(pcap_file)
    
    # Process actions if config provided
    if action_config:
        from nids import ActionHandler
        handler = ActionHandler(config=action_config)
        handler.process(result)
    
    # Print results
    print(f"\n{'='*60}")
    print(f"  PCAP Analysis: {pcap_file.name}")
    print(f"{'='*60}")
    print(f"  Total flows: {result.total_flows}")
    print(f"  Processing time: {result.processing_time:.2f}s")
    
    # Calculate total attack flows
    total_attack_flows = sum(d.flow_count for d in result.detections)
    print(f"  Detections: {len(result.detections)} unique ({total_attack_flows} flows)")
    
    if result.detections:
        print(f"\n  Threats by level:")
        by_level = {}
        for d in result.detections:
            by_level.setdefault(d.threat_level.name, []).append(d)
        
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if level in by_level:
                level_flows = sum(d.flow_count for d in by_level[level])
                print(f"    [{level}] {len(by_level[level])} detections ({level_flows} flows)")
        
        print(f"\n  Top threats:")
        for d in sorted(result.detections, 
                       key=lambda x: x.confidence, reverse=True)[:5]:
            print(f"    - {d.attack_type}: {d.src_ip} -> {d.dst_ip} "
                  f"({d.flow_count} flows, confidence: {d.confidence:.2%}, layer: {d.layer})")
    
    print(f"{'='*60}\n")
    return result




def run_continuous(host: str, user: str, interface: str,
                   actions: List[ActionType], interval: int,
                   threshold: float,
                   block_duration: int = 300, streaming: bool = False,
                   action_config: dict = None):
    """Run continuous detection loop"""
    
    # Use provided action_config or create default
    if action_config is None:
        action_config = {
            'enabled_actions': actions,
            'block_threshold': 'HIGH',
            'block_duration': block_duration,
        }
        
    # Initialize pipeline
    pipeline = DetectionPipeline(
        pfsense_host=host,
        pfsense_user=user,
        pfsense_interface=interface,
        capture_duration=interval,
        action_config=action_config,
        anomaly_threshold=-threshold,
        anomaly_model='vae',
        streaming=streaming  # Enable parallel capture/analysis
    )
    
    # Start continuous monitoring
    pipeline.start()


def main():
    parser = argparse.ArgumentParser(
        description='3-Layer Hybrid NIDS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze PCAP file
  python detection_pipeline.py --pcap capture.pcap
  
  # Single realtime capture (60s)
  python detection_pipeline.py --realtime --interval 60 --action alert
  
  # Continuous monitoring with blocking
  python detection_pipeline.py --continuous --action alert --action block
  
  # With webhook notifications
  python detection_pipeline.py --continuous \\
      --action alert --action webhook \\
      --webhook-url https://your-webhook.com/api/alerts
  
  # With email alerts (CRITICAL threats only)
  python detection_pipeline.py --continuous \\
      --action alert --action email \\
      --email-to admin@example.com \\
      --email-from nids@example.com \\
      --email-smtp-host smtp.gmail.com \\
      --email-smtp-port 587 \\
      --email-username your-email@gmail.com \\
      --email-password your-app-password
  
  # With Wazuh integration
  python detection_pipeline.py --continuous \\
      --action alert --action wazuh \\
      --wazuh-api-url https://wazuh-manager:55000 \\
      --wazuh-api-user wazuh \\
      --wazuh-api-password your-password
  
  # Full deployment with all actions
  python detection_pipeline.py --continuous \\
      --host 172.16.158.100 --user admin --interface em1 \\
      --action log --action alert --action block \\
      --action webhook --action email --action wazuh \\
      --webhook-url https://your-webhook.com/api/alerts \\
      --email-to admin@example.com --email-from nids@example.com \\
      --email-smtp-host smtp.gmail.com --email-username user@gmail.com \\
      --wazuh-api-url https://wazuh-manager:55000 \\
      --block-duration 300
        """)
    
    # Mode selection
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--pcap', type=Path, help='Analyze PCAP file')
    mode.add_argument('--continuous', action='store_true', 
                      help='Continuous monitoring mode')
    
    # Detection settings (defaults from environment variables)
    import os
    parser.add_argument('--interval', type=int, 
                        default=int(os.getenv('DETECTION_INTERVAL', '15')),
                        help='Capture interval in seconds (default: from DETECTION_INTERVAL env or 15)')
    parser.add_argument('--streaming', action='store_true',
                        help='Enable streaming mode (parallel capture/analysis)')
    parser.add_argument('--threshold', type=float,
                        default=float(os.getenv('DETECTION_THRESHOLD', '0.5')),
                        help='Detection threshold (default: from DETECTION_THRESHOLD env or 0.5)')
    
    # Add all action configuration arguments using ActionConfigBuilder (--action)
    ActionConfigBuilder.add_all_arguments(parser)
    
    # pfSense connection (defaults from environment variables)
    import os
    parser.add_argument('--host', default=os.getenv('PFSENSE_HOST', '172.16.158.100'),
                        help='pfSense host IP (default: from PFSENSE_HOST env or 172.16.158.100)')
    parser.add_argument('--user', default=os.getenv('PFSENSE_USER', 'admin'),
                        help='SSH username (default: from PFSENSE_USER env or admin)')
    parser.add_argument('--interface', default=os.getenv('PFSENSE_INTERFACE', 'em1'),
                        help='Network interface to capture (default: from PFSENSE_INTERFACE env or em1)')

    args = parser.parse_args()
    
    # Build action configuration using ActionConfigBuilder
    try:
        action_config = ActionConfigBuilder.build_from_args(args)
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    
    # Parse actions for use in function calls
    actions = action_config['enabled_actions']
    
    # Execute selected mode
    if args.pcap:
        if not args.pcap.exists():
            logger.error(f"File not found: {args.pcap}")
            sys.exit(1)
        analyze_pcap(args.pcap, actions, args.threshold, action_config)
    
    elif args.continuous:
        run_continuous(
            host=args.host,
            user=args.user,
            interface=args.interface,
            actions=actions,
            interval=args.interval,
            threshold=args.threshold,
            block_duration=args.block_duration,
            streaming=args.streaming,
            action_config=action_config
        )


if __name__ == '__main__':
    main()
