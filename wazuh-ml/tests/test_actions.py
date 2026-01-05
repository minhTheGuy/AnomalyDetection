#!/usr/bin/env python3
"""
test_actions.py - Test webhook, email, and wazuh action features

This script helps verify that webhook, email, and Wazuh integrations are working correctly.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
import os

# Load environment variables from .env file (python-dotenv)
# Must be done BEFORE importing nids modules that might use env vars
try:
    from dotenv import load_dotenv
    project_root = Path(__file__).parent.parent
    env_file = project_root / '.env'
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass  # python-dotenv not installed

# Setup logging early
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent))
from nids.models import FlowDetection, ThreatLevel
from nids.actions import ActionHandler
from nids.action_config import ActionConfigBuilder
import argparse


def create_test_detection():
    """Create a test FlowDetection for testing"""
    return FlowDetection(
        flow_id='test-123',
        src_ip='192.168.1.100',
        dst_ip='10.0.0.50',
        src_port=54321,
        dst_port=80,
        protocol='TCP',
        attack_type='DoS Attack (Test)',
        confidence=0.95,
        layer='test',
        threat_level=ThreatLevel.CRITICAL,
        flow_count=1
    )


def test_webhook(config: dict):
    """Test webhook functionality"""
    print("\n" + "="*60)
    print("Testing Webhook")
    print("="*60)
    
    webhook_url = config.get('webhook_url')
    if not webhook_url:
        print("❌ Webhook URL not configured")
        print("   Set WEBHOOK_URL environment variable or use --webhook-url")
        return False
    
    print(f"✓ Webhook URL: {webhook_url}")
    
    # Check if URL protocol matches Flask app (HTTP vs HTTPS)
    if webhook_url.startswith('https://') and ('localhost' in webhook_url or '127.0.0.1' in webhook_url):
        print(f"  ⚠️  Warning: Using HTTPS for localhost. If your Flask app runs on HTTP,")
        print(f"     change WEBHOOK_URL to http://localhost:5000/webhook")
        print(f"     (The script will auto-retry with HTTP if HTTPS fails)")
    
    try:
        action_config = {
            'enabled_actions': ['webhook'],
            'webhook_url': webhook_url
        }
        
        handler = ActionHandler(config=action_config)
        test_detection = create_test_detection()
        
        print(f"  Sending test detection to {webhook_url}...")
        
        # Capture logs to check if webhook succeeded
        import io
        import sys
        from contextlib import redirect_stderr, redirect_stdout
        
        log_capture = io.StringIO()
        with redirect_stderr(log_capture), redirect_stdout(log_capture):
            handler._action_webhook(test_detection)
        
        # Check if there were any errors in the logs
        log_output = log_capture.getvalue()
        if 'ERROR' in log_output or 'failed' in log_output.lower():
            print(f"  ❌ Webhook test failed")
            print(f"  Error details: {log_output}")
            return False
        
        print("  ✓ Webhook request sent successfully")
        print(f"  Check your Flask app console to confirm receipt")
        return True
        
    except Exception as e:
        print(f"  ❌ Webhook test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_email(config: dict):
    """Test email functionality"""
    print("\n" + "="*60)
    print("Testing Email")
    print("="*60)
    
    email_config = config.get('email')
    if not email_config or not email_config.get('to'):
        print("❌ Email configuration not found")
        print("   Configure email settings using environment variables or command-line args")
        print("   Required: EMAIL_TO, EMAIL_SMTP_HOST, EMAIL_USERNAME, EMAIL_PASSWORD")
        return False
    
    print(f"✓ SMTP Host: {email_config.get('smtp_host', 'not set')}")
    print(f"✓ SMTP Port: {email_config.get('smtp_port', 'not set')}")
    print(f"✓ To: {email_config.get('to')}")
    print(f"✓ From: {email_config.get('from', email_config.get('username', 'not set'))}")
    print(f"✓ Username: {email_config.get('username', 'not set')}")
    
    try:
        action_config = {
            'enabled_actions': ['email'],
            'email': email_config
        }
        
        handler = ActionHandler(config=action_config)
        test_detection = create_test_detection()
        
        print(f"  Sending test email to {email_config.get('to')}...")
        handler._action_email(test_detection)
        print("  ✓ Email sent successfully")
        print(f"  Check your inbox ({email_config.get('to')}) for the test email")
        return True
        
    except Exception as e:
        print(f"  ❌ Email test failed: {e}")
        import traceback
        traceback.print_exc()
        print(f"  Common issues:")
        print(f"    - Incorrect SMTP credentials")
        print(f"    - Gmail requires App Password (not regular password)")
        print(f"    - Firewall blocking SMTP port")
        print(f"    - Missing required fields: to, smtp_host, username, password")
        return False


def test_wazuh(config: dict):
    """Test Wazuh functionality"""
    print("\n" + "="*60)
    print("Testing Wazuh")
    print("="*60)
    
    wazuh_config = config.get('wazuh', {})
    if not wazuh_config:
        print("❌ Wazuh configuration not found")
        print("   Configure Wazuh settings using environment variables or command-line args")
        print("   Required: WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD")
        return False
    
    method = wazuh_config.get('method', 'auto')
    print(f"✓ Method: {method}")
    
    if wazuh_config.get('api_url'):
        print(f"✓ API URL: {wazuh_config.get('api_url')}")
    if wazuh_config.get('api_user'):
        print(f"✓ API User: {wazuh_config.get('api_user')}")
    if wazuh_config.get('socket_path'):
        print(f"✓ Socket Path: {wazuh_config.get('socket_path')}")
    
    try:
        action_config = {
            'enabled_actions': ['wazuh'],
            'wazuh': wazuh_config
        }
        
        handler = ActionHandler(config=action_config)
        test_detection = create_test_detection()
        
        print(f"  Sending test detection to Wazuh ({method})...")
        handler._action_wazuh(test_detection)
        print("  ✓ Wazuh test completed")
        print(f"  Check Wazuh Manager logs/events to confirm receipt")
        return True
        
    except Exception as e:
        print(f"  ❌ Wazuh test failed: {e}")
        import traceback
        traceback.print_exc()
        print(f"  Common issues:")
        print(f"    - Wazuh Manager not accessible")
        print(f"    - Incorrect API credentials")
        print(f"    - Socket path incorrect (if using socket method)")
        print(f"    - Missing required fields: api_url, api_user, api_password")
        return False


def check_action_logs():
    """Check action logs file for recent activity"""
    print("\n" + "="*60)
    print("Checking Action Logs")
    print("="*60)
    
    from nids import LOGS_DIR
    log_file = LOGS_DIR / 'action_logs.jsonl'
    
    if not log_file.exists():
        print(f"  ℹ️  No action logs found at {log_file}")
        return
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        if not lines:
            print(f"  ℹ️  Action log file is empty")
            return
        
        print(f"  ✓ Found {len(lines)} log entries")
        print(f"\n  Last 5 entries:")
        for line in lines[-5:]:
            try:
                entry = json.loads(line)
                action = entry.get('action', 'unknown')
                timestamp = entry.get('timestamp', 'unknown')
                print(f"    - [{timestamp}] {action}")
            except:
                pass
                
    except Exception as e:
        print(f"  ❌ Error reading logs: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Test webhook, email, and wazuh actions',
        epilog="""
Environment Variables:
  All configuration can be set via .env file or environment variables.
  The script automatically loads from .env file in the project root.
  
  See config/action_config.env.example for all available variables.
        """
    )
    
    # Add all action configuration arguments
    # These will use environment variables as defaults if not provided
    ActionConfigBuilder.add_all_arguments(parser)
    
    parser.add_argument('--test', choices=['webhook', 'email', 'wazuh', 'all'], 
                       default='all', help='Which test to run (default: all)')
    parser.add_argument('--check-logs', action='store_true', 
                       help='Also check action logs for recent activity')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed configuration information')
    
    args = parser.parse_args()
    
    # Ensure actions are set for testing (required by ActionConfigBuilder)
    if not args.actions:
        # If no actions specified, add the ones we're testing
        if args.test == 'webhook':
            args.actions = ['webhook']
        elif args.test == 'email':
            args.actions = ['email']
        elif args.test == 'wazuh':
            args.actions = ['wazuh']
        elif args.test == 'all':
            args.actions = ['webhook', 'email', 'wazuh']
    
    # Build configuration from arguments and environment
    # ActionConfigBuilder automatically reads from environment variables
    # when command-line arguments are not provided
    try:
        config = ActionConfigBuilder.build_from_args(args)
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Make sure required environment variables are set in .env file")
        logger.error("For email: EMAIL_TO, EMAIL_SMTP_HOST, EMAIL_USERNAME, EMAIL_PASSWORD")
        logger.error("For Wazuh: WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD")
        sys.exit(1)
    
    print("="*60)
    print("Action Features Test")
    print("="*60)
    
    # Show configuration if verbose
    if args.verbose:
        print("\nConfiguration loaded from environment/arguments:")
        if config.get('webhook_url'):
            print(f"  ✓ Webhook URL: {config.get('webhook_url')}")
        else:
            print(f"  ✗ Webhook URL: not configured")
        if config.get('email'):
            email = config.get('email', {})
            print(f"  ✓ Email: {email.get('to', 'not set')} via {email.get('smtp_host', 'not set')}")
        else:
            print(f"  ✗ Email: not configured")
        if config.get('wazuh'):
            wazuh = config.get('wazuh', {})
            print(f"  ✓ Wazuh: {wazuh.get('api_url', 'not set')} (method: {wazuh.get('method', 'auto')})")
        else:
            print(f"  ✗ Wazuh: not configured")
        print()
    
    print(f"Testing: {args.test}")
    
    results = {}
    
    if args.test in ['webhook', 'all']:
        results['webhook'] = test_webhook(config)
    
    if args.test in ['email', 'all']:
        results['email'] = test_email(config)
    
    if args.test in ['wazuh', 'all']:
        results['wazuh'] = test_wazuh(config)
    
    if args.check_logs:
        check_action_logs()
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    for feature, success in results.items():
        status = "✓ PASS" if success else "❌ FAIL"
        print(f"  {feature:12} {status}")
    
    if all(results.values()):
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed. Check configuration and try again.")
        return 1


if __name__ == '__main__':
    sys.exit(main())

