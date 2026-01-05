"""
webhook_config.py - Webhook configuration parsing and validation
"""

import logging
from typing import Optional, Dict
from argparse import Namespace
import os

from ..models import ActionType

logger = logging.getLogger(__name__)


class WebhookConfig:
    """Webhook configuration parser and validator"""
    
    @staticmethod
    def from_args(args: Namespace) -> Optional[Dict]:
        """Build webhook configuration from command-line arguments"""
        # Check if webhook action is in args.actions (which is a list of strings)
        actions_list = args.actions or []
        if ActionType.WEBHOOK.value not in actions_list and ActionType.WEBHOOK not in actions_list:
            return None
        
        # Use args value (which comes from env var as default) or fall back to env var
        webhook_url = getattr(args, 'webhook_url', None)
        if webhook_url is None:
            webhook_url = os.getenv('WEBHOOK_URL')
        
        if not webhook_url:
            return None  # Don't raise error, just return None if not configured
        
        return {
            'webhook_url': webhook_url
        }
    
    @staticmethod
    def add_arguments(parser):
        """Add webhook-related arguments to argument parser"""
        parser.add_argument(
            '--webhook-url',
            default=os.getenv('WEBHOOK_URL'),
            help='Webhook URL for notifications (default: from WEBHOOK_URL env var)'
        )
    
    @staticmethod
    def validate(config: Optional[Dict]) -> bool:
        """Validate webhook configuration"""
        if config is None:
            return True
        
        if not config.get('webhook_url'):
            logger.error("Webhook configuration missing 'webhook_url'")
            return False
        
        url = config['webhook_url']
        if not url.startswith(('http://', 'https://')):
            logger.error(f"Webhook URL must start with http:// or https://: {url}")
            return False
        
        return True

