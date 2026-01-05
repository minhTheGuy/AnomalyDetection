"""
action_config_builder.py - Build action configuration from command-line arguments
"""

import logging
from typing import Dict, Optional
from argparse import Namespace, ArgumentParser
import os
from ..models import ActionType
from .webhook_config import WebhookConfig
from .email_config import EmailConfig
from .wazuh_config import WazuhConfig

logger = logging.getLogger(__name__)


class ActionConfigBuilder:
    """Build action configuration dictionary from command-line arguments"""
    
    @staticmethod
    def add_all_arguments(parser: ArgumentParser):
        """Add all action-related arguments to parser"""
        # Webhook arguments
        WebhookConfig.add_arguments(parser)
        
        # Email arguments
        EmailConfig.add_arguments(parser)
        
        # Wazuh arguments
        WazuhConfig.add_arguments(parser)
        
        # Common action arguments
        parser.add_argument(
            '--action',
            action='append',
            dest='actions',
            choices=['log', 'alert', 'block', 'webhook', 'email', 'wazuh'],
            help='Actions to execute on detection (can specify multiple)'
        )
        parser.add_argument(
            '--block-duration',
            type=int,
            default=os.getenv('BLOCK_DURATION', '300'),
            help='Auto-unblock after N seconds (default: from BLOCK_DURATION env or 300)'
        )
    
    @staticmethod
    def build_from_args(args: Namespace, block_threshold: str = 'HIGH') -> Dict:
        """
        Build complete action configuration from parsed arguments
        
        Args:
            args: Parsed command-line arguments
            block_threshold: Block threshold level (default: HIGH)
        
        Returns:
            Dictionary with action configuration
        
        Raises:
            ValueError: If required configuration is missing
        """
        # Parse actions
        actions = [ActionType(a) for a in (args.actions or ['log', 'alert'])]
        
        # Build base configuration
        config = {
            'enabled_actions': actions,
            'block_threshold': block_threshold,
            'block_duration': getattr(args, 'block_duration', 300),
        }
        
        # Build webhook configuration
        try:
            webhook_config = WebhookConfig.from_args(args)
            if webhook_config and webhook_config.get('webhook_url'):
                if not WebhookConfig.validate(webhook_config):
                    raise ValueError("Invalid webhook configuration")
                config['webhook_url'] = webhook_config['webhook_url']
        except ValueError as e:
            logger.error(str(e))
            raise
        
        # Build email configuration
        try:
            email_config = EmailConfig.from_args(args)
            if email_config:
                if not EmailConfig.validate(email_config):
                    raise ValueError("Invalid email configuration")
                config['email'] = email_config
        except ValueError as e:
            logger.error(str(e))
            raise
        
        # Build Wazuh configuration
        try:
            wazuh_config = WazuhConfig.from_args(args)
            if wazuh_config:
                if not WazuhConfig.validate(wazuh_config):
                    logger.warning("Wazuh configuration validation failed, but continuing")
                config['wazuh'] = wazuh_config
            elif ActionType.WAZUH in actions:
                # Empty config is OK for Wazuh - will use environment variables
                config['wazuh'] = {}
        except ValueError as e:
            logger.error(str(e))
            raise
        
        return config
    
    @staticmethod
    def validate_config(config: Dict) -> bool:
        """Validate complete action configuration"""
        # Validate individual components
        if 'webhook_url' in config and not WebhookConfig.validate({'webhook_url': config['webhook_url']}):
            return False
        
        if 'email' in config and not EmailConfig.validate(config['email']):
            return False
        
        if 'wazuh' in config and not WazuhConfig.validate(config['wazuh']):
            return False
        
        return True

