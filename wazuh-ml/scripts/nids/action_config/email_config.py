"""
email_config.py - Email configuration parsing and validation
"""

import logging
from typing import Optional, Dict
from argparse import Namespace
import os

from ..models import ActionType

logger = logging.getLogger(__name__)


class EmailConfig:
    """Email configuration parser and validator"""
    
    @staticmethod
    def from_args(args: Namespace) -> Optional[Dict]:
        """Build email configuration from command-line arguments"""
        # Check if email action is in args.actions (which is a list of strings)
        actions_list = args.actions or []
        if ActionType.EMAIL.value not in actions_list and ActionType.EMAIL not in actions_list:
            return None
        
        # Use args values (which come from env vars as defaults) or fall back to env vars
        # getattr returns the default if attribute doesn't exist, so we check if it's None explicitly
        email_to = getattr(args, 'email_to', None)
        if email_to is None:
            email_to = os.getenv('EMAIL_TO')
        
        email_from = getattr(args, 'email_from', None)
        if email_from is None:
            email_from = os.getenv('EMAIL_FROM')
        
        smtp_host = getattr(args, 'email_smtp_host', None)
        if smtp_host is None:
            smtp_host = os.getenv('EMAIL_SMTP_HOST', 'localhost')
        
        smtp_port = getattr(args, 'email_smtp_port', None)
        if smtp_port is None:
            smtp_port = int(os.getenv('EMAIL_SMTP_PORT', '587'))
        else:
            smtp_port = int(smtp_port)
        
        config = {
            'to': email_to,
            'from': email_from,
            'smtp_host': smtp_host,
            'smtp_port': smtp_port,
        }
        
        # Add authentication if provided (from args or env vars)
        username = getattr(args, 'email_username', None)
        if username is None:
            username = os.getenv('EMAIL_USERNAME')
        
        password = getattr(args, 'email_password', None)
        if password is None:
            password = os.getenv('EMAIL_PASSWORD')
        
        if username:
            config['username'] = username
        if password:
            config['password'] = password
        
        # Return None if required 'to' field is missing
        if not config.get('to'):
            return None
        
        return config
    
    @staticmethod
    def add_arguments(parser):
        """Add email-related arguments to argument parser"""
        email_group = parser.add_argument_group('email', 'Email alert configuration')
        email_group.add_argument(
            '--email-to',
            default=os.getenv('EMAIL_TO'),
            help='Email recipient address (default: from EMAIL_TO env var)'
        )
        email_group.add_argument(
            '--email-from',
            default=os.getenv('EMAIL_FROM'),
            help='Email sender address (default: from EMAIL_FROM env var or username)'
        )
        email_group.add_argument(
            '--email-smtp-host',
            default=os.getenv('EMAIL_SMTP_HOST', 'localhost'),
            help='SMTP server hostname (default: from EMAIL_SMTP_HOST env or localhost)'
        )
        email_group.add_argument(
            '--email-smtp-port',
            type=int,
            default=int(os.getenv('EMAIL_SMTP_PORT', '587')),
            help='SMTP server port (default: from EMAIL_SMTP_PORT env or 587)'
        )
        email_group.add_argument(
            '--email-username',
            default=os.getenv('EMAIL_USERNAME'),
            help='SMTP username (default: from EMAIL_USERNAME env var)'
        )
        email_group.add_argument(
            '--email-password',
            default=os.getenv('EMAIL_PASSWORD'),
            help='SMTP password (default: from EMAIL_PASSWORD env var)'
        )
    
    @staticmethod
    def validate(config: Optional[Dict]) -> bool:
        """Validate email configuration"""
        if config is None:
            return True
        
        if not config.get('to'):
            logger.error("Email configuration missing 'to' address")
            return False
        
        # Validate email format (basic)
        to_addr = config['to']
        if '@' not in to_addr:
            logger.error(f"Invalid email address format: {to_addr}")
            return False
        
        # Validate SMTP port
        port = config.get('smtp_port', 587)
        if not (1 <= port <= 65535):
            logger.error(f"Invalid SMTP port: {port}")
            return False
        
        return True

