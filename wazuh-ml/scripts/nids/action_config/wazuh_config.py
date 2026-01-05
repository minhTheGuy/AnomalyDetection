"""
wazuh_config.py - Wazuh configuration parsing and validation
"""

import os
import logging
from typing import Optional, Dict
from argparse import Namespace

from ..models import ActionType

logger = logging.getLogger(__name__)


class WazuhConfig:
    """Wazuh configuration parser and validator"""
    
    @staticmethod
    def from_args(args: Namespace) -> Optional[Dict]:
        """Build Wazuh configuration from command-line arguments"""
        # Check if wazuh action is in args.actions (which is a list of strings)
        actions_list = args.actions or []
        if ActionType.WAZUH.value not in actions_list and ActionType.WAZUH not in actions_list:
            return None
        
        config = {}
        
        # API configuration (from args or env vars)
        api_url = getattr(args, 'wazuh_api_url', None)
        if api_url is None:
            api_url = os.getenv('WAZUH_API_URL')
        
        api_user = getattr(args, 'wazuh_api_user', None)
        if api_user is None:
            api_user = os.getenv('WAZUH_API_USER')
        
        api_password = getattr(args, 'wazuh_api_password', None)
        if api_password is None:
            api_password = os.getenv('WAZUH_API_PASSWORD')
        
        if api_url:
            config['api_url'] = api_url
        if api_user:
            config['api_user'] = api_user
        if api_password:
            config['api_password'] = api_password
        
        # Socket configuration
        socket_path = getattr(args, 'wazuh_socket_path', None)
        if socket_path is None:
            socket_path = os.getenv('WAZUH_SOCKET_PATH')
        if socket_path:
            config['socket_path'] = socket_path
        
        # Method configuration
        method = getattr(args, 'wazuh_method', None)
        if method is None:
            method = os.getenv('WAZUH_METHOD', 'auto')
        if method != 'auto':
            config['method'] = method
        
        return config if config else {}
    
    @staticmethod
    def add_arguments(parser):
        """Add Wazuh-related arguments to argument parser"""
        import os
        wazuh_group = parser.add_argument_group('wazuh', 'Wazuh SIEM integration configuration')
        wazuh_group.add_argument(
            '--wazuh-api-url',
            default=os.getenv('WAZUH_API_URL'),
            help='Wazuh API URL (default: from WAZUH_API_URL env var)'
        )
        wazuh_group.add_argument(
            '--wazuh-api-user',
            default=os.getenv('WAZUH_API_USER'),
            help='Wazuh API username (default: from WAZUH_API_USER env var)'
        )
        wazuh_group.add_argument(
            '--wazuh-api-password',
            default=os.getenv('WAZUH_API_PASSWORD'),
            help='Wazuh API password (default: from WAZUH_API_PASSWORD env var)'
        )
        wazuh_group.add_argument(
            '--wazuh-socket-path',
            default=os.getenv('WAZUH_SOCKET_PATH'),
            help='Wazuh socket path (default: from WAZUH_SOCKET_PATH env var)'
        )
        wazuh_group.add_argument(
            '--wazuh-method',
            choices=['socket', 'api', 'log', 'auto'],
            default=os.getenv('WAZUH_METHOD', 'auto'),
            help='Wazuh connection method (default: from WAZUH_METHOD env or auto)'
        )
    
    @staticmethod
    def validate(config: Optional[Dict]) -> bool:
        """Validate Wazuh configuration"""
        if config is None or not config:
            # Empty config is OK - will use environment variables
            return True
        
        # If API URL is provided, check format
        api_url = config.get('api_url')
        if api_url and not api_url.startswith(('http://', 'https://')):
            logger.warning(f"Wazuh API URL should start with http:// or https://: {api_url}")
        
        # If method is specified, ensure required config is present
        method = config.get('method', 'auto')
        if method == 'api':
            if not api_url:
                logger.warning("Wazuh method is 'api' but no api_url provided, will use environment variables")
        elif method == 'socket':
            if not config.get('socket_path'):
                logger.warning("Wazuh method is 'socket' but no socket_path provided, will auto-detect")
        
        return True

