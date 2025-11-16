"""
Action Executor - Thực thi các actions
"""
import os
import json
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import pandas as pd
from enum import Enum

from actions.action_generator import ActionType
from utils.common import ensure_dir


def _create_result(success: bool, message: str, **kwargs) -> Dict:
    """Helper: Tạo result dict với timestamp"""
    result = {
        'success': success,
        'message': message,
        'timestamp': datetime.now().isoformat(),
    }
    result.update(kwargs)
    return result


def _execute_pfsense_action(action_type: str, action: Dict, executor) -> Dict:
    """Helper: Execute pfSense action (block IP hoặc port)"""
    if not executor.enable_pfsense:
        return _create_result(
            False,
            'pfSense not enabled. Enable with ENABLE_PFSENSE=true',
            block_info={'status': 'pfSense_not_configured'}
        )
    
    try:
        from actions.pfsense_integration import get_pfsense_client
        pfsense = get_pfsense_client(method=executor.pfsense_method)
        
        if not pfsense:
            return _create_result(False, 'Failed to get pfSense client')
        
        params = action.get('params', {})
        
        if action_type == 'block_ip':
            ip = params.get('ip')
            if not ip:
                return _create_result(False, 'No IP address provided')
            
            if executor.pfsense_method == 'ssh':
                result = pfsense.block_ip_pfctl(ip)
            else:
                duration = params.get('duration', 3600)
                reason = params.get('reason', 'Security threat detected')
                result = pfsense.block_ip(ip, duration=duration, reason=reason)
        
        elif action_type == 'block_port':
            port = params.get('port')
            if not port:
                return _create_result(False, 'No port provided')
            
            ip = params.get('ip')
            duration = params.get('duration', 3600)
            result = pfsense.block_port(port, ip=ip, duration=duration)
        
        else:
            return _create_result(False, f'Unknown action type: {action_type}')
        
        if result.get('success'):
            return _create_result(
                True,
                result.get('message', f'{action_type} executed successfully'),
                block_info=result
            )
        else:
            return _create_result(
                False,
                f'pfSense {action_type} failed: {result.get("message")}'
            )
    
    except Exception as e:
        return _create_result(False, f'pfSense integration error: {str(e)}')


def _json_serialize(obj: Any) -> Any:
    """Convert non-serializable objects to JSON-serializable format"""
    if isinstance(obj, pd.Timestamp):
        return obj.isoformat()
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Enum):
        return obj.value
    elif isinstance(obj, dict):
        return {k: _json_serialize(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_json_serialize(item) for item in obj]
    elif pd.isna(obj):
        return None
    else:
        return obj


class ActionExecutor:
    """Executor cho các actions"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize action executor
        
        Args:
            config: Configuration dict
        """
        self.config = config or {}
        self.telegram_bot_token = self.config.get('telegram_bot_token') or os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_chat_id = self.config.get('telegram_chat_id') or os.getenv('TELEGRAM_CHAT_ID')
        self.action_log_path = self.config.get('action_log_path', 'data/action_logs.jsonl')
        
        # pfSense configuration
        self.enable_pfsense = self.config.get('enable_pfsense', False) or os.getenv('ENABLE_PFSENSE', 'false').lower() == 'true'
        self.pfsense_method = self.config.get('pfsense_method', 'ssh') or os.getenv('PFSENSE_METHOD', 'ssh')
        
        # Đảm bảo thư mục tồn tại
        ensure_dir(self.action_log_path)
    
    def execute_action(self, action: Dict) -> Dict:
        """
        Thực thi một action
        
        Args:
            action: Action dict từ ActionGenerator
            
        Returns:
            Dict với kết quả: {'success': bool, 'message': str, 'timestamp': str}
        """
        action_type = ActionType(action['type'])
        result = {
            'success': False,
            'message': '',
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type.value,
        }
        
        try:
            if action_type == ActionType.LOG:
                result = self._execute_log(action)
            elif action_type == ActionType.ALERT:
                result = self._execute_alert(action)
            elif action_type == ActionType.NOTIFY_TELEGRAM:
                result = self._execute_telegram_notify(action)
            elif action_type == ActionType.BLOCK_IP:
                result = self._execute_block_ip(action)
            elif action_type == ActionType.BLOCK_PORT:
                result = self._execute_block_port(action)
            elif action_type == ActionType.ESCALATE:
                result = self._execute_escalate(action)
            else:
                result['message'] = f'Unknown action type: {action_type}'
        
        except Exception as e:
            result['success'] = False
            result['message'] = f'Error executing action: {str(e)}'
        
        # Log action result
        self._log_action(action, result)
        
        return result
    
    def _execute_log(self, action: Dict) -> Dict:
        """Execute LOG action"""
        return _create_result(True, 'Logged successfully')
    
    def _execute_alert(self, action: Dict) -> Dict:
        """Execute ALERT action"""
        message = f"ALERT: {action.get('reason', 'Unknown alert')}"
        print(f"  {message}")
        return _create_result(True, f'Alert logged: {message}')
    
    def _execute_telegram_notify(self, action: Dict) -> Dict:
        """Execute TELEGRAM NOTIFY action"""
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return _create_result(False, 'Telegram bot token or chat ID not configured')
        
        params = action.get('params', {})
        message = params.get('message', action.get('reason', 'Unknown alert'))
        chat_id = params.get('chat_id') or self.telegram_chat_id
        bot_token = params.get('bot_token') or self.telegram_bot_token
        
        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'Markdown',
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            return _create_result(True, f'Telegram notification sent to chat {chat_id}')
        except Exception as e:
            return _create_result(False, f'Failed to send Telegram notification: {str(e)}')
    
    def _execute_block_ip(self, action: Dict) -> Dict:
        """Execute BLOCK IP action trên pfSense firewall"""
        return _execute_pfsense_action('block_ip', action, self)
    
    def _execute_block_port(self, action: Dict) -> Dict:
        """Execute BLOCK PORT action trên pfSense firewall"""
        return _execute_pfsense_action('block_port', action, self)
    
    def _execute_escalate(self, action: Dict) -> Dict:
        """Execute ESCALATE action"""
        message = f"ESCALATION: {action.get('reason', 'Unknown escalation')}"
        # Có thể tích hợp với: Email, SMS, PagerDuty, OpsGenie, etc.
        return _create_result(True, f'Escalation sent: {message}')
    
    def _log_action(self, action: Dict, result: Dict):
        """Log action và result vào file"""
        log_entry = {
            'action': action,
            'result': result,
            'logged_at': datetime.now().isoformat(),
        }
        
        # Serialize để đảm bảo tất cả objects đều JSON-compatible
        log_entry_serialized = _json_serialize(log_entry)
        
        with open(self.action_log_path, 'a') as f:
            f.write(json.dumps(log_entry_serialized) + '\n')
    
    def execute_actions_batch(self, actions_df: pd.DataFrame) -> pd.DataFrame:
        """
        Thực thi nhiều actions
        
        Args:
            actions_df: DataFrame từ ActionGenerator.generate_actions_batch()
            
        Returns:
            DataFrame với kết quả execution
        """
        results = []
        
        for idx, row in actions_df.iterrows():
            action = {
                'type': row['action_type'],
                'target': row['target'],
                'reason': row['reason'],
                'severity': row['severity'],
                'params': row['params'] if isinstance(row['params'], dict) else {},
            }
            
            result = self.execute_action(action)
            result['anomaly_index'] = row['anomaly_index']
            result['action_index'] = idx
            results.append(result)
        
        return pd.DataFrame(results)

