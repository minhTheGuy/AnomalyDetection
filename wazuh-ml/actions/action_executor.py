"""
Action Executor - Thực thi các actions
"""
import os
import json
from typing import Callable, Dict, List, Optional, Any
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


def _schedule_unblock_if_needed(result: Dict, params: Dict, scheduler, action_type: str) -> Dict:
    """Helper: Schedule unblock nếu có duration"""
    duration = params.get('duration', 0)
    if not result.get('success') or duration <= 0 or not scheduler:
        return result
    
    ip = params.get('ip')
    port = params.get('port')
    table_name = params.get('table_name', 'blocked_ips')
    
    if action_type in ['block_ip', 'reject_ip'] and ip:
        rule_id = f"ip_{ip}_{int(datetime.now().timestamp())}"
        schedule_result = scheduler.schedule_unblock(
            ip=ip, duration=duration, table_name=table_name, rule_id=rule_id
        )
    elif action_type in ['block_port', 'reject_port'] and port:
        rule_id = f"port_{port}_{ip or 'all'}_{int(datetime.now().timestamp())}"
        schedule_result = scheduler.schedule_unblock(
            ip=ip, port=port, duration=duration, rule_id=rule_id
        )
    else:
        return result
    
    result['scheduled_unblock'] = schedule_result
    return result


def _ensure_param(field: str):
    def validator(params: Dict) -> Optional[str]:
        value = params.get(field)
        if value is None:
            return f'No {field} provided'
        if isinstance(value, str) and not value.strip():
            return f'No {field} provided'
        return None
    return validator


def _ssh_block_ip(client, params):
    return client.block_ip_pfctl(
        params['ip'],
        params.get('table_name', 'blocked_ips'),
        params.get('action', 'block'),
        params.get('interface', 'lan'),
    )


def _ssh_block_port(client, params):
    return client.block_port_pfctl(
        params['port'],
        params.get('ip'),
        params.get('action', 'block'),
        params.get('interface', 'lan'),
    )


def _api_block_ip(client, params):
    return client.block_ip(
        params['ip'],
        params.get('duration', 0),
        params.get('reason', 'Security threat detected')
    )


def _api_block_port(client, params):
    return client.block_port(
        params['port'],
        params.get('ip'),
        params.get('duration', 0)
    )


_PFSENSE_VALIDATORS = {
    'block_ip': _ensure_param('ip'),
    'reject_ip': _ensure_param('ip'),
    'block_port': _ensure_param('port'),
    'reject_port': _ensure_param('port'),
}


_PFSENSE_EXECUTORS: Dict[str, Dict[str, Callable]] = {
    'ssh': {
        'block_ip': _ssh_block_ip,
        'reject_ip': _ssh_block_ip,
        'block_port': _ssh_block_port,
        'reject_port': _ssh_block_port,
    },
    'api': {
        'block_ip': _api_block_ip,
        'reject_ip': _api_block_ip,
        'block_port': _api_block_port,
        'reject_port': _api_block_port,
    }
}


def _execute_pfsense_action(action_type: str, action: Dict, executor) -> Dict:
    """Helper: Execute pfSense action (block/reject IP hoặc port)"""
    if not executor.enable_pfsense:
        return _create_result(
            False, 'pfSense not enabled. Enable with ENABLE_PFSENSE=true',
            block_info={'status': 'pfSense_not_configured'}
        )
    
    try:
        from actions.pfsense_integration import get_pfsense_client, RuleScheduler
        params = action.get('params', {})
        validator = _PFSENSE_VALIDATORS.get(action_type)
        if validator:
            error = validator(params)
            if error:
                return _create_result(False, error)
        
        method = executor.pfsense_method if executor.pfsense_method in _PFSENSE_EXECUTORS else 'ssh'
        pfsense = get_pfsense_client(method=method)
        if not pfsense:
            return _create_result(False, 'Failed to get pfSense client')
        
        executor_fn = _PFSENSE_EXECUTORS.get(method, {}).get(action_type)
        if not executor_fn:
            return _create_result(False, f'Unsupported pfSense action: {action_type}')
        result = executor_fn(pfsense, params)
        
        scheduler = RuleScheduler() if params.get('duration', 0) > 0 else None
        result = _schedule_unblock_if_needed(result, params, scheduler, action_type)
        if result.get('success'):
            return _create_result(True, result.get('message', f'{action_type} executed successfully'), block_info=result)
        return _create_result(False, f'pfSense {action_type} failed: {result.get("message")}')
    
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
        self.action_log_path = self.config.get('action_log_path', 'data/action_logs.jsonl')
        
        # pfSense configuration
        self.enable_pfsense = self.config.get('enable_pfsense', False) or os.getenv('ENABLE_PFSENSE', 'false').lower() == 'true'
        self.pfsense_method = self.config.get('pfsense_method', 'ssh') or os.getenv('PFSENSE_METHOD', 'ssh')
        
        # Đảm bảo thư mục tồn tại
        ensure_dir(self.action_log_path)
        
        # Initialize rule scheduler
        from actions.pfsense_integration import RuleScheduler
        self.scheduler = RuleScheduler()
        self._handlers: Dict[ActionType, Callable[[Dict], Dict]] = {
            ActionType.LOG: self._execute_log,
            ActionType.ALERT: self._execute_alert,
            ActionType.BLOCK_IP: self._execute_block_ip,
            ActionType.BLOCK_PORT: self._execute_block_port,
            ActionType.REJECT_IP: self._execute_reject_ip,
            ActionType.REJECT_PORT: self._execute_reject_port,
            ActionType.ESCALATE: self._execute_escalate,
        }
    
    def execute_action(self, action: Dict) -> Dict:
        """
        Thực thi một action
        
        Args:
            action: Action dict từ ActionGenerator
            
        Returns:
            Dict với kết quả: {'success': bool, 'message': str, 'timestamp': str}
        """
        action_type = ActionType(action['type'])
        handler = self._handlers.get(action_type)
        if not handler:
            result = _create_result(False, f'Unknown action type: {action_type}')
        else:
            try:
                result = handler(action)
            except Exception as exc:
                result = _create_result(False, f'Error executing action: {exc}')
        
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
    
    def _execute_block_ip(self, action: Dict) -> Dict:
        """Execute BLOCK IP action trên pfSense firewall"""
        return _execute_pfsense_action('block_ip', action, self)
    
    def _execute_block_port(self, action: Dict) -> Dict:
        """Execute BLOCK PORT action trên pfSense firewall"""
        return _execute_pfsense_action('block_port', action, self)
    
    def _execute_reject_ip(self, action: Dict) -> Dict:
        """Execute REJECT IP action trên pfSense firewall"""
        return _execute_pfsense_action('reject_ip', action, self)
    
    def _execute_reject_port(self, action: Dict) -> Dict:
        """Execute REJECT PORT action trên pfSense firewall"""
        return _execute_pfsense_action('reject_port', action, self)
    
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
            result.update({
                'anomaly_index': row['anomaly_index'],
                'action_index': idx
            })
            results.append(result)
        
        return pd.DataFrame(results)
    
    def process_scheduled_unblocks(self) -> List[Dict]:
        """
        Process các scheduled unblocks đã đến thời gian
        
        Returns:
            List of unblock results
        """
        return self.scheduler.process_scheduled_unblocks()

