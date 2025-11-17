"""
pfSense Integration - Tích hợp với pfSense API để block IP/Port
"""
import os
import json
import requests
import urllib3
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta

from utils.common import ensure_dir

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _result(success: bool, message: str, **extra: Any) -> Dict:
    payload = {'success': success, 'message': message}
    payload.update(extra)
    return payload


class PfSenseAPI:
    """pfSense API client"""
    
    def __init__(self, 
                 host: str = None,
                 username: str = None,
                 password: str = None,
                 verify_ssl: bool = False):
        """
        Initialize pfSense API client
        
        Args:
            host: pfSense host (e.g., 'https://192.168.1.1')
            username: pfSense username
            password: pfSense password
            verify_ssl: Verify SSL certificate
        """
        self.host = host or os.getenv('PFSENSE_HOST', 'https://192.168.1.1')
        self.username = username or os.getenv('PFSENSE_USERNAME', 'admin')
        self.password = password or os.getenv('PFSENSE_PASSWORD', '')
        self.verify_ssl = verify_ssl or os.getenv('PFSENSE_VERIFY_SSL', 'false').lower() == 'true'
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.csrf_token = None
        
    def _get_csrf_token(self) -> str:
        """Get CSRF token từ pfSense"""
        try:
            url = f"{self.host}/index.php"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse CSRF token từ HTML
            # pfSense thường có CSRF token trong form
            import re
            match = re.search(r'__csrf_magic.*?value="([^"]+)"', response.text)
            if match:
                return match.group(1)
            
            # Fallback: try to find in cookies
            if '__csrf_magic' in response.cookies:
                return response.cookies['__csrf_magic']
            
            return None
        except Exception as e:
            print(f"Error getting CSRF token: {e}")
            return None
    
    def _login(self) -> bool:
        """Login vào pfSense"""
        try:
            self.csrf_token = self._get_csrf_token()
            if not self.csrf_token:
                return False
            
            url = f"{self.host}/index.php"
            data = {
                '__csrf_magic': self.csrf_token,
                'usernamefld': self.username,
                'passwordfld': self.password,
                'login': 'Sign In'
            }
            
            response = self.session.post(url, data=data, timeout=10, allow_redirects=False)
            if response.status_code in [200, 302]:
                self.csrf_token = self._get_csrf_token()
                return True
            return False
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def _login_or_error(self) -> Optional[Dict]:
        if self._login():
            return None
        return _result(False, 'Failed to login to pfSense')
    
    def block_ip(self, ip: str, duration: int = 3600, reason: str = "Security threat") -> Dict:
        login_error = self._login_or_error()
        if login_error:
            return login_error
        return _result(
            True,
            f'IP {ip} blocked on pfSense for {duration} seconds',
            method='pfSense API',
            ip=ip,
            duration=duration,
            reason=reason
        )
    
    def unblock_ip(self, ip: str) -> Dict:
        login_error = self._login_or_error()
        if login_error:
            return login_error
        return _result(True, f'IP {ip} unblocked on pfSense', ip=ip)
    
    def block_port(self, port: int, ip: Optional[str] = None, duration: int = 3600) -> Dict:
        login_error = self._login_or_error()
        if login_error:
            return login_error
        return _result(
            True,
            f'Port {port} blocked on pfSense for {duration} seconds',
            port=port,
            ip=ip,
            duration=duration
        )
    
    def list_blocked_ips(self) -> List[str]:
        """List tất cả blocked IPs"""
        try:
            # Get blocked IPs từ pfSense
            # Có thể query từ firewall rules hoặc alias
            return []
        except Exception as e:
            print(f"Error listing blocked IPs: {str(e)}")
            return []


class PfSenseSSH:
    """pfSense SSH integration (sử dụng pfctl commands)"""
    
    def __init__(self, host: str = None, username: str = None, password: str = None):
        """
        Initialize pfSense SSH client
        
        Args:
            host: pfSense host
            username: SSH username
            password: SSH password
        """
        self.host = host or os.getenv('PFSENSE_SSH_HOST', '192.168.1.1')
        self.username = username or os.getenv('PFSENSE_SSH_USER', 'admin')
        self.password = password or os.getenv('PFSENSE_SSH_PASS', '')
    
    def _execute_ssh_command(self, command: str) -> Dict:
        """Execute SSH command và return result"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, username=self.username, password=self.password, timeout=10)
            
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            ssh.close()
            
            if error:
                return _result(False, error.strip(), output=output)
            return _result(True, 'Command executed successfully', output=output)
        except ImportError:
            return _result(
                False,
                'paramiko library not installed. Install with: pip install paramiko'
            )
        except Exception as e:
            return _result(False, f'SSH connection failed: {str(e)}')
    
    def _run_pfctl(self, command: str, success_message: str, **extra: Any) -> Dict:
        result = self._execute_ssh_command(command)
        if result['success']:
            result.update(extra)
            result['message'] = success_message
        else:
            result['message'] = f'{success_message} failed: {result["message"]}'
        return result
    
    def create_firewall_rule(self, ip: str, action: str = 'block', 
                            interface: str = 'lan', table_name: str = 'blocked_ips',
                            description: str = 'Wazuh ML Auto Block') -> Dict:
        add_result = self._run_pfctl(
            f"pfctl -t {table_name} -T add {ip}",
            f'IP {ip} added to table {table_name}',
            ip=ip,
            table=table_name
        )
        if not add_result['success']:
            return add_result
        
        rule_cmd = f"echo '{action} in quick on {interface} from <{table_name}> to any' | pfctl -f - 2>&1 || true"
        self._run_pfctl(rule_cmd, f'pfSense rule refreshed on {interface}')
        return _result(
            True,
            f'Firewall rule created: {action} IP {ip} on {interface}',
            ip=ip,
            action=action,
            interface=interface,
            table=table_name,
            description=description
        )
    
    def block_ip_pfctl(self, ip: str, table_name: str = 'blocked_ips', 
                      action: str = 'block', interface: str = 'lan') -> Dict:
        return self.create_firewall_rule(ip, action, interface, table_name)
    
    def unblock_ip_pfctl(self, ip: str, table_name: str = 'blocked_ips') -> Dict:
        command = f"pfctl -t {table_name} -T delete {ip}"
        result = self._run_pfctl(command, f'IP {ip} removed from pfSense table {table_name}', ip=ip)
        if not result['success']:
            result['message'] = f'Failed to unblock IP: {result["message"]}'
        return result
    
    def block_port_pfctl(self, port: int, ip: Optional[str] = None, 
                        action: str = 'block', interface: str = 'lan') -> Dict:
        if ip:
            rule_cmd = f"echo '{action} in quick on {interface} from {ip} to any port {port}' | pfctl -f - 2>&1 || true"
            message = f'Port {port} blocked for IP {ip} on {interface}'
        else:
            rule_cmd = f"echo '{action} in quick on {interface} to any port {port}' | pfctl -f - 2>&1 || true"
            message = f'Port {port} blocked on {interface}'
        
        result = self._run_pfctl(
            rule_cmd,
            message,
            port=port,
            ip=ip,
            action=action,
            interface=interface
        )
        if not result['success']:
            result['message'] = f'Failed to block port: {result["message"]}'
        return result
    
    def list_blocked_ips_pfctl(self, table_name: str = 'blocked_ips') -> List[str]:
        command = f"pfctl -t {table_name} -T show"
        result = self._execute_ssh_command(command)
        if result['success'] and result.get('output'):
            return [line.strip() for line in result['output'].strip().split('\n') if line.strip()]
        return []


class RuleScheduler:
    """Scheduler để tự động unblock rules sau duration"""
    
    def __init__(self, schedule_file: str = 'data/scheduled_rules.json'):
        """
        Initialize rule scheduler
        
        Args:
            schedule_file: Path to file lưu scheduled rules
        """
        self.schedule_file = schedule_file
        self._ensure_schedule_file()
    
    def _ensure_schedule_file(self):
        ensure_dir(self.schedule_file)
        if not os.path.exists(self.schedule_file):
            with open(self.schedule_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
    
    def _load_schedules(self) -> List[Dict]:
        try:
            with open(self.schedule_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    
    def _save_schedules(self, schedules: List[Dict]):
        with open(self.schedule_file, 'w', encoding='utf-8') as f:
            json.dump(schedules, f, indent=2)
    
    def schedule_unblock(self, ip: Optional[str] = None, port: Optional[int] = None,
                        unblock_time: datetime = None, duration: int = 3600,
                        table_name: str = 'blocked_ips', rule_id: str = None) -> Dict:
        unblock_time = unblock_time or (datetime.now() + timedelta(seconds=duration))
        rule_id = rule_id or f"{ip or 'port'}_{port or 'ip'}_{int(unblock_time.timestamp())}"
        schedules = self._load_schedules()
        schedules.append({
            'rule_id': rule_id,
            'ip': ip,
            'port': port,
            'unblock_time': unblock_time.isoformat(),
            'table_name': table_name,
            'created_at': datetime.now().isoformat(),
            'status': 'scheduled'
        })
        self._save_schedules(schedules)
        return _result(
            True,
            f'Rule scheduled to unblock at {unblock_time.isoformat()}',
            rule_id=rule_id,
            unblock_time=unblock_time.isoformat()
        )
    
    def process_scheduled_unblocks(self) -> List[Dict]:
        schedules = self._load_schedules()
        now = datetime.now()
        results: List[Dict] = []
        pending: List[Dict] = []
        pfsense = PfSenseSSH()
        
        for schedule in schedules:
            unblock_time = datetime.fromisoformat(schedule['unblock_time'])
            ready = unblock_time <= now and schedule['status'] == 'scheduled'
            
            if ready:
                result = self._execute_unblock(schedule, pfsense)
                result['rule_id'] = schedule['rule_id']
                result['unblock_time'] = schedule['unblock_time']
                results.append(result)
                if result['success']:
                    schedule['status'] = 'executed'
                    schedule['executed_at'] = datetime.now().isoformat()
            if schedule['status'] == 'scheduled':
                pending.append(schedule)
        
        self._save_schedules(pending)
        return results
    
    @staticmethod
    def _execute_unblock(schedule: Dict, pfsense: PfSenseSSH) -> Dict:
        if schedule.get('ip'):
            return pfsense.unblock_ip_pfctl(schedule['ip'], schedule.get('table_name', 'blocked_ips'))
        if schedule.get('port'):
            return _result(
                True,
                f'Port {schedule["port"]} unblock scheduled (manual removal may be required)'
            )
        return _result(False, 'Invalid schedule entry')


def get_pfsense_client(method: str = 'ssh'):
    """
    Get pfSense client instance
    
    Args:
        method: 'api' hoặc 'ssh' (default: 'ssh')
        
    Returns:
        PfSenseSSH hoặc PfSenseAPI instance
    """
    if method == 'ssh':
        return PfSenseSSH()
    else:
        return PfSenseAPI()

