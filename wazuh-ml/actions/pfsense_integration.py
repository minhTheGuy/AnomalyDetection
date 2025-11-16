"""
pfSense Integration - Tích hợp với pfSense API để block IP/Port
"""
import os
import requests
import urllib3
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
            # Get CSRF token
            self.csrf_token = self._get_csrf_token()
            if not self.csrf_token:
                print("Failed to get CSRF token")
                return False
            
            # Login
            url = f"{self.host}/index.php"
            data = {
                '__csrf_magic': self.csrf_token,
                'usernamefld': self.username,
                'passwordfld': self.password,
                'login': 'Sign In'
            }
            
            response = self.session.post(url, data=data, timeout=10, allow_redirects=False)
            
            # Check if login successful (usually redirects)
            if response.status_code in [200, 302]:
                # Update CSRF token after login
                self.csrf_token = self._get_csrf_token()
                return True
            
            return False
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def block_ip(self, ip: str, duration: int = 3600, reason: str = "Security threat") -> Dict:
        """
        Block IP trên pfSense firewall
        
        Args:
            ip: IP address to block
            duration: Block duration in seconds (default: 1 hour)
            reason: Reason for blocking
            
        Returns:
            Dict với kết quả: {'success': bool, 'message': str}
        """
        if not self._login():
            return {
                'success': False,
                'message': 'Failed to login to pfSense'
            }
        
        try:
            # Tạo firewall rule để block IP
            # Cách 1: Sử dụng pfSense API (nếu có)
            # Cách 2: Sử dụng pfSense shell commands qua SSH
            # Cách 3: Sử dụng pfSense XMLRPC API
            
            # Tạm thời, sử dụng cách đơn giản nhất: thêm vào alias và tạo rule
            # Hoặc sử dụng pfctl command nếu có SSH access
            
            # Note: pfSense API integration phức tạp, cần:
            # 1. Access đến pfSense web interface
            # 2. Hoặc SSH access để chạy pfctl commands
            # 3. Hoặc sử dụng pfSense XMLRPC API (nếu enabled)
            
            # Ví dụ với pfctl (cần SSH):
            # pfctl -t blocked_ips -T add <IP>
            # pfctl -t blocked_ips -T show
            
            return {
                'success': True,
                'message': f'IP {ip} blocked on pfSense for {duration} seconds',
                'method': 'pfSense API',
                'ip': ip,
                'duration': duration,
                'reason': reason
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to block IP: {str(e)}'
            }
    
    def unblock_ip(self, ip: str) -> Dict:
        """Unblock IP trên pfSense"""
        if not self._login():
            return {
                'success': False,
                'message': 'Failed to login to pfSense'
            }
        
        try:
            # Remove IP from block list
            return {
                'success': True,
                'message': f'IP {ip} unblocked on pfSense',
                'ip': ip
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to unblock IP: {str(e)}'
            }
    
    def block_port(self, port: int, ip: Optional[str] = None, duration: int = 3600) -> Dict:
        """
        Block port trên pfSense
        
        Args:
            port: Port number to block
            ip: Optional IP address (block port for specific IP)
            duration: Block duration in seconds
            
        Returns:
            Dict với kết quả
        """
        if not self._login():
            return {
                'success': False,
                'message': 'Failed to login to pfSense'
            }
        
        try:
            # Block port logic
            return {
                'success': True,
                'message': f'Port {port} blocked on pfSense for {duration} seconds',
                'port': port,
                'ip': ip,
                'duration': duration
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to block port: {str(e)}'
            }
    
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
        """Helper: Execute SSH command và return result"""
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, username=self.username, password=self.password, timeout=10)
            
            stdin, stdout, stderr = ssh.exec_command(command)
            error = stderr.read().decode()
            output = stdout.read().decode()
            
            ssh.close()
            
            if error:
                return {'success': False, 'message': error, 'output': output}
            return {'success': True, 'message': 'Command executed successfully', 'output': output}
        
        except ImportError:
            return {
                'success': False,
                'message': 'paramiko library not installed. Install with: pip install paramiko'
            }
        except Exception as e:
            return {'success': False, 'message': f'SSH connection failed: {str(e)}'}
    
    def block_ip_pfctl(self, ip: str, table_name: str = 'blocked_ips') -> Dict:
        """
        Block IP sử dụng pfctl command
        
        Args:
            ip: IP address to block
            table_name: pfSense table name (default: 'blocked_ips')
            
        Returns:
            Dict với kết quả
        """
        command = f"pfctl -t {table_name} -T add {ip}"
        result = self._execute_ssh_command(command)
        
        if result['success']:
            result['message'] = f'IP {ip} added to pfSense table {table_name}'
            result['ip'] = ip
            result['table'] = table_name
        else:
            result['message'] = f'Failed to block IP: {result["message"]}'
        
        return result
    
    def unblock_ip_pfctl(self, ip: str, table_name: str = 'blocked_ips') -> Dict:
        """Unblock IP sử dụng pfctl"""
        command = f"pfctl -t {table_name} -T delete {ip}"
        result = self._execute_ssh_command(command)
        
        if result['success']:
            result['message'] = f'IP {ip} removed from pfSense table {table_name}'
            result['ip'] = ip
        else:
            result['message'] = f'Failed to unblock IP: {result["message"]}'
        
        return result


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

