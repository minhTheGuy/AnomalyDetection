"""
wazuh.py - Wazuh HIDS Integration Module

Provides:
- WazuhClient: Send detections to Wazuh Manager
- WazuhAlertParser: Parse Wazuh HIDS alerts  
- WazuhIndexerClient: Read alerts from Wazuh Indexer (OpenSearch)
- HIDSCorrelator: Correlate HIDS + NIDS detections
"""

import os
import json
import socket
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import urllib3

try:
    from dotenv import load_dotenv
    for p in [Path(__file__).parent.parent.parent.parent / '.env',
              Path(__file__).parent.parent.parent / '.env']:
        if p.exists():
            load_dotenv(p)
            break
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from .models import FlowDetection, ThreatLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class WazuhAlert:
    """Parsed Wazuh HIDS alert"""
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    agent_ip: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    full_log: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    
    @property
    def threat_level(self) -> ThreatLevel:
        if self.rule_level >= 12: return ThreatLevel.CRITICAL
        elif self.rule_level >= 10: return ThreatLevel.HIGH
        elif self.rule_level >= 7: return ThreatLevel.MEDIUM
        return ThreatLevel.LOW
    
    def to_dict(self) -> Dict:
        return {k: getattr(self, k) if k != 'timestamp' else self.timestamp.isoformat() 
                for k in ['timestamp', 'rule_id', 'rule_level', 'rule_description',
                          'agent_id', 'agent_name', 'src_ip', 'dst_ip']}


@dataclass
class CorrelatedAlert:
    """Correlated HIDS + NIDS alert"""
    timestamp: datetime
    correlation_type: str
    nids_detection: Optional[FlowDetection]
    hids_alert: Optional[WazuhAlert]
    combined_threat_level: ThreatLevel
    description: str
    recommended_action: str


# ============================================================================
# Helper Functions
# ============================================================================

def _get_env(key: str, *alt_keys: str, default: str = None) -> Optional[str]:
    """Get env variable with fallbacks"""
    for k in [key] + list(alt_keys):
        val = os.getenv(k)
        if val:
            return val
    return default


def _parse_wazuh_alert(data: Dict) -> Optional[WazuhAlert]:
    """Parse alert from JSON data"""
    try:
        rule = data.get('rule', {})
        agent = data.get('agent', {})
        data_fields = data.get('data', {}) if isinstance(data.get('data'), dict) else {}
        
        timestamp_str = data.get('timestamp', '')
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            timestamp = datetime.now()
        
        return WazuhAlert(
            timestamp=timestamp,
            rule_id=str(rule.get('id', 'unknown')),
            rule_level=int(rule.get('level', 0)),
            rule_description=rule.get('description', ''),
            agent_id=str(agent.get('id', '000')),
            agent_name=agent.get('name', 'unknown'),
            agent_ip=agent.get('ip', 'unknown'),
            src_ip=data_fields.get('srcip') or data_fields.get('src_ip') or data.get('predecoder', {}).get('srcip'),
            dst_ip=data_fields.get('dstip') or data_fields.get('dst_ip'),
            src_port=int(data_fields.get('srcport', 0)) if data_fields.get('srcport') else None,
            dst_port=int(data_fields.get('dstport', 0)) if data_fields.get('dstport') else None,
            user=data_fields.get('user') or data_fields.get('srcuser'),
            process_name=data_fields.get('process_name'),
            file_path=data.get('syscheck', {}).get('path'),
            full_log=data.get('full_log'),
            groups=rule.get('groups', [])
        )
    except Exception as e:
        logger.debug(f"Error parsing alert: {e}")
        return None


class _WazuhAPIBase:
    """Base class for Wazuh API authentication"""
    
    def __init__(self):
        self._api_token = None
        self._token_expires = None
    
    def _get_api_token(self, api_url: str, api_user: str, api_password: str) -> Optional[str]:
        """Get or refresh API token"""
        if self._api_token and self._token_expires and datetime.now() < self._token_expires:
            return self._api_token
        
        # Ensure API URL has port if not specified
        api_url = self._normalize_api_url(api_url)
        if not api_url:
            logger.error("Wazuh API URL is invalid or missing port")
            return None
        
        try:
            auth_url = f"{api_url}/security/user/authenticate"
            response = requests.post(
                auth_url,
                auth=(api_user, api_password),
                verify=False, timeout=10
            )
            response.raise_for_status()
            self._api_token = response.json().get('data', {}).get('token')
            self._token_expires = datetime.now() + timedelta(minutes=14)
            return self._api_token
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.error(f"Wazuh API endpoint not found (404): {auth_url}")
                logger.error("Check if API URL includes port (e.g., https://host:55000)")
            else:
                logger.error(f"Wazuh API auth HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"Wazuh API auth error: {e}")
            return None
    
    def _normalize_api_url(self, api_url: str) -> Optional[str]:
        """Ensure API URL includes port number"""
        if not api_url:
            return None
        
        # Remove trailing slash
        api_url = api_url.rstrip('/')
        
        # If URL doesn't have a port, try to add default port 55000
        if '://' in api_url:
            scheme, rest = api_url.split('://', 1)
            if ':' not in rest.split('/')[0]:  # No port in host part
                # Add default Wazuh API port
                host = rest.split('/')[0]
                path = rest[len(host):] if len(rest) > len(host) else ''
                api_url = f"{scheme}://{host}:55000{path}"
                logger.debug(f"Added default port 55000 to Wazuh API URL: {api_url}")
        
        return api_url


# ============================================================================
# WazuhClient - Send detections to Wazuh
# ============================================================================

class WazuhClient(_WazuhAPIBase):
    """Send detections to Wazuh Manager via socket, API, or log file"""
    
    SOCKET_PATHS = ['/var/ossec/queue/sockets/queue', '/var/ossec/queue/ossec/queue']
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        self.config = config or {}
        
        # Socket
        self.socket_path = self.config.get('socket_path')
        if not self.socket_path:
            self.socket_path = next((p for p in self.SOCKET_PATHS if Path(p).exists()), None)
        
        # API
        host = _get_env('WAZUH_MANAGER_HOST')
        port = _get_env('WAZUH_MANAGER_PORT', default='55000')
        # Get API URL from config or construct from host/port
        api_url_from_config = self.config.get('api_url')
        if api_url_from_config:
            self.api_url = api_url_from_config
        elif host:
            # Construct URL with port
            self.api_url = f"https://{host}:{port}"
        else:
            # Try to get from WAZUH_API_URL env var
            self.api_url = _get_env('WAZUH_API_URL')
        
        # Normalize API URL to ensure it has a port
        if self.api_url:
            self.api_url = self._normalize_api_url(self.api_url)
        
        self.api_user = self.config.get('api_user') or _get_env('WAZUH_MANAGER_USER', 'WAZUH_API_USER', default='wazuh')
        self.api_password = self.config.get('api_password') or _get_env('WAZUH_MANAGER_PASSWORD', 'WAZUH_API_PASSWORD')
        
        # Log file
        from .config import LOGS_DIR
        self.log_path = Path(self.config.get('log_path', LOGS_DIR / 'action_logs.json'))
        
        # Determine method
        self.method = self.config.get('method', 'auto')
        if self.method == 'auto':
            if self.socket_path and Path(self.socket_path).exists():
                self.method = 'socket'
            elif self.api_url and self.api_password:
                self.method = 'api'
            else:
                self.method = 'log'
        logger.info(f"Wazuh: Using {self.method} method")
    
    def send(self, detection: FlowDetection) -> bool:
        """Send detection to Wazuh"""
        msg = {
            'timestamp': datetime.now().isoformat(),
            'source': 'hybrid-nids',
            'attack_type': detection.attack_type,
            'threat_level': detection.threat_level.name,
            'confidence': round(detection.confidence, 4),
            'src_ip': detection.src_ip,
            'dst_ip': detection.dst_ip,
            'dst_port': detection.dst_port,
            'layer': detection.layer,
        }
        
        if self.method == 'socket':
            return self._send_socket(msg)
        elif self.method == 'api':
            return self._send_api(msg)
        return self._send_log(msg)
    
    def _send_socket(self, msg: Dict) -> bool:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(self.socket_path)
            sock.send(f"1:hybrid-nids:{json.dumps(msg)}".encode())
            sock.close()
            return True
        except Exception as e:
            logger.warning(f"Socket error: {e}, falling back to log")
            return self._send_log(msg)
    
    def _send_api(self, msg: Dict) -> bool:
        try:
            token = self._get_api_token(self.api_url, self.api_user, self.api_password)
            if not token:
                return self._send_log(msg)
            
            event_str = f"hybrid-nids: {json.dumps(msg)}"
            response = requests.post(
                f"{self.api_url}/events",
                headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
                json={"events": [event_str]},
                verify=False, timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"API error: {e}")
            return self._send_log(msg)
    
    def _send_log(self, msg: Dict) -> bool:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(msg) + '\n')
            return True
        except Exception as e:
            logger.error(f"Log write error: {e}")
            return False


# ============================================================================
# WazuhAlertParser - Parse local Wazuh alerts
# ============================================================================

class WazuhAlertParser(_WazuhAPIBase):
    """Parse Wazuh HIDS alerts from local file or API"""
    
    DEFAULT_PATH = '/var/ossec/logs/alerts/alerts.json'
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__()
        self.config = config or {}
        self.alerts_path = Path(self.config.get('alerts_path', self.DEFAULT_PATH))
        self.lookback_minutes = self.config.get('lookback_minutes', 5)
        self.api_url = self.config.get('api_url') or _get_env('WAZUH_API_URL')
        self.api_user = self.config.get('api_user') or _get_env('WAZUH_API_USER', default='wazuh')
        self.api_password = self.config.get('api_password') or _get_env('WAZUH_API_PASSWORD')
        self._last_position = 0
    
    def get_recent_alerts(self, minutes: int = None) -> List[WazuhAlert]:
        minutes = minutes or self.lookback_minutes
        
        if self.alerts_path.exists():
            return self._parse_file(minutes)
        elif self.api_url and self.api_password:
            return self._fetch_api(minutes)
        
        logger.warning("No Wazuh alert source available")
        return []
    
    def _parse_file(self, minutes: int) -> List[WazuhAlert]:
        alerts = []
        cutoff = datetime.now() - timedelta(minutes=minutes)
        
        try:
            with open(self.alerts_path, 'r') as f:
                f.seek(self._last_position)
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        alert = _parse_wazuh_alert(json.loads(line))
                        if alert and alert.timestamp >= cutoff:
                            alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
                self._last_position = f.tell()
        except Exception as e:
            logger.error(f"Error reading alerts: {e}")
        
        return alerts
    
    def _fetch_api(self, minutes: int) -> List[WazuhAlert]:
        try:
            token = self._get_api_token(self.api_url, self.api_user, self.api_password)
            if not token:
                return []
            
            from_time = (datetime.now() - timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%S')
            response = requests.get(
                f"{self.api_url}/alerts",
                headers={'Authorization': f'Bearer {token}'},
                params={'limit': 500, 'sort': '-timestamp', 'q': f'timestamp>{from_time}'},
                verify=False, timeout=30
            )
            response.raise_for_status()
            
            return [a for a in (_parse_wazuh_alert(item) 
                    for item in response.json().get('data', {}).get('affected_items', [])) if a]
        except Exception as e:
            logger.error(f"API fetch error: {e}")
            return []


# ============================================================================
# WazuhIndexerClient - Read from OpenSearch
# ============================================================================

class WazuhIndexerClient:
    """Read alerts from Wazuh Indexer (OpenSearch)"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.host = self.config.get('host') or _get_env('WAZUH_INDEXER_HOST')
        self.port = int(self.config.get('port') or _get_env('WAZUH_INDEXER_PORT', default='9200'))
        self.user = self.config.get('user') or _get_env('WAZUH_INDEXER_USER', default='admin')
        self.password = self.config.get('password') or _get_env('WAZUH_INDEXER_PASSWORD')
        self.index_pattern = self.config.get('index_pattern', 'wazuh-alerts-*')
        self.base_url = f"https://{self.host}:{self.port}" if self.host else None
        self.available = self._check_connection()
    
    def _check_connection(self) -> bool:
        if not self.base_url or not self.password:
            return False
        try:
            r = requests.get(f"{self.base_url}/_cluster/health", 
                           auth=(self.user, self.password), verify=False, timeout=5)
            if r.status_code == 200:
                logger.info(f"Wazuh Indexer: Connected to {self.host}:{self.port}")
                return True
        except:
            pass
        return False
    
    def get_recent_alerts(self, minutes: int = 5, agent_id: str = None,
                          rule_level_min: int = 0, limit: int = 500) -> List[WazuhAlert]:
        if not self.available:
            return []
        
        try:
            query = {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [{"range": {"timestamp": {"gte": f"now-{minutes}m"}}}], "filter": []}}
            }
            if agent_id:
                query["query"]["bool"]["filter"].append({"term": {"agent.id": agent_id}})
            if rule_level_min > 0:
                query["query"]["bool"]["filter"].append({"range": {"rule.level": {"gte": rule_level_min}}})
            
            r = requests.post(f"{self.base_url}/{self.index_pattern}/_search",
                            auth=(self.user, self.password), json=query, verify=False, timeout=30)
            r.raise_for_status()
            
            alerts = [a for a in (_parse_wazuh_alert(h['_source']) 
                      for h in r.json().get('hits', {}).get('hits', [])) if a]
            logger.info(f"Wazuh Indexer: Retrieved {len(alerts)} alerts")
            return alerts
        except Exception as e:
            logger.error(f"Indexer query error: {e}")
            return []
    
    def get_alerts_by_ip(self, ip: str, minutes: int = 60) -> List[WazuhAlert]:
        if not self.available:
            return []
        
        try:
            query = {
                "size": 100,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {
                    "must": [{"range": {"timestamp": {"gte": f"now-{minutes}m"}}}],
                    "should": [{"match": {"data.srcip": ip}}, {"match": {"data.dstip": ip}},
                              {"match": {"agent.ip": ip}}, {"match_phrase": {"full_log": ip}}],
                    "minimum_should_match": 1
                }}
            }
            r = requests.post(f"{self.base_url}/{self.index_pattern}/_search",
                            auth=(self.user, self.password), json=query, verify=False, timeout=30)
            r.raise_for_status()
            return [a for a in (_parse_wazuh_alert(h['_source']) 
                    for h in r.json().get('hits', {}).get('hits', [])) if a]
        except Exception as e:
            logger.error(f"IP query error: {e}")
            return []


# ============================================================================
# HIDSCorrelator - Correlate HIDS + NIDS
# ============================================================================

class HIDSCorrelator:
    """Correlate host-based (Wazuh) and network-based (NIDS) detections"""
    
    ATTACK_RELATIONSHIPS = {
        'portscan': ['scan', 'network'], 'dos': ['network', 'flood'], 'ddos': ['network', 'flood'],
        'brute': ['authentication_failed', 'sshd', 'pam'], 'ssh': ['sshd', 'pam'],
        'web': ['web_attack', 'sql_injection', 'xss'], 'malware': ['malware', 'rootkit', 'trojan'],
        'infiltration': ['syscheck', 'exploit'],
    }
    
    def __init__(self, config: Optional[Dict] = None, indexer: Optional[WazuhIndexerClient] = None):
        self.parser = WazuhAlertParser(config)
        self.indexer = indexer
        if not self.indexer:
            try:
                self.indexer = WazuhIndexerClient()
                if not self.indexer.available:
                    self.indexer = None
            except:
                self.indexer = None
        
        self._cache: List[WazuhAlert] = []
        self._cache_time: Optional[datetime] = None
    
    def correlate(self, detections: List[FlowDetection]) -> List[CorrelatedAlert]:
        self._refresh_cache()
        
        correlated = []
        seen_pairs = set()  # Avoid duplicate correlations
        
        for det in detections:
            for alert, corr_type in self._find_matches(det):
                # Deduplicate: only one correlation per (src_ip, attack_type, rule_id)
                pair_key = f"{det.src_ip}-{det.attack_type}-{alert.rule_id}"
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                correlated.append(self._create_alert(det, alert, corr_type))
        
        # Detect attack chains
        correlated.extend(self._detect_chains())
        return correlated
    
    def _refresh_cache(self):
        if not self._cache_time or (datetime.now() - self._cache_time) > timedelta(minutes=5):
            self._cache = (self.indexer.get_recent_alerts(5) if self.indexer and self.indexer.available 
                          else self.parser.get_recent_alerts())
            self._cache_time = datetime.now()
    
    def _find_matches(self, det: FlowDetection) -> List[tuple]:
        matches = []
        for alert in self._cache:
            if alert.src_ip and (alert.src_ip == det.src_ip or alert.agent_ip == det.dst_ip):
                matches.append((alert, 'ip_match'))
            elif self._attacks_related(det.attack_type, alert.groups):
                matches.append((alert, 'attack_pattern'))
        return matches
    
    def _attacks_related(self, attack: str, groups: List[str]) -> bool:
        attack_lower = attack.lower()
        for key, hids_keys in self.ATTACK_RELATIONSHIPS.items():
            if key in attack_lower and any(hk in g.lower() for g in groups for hk in hids_keys):
                return True
        return False
    
    def _create_alert(self, det: FlowDetection, hids: WazuhAlert, corr_type: str) -> CorrelatedAlert:
        level = max(det.threat_level, hids.threat_level, key=lambda x: x.value)
        if corr_type == 'ip_match' and level.value < ThreatLevel.HIGH.value:
            level = ThreatLevel(level.value + 1)
        
        actions = {
            ThreatLevel.CRITICAL: "IMMEDIATE: Block IP, isolate host, investigate",
            ThreatLevel.HIGH: "URGENT: Block IP, review logs, escalate",
            ThreatLevel.MEDIUM: "MONITOR: Add to watchlist, review in 1 hour",
        }
        
        return CorrelatedAlert(
            timestamp=datetime.now(),
            correlation_type=corr_type,
            nids_detection=det,
            hids_alert=hids,
            combined_threat_level=level,
            description=f"Correlated {corr_type}: NIDS {det.attack_type} from {det.src_ip}, HIDS rule {hids.rule_id}: {hids.rule_description}",
            recommended_action=actions.get(level, "LOG: Record for analysis")
        )
    
    def _detect_chains(self) -> List[CorrelatedAlert]:
        chains = []
        by_ip: Dict[str, List[WazuhAlert]] = {}
        for a in self._cache:
            if a.src_ip:
                by_ip.setdefault(a.src_ip, []).append(a)
        
        for ip, alerts in by_ip.items():
            if len(alerts) >= 3:
                sorted_alerts = sorted(alerts, key=lambda x: x.timestamp)
                levels = [a.rule_level for a in sorted_alerts]
                if sum(1 for i in range(1, len(levels)) if levels[i] > levels[i-1]) >= len(levels) // 2:
                    chains.append(CorrelatedAlert(
                        timestamp=datetime.now(),
                        correlation_type='attack_chain',
                        nids_detection=None,
                        hids_alert=sorted_alerts[-1],
                        combined_threat_level=ThreatLevel.CRITICAL,
                        description=f"Attack chain from {ip}: {len(alerts)} progressive alerts",
                        recommended_action="CRITICAL: Active attack, block immediately"
                    ))
        return chains


def create_wazuh_integration(config: Optional[Dict] = None) -> tuple:
    """Create all Wazuh integration components"""
    config = config or {}
    return (WazuhClient(config), WazuhAlertParser(config), 
            WazuhIndexerClient(config), HIDSCorrelator(config))
