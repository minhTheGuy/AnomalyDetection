"""
actions.py - Response actions for detected threats
Supports: log, alert, block, webhook, email, wazuh

Wazuh Integration:
- Sends ML detections to Wazuh Manager (socket/API/log)
- Parses Wazuh HIDS alerts for correlation
- Combines host-based and network-based detection
"""

import json
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional

from .config import LOGS_DIR
from .models import ActionType, ThreatLevel, FlowDetection, DetectionResult
from .stats import stats
from .wazuh import WazuhClient, HIDSCorrelator, CorrelatedAlert


logger = logging.getLogger(__name__)


class ActionHandler:
    """Handle response actions for detected threats"""
    
    def __init__(self, config: Optional[Dict] = None, pfsense_capture=None):
        self.config = config or {}
        self.pfsense = pfsense_capture
        self.enabled_actions = self.config.get('enabled_actions', [ActionType.LOG, ActionType.ALERT])
        self.block_duration = self.config.get('block_duration', 300)
        self.block_threshold = ThreatLevel[self.config.get('block_threshold', 'HIGH').upper()]
        self.webhook_url = self.config.get('webhook_url')
        self.email_config = self.config.get('email', {})
        self.wazuh_config = self.config.get('wazuh', {})
        self.wazuh_client = self.hids_correlator = None
        self.log_file = LOGS_DIR / 'action_logs.jsonl'
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        
        if self.wazuh_config or ActionType.WAZUH in self.enabled_actions:
            try:
                self.wazuh_client = WazuhClient(self.wazuh_config)
                self.hids_correlator = HIDSCorrelator(self.wazuh_config)
            except Exception as e:
                logger.warning(f"Wazuh init failed: {e}")
    
    def process(self, result: DetectionResult):
        """Process detection result and execute appropriate actions"""
        if not result.detections: return
        
        if self.hids_correlator:
            try:
                correlated = self.hids_correlator.correlate(result.detections)
                for alert in correlated:
                    self._handle_correlated(alert)
            except Exception as e:
                logger.warning(f"HIDS correlation failed: {e}")
        
        for det in result.detections:
            self._handle_detection(det)
        stats.update(result)
    
    def _handle_correlated(self, alert: CorrelatedAlert):
        """Handle correlated HIDS+NIDS alert"""
        with open(self.log_file, 'a') as f:
            f.write(json.dumps({
                'timestamp': datetime.now().isoformat(), 'action': 'correlation',
                'correlation_type': alert.correlation_type,
                'threat_level': alert.combined_threat_level.name,
                'description': alert.description,
                'nids': alert.nids_detection.attack_type if alert.nids_detection else None,
                'hids_rule': alert.hids_alert.rule_id if alert.hids_alert else None
            }) + '\n')
        
        if ActionType.ALERT in self.enabled_actions:
            print(f"\033[95m[CORRELATED] [{alert.combined_threat_level.name}] "
                  f"{alert.correlation_type}: {alert.description[:100]}\033[0m")
        
        if ActionType.BLOCK in self.enabled_actions and alert.combined_threat_level.value >= ThreatLevel.HIGH.value:
            if alert.nids_detection:
                self._action_block(alert.nids_detection)
            elif alert.hids_alert and alert.hids_alert.src_ip:
                self._action_block(FlowDetection(
                    flow_id='correlated', src_ip=alert.hids_alert.src_ip,
                    dst_ip=alert.hids_alert.agent_ip, src_port=0, dst_port=0,
                    protocol='unknown', attack_type=f"[HIDS] {alert.hids_alert.rule_description}",
                    confidence=0.9, layer='wazuh_correlation', threat_level=alert.combined_threat_level
                ))
    
    def _handle_detection(self, d: FlowDetection):
        """Handle individual detection"""
        lvl = d.threat_level.value
        if ActionType.LOG in self.enabled_actions: self._action_log(d)
        if ActionType.ALERT in self.enabled_actions and lvl >= ThreatLevel.MEDIUM.value: self._action_alert(d)
        if ActionType.BLOCK in self.enabled_actions and lvl >= self.block_threshold.value: self._action_block(d)
        if ActionType.WEBHOOK in self.enabled_actions and lvl >= ThreatLevel.MEDIUM.value: self._action_webhook(d)
        if ActionType.EMAIL in self.enabled_actions and lvl >= ThreatLevel.CRITICAL.value: self._action_email(d)
        if ActionType.WAZUH in self.enabled_actions: self._action_wazuh(d)
    
    def _action_log(self, d: FlowDetection):
        """Log detection to file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps({
                    'timestamp': datetime.now().isoformat(), 'action': 'log',
                    'detection': {'flow_id': d.flow_id, 'src_ip': d.src_ip, 'dst_ip': d.dst_ip,
                        'src_port': d.src_port, 'dst_port': d.dst_port, 'protocol': d.protocol,
                        'attack_type': d.attack_type, 'confidence': d.confidence,
                        'layer': d.layer, 'threat_level': d.threat_level.name}
                }) + '\n')
        except Exception as e:
            logger.error(f"Log failed: {e}")
    
    def _action_alert(self, d: FlowDetection):
        """Print alert to console"""
        colors = {ThreatLevel.LOW: '92', ThreatLevel.MEDIUM: '93', ThreatLevel.HIGH: '91', ThreatLevel.CRITICAL: '95'}
        c = f"\033[{colors.get(d.threat_level, '0')}m"
        print(f"{c}[ALERT] [{d.threat_level.name}] {d.attack_type} from {d.src_ip} -> {d.dst_ip}:{d.dst_port} (conf: {d.confidence:.2f}, layer: {d.layer})\033[0m")
    
    def _action_block(self, d: FlowDetection):
        """Block source IP via pfSense"""
        if not self.pfsense: return
        ip = d.src_ip
        if stats.is_blocked(ip, self.block_duration): return
        
        if self.pfsense.block_ip(ip):
            stats.record_block(ip)
            logger.info(f"Blocked {ip} for {self.block_duration}s")
            with open(self.log_file, 'a') as f:
                f.write(json.dumps({'timestamp': datetime.now().isoformat(), 'action': 'block',
                    'ip': ip, 'duration': self.block_duration, 'reason': d.attack_type}) + '\n')
    
    def _action_webhook(self, d: FlowDetection):
        """Send detection to webhook"""
        if not self.webhook_url: return
        try:
            # Disable SSL verification for localhost/development (not recommended for production)
            verify_ssl = not ('localhost' in self.webhook_url or '127.0.0.1' in self.webhook_url)
            
            response = requests.post(
                self.webhook_url, 
                json={
                    'timestamp': datetime.now().isoformat(), 
                    'source': 'hybrid-nids',
                    'detection': {
                        'src_ip': d.src_ip, 
                        'dst_ip': d.dst_ip, 
                        'attack_type': d.attack_type,
                        'confidence': d.confidence, 
                        'threat_level': d.threat_level.name, 
                        'layer': d.layer
                    }
                }, 
                timeout=10,
                verify=verify_ssl
            )
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            # If SSL error, try HTTP instead of HTTPS
            if self.webhook_url.startswith('https://'):
                http_url = self.webhook_url.replace('https://', 'http://', 1)
                logger.warning(f"HTTPS failed for {self.webhook_url}, trying HTTP: {http_url}")
                try:
                    response = requests.post(
                        http_url,
                        json={
                            'timestamp': datetime.now().isoformat(), 
                            'source': 'hybrid-nids',
                            'detection': {
                                'src_ip': d.src_ip, 
                                'dst_ip': d.dst_ip, 
                                'attack_type': d.attack_type,
                                'confidence': d.confidence, 
                                'threat_level': d.threat_level.name, 
                                'layer': d.layer
                            }
                        },
                        timeout=10
                    )
                    response.raise_for_status()
                    logger.info(f"Webhook sent successfully via HTTP fallback")
                except Exception as e2:
                    logger.error(f"Webhook failed (both HTTPS and HTTP): {e2}")
            else:
                logger.error(f"Webhook SSL error: {e}. Check if URL should be HTTP instead of HTTPS.")
        except Exception as e:
            logger.error(f"Webhook failed: {e}")
    
    def _action_email(self, d: FlowDetection):
        """Send email alert"""
        if not self.email_config: return
        try:
            cfg = self.email_config
            to_addr = cfg.get('to')
            if not to_addr: return
            
            msg = MIMEMultipart()
            msg['From'] = cfg.get('from', cfg.get('username'))
            msg['To'] = to_addr
            msg['Subject'] = f'[{d.threat_level.name}] NIDS Alert: {d.attack_type}'
            msg.attach(MIMEText(f"""NIDS Alert: {d.threat_level.name}
Attack: {d.attack_type} | Confidence: {d.confidence:.2%} | Layer: {d.layer}
Source: {d.src_ip}:{d.src_port} -> {d.dst_ip}:{d.dst_port} ({d.protocol})
Time: {datetime.now().isoformat()}""", 'plain'))
            
            with smtplib.SMTP(cfg.get('smtp_host', 'localhost'), cfg.get('smtp_port', 587)) as srv:
                srv.starttls()
                if cfg.get('username') and cfg.get('password'):
                    srv.login(cfg['username'], cfg['password'])
                srv.send_message(msg)
        except Exception as e:
            logger.error(f"Email failed: {e}")
    
    def _action_wazuh(self, d: FlowDetection):
        """Send detection to Wazuh (socket/API/log)"""
        if not self.wazuh_client:
            try: self.wazuh_client = WazuhClient(self.wazuh_config) if self.wazuh_config else WazuhClient()
            except: return
        try:
            self.wazuh_client.send(d)
        except Exception as e:
            logger.error(f"Wazuh failed: {e}")
    
    def cleanup_expired_blocks(self):
        """Unblock IPs that exceeded block duration"""
        if not self.pfsense: return
        for ip in stats.get_expired(self.block_duration):
            if self.pfsense.unblock_ip(ip):
                stats.record_unblock(ip)
    
    def get_hids_alerts(self, minutes: int = 5) -> List[Dict]:
        """Get recent Wazuh HIDS alerts"""
        if not self.hids_correlator: return []
        try: return [a.to_dict() for a in self.hids_correlator.parser.get_recent_alerts(minutes)]
        except: return []
