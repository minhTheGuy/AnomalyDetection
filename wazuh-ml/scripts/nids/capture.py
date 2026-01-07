"""
capture.py - pfSense packet capture and flow extraction
"""

import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

import pandas as pd

from .config import FLOWS_DIR, FEATURE_MAPPING_REVERSE

logger = logging.getLogger(__name__)

class PfSenseCapture:
    """Capture packets from pfSense via SSH"""
    
    def __init__(self, host: str, user: str, interface: str = 'em0',
                 key_file: Optional[str] = None):
        from .utils import validate_ssh_key
        
        self.host = host
        self.user = user
        self.interface = interface
        self.key_file = validate_ssh_key(key_file)
        self._validate_connection()
    
    def _validate_connection(self):
        """Validate SSH connection to pfSense"""
        try:
            cmd = self._ssh_cmd(['echo', 'connected'])
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode != 0:
                logger.warning(f"pfSense connection test failed: {result.stderr.decode()}")
        except Exception as e:
            logger.warning(f"Could not validate pfSense connection: {e}")
    
    def _ssh_cmd(self, remote_cmd: list) -> list:
        """Build SSH command"""
        cmd = ['ssh', '-o', 'StrictHostKeyChecking=no',
               '-o', 'BatchMode=yes']
        # Only add -i if key_file exists and is accessible
        if self.key_file and Path(self.key_file).exists():
            cmd.extend(['-i', self.key_file])
        cmd.append(f'{self.user}@{self.host}')
        cmd.extend(remote_cmd)
        return cmd
    
    def capture(self, duration: int, output_path: Path) -> bool:
        """Capture packets from pfSense for specified duration"""
        try:
            # Capture on pfSense
            remote_file = f'/tmp/capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap'
            capture_cmd = self._ssh_cmd([
                'tcpdump', '-i', self.interface, '-w', remote_file,
                '-c', '10000',  # Max packets
                '-G', str(duration), '-W', '1'  # Time limit
            ])
            
            logger.info(f"Starting {duration}s packet capture on {self.interface}")
            result = subprocess.run(capture_cmd, capture_output=True, 
                                    timeout=duration + 30)
            
            if result.returncode != 0:
                logger.error(f"Capture failed: {result.stderr.decode()}")
                return False
            
            # Copy file back
            scp_cmd = ['scp', '-o', 'StrictHostKeyChecking=no']
            # Only add -i if key_file exists and is accessible
            if self.key_file and Path(self.key_file).exists():
                scp_cmd.extend(['-i', self.key_file])
            scp_cmd.extend([f'{self.user}@{self.host}:{remote_file}', str(output_path)])
            
            subprocess.run(scp_cmd, check=True, timeout=60)
            
            # Cleanup remote file
            cleanup_cmd = self._ssh_cmd(['rm', '-f', remote_file])
            subprocess.run(cleanup_cmd, timeout=10)
            
            logger.info(f"Capture saved to {output_path}")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("Capture timeout")
            return False
        except Exception as e:
            logger.error(f"Capture error: {e}")
            return False
    
    def block_ip(self, ip: str) -> bool:
        """Block IP using pfSense easyrule"""
        try:
            cmd = self._ssh_cmd(['easyrule', 'block', self.interface, ip])
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            
            if result.returncode == 0:
                logger.info(f"Blocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to block {ip}: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Block error: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP (reload filter rules)"""
        try:
            cmd = self._ssh_cmd(['pfctl', '-d', '&&', 'pfctl', '-e', '-f', 
                                '/tmp/rules.debug'])
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            logger.info(f"Unblocked IP: {ip}")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Unblock error: {e}")
            return False


def extract_flows(pcap_file: Path, output_dir: Path = FLOWS_DIR,
                  cicflowmeter_path: Optional[str] = None) -> Optional[pd.DataFrame]:
    """Extract network flows from PCAP using CICFlowMeter"""
    
    # Find CICFlowMeter
    if cicflowmeter_path and Path(cicflowmeter_path).exists():
        cfm_path = Path(cicflowmeter_path)
    else:
        # Search common locations (including Python venv)
        import shutil
        
        # First try to find in PATH
        cfm_from_path = shutil.which('cicflowmeter')
        if cfm_from_path:
            cfm_path = Path(cfm_from_path)
        else:
            search_paths = [
                Path.home() / 'mlenv' / 'bin' / 'cicflowmeter',
                Path.home() / 'CICFlowMeter' / 'bin' / 'cfm',
                Path('/opt/CICFlowMeter/bin/cfm'),
                Path('/usr/local/bin/cfm'),
                Path('/usr/local/bin/cicflowmeter'),
            ]
            cfm_path = None
            for p in search_paths:
                if p.exists():
                    cfm_path = p
                    break
    
    if not cfm_path:
        logger.error("CICFlowMeter not found. Install with: pip install cicflowmeter")
        return None
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate output CSV path
    csv_output = output_dir / f"{pcap_file.stem}_flows.csv"
    
    try:
        # Python cicflowmeter syntax: cicflowmeter -f <pcap> -c <output.csv>
        cmd = [str(cfm_path), '-f', str(pcap_file), '-c', str(csv_output)]
        logger.info(f"Extracting flows from {pcap_file.name}")
        
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        
        if result.returncode != 0:
            stderr = result.stderr.decode() if result.stderr else ''
            logger.error(f"Flow extraction failed: {stderr}")
            return None
        
        # Check if CSV was created
        if not csv_output.exists():
            # Try to find any generated CSV
            csv_files = list(output_dir.glob('*.csv'))
            if not csv_files:
                logger.error("No flow CSV generated")
                return None
            csv_output = max(csv_files, key=lambda p: p.stat().st_mtime)
        
        df = pd.read_csv(csv_output)
        
        # Normalize column names (lowercase, underscores)
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
        
        # Map cicflowmeter column names to CIC-IDS-2017 format (for model compatibility)
        df = df.rename(columns=FEATURE_MAPPING_REVERSE)
        
        # Clean data
        df = df.replace([float('inf'), float('-inf')], 0)
        df = df.fillna(0)
        
        logger.info(f"Extracted {len(df)} flows from {pcap_file.name}")
        return df
        
    except subprocess.TimeoutExpired:
        logger.error("Flow extraction timeout")
        return None
    except Exception as e:
        logger.error(f"Flow extraction error: {e}")
        return None
