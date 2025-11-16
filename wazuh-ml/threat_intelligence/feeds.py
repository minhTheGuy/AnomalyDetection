"""
Threat Intelligence Feeds Integration
Tích hợp các nguồn threat intelligence để enhance detection
"""
import os
import json
import requests
import pandas as pd
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import hashlib
import time


class ThreatIntelligenceFeed:
    """Base class cho threat intelligence feeds"""
    
    def __init__(self, cache_dir: str = "data/threat_intel"):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_ttl = 3600  # 1 hour cache
        
    def get_malicious_ips(self) -> Set[str]:
        """Get list of malicious IPs"""
        raise NotImplementedError
        
    def get_malicious_hashes(self) -> Set[str]:
        """Get list of malicious file hashes"""
        raise NotImplementedError
        
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is malicious"""
        return ip in self.get_malicious_ips()
        
    def is_malicious_hash(self, file_hash: str) -> bool:
        """Check if file hash is malicious"""
        return file_hash.lower() in {h.lower() for h in self.get_malicious_hashes()}


class AbuseIPDBFeed(ThreatIntelligenceFeed):
    """AbuseIPDB threat intelligence feed"""
    
    def __init__(self, api_key: Optional[str] = None, cache_dir: str = "data/threat_intel"):
        super().__init__(cache_dir)
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.api_url = "https://api.abuseipdb.com/api/v2/check"
        
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation"""
        cache_file = os.path.join(self.cache_dir, f"abuseipdb_{ip}.json")
        
        # Check cache
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < self.cache_ttl:
                with open(cache_file, 'r') as f:
                    return json.load(f)
        
        if not self.api_key:
            return {"is_public": False, "abuse_confidence": 0}
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(self.api_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "is_public": data.get("data", {}).get("isPublic", False),
                "abuse_confidence": data.get("data", {}).get("abuseConfidencePercentage", 0),
                "usage_type": data.get("data", {}).get("usageType", ""),
                "country": data.get("data", {}).get("countryCode", ""),
            }
            
            # Cache result
            with open(cache_file, 'w') as f:
                json.dump(result, f)
                
            return result
        except Exception as e:
            print(f"Error checking IP {ip}: {e}")
            return {"is_public": False, "abuse_confidence": 0}
    
    def get_malicious_ips(self) -> Set[str]:
        """Get malicious IPs (from cache or API)"""
        # This would typically load from a blocklist
        # For now, return empty set
        return set()


class VirusTotalFeed(ThreatIntelligenceFeed):
    """VirusTotal threat intelligence feed"""
    
    def __init__(self, api_key: Optional[str] = None, cache_dir: str = "data/threat_intel"):
        super().__init__(cache_dir)
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.api_url = "https://www.virustotal.com/vtapi/v2"
        
    def check_hash(self, file_hash: str) -> Dict:
        """Check file hash reputation"""
        cache_file = os.path.join(self.cache_dir, f"vt_{file_hash}.json")
        
        # Check cache
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < self.cache_ttl:
                with open(cache_file, 'r') as f:
                    return json.load(f)
        
        if not self.api_key:
            return {"detected": False, "positives": 0}
        
        try:
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            response = requests.get(f"{self.api_url}/file/report", params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "detected": data.get("response_code") == 1,
                "positives": data.get("positives", 0),
                "total": data.get("total", 0),
                "scan_date": data.get("scan_date", ""),
            }
            
            # Cache result
            with open(cache_file, 'w') as f:
                json.dump(result, f)
                
            return result
        except Exception as e:
            print(f"Error checking hash {file_hash}: {e}")
            return {"detected": False, "positives": 0}
    
    def get_malicious_hashes(self) -> Set[str]:
        """Get malicious hashes (from cache)"""
        # Load from cache files
        hashes = set()
        for filename in os.listdir(self.cache_dir):
            if filename.startswith("vt_") and filename.endswith(".json"):
                file_hash = filename[3:-5]  # Remove "vt_" and ".json"
                cache_file = os.path.join(self.cache_dir, filename)
                try:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                        if data.get("detected") and data.get("positives", 0) > 0:
                            hashes.add(file_hash)
                except:
                    pass
        return hashes


class LocalThreatFeed(ThreatIntelligenceFeed):
    """Local threat intelligence feed (from CSV/JSON files)"""
    
    def __init__(self, ip_list_path: Optional[str] = None, hash_list_path: Optional[str] = None, 
                 cache_dir: str = "data/threat_intel"):
        super().__init__(cache_dir)
        self.ip_list_path = ip_list_path or os.path.join(cache_dir, "malicious_ips.txt")
        self.hash_list_path = hash_list_path or os.path.join(cache_dir, "malicious_hashes.txt")
        self._malicious_ips: Optional[Set[str]] = None
        self._malicious_hashes: Optional[Set[str]] = None
        
    def load_malicious_ips(self) -> Set[str]:
        """Load malicious IPs from file"""
        if self._malicious_ips is not None:
            return self._malicious_ips
            
        ips = set()
        if os.path.exists(self.ip_list_path):
            try:
                with open(self.ip_list_path, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            ips.add(ip)
            except Exception as e:
                print(f"Error loading IP list: {e}")
        
        self._malicious_ips = ips
        return ips
    
    def load_malicious_hashes(self) -> Set[str]:
        """Load malicious hashes from file"""
        if self._malicious_hashes is not None:
            return self._malicious_hashes
            
        hashes = set()
        if os.path.exists(self.hash_list_path):
            try:
                with open(self.hash_list_path, 'r') as f:
                    for line in f:
                        file_hash = line.strip().lower()
                        if file_hash and not file_hash.startswith('#'):
                            hashes.add(file_hash)
            except Exception as e:
                print(f"Error loading hash list: {e}")
        
        self._malicious_hashes = hashes
        return hashes
    
    def get_malicious_ips(self) -> Set[str]:
        """Get malicious IPs"""
        return self.load_malicious_ips()
    
    def get_malicious_hashes(self) -> Set[str]:
        """Get malicious hashes"""
        return self.load_malicious_hashes()
    
    def add_malicious_ip(self, ip: str):
        """Add IP to malicious list"""
        ips = self.load_malicious_ips()
        ips.add(ip)
        self._malicious_ips = ips
        
        # Save to file
        os.makedirs(os.path.dirname(self.ip_list_path), exist_ok=True)
        with open(self.ip_list_path, 'a') as f:
            f.write(f"{ip}\n")
    
    def add_malicious_hash(self, file_hash: str):
        """Add hash to malicious list"""
        hashes = self.load_malicious_hashes()
        hashes.add(file_hash.lower())
        self._malicious_hashes = hashes
        
        # Save to file
        os.makedirs(os.path.dirname(self.hash_list_path), exist_ok=True)
        with open(self.hash_list_path, 'a') as f:
            f.write(f"{file_hash.lower()}\n")


class ThreatIntelligenceManager:
    """Manager cho multiple threat intelligence feeds"""
    
    def __init__(self):
        self.feeds: List[ThreatIntelligenceFeed] = []
        self.local_feed = LocalThreatFeed()
        self.feeds.append(self.local_feed)
        
        # Add external feeds if API keys are available
        abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        if abuseipdb_key:
            self.feeds.append(AbuseIPDBFeed(api_key=abuseipdb_key))
        
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if vt_key:
            self.feeds.append(VirusTotalFeed(api_key=vt_key))
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is malicious across all feeds"""
        for feed in self.feeds:
            if feed.is_malicious_ip(ip):
                return True
        return False
    
    def is_malicious_hash(self, file_hash: str) -> bool:
        """Check if file hash is malicious across all feeds"""
        for feed in self.feeds:
            if feed.is_malicious_hash(file_hash):
                return True
        return False
    
    def enrich_log(self, log: Dict) -> Dict:
        """Enrich log với threat intelligence data"""
        enriched = log.copy()
        
        # Check source IP
        src_ip = log.get('src_ip') or log.get('data', {}).get('src_ip')
        if src_ip:
            enriched['ti_src_ip_malicious'] = self.is_malicious_ip(src_ip)
            if isinstance(self.feeds[0], AbuseIPDBFeed):
                abuse_data = self.feeds[0].check_ip(src_ip)
                enriched['ti_src_ip_abuse_confidence'] = abuse_data.get('abuse_confidence', 0)
        
        # Check destination IP
        dst_ip = log.get('dst_ip') or log.get('data', {}).get('dest_ip')
        if dst_ip:
            enriched['ti_dst_ip_malicious'] = self.is_malicious_ip(dst_ip)
        
        # Check file hash
        file_hash = log.get('syscheck_sha256') or log.get('syscheck', {}).get('sha256_after')
        if file_hash:
            enriched['ti_file_hash_malicious'] = self.is_malicious_hash(file_hash)
            if isinstance(self.feeds[0], VirusTotalFeed):
                vt_data = self.feeds[0].check_hash(file_hash)
                enriched['ti_file_hash_positives'] = vt_data.get('positives', 0)
        
        return enriched
    
    def add_detected_threat(self, ip: Optional[str] = None, file_hash: Optional[str] = None):
        """Add detected threat to local feed"""
        if ip:
            self.local_feed.add_malicious_ip(ip)
        if file_hash:
            self.local_feed.add_malicious_hash(file_hash)


# Global instance
_threat_intel_manager: Optional[ThreatIntelligenceManager] = None

def get_threat_intel_manager() -> ThreatIntelligenceManager:
    """Get global threat intelligence manager instance"""
    global _threat_intel_manager
    if _threat_intel_manager is None:
        _threat_intel_manager = ThreatIntelligenceManager()
    return _threat_intel_manager

