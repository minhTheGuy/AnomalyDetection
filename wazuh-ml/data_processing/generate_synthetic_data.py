#!/usr/bin/env python3
"""
Script tạo synthetic data để augment training dataset
Tạo ra file JSON giống format của security_logs_raw.json từ Wazuh Indexer
"""

import json
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import sys
import pandas as pd

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import RAW_JSON_PATH, CSV_PATH
from utils.common import safe_save_csv, print_header
from data_processing.common import parse_hits_to_dataframe


# ============================================================================
# CONFIGURATION
# ============================================================================

# Agents
AGENTS = [
    {"name": "wazuh-server", "ip": "172.16.158.150"},
    {"name": "pfsense.home.arpa", "ip": "172.16.158.100"},
    {"name": "web-server-01", "ip": "192.168.1.10"},
    {"name": "db-server-01", "ip": "192.168.1.20"},
    {"name": "workstation-01", "ip": "192.168.1.100"},
]

# IP ranges
INTERNAL_IPS = ["192.168.1.", "192.168.180.", "172.16.158.", "10.0.0."]
EXTERNAL_IPS = ["1.1.1.1", "8.8.8.8", "118.69.65.177", "185.125.190.83", "199.19.53.1"]

# Ports
WELL_KNOWN_PORTS = [22, 80, 443, 53, 25, 110, 143, 993, 995]
REGISTERED_PORTS = list(range(1024, 49152))
DYNAMIC_PORTS = list(range(49152, 65536))

# Protocols
PROTOCOLS = ["tcp", "udp", "icmp"]
APP_PROTOCOLS = ["http", "https", "ssl", "dns", "ssh", "ftp", "smtp"]

# Rule IDs và levels
RULE_IDS = {
    "benign": [5715, 503, 5502, 19011, 52004],
    "attack": [86601, 2501, 550, 554, 553, 40704],
    "syscheck": [550, 554, 553],
}

RULE_LEVELS = {
    "benign": [0, 1, 2, 3],
    "attack": [5, 7, 9, 12, 15],
    "syscheck": [3, 5, 7],
}

# Decoders
DECODERS = ["sshd", "ossec", "sca", "suricata", "json", "syscheck_integrity_changed", 
            "syscheck_new_entry", "syscheck_deleted", "systemd", "pam", "kernel"]

# Locations
LOCATIONS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "journald",
    "syscheck",
    "/var/log/suricata/suricata_em044793/eve.json",
    "sca",
    "wazuh-agent",
]


# ============================================================================
# EVENT GENERATORS
# ============================================================================

def generate_sha256(text: str) -> str:
    """Generate SHA256 hash"""
    return hashlib.sha256(text.encode()).hexdigest()


def generate_timestamp(base_time: datetime, offset_seconds: int = 0) -> str:
    """Generate ISO timestamp"""
    ts = base_time + timedelta(seconds=offset_seconds)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_internal_ip() -> str:
    """Generate internal IP"""
    base = random.choice(INTERNAL_IPS)
    if base.endswith("."):
        return base + str(random.randint(1, 254))
    return base


def generate_external_ip() -> str:
    """Generate external IP"""
    return random.choice(EXTERNAL_IPS)


def generate_port(port_type: str = "random") -> int:
    """Generate port number"""
    if port_type == "well_known":
        return random.choice(WELL_KNOWN_PORTS)
    elif port_type == "registered":
        return random.choice(REGISTERED_PORTS)
    elif port_type == "dynamic":
        return random.choice(DYNAMIC_PORTS)
    else:
        return random.choice(WELL_KNOWN_PORTS + REGISTERED_PORTS[:1000])


def generate_benign_ssh_event(base_time: datetime, offset: int) -> Dict:
    """Generate benign SSH authentication success event"""
    agent = random.choice(AGENTS)
    src_ip = generate_internal_ip()
    
    return {
        "_index": f"wazuh-alerts-4.x-{base_time.strftime('%Y.%m.%d')}",
        "_id": f"synth_{random.randint(100000, 999999)}",
        "_score": 1.0,
        "_source": {
            "agent": agent,
            "@timestamp": generate_timestamp(base_time, offset),
            "timestamp": generate_timestamp(base_time, offset),
            "rule": {
                "level": 3,
                "description": "sshd: authentication success.",
                "groups": ["syslog", "sshd", "authentication_success"],
                "id": "5715"
            },
            "location": "/var/log/auth.log",
            "decoder": {"name": "sshd"},
            "full_log": f"{base_time.strftime('%b %d %H:%M:%S')} {agent['name']} sshd[{random.randint(10000, 99999)}]: Accepted password for user{random.randint(1, 10)} from {src_ip} port {generate_port('dynamic')} ssh2"
        }
    }


def generate_benign_network_event(base_time: datetime, offset: int) -> Dict:
    """Generate benign network event (DNS, HTTP, etc.)"""
    agent = random.choice(AGENTS)
    proto = random.choice(["tcp", "udp"])
    app_proto = random.choice(["dns", "http", "https"])
    
    src_ip = generate_internal_ip()
    dst_ip = generate_external_ip() if random.random() > 0.3 else generate_internal_ip()
    src_port = generate_port("dynamic")
    dst_port = 53 if app_proto == "dns" else (443 if app_proto == "https" else 80)
    
    bytes_toserver = random.randint(100, 5000)
    bytes_toclient = random.randint(500, 10000)
    
    return {
        "_index": f"wazuh-alerts-4.x-{base_time.strftime('%Y.%m.%d')}",
        "_id": f"synth_{random.randint(100000, 999999)}",
        "_score": 1.0,
        "_source": {
            "agent": agent,
            "@timestamp": generate_timestamp(base_time, offset),
            "timestamp": generate_timestamp(base_time, offset),
            "rule": {
                "level": random.choice([2, 3]),
                "description": f"suricata: {app_proto} connection",
                "groups": ["ids", "suricata"],
                "id": "86601"
            },
            "location": "/var/log/suricata/suricata_em044793/eve.json",
            "decoder": {"name": "json"},
            "data": {
                "event_type": "flow",
                "app_proto": app_proto,
                "proto": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "flow": {
                    "bytes_toserver": bytes_toserver,
                    "bytes_toclient": bytes_toclient,
                    "pkts_toserver": random.randint(1, 10),
                    "pkts_toclient": random.randint(1, 15)
                }
            },
            "full_log": f"{app_proto} connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
        }
    }


def generate_attack_brute_force_event(base_time: datetime, offset: int) -> Dict:
    """Generate brute force attack event"""
    agent = random.choice(AGENTS)
    src_ip = generate_external_ip() if random.random() > 0.5 else generate_internal_ip()
    
    return {
        "_index": f"wazuh-alerts-4.x-{base_time.strftime('%Y.%m.%d')}",
        "_id": f"synth_{random.randint(100000, 999999)}",
        "_score": 1.0,
        "_source": {
            "agent": agent,
            "@timestamp": generate_timestamp(base_time, offset),
            "timestamp": generate_timestamp(base_time, offset),
            "rule": {
                "level": random.choice([5, 7, 9]),
                "description": "sshd: authentication failed.",
                "groups": ["syslog", "sshd", "authentication_failed"],
                "id": "5712"
            },
            "location": "/var/log/auth.log",
            "decoder": {"name": "sshd"},
            "full_log": f"{base_time.strftime('%b %d %H:%M:%S')} {agent['name']} sshd[{random.randint(10000, 99999)}]: Failed password for invalid user admin{random.randint(1, 100)} from {src_ip} port {generate_port('dynamic')} ssh2"
        }
    }


def generate_attack_scan_event(base_time: datetime, offset: int) -> Dict:
    """Generate port scan attack event"""
    agent = random.choice(AGENTS)
    src_ip = generate_external_ip() if random.random() > 0.7 else generate_internal_ip()
    dst_ip = agent["ip"]
    
    # Scan các port khác nhau
    scan_ports = [22, 80, 443, 3389, 5432, 3306, 1521, 5800, 5900]
    dst_port = random.choice(scan_ports)
    
    signatures = [
        "et scan potential ssh scan",
        "et scan suspicious inbound to postgresql port 5432",
        "et scan potential vnc scan 5800-5820",
        "et scan suspicious inbound to mysql port 3306",
        "et scan potential rdp scan",
        "gpl dns named version attempt",
        "et scan potential http probe",
        "et scan tcp probe",
    ]
    signature = random.choice(signatures)
    
    return {
        "_index": f"wazuh-alerts-4.x-{base_time.strftime('%Y.%m.%d')}",
        "_id": f"synth_{random.randint(100000, 999999)}",
        "_score": 1.0,
        "_source": {
            "agent": agent,
            "@timestamp": generate_timestamp(base_time, offset),
            "timestamp": generate_timestamp(base_time, offset),
            "rule": {
                "level": random.choice([2, 3, 5]),
                "description": f"suricata: alert - {signature}",
                "groups": ["ids", "suricata"],
                "id": "86601"
            },
            "location": "/var/log/suricata/suricata_em044793/eve.json",
            "decoder": {"name": "json"},
            "data": {
                "event_type": "alert",
                "proto": "tcp",
                "src_ip": src_ip,
                "src_port": generate_port("dynamic"),
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "alert": {
                    "severity": random.choice([2, 3]),
                    "signature": signature,
                    "category": random.choice(["attempted information leak", "potentially bad traffic"])
                },
                "flow": {
                    "bytes_toserver": random.randint(60, 200),
                    "bytes_toclient": 0,
                    "pkts_toserver": 1,
                    "pkts_toclient": 0
                }
            },
            "full_log": f"Alert: {signature} from {src_ip} to {dst_ip}:{dst_port}"
        }
    }


def generate_syscheck_event(base_time: datetime, offset: int, event_type: str = "modified") -> Dict:
    """Generate syscheck (file integrity) event"""
    agent = random.choice(AGENTS)
    
    syscheck_paths = {
        "modified": [
            "/etc/hosts",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/etc/wazuh-indexer/opensearch-security/internal_users.yml",
        ],
        "added": [
            "/tmp/suspicious_file.sh",
            "/etc/rc5.d/k01wazuh-indexer",
            "/boot/vmlinuz-6.8.0-87-generic",
        ],
        "deleted": [
            "/tmp/temp_file.log",
            "/boot/config-6.8.0-85-generic",
        ]
    }
    
    path = random.choice(syscheck_paths.get(event_type, syscheck_paths["modified"]))
    file_size = random.randint(100, 100000) if event_type != "deleted" else random.randint(100, 50000)
    
    rule_ids = {"modified": "550", "added": "554", "deleted": "553"}
    rule_levels = {"modified": 7, "added": 5, "deleted": 7}
    
    return {
        "_index": f"wazuh-alerts-4.x-{base_time.strftime('%Y.%m.%d')}",
        "_id": f"synth_{random.randint(100000, 999999)}",
        "_score": 1.0,
        "_source": {
            "agent": agent,
            "@timestamp": generate_timestamp(base_time, offset),
            "timestamp": generate_timestamp(base_time, offset),
            "rule": {
                "level": rule_levels[event_type],
                "description": f"integrity checksum changed." if event_type == "modified" else f"file {event_type} to the system.",
                "groups": ["ossec", "syscheck", f"syscheck_entry_{event_type}", "syscheck_file"],
                "id": rule_ids[event_type]
            },
            "location": "syscheck",
            "decoder": {"name": f"syscheck_{'integrity_changed' if event_type == 'modified' else ('new_entry' if event_type == 'added' else 'deleted')}"},
            "syscheck": {
                "event": event_type,
                "path": path,
                "size_after": file_size if event_type != "deleted" else None,
                "sha256_after": generate_sha256(path + str(file_size)) if event_type != "deleted" else None,
                "uname_after": random.choice(["root", "wazuh-indexer", "www-data"]),
                "mtime_after": (base_time - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%dT%H:%M:%S")
            },
            "full_log": f"File '{path}' {event_type}\nMode: scheduled"
        }
    }


def generate_malware_alert_event(base_time: datetime, offset: int) -> Dict:
    """Generate malware detection alert"""
    agent = random.choice(AGENTS)
    src_ip = generate_external_ip()
    dst_ip = agent["ip"]
    
    signatures = [
        "ET MALWARE Suspicious inbound to mySQL port 3306",
        "ET TROJAN Possible C2 Communication",
        "ET MALWARE Known Malware IP",
        "ET MALWARE Suspicious inbound to postgresql port 5432",
        "ET TROJAN Possible Backdoor Communication",
        "ET MALWARE Win32 Possible Malware Download",
        "ET TROJAN Possible C2 Heartbeat",
    ]
    signature = random.choice(signatures)
    
    return {
        "_index": f"wazuh-alerts-4.x-{base_time.strftime('%Y.%m.%d')}",
        "_id": f"synth_{random.randint(100000, 999999)}",
        "_score": 1.0,
        "_source": {
            "agent": agent,
            "@timestamp": generate_timestamp(base_time, offset),
            "timestamp": generate_timestamp(base_time, offset),
            "rule": {
                "level": random.choice([12, 15]),
                "description": f"suricata: alert - {signature}",
                "groups": ["ids", "suricata"],
                "id": "86601"
            },
            "location": "/var/log/suricata/suricata_em044793/eve.json",
            "decoder": {"name": "json"},
            "data": {
                "event_type": "alert",
                "proto": "tcp",
                "src_ip": src_ip,
                "src_port": generate_port("dynamic"),
                "dest_ip": dst_ip,
                "dest_port": random.choice([3306, 4444, 8080]),
                "alert": {
                    "severity": 3,
                    "signature": signature,
                    "category": "A Network Trojan was detected"
                },
                "flow": {
                    "bytes_toserver": random.randint(1000, 10000),
                    "bytes_toclient": random.randint(500, 5000),
                    "pkts_toserver": random.randint(10, 50),
                    "pkts_toclient": random.randint(5, 30)
                }
            },
            "full_log": f"Alert: {signature} from {src_ip} to {dst_ip}"
        }
    }


# ============================================================================
# MAIN GENERATOR
# ============================================================================

def generate_synthetic_data(
    num_events: int = 5000,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    benign_ratio: float = 0.7,
    output_path: Optional[str] = None,
    csv_output_path: Optional[str] = None
) -> Dict:
    """
    Generate synthetic Wazuh logs in Elasticsearch format
    
    Args:
        num_events: Total number of events to generate
        start_date: Start date for events (default: 7 days ago)
        end_date: End date for events (default: now)
        benign_ratio: Ratio of benign vs attack events (0.0-1.0)
        output_path: Path to save JSON file (default: RAW_JSON_PATH)
    """
    if start_date is None:
        start_date = datetime.now() - timedelta(days=7)
    if end_date is None:
        end_date = datetime.now()
    if output_path is None:
        output_path = RAW_JSON_PATH
    
    print_header("GENERATING SYNTHETIC DATA")
    print(f"Generating {num_events} synthetic events...")
    print(f"Date range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
    print(f"Benign ratio: {benign_ratio*100:.1f}%")
    
    hits = []
    time_span = (end_date - start_date).total_seconds()
    
    num_benign = int(num_events * benign_ratio)
    num_attack = num_events - num_benign
    
    # Generate benign events
    print(f"\nGenerating {num_benign} benign events...")
    for i in range(num_benign):
        offset = int((i / num_benign) * time_span)
        base_time = start_date + timedelta(seconds=offset)
        
        # Randomly choose benign event type
        event_type = random.choices(
            ["ssh", "network", "syscheck"],
            weights=[0.4, 0.4, 0.2]
        )[0]
        
        if event_type == "ssh":
            hits.append(generate_benign_ssh_event(base_time, 0))
        elif event_type == "network":
            hits.append(generate_benign_network_event(base_time, 0))
        else:  # syscheck
            syscheck_type = random.choice(["modified", "added"])
            hits.append(generate_syscheck_event(base_time, 0, syscheck_type))
        
        if (i + 1) % 500 == 0:
            print(f"  Generated {i + 1}/{num_benign} benign events...")
    
    # Generate attack events
    print(f"\nGenerating {num_attack} attack events...")
    for i in range(num_attack):
        offset = int((i / num_attack) * time_span)
        base_time = start_date + timedelta(seconds=offset)
        
        # Randomly choose attack type
        attack_type = random.choices(
            ["brute_force", "scan", "malware", "syscheck_suspicious"],
            weights=[0.3, 0.4, 0.2, 0.1]
        )[0]
        
        if attack_type == "brute_force":
            hits.append(generate_attack_brute_force_event(base_time, 0))
        elif attack_type == "scan":
            hits.append(generate_attack_scan_event(base_time, 0))
        elif attack_type == "malware":
            hits.append(generate_malware_alert_event(base_time, 0))
        else:  # syscheck_suspicious
            hits.append(generate_syscheck_event(base_time, 0, "added"))
        
        if (i + 1) % 500 == 0:
            print(f"  Generated {i + 1}/{num_attack} attack events...")
    
    # Shuffle hits to mix benign and attack events
    random.shuffle(hits)
    
    # Create Elasticsearch response format
    result = {
        "took": random.randint(20, 50),
        "timed_out": False,
        "_shards": {
            "total": 27,
            "successful": 27,
            "skipped": 0,
            "failed": 0
        },
        "hits": {
            "total": {
                "value": len(hits),
                "relation": "eq"
            },
            "max_score": 1.0,
            "hits": hits
        }
    }
    
    # Save to file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"\nGenerated {len(hits)} events")
    print(f"Saved JSON to: {output_path}")
    
    # Parse hits -> CSV format
    print(f"\nConverting to CSV format...")
    df = parse_hits_to_dataframe(hits)

    # Determine CSV output path
    if csv_output_path is None:
        if output_path == RAW_JSON_PATH or output_path is None:
            csv_output_path = CSV_PATH
        else:
            # Nếu output_path là custom, tạo CSV path tương ứng
            csv_output_path = output_path.replace(".json", ".csv")
            if csv_output_path == output_path:  # Nếu không có .json extension
                csv_output_path = output_path + ".csv"

    # Save CSV
    if safe_save_csv(df, csv_output_path):
        print(f"Saved CSV to: {csv_output_path}")
    print(f"Total records: {len(df)}")
    print(f"\nEvent breakdown:")
    print(f"  Benign: {num_benign}")
    print(f"  Attack: {num_attack}")
    
    return result


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate synthetic Wazuh logs")
    parser.add_argument("--num-events", type=int, default=5000, help="Number of events to generate")
    parser.add_argument("--benign-ratio", type=float, default=0.7, help="Ratio of benign events (0.0-1.0)")
    parser.add_argument("--days", type=int, default=7, help="Number of days to span")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file path (CSV will be auto-generated)")
    parser.add_argument("--csv-output", type=str, default=None, help="Output CSV file path (optional, auto-generated if not specified)")
    
    args = parser.parse_args()
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=args.days)
    
    generate_synthetic_data(
        num_events=args.num_events,
        start_date=start_date,
        end_date=end_date,
        benign_ratio=args.benign_ratio,
        output_path=args.output,
        csv_output_path=getattr(args, 'csv_output', None)
    )

