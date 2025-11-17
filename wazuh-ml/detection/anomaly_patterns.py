"""
Pattern definitions for whitelist and suspicious anomaly rules.
"""

WHITELISTED_PATTERNS = {
    "ssh_internal_admin": {
        "description": "SSH login từ admin nội bộ",
        "conditions": {
            "event_desc": ["sshd: authentication success"],
            "src_ip": ["172.16.158.1", "172.16.158.100"],
            "is_business_hours": [1],
        },
    },
    "dns_queries_internal": {
        "description": "Internal DNS queries/responses",
        "conditions": {"proto": ["udp"], "dst_port": [53], "is_internal_src": [1], "is_internal_dst": [1]},
    },
    "icmp_ping_internal": {
        "description": "ICMP echo internal monitoring",
        "conditions": {"event_desc": ["icmp echo request", "icmp echo reply"], "is_internal_communication": [1]},
    },
    "ntp_sync": {"description": "NTP time synchronization", "conditions": {"dst_port": [123], "proto": ["udp"]}},
    "dhcp_activity": {"description": "DHCP client/server traffic", "conditions": {"dst_port": [67, 68], "proto": ["udp"]}},
    "pfSense_webui": {
        "description": "pfSense WebUI access from admin",
        "conditions": {"dst_ip": ["172.16.158.100", "172.16.158.1"], "dst_port": [443, 4443], "is_internal_src": [1]},
    },
    "system_update": {
        "description": "System updates và package management",
        "conditions": {"event_desc": ["apt user-agent", "package management"], "rule_level": [0, 1, 2, 3, 4]},
    },
    "scheduled_integrity_check": {
        "description": "FIM checks định kỳ",
        "conditions": {"event_desc": ["integrity checksum changed"], "hour": [2, 3], "rule_level": list(range(8))},
    },
    "compliance_check": {
        "description": "CIS compliance checks",
        "conditions": {"event_desc": ["cis", "benchmark", "status changed from failed to passed"]},
    },
}

SUSPICIOUS_PATTERNS = {
    "brute_force": {
        "description": "Brute force attempts",
        "conditions": {"event_desc": ["non-existent user", "failed password", "invalid user"]},
        "score_multiplier": 2.0,
    },
    "port_scan": {
        "description": "Potential port scanning activity",
        "conditions": {"event_desc": ["port scan", "nmap", "syn scan", "xmas scan"]},
        "score_multiplier": 2.0,
    },
    "external_rdp_attempt": {
        "description": "RDP access attempts from external source",
        "conditions": {"is_internal_src": [0], "dst_port": [3389]},
        "score_multiplier": 2.5,
    },
    "http_scan_tools": {
        "description": "Web scanning tools detected",
        "conditions": {"event_desc": ["nikto", "sqlmap", "gobuster", "dirb"]},
        "score_multiplier": 2.2,
    },
    "web_sql_injection_signatures": {
        "description": "Possible SQL injection payload patterns",
        "conditions": {"event_desc": ["sql injection", "union select", "or 1=1", "' or '1'='1"]},
        "score_multiplier": 2.8,
    },
    "ssh_password_spray": {
        "description": "Multiple SSH auth failures",
        "conditions": {"event_desc": ["failed password", "authentication failure"]},
        "score_multiplier": 2.3,
    },
    "high_egress_to_external": {
        "description": "High egress bytes to external destination",
        "conditions": {"is_internal_src": [1], "is_internal_dst": [0], "bytes": [1_000_000]},
        "score_multiplier": 1.8,
    },
    "lateral_movement": {
        "description": "Internal-to-internal lateral movement",
        "conditions": {"is_internal_src": [1], "is_internal_dst": [1], "dst_port": [445, 3389, 5985, 5986]},
        "score_multiplier": 2.2,
    },
    "night_activity": {
        "description": "Activity vào ban đêm",
        "conditions": {"is_night": [1], "rule_level": list(range(5, 16))},
        "score_multiplier": 1.5,
    },
    "external_access": {
        "description": "Access từ external IPs",
        "conditions": {"is_internal_src": [0], "rule_level": list(range(5, 16))},
        "score_multiplier": 1.8,
    },
    "high_severity": {
        "description": "High/Critical severity events",
        "conditions": {"is_critical": [1]},
        "score_multiplier": 2.5,
    },
    "burst_activity": {
        "description": "Burst of events",
        "conditions": {"is_burst": [1]},
        "score_multiplier": 1.3,
    },
}


