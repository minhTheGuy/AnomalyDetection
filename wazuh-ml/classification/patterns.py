"""
Pattern definitions cho classification
Tách riêng để code gọn và dễ maintain
"""

# Attack type patterns
ATTACK_PATTERNS = {
    'brute_force': [
        r'failed password', r'authentication failure', r'authentication failed',
        r'invalid user', r'login attempt', r'brute force', r'too many attempts',
        r'connection closed', r'connection reset', r'too many authentication failures'
    ],
    'port_scan': [
        r'et scan', r'potential.*scan', r'scan.*port', r'port.*scan',
        r'postgresql port', r'mysql port', r'ssh scan', r'vnc scan', r'rdp scan',
        r'http.*probe', r'tcp.*probe', r'udp.*probe', r'port scan', r'nmap',
        r'syn scan', r'xmas scan', r'fin scan', r'null scan', r'port sweep',
        r'network scan', r'host scan', r'multiple connection attempts',
        r'connection attempts from', r'scan.*inbound'
    ],
    'sql_injection': [
        r'sql injection', r'union select', r"or 1=1", r"' or '1'='1",
        r'select.*from', r'insert.*into', r'delete.*from', r'drop table',
        r'exec.*xp_', r'information_schema'
    ],
    'xss': [
        r'cross.site.scripting', r'xss', r'<script', r'javascript:',
        r'onerror=', r'onclick=', r'eval\(', r'document\.cookie'
    ],
    'dos_ddos': [
        r'denial of service', r'dos', r'ddos', r'flood', r'syn flood',
        r'icmp flood', r'udp flood', r'connection flood', r'resource exhaustion',
        r'too many connections', r'rate limit exceeded', r'et dos', r'et ddos',
        r'flood.*attack', r'burst.*traffic'
    ],
    'malware': [
        r'malware', r'virus', r'trojan', r'ransomware', r'backdoor',
        r'rootkit', r'worm', r'spyware', r'adware', r'exploit',
        r'payload', r'shellcode', r'et malware', r'et trojan',
        r'known malware ip', r'suspicious inbound to.*port', r'malware.*ip',
        r'trojan.*communication', r'c2 communication', r'possible.*trojan',
        r'suspicious.*malware'
    ],
    'privilege_escalation': [
        r'privilege escalation', r'sudo', r'su ', r'root access',
        r'administrator access', r'permission denied', r'access denied',
        r'unauthorized access', r'elevated privileges'
    ],
    'data_exfiltration': [
        r'data exfiltration', r'data leak', r'large data transfer',
        r'unusual data volume', r'external data transfer', r'bulk download',
        r'data export', r'sensitive data'
    ],
    'web_attack': [
        r'web attack', r'http attack', r'https attack', r'web vulnerability',
        r'nikto', r'sqlmap', r'gobuster', r'dirb', r'burp', r'owasp',
        r'path traversal', r'directory traversal', r'file inclusion',
        r'command injection', r'remote code execution'
    ],
    'suspicious_activity': [
        r'suspicious', r'anomalous', r'unusual', r'abnormal', r'atypical',
        r'irregular', r'strange', r'odd behavior', r'unexpected'
    ]
}

# Event category patterns
EVENT_CATEGORY_PATTERNS = {
    'authentication': [
        r'login', r'logout', r'authentication', r'auth', r'session',
        r'password', r'credential', r'user account', r'sshd', r'su ',
        r'sudo', r'kerberos', r'ldap'
    ],
    'file_integrity': [
        r'file integrity', r'file changed', r'file modified', r'file deleted',
        r'file created', r'integrity checksum', r'fim', r'file monitoring',
        r'file access', r'permission changed'
    ],
    'network': [
        r'network', r'connection', r'port', r'protocol', r'ip address',
        r'firewall', r'packet', r'traffic', r'network interface',
        r'network scan', r'network activity', r'suricata', r'ids', r'ips',
        r'alert', r'intrusion', r'snort'
    ],
    'system': [
        r'system', r'process', r'service', r'daemon', r'kernel',
        r'system call', r'process execution', r'service started',
        r'service stopped', r'system event'
    ],
    'compliance': [
        r'cis', r'benchmark', r'compliance', r'policy', r'audit',
        r'security policy', r'configuration', r'hardening'
    ],
    'vulnerability': [
        r'vulnerability', r'cve', r'exploit', r'security flaw',
        r'weakness', r'security issue', r'patch', r'update required'
    ],
    'malware_detection': [
        r'malware', r'virus', r'trojan', r'threat', r'infection',
        r'antivirus', r'security scan', r'threat detection'
    ],
    'web': [
        r'http', r'https', r'web', r'apache', r'nginx', r'web server',
        r'web application', r'url', r'request', r'response'
    ]
}

# Priority order cho attack type matching (quan trọng để tránh false positives)
ATTACK_PRIORITY_ORDER = [
    'malware', 'brute_force', 'port_scan', 'dos_ddos',
    'sql_injection', 'xss', 'privilege_escalation', 'data_exfiltration',
    'web_attack', 'suspicious_activity'
]

