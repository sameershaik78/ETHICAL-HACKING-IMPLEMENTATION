"""
Pre-curated High-Fidelity Threat Intelligence Database of IOCs
Contains simulated and real-world known threat indicators for rapid offline / baseline evaluation.
"""

KNOWN_IOCS = {
    # Malicious IP Addresses
    "185.220.101.5": {
        "type": "ip",
        "reputation_score": 98.0,
        "malicious_count": 68,
        "total_engines": 72,
        "threat_labels": "Tor Exit Node, Cobalt Strike C2, Brute-Force Bot",
        "country": "Germany",
        "isp": "Zwiebelfreunde e.V.",
        "category": "Command and Control",
        "mitre_id": "T1071"
    },
    "45.33.32.156": {
        "type": "ip",
        "reputation_score": 92.0,
        "malicious_count": 54,
        "total_engines": 70,
        "threat_labels": "Mirai Botnet, Port Scanner, SSH Brute Force",
        "country": "United States",
        "isp": "Linode, LLC",
        "category": "Scanner / Botnet",
        "mitre_id": "T1110"
    },
    "194.26.29.112": {
        "type": "ip",
        "reputation_score": 95.0,
        "malicious_count": 61,
        "total_engines": 69,
        "threat_labels": "LockBit Ransomware C2, DarkWeb Gateway",
        "country": "Russia",
        "isp": "Hostkey B.V.",
        "category": "Ransomware C2",
        "mitre_id": "T1486"
    },
    "103.203.57.18": {
        "type": "ip",
        "reputation_score": 88.0,
        "malicious_count": 48,
        "total_engines": 68,
        "threat_labels": "SQLi Exploit Source, Automated Scanner",
        "country": "Hong Kong",
        "isp": "Ucloud Information Tech",
        "category": "Web Exploitation",
        "mitre_id": "T1190"
    },
    "91.240.118.234": {
        "type": "ip",
        "reputation_score": 96.0,
        "malicious_count": 65,
        "total_engines": 71,
        "threat_labels": "Emotet Beacon, Banking Trojan Relay",
        "country": "Netherlands",
        "isp": "Serverion B.V.",
        "category": "Trojan / C2",
        "mitre_id": "T1071"
    },
    "198.51.100.44": {
        "type": "ip",
        "reputation_score": 85.0,
        "malicious_count": 42,
        "total_engines": 65,
        "threat_labels": "Phishing Proxy, Credential Harvester",
        "country": "Panama",
        "isp": "Offshore Hosting Ltd",
        "category": "Phishing",
        "mitre_id": "T1566"
    },
    "203.0.113.195": {
        "type": "ip",
        "reputation_score": 82.0,
        "malicious_count": 39,
        "total_engines": 65,
        "threat_labels": "DNS Tunneling Exfiltration Endpoint",
        "country": "Seychelles",
        "isp": "Global Cloud Connect",
        "category": "Data Exfiltration",
        "mitre_id": "T1048"
    },

    # Benign / Safe IP Addresses (for false positive calibration)
    "8.8.8.8": {
        "type": "ip",
        "reputation_score": 0.0,
        "malicious_count": 0,
        "total_engines": 75,
        "threat_labels": "Clean, Google Public DNS",
        "country": "United States",
        "isp": "Google LLC",
        "category": "Benign DNS",
        "mitre_id": None
    },
    "1.1.1.1": {
        "type": "ip",
        "reputation_score": 0.0,
        "malicious_count": 0,
        "total_engines": 75,
        "threat_labels": "Clean, Cloudflare Resolver",
        "country": "Australia",
        "isp": "Cloudflare, Inc.",
        "category": "Benign DNS",
        "mitre_id": None
    },
    "13.107.4.52": {
        "type": "ip",
        "reputation_score": 1.0,
        "malicious_count": 0,
        "total_engines": 72,
        "threat_labels": "Clean, Microsoft Azure CDN",
        "country": "United States",
        "isp": "Microsoft Corporation",
        "category": "Benign Infrastructure",
        "mitre_id": None
    },

    # Malicious Domains
    "login-microsoftonline-verify.cc": {
        "type": "domain",
        "reputation_score": 96.0,
        "malicious_count": 58,
        "total_engines": 68,
        "threat_labels": "Phishing, Microsoft Impersonation, Credential Theft",
        "category": "Phishing",
        "mitre_id": "T1566"
    },
    "update-windows-defender-service.org": {
        "type": "domain",
        "reputation_score": 94.0,
        "malicious_count": 52,
        "total_engines": 67,
        "threat_labels": "Malware Dropper, Fake Defender Update",
        "category": "Malware Delivery",
        "mitre_id": "T1059"
    },
    "c2-beacon-traffic-relay.top": {
        "type": "domain",
        "reputation_score": 98.0,
        "malicious_count": 64,
        "total_engines": 70,
        "threat_labels": "Cobalt Strike malleable C2, Active Beacon",
        "category": "Command and Control",
        "mitre_id": "T1071"
    },
    "exfil-dns-tunnel-storage.xyz": {
        "type": "domain",
        "reputation_score": 90.0,
        "malicious_count": 45,
        "total_engines": 66,
        "threat_labels": "DNS Exfiltration Receiver, High Entropy Queries",
        "category": "Data Exfiltration",
        "mitre_id": "T1048"
    },

    # Malicious File Hashes (SHA256)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "type": "hash",
        "reputation_score": 0.0,
        "malicious_count": 0,
        "total_engines": 70,
        "threat_labels": "Empty File Hash (Benign)",
        "category": "Benign",
        "mitre_id": None
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "type": "hash",
        "reputation_score": 99.0,
        "malicious_count": 69,
        "total_engines": 72,
        "threat_labels": "WannaCry Ransomware Binary, EternalBlue Exploit",
        "category": "Ransomware",
        "mitre_id": "T1486"
    },
    "84c82835a5d21bbcf75a61706d8ab549f3f69f8da294c30719263010f5d143cb": {
        "type": "hash",
        "reputation_score": 98.0,
        "malicious_count": 66,
        "total_engines": 71,
        "threat_labels": "Mimikatz LSASS dumper, Credential Injection",
        "category": "Credential Theft",
        "mitre_id": "T1110"
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "type": "hash",
        "reputation_score": 97.0,
        "malicious_count": 62,
        "total_engines": 68,
        "threat_labels": "EICAR Standard Anti-Virus Test File / Malicious Web Shell",
        "category": "Exploit Tool",
        "mitre_id": "T1059"
    }
}
