"""
MITRE ATT&CK Framework Mapping and Reference Data
"""

MITRE_TACTICS = [
    {"id": "TA0001", "name": "Initial Access", "description": "Techniques that use various entry vectors to gain a foothold on the network."},
    {"id": "TA0002", "name": "Execution", "description": "Techniques that result in adversary-controlled code running on a local or remote system."},
    {"id": "TA0003", "name": "Persistence", "description": "Techniques used to keep access to systems across restarts, changed credentials, and other interruptions."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques used to gain higher-level permissions on a system or network."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques used to avoid detection throughout their compromise."},
    {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials like account names and passwords."},
    {"id": "TA0007", "name": "Discovery", "description": "Techniques to gain knowledge about the system and internal network."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques used to enter and control remote systems on a network."},
    {"id": "TA0009", "name": "Collection", "description": "Techniques used to gather information of interest, such as sensitive files."},
    {"id": "TA0011", "name": "Command and Control", "description": "Techniques used to communicate with systems under adversary control."},
    {"id": "TA0010", "name": "Exfiltration", "description": "Techniques used to steal data from your network."},
    {"id": "TA0040", "name": "Impact", "description": "Techniques used to disrupt, destroy, or compromise the integrity of systems and data."}
]

MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to attempt credential access through password guessing, credential stuffing, or password spraying against target accounts.",
        "detection": "Monitor authentication logs for high volumes of failed login attempts from a single source IP, especially across multiple usernames.",
        "mitigation": "Enforce Multi-Factor Authentication (MFA), account lockout policies, and rate-limiting on authentication endpoints."
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program using software, web applications, or network services.",
        "detection": "Analyze Web Application Firewall (WAF) logs, web server access logs for anomalous payload strings (SQLi, XSS, RCE), and crash dumps.",
        "mitigation": "Apply security patches rapidly, implement Web Application Firewalls, and conduct regular penetration testing and vulnerability scanning."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python, Cmd) to execute arbitrary commands and payloads.",
        "detection": "Enable Script Block Logging, process creation logging (Sysmon Event ID 1), and look for obfuscated or base64 encoded command arguments.",
        "mitigation": "Enforce Constrained Language Mode in PowerShell, restrict execution policies, and employ application whitelisting (AppLocker / WDAC)."
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with legitimate network traffic.",
        "detection": "Inspect SSL/TLS certificate anomalies, JA3/JA3S fingerprints, unusual beacon intervals, and anomalous DNS query volume.",
        "mitigation": "Implement deep packet inspection, TLS decryption, outbound proxy filtering, and DNS sinkholing."
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may encrypt data on target systems or within networks to disrupt system availability and demand ransom.",
        "detection": "Monitor for rapid file modification/rename operations with unknown extensions, volume shadow copy deletion (vssadmin delete shadows), and bcdedit tampering.",
        "mitigation": "Maintain immutable off-site backups, deploy behavioral EDR ransomware protection, and restrict administrative access."
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries send phishing messages with malicious attachments or links to gain initial access, execute malware, or steal credentials.",
        "detection": "Analyze email gateway telemetry for spoofed domains, suspicious attachments (macro-enabled Office, ISO, ZIP), and brand impersonation.",
        "mitigation": "Implement DMARC, DKIM, SPF email authentication, user awareness simulations, and link-rewriting inspection."
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts, including port scans to identify vulnerable services.",
        "detection": "Network IDS/IPS alerts detecting rapid SYN scans, sequential port probes, or unusual ICMP sweeps across subnet segments.",
        "mitigation": "Implement internal micro-segmentation, disable unused network ports, and monitor traffic with network sensors."
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may exfiltrate data rather than normal command channel, such as DNS tunneling, ICMP payloads, or external cloud storage.",
        "detection": "Look for high entropy DNS queries, exceptionally large TXT record requests, or unexpected outbound connections to storage buckets.",
        "mitigation": "Filter unauthorized external file-sharing domains, enforce DNS proxying, and monitor outbound data transfer thresholds."
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, or Privilege Escalation.",
        "detection": "Monitor for impossible travel logins, access from unusual geolocation or VPN exit nodes, and administrative activity during off-hours.",
        "mitigation": "Implement risk-based adaptive authentication, conditional access policies, and privileged access management (PAM)."
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "description": "Adversaries may log on to remote systems using tools such as RDP, SSH, SMB, or WinRM to move laterally within the network.",
        "detection": "Monitor internal network flows for unusual SMB/RDP sessions between workstations rather than server-to-workstation.",
        "mitigation": "Disable network-level authentication bypasses, segment management networks, and restrict host-to-host SMB/RDP connectivity."
    }
}

def get_technique_details(technique_id):
    """Retrieve full technique details by technique ID or return default."""
    if not technique_id:
        return None
    tid = technique_id.upper().strip()
    return MITRE_TECHNIQUES.get(tid, {
        "id": tid,
        "name": "Known ATT&CK Technique",
        "tactic": "General Cyber Tactic",
        "tactic_id": "TA0000",
        "description": "Activity associated with documented adversary tactics, techniques, and procedures.",
        "detection": "Review endpoint and network telemetry correlated with the alert.",
        "mitigation": "Implement defense-in-depth security controls and log auditing."
    })
