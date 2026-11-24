import re
import numpy as np

SEVERITY_MAP = {
    'LOW': 25.0,
    'MEDIUM': 50.0,
    'HIGH': 75.0,
    'CRITICAL': 100.0
}

ASSET_CRITICALITY_MAP = {
    'LOW': 25.0,
    'MEDIUM': 50.0,
    'HIGH': 75.0,
    'CRITICAL': 100.0
}

HIGH_RISK_PORTS = {22, 3389, 445, 139, 4444, 88, 389, 8080, 8443, 7001, 5985}
MEDIUM_RISK_PORTS = {80, 443, 21, 23, 25, 1433, 3306, 5432, 27017, 6379}

ATTACK_TYPE_CODES = {
    'BRUTE FORCE': 1,
    'SQL INJECTION': 2,
    'C2 BEACONING': 3,
    'RANSOMWARE': 4,
    'PORT SCAN': 5,
    'PHISHING': 6,
    'DATA EXFILTRATION': 7,
    'PRIVILEGE ESCALATION': 8,
    'MALWARE EXECUTION': 9,
    'UNAUTHORIZED ACCESS': 10
}

class FeatureExtractor:
    FEATURE_NAMES = [
        'Severity Score',
        'Threat Intel Score',
        'Asset Criticality Score',
        'Attack Frequency Norm',
        'Vulnerability Impact Score',
        'Port Risk Score',
        'Known C2 Indicator Flag',
        'Attack Type Code'
    ]

    @staticmethod
    def extract_features(data):
        """
        Extract 8 normalized numerical features from an alert object or dictionary.
        Returns numpy array of shape (8,).
        """
        # 1. Severity
        sev = str(data.get('raw_severity', 'Medium')).upper().strip()
        sev_score = SEVERITY_MAP.get(sev, 50.0)

        # 2. Threat Intel Score
        ti_score = float(data.get('threat_intel_score', 0.0) or 0.0)
        ti_score = max(0.0, min(100.0, ti_score))

        # 3. Asset Criticality
        crit = str(data.get('asset_criticality', 'Medium')).upper().strip()
        asset_score = ASSET_CRITICALITY_MAP.get(crit, 50.0)

        # 4. Attack Frequency
        try:
            freq = int(data.get('attack_frequency', 1) or 1)
        except Exception:
            freq = 1
        freq_norm = min(100.0, freq * 4.0)

        # 5. Vulnerability Impact
        cve = str(data.get('vulnerability_cve', '') or '').strip()
        if cve and cve.upper() != 'N/A' and cve.upper() != 'NONE':
            # Approximate CVSS based on CVE presence
            vuln_score = 85.0
        else:
            vuln_score = 20.0

        # 6. Port Risk
        dest_port = data.get('destination_port')
        try:
            port = int(dest_port) if dest_port is not None else 0
        except Exception:
            port = 0

        if port in HIGH_RISK_PORTS:
            port_risk = 90.0
        elif port in MEDIUM_RISK_PORTS:
            port_risk = 55.0
        elif port > 1024:
            port_risk = 40.0
        elif port > 0:
            port_risk = 30.0
        else:
            port_risk = 20.0

        # 7. Known C2 / Ransomware flag
        threat_labels = str(data.get('threat_labels', '') or '').lower()
        title = str(data.get('title', '') or '').lower()
        desc = str(data.get('description', '') or '').lower()
        full_text = f"{threat_labels} {title} {desc}"
        known_c2 = 1.0 if any(k in full_text for k in ['c2', 'beacon', 'cobalt strike', 'ransomware', 'lockbit', 'wannacry']) else 0.0

        # 8. Attack Type Code
        atk_type = str(data.get('attack_type', 'Other')).upper().strip()
        atk_code = float(ATTACK_TYPE_CODES.get(atk_type, 0))

        return np.array([
            sev_score,
            ti_score,
            asset_score,
            freq_norm,
            vuln_score,
            port_risk,
            known_c2,
            atk_code
        ], dtype=np.float32)
