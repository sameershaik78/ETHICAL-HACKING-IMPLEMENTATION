from ml_engine.feature_extractor import FeatureExtractor, SEVERITY_MAP, ASSET_CRITICALITY_MAP
from ml_engine.predictor import PriorityPredictor

class ScoringService:
    def __init__(self, predictor=None):
        self.predictor = predictor or PriorityPredictor()

    def calculate_baseline_risk_score(self, severity, threat_intel_score, asset_criticality,
                                       attack_frequency=1, vulnerability_cve=None, weights=None):
        """
        Calculates explainable baseline risk score using weighted formula:
        Risk Score = (Severity * 0.25) + (Threat Intel * 0.25) + (Asset Criticality * 0.20)
                   + (Attack Frequency * 0.15) + (Vulnerability Impact * 0.15)
        All parameters normalized to 0-100 scale.
        """
        if weights is None:
            weights = {
                'severity': 0.25,
                'threat_intel': 0.25,
                'asset_criticality': 0.20,
                'attack_frequency': 0.15,
                'vuln_impact': 0.15
            }

        # 1. Severity (0-100)
        sev_score = SEVERITY_MAP.get(str(severity).upper().strip(), 50.0)

        # 2. Threat Intel (0-100)
        ti_score = max(0.0, min(100.0, float(threat_intel_score or 0.0)))

        # 3. Asset Criticality (0-100)
        asset_score = ASSET_CRITICALITY_MAP.get(str(asset_criticality).upper().strip(), 50.0)

        # 4. Attack Frequency (0-100)
        try:
            freq = int(attack_frequency or 1)
        except Exception:
            freq = 1
        freq_score = min(100.0, freq * 4.0)

        # 5. Vulnerability Impact (0-100)
        cve_str = str(vulnerability_cve or '').strip()
        if cve_str and cve_str.upper() not in ('N/A', 'NONE', ''):
            vuln_score = 85.0
        else:
            vuln_score = 20.0

        risk_score = (
            (sev_score * weights['severity']) +
            (ti_score * weights['threat_intel']) +
            (asset_score * weights['asset_criticality']) +
            (freq_score * weights['attack_frequency']) +
            (vuln_score * weights['vuln_impact'])
        )
        risk_score = max(0.0, min(100.0, risk_score))

        # Classification mapping
        if risk_score >= 80.0:
            priority = 'Critical'
        elif risk_score >= 60.0:
            priority = 'High'
        elif risk_score >= 35.0:
            priority = 'Medium'
        else:
            priority = 'Low'

        return {
            'risk_score': round(risk_score, 1),
            'priority_level': priority,
            'severity_score': round(sev_score, 1),
            'threat_intel_score': round(ti_score, 1),
            'asset_score': round(asset_score, 1),
            'frequency_score': round(freq_score, 1),
            'vuln_score': round(vuln_score, 1)
        }

    def generate_recommended_action(self, attack_type, priority_level, destination_ip, source_ip):
        """
        Generate actionable SOC playbook recommendation based on threat context.
        """
        atk = str(attack_type).lower()
        if priority_level == 'Critical':
            if 'ransomware' in atk:
                return f"[IMMEDIATE ACTION] 1. Isolate target host ({destination_ip}) from network. 2. Terminate malicious process tree. 3. Block source IP ({source_ip}) on perimeter firewall. 4. Preserve RAM dump for digital forensics."
            elif 'c2' in atk or 'beacon' in atk:
                return f"[IMMEDIATE ACTION] 1. Null-route / sinkhole C2 destination ({source_ip}). 2. Kill malicious persistence service on {destination_ip}. 3. Revoke all active kerberos/session tokens."
            elif 'sql' in atk:
                return f"[CRITICAL ACTION] 1. Temporarily enable WAF virtual patching against payload signature. 2. Terminate active database connections from {source_ip}. 3. Review DB audit logs for exfiltrated tables."
            else:
                return f"[CRITICAL ACTION] 1. Isolate compromised asset ({destination_ip}). 2. Block offending IP ({source_ip}) on firewall. 3. Escalate to Tier-3 incident response lead."

        elif priority_level == 'High':
            if 'brute force' in atk:
                return f"[HIGH PRIORITY] 1. Rate-limit and temporarily ban source IP ({source_ip}) in iptables/fail2ban. 2. Lock targeted user accounts. 3. Force MFA authentication challenge."
            elif 'phishing' in atk:
                return f"[HIGH PRIORITY] 1. Purge phishing email from all user inboxes across tenant. 2. Block sender domain and landing URL on Secure Web Gateway (SWG). 3. Force password resets for users who clicked."
            else:
                return f"[HIGH PRIORITY] 1. Investigate process activity and network flows on {destination_ip}. 2. Validate alert legitimacy with asset owner. 3. Apply defensive firewall rule."

        elif priority_level == 'Medium':
            return f"[INVESTIGATE] 1. Correlate with historical IDS/IPS logs from {source_ip}. 2. Verify whether activity is approved penetration testing or vulnerability scanning. 3. Add source IP to automated 24h watchlist."

        else: # Low
            return f"[MONITOR] 1. Tag as low-priority telemetry. 2. Archive alert. 3. If frequency increases above threshold, automated pipeline will re-escalate."

    def prioritize_alert(self, alert_data, weights=None):
        """
        Complete end-to-end prioritization:
        1. Calculate baseline explainable risk score
        2. Run ML inference for classification and probability
        3. Extract feature importance explainability
        4. Generate response action
        """
        baseline = self.calculate_baseline_risk_score(
            severity=alert_data.get('raw_severity', 'Medium'),
            threat_intel_score=alert_data.get('threat_intel_score', 0.0),
            asset_criticality=alert_data.get('asset_criticality', 'Medium'),
            attack_frequency=alert_data.get('attack_frequency', 1),
            vulnerability_cve=alert_data.get('vulnerability_cve', None),
            weights=weights
        )

        features = FeatureExtractor.extract_features(alert_data)
        ml_priority, ml_conf, probs, explainability = self.predictor.predict(features)

        rec_action = self.generate_recommended_action(
            attack_type=alert_data.get('attack_type', 'General'),
            priority_level=baseline['priority_level'],
            destination_ip=alert_data.get('destination_ip', 'Internal Host'),
            source_ip=alert_data.get('source_ip', 'External Host')
        )

        return {
            'risk_score': baseline['risk_score'],
            'priority_level': baseline['priority_level'],
            'ml_priority': ml_priority,
            'ml_confidence': ml_conf,
            'probabilities': probs,
            'explainability': explainability,
            'severity_score': baseline['severity_score'],
            'threat_intel_score': baseline['threat_intel_score'],
            'asset_score': baseline['asset_score'],
            'frequency_score': baseline['frequency_score'],
            'vuln_score': baseline['vuln_score'],
            'recommended_action': rec_action
        }
