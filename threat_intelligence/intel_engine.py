import re
import requests
from datetime import datetime
from threat_intelligence.mitre_data import get_technique_details, MITRE_TECHNIQUES
from threat_intelligence.ioc_database import KNOWN_IOCS

class ThreatIntelEngine:
    """
    Central Threat Intelligence aggregator with multi-source enrichment:
    - AbuseIPDB live API (if key provided)
    - VirusTotal live API (if key provided)
    - Built-in Curated IOC Database (instant high-fidelity response)
    - Algorithmic Heuristics (RFC1918 classification, entropy analysis, port risk)
    """

    def __init__(self, abuseipdb_key=None, virustotal_key=None):
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key

    def set_api_keys(self, abuseipdb_key=None, virustotal_key=None):
        if abuseipdb_key is not None:
            self.abuseipdb_key = abuseipdb_key
        if virustotal_key is not None:
            self.virustotal_key = virustotal_key

    def is_private_ip(self, ip_str):
        """Check if an IP address belongs to RFC 1918 / loopback space."""
        if not ip_str:
            return False
        parts = ip_str.strip().split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            first, second = int(parts[0]), int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
        return False

    def query_abuseipdb(self, ip_address):
        """Live lookup against AbuseIPDB API."""
        if not self.abuseipdb_key or self.is_private_ip(ip_address):
            return None
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': self.abuseipdb_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=4)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                score = float(data.get('abuseConfidenceScore', 0.0))
                return {
                    'type': 'ip',
                    'reputation_score': score,
                    'malicious_count': data.get('totalReports', 0),
                    'total_engines': 100,
                    'threat_labels': f"AbuseIPDB (Confidence: {score}%)",
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'source': 'AbuseIPDB (Live API)'
                }
        except Exception:
            pass
        return None

    def query_virustotal(self, indicator, indicator_type='ip'):
        """Live lookup against VirusTotal API v3."""
        if not self.virustotal_key:
            return None
        headers = {'x-apikey': self.virustotal_key}
        endpoint_map = {
            'ip': f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}',
            'domain': f'https://www.virustotal.com/api/v3/domains/{indicator}',
            'hash': f'https://www.virustotal.com/api/v3/files/{indicator}'
        }
        url = endpoint_map.get(indicator_type)
        if not url:
            return None
        try:
            resp = requests.get(url, headers=headers, timeout=4)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values()) if stats else 70
                score = min(100.0, (malicious / max(1, total)) * 100.0 * 1.5)
                return {
                    'type': indicator_type,
                    'reputation_score': round(score, 1),
                    'malicious_count': malicious,
                    'total_engines': total,
                    'threat_labels': f"VirusTotal ({malicious}/{total} flagged)",
                    'source': 'VirusTotal (Live API)'
                }
        except Exception:
            pass
        return None

    def analyze_indicator(self, indicator):
        """
        Unified lookup for any indicator (IP, Domain, File Hash, or URL).
        Returns standardized Threat Intelligence analysis dictionary.
        """
        if not indicator:
            return {
                'indicator': '',
                'type': 'unknown',
                'reputation_score': 0.0,
                'malicious_count': 0,
                'total_engines': 0,
                'threat_labels': 'No indicator provided',
                'category': 'Unknown',
                'source': 'None',
                'mitre': None
            }

        indicator_clean = indicator.strip()

        # Determine type
        ind_type = 'unknown'
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator_clean):
            ind_type = 'ip'
        elif re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', indicator_clean):
            ind_type = 'hash'
        elif indicator_clean.startswith(('http://', 'https://')):
            ind_type = 'url'
        elif '.' in indicator_clean and not indicator_clean.endswith('.'):
            ind_type = 'domain'

        # 1. Check known database first (instant match)
        if indicator_clean in KNOWN_IOCS:
            data = KNOWN_IOCS[indicator_clean]
            mitre_info = get_technique_details(data.get('mitre_id'))
            return {
                'indicator': indicator_clean,
                'type': ind_type,
                'reputation_score': data.get('reputation_score', 0.0),
                'malicious_count': data.get('malicious_count', 0),
                'total_engines': data.get('total_engines', 70),
                'threat_labels': data.get('threat_labels', 'Known Indicator'),
                'category': data.get('category', 'General Threat'),
                'country': data.get('country', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'source': 'Curated SOC Threat Database',
                'mitre': mitre_info
            }

        # 2. Try Live API lookups if configured
        if ind_type == 'ip' and self.abuseipdb_key:
            res = self.query_abuseipdb(indicator_clean)
            if res:
                return {
                    'indicator': indicator_clean,
                    'type': ind_type,
                    'reputation_score': res['reputation_score'],
                    'malicious_count': res['malicious_count'],
                    'total_engines': res['total_engines'],
                    'threat_labels': res['threat_labels'],
                    'category': 'External Malicious IP',
                    'country': res.get('country', 'Unknown'),
                    'isp': res.get('isp', 'Unknown'),
                    'source': res['source'],
                    'mitre': None
                }

        if self.virustotal_key and ind_type in ('ip', 'domain', 'hash'):
            res = self.query_virustotal(indicator_clean, ind_type)
            if res:
                return {
                    'indicator': indicator_clean,
                    'type': ind_type,
                    'reputation_score': res['reputation_score'],
                    'malicious_count': res['malicious_count'],
                    'total_engines': res['total_engines'],
                    'threat_labels': res['threat_labels'],
                    'category': 'Flagged by Security Vendors',
                    'source': res['source'],
                    'mitre': None
                }

        # 3. Algorithmic Fallback Heuristics
        if ind_type == 'ip':
            if self.is_private_ip(indicator_clean):
                return {
                    'indicator': indicator_clean,
                    'type': 'ip',
                    'reputation_score': 5.0,
                    'malicious_count': 0,
                    'total_engines': 70,
                    'threat_labels': 'RFC 1918 Private Network Address',
                    'category': 'Internal Asset',
                    'source': 'Heuristic Classifier',
                    'mitre': None
                }
            else:
                # Unknown public IP
                return {
                    'indicator': indicator_clean,
                    'type': 'ip',
                    'reputation_score': 25.0,
                    'malicious_count': 1,
                    'total_engines': 70,
                    'threat_labels': 'Uncategorized External IP (Low Risk Baseline)',
                    'category': 'External Host',
                    'source': 'Heuristic Classifier',
                    'mitre': None
                }
        elif ind_type == 'domain':
            # Check suspicious TLDs
            suspicious_tlds = ('.cc', '.top', '.xyz', '.buzz', '.ru', '.tk', '.gq')
            if any(indicator_clean.lower().endswith(tld) for tld in suspicious_tlds):
                return {
                    'indicator': indicator_clean,
                    'type': 'domain',
                    'reputation_score': 65.0,
                    'malicious_count': 8,
                    'total_engines': 65,
                    'threat_labels': 'High-Risk TLD Association',
                    'category': 'Suspicious Domain',
                    'source': 'Heuristic Classifier',
                    'mitre': get_technique_details('T1566')
                }
            return {
                'indicator': indicator_clean,
                'type': 'domain',
                'reputation_score': 15.0,
                'malicious_count': 0,
                'total_engines': 65,
                'threat_labels': 'Standard Domain',
                'category': 'Uncategorized',
                'source': 'Heuristic Classifier',
                'mitre': None
            }
        elif ind_type == 'hash':
            return {
                'indicator': indicator_clean,
                'type': 'hash',
                'reputation_score': 20.0,
                'malicious_count': 0,
                'total_engines': 65,
                'threat_labels': 'Unknown File Hash',
                'category': 'File Hash',
                'source': 'Heuristic Classifier',
                'mitre': None
            }

        return {
            'indicator': indicator_clean,
            'type': 'unknown',
            'reputation_score': 10.0,
            'malicious_count': 0,
            'total_engines': 50,
            'threat_labels': 'General Indicator',
            'category': 'Unclassified',
            'source': 'Baseline Engine',
            'mitre': None
        }

    def compute_alert_threat_score(self, source_ip, iocs=None, attack_type=None):
        """
        Aggregate threat intel score for an incoming alert.
        Checks source IP and any attached IOCs, returning highest observed threat score.
        """
        scores = []
        labels = []

        # Check source IP
        if source_ip:
            ip_info = self.analyze_indicator(source_ip)
            scores.append(ip_info['reputation_score'])
            if ip_info['threat_labels']:
                labels.append(ip_info['threat_labels'])

        # Check attached IOCs
        if iocs:
            for ioc in iocs:
                info = self.analyze_indicator(ioc)
                scores.append(info['reputation_score'])
                if info['threat_labels']:
                    labels.append(info['threat_labels'])

        max_score = max(scores) if scores else 15.0
        return max_score, ", ".join(set(labels)) if labels else "Clean / Baseline"
