import csv
import io
import json
from datetime import datetime
from models import db, Alert, PrioritizationResult, ThreatIntelCache, SystemSetting
from threat_intelligence.intel_engine import ThreatIntelEngine
from services.scoring_service import ScoringService

class AlertService:
    def __init__(self):
        self.threat_engine = ThreatIntelEngine()
        self.scoring_service = ScoringService()

    def ingest_single_alert(self, alert_dict, commit=True):
        """
        Process and ingest a single alert:
        - Checks threat intel for source IP & IOCs
        - Calculates baseline risk score and ML prediction
        - Creates Alert and PrioritizationResult DB models
        """
        # Load API keys from settings if present
        abuse_key = SystemSetting.get('ABUSEIPDB_API_KEY')
        vt_key = SystemSetting.get('VIRUSTOTAL_API_KEY')
        self.threat_engine.set_api_keys(abuse_key, vt_key)

        source_ip = alert_dict.get('source_ip', '').strip()
        iocs = alert_dict.get('ioc_indicators') or []
        if isinstance(iocs, str):
            try:
                iocs = json.loads(iocs)
            except Exception:
                iocs = [x.strip() for x in iocs.split(',') if x.strip()]

        # Threat Intel enrichment
        ti_score, ti_labels = self.threat_engine.compute_alert_threat_score(
            source_ip=source_ip,
            iocs=iocs,
            attack_type=alert_dict.get('attack_type')
        )

        alert_dict['threat_intel_score'] = ti_score
        alert_dict['threat_labels'] = ti_labels

        # AI Prioritization
        p_res = self.scoring_service.prioritize_alert(alert_dict)

        # Parse timestamp
        ts = alert_dict.get('timestamp')
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except Exception:
                try:
                    ts = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                except Exception:
                    ts = datetime.utcnow()
        elif not isinstance(ts, datetime):
            ts = datetime.utcnow()

        alert = Alert(
            alert_id=alert_dict.get('alert_id'),
            timestamp=ts,
            title=alert_dict.get('title', 'Security Alert'),
            description=alert_dict.get('description', ''),
            source_ip=source_ip,
            destination_ip=alert_dict.get('destination_ip', '').strip(),
            source_port=int(alert_dict.get('source_port') or 0),
            destination_port=int(alert_dict.get('destination_port') or 0),
            protocol=alert_dict.get('protocol', 'TCP').upper(),
            attack_type=alert_dict.get('attack_type', 'Other'),
            raw_severity=alert_dict.get('raw_severity', 'Medium'),
            asset_name=alert_dict.get('asset_name', 'Unknown Asset'),
            asset_criticality=alert_dict.get('asset_criticality', 'Medium'),
            attack_frequency=int(alert_dict.get('attack_frequency') or 1),
            vulnerability_cve=alert_dict.get('vulnerability_cve') or 'N/A',
            mitre_technique_id=alert_dict.get('mitre_technique_id') or '',
            mitre_technique_name=alert_dict.get('mitre_technique_name') or '',
            mitre_tactic=alert_dict.get('mitre_tactic') or '',
            ioc_indicators=json.dumps(iocs) if isinstance(iocs, list) else iocs,
            raw_payload=alert_dict.get('raw_payload') or '',
            status=alert_dict.get('status', 'New'),
            is_simulated=bool(alert_dict.get('is_simulated', True))
        )
        db.session.add(alert)
        db.session.flush()

        prioritization = PrioritizationResult(
            alert_id=alert.id,
            risk_score=p_res['risk_score'],
            priority_level=p_res['priority_level'],
            ml_priority=p_res['ml_priority'],
            ml_confidence=p_res['ml_confidence'],
            threat_category=alert_dict.get('attack_type', 'General'),
            threat_intel_score=p_res['threat_intel_score'],
            severity_score=p_res['severity_score'],
            asset_score=p_res['asset_score'],
            frequency_score=p_res['frequency_score'],
            vuln_score=p_res['vuln_score'],
            top_contributing_factors=json.dumps(p_res['explainability']),
            recommended_action=p_res['recommended_action']
        )
        db.session.add(prioritization)

        if commit:
            db.session.commit()

        return alert

    def parse_and_import_csv(self, file_content_str):
        """
        Parses CSV string, validates required columns, and ingests all records.
        Returns (success_count, error_list)
        """
        f = io.StringIO(file_content_str.strip())
        reader = csv.DictReader(f)

        required_cols = {'title', 'source_ip', 'destination_ip', 'attack_type', 'raw_severity', 'asset_name'}
        headers = {col.strip().lower() for col in (reader.fieldnames or [])}
        missing = required_cols - headers
        if missing:
            raise ValueError(f"CSV missing mandatory columns: {', '.join(missing)}")

        success_count = 0
        errors = []

        existing_count = Alert.query.count()

        for idx, row in enumerate(reader, start=1):
            try:
                # Clean row keys
                clean_row = {k.strip().lower(): v.strip() for k, v in row.items() if k}
                
                alert_id = clean_row.get('alert_id')
                if not alert_id:
                    alert_id = f"ALT-{datetime.utcnow().year}-{existing_count + success_count + 1:04d}"

                clean_row['alert_id'] = alert_id
                self.ingest_single_alert(clean_row, commit=False)
                success_count += 1
            except Exception as e:
                errors.append(f"Row {idx}: {str(e)}")

        db.session.commit()
        return success_count, errors
