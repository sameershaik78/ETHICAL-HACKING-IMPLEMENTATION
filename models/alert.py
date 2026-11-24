from datetime import datetime
import json
from models import db

class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(16), default='TCP')  # TCP, UDP, ICMP, HTTP, DNS, etc.
    attack_type = db.Column(db.String(64), nullable=False, index=True)
    raw_severity = db.Column(db.String(16), nullable=False)  # Critical, High, Medium, Low
    asset_name = db.Column(db.String(128), nullable=False)
    asset_criticality = db.Column(db.String(16), default='Medium')  # Critical, High, Medium, Low
    attack_frequency = db.Column(db.Integer, default=1)
    vulnerability_cve = db.Column(db.String(64), nullable=True)
    mitre_technique_id = db.Column(db.String(32), nullable=True, index=True)
    mitre_technique_name = db.Column(db.String(128), nullable=True)
    mitre_tactic = db.Column(db.String(64), nullable=True)
    ioc_indicators = db.Column(db.Text, nullable=True)  # JSON serialized list of IOC strings
    raw_payload = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), default='New', index=True)  # New, Under Investigation, Escalated, Closed, False Positive
    is_simulated = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    prioritization = db.relationship('PrioritizationResult', backref='alert', uselist=False, cascade='all, delete-orphan')

    def get_iocs(self):
        if not self.ioc_indicators:
            return []
        try:
            return json.loads(self.ioc_indicators)
        except Exception:
            return [x.strip() for x in self.ioc_indicators.split(',') if x.strip()]

    def set_iocs(self, ioc_list):
        self.ioc_indicators = json.dumps(ioc_list if isinstance(ioc_list, list) else [ioc_list])

    def to_dict(self):
        res = self.prioritization
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'title': self.title,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'attack_type': self.attack_type,
            'raw_severity': self.raw_severity,
            'asset_name': self.asset_name,
            'asset_criticality': self.asset_criticality,
            'attack_frequency': self.attack_frequency,
            'vulnerability_cve': self.vulnerability_cve,
            'mitre_technique_id': self.mitre_technique_id,
            'mitre_technique_name': self.mitre_technique_name,
            'mitre_tactic': self.mitre_tactic,
            'ioc_indicators': self.get_iocs(),
            'raw_payload': self.raw_payload,
            'status': self.status,
            'is_simulated': self.is_simulated,
            'prioritization': res.to_dict() if res else None
        }

class PrioritizationResult(db.Model):
    __tablename__ = 'prioritization_results'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), unique=True, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)  # 0.0 to 100.0
    priority_level = db.Column(db.String(16), nullable=False)  # Critical, High, Medium, Low
    ml_priority = db.Column(db.String(16), nullable=False)  # ML predicted priority
    ml_confidence = db.Column(db.Float, default=0.0)  # 0.0 to 100.0
    threat_category = db.Column(db.String(64), nullable=True)
    threat_intel_score = db.Column(db.Float, default=0.0)
    severity_score = db.Column(db.Float, default=0.0)
    asset_score = db.Column(db.Float, default=0.0)
    frequency_score = db.Column(db.Float, default=0.0)
    vuln_score = db.Column(db.Float, default=0.0)
    top_contributing_factors = db.Column(db.Text, nullable=True)  # JSON dict
    recommended_action = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_factors(self):
        if not self.top_contributing_factors:
            return {}
        try:
            return json.loads(self.top_contributing_factors)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'risk_score': round(self.risk_score, 1),
            'priority_level': self.priority_level,
            'ml_priority': self.ml_priority,
            'ml_confidence': round(self.ml_confidence, 1),
            'threat_category': self.threat_category,
            'threat_intel_score': round(self.threat_intel_score, 1),
            'severity_score': round(self.severity_score, 1),
            'asset_score': round(self.asset_score, 1),
            'frequency_score': round(self.frequency_score, 1),
            'vuln_score': round(self.vuln_score, 1),
            'factors': self.get_factors(),
            'recommended_action': self.recommended_action
        }
