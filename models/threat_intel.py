from datetime import datetime
import json
from models import db

class ThreatIntelCache(db.Model):
    __tablename__ = 'threat_intel_cache'

    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(16), nullable=False)  # ip, domain, hash, url
    indicator_value = db.Column(db.String(255), nullable=False, index=True)
    reputation_score = db.Column(db.Float, default=0.0)  # 0 to 100
    malicious_count = db.Column(db.Integer, default=0)
    total_engines = db.Column(db.Integer, default=0)
    threat_labels = db.Column(db.String(255), nullable=True)
    source_provider = db.Column(db.String(64), default='ThreatIntel Feed')
    details_json = db.Column(db.Text, nullable=True)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)

    def get_details(self):
        if not self.details_json:
            return {}
        try:
            return json.loads(self.details_json)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.indicator_type,
            'value': self.indicator_value,
            'reputation_score': self.reputation_score,
            'malicious_count': self.malicious_count,
            'total_engines': self.total_engines,
            'threat_labels': self.threat_labels,
            'source_provider': self.source_provider,
            'details': self.get_details(),
            'last_checked': self.last_checked.strftime('%Y-%m-%d %H:%M:%S') if self.last_checked else None
        }

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    def get(cls, key, default=None):
        setting = cls.query.filter_by(key=key).first()
        return setting.value if setting else default

    @classmethod
    def set(cls, key, value, description=None):
        setting = cls.query.filter_by(key=key).first()
        if not setting:
            setting = cls(key=key, value=str(value), description=description)
            db.session.add(setting)
        else:
            setting.value = str(value)
            if description:
                setting.description = description
        db.session.commit()
