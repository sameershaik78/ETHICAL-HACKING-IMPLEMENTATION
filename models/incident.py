from datetime import datetime
import json
from models import db

incident_alerts = db.Table('incident_alerts',
    db.Column('incident_id', db.Integer, db.ForeignKey('incidents.id'), primary_key=True),
    db.Column('alert_id', db.Integer, db.ForeignKey('alerts.id'), primary_key=True)
)

class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(16), default='High')  # Critical, High, Medium, Low
    status = db.Column(db.String(32), default='Open', index=True)  # Open, In Progress, Contained, Resolved, Closed
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolution_summary = db.Column(db.Text, nullable=True)
    containment_actions = db.Column(db.Text, nullable=True)  # JSON list of actions

    # Relationships
    alerts = db.relationship('Alert', secondary=incident_alerts, backref=db.backref('incidents', lazy='dynamic'))
    timeline = db.relationship('IncidentTimeline', backref='incident', cascade='all, delete-orphan', order_by='IncidentTimeline.timestamp.desc()')

    def get_actions(self):
        if not self.containment_actions:
            return []
        try:
            return json.loads(self.containment_actions)
        except Exception:
            return []

    def set_actions(self, actions_list):
        self.containment_actions = json.dumps(actions_list)

    def to_dict(self):
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'status': self.status,
            'assigned_to': self.assignee.full_name if self.assignee else 'Unassigned',
            'assigned_to_id': self.assigned_to_id,
            'created_by': self.creator.full_name if self.creator else 'System',
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'alert_count': len(self.alerts),
            'resolution_summary': self.resolution_summary,
            'containment_actions': self.get_actions()
        }

class IncidentTimeline(db.Model):
    __tablename__ = 'incident_timeline'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action_type = db.Column(db.String(64), nullable=False)  # Note Added, Status Change, Action Executed, etc.
    note = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'action_type': self.action_type,
            'note': self.note,
            'author': self.author.full_name if self.author else 'System',
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
