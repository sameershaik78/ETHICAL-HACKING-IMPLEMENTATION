from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from sqlalchemy import func
from models import db, Alert, PrioritizationResult, Incident

analytics_bp = Blueprint('analytics', __name__, url_prefix='/analytics')

@analytics_bp.route('', strict_slashes=False)
@analytics_bp.route('/', strict_slashes=False)
@login_required
def index():
    total_alerts = Alert.query.count()
    total_incidents = Incident.query.count()
    crit_count = PrioritizationResult.query.filter_by(priority_level='Critical').count()
    high_count = PrioritizationResult.query.filter_by(priority_level='High').count()

    # Top targeted assets
    top_assets = db.session.query(Alert.asset_name, Alert.asset_criticality, func.count(Alert.id))\
        .group_by(Alert.asset_name, Alert.asset_criticality)\
        .order_by(func.count(Alert.id).desc())\
        .limit(8).all()

    # Top attacking IPs
    top_ips = db.session.query(Alert.source_ip, func.count(Alert.id))\
        .group_by(Alert.source_ip)\
        .order_by(func.count(Alert.id).desc())\
        .limit(8).all()

    # Threat Categories
    categories = db.session.query(Alert.attack_type, func.count(Alert.id))\
        .group_by(Alert.attack_type)\
        .order_by(func.count(Alert.id).desc()).all()

    return render_template(
        'analytics/index.html',
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        crit_count=crit_count,
        high_count=high_count,
        top_assets=top_assets,
        top_ips=top_ips,
        categories=categories
    )

@analytics_bp.route('/api/charts')
@login_required
def api_charts():
    # Severity distribution
    crit = PrioritizationResult.query.filter_by(priority_level='Critical').count()
    high = PrioritizationResult.query.filter_by(priority_level='High').count()
    med = PrioritizationResult.query.filter_by(priority_level='Medium').count()
    low = PrioritizationResult.query.filter_by(priority_level='Low').count()

    # Risk score buckets: 0-20, 20-40, 40-60, 60-80, 80-100
    b1 = PrioritizationResult.query.filter(PrioritizationResult.risk_score < 20).count()
    b2 = PrioritizationResult.query.filter(PrioritizationResult.risk_score >= 20, PrioritizationResult.risk_score < 40).count()
    b3 = PrioritizationResult.query.filter(PrioritizationResult.risk_score >= 40, PrioritizationResult.risk_score < 60).count()
    b4 = PrioritizationResult.query.filter(PrioritizationResult.risk_score >= 60, PrioritizationResult.risk_score < 80).count()
    b5 = PrioritizationResult.query.filter(PrioritizationResult.risk_score >= 80).count()

    # Incidents by status
    inc_open = Incident.query.filter_by(status='Open').count()
    inc_progress = Incident.query.filter_by(status='In Progress').count()
    inc_contained = Incident.query.filter_by(status='Contained').count()
    inc_resolved = Incident.query.filter_by(status='Resolved').count()

    return jsonify({
        'priorities': [crit, high, med, low],
        'risk_buckets': [b1, b2, b3, b4, b5],
        'incidents': [inc_open, inc_progress, inc_contained, inc_resolved]
    })
