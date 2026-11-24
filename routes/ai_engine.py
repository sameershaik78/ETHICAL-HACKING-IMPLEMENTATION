import json
from flask import Blueprint, render_template, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from models import db, Alert, PrioritizationResult, SystemSetting
from ml_engine.predictor import PriorityPredictor
from services.scoring_service import ScoringService

ai_engine_bp = Blueprint('ai_engine', __name__, url_prefix='/ai-prioritization')
scoring_svc = ScoringService()
predictor = PriorityPredictor()

@ai_engine_bp.route('', strict_slashes=False)
@ai_engine_bp.route('/', strict_slashes=False)
@login_required
def index():
    metadata = predictor.metadata or {}
    
    # Current risk weights
    weights = {
        'severity': float(SystemSetting.get('WEIGHT_SEVERITY', 0.25)),
        'threat_intel': float(SystemSetting.get('WEIGHT_THREAT_INTEL', 0.25)),
        'asset_criticality': float(SystemSetting.get('WEIGHT_ASSET_CRITICALITY', 0.20)),
        'attack_frequency': float(SystemSetting.get('WEIGHT_ATTACK_FREQUENCY', 0.15)),
        'vuln_impact': float(SystemSetting.get('WEIGHT_VULN_IMPACT', 0.15))
    }

    # Model comparison samples (5 recent alerts)
    sample_alerts = Alert.query.join(PrioritizationResult).order_by(Alert.timestamp.desc()).limit(8).all()

    return render_template(
        'ai_engine/index.html',
        metadata=metadata,
        weights=weights,
        sample_alerts=sample_alerts
    )

@ai_engine_bp.route('/recalculate-all', methods=['POST'])
@login_required
def recalculate_all():
    if not current_user.is_admin:
        flash('Only SOC Administrators can trigger global alert reprioritization.', 'danger')
        return redirect(url_for('ai_engine.index'))

    alerts = Alert.query.all()
    count = 0
    for a in alerts:
        res = scoring_svc.prioritize_alert(a.to_dict())
        p = a.prioritization
        if p:
            p.risk_score = res['risk_score']
            p.priority_level = res['priority_level']
            p.ml_priority = res['ml_priority']
            p.ml_confidence = res['ml_confidence']
            p.threat_intel_score = res['threat_intel_score']
            p.severity_score = res['severity_score']
            p.asset_score = res['asset_score']
            p.frequency_score = res['frequency_score']
            p.vuln_score = res['vuln_score']
            p.top_contributing_factors = json.dumps(res['explainability'])
            p.recommended_action = res['recommended_action']
            count += 1

    db.session.commit()
    flash(f"Successfully recomputed AI prioritization scores for all {count} alerts!", 'success')
    return redirect(url_for('ai_engine.index'))
