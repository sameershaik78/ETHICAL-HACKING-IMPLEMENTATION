from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from threat_intelligence import intel_engine
from threat_intelligence.mitre_data import MITRE_TACTICS, MITRE_TECHNIQUES, get_technique_details
from models import ThreatIntelCache

threat_intel_bp = Blueprint('threat_intel', __name__, url_prefix='/threat-intel')

@threat_intel_bp.route('', strict_slashes=False)
@threat_intel_bp.route('/', strict_slashes=False)
@login_required
def index():
    cached_iocs = ThreatIntelCache.query.order_by(ThreatIntelCache.last_checked.desc()).limit(20).all()
    return render_template('threat_intel/index.html', cached_iocs=cached_iocs, tactics=MITRE_TACTICS)

@threat_intel_bp.route('/lookup', methods=['GET', 'POST'])
@login_required
def lookup():
    query = request.args.get('q', '').strip() or request.form.get('indicator', '').strip()
    result = None
    if query:
        result = intel_engine.analyze_indicator(query)
    return render_template('threat_intel/lookup.html', query=query, result=result)

@threat_intel_bp.route('/mitre')
@login_required
def mitre_matrix():
    return render_template('threat_intel/mitre.html', tactics=MITRE_TACTICS, techniques=MITRE_TECHNIQUES)

@threat_intel_bp.route('/mitre/<technique_id>')
@login_required
def mitre_detail(technique_id):
    technique = get_technique_details(technique_id)
    return render_template('threat_intel/mitre_detail.html', technique=technique)
