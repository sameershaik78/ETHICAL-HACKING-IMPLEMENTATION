from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import db, SystemSetting, Alert, Incident, ThreatIntelCache
from ml_engine.train_model import train_and_save_model
from ml_engine.predictor import PriorityPredictor

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')
predictor = PriorityPredictor()

@settings_bp.route('', methods=['GET', 'POST'], strict_slashes=False)
@settings_bp.route('/', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def index():
    if request.method == 'POST':
        if not current_user.is_admin:
            flash('Only SOC Administrators can modify system configuration.', 'danger')
            return redirect(url_for('settings.index'))

        # Threat Intel API Keys
        abuse_key = request.form.get('abuseipdb_api_key', '').strip()
        vt_key = request.form.get('virustotal_api_key', '').strip()
        SystemSetting.set('ABUSEIPDB_API_KEY', abuse_key, 'API Key for AbuseIPDB')
        SystemSetting.set('VIRUSTOTAL_API_KEY', vt_key, 'API Key for VirusTotal v3')

        # Weights
        try:
            w_sev = float(request.form.get('weight_severity', 0.25))
            w_ti = float(request.form.get('weight_threat_intel', 0.25))
            w_crit = float(request.form.get('weight_asset_criticality', 0.20))
            w_freq = float(request.form.get('weight_attack_frequency', 0.15))
            w_vuln = float(request.form.get('weight_vuln_impact', 0.15))

            total_weight = w_sev + w_ti + w_crit + w_freq + w_vuln
            if abs(total_weight - 1.0) > 0.01:
                flash(f"Warning: Weights sum to {total_weight:.2f} instead of 1.0. Please adjust them to equal 1.0.", 'warning')

            SystemSetting.set('WEIGHT_SEVERITY', str(w_sev))
            SystemSetting.set('WEIGHT_THREAT_INTEL', str(w_ti))
            SystemSetting.set('WEIGHT_ASSET_CRITICALITY', str(w_crit))
            SystemSetting.set('WEIGHT_ATTACK_FREQUENCY', str(w_freq))
            SystemSetting.set('WEIGHT_VULN_IMPACT', str(w_vuln))
            flash('Settings and Risk Weights saved successfully.', 'success')
        except ValueError:
            flash('Invalid numeric value for weights.', 'danger')

        return redirect(url_for('settings.index'))

    # Load settings
    settings = {
        'abuseipdb_key': SystemSetting.get('ABUSEIPDB_API_KEY', ''),
        'virustotal_key': SystemSetting.get('VIRUSTOTAL_API_KEY', ''),
        'w_sev': SystemSetting.get('WEIGHT_SEVERITY', '0.25'),
        'w_ti': SystemSetting.get('WEIGHT_THREAT_INTEL', '0.25'),
        'w_crit': SystemSetting.get('WEIGHT_ASSET_CRITICALITY', '0.20'),
        'w_freq': SystemSetting.get('WEIGHT_ATTACK_FREQUENCY', '0.15'),
        'w_vuln': SystemSetting.get('WEIGHT_VULN_IMPACT', '0.15')
    }

    # Diagnostics
    stats = {
        'total_alerts': Alert.query.count(),
        'total_incidents': Incident.query.count(),
        'cached_iocs': ThreatIntelCache.query.count(),
        'model_status': 'Ready (Active)' if predictor.is_ready() else 'Not Trained'
    }

    return render_template('settings/index.html', settings=settings, stats=stats)

@settings_bp.route('/retrain-model', methods=['POST'])
@login_required
def retrain_model():
    if not current_user.is_admin:
        flash('Only SOC Administrators can trigger machine learning model retraining.', 'danger')
        return redirect(url_for('settings.index'))

    try:
        model, metadata = train_and_save_model()
        predictor.reload()
        acc = metadata.get('accuracy_rf', 0.0)
        flash(f"Random Forest model retrained successfully! Test Accuracy: {acc}%. Model hot-reloaded into inference pipeline.", 'success')
    except Exception as e:
        flash(f"Failed to retrain model: {str(e)}", 'danger')

    return redirect(url_for('settings.index'))
