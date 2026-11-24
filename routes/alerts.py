from datetime import datetime
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, Response
from flask_login import login_required
from models import db, Alert, PrioritizationResult
from services.alert_service import AlertService

alerts_bp = Blueprint('alerts', __name__, url_prefix='/alerts')
alert_service = AlertService()

@alerts_bp.route('', strict_slashes=False)
@alerts_bp.route('/', strict_slashes=False)
@login_required
def index():
    priority_filter = request.args.get('priority', '').strip()
    status_filter = request.args.get('status', '').strip()
    attack_filter = request.args.get('attack_type', '').strip()
    search = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = Alert.query.join(PrioritizationResult)

    if priority_filter:
        query = query.filter(PrioritizationResult.priority_level == priority_filter)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if attack_filter:
        query = query.filter(Alert.attack_type.ilike(f"%{attack_filter}%"))
    if search:
        query = query.filter(
            (Alert.title.ilike(f"%{search}%")) |
            (Alert.source_ip.ilike(f"%{search}%")) |
            (Alert.destination_ip.ilike(f"%{search}%")) |
            (Alert.asset_name.ilike(f"%{search}%")) |
            (Alert.alert_id.ilike(f"%{search}%"))
        )

    pagination = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=15, error_out=False)
    alerts = pagination.items

    # Available attack types for filter dropdown
    attack_types = [r[0] for r in db.session.query(Alert.attack_type).distinct().all() if r[0]]

    return render_template(
        'alerts/index.html',
        alerts=alerts,
        pagination=pagination,
        priority_filter=priority_filter,
        status_filter=status_filter,
        attack_filter=attack_filter,
        search=search,
        attack_types=attack_types
    )

@alerts_bp.route('/<alert_id>')
@login_required
def detail(alert_id):
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    return render_template('alerts/detail.html', alert=alert)

@alerts_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    if request.method == 'POST':
        existing_count = Alert.query.count()
        generated_id = f"ALT-{datetime.utcnow().year}-{existing_count + 1:04d}"

        alert_data = {
            'alert_id': generated_id,
            'title': request.form.get('title', '').strip(),
            'description': request.form.get('description', '').strip(),
            'source_ip': request.form.get('source_ip', '').strip(),
            'destination_ip': request.form.get('destination_ip', '').strip(),
            'source_port': request.form.get('source_port', 0),
            'destination_port': request.form.get('destination_port', 0),
            'protocol': request.form.get('protocol', 'TCP'),
            'attack_type': request.form.get('attack_type', 'Other'),
            'raw_severity': request.form.get('raw_severity', 'Medium'),
            'asset_name': request.form.get('asset_name', 'Internal Asset'),
            'asset_criticality': request.form.get('asset_criticality', 'Medium'),
            'attack_frequency': request.form.get('attack_frequency', 1),
            'vulnerability_cve': request.form.get('vulnerability_cve', 'N/A'),
            'mitre_technique_id': request.form.get('mitre_technique_id', ''),
            'mitre_technique_name': request.form.get('mitre_technique_name', ''),
            'mitre_tactic': request.form.get('mitre_tactic', ''),
            'ioc_indicators': request.form.get('ioc_indicators', ''),
            'raw_payload': request.form.get('raw_payload', ''),
            'status': 'New',
            'is_simulated': False
        }

        try:
            alert = alert_service.ingest_single_alert(alert_data)
            flash(f"Alert {alert.alert_id} created and prioritized successfully! (Risk Score: {alert.prioritization.risk_score}, Priority: {alert.prioritization.priority_level})", 'success')
            return redirect(url_for('alerts.detail', alert_id=alert.alert_id))
        except Exception as e:
            flash(f"Error creating alert: {str(e)}", 'danger')

    return render_template('alerts/new.html')

@alerts_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'warning')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'warning')
            return redirect(request.url)

        if not file.filename.lower().endswith('.csv'):
            flash('Only CSV files are supported.', 'danger')
            return redirect(request.url)

        try:
            content = file.stream.read().decode('utf-8')
            success_count, errors = alert_service.parse_and_import_csv(content)
            flash(f"Batch ingestion complete! Successfully prioritized {success_count} alerts.", 'success')
            if errors:
                flash(f"Encountered {len(errors)} row warning(s): {errors[0]}", 'warning')
            return redirect(url_for('alerts.index'))
        except Exception as e:
            flash(f"Failed to process CSV file: {str(e)}", 'danger')
            return redirect(request.url)

    return render_template('alerts/upload.html')

@alerts_bp.route('/template')
@login_required
def download_template():
    header = "alert_id,title,description,source_ip,destination_ip,source_port,destination_port,protocol,attack_type,raw_severity,asset_name,asset_criticality,attack_frequency,vulnerability_cve,mitre_technique_id,mitre_technique_name,mitre_tactic,ioc_indicators,raw_payload\n"
    sample = "ALT-SAMPLE-01,Test Web Attack,Sample description,103.203.57.18,10.0.1.5,45120,443,TCP,SQL Injection,High,CUSTOMER-PORTAL,High,5,CVE-2024-3400,T1190,Exploit Public-Facing Application,Initial Access,103.203.57.18,' OR 1=1--\n"
    return Response(
        header + sample,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=soc_alerts_template.csv"}
    )

@alerts_bp.route('/<alert_id>/status', methods=['POST'])
@login_required
def update_status(alert_id):
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    new_status = request.form.get('status')
    if new_status in ['New', 'Under Investigation', 'Escalated', 'Closed', 'False Positive']:
        alert.status = new_status
        db.session.commit()
        flash(f"Status for {alert.alert_id} updated to {new_status}.", 'success')
    return redirect(request.referrer or url_for('alerts.detail', alert_id=alert.alert_id))
