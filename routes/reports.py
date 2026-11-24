from flask import Blueprint, render_template, request, Response
from flask_login import login_required
from models import Alert, Incident, PrioritizationResult
from services.report_service import ReportService

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')
report_svc = ReportService()

@reports_bp.route('', strict_slashes=False)
@reports_bp.route('/', strict_slashes=False)
@login_required
def index():
    priority_filter = request.args.get('priority', '').strip()
    status_filter = request.args.get('status', '').strip()

    query = Alert.query.join(PrioritizationResult)
    if priority_filter:
        query = query.filter(PrioritizationResult.priority_level == priority_filter)
    if status_filter:
        query = query.filter(Alert.status == status_filter)

    alerts = query.order_by(Alert.timestamp.desc()).limit(15).all()
    total_count = query.count()

    return render_template(
        'reports/index.html',
        alerts=alerts,
        total_count=total_count,
        priority_filter=priority_filter,
        status_filter=status_filter
    )

@reports_bp.route('/export/csv')
@login_required
def export_csv():
    priority_filter = request.args.get('priority', '').strip()
    query = Alert.query.join(PrioritizationResult)
    if priority_filter:
        query = query.filter(PrioritizationResult.priority_level == priority_filter)

    csv_data = report_svc.export_csv(query)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=soc_prioritized_alerts.csv"}
    )

@reports_bp.route('/export/pdf')
@login_required
def export_pdf():
    pdf_bytes = report_svc.export_pdf(title="SOC Executive Threat Intelligence & Alert Prioritization Report")
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-disposition": "attachment; filename=soc_threat_intelligence_report.pdf"}
    )
