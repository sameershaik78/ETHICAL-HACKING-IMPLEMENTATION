import json
from datetime import datetime
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import db, Incident, IncidentTimeline, Alert, User

incidents_bp = Blueprint('incidents', __name__, url_prefix='/incidents')

@incidents_bp.route('', strict_slashes=False)
@incidents_bp.route('/', strict_slashes=False)
@login_required
def index():
    status_filter = request.args.get('status', '').strip()
    priority_filter = request.args.get('priority', '').strip()

    query = Incident.query

    if status_filter:
        query = query.filter_by(status=status_filter)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)

    incidents = query.order_by(Incident.updated_at.desc()).all()

    # Metrics
    open_count = Incident.query.filter_by(status='Open').count()
    progress_count = Incident.query.filter_by(status='In Progress').count()
    contained_count = Incident.query.filter_by(status='Contained').count()
    resolved_count = Incident.query.filter_by(status='Resolved').count()

    return render_template(
        'incidents/index.html',
        incidents=incidents,
        open_count=open_count,
        progress_count=progress_count,
        contained_count=contained_count,
        resolved_count=resolved_count,
        status_filter=status_filter,
        priority_filter=priority_filter
    )

@incidents_bp.route('/<incident_id>')
@login_required
def detail(incident_id):
    incident = Incident.query.filter_by(incident_id=incident_id).first_or_404()
    users = User.query.filter_by(is_active=True).all()
    return render_template('incidents/detail.html', incident=incident, users=users)

@incidents_bp.route('/create-from-alert/<alert_id>', methods=['POST'])
@login_required
def create_from_alert(alert_id):
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()

    count = Incident.query.count()
    inc_id = f"INC-{datetime.utcnow().year}-{count + 1:04d}"

    priority = alert.prioritization.priority_level if alert.prioritization else alert.raw_severity
    if priority not in ['Critical', 'High', 'Medium', 'Low']:
        priority = 'High'

    incident = Incident(
        incident_id=inc_id,
        title=f"Security Incident: {alert.title}",
        description=f"Promoted from alert {alert.alert_id}. Target asset: {alert.asset_name}. Offending IP: {alert.source_ip}. {alert.description}",
        priority=priority,
        status='Open',
        assigned_to_id=current_user.id,
        created_by_id=current_user.id
    )
    incident.alerts.append(alert)
    db.session.add(incident)
    db.session.flush()

    # Timeline note
    timeline = IncidentTimeline(
        incident_id=incident.id,
        user_id=current_user.id,
        action_type="Incident Created",
        note=f"Incident opened by {current_user.full_name} from alert {alert.alert_id}."
    )
    db.session.add(timeline)

    # Update alert status
    alert.status = 'Escalated'
    db.session.commit()

    flash(f"Incident {incident.incident_id} created successfully from alert {alert.alert_id}!", 'success')
    return redirect(url_for('incidents.detail', incident_id=incident.incident_id))

@incidents_bp.route('/<incident_id>/timeline', methods=['POST'])
@login_required
def add_timeline_note(incident_id):
    incident = Incident.query.filter_by(incident_id=incident_id).first_or_404()
    note_text = request.form.get('note', '').strip()
    action_type = request.form.get('action_type', 'Note Added')

    if note_text:
        tl = IncidentTimeline(
            incident_id=incident.id,
            user_id=current_user.id,
            action_type=action_type,
            note=note_text
        )
        db.session.add(tl)
        incident.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Timeline updated successfully.", 'success')

    return redirect(url_for('incidents.detail', incident_id=incident.incident_id))

@incidents_bp.route('/<incident_id>/update-status', methods=['POST'])
@login_required
def update_status(incident_id):
    incident = Incident.query.filter_by(incident_id=incident_id).first_or_404()
    new_status = request.form.get('status')
    resolution_summary = request.form.get('resolution_summary', '').strip()

    if new_status in ['Open', 'In Progress', 'Contained', 'Resolved', 'Closed']:
        old_status = incident.status
        incident.status = new_status
        if resolution_summary:
            incident.resolution_summary = resolution_summary

        tl = IncidentTimeline(
            incident_id=incident.id,
            user_id=current_user.id,
            action_type="Status Change",
            note=f"Status changed from {old_status} to {new_status} by {current_user.full_name}."
        )
        db.session.add(tl)
        db.session.commit()
        flash(f"Incident status updated to {new_status}.", 'success')

    return redirect(url_for('incidents.detail', incident_id=incident.incident_id))

@incidents_bp.route('/<incident_id>/assign', methods=['POST'])
@login_required
def assign_analyst(incident_id):
    incident = Incident.query.filter_by(incident_id=incident_id).first_or_404()
    user_id = request.form.get('user_id', type=int)
    assigned_user = User.query.get(user_id) if user_id else None

    incident.assigned_to_id = assigned_user.id if assigned_user else None
    tl = IncidentTimeline(
        incident_id=incident.id,
        user_id=current_user.id,
        action_type="Assigned",
        note=f"Assigned to {assigned_user.full_name if assigned_user else 'Unassigned'}."
    )
    db.session.add(tl)
    db.session.commit()
    flash("Incident assignee updated.", 'success')
    return redirect(url_for('incidents.detail', incident_id=incident.incident_id))

@incidents_bp.route('/<incident_id>/execute-playbook', methods=['POST'])
@login_required
def execute_playbook(incident_id):
    incident = Incident.query.filter_by(incident_id=incident_id).first_or_404()
    action = request.form.get('action', '').strip()

    if action:
        actions = incident.get_actions()
        if action not in actions:
            actions.append(action)
            incident.set_actions(actions)

        tl = IncidentTimeline(
            incident_id=incident.id,
            user_id=current_user.id,
            action_type="Playbook Executed",
            note=f"SOC Playbook Response executed: {action} by {current_user.full_name}."
        )
        db.session.add(tl)
        db.session.commit()
        flash(f"Playbook action executed: {action}", 'success')

    return redirect(url_for('incidents.detail', incident_id=incident.incident_id))
