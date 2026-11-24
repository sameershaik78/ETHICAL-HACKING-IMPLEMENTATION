import os
import sys
from datetime import datetime
from flask import Flask, render_template
from flask_login import LoginManager
from config import config_dict
from models import db, User
from routes import register_blueprints

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config_dict.get(config_name, config_dict['default']))

    # Ensure instance directory exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please authenticate to access the SOC Command Platform.'
    login_manager.login_message_category = 'warning'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    register_blueprints(app)

    # Jinja Template Filters
    @app.template_filter('datetime_format')
    def datetime_format(value, fmt='%Y-%m-%d %H:%M:%S'):
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value)
                return dt.strftime(fmt)
            except Exception:
                return value
        elif isinstance(value, datetime):
            return value.strftime(fmt)
        return 'N/A'

    @app.template_filter('priority_badge')
    def priority_badge(priority):
        p = str(priority).capitalize()
        mapping = {
            'Critical': 'badge-critical',
            'High': 'badge-high',
            'Medium': 'badge-medium',
            'Low': 'badge-low'
        }
        return mapping.get(p, 'badge-secondary')

    @app.template_filter('status_badge')
    def status_badge(status):
        s = str(status)
        mapping = {
            'New': 'bg-primary',
            'Under Investigation': 'bg-warning text-dark',
            'Escalated': 'bg-danger',
            'Closed': 'bg-secondary',
            'False Positive': 'bg-success',
            'Open': 'bg-danger',
            'In Progress': 'bg-warning text-dark',
            'Contained': 'bg-info text-dark',
            'Resolved': 'bg-success'
        }
        return mapping.get(s, 'bg-secondary')

    @app.template_filter('risk_color')
    def risk_color(score):
        try:
            val = float(score)
            if val >= 80:
                return '#ef4444' # red
            elif val >= 60:
                return '#f97316' # orange
            elif val >= 35:
                return '#eab308' # yellow
            else:
                return '#10b981' # green
        except Exception:
            return '#94a3b8'

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('base.html', error_code=404, error_message="Page Not Found"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('base.html', error_code=500, error_message="Internal Server Error"), 500

    return app

if __name__ == '__main__':
    app = create_app('development')
    with app.app_context():
        db.create_all()
    print("=" * 60)
    print("SOC Alert Prioritization Platform Starting...")
    print("Web Console: http://127.0.0.1:5000")
    print("Default Admin:   admin@soc.corp   (Password: AdminPassword123!)")
    print("Default Analyst: analyst@soc.corp (Password: AnalystPassword123!)")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
