from flask import Blueprint

def register_blueprints(app):
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.alerts import alerts_bp
    from routes.threat_intel import threat_intel_bp
    from routes.ai_engine import ai_engine_bp
    from routes.incidents import incidents_bp
    from routes.analytics import analytics_bp
    from routes.reports import reports_bp
    from routes.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(ai_engine_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
