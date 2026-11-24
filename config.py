import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-cybersecurity-secret-key-prod-2026-secure')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'soc_platform.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    
    # Upload limits
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    UPLOAD_EXTENSIONS = ['.csv']
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'instance', 'uploads')
    
    # Threat Intelligence API Keys (can also be overridden in DB SystemSetting)
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # ML Engine paths
    ML_MODEL_PATH = os.path.join(BASE_DIR, 'models_ml', 'priority_rf_model.joblib')
    ML_METADATA_PATH = os.path.join(BASE_DIR, 'models_ml', 'model_metadata.json')
    
    # Risk weights baseline
    WEIGHT_SEVERITY = float(os.environ.get('WEIGHT_SEVERITY', 0.25))
    WEIGHT_THREAT_INTEL = float(os.environ.get('WEIGHT_THREAT_INTEL', 0.25))
    WEIGHT_ASSET_CRITICALITY = float(os.environ.get('WEIGHT_ASSET_CRITICALITY', 0.20))
    WEIGHT_ATTACK_FREQUENCY = float(os.environ.get('WEIGHT_ATTACK_FREQUENCY', 0.15))
    WEIGHT_VULN_IMPACT = float(os.environ.get('WEIGHT_VULN_IMPACT', 0.15))

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config_dict = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
