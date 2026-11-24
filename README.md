# Threat Intelligence-Driven Security Operations Center (SOC) Alert Prioritization Platform

An enterprise-grade, intelligent cybersecurity web application designed for modern Security Operations Centers (SOC). The platform combines Threat Intelligence feeds, Machine Learning classification (Random Forest), and explainable multi-factor risk scoring to analyze incoming security alerts, eliminate false positives, and streamline incident response.

---

## Key Features

1. **Enterprise Dark Cybersecurity UI/UX**:
   - Modern SIEM command console styled with high-contrast cybersecurity aesthetics (deep carbon `#070b14`, cyan glows, crimson critical alerts, emerald indicators).
   - Responsive sidebar with all 10 core navigation items.
   - Interactive Chart.js graphs for alert trends, priority distribution, MITRE ATT&CK tactics, and threat categories.

2. **Dual Prioritization Engine**:
   - **Explainable Multi-Factor Risk Score (0–100)**:
     $$\text{Risk Score} = (\text{Severity} \times 0.25) + (\text{Threat Intel} \times 0.25) + (\text{Asset Criticality} \times 0.20) + (\text{Attack Frequency} \times 0.15) + (\text{Vulnerability Impact} \times 0.15)$$
   - **Machine Learning Classification**: Trained `RandomForestClassifier` with dynamic feature contribution explainability and confidence metrics.

3. **Multi-Source Threat Intelligence**:
   - Built-in curated threat database of 100+ high-fidelity IOCs (Tor exit nodes, Cobalt Strike beacons, LockBit hashes, Mirai botnets, phishing domains).
   - Optional live API integrations with **AbuseIPDB** and **VirusTotal v3**.
   - Automated MITRE ATT&CK Matrix mapping (Tactics & Techniques).
   - Dedicated IOC Lookup tool for ad-hoc IP, domain, and hash reputation inspection.

4. **Security Alert Management**:
   - Bulk CSV file upload and ingestion.
   - Manual alert entry form with automatic threat intelligence enrichment.
   - Deep forensic inspection modal with network flow visualization and raw payload view.
   - Multi-factor search and filtering by priority, attack type, status, and target asset.

5. **Incident Management & Containment Playbooks**:
   - 1-Click alert-to-incident escalation.
   - Incident tracking with status workflow: `Open` &rarr; `In Progress` &rarr; `Contained` &rarr; `Resolved` &rarr; `Closed`.
   - SOC analyst assignment and investigation timeline audit trail.
   - Standardized containment response playbooks (Host Isolation, Firewall Blacklist, User Token Revocation, Memory RAM Dump).

6. **Executive & Technical Reporting**:
   - Professional PDF report generation using `ReportLab` with executive KPIs, critical threats table, and strategic recommendations.
   - Tabular CSV exports of prioritized alert data.

7. **Authentication & Role-Based Access Control**:
   - Secure PBKDF2 password hashing.
   - Roles: `Admin` (System settings, user management, ML model retraining) and `SOC Analyst` (Triage, incident handling, reports).

---

## Technology Stack

- **Backend**: Python 3.11+ / Flask, Flask-SQLAlchemy, Flask-Login, Requests, ReportLab
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
- **Database**: SQLite (ORM via SQLAlchemy)
- **Frontend**: HTML5, CSS3, JavaScript (ES6), Bootstrap 5.3, Chart.js 4.4, FontAwesome 6

---

## Installation & Setup Instructions

### 1. Prerequisites
Ensure Python 3.11+ is installed.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize Database & Seed Sample Data
Run the automated seed script to generate tables, pre-seed admin/analyst users, ingest 65+ realistic alerts, and populate sample incidents:
```bash
python data/seed_data.py
```

### 4. (Optional) Train the Machine Learning Model
The pre-trained Random Forest model is already bundled in `models_ml/`. To retrain:
```bash
python -m ml_engine.train_model
```

### 5. Launch the Web Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Default Login Credentials

| Role | Username / Email | Password |
|---|---|---|
| **SOC Administrator** | `admin@soc.corp` | `AdminPassword123!` |
| **SOC Analyst** | `analyst@soc.corp` | `AnalystPassword123!` |

---

## Project Structure

```
soc_alert_prioritization/
|-- app.py                     # Flask application entry point
|-- config.py                  # Application configuration & risk weights
|-- requirements.txt           # Dependencies
|-- README.md                  # Comprehensive documentation
|-- models/                    # SQLAlchemy database models
|   |-- user.py                # User & Role authentication
|   |-- alert.py               # Alert & PrioritizationResult
|   |-- incident.py            # Incident, Timeline, IncidentAlertMap
|   `-- threat_intel.py        # ThreatIntelCache & SystemSetting
|-- routes/                    # Flask blueprints
|   |-- auth.py                # Login, registration, profile, user admin
|   |-- dashboard.py           # Command center & stats API
|   |-- alerts.py              # Ingestion, CSV upload, forensic detail
|   |-- threat_intel.py        # IOC lookup & MITRE matrix
|   |-- ai_engine.py           # ML explainability & formula inspection
|   |-- incidents.py           # Incident workspace & response playbooks
|   |-- analytics.py           # Advanced visualization charts
|   |-- reports.py             # CSV & PDF export downloads
|   `-- settings.py            # API keys & model retraining
|-- services/                  # Business logic
|   |-- alert_service.py       # Ingestion & CSV parsing
|   |-- scoring_service.py     # Dual-engine risk scoring & playbooks
|   `-- report_service.py      # PDF (ReportLab) & CSV generation
|-- ml_engine/                 # Machine learning pipeline
|   |-- feature_extractor.py   # Vectorizer & normalization
|   |-- train_model.py         # Synthetic SOC dataset training
|   `-- predictor.py           # Random Forest inference & explainability
|-- threat_intelligence/       # Threat intel subsystem
|   |-- intel_engine.py        # Aggregator (AbuseIPDB, VT, Curated)
|   |-- mitre_data.py          # ATT&CK tactics & techniques
|   `-- ioc_database.py        # Pre-curated known indicators
|-- templates/                 # Jinja2 templates (Dark SOC Theme)
|-- static/                    # CSS, JS, Assets
|-- data/
|   |-- sample_alerts.csv      # 65+ realistic alerts
|   `-- seed_data.py           # Database seeder
`-- models_ml/                 # Serialized model & metadata
```

---

## License
Educational & Professional Demonstration Platform for Security Operations Centers.
