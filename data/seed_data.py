import os
import sys
from datetime import datetime, timedelta

# Ensure workspace root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app
from models import db, User, Alert, PrioritizationResult, Incident, IncidentTimeline, ThreatIntelCache, SystemSetting
from threat_intelligence.ioc_database import KNOWN_IOCS
from services.alert_service import AlertService

def seed_database():
    app = create_app('development')
    with app.app_context():
        print("Ensuring database tables are created...")
        db.create_all()

        # 1. Seed Users
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@soc.corp',
                full_name='Chief SOC Administrator',
                role='Admin',
                is_active=True
            )
            admin.set_password('AdminPassword123!')
            db.session.add(admin)
            print("Created Admin User: admin@soc.corp (Password: AdminPassword123!)")

        if not User.query.filter_by(username='analyst').first():
            analyst = User(
                username='analyst',
                email='analyst@soc.corp',
                full_name='Senior SOC Analyst',
                role='SOC Analyst',
                is_active=True
            )
            analyst.set_password('AnalystPassword123!')
            db.session.add(analyst)
            print("Created Analyst User: analyst@soc.corp (Password: AnalystPassword123!)")

        db.session.commit()

        # 2. Seed Default System Settings
        default_settings = [
            ('ABUSEIPDB_API_KEY', '', 'API Key for AbuseIPDB Threat Intelligence'),
            ('VIRUSTOTAL_API_KEY', '', 'API Key for VirusTotal v3 Threat Intelligence'),
            ('WEIGHT_SEVERITY', '0.25', 'Risk weight for Alert Severity'),
            ('WEIGHT_THREAT_INTEL', '0.25', 'Risk weight for Threat Intelligence'),
            ('WEIGHT_ASSET_CRITICALITY', '0.20', 'Risk weight for Asset Criticality'),
            ('WEIGHT_ATTACK_FREQUENCY', '0.15', 'Risk weight for Attack Frequency'),
            ('WEIGHT_VULN_IMPACT', '0.15', 'Risk weight for Vulnerability Impact'),
            ('AUTO_INCIDENT_ESCALATION', 'True', 'Automatically escalate Critical alerts with Risk Score >= 85')
        ]

        for k, v, desc in default_settings:
            if not SystemSetting.query.filter_by(key=k).first():
                SystemSetting.set(k, v, desc)

        print("Default System Settings seeded.")

        # 3. Seed Threat Intel Cache with Known IOCs
        for ioc_val, ioc_data in KNOWN_IOCS.items():
            if not ThreatIntelCache.query.filter_by(indicator_value=ioc_val).first():
                entry = ThreatIntelCache(
                    indicator_type=ioc_data['type'],
                    indicator_value=ioc_val,
                    reputation_score=ioc_data.get('reputation_score', 0.0),
                    malicious_count=ioc_data.get('malicious_count', 0),
                    total_engines=ioc_data.get('total_engines', 70),
                    threat_labels=ioc_data.get('threat_labels', ''),
                    source_provider='Curated SOC Threat Database'
                )
                db.session.add(entry)

        db.session.commit()
        print("Threat Intelligence Cache seeded with known indicators.")

        # 4. Ingest Sample Alerts if none exist
        if Alert.query.count() == 0:
            csv_path = os.path.join(BASE_DIR, 'data', 'sample_alerts.csv')
            if os.path.exists(csv_path):
                print(f"Reading and ingesting sample alerts from: {csv_path}")
                with open(csv_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                svc = AlertService()
                success_count, errors = svc.parse_and_import_csv(content)
                print(f"Successfully ingested and prioritized {success_count} alerts! (Errors: {len(errors)})")

        # 5. Seed Sample Incidents from Top Critical Alerts
        if Incident.query.count() == 0:
            analyst_user = User.query.filter_by(username='analyst').first()
            admin_user = User.query.filter_by(username='admin').first()

            # Find Cobalt Strike alert
            c2_alert = Alert.query.filter(Alert.attack_type.ilike('%c2%')).first()
            if c2_alert:
                inc1 = Incident(
                    incident_id="INC-2026-0001",
                    title="Active Cobalt Strike C2 Beaconing on Payment Gateway",
                    description="High-frequency encrypted beaconing detected from PAYMENT-GW-PROD-01 to known hostile IP 185.220.101.5. Threat intelligence confirms Tor exit node and known C2 infrastructure.",
                    priority="Critical",
                    status="In Progress",
                    assigned_to_id=analyst_user.id if analyst_user else None,
                    created_by_id=admin_user.id if admin_user else None,
                    containment_actions='["Host Isolated from Subnet", "C2 Destination Blocked on Firewall", "RAM Dump Preserved"]'
                )
                inc1.alerts.append(c2_alert)
                db.session.add(inc1)
                db.session.flush()

                t1 = IncidentTimeline(
                    incident_id=inc1.id,
                    user_id=admin_user.id if admin_user else None,
                    action_type="Incident Created",
                    note="Escalated automatically from Critical Alert ALT-2026-0001 (Risk Score: 92.5)."
                )
                t2 = IncidentTimeline(
                    incident_id=inc1.id,
                    user_id=analyst_user.id if analyst_user else None,
                    action_type="Playbook Executed",
                    note="Network isolation command issued via EDR API to PAYMENT-GW-PROD-01. Host isolated successfully."
                )
                db.session.add_all([t1, t2])

            # Find LockBit alert
            lockbit_alert = Alert.query.filter(Alert.attack_type.ilike('%ransomware%')).first()
            if lockbit_alert:
                inc2 = Incident(
                    incident_id="INC-2026-0002",
                    title="LockBit Ransomware Pre-Encryption Staging Detected",
                    description="Execution of vssadmin shadow copy deletion observed on legal file server. Malicious payload hash matched known LockBit v3 affiliate sample.",
                    priority="Critical",
                    status="Contained",
                    assigned_to_id=analyst_user.id if analyst_user else None,
                    created_by_id=analyst_user.id if analyst_user else None,
                    containment_actions='["Host Isolated", "Process Terminated", "Domain Admin Credential Reset", "Backups Verified Immutable"]'
                )
                inc2.alerts.append(lockbit_alert)
                db.session.add(inc2)
                db.session.flush()

                t3 = IncidentTimeline(
                    incident_id=inc2.id,
                    user_id=analyst_user.id if analyst_user else None,
                    action_type="Incident Created",
                    note="Created after analyst review of ransomware pre-encryption indicators."
                )
                t4 = IncidentTimeline(
                    incident_id=inc2.id,
                    user_id=analyst_user.id if analyst_user else None,
                    action_type="Status Change",
                    note="Moved status to Contained. Target process tree terminated, no files were encrypted."
                )
                db.session.add_all([t3, t4])

            # Find SSH Brute Force alert
            ssh_alert = Alert.query.filter(Alert.attack_type.ilike('%brute force%')).first()
            if ssh_alert:
                inc3 = Incident(
                    incident_id="INC-2026-0003",
                    title="Distributed SSH Brute Force Surge on Perimeter Bastion",
                    description="Over 250 failed login attempts from Mirai botnet node 45.33.32.156 targeting SSH root accounts on edge bastion.",
                    priority="High",
                    status="Resolved",
                    assigned_to_id=admin_user.id if admin_user else None,
                    created_by_id=admin_user.id if admin_user else None,
                    resolution_summary="Source IP 45.33.32.156 added to perimeter firewall drop rule. SSH password authentication disabled in favor of hardware SSH keys.",
                    containment_actions='["IP Blacklisted on Firewall", "SSH Key-Only Auth Enforced"]'
                )
                inc3.alerts.append(ssh_alert)
                db.session.add(inc3)
                db.session.flush()

                t5 = IncidentTimeline(
                    incident_id=inc3.id,
                    user_id=admin_user.id if admin_user else None,
                    action_type="Resolved",
                    note="Perimeter ACL updated. Threat mitigated."
                )
                db.session.add(t5)

            db.session.commit()
            print("Sample Incidents and Timelines seeded successfully.")

        print("Database Seeding Completed Successfully!")

if __name__ == '__main__':
    seed_database()
