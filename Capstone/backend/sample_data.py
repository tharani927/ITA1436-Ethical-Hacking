import os
import csv
from datetime import datetime, timedelta
import random

SAMPLE_DATASETS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'sample_datasets')
)

SYNTHETIC_DOMAINS = [
    'defense-sys.internal', 'apex-fintech.org', 'omega-cloud.io',
    'synth-health.net', 'global-logistics.biz', 'matrix-infra.corp',
    'synthmail.com', 'secure-bank.internal', 'cyberlabs.edu', 'agency.gov.fake'
]

SYNTHETIC_SOURCES = [
    'TorForum-DarkThread-77',
    'RansomDump-Simulated-Exfil',
    'Paste-Bin-ThreatFeed',
    'DarkMarket-Synthetic-Broker',
    'BreachCompilation-v2.1-Simulated',
    'Underground-IRC-Snippet'
]

SYNTHETIC_ROLES = [
    ('admin.security', 'admin123', 'High', 'Privileged Account, Weak Password Pattern'),
    ('root.operator', '$2a$12$e8Yx9pL4m0nQ2v1...', 'High', 'Privileged Account, High-Value Domain'),
    ('ciso.executive', 'P@ssw0rd2026!', 'High', 'Privileged Account, Corporate Domain'),
    ('devops.lead', '12345678', 'High', 'Privileged Account, Plaintext Exposure'),
    ('billing.finance', 'finance2026', 'High', 'Privileged Account, Plaintext Exposure'),
    ('db.master', '$argon2id$v=19$m=65536...', 'High', 'Privileged Account'),
    ('sysadmin.linux', 'toor', 'High', 'Privileged Account, Weak Password Pattern'),
    ('j.watson', '5f4dcc3b5aa765d61d8327deb882cf99', 'Medium', 'MD5 Weak Hash, Plaintext Exposure'),
    ('clara.smith', '7c4a8d09ca3762af61e59520943dc26494f8941b', 'Medium', 'SHA-1 Deprecated Hash'),
    ('marcus.vance', 'Spring2026#', 'Medium', 'Plaintext Credential, Standard User'),
    ('alex.turner', 'welcome123', 'Medium', 'Weak Password Pattern'),
    ('sara.connor', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Low', 'SHA-256 Cryptographic Hash'),
    ('elena.rostova', '$2b$10$N9qo8uLOickgx2ZMRZoMye...', 'Low', 'Bcrypt Salted Hash'),
    ('david.kim', '$2b$12$K89aP1oQ6m5v7z3...', 'Low', 'Bcrypt Salted Hash'),
    ('nathan.drake', '$argon2i$v=19$m=4096,t=3,p=1...', 'Low', 'Argon2 Secure Hash'),
    ('user.guest99', 'Guest#98721_Safe', 'Low', 'High Entropy Password')
]

def generate_sample_datasets():
    """Generates synthetic CSV and TXT breach sample files for capstone demonstration."""
    os.makedirs(SAMPLE_DATASETS_DIR, exist_ok=True)

    # 1. Main CSV dataset: synthetic_darkweb_leaks_sample.csv
    csv_path = os.path.join(SAMPLE_DATASETS_DIR, 'synthetic_darkweb_leaks_sample.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Record_ID', 'Email', 'Credential_Hash', 'Domain', 'Source', 'Detection_Date', 'Role_Risk', 'Status'])
        
        base_time = datetime.now() - timedelta(days=12)
        rec_id = 1001

        for i in range(45):
            role_data = SYNTHETIC_ROLES[i % len(SYNTHETIC_ROLES)]
            domain = SYNTHETIC_DOMAINS[i % len(SYNTHETIC_DOMAINS)]
            email = f"{role_data[0]}@{domain}"
            source = SYNTHETIC_SOURCES[i % len(SYNTHETIC_SOURCES)]
            date_str = (base_time + timedelta(hours=i * 6)).strftime("%Y-%m-%d %H:%M:%S")
            status = "Active Threat" if role_data[2] == "High" else ("Investigating" if i % 2 == 0 else "Remediated")
            
            writer.writerow([
                f"REC-{rec_id}",
                email,
                role_data[1],
                domain,
                source,
                date_str,
                role_data[2],
                status
            ])
            rec_id += 1

    # 2. Text leak dump dataset: synthetic_pastebin_dump_sample.txt
    txt_path = os.path.join(SAMPLE_DATASETS_DIR, 'synthetic_pastebin_dump_sample.txt')
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write("# Synthetic Dark Web Paste Dump (Ethical Research Sample)\n")
        f.write("# Format: email:password_or_hash\n\n")
        
        for i in range(30):
            role_data = SYNTHETIC_ROLES[i % len(SYNTHETIC_ROLES)]
            domain = SYNTHETIC_DOMAINS[(i + 2) % len(SYNTHETIC_DOMAINS)]
            email = f"user_{i}_{role_data[0]}@{domain}"
            f.write(f"{email}:{role_data[1]}\n")

    # 3. High-Risk Corporate Breach: synthetic_corporate_breach.csv
    corp_path = os.path.join(SAMPLE_DATASETS_DIR, 'synthetic_corporate_breach.csv')
    with open(corp_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['email', 'password', 'source', 'date', 'status'])
        
        corp_roles = ['administrator', 'ceo', 'payroll', 'secops', 'infra.lead', 'dev.lead', 'support.tier3']
        for i, r in enumerate(corp_roles):
            writer.writerow([
                f"{r}@apex-fintech.org",
                f"Apex2026!_{i}",
                "Ransomware-Exfil-Simulation",
                (datetime.now() - timedelta(hours=i*2)).strftime("%Y-%m-%d %H:%M:%S"),
                "Active Threat"
            ])
        for j in range(20):
            writer.writerow([
                f"staff_{j}@apex-fintech.org",
                f"password{j}!",
                "Ransomware-Exfil-Simulation",
                (datetime.now() - timedelta(hours=j*3)).strftime("%Y-%m-%d %H:%M:%S"),
                "Investigating"
            ])

    return [csv_path, txt_path, corp_path]

def seed_database_sample(database_module, analyzer_module):
    """
    Populate database with the synthetic dataset for immediate demonstration.
    """
    csv_path = os.path.join(SAMPLE_DATASETS_DIR, 'synthetic_darkweb_leaks_sample.csv')
    if not os.path.exists(csv_path):
        generate_sample_datasets()
    
    # Process the CSV file through analyzer
    result = analyzer_module.parse_and_analyze_file(csv_path, 'synthetic_darkweb_leaks_sample.csv')
    database_module.save_scan(result)
    database_module.save_leak_records(result['processed_records'])
    return result
