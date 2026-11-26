import re
import os
import uuid
import hashlib
from datetime import datetime
import pandas as pd

# Regex for detecting email addresses
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
EXTRACT_EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

# Privileged role indicators
PRIVILEGED_KEYWORDS = [
    'admin', 'root', 'administrator', 'sysadmin', 'devops', 'security',
    'ceo', 'cto', 'cfo', 'ciso', 'finance', 'billing', 'payroll',
    'hr', 'database', 'support', 'infra', 'master', 'operations'
]

# Common weak passwords (for synthetic risk detection)
COMMON_WEAK_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
    '1234', '111111', '1234567', 'dragon', 'welcome', 'admin',
    'admin123', 'root', 'toor', 'letmein', 'pass123', 'default',
    'changeme', 'iloveyou', 'sunshine', 'princess', 'football'
}

def mask_email(email):
    """
    Mask an email address for ethical display.
    Example: john.doe@example.com -> j***e@example.com
             ad@corp.com -> a*@corp.com
    """
    if not email or '@' not in email:
        return '***@masked.com'
    
    parts = email.strip().split('@', 1)
    username = parts[0]
    domain = parts[1] if len(parts) > 1 else 'unknown.com'

    if len(username) <= 1:
        masked_user = '*'
    elif len(username) == 2:
        masked_user = username[0] + '*'
    elif len(username) <= 4:
        masked_user = username[0] + '**' + username[-1]
    else:
        masked_user = username[0] + '***' + username[-1]

    return f"{masked_user}@{domain}"

def detect_credential_type(raw_val):
    """
    Determine whether a credential is a hash or plaintext, without storing the raw value.
    """
    if not raw_val:
        return "Unknown / Empty"
    
    val = str(raw_val).strip()
    length = len(val)

    if val.startswith(('$2a$', '$2b$', '$2y$')):
        return "Bcrypt Salted Hash"
    if val.startswith(('$argon2', '$pbkdf2')):
        return "Argon2 / PBKDF2 Secure Hash"
    if length == 32 and re.match(r'^[a-fA-F0-9]{32}$', val):
        return "MD5 Weak Hash"
    if length == 40 and re.match(r'^[a-fA-F0-9]{40}$', val):
        return "SHA-1 Deprecated Hash"
    if length == 64 and re.match(r'^[a-fA-F0-9]{64}$', val):
        return "SHA-256 Cryptographic Hash"
    
    return "Plaintext Credential"

def evaluate_record_risk(email, cred_type, raw_password_sample, source):
    """
    Evaluate threat severity for a single credential record.
    Returns: (risk_level, risk_factors_list)
    """
    risk_level = "Low"
    factors = []
    
    email_lower = email.lower()
    user_part = email_lower.split('@')[0] if '@' in email_lower else ''
    domain_part = email_lower.split('@')[1] if '@' in email_lower else ''

    # 1. Privileged Account Check
    is_privileged = any(kw in user_part for kw in PRIVILEGED_KEYWORDS)
    if is_privileged:
        factors.append("Privileged Account")

    # 2. Critical Domain Check (.gov, .mil, .edu, corporate internal)
    is_critical_domain = any(domain_part.endswith(suffix) for suffix in ['.gov', '.mil', '.edu', '.internal', '.corp'])
    if is_critical_domain:
        factors.append("High-Value Domain")

    # 3. Credential Weakness Check
    pwd_clean = str(raw_password_sample).strip() if raw_password_sample else ""
    is_weak_pwd = False

    if cred_type == "Plaintext Credential":
        factors.append("Plaintext Exposure")
        if pwd_clean.lower() in COMMON_WEAK_PASSWORDS or len(pwd_clean) < 8 or pwd_clean.lower() == user_part:
            is_weak_pwd = True
            factors.append("Weak Password Pattern")
    elif "Weak Hash" in cred_type or "Deprecated" in cred_type:
        factors.append("Easily Reversible Hash")
    elif "Bcrypt" in cred_type or "Argon2" in cred_type or "SHA-256" in cred_type:
        factors.append("Salted/Hashed Storage")

    # Risk Level Determination
    if is_privileged or (is_critical_domain and "Plaintext" in factors) or (is_weak_pwd and is_critical_domain):
        risk_level = "High"
    elif is_weak_pwd or "Plaintext Exposure" in factors or "Weak Hash" in cred_type or is_critical_domain:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Default factor if empty
    if not factors:
        factors.append("Standard User Credential")

    return risk_level, factors

def parse_and_analyze_file(file_path, original_filename):
    """
    Process CSV or TXT file using pandas and heuristic parsing.
    Returns: dict of stats and list of processed leak records.
    """
    ext = os.path.splitext(original_filename)[1].lower()
    records_to_process = []
    
    if ext == '.csv':
        try:
            # First try standard CSV read with pandas
            df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
            
            # Identify columns
            cols_lower = {str(c).lower().strip(): c for c in df.columns}
            
            email_col = None
            pwd_col = None
            source_col = None
            date_col = None
            status_col = None

            for col, orig in cols_lower.items():
                if any(k in col for k in ['email', 'mail', 'user_email']):
                    email_col = orig
                elif any(k in col for k in ['password', 'passwd', 'pass', 'hash', 'credential']):
                    pwd_col = orig
                elif any(k in col for k in ['source', 'origin', 'breach_name', 'leak_source']):
                    source_col = orig
                elif any(k in col for k in ['date', 'time', 'detected', 'scan_date']):
                    date_col = orig
                elif any(k in col for k in ['status', 'state']):
                    status_col = orig

            # If no email column found by name, scan first row for email format
            if not email_col:
                for col in df.columns:
                    sample_vals = df[col].dropna().astype(str).head(10)
                    if any(EXTRACT_EMAIL_REGEX.search(v) for v in sample_vals):
                        email_col = col
                        break

            # If columns still missing, treat as raw rows
            if email_col:
                for idx, row in df.iterrows():
                    raw_email = str(row[email_col]).strip()
                    raw_pwd = str(row[pwd_col]).strip() if pwd_col and pwd_col in row else ""
                    src = str(row[source_col]).strip() if source_col and source_col in row else f"Upload:{original_filename}"
                    dt = str(row[date_col]).strip() if date_col and date_col in row else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    st = str(row[status_col]).strip() if status_col and status_col in row else "Active Threat"
                    
                    records_to_process.append({
                        'raw_email': raw_email,
                        'raw_password': raw_pwd,
                        'source': src,
                        'date': dt,
                        'status': st
                    })
            else:
                # Fallback: line-by-line parsing if headerless or unstructured CSV
                records_to_process = parse_txt_lines(file_path, original_filename)
        except Exception as e:
            # Fallback to text line parser
            records_to_process = parse_txt_lines(file_path, original_filename)
    else:
        # TXT or arbitrary delimited dump
        records_to_process = parse_txt_lines(file_path, original_filename)

    # Process and classify the extracted records
    scan_id = f"SCN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    seen_emails = set()
    duplicate_count = 0
    valid_email_count = 0
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    
    processed_records = []
    
    record_counter = 1000 + int(datetime.now().strftime('%f')) % 8000

    for item in records_to_process:
        raw_email = item.get('raw_email', '').strip()
        raw_pwd = item.get('raw_password', '').strip()
        source = item.get('source', f"Dump:{original_filename}")
        detection_date = item.get('date', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        status = item.get('status', 'Active Threat')

        # Find valid email inside the line/string
        match = EXTRACT_EMAIL_REGEX.search(raw_email)
        if not match:
            continue
        
        email = match.group(0).lower()
        valid_email_count += 1

        if email in seen_emails:
            duplicate_count += 1
            # Still process duplicate or note it
        seen_emails.add(email)

        domain = email.split('@')[1] if '@' in email else 'unknown.com'
        cred_type = detect_credential_type(raw_pwd)
        risk_level, factors = evaluate_record_risk(email, cred_type, raw_pwd, source)

        if risk_level == "High":
            high_risk_count += 1
        elif risk_level == "Medium":
            medium_risk_count += 1
        else:
            low_risk_count += 1

        record_id = f"REC-{record_counter}"
        record_counter += 1
        email_hash = hashlib.sha256(email.encode('utf-8')).hexdigest()

        processed_records.append({
            'record_id': record_id,
            'scan_id': scan_id,
            'email_masked': mask_email(email),
            'email_hash': email_hash,
            'domain': domain,
            'source': source,
            'detection_date': detection_date,
            'risk_level': risk_level,
            'risk_factors': ", ".join(factors),
            'credential_type': cred_type,
            'status': status
        })

    total_records = len(records_to_process)
    
    # Calculate overall risk score for this scan
    if valid_email_count > 0:
        base_score = ((high_risk_count * 1.0) + (medium_risk_count * 0.5) + (low_risk_count * 0.15)) / valid_email_count * 100
        overall_risk_score = min(100.0, round(base_score, 1))
    else:
        overall_risk_score = 0.0

    return {
        'scan_id': scan_id,
        'filename': original_filename,
        'file_type': ext.upper().replace('.', ''),
        'total_records': total_records,
        'email_records': valid_email_count,
        'duplicate_records': duplicate_count,
        'high_risk_count': high_risk_count,
        'medium_risk_count': medium_risk_count,
        'low_risk_count': low_risk_count,
        'overall_risk_score': overall_risk_score,
        'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'status': 'Completed',
        'processed_records': processed_records
    }

def parse_txt_lines(file_path, original_filename):
    """
    Parses a text file line-by-line detecting common breach dump formats:
    email:password, email:hash, user:email:password, email;password, email,password
    """
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_str = line.strip()
            if not line_str or line_str.startswith('#'):
                continue
            
            # Check delimiters
            delims = [':', ';', '|', ',', '\t']
            detected_delim = None
            for d in delims:
                if d in line_str:
                    detected_delim = d
                    break

            if detected_delim:
                tokens = [t.strip() for t in line_str.split(detected_delim)]
                # Look for email among tokens
                email_token = None
                pwd_token = ""
                for idx, t in enumerate(tokens):
                    if EXTRACT_EMAIL_REGEX.search(t):
                        email_token = t
                        # Credential is often right after email or preceding
                        if idx + 1 < len(tokens):
                            pwd_token = tokens[idx + 1]
                        elif idx - 1 >= 0:
                            pwd_token = tokens[idx - 1]
                        break
                
                if email_token:
                    results.append({
                        'raw_email': email_token,
                        'raw_password': pwd_token,
                        'source': f"TextDump:{original_filename}",
                        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'status': 'Active Threat'
                    })
            else:
                # Single email per line
                match = EXTRACT_EMAIL_REGEX.search(line_str)
                if match:
                    results.append({
                        'raw_email': match.group(0),
                        'raw_password': '',
                        'source': f"TextDump:{original_filename}",
                        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'status': 'Active Threat'
                    })

    return results
