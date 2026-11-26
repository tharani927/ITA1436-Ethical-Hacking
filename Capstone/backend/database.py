import sqlite3
import os
import json
import uuid
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
DB_PATH = os.path.join(DB_DIR, 'darkwatch.db')

def get_connection():
    """Create and return a database connection with dictionary-like row access."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables for DarkWatch."""
    conn = get_connection()
    cursor = conn.cursor()

    # Table: Users (Administrator Accounts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Administrator',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    ''')

    # Migration: Add last_login column if it doesn't exist
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN last_login TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Table: Active Sessions (Session-based Authentication)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Table: Notifications
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'info',
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    # Table: Scans (Analysis History)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            total_records INTEGER NOT NULL DEFAULT 0,
            email_records INTEGER NOT NULL DEFAULT 0,
            duplicate_records INTEGER NOT NULL DEFAULT 0,
            high_risk_count INTEGER NOT NULL DEFAULT 0,
            medium_risk_count INTEGER NOT NULL DEFAULT 0,
            low_risk_count INTEGER NOT NULL DEFAULT 0,
            overall_risk_score REAL NOT NULL DEFAULT 0.0,
            scan_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Completed'
        )
    ''')

    # Table: Leak Records
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leak_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT UNIQUE NOT NULL,
            scan_id TEXT NOT NULL,
            email_masked TEXT NOT NULL,
            domain TEXT NOT NULL,
            source TEXT NOT NULL,
            detection_date TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_factors TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Active Threat',
            email_hash TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        )
    ''')

    # Migration: Add email_hash column if it doesn't exist
    try:
        cursor.execute('ALTER TABLE leak_records ADD COLUMN email_hash TEXT')
    except sqlite3.OperationalError:
        pass

    # Table: System Settings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # Seed or Update Default Administrator: Username "Admin" (Capital A), Password "Admin@123"
    cursor.execute('SELECT id, username FROM users WHERE username = ? OR username = ?', ('Admin', 'admin'))
    admin_row = cursor.fetchone()
    hashed_pw = generate_password_hash('Admin@123')
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not admin_row:
        cursor.execute(
            'INSERT INTO users (username, password_hash, role, created_at, last_login) VALUES (?, ?, ?, ?, ?)',
            ('Admin', hashed_pw, 'Administrator', now_str, now_str)
        )
    else:
        # Ensure username is 'Admin' with capital A and password hash is valid
        cursor.execute(
            'UPDATE users SET username = ?, password_hash = ? WHERE id = ?',
            ('Admin', hashed_pw, admin_row['id'])
        )

    # Insert default settings if not exists
    cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', ('theme', 'dark'))
    cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', ('notifications_enabled', 'true'))
    cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', ('notify_high_risk', 'true'))
    cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', ('notify_analysis_complete', 'true'))
    cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', ('notify_login_activity', 'true'))
    cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', ('session_timeout', '24h'))

    conn.commit()
    conn.close()

# --------------------------------------------------------------------------
# Authentication & User Management
# --------------------------------------------------------------------------

def get_user_by_username(username):
    """Retrieve user record by exact username."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password_hash, role, created_at, last_login FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id):
    """Retrieve user record by user ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, created_at, last_login FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def verify_user_credentials(username, password):
    """Verify administrator credentials against secure password hash."""
    user = get_user_by_username(username)
    if not user:
        return False, None
    if check_password_hash(user['password_hash'], password):
        return True, {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'last_login': user['last_login']
        }
    return False, None

def update_user_last_login(user_id):
    """Update user's last login timestamp."""
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (now_str, user_id))
    conn.commit()
    conn.close()
    return now_str

def update_admin_password(user_id, new_password):
    """Update administrator password with secure cryptographic hash."""
    conn = get_connection()
    cursor = conn.cursor()
    hashed_pw = generate_password_hash(new_password)
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_pw, user_id))
    conn.commit()
    conn.close()
    return True

def create_session(user_id, duration_str='24h'):
    """Generate and store a new active session token."""
    token = str(uuid.uuid4())
    now = datetime.now()

    # Parse duration
    hours = 24
    if duration_str == '15m':
        delta = timedelta(minutes=15)
    elif duration_str == '30m':
        delta = timedelta(minutes=30)
    elif duration_str == '1h':
        delta = timedelta(hours=1)
    elif duration_str == '4h':
        delta = timedelta(hours=4)
    else:
        delta = timedelta(hours=hours)

    expires_at = (now + delta).strftime("%Y-%m-%d %H:%M:%S")
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO active_sessions (token, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (token, user_id, created_at, expires_at))
    conn.commit()
    conn.close()
    return token, expires_at

def validate_session(token):
    """Validate session token and return user details if active."""
    if not token:
        return None
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.token, s.expires_at, u.id as user_id, u.username, u.role, u.last_login
        FROM active_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    ''', (token,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    # Check expiration
    expires_dt = datetime.strptime(row['expires_at'], "%Y-%m-%d %H:%M:%S")
    if datetime.now() > expires_dt:
        delete_session(token)
        return None

    return {
        'user_id': row['user_id'],
        'username': row['username'],
        'role': row['role'],
        'last_login': row['last_login'],
        'token': row['token']
    }

def delete_session(token):
    """Delete session token on logout."""
    if not token:
        return
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM active_sessions WHERE token = ?', (token,))
    conn.commit()
    conn.close()

# --------------------------------------------------------------------------
# Notification System
# --------------------------------------------------------------------------

def create_notification(title, message, notif_type='info'):
    """
    Store a notification event in SQLite if notifications are enabled.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if notifications are globally enabled
    cursor.execute('SELECT value FROM system_settings WHERE key = ?', ('notifications_enabled',))
    row = cursor.fetchone()
    if row and row['value'].lower() == 'false':
        conn.close()
        return None

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO notifications (title, message, type, is_read, created_at)
        VALUES (?, ?, ?, 0, ?)
    ''', (title, message, notif_type, now_str))
    notif_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return notif_id

def get_notifications(limit=30):
    """Retrieve recent notifications ordered by newest first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, title, message, type, is_read, created_at
        FROM notifications
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT COUNT(*) as unread FROM notifications WHERE is_read = 0')
    unread_count = cursor.fetchone()['unread']
    conn.close()

    return {
        'notifications': rows,
        'unread_count': unread_count
    }

def mark_notification_as_read(notif_id):
    """Mark a specific notification as read."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notif_id,))
    conn.commit()
    conn.close()
    return True

def mark_all_notifications_as_read():
    """Mark all notifications as read."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE notifications SET is_read = 1 WHERE is_read = 0')
    conn.commit()
    conn.close()
    return True

def clear_all_notifications():
    """Clear all notifications from database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM notifications')
    conn.commit()
    conn.close()
    return True

# --------------------------------------------------------------------------
# Scans & Leak Records
# --------------------------------------------------------------------------

def save_scan(scan_data):
    """Save a scan record and return scan_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (
            scan_id, filename, file_type, total_records, email_records,
            duplicate_records, high_risk_count, medium_risk_count, low_risk_count,
            overall_risk_score, scan_date, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_data['scan_id'],
        scan_data['filename'],
        scan_data['file_type'],
        scan_data['total_records'],
        scan_data['email_records'],
        scan_data['duplicate_records'],
        scan_data['high_risk_count'],
        scan_data['medium_risk_count'],
        scan_data['low_risk_count'],
        scan_data['overall_risk_score'],
        scan_data['scan_date'],
        scan_data.get('status', 'Completed')
    ))
    conn.commit()
    conn.close()
    return scan_data['scan_id']

def save_leak_records(records):
    """Batch insert leak records."""
    if not records:
        return
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany('''
        INSERT OR REPLACE INTO leak_records (
            record_id, scan_id, email_masked, email_hash, domain, source,
            detection_date, risk_level, risk_factors, credential_type, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', [
        (
            r['record_id'],
            r['scan_id'],
            r['email_masked'],
            r.get('email_hash', ''),
            r['domain'],
            r['source'],
            r['detection_date'],
            r['risk_level'],
            r['risk_factors'] if isinstance(r['risk_factors'], str) else json.dumps(r['risk_factors']),
            r.get('credential_type', 'Masked Credential'),
            r.get('status', 'Active Threat')
        ) for r in records
    ])
    conn.commit()
    conn.close()

def get_dashboard_stats():
    """Retrieve summarized statistics and recent activity for Dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    # Query active unique credentials and risk counts directly from leak_records repository
    cursor.execute('''
        SELECT 
            COUNT(*) AS leaked_credentials,
            COALESCE(SUM(CASE WHEN LOWER(risk_level) = 'high' THEN 1 ELSE 0 END), 0) AS high_risk_records,
            COALESCE(SUM(CASE WHEN LOWER(risk_level) = 'medium' THEN 1 ELSE 0 END), 0) AS medium_risk_records,
            COALESCE(SUM(CASE WHEN LOWER(risk_level) = 'low' THEN 1 ELSE 0 END), 0) AS low_risk_records
        FROM leak_records
    ''')
    stat_row = cursor.fetchone()

    cursor.execute('SELECT COALESCE(SUM(total_records), 0) AS total_analyzed FROM scans')
    scan_row = cursor.fetchone()
    total_analyzed = scan_row['total_analyzed'] if scan_row else 0
    if total_analyzed == 0 and stat_row['leaked_credentials'] > 0:
        total_analyzed = stat_row['leaked_credentials']

    cursor.execute('''
        SELECT scan_date, filename, total_records, high_risk_count
        FROM scans
        ORDER BY id DESC LIMIT 1
    ''')
    last_scan_row = cursor.fetchone()
    last_scan_str = last_scan_row['scan_date'] if last_scan_row else 'No scans yet'

    cursor.execute('''
        SELECT scan_id, filename, scan_date, total_records, email_records, 
               high_risk_count, medium_risk_count, low_risk_count, status
        FROM scans
        ORDER BY id DESC LIMIT 6
    ''')
    recent_activity = [dict(row) for row in cursor.fetchall()]

    high = stat_row['high_risk_records']
    med = stat_row['medium_risk_records']
    low = stat_row['low_risk_records']
    total_risks = high + med + low

    conn.close()

    return {
        'total_records_analyzed': total_analyzed,
        'leaked_credentials': stat_row['leaked_credentials'],
        'high_risk_records': high,
        'medium_risk_records': med,
        'low_risk_records': low,
        'last_scan': last_scan_str,
        'risk_distribution': {
            'high': high,
            'medium': med,
            'low': low,
            'high_percent': round((high / total_risks * 100), 1) if total_risks > 0 else 0,
            'medium_percent': round((med / total_risks * 100), 1) if total_risks > 0 else 0,
            'low_percent': round((low / total_risks * 100), 1) if total_risks > 0 else 0
        },
        'recent_activity': recent_activity
    }

def get_leak_records(search='', risk_level='', status='', duplicates_only=False, page=1, per_page=20):
    """Retrieve leak records with search, risk, status, and duplicates filtering."""
    conn = get_connection()
    cursor = conn.cursor()

    query = 'SELECT * FROM leak_records WHERE 1=1'
    count_query = 'SELECT COUNT(*) as cnt FROM leak_records WHERE 1=1'
    params = []
    count_params = []

    if duplicates_only:
        dup_filter = ''' AND COALESCE(NULLIF(email_hash, ''), email_masked || '@' || domain) IN (
            SELECT COALESCE(NULLIF(email_hash, ''), email_masked || '@' || domain)
            FROM leak_records
            GROUP BY COALESCE(NULLIF(email_hash, ''), email_masked || '@' || domain)
            HAVING COUNT(*) > 1
        )'''
        query += dup_filter
        count_query += dup_filter

    if search:
        search_filter = ' AND (email_masked LIKE ? OR domain LIKE ? OR source LIKE ? OR record_id LIKE ?)'
        query += search_filter
        count_query += search_filter
        term = f'%{search.strip()}%'
        params.extend([term, term, term, term])
        count_params.extend([term, term, term, term])

    if risk_level and risk_level.lower() != 'all':
        query += ' AND LOWER(risk_level) = ?'
        count_query += ' AND LOWER(risk_level) = ?'
        params.append(risk_level.lower())
        count_params.append(risk_level.lower())

    if status and status.lower() != 'all':
        query += ' AND LOWER(status) = ?'
        count_query += ' AND LOWER(status) = ?'
        params.append(status.lower())
        count_params.append(status.lower())

    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()['cnt']

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    offset = (page - 1) * per_page
    params.extend([per_page, offset])

    cursor.execute(query, params)
    records = [dict(row) for row in cursor.fetchall()]
    conn.close()

    total_pages = (total_count + per_page - 1) // per_page if per_page > 0 else 1

    return {
        'records': records,
        'total': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, total_pages)
    }

def count_duplicate_records():
    """Count number of redundant duplicate records in leak_records repository."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) AS dup_count FROM leak_records
        WHERE id NOT IN (
            SELECT MIN(id) FROM leak_records
            GROUP BY COALESCE(NULLIF(email_hash, ''), email_masked || '@' || domain)
        )
    ''')
    row = cursor.fetchone()
    count = row['dup_count'] if row else 0
    conn.close()
    return count

def delete_duplicate_records():
    """
    Remove all redundant duplicate records inside a database transaction,
    retaining the primary (earliest) record for each unique credential identity.
    Returns the number of deleted records.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('BEGIN TRANSACTION')
        cursor.execute('''
            DELETE FROM leak_records
            WHERE id NOT IN (
                SELECT MIN(id) FROM leak_records
                GROUP BY COALESCE(NULLIF(email_hash, ''), email_masked || '@' || domain)
            )
        ''')
        deleted_count = cursor.rowcount
        conn.commit()
        return deleted_count
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def delete_leak_record(record_id):
    """Delete a single leak record by record_id or primary key id."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM leak_records WHERE record_id = ? OR id = ?', (record_id, record_id))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_risk_assessment_data():
    """Calculate and return comprehensive risk assessment metrics."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT 
            COUNT(*) as total_leaks,
            SUM(CASE WHEN LOWER(risk_level) = 'high' THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN LOWER(risk_level) = 'medium' THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN LOWER(risk_level) = 'low' THEN 1 ELSE 0 END) as low_risk
        FROM leak_records
    ''')
    row = cursor.fetchone()
    total_leaks = row['total_leaks'] or 0
    high_risk = row['high_risk'] or 0
    medium_risk = row['medium_risk'] or 0
    low_risk = row['low_risk'] or 0

    cursor.execute('''
        SELECT 
            SUM(CASE WHEN risk_factors LIKE '%Privileged Account%' THEN 1 ELSE 0 END) as privileged_count,
            SUM(CASE WHEN risk_factors LIKE '%Weak Password%' THEN 1 ELSE 0 END) as weak_password_count,
            SUM(CASE WHEN risk_factors LIKE '%Plaintext%' THEN 1 ELSE 0 END) as plaintext_count,
            SUM(CASE WHEN domain LIKE '%.gov%' OR domain LIKE '%.edu%' OR domain LIKE '%.internal%' THEN 1 ELSE 0 END) as critical_domain_count
        FROM leak_records
    ''')
    factors_row = cursor.fetchone()
    conn.close()

    privileged_count = factors_row['privileged_count'] or 0
    weak_pwd_count = factors_row['weak_password_count'] or 0
    plaintext_count = factors_row['plaintext_count'] or 0
    critical_domain_count = factors_row['critical_domain_count'] or 0

    if total_leaks > 0:
        base_score = ((high_risk * 1.0) + (medium_risk * 0.5) + (low_risk * 0.15)) / total_leaks * 80
        priv_penalty = min(15, privileged_count * 2.5)
        plain_penalty = min(10, (plaintext_count / total_leaks) * 10)
        overall_score = min(100.0, round(base_score + priv_penalty + plain_penalty, 1))
    else:
        overall_score = 0.0

    if overall_score >= 70:
        risk_grade = "High Risk"
        risk_color = "#EF4444"
    elif overall_score >= 35:
        risk_grade = "Medium Risk"
        risk_color = "#F59E0B"
    elif overall_score > 0:
        risk_grade = "Low Risk"
        risk_color = "#10B981"
    else:
        risk_grade = "No Threat Detected"
        risk_color = "#64748B"

    summary_points = []
    if total_leaks == 0:
        summary_points.append("No active credential leaks detected in the system.")
        summary_points.append("Upload a threat intelligence feed or breach dump to initiate threat classification.")
    else:
        summary_points.append(
            f"Evaluated {total_leaks} leaked credential records. "
            f"{high_risk} ({round((high_risk/total_leaks)*100, 1)}%) identified as High Severity."
        )
        if privileged_count > 0:
            summary_points.append(
                f"Critical Alert: {privileged_count} administrative or privileged accounts detected in leaked dumps."
            )
        if plaintext_count > 0:
            summary_points.append(
                f"Credential Exposure: {plaintext_count} records expose raw or easily crackable credentials."
            )
        if critical_domain_count > 0:
            summary_points.append(
                f"Domain Impact: {critical_domain_count} corporate or institutional domain identities compromised."
            )
        summary_points.append(
            "Recommended Action: Force immediate credential rotation and verify Multi-Factor Authentication (MFA)."
        )

    return {
        'overall_risk_score': overall_score,
        'risk_grade': risk_grade,
        'risk_color': risk_color,
        'total_records': total_leaks,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'factors': {
            'privileged_accounts': privileged_count,
            'weak_passwords': weak_pwd_count,
            'plaintext_exposure': plaintext_count,
            'critical_domains': critical_domain_count
        },
        'summary': summary_points
    }

def reset_all_data():
    """Clear all analysis scan records and leak records inside a database transaction."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('BEGIN TRANSACTION')
        cursor.execute('DELETE FROM leak_records')
        cursor.execute('DELETE FROM scans')
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Settings Operations
# --------------------------------------------------------------------------

def get_setting(key, default=''):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM system_settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else default

def get_settings():
    """Fetch settings dictionary."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM system_settings')
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    return settings

def update_setting(key, value):
    """Update a specific setting."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, str(value)))
    conn.commit()
    conn.close()
