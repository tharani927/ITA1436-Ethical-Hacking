import os
from functools import wraps
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.utils import secure_filename

import database
import analyzer
import sample_data

app = Flask(__name__)
app.secret_key = os.environ.get('DARKWATCH_SECRET_KEY', 'darkwatch_secops_secret_key_capstone_2026_fixed')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

CORS(
    app,
    supports_credentials=True,
    origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000"
    ]
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'csv', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize database on startup
database.init_db()

# Ensure sample datasets exist
sample_data.generate_sample_datasets()

# Seed database if completely empty
initial_stats = database.get_dashboard_stats()
if initial_stats['total_records_analyzed'] == 0:
    try:
        sample_data.seed_database_sample(database, analyzer)
        database.create_notification(
            "System Initialized",
            "Initial synthetic threat intelligence dataset seeded for academic research.",
            "info"
        )
    except Exception as e:
        print(f"[DarkWatch] Warning seeding sample dataset: {e}")

# --------------------------------------------------------------------------
# Authentication Decorator
# --------------------------------------------------------------------------

def get_current_user():
    """Extract user from active Flask session or Bearer token header."""
    auth_header = request.headers.get('Authorization', '')
    token = None
    if auth_header.startswith('Bearer '):
        token = auth_header[7:].strip()
    elif request.headers.get('X-Session-Token'):
        token = request.headers.get('X-Session-Token')
    
    if token:
        user_data = database.validate_session(token)
        if user_data:
            return user_data

    session_token = session.get('token')
    if session_token:
        user_data = database.validate_session(session_token)
        if user_data:
            return user_data

    return None

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({
                'success': False,
                'authenticated': False,
                'error': 'Authentication required. Please log in.'
            }), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

# --------------------------------------------------------------------------
# Authentication Routes
# --------------------------------------------------------------------------

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate administrator credentials and establish session."""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({
            'success': False,
            'error': 'Username and password are required.'
        }), 400

    valid, user = database.verify_user_credentials(username, password)
    if not valid:
        # Check login activity notification preference
        if database.get_setting('notify_login_activity', 'true') == 'true':
            database.create_notification(
                "Failed Login Attempt",
                f"Failed login attempt detected for username: '{username}'.",
                "danger"
            )
        return jsonify({
            'success': False,
            'error': 'Invalid username or password.'
        }), 401

    # Update last login timestamp
    database.update_user_last_login(user['id'])

    # Determine session duration from settings
    duration_str = database.get_setting('session_timeout', '24h')

    # Create active session
    token, expires_at = database.create_session(user['id'], duration_str=duration_str)
    session['token'] = token
    session['user_id'] = user['id']
    session['username'] = user['username']

    # Generate success notification if alert enabled
    if database.get_setting('notify_login_activity', 'true') == 'true':
        database.create_notification(
            "Login Successful",
            f"Administrator '{user['username']}' logged in successfully.",
            "success"
        )

    return jsonify({
        'success': True,
        'message': 'Login successful.',
        'token': token,
        'expires_at': expires_at,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'last_login': user.get('last_login')
        }
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Terminate administrator session."""
    user = get_current_user()
    if user and 'token' in user:
        database.delete_session(user['token'])

    session.clear()
    return jsonify({
        'success': True,
        'message': 'Logged out successfully.'
    }), 200

@app.route('/api/auth/check', methods=['GET'])
def check_auth():
    """Verify if the caller currently has an active authenticated session."""
    user = get_current_user()
    if user:
        return jsonify({
            'success': True,
            'authenticated': True,
            'user': {
                'id': user['user_id'],
                'username': user['username'],
                'role': user['role'],
                'last_login': user.get('last_login')
            }
        }), 200
    return jsonify({
        'success': False,
        'authenticated': False
    }), 401

# --------------------------------------------------------------------------
# Notification Routes
# --------------------------------------------------------------------------

@app.route('/api/notifications', methods=['GET'])
@auth_required
def get_notifications():
    """Retrieve recent notifications and unread count."""
    try:
        limit = request.args.get('limit', 25, type=int)
        data = database.get_notifications(limit=limit)
        return jsonify({'success': True, 'data': data}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/mark-read/<int:notif_id>', methods=['POST'])
@auth_required
def mark_notification_read(notif_id):
    """Mark a specific notification as read."""
    try:
        database.mark_notification_as_read(notif_id)
        return jsonify({'success': True, 'message': 'Notification marked as read.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@auth_required
def mark_all_notifications_read():
    """Mark all notifications as read."""
    try:
        database.mark_all_notifications_as_read()
        return jsonify({'success': True, 'message': 'All notifications marked as read.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/clear', methods=['POST'])
@auth_required
def clear_notifications():
    """Clear all notifications."""
    try:
        database.clear_all_notifications()
        return jsonify({'success': True, 'message': 'All notifications cleared.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --------------------------------------------------------------------------
# System & Health
# --------------------------------------------------------------------------

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'online',
        'system': 'DarkWatch Leaked Credential Intelligence System',
        'version': '1.0.0-capstone',
        'database': 'SQLite Connected'
    }), 200

# --------------------------------------------------------------------------
# Core Protected Application Endpoints
# --------------------------------------------------------------------------

@app.route('/api/dashboard', methods=['GET'])
@auth_required
def get_dashboard():
    """Retrieve dashboard statistics, recent activity, and risk distribution."""
    try:
        stats = database.get_dashboard_stats()
        return jsonify({
            'success': True,
            'data': stats
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload-and-analyze', methods=['POST'])
@auth_required
def upload_and_analyze():
    """Handle file upload and run threat intelligence analysis."""
    if 'file' not in request.files:
        database.create_notification("Upload Error", "No file provided in upload request.", "danger")
        return jsonify({'success': False, 'error': 'No file uploaded in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        database.create_notification(
            "File Processing Failed",
            f"Unsupported file format for '{file.filename}'. Use CSV or TXT.",
            "danger"
        )
        return jsonify({
            'success': False, 
            'error': 'Unsupported file format. Please upload CSV (.csv) or Text (.txt) files only.'
        }), 400

    try:
        filename = secure_filename(file.filename)
        saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(saved_path)

        # Run analysis through analyzer engine
        analysis_result = analyzer.parse_and_analyze_file(saved_path, filename)

        # Persist into database
        database.save_scan(analysis_result)
        database.save_leak_records(analysis_result['processed_records'])

        # Notify: Analysis completed (if enabled)
        if database.get_setting('notify_analysis_complete', 'true') == 'true':
            database.create_notification(
                "Analysis Completed",
                f"Analysis completed for '{filename}'. Analyzed {analysis_result['email_records']} credentials.",
                "success"
            )

        # Notify: High-risk alert (if enabled)
        if analysis_result['high_risk_count'] > 0 and database.get_setting('notify_high_risk', 'true') == 'true':
            database.create_notification(
                "High-Risk Records Detected",
                f"Identified {analysis_result['high_risk_count']} high-risk records in '{filename}'.",
                "danger"
            )

        return jsonify({
            'success': True,
            'data': {
                'scan_id': analysis_result['scan_id'],
                'filename': analysis_result['filename'],
                'file_type': analysis_result['file_type'],
                'total_records': analysis_result['total_records'],
                'email_records': analysis_result['email_records'],
                'duplicate_records': analysis_result['duplicate_records'],
                'high_risk_count': analysis_result['high_risk_count'],
                'medium_risk_count': analysis_result['medium_risk_count'],
                'low_risk_count': analysis_result['low_risk_count'],
                'overall_risk_score': analysis_result['overall_risk_score'],
                'scan_date': analysis_result['scan_date'],
                'preview_records': analysis_result['processed_records'][:10]
            }
        }), 200

    except Exception as e:
        database.create_notification(
            "File Processing Failed",
            f"Error processing file '{file.filename}': {str(e)}",
            "danger"
        )
        return jsonify({'success': False, 'error': f"Processing error: {str(e)}"}), 500

@app.route('/api/analyze-sample-file', methods=['POST'])
@auth_required
def analyze_sample_file():
    """Analyze one of the pre-loaded synthetic datasets for demonstration."""
    req_data = request.get_json() or {}
    sample_name = req_data.get('sample_name', 'synthetic_darkweb_leaks_sample.csv')
    
    file_path = os.path.join(sample_data.SAMPLE_DATASETS_DIR, sample_name)
    if not os.path.exists(file_path):
        sample_data.generate_sample_datasets()

    try:
        analysis_result = analyzer.parse_and_analyze_file(file_path, sample_name)
        database.save_scan(analysis_result)
        database.save_leak_records(analysis_result['processed_records'])

        if database.get_setting('notify_analysis_complete', 'true') == 'true':
            database.create_notification(
                "Analysis Completed",
                f"Synthetic analysis completed. {analysis_result['email_records']} credentials analyzed.",
                "success"
            )

        if analysis_result['high_risk_count'] > 0 and database.get_setting('notify_high_risk', 'true') == 'true':
            database.create_notification(
                "High-Risk Records Detected",
                f"Synthetic scan identified {analysis_result['high_risk_count']} high-risk exposures.",
                "danger"
            )

        return jsonify({
            'success': True,
            'data': {
                'scan_id': analysis_result['scan_id'],
                'filename': analysis_result['filename'],
                'file_type': analysis_result['file_type'],
                'total_records': analysis_result['total_records'],
                'email_records': analysis_result['email_records'],
                'duplicate_records': analysis_result['duplicate_records'],
                'high_risk_count': analysis_result['high_risk_count'],
                'medium_risk_count': analysis_result['medium_risk_count'],
                'low_risk_count': analysis_result['low_risk_count'],
                'overall_risk_score': analysis_result['overall_risk_score'],
                'scan_date': analysis_result['scan_date'],
                'preview_records': analysis_result['processed_records'][:10]
            }
        }), 200
    except Exception as e:
        database.create_notification(
            "File Processing Failed",
            f"Failed analyzing sample '{sample_name}': {str(e)}",
            "danger"
        )
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/leak-records', methods=['GET'])
@auth_required
def get_leak_records():
    """Retrieve filtered and paginated leak records."""
    search = request.args.get('search', '', type=str)
    risk_level = request.args.get('risk', '', type=str)
    status = request.args.get('status', '', type=str)
    duplicates_only = request.args.get('duplicates', 'false').lower() in ('true', '1')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 15, type=int)

    try:
        data = database.get_leak_records(
            search=search,
            risk_level=risk_level,
            status=status,
            duplicates_only=duplicates_only,
            page=page,
            per_page=per_page
        )
        return jsonify({
            'success': True,
            'data': data
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/leak-records/duplicates', methods=['GET'])
@auth_required
def get_duplicate_records_count():
    """Retrieve count of redundant duplicate records in the repository."""
    try:
        count = database.count_duplicate_records()
        return jsonify({
            'success': True,
            'count': count
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/leak-records/delete-duplicates', methods=['POST'])
@auth_required
def delete_duplicates():
    """Remove all redundant duplicate records across the repository in a database transaction."""
    try:
        deleted_count = database.delete_duplicate_records()
        database.create_notification(
            "Duplicate Records Cleaned",
            f"Successfully removed {deleted_count} duplicate credential records.",
            "info"
        )
        return jsonify({
            'success': True,
            'message': f"Successfully removed {deleted_count} duplicate records.",
            'deleted_count': deleted_count
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': f"Duplicate deletion failed: {str(e)}"}), 500

@app.route('/api/leak-records/<record_id>', methods=['DELETE'])
@auth_required
def delete_single_leak_record(record_id):
    """Delete a single leak record by its record_id."""
    try:
        deleted = database.delete_leak_record(record_id)
        if not deleted:
            return jsonify({'success': False, 'error': 'Record not found.'}), 404
        
        database.create_notification(
            "Record Removed",
            f"Credential record {record_id} was removed from repository.",
            "info"
        )
        return jsonify({
            'success': True,
            'message': f"Record {record_id} deleted successfully."
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/risk-assessment', methods=['GET'])
@auth_required
def get_risk_assessment():
    """Retrieve full risk assessment metrics and calculated summary."""
    try:
        assessment = database.get_risk_assessment_data()
        return jsonify({
            'success': True,
            'data': assessment
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --------------------------------------------------------------------------
# Settings Routes
# --------------------------------------------------------------------------

@app.route('/api/settings', methods=['GET'])
@auth_required
def get_app_settings():
    """Retrieve comprehensive settings for Account, Notifications, Security, and Appearance."""
    try:
        user = database.get_user_by_id(request.current_user['user_id'])
        settings = database.get_settings()
        return jsonify({
            'success': True,
            'settings': {
                'username': user['username'] if user else 'Admin',
                'last_login': user.get('last_login') if user else 'N/A',
                'theme': settings.get('theme', 'dark'),
                'notifications_enabled': settings.get('notifications_enabled', 'true') == 'true',
                'notify_high_risk': settings.get('notify_high_risk', 'true') == 'true',
                'notify_analysis_complete': settings.get('notify_analysis_complete', 'true') == 'true',
                'notify_login_activity': settings.get('notify_login_activity', 'true') == 'true',
                'session_timeout': settings.get('session_timeout', '24h')
            }
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/settings', methods=['POST'])
@auth_required
def update_app_settings():
    """Update settings for Notifications, Security, and Appearance."""
    data = request.get_json() or {}

    # Only allow whitelisted configuration keys (application name cannot be changed)
    allowed_keys = [
        'theme',
        'notifications_enabled',
        'notify_high_risk',
        'notify_analysis_complete',
        'notify_login_activity',
        'session_timeout'
    ]

    for key in allowed_keys:
        if key in data:
            database.update_setting(key, str(data[key]).lower() if isinstance(data[key], bool) else str(data[key]))

    return jsonify({'success': True, 'message': 'Settings saved successfully.'}), 200

@app.route('/api/settings/password', methods=['POST'])
@auth_required
def change_password():
    """Change administrator password."""
    data = request.get_json() or {}
    new_password = data.get('new_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()

    if not new_password or not confirm_password:
        return jsonify({'success': False, 'error': 'Both password fields are required.'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters.'}), 400

    if new_password != confirm_password:
        return jsonify({'success': False, 'error': 'Passwords do not match.'}), 400

    try:
        user_id = request.current_user['user_id']
        database.update_admin_password(user_id, new_password)
        database.create_notification(
            "Security Alert",
            "Administrator account password was successfully updated.",
            "info"
        )
        return jsonify({'success': True, 'message': 'Password updated successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/settings/reset-data', methods=['POST'])
@app.route('/api/reset-data', methods=['POST'])
@auth_required
def reset_data():
    """Reset all uploaded dataset records and analysis scans in a transaction."""
    try:
        database.reset_all_data()

        # Clean any uploaded temporary files in backend/uploads without touching datasets/
        upload_dir = app.config['UPLOAD_FOLDER']
        if os.path.exists(upload_dir):
            for fname in os.listdir(upload_dir):
                fpath = os.path.join(upload_dir, fname)
                if os.path.isfile(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

        # Generate notification for security audit if enabled
        database.create_notification(
            "Data Reset",
            "Application analysis data and scan history were reset by Administrator.",
            "warning"
        )
        return jsonify({
            'success': True,
            'message': 'Application data has been reset successfully.'
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': f"Reset failed: {str(e)}"}), 500

if __name__ == '__main__':
    print("[DarkWatch] Starting DarkWeb Monitoring & Credential Intelligence REST API on port 5000...")
    app.run(host='127.0.0.1', port=5000, debug=False)
