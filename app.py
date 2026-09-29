import csv
import io
import json
import sys
from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify
from tracker import init_db, record_login_attempt, get_recent_logs, get_log_analytics, get_risk_distribution, get_hourly_activity

app = Flask(__name__)
app.secret_key = 'super-secret-security-admin-key-2026'
app.url_map.strict_slashes = False

# Initialize SQLite database & ML model on startup
init_db()

REGULAR_USERS = {
    'user1': 'user123',
    'admin': '1234'
}

ADMIN_USERS = {
    'security_admin': 'AdminSecure@2026'
}

def get_client_ip():
    """Extract client IP address, handling X-Forwarded-For headers if behind a proxy."""
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr

# --- PORTAL 1: USER LOGIN PORTAL ---

@app.route('/', methods=['GET'])
def index():
    return render_template('login.html', message=None, status=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return redirect(url_for('index'))
        
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # Check regular user authentication
    if username in REGULAR_USERS and REGULAR_USERS[username] == password:
        status = "SUCCESS"
        message = f"Login Successful! Welcome {username}"
    else:
        status = "FAILED"
        message = "Invalid Credentials"
        
    # Record attempt via Activity Tracker Module (extracts features, predicts ML risk, triggers alert if High Risk)
    record_login_attempt(username, ip_address, user_agent, status)

    return render_template('login.html', message=message, status=status)

# --- PORTAL 2: SECURITY ADMIN PORTAL (PROTECTED) ---

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if username in ADMIN_USERS and ADMIN_USERS[username] == password:
            session['admin_logged_in'] = True
            session['admin_user'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error="Invalid Admin Credentials")
            
    return render_template('admin_login.html', error=None)

@app.route('/admin-logout', methods=['GET'])
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_user', None)
    return redirect(url_for('admin_login'))

@app.route('/admin', methods=['GET'])
@app.route('/dashboard', methods=['GET'])
def admin_dashboard():
    # Enforce admin authentication session check
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
        
    username_filter = request.args.get('username', '')
    risk_filter = request.args.get('risk_level', 'All')
    status_filter = request.args.get('status', 'All')

    filters = {
        'username': username_filter,
        'risk_level': risk_filter,
        'status': status_filter
    }

    # Fetch logs with filters
    logs = get_recent_logs(
        limit=50,
        username_filter=username_filter,
        risk_filter=risk_filter,
        status_filter=status_filter
    )
    
    # Compute analytics
    analytics = get_log_analytics()
    risk_dist = get_risk_distribution()
    hourly_data = get_hourly_activity()
    
    # Check if any attempt is flagged as High Risk
    high_risk_detected = any(log.get('risk_level') == 'High Risk' for log in logs)
    
    return render_template('admin.html', records=logs, analytics=analytics, filters=filters, high_risk_detected=high_risk_detected, risk_dist=risk_dist, hourly_data=hourly_data)

@app.route('/admin/api/stats', methods=['GET'])
def admin_api_stats():
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    logs = get_recent_logs(limit=50)
    analytics = get_log_analytics()
    risk_dist = get_risk_distribution()
    hourly_data = get_hourly_activity()
    high_risk_detected = any(log.get('risk_level') == 'High Risk' for log in logs)
    return jsonify({
        'analytics': analytics,
        'risk_distribution': risk_dist,
        'hourly_data': hourly_data,
        'high_risk_detected': high_risk_detected,
        'logs': logs
    })

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    import time
    for i in range(1, 6):
        record_login_attempt(f"simulated_attacker_{i}", f"192.168.1.{10+i}", "CyberAttackSimulator/1.0", "FAILED")
        time.sleep(0.1)
    return jsonify({'status': 'attack_simulated', 'count': 5, 'high_risk_flagged': True})

# --- DATA EXPORT ENDPOINTS (Phase 5 & 6) ---

@app.route('/admin/export', methods=['GET'])
def export_logs():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    export_format = request.args.get('format', 'csv').lower()
    logs = get_recent_logs(limit=500)

    if export_format == 'json':
        json_output = json.dumps(logs, indent=2)
        return Response(
            json_output,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=login_logs_export.json'}
        )
    else:
        # Default CSV export
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Username', 'IP Address', 'User Agent', 'Status', 'Timestamp (UTC)', 'Features (JSON)', 'Risk Level'])
        
        for log in logs:
            writer.writerow([
                log.get('id'),
                log.get('username'),
                log.get('ip_address'),
                log.get('user_agent'),
                log.get('status'),
                log.get('timestamp'),
                log.get('features', '[]'),
                log.get('risk_level')
            ])
            
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=login_logs_export.csv'}
        )

@app.route('/activity', methods=['GET'])
def activity():
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
