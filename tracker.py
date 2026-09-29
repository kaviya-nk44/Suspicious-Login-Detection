import json
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from model import predict_risk_level
from alerts import send_admin_alert

DB_NAME = 'login_activity.db'

def init_db():
    """Initialize SQLite database, ensuring login_logs table and features column exist."""
    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    features TEXT NOT NULL DEFAULT '[]',
                    risk_level TEXT NOT NULL DEFAULT 'PENDING'
                )
            ''')
            
            # Ensure features column exists in case table was created previously
            cursor.execute("PRAGMA table_info(login_logs)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'features' not in columns:
                cursor.execute("ALTER TABLE login_logs ADD COLUMN features TEXT NOT NULL DEFAULT '[]'")
                
            conn.commit()
    except sqlite3.Error as e:
        print(f"[DB ERROR] Database initialization failed: {e}", file=sys.stderr, flush=True)

def extract_features(username, current_ip):
    """
    Extract 5 behavioral security features for a login attempt:
    1. login_hour: UTC Hour (0-23)
    2. failed_attempts: Count of failed logins for username in last 15 mins
    3. login_frequency: Total login attempts count in last 5 mins
    4. ip_changed: 1 if current IP differs from user's last successful IP, else 0
    5. time_gap: Seconds elapsed since immediate prior attempt for username
    """
    clean_username = username.strip() if username else 'Unknown'
    clean_ip = current_ip.strip() if current_ip else 'Unknown'
    
    now_utc = datetime.now(timezone.utc)
    login_hour = now_utc.hour
    
    fifteen_mins_ago = (now_utc - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    five_mins_ago = (now_utc - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            cursor = conn.cursor()
            
            # 1. Count failed attempts for username in last 15 mins
            cursor.execute('''
                SELECT COUNT(*) FROM login_logs
                WHERE username = ? AND status = 'FAILED' AND timestamp >= ?
            ''', (clean_username, fifteen_mins_ago))
            failed_attempts = cursor.fetchone()[0]
            
            # 2. Count total login attempts in last 5 mins
            cursor.execute('''
                SELECT COUNT(*) FROM login_logs
                WHERE timestamp >= ?
            ''', (five_mins_ago,))
            login_frequency = cursor.fetchone()[0] + 1
            
            # 3. Check if IP changed compared to last successful login
            cursor.execute('''
                SELECT ip_address FROM login_logs
                WHERE username = ? AND status = 'SUCCESS'
                ORDER BY id DESC LIMIT 1
            ''', (clean_username,))
            last_success_row = cursor.fetchone()
            if last_success_row and last_success_row[0] != clean_ip:
                ip_changed = 1
            else:
                ip_changed = 0
                
            # 4. Compute time gap in seconds since immediate prior attempt
            cursor.execute('''
                SELECT timestamp FROM login_logs
                WHERE username = ?
                ORDER BY id DESC LIMIT 1
            ''', (clean_username,))
            prior_row = cursor.fetchone()
            if prior_row:
                try:
                    prior_dt = datetime.strptime(prior_row[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    time_gap = int((now_utc - prior_dt).total_seconds())
                    time_gap = max(0, time_gap)
                except Exception:
                    time_gap = 9999
            else:
                time_gap = 9999
    except Exception as e:
        print(f"[FEATURE ERROR] Feature extraction error: {e}", file=sys.stderr, flush=True)
        login_hour = now_utc.hour
        failed_attempts = 0
        login_frequency = 1
        ip_changed = 0
        time_gap = 9999

    return [login_hour, failed_attempts, login_frequency, ip_changed, time_gap]

def record_login_attempt(username, ip_address, user_agent, status):
    """
    Extract features, evaluate ML risk prediction, store attempt in database,
    trigger urgent alert if High Risk, and output formatted console log.
    """
    clean_username = username.strip() if username else 'Unknown'
    clean_ip = ip_address.strip() if ip_address else 'Unknown'
    clean_user_agent = user_agent.strip() if user_agent else 'Unknown'
    clean_status = 'SUCCESS' if str(status).upper() == 'SUCCESS' else 'FAILED'
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Phase 3: Extract features
    features = extract_features(clean_username, clean_ip)
    features_json = json.dumps(features)

    # Phase 4: Predict ML Risk Level
    risk_level = predict_risk_level(features)

    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_logs (username, ip_address, user_agent, status, timestamp, features, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (clean_username, clean_ip, clean_user_agent, clean_status, timestamp_utc, features_json, risk_level))
            conn.commit()
            
        print(f"[SECURITY EVENT] User: {clean_username} | Status: {clean_status} | Features: {features} | ML Risk: {risk_level}", flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
    except sqlite3.Error as e:
        print(f"[LOG ERROR] Failed to store login attempt: {e}", file=sys.stderr, flush=True)

    # Phase 7: Real-Time High-Risk Alert Trigger
    if risk_level == 'High Risk':
        send_admin_alert(
            username=clean_username,
            ip_address=clean_ip,
            timestamp=timestamp_utc,
            risk_level=risk_level,
            reason=f"Brute Force / Anomaly Pattern Detected (Features: {features})"
        )

    return risk_level

def get_recent_logs(limit=50, username_filter=None, risk_filter=None, status_filter=None):
    """Retrieve recent login logs ordered by timestamp/id DESC with optional filtering."""
    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT id, username, ip_address, user_agent, status, timestamp, features, risk_level FROM login_logs WHERE 1=1"
            params = []
            
            if username_filter:
                query += " AND username LIKE ?"
                params.append(f"%{username_filter.strip()}%")
            if risk_filter and risk_filter.upper() != 'ALL':
                query += " AND risk_level = ?"
                params.append(risk_filter.strip())
            if status_filter and status_filter.upper() != 'ALL':
                query += " AND status = ?"
                params.append(status_filter.strip().upper())
                
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"[LOG ERROR] Failed to fetch recent logs: {e}", file=sys.stderr, flush=True)
        return []

def get_log_analytics():
    """Compute summary analytics for the Security Admin Dashboard."""
    analytics = {
        'total_attempts': 0,
        'successful_logins': 0,
        'failed_logins': 0,
        'high_risk_incidents': 0
    }
    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM login_logs")
            analytics['total_attempts'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'SUCCESS'")
            analytics['successful_logins'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM login_logs WHERE status = 'FAILED'")
            analytics['failed_logins'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk_level = 'High Risk'")
            analytics['high_risk_incidents'] = cursor.fetchone()[0]
    except sqlite3.Error as e:
        print(f"[ANALYTICS ERROR] Failed to compute analytics: {e}", file=sys.stderr, flush=True)

    return analytics

def get_risk_distribution():
    """Count records by risk level (Normal, Suspicious, High Risk)."""
    dist = {'Normal': 0, 'Suspicious': 0, 'High Risk': 0}
    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT risk_level, COUNT(*) FROM login_logs GROUP BY risk_level")
            for row in cursor.fetchall():
                if row[0] in dist:
                    dist[row[0]] = row[1]
    except Exception as e:
        print(f"[DIST ERROR] Error computing risk distribution: {e}", file=sys.stderr, flush=True)
    return dist

def get_hourly_activity():
    """Get total and failed login counts grouped by hour of day (0-23)."""
    hours = [f"{i:02d}:00" for i in range(24)]
    total_counts = [0] * 24
    failed_counts = [0] * 24
    try:
        with sqlite3.connect(DB_NAME, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, status FROM login_logs")
            for row in cursor.fetchall():
                try:
                    dt = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                    h = dt.hour
                    total_counts[h] += 1
                    if row[1] == 'FAILED':
                        failed_counts[h] += 1
                except Exception:
                    pass
    except Exception as e:
        print(f"[HOURLY ERROR] Error computing hourly activity: {e}", file=sys.stderr, flush=True)

    return {
        'labels': hours,
        'total': total_counts,
        'failed': failed_counts
    }
