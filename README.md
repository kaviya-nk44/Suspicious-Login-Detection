# AI-Based Suspicious Login Pattern Detection and Alert System - Phase 2

This repository contains Phase 2 of the Suspicious Login Pattern Detection system, featuring a dedicated activity tracking module (`tracker.py`) and persistent SQLite logging (`login_logs` schema) to prepare data for downstream ML feature extraction.

## Project Structure

```text
Suspicious-Login-Detection/
├── app.py              # Main Flask web application & routes
├── tracker.py          # Dedicated activity tracking & database module
├── requirements.txt    # Python dependencies (Flask)
├── README.md           # Documentation
├── login_activity.db   # Local SQLite database
├── static/
│   └── style.css       # Responsive UI styles & table badges
└── templates/
    ├── login.html      # User login form
    └── activity.html   # Recent login logs table UI (Phase 2)
```

## Database Schema (`login_logs` table)

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER` | Primary Key (Auto-increment) |
| `username` | `TEXT` | Username submitted in login form |
| `ip_address` | `TEXT` | Extracted client IP (`X-Forwarded-For` or `remote_addr`) |
| `user_agent` | `TEXT` | Browser/Client User-Agent header string |
| `status` | `TEXT` | Authentication outcome (`SUCCESS` / `FAILED`) |
| `timestamp` | `TEXT` | Auto-populated UTC DateTime (`YYYY-MM-DD HH:MM:SS`) |
| `risk_level` | `TEXT` | Default risk classification (`PENDING`) |

## Setup & Running

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Flask Application**
   ```bash
   python app.py
   ```
   The server runs at [http://127.0.0.1:5000](http://127.0.0.1:5000).

3. **Terminal Write Log Format**
   Each attempt produces an instant, thread-safe write log entry in the terminal:
   ```text
   [LOG STORED] User: admin | IP: 127.0.0.1 | Status: SUCCESS
   ```

4. **View Activity Logs**
   Open [http://127.0.0.1:5000/activity](http://127.0.0.1:5000/activity) to view the last 50 login attempts with color-coded status badges.
