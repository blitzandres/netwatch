# NetWatch — Changes Log

## Environment Requirements

**Required (standard on macOS):**
- sudo privileges (for tcpdump + pfctl)
- Python 3.8+
- pip install flask psutil (handled by launch.sh)

**Optional for new features:**
- pip install gspread google-auth  — Google Sheets export
- sqlite3 is built into Python, no install needed

## Backend Changes (app.py)

### Bug Fixes
- Fixed intrusion_worker and api_topology_data: packet keys corrected from src_ip/dst_ip to src/dst. Intrusion detection and Network Map now work.
- Fixed dns_benchmark: runs async instead of blocking Flask thread.

### SQLite Persistence (30-Day History)
- Creates ~/netwatch_logs/netwatch.db on startup
- Tables: traffic_history, threat_log, dns_log_persist
- history_flusher now inserts into SQLite on each hourly flush
- Records older than 30 days auto-deleted daily
- New: GET /api/history_30d — last 30 days grouped by day
- New: GET /api/export_csv — CSV download of last 30 days

### Google Sheets Export
- New: POST /api/export_google_sheets
- Accepts: {credentials_path, sheet_id}
- Returns helpful error if gspread not installed

### Frequent IP Store
- frequent_ips dict persisted to ~/netwatch_logs/frequent_ips.json
- Auto-populates IPs seen 10+ times
- GET/POST/DELETE /api/frequent_ips endpoints

### History Deque
- history_buckets: deque(168) -> deque(720) for 30-day RAM cache

## Frontend Changes (static/index.html)

### IP Dropdowns
Replaced text inputs with smart dropdowns on:
- IP Reputation, Block/Trust, Port Scanner, Traceroute,
  SSL Inspector, Ping Watchdog, Host Discovery

Each has a Custom option that reveals the original text input.

### New Functions
- ipSelChange(inputId, selId) — dropdown show/hide logic
- loadFrequentIPs() — populates all freq-ip-sel dropdowns
- exportGoogleSheets() — calls export API with modal inputs

### New: 30-Day History Panel (Analyze section)
- Total GB used, Chart.js bar chart, export buttons, data table

### New: IP Book Panel (Tools section)
- Table of saved IPs with one-click action buttons per row

### Navigation
- history30 and ipbook added to routing arrays
