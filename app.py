import sys 
import os 
import json
import sqlite3
import csv
import io
from flask import Flask, render_template_string, request, Response

# ==========================================
# 🚀 1. BULLETPROOF WORKSPACE PATH RESOLUTION
# ==========================================
ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
if ROOT_PATH not in sys.path:
    sys.path.insert(0, ROOT_PATH)

# Inject path inclusion mappings to bypass relative lookup anomalies
sys.path.insert(0, os.path.join(ROOT_PATH, "correlation"))
sys.path.insert(0, os.path.join(ROOT_PATH, "timeline"))
sys.path.insert(0, os.path.join(ROOT_PATH, "ai"))
sys.path.insert(0, os.path.join(ROOT_PATH, "report"))

import ollama
import correlation
import ollama_client

# ✅ CORE GENERATOR IMPORTS - FLUSH COMPLETELY TO THE LEFT MARGIN (ZERO SPACES)
from correlation import parse_and_correlate_raw_telemetry, load_mitre_mapping
from builder import generate_visual_narrative
from report_generator import build_forensic_html_report


reconvec_app = Flask(__name__)
reconvec_app.secret_key = "reconvec_secure_system_key"

# ==========================================
# 🎨 2. CENTRAL JINJA2 HTML TEMPLATE CODES
# ==========================================

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>RECONVEC-AI</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; }
        .container { max-width: 800px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #1e3a8a; }
        textarea { width: 100%; height: 120px; padding: 10px; margin: 15px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { background-color: #1e3a8a; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .result { background-color: #f8fafc; padding: 20px; border-left: 4px solid #1e3a8a; margin-top: 20px; white-space: pre-wrap; font-family: monospace; text-align: left;}
        .nav-links { margin-top: 15px; }
        .nav-links a { color: #1e3a8a; text-decoration: none; font-weight: bold; margin-right: 15px;}
    </style>
</head>
<body>
    <div class="container">
        <h1>RECONVEC-AI</h1>
        <p style="color: #64748b;">Local Security Log Analyzer Active</p>
        <div class="nav-links">
            <a href="/">📥 Live Parser</a>
            <a href="/view_db">🛡️ Enterprise Dashboard</a>
        </div>
        <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;">
        <form method="POST">
            <label><b>Paste your Security Logs here:</b></label>
            <textarea name="user_prompt" placeholder="e.g., Jan 12 02:45:10 server1 sshd: Failed password for invalid user admin from 192.168.1.50"></textarea>
            <button type="submit">Analyze & Ingest Log with Llama 3.2</button>
        </form>
        {% if response %}
        <div class="result">
            <h3>🔍 Processing Response Matrix:</h3>
            <p>{{ response }}</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RECONVEC-AI Enterprise Threat Intelligence Console</title>
    <!-- Load Chart.js for High-Fidelity Data Visualizations -->
    <script src="https://jsdelivr.net"></script>
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-card: #131a26;
            --border-color: #1f293d;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --cyan-accent: #38bdf8;
            --purple-accent: #a855f7;
            --critical-red: #ef4444;
            --high-orange: #f97316;
            --medium-yellow: #eab308;
            --low-green: #10b981;
        }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 30px; 
            background-color: var(--bg-main); 
            color: var(--text-primary); 
            text-align: left;
        }
        .top-navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 15px;
            margin-bottom: 30px;
        }
        .app-branding h1 { margin: 0; color: var(--cyan-accent); font-size: 26px; font-weight: 800; letter-spacing: 0.5px; }
        .app-branding p { margin: 4px 0 0 0; color: var(--text-secondary); font-size: 13px; }
        .system-status { display: flex; gap: 15px; font-size: 12px; }
        .status-pill { background: #1e293b; padding: 4px 10px; border-radius: 20px; border: 1px solid var(--border-color); font-weight: bold;}
        .analytics-charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }
        .chart-container-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            height: 260px;
        }
        .chart-title { font-size: 12px; text-transform: uppercase; font-weight: bold; color: var(--text-secondary); letter-spacing: 1px; margin-bottom: 15px; border-left: 3px solid var(--cyan-accent); padding-left: 8px;}
        .control-console-box {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        .search-input-field {
            flex: 1;
            min-width: 250px;
            background: var(--bg-main);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 15px;
            border-radius: 6px;
            font-size: 14px;
        }
        .filter-dropdown-select {
            background: var(--bg-main);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px;
            border-radius: 6px;
            font-size: 14px;
            cursor: pointer;
        }
        .nav-action-btn {
            background: var(--cyan-accent);
            color: #000;
            padding: 10px 20px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            font-size: 14px;
            transition: opacity 0.2s;
        }
        .soc-footer {
            margin-top: 50px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="top-navbar">
        <div class="app-branding">
            <h1>RECONVEC-AI Enterprise Threat Monitoring Console</h1>
            <p>Autonomous Forensics & Advanced Incident Attack Chain Synthesis Engine</p>
        </div>
        <div class="system-status">
            <span class="status-pill" style="color: var(--low-green);">● SIEM CORE: ACTIVE</span>
            <span class="status-pill" style="color: var(--cyan-accent);">OLLAMA LLM: READY</span>
            <span class="status-pill">VERSION: 2.1.0</span>
        </div>
    </div>

    <div class="analytics-charts-grid">
        <div class="chart-container-card">
            <div class="chart-title">MITRE ATTACK Tactic Frequency Distribution</div>
            <div style="height: 200px; width: 100%; position: relative;">
                <canvas id="mitreTacticChart"></canvas>
            </div>
        </div>
        <div class="chart-container-card">
            <div class="chart-title">Incident Severity Breakdown Indicators</div>
            <div style="height: 200px; width: 100%; position: relative;">
                <canvas id="severityPieChart"></canvas>
            </div>
        </div>
    </div>

    <div class="control-console-box">
        <input type="text" id="dashboardSearch" class="search-input-field" placeholder="Search parameters across: Host, User, IP, Variant, or Event Type..." onkeyup="executeClientSideFilter()">
        <select id="severityFilter" class="filter-dropdown-select" onchange="executeClientSideFilter()">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
        </select>
        <a href="/" class="nav-action-btn" style="background:#1e293b; color:var(--text-primary); border:1px solid var(--border-color);">Open Live Parser</a>
    </div>

 <form method="GET" action="/view_db" class="control-console-box" style="display: flex; flex-wrap: wrap; gap: 15px; width: 100%; box-sizing: border-box;">
        
        <!-- Step 5: Master Query String Input Field -->
        <input type="text" name="search" class="search-input-field" value="{{ search_val }}" placeholder="Search by IP, Username, MITRE ID, Date, or Message...">
        
        <!-- Step 6: Severity Dropdown -->
        <select name="severity" class="filter-dropdown-select">
            <option value="ALL" {% if sev_val == 'ALL' %}selected{% endif %}>All Severities</option>
            <option value="CRITICAL" {% if sev_val == 'CRITICAL' %}selected{% endif %}>Critical</option>
            <option value="HIGH" {% if sev_val == 'HIGH' %}selected{% endif %}>High</option>
            <option value="MEDIUM" {% if sev_val == 'MEDIUM' %}selected{% endif %}>Medium</option>
            <option value="LOW" {% if sev_val == 'LOW' %}selected{% endif %}>Low</option>
        </select>

        <!-- Step 6: OS Framework Platform Dropdown -->
        <select name="os" class="filter-dropdown-select">
            <option value="ALL" {% if os_val == 'ALL' %}selected{% endif %}>All Host Platforms</option>
            <option value="LINUX" {% if os_val == 'LINUX' %}selected{% endif %}>Linux Servers</option>
            <option value="WINDOWS" {% if os_val == 'WINDOWS' %}selected{% endif %}>Windows Enterprise</option>
        </select>

        <!-- Step 6: Ingress Service App Vector Dropdown -->
        <select name="service" class="filter-dropdown-select">
            <option value="ALL" {% if svc_val == 'ALL' %}selected{% endif %}>All Vectors</option>
            <option value="SSH" {% if svc_val == 'SSH' %}selected{% endif %}>SSH Remote Logins</option>
            <option value="APACHE" {% if svc_val == 'APACHE' %}selected{% endif %}>Apache / Web Exploits</option>
        </select>

        <button type="submit" class="nav-action-btn" style="border: none; cursor: pointer;">🔍 Filter Metrics</button>
        <a href="/view_db" class="nav-action-btn" style="background:#1e293b; color:#f8fafc; border:1px solid #1f293d; text-align:center; padding-top:10px; height:20px;">Reset</a>
        
        <!-- Step 8: Global Database Exfiltration Toolbars -->
        <div style="margin-left: auto; display: flex; gap: 10px;">
            <a href="/export/db/json" class="nav-action-btn" style="background: #0284c7; color: white;">📥 Dump DB JSON</a>
            <a href="/export/db/csv" class="nav-action-btn" style="background: #0284c7; color: white;">📊 Dump DB CSV</a>
            <!-- Step 7: Clear Database Action Controller Trigger -->
            <button type="button" onclick="executeGlobalPurgeEngine()" class="nav-action-btn" style="background: var(--critical-red); color: white; border: none; cursor: pointer;">⚠️ Clear DB</button>
        </div>
    </form>
 
 
    <div id="incidentsGridContainer">
        {{ visual_timeline_html|safe }}
    </div>

    <div class="soc-footer">
        Powered by <strong>Ollama Local Inference Server (Llama 3.2:1b Engine)</strong> | Controlled Environment Research Framework<br>
        &copy; 2026 RECONVEC-AI Project Lab | Security Analytics Pipeline Operational
    </div>

    <script>
        document.addEventListener("DOMContentLoaded", function() {
            const tacticLabels = [];
            const tacticCounts = [];
            {% for tactic, count in tactic_stats.items() %}
                tacticLabels.push("{{ tactic }}");
                tacticCounts.push({{ count }});
            {% endfor %}

            new Chart(document.getElementById('mitreTacticChart'), {
                type: 'bar',
                data: {
                    labels: tacticLabels,
                    datasets: [{
                        label: 'Aggregated Detections',
                        data: tacticCounts,
                        backgroundColor: '#38bdf8',
                        borderColor: '#0284c7',
                        borderWidth: 1,
                        borderRadius: 4
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: '#1f293d' }, ticks: { color: '#94a3b8' } },
                        y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                    }
                }
            });

            let critical = 0, high = 0, medium = 0, low = 0;
            const elements = document.querySelectorAll('[data-severity-rank]');
            elements.forEach(el => {
                const sev = el.getAttribute('data-severity-rank');
                if(sev === 'CRITICAL') critical++;
                else if(sev === 'HIGH') high++;
                else if(sev === 'MEDIUM') medium++;
                else if(sev === 'LOW') low++;
            });

            new Chart(document.getElementById('severityPieChart'), {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [critical, high, medium, low],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#10b981'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 12 } } } },
                    cutout: '70%'
                }
            });
        });

        function executeClientSideFilter() {
            const query = document.getElementById('dashboardSearch').value.toLowerCase();
            const selectedSeverity = document.getElementById('severityFilter').value;
            const incidentCards = document.querySelectorAll('[data-incident-card]');

            incidentCards.forEach(card => {
                const contentText = card.textContent.toLowerCase();
                const cardSeverity = card.getAttribute('data-severity-rank');
                const matchesSearch = contentText.includes(query);
                const matchesSeverity = (selectedSeverity === 'ALL' || cardSeverity === selectedSeverity);

                if (matchesSearch && matchesSeverity) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function toggleLogEventDetailsBlock(containerId) {
            const block = document.getElementById(containerId);
            if(block.style.display === 'none') {
                block.style.display = 'block';
            } else {
                block.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""

# ==========================================
# 🛠️ 3. CORE FLASK ROUTING MODULES
# ==========================================

@reconvec_app.route('/', methods=['GET', 'POST'])
def home():
    ai_response = ""
    if request.method == 'POST':
        raw_input_block = request.form.get('user_prompt', '')
        log_lines = [line.strip() for line in raw_input_block.split('\n') if line.strip()]
        
        success_count = 0
        parsed_nodes = []
        
        # Connect once globally to prepare enhanced transactional storage schemas
        conn = sqlite3.connect("reconvec.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS normalized_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                host TEXT,
                source_ip TEXT,
                destination_host TEXT,
                username TEXT,
                event_type TEXT,
                severity TEXT,
                log_source TEXT,
                raw_log TEXT,
                normalized BOOLEAN
            )
        """)
        conn.commit()
        conn.close()
        
        for single_log in log_lines:
            try:
                response = ollama.generate(
                    model='llama3.2:1b',
                    format='json',
                    prompt=(
                        f"Analyze this raw log entry string: '{single_log}'.\n"
                        f"Extract variables and return a flat JSON object with these exact keys:\n"
                        f"- 'timestamp': Formatted as 'YYYY-MM-DD HH:MM:SS'. Default year: 2026.\n"
                        f"- 'host': The targeted system name identifier string.\n"
                        f"- 'source_ip': The source network connection IP.\n"
                        f"- 'destination_host': The target machine name receiving the log alert.\n"
                        f"- 'username': Account identity string.\n"
                        f"- 'event_type': Classify as: 'SSH Login Failed', 'SSH Login Success', or 'Sudo Privilege Escalation'.\n"
                        f"- 'severity': Assign 'Low', 'Medium', 'High', or 'Critical' based on threat level.\n"
                        f"- 'log_source': Logging daemon category name (e.g., 'SSH' or 'Sudo').\n\n"
                        f"Return only the raw JSON. Do not include markdown code fence wrappers or trailing characters."
                    )
                )
                
                raw_json = response['response'].strip()
                parsed_data = json.loads(raw_json)
                
                # Dynamic validation check for date extraction integrity
                extracted_ts = str(parsed_data.get('timestamp', '')).strip()
                if len(extracted_ts) < 19 or "-" not in extracted_ts or ":" not in extracted_ts:
                    from datetime import datetime
                    extracted_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Database transaction execution binding matching target schema layout
                conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "reconvec.db"))
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO normalized_events (timestamp, host, source_ip, destination_host, username, event_type, severity, log_source, raw_log, normalized)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    extracted_ts,
                    parsed_data.get('host', 'Prod-Server-01'),
                    parsed_data.get('source_ip', '172.16.5.4'),
                    parsed_data.get('destination_host', parsed_data.get('host', 'Prod-Server-01')),
                    parsed_data.get('username', 'unknown'),
                    parsed_data.get('event_type', 'Unclassified Alert'),
                    parsed_data.get('severity', 'Medium'),
                    parsed_data.get('log_source', 'SSH'),
                    single_log,
                    True
                ))
                
                # Capture generated row primary key id number
                generated_id = cursor.lastrowid
                conn.commit()
                conn.close()
                
                # Standardize payload object layout arrays to match destination design models
                formatted_node = {
                    "event_id": generated_id,
                    "timestamp": extracted_ts,
                    "host": parsed_data.get('host', 'Prod-Server-01'),
                    "source_ip": parsed_data.get('source_ip', '172.16.5.4'),
                    "destination_host": parsed_data.get('destination_host', parsed_data.get('host', 'Prod-Server-01')),
                    "username": parsed_data.get('username', 'unknown'),
                    "event_type": parsed_data.get('event_type', 'Unclassified Alert'),
                    "severity": parsed_data.get('severity', 'Medium'),
                    "log_source": parsed_data.get('log_source', 'SSH'),
                    "raw_log": single_log,
                    "normalized": True
                }
                
                success_count += 1
                parsed_nodes.append(formatted_node)
                
            except Exception as e:
                print(f"Ingestion extraction failure row skip details: {str(e)}")
                continue
                
        if success_count > 0:
            ai_response = f"✅ SUCCESS: {success_count} log entries normalized and written to database!\n\n" + json.dumps(parsed_nodes, indent=4)
        else:
            ai_response = "❌ Ingestion Pipeline Error: Processing failed across log input arrays."
            
    return render_template_string(INDEX_TEMPLATE, response=ai_response)
    
reconvec_app.route('/view_db')
def view_database():
    search_query = request.args.get('search', '').strip()
    severity_filter = request.args.get('severity', 'ALL').strip()
    host_os_filter = request.args.get('os', 'ALL').strip()  
    service_filter = request.args.get('service', 'ALL').strip() 

    try:
        import sqlite3
        conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "reconvec.db"))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS normalized_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                host TEXT,
                source_ip TEXT,
                destination_host TEXT,
                username TEXT,
                event_type TEXT,
                severity TEXT,
                log_source TEXT,
                raw_log TEXT,
                normalized BOOLEAN
            )
        """)
        conn.commit()
        conn.close()
        pipeline_data = correlation.load_and_group_events("reconvec.db")
        
        incident_data = pipeline_data.get("incidents", {})
        tactic_stats = pipeline_data.get("statistics", {})
        
        # 🧠  Advanced Context Orchestration Loop
        # Compiles natural language explanations for every identified threat vector
        ai_narratives_map = {}
        for inc_id, info in incident_data.items():
            explanation, duration, status = ollama_client.get_ai_incident_explanation(
                incident_id=inc_id,
                classification=info.get('classification', 'Custom Threat Vector'),
                events=info.get('events', []),
                host=info.get('host', 'Unknown Asset'),
                risk_score=info.get('risk_score', 0),
                confidence_score=info.get('confidence_score', 0),
                db_path="reconvec.db"
            )
            ai_narratives_map[inc_id] = {
                "text": explanation,
                "duration": duration,
                "status": status
            }
        
        # Build Day 10 Upgraded High-Fidelity Visual Timelines passing the AI mapping array
        visual_timeline_html = generate_visual_narrative(incident_data, ai_narratives_map)
        
    except Exception as e:
        tactic_stats = {"Database Connection Error": str(e)}
        visual_timeline_html = f"<p style='color:red;'>Timeline Failure: {str(e)}</p>"

    return render_template_string(
        DASHBOARD_TEMPLATE, 
        tactic_stats=tactic_stats,
        visual_timeline_html=visual_timeline_html
    )
# ==========================================
# 📥 4. PROGRAMMATIC ADVANCED FORENSIC EXPORTS
# ==========================================

@reconvec_app.route('/export/json/<host_id>')
def export_incident_json(host_id):
    """Programmatic Export Component: Pulls structured incident profiles to JSON downloads."""
    pipeline_data = load_and_group_events("reconvec.db")
    incidents = pipeline_data.get("incidents", {})
    
    target_data = {}
    for inc_id, data in incidents.items():
        if data["host"] == host_id:
            target_data[inc_id] = data
            
    return Response(
        json.dumps(target_data, indent=4),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename=RECONVEC_INCIDENT_{host_id}.json'}
    )

@reconvec_app.route('/export/csv/<host_id>')
def export_incident_csv(host_id):
    """Programmatic Export Component: Formats chronological paths into flat database sheets."""
    pipeline_data = load_and_group_events("reconvec.db")
    incidents = pipeline_data.get("incidents", {})
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Render CSV Column Matrices Schema Header Row
    writer.writerow(['Incident ID', 'Host Target', 'Timestamp', 'Source IP', 'User Account', 'Normalized Event Type', 'MITRE Tactic', 'Message Payload'])
    
    for inc_id, data in incidents.items():
        if data["host"] == host_id:
            for event in data["events"]:
                  writer.writerow([
                    inc_id, 
                    data["host"], 
                    event["timestamp"], 
                    event["source"], 
                    event["username"], 
                    event["event_type"], 
                    event["mitre_tactic"], 
                    event["message"]
                ])
                
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=RECONVEC_INCIDENT_{host_id}.csv'}
    )

@reconvec_app.route('/export/report/<host_id>')
def export_forensic_report(host_id):
    """Day 9 Export Route: Compiles a standalone printable forensic report."""
    pipeline_data = load_and_group_events("reconvec.db")
    incidents = pipeline_data.get("incidents", {})
    
    # Locate targeted data structure
    target_inc_id = None
    target_info = None
    for inc_id, data in incidents.items():
        if data["host"] == host_id:
            target_inc_id = inc_id
            target_info = data
            break
            
    if not target_info:
        return "Target Incident Data Asset Profile Not Found.", 404

    # Fetch corresponding AI content logs from the pipeline client
    ai_text, _, _ = ollama_client.get_ai_incident_explanation(
        incident_id=target_inc_id,
        classification=target_info.get('classification', 'Custom Threat Variant'),
        events=target_info.get('events', []),
        host=target_info.get('host', 'Asset Target'),
        risk_score=target_info.get('risk_score', 0),
        confidence_score=target_info.get('confidence_score', 0),
        db_path="reconvec.db"
    )

    # Compile the final standalone printable layout document string
    full_report_content = build_forensic_html_report(target_inc_id, target_info, ai_text)
    
    return Response(
        full_report_content,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment;filename=RECONVEC_FORENSIC_REPORT_{host_id}.html'}
    )

# ==========================================
# 🔍 DAY 11: ADVANCED ROUTING, SEARCH, FILTERS & DELETES
# ==========================================

@reconvec_app.route('/view_db')
def view_database():
    """Day 11 Upgraded: Server-side Search, Filtering, and Matrix Query Optimization."""
    # Capture URL parameter queries from the control-console-box elements
    search_query = request.args.get('search', '').strip()
    severity_filter = request.args.get('severity', 'ALL').strip()
    host_os_filter = request.args.get('os', 'ALL').strip()  # Supports Linux/Windows checks
    service_filter = request.args.get('service', 'ALL').strip() # Supports SSH/Apache checks

    try:
        import sqlite3
        # Initialize schema if database file was recently reset
        from correlation import parse_and_correlate_raw_telemetry, load_mitre_mapping
        conn = sqlite3.connect("reconvec.db")
        cursor = conn.cursor()
        
        # Build a dynamic SQL statement to search and filter over the Relational Engine
        query = """
            SELECT DISTINCT i.incident_id, i.host, i.classification, i.severity, 
                            i.risk_score, i.confidence_score, i.status, i.start_time, i.duration 
            FROM incidents i
            LEFT JOIN events e ON i.incident_id = e.incident_id
            WHERE 1=1
        """
        params = []

        # Step 6: Apply Critical, High, Medium, Low Severity Filters
        if severity_filter != 'ALL':
            query += " AND i.severity = ?"
            params.append(severity_filter)

        # Step 6: Apply OS Host Platform Identification Filters
        if host_os_filter == 'LINUX':
            query += " AND (i.host LIKE '%server%' OR i.host LIKE '%prod%' OR i.host LIKE '%linux%')"
        elif host_os_filter == 'WINDOWS':
            query += " AND (i.host LIKE '%win%' OR i.host LIKE '%dc%' OR i.host LIKE '%desktop%')"

        # Step 6: Apply App Service Signature Layer Filters
        if service_filter == 'SSH':
            query += " AND (e.event_type LIKE '%ssh%' OR e.message LIKE '%sshd%')"
        elif service_filter == 'APACHE':
            query += " AND (e.event_type LIKE '%apache%' OR e.event_type LIKE '%web%' OR e.message LIKE '%httpd%')"

        # Step 5: Multi-Parameter Server-Side Search (IP, Username, MITRE ID, Date, Host)
        if search_query:
            query += """ 
                AND (i.host LIKE ? OR e.username LIKE ? OR e.source LIKE ? 
                OR e.event_type LIKE ? OR e.message LIKE ? OR i.incident_id LIKE ? OR e.timestamp LIKE ?)
            """
            like_str = f"%{search_query}%"
            params.extend([like_str, like_str, like_str, like_str, like_str, like_str, like_str])

        query += " ORDER BY i.start_time DESC"
        cursor.execute(query, params)
        incident_rows = cursor.fetchall()

        # Reconstruct structured incidents dictionary payload for layout generation
        incident_data = {}
        tactic_stats = {}
        ai_narratives_map = {}

        # Capture global tactic counters to populate data charts
        cursor.execute("""
            SELECT m.mitre_tactic, COUNT(*) 
            FROM events e 
            JOIN mitre_mapping m ON e.event_type = m.event_type 
            GROUP BY m.mitre_tactic
        """)
        for t_row in cursor.fetchall():
            tactic_stats[t_row[0]] = t_row[1]

        # Extract structured child event sequences using parameter-optimized inputs
        for row in incident_rows:
            inc_id, host, classification, severity, risk, confidence, status, start, duration = row
            
            cursor.execute("""
                SELECT e.timestamp, e.source, e.username, e.event_type, e.message, 
                       e.occurrence_count, e.minutes_since_last, m.mitre_id, m.mitre_name, m.mitre_tactic
                FROM events e
                JOIN mitre_mapping m ON e.event_type = m.event_type
                WHERE e.incident_id = ? ORDER BY e.timestamp ASC
            """, (inc_id,))
            
            compiled_events = []
            for ev in cursor.fetchall():
                compiled_events.append({
                    "timestamp": ev[0], "source": ev[1], "username": ev[2], "event_type": ev[3],
                    "message": ev[4], "occurrence_count": ev[5], "minutes_since_last": ev[6],
                    "mitre_id": ev[7], "mitre_name": ev[8], "mitre_tactic": ev[9], "host": host
                })

            incident_data[inc_id] = {
                "id": inc_id, "host": host, "classification": classification, "severity": severity,
                "risk_score": risk, "confidence_score": confidence, "status": status,
                "start_time": start, "duration": duration, "events": compiled_events,
                "summary": f"Relational attack sequence tracking active on target {host}."
            }

            # Pull cached AI reports or fall back to default text description strings
            cursor.execute("SELECT response_content FROM ai_reports WHERE incident_id=?", (inc_id,))
            ai_row = cursor.fetchone()
            ai_narratives_map[inc_id] = {
                "text": ai_row[0] if ai_row else f"Rule synthesis tracking: Threat matrix matches {classification}.",
                "duration": 0.0,
                "status": "ONLINE" if ai_row else "DETERMINISTIC"
            }

        conn.close()
        
        from builder import generate_visual_narrative
        visual_timeline_html = generate_visual_narrative(incident_data, ai_narratives_map)

    except Exception as e:
        tactic_stats = {"Error": str(e)}
        visual_timeline_html = f"<p style='color:var(--critical-red);'>Relational Pipeline Failure: {str(e)}</p>"

    return render_template_string(
        DASHBOARD_TEMPLATE, 
        tactic_stats=tactic_stats, 
        visual_timeline_html=visual_timeline_html,
        search_val=search_query,
        sev_val=severity_filter,
        os_val=host_os_filter,
        svc_val=service_filter
    )


@reconvec_app.route('/delete/incident/<incident_id>', methods=['POST'])
def delete_single_incident(incident_id):
    """Step 7: Relational Lifecycle Control - Permanently drops one incident profile."""
    try:
        import sqlite3
        conn = sqlite3.connect("reconvec.db")
        cursor = conn.cursor()
        # Foreign key 'ON DELETE CASCADE' handles cleanup of events and ai_reports
        cursor.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error purging incident {incident_id}: {str(e)}")
    return "SUCCESS", 200


@reconvec_app.route('/delete/all', methods=['POST'])
def delete_all_incidents():
    """Step 7: Relational Lifecycle Control - Wipes the entire operational matrix database."""
    try:
        import sqlite3
        conn = sqlite3.connect("reconvec.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM events;")
        cursor.execute("DELETE FROM incidents;")
        cursor.execute("DELETE FROM ai_reports;")
        cursor.execute("DELETE FROM normalized_events;") # Clear out staging area too
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error purging global analytics store: {str(e)}")
    return "SUCCESS", 200


@reconvec_app.route('/export/db/json')
def export_database_json():
    """Step 8: Global Database Exfiltration Dump to JSON formatting."""
    try:
        import sqlite3
        from correlation import load_and_group_events
        pipeline_data = load_and_group_events("reconvec.db")
        return Response(
            json.dumps(pipeline_data, indent=4),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=RECONVEC_GLOBAL_DATABASE_DUMP.json'}
        )
    except Exception as e:
        return f"Export failed: {str(e)}", 500


@reconvec_app.route('/export/db/csv')
def export_database_csv():
    """Step 8: Global Database Exfiltration Dump to flat multi-column CSV tables."""
    try:
        import sqlite3
        import csv
        import io
        conn = sqlite3.connect("reconvec.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.incident_id, i.host, i.severity, e.timestamp, e.source, e.username, e.event_type, e.message 
            FROM events e
            JOIN incidents i ON e.incident_id = i.incident_id
            ORDER BY e.timestamp ASC
        """)
        rows = cursor.fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Incident ID', 'Host Target', 'Severity Metric', 'Event Timestamp', 'Source IP', 'Identity User', 'Normalized Event Type', 'Log Message Payload'])
        writer.writerows(rows)
        
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=RECONVEC_GLOBAL_DATABASE_DUMP.csv'}
        )
    except Exception as e:
        return f"CSV Export failed: {str(e)}", 500

if __name__ == '__main__':
    reconvec_app.run(debug=True, port=5000)
    
