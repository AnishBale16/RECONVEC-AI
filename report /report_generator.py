import os

def build_forensic_html_report(inc_id, info, ai_text):
    """
    Day 9 Report Structure Module - Day 11 Aligned.
    Compiles an Executive Summary, Timelines, MITRE Mappings, Risk Indices, 
    and AI Analysis into a standalone, print-optimized document layout.
    """
    severity = info.get('severity', 'LOW')
    events = info.get('events', [])
    
    # Extract compromised users dynamically to populate containment playbooks safely
    affected_users = set()
    tactic_list = []
    for e in events:
        tactic = e.get('mitre_tactic', 'Unclassified / Unknown Tactic')
        if tactic:
            tactic_list.append(tactic)
        user = e.get('username')
        if user and user.lower() != 'unknown':
            affected_users.add(user)
            
    # Fall back to a default indicator if no username was extracted by the pipeline
    user_display = ", ".join(affected_users) if affected_users else "affected identity sessions"
    
    # Generate the Executive Summary dynamically based on your exact specifications
    actions_desc = "scanned services"
    if "Credential Access" in tactic_list:
        actions_desc += ", performed repeated SSH login attempts"
    if "Initial Access" in tactic_list or "Initial Access / Persistence" in tactic_list:
        actions_desc += ", gained initial entry access"
    if "Execution" in tactic_list:
        actions_desc += ", executed malicious operational code strings"
    if "Privilege Escalation" in tactic_list:
        actions_desc += ", executed privileged commands"
    if "Collection" in tactic_list:
        actions_desc += ", and accessed sensitive core configuration files"
        
    executive_summary = f"A {severity.lower()}-severity attack targeted the server {info.get('host', 'Asset')}. The attacker {actions_desc}."

    # Build internal chronological timeline matrix table rows defensively
    table_rows = ""
    for idx, event in enumerate(events, start=1):
        table_rows += f"""
        <tr>
            <td style="padding: 10px; border: 1px solid #cbd5e1; font-family: monospace;">Step {idx}</td>
            <td style="padding: 10px; border: 1px solid #cbd5e1; font-family: monospace;">{event.get('timestamp', 'N/A')}</td>
            <td style="padding: 10px; border: 1px solid #cbd5e1; font-weight: bold;">{event.get('event_type', 'Unclassified Event')}</td>
            <td style="padding: 10px; border: 1px solid #cbd5e1; font-family: monospace; color:#ef4444;">{event.get('mitre_id', 'N/A')}</td>
            <td style="padding: 10px; border: 1px solid #cbd5e1; font-size: 12px; font-family: monospace;">{event.get('message', 'No log description payload available.')}</td>
        </tr>
        """

    # Print-optimized HTML construction envelope
    report_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RECONVEC-AI Forensic Report - {inc_id}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            margin: 50px;
            color: #1e293b;
            background: white;
        }}
        .header {{
            border-bottom: 3px solid #1e3a8a;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }}
        .section {{
            background: #f8fafc;
            padding: 20px;
            border-radius: 6px;
            border-left: 5px solid #1e3a8a;
            margin-bottom: 25px;
            page-break-inside: avoid;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: bold;
            color: #1e3a8a;
            text-transform: uppercase;
            margin-top: 0;
            margin-bottom: 10px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 5px;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}
        .metric-card {{
            background: #f1f5f9;
            padding: 12px;
            border-radius: 4px;
            text-align: center;
            border: 1px solid #e2e8f0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 13px;
        }}
        th {{
            background-color: #1e3a8a;
            color: white;
            padding: 10px;
            text-align: left;
        }}
        .ai-content {{
            white-space: pre-wrap;
            font-size: 13.5px;
            background: #faf5ff;
            border-left: 5px solid #a855f7;
            padding: 15px;
            border-radius: 4px;
            color: #4c1d95;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin:0; color:#1e3a8a;">🛡️ RECONVEC-AI AUTOMATED FORENSIC REPORT</h1>
        <p style="margin:5px 0 0 0; color:#64748b; font-size:14px;">Programmatic Incident Signature Briefing | Generation Time: 2026-07-16</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric-card"><strong>Tracking ID</strong><br><span style="font-size:18px; color:#1e3a8a;">{inc_id}</span></div>
        <div class="metric-card"><strong>Risk Index Score</strong><br><span style="font-size:18px; color:#ef4444;">{info.get('risk_score', 0)} / 100</span></div>
        <div class="metric-card"><strong>Confidence Metric</strong><br><span style="font-size:18px; color:#10b981;">{info.get('confidence_score', 0)}%</span></div>
    </div>

    <!-- Step 3: Executive Summary Section Container -->
    <div class="section" style="border-left-color: #ef4444;">
        <div class="section-title" style="color:#ef4444;">📋 Executive Summary</div>
        <p style="font-size: 14px; font-weight: 500; margin:0; color:#0f172a;">{executive_summary}</p>
    </div>

    <div class="section" style="border-left-color: #38bdf8;">
        <div class="section-title" style="color:#38bdf8;">⏱️ Forensic Log Audit Timeline</div>
        <table>
            <thead>
                <tr>
                    <th>Step</th>
                    <th>Timestamp</th>
                    <th>Normalized Event</th>
                    <th>MITRE ID</th>
                    <th>Audit Log Message payload</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>

    <div class="section" style="border-left-color: #a855f7;">
        <div class="section-title" style="color:#a855f7;">🧠 Deep-LLM Advanced Analytical Narrative Report</div>
        <div class="ai-content">{ai_text}</div>
    </div>

    <div class="section" style="border-left-color: #10b981;">
        <div class="section-title" style="color:#10b981;">🚨 Recommended Containment Playbook Responses</div>
        <ul style="margin: 0; padding-left: 20px; font-size: 13.5px;">
            <li>Isolate the local server node asset target <strong>{info.get('host', 'Asset')}</strong> from external ingress routing networks.</li>
            <li>Invalidate, revoke, and rotate validation keys for user accounts: <strong>{user_display}</strong>.</li>
            <li>Analyze running system processes to flag any hidden active beacon callbacks.</li>
        </ul>
    </div>
</body>
</html>
"""
    return report_html
