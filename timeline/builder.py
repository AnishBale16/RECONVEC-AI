import os
import sqlite3
from datetime import datetime

class TimelineBuilder:
    def __init__(self, db_path="reconvec.db"):
        self.db_path = db_path

    def compile_incident_timeline(self, incident_data):
        """Converts correlated incident event objects into sequentially linked tracking arrays."""
        if not incident_data or "events" not in incident_data:
            return []
        
        sorted_events = sorted(
            incident_data["events"], 
            key=lambda x: x.get("timestamp", "")
        )
        
        compiled_timeline = []
        for index, event in enumerate(sorted_events):
            # Extract raw event tuple indices cleanly 
            raw_ev = event.get("timestamp")
            
            # Reconstruct index payload matching the backend structure
            timestamp_val = raw_ev[0] if isinstance(raw_ev, tuple) else event.get("timestamp")
            source_val = raw_ev[1] if isinstance(raw_ev, tuple) else event.get("source")
            user_val = raw_ev[2] if isinstance(raw_ev, tuple) else event.get("username")
            action_val = raw_ev[3] if isinstance(raw_ev, tuple) else event.get("event_type")
            details_val = raw_ev[4] if isinstance(raw_ev, tuple) else event.get("message")
            weight_val = raw_ev[5] if isinstance(raw_ev, tuple) else event.get("occurrence_count", 1)
            delta_val = raw_ev[6] if isinstance(raw_ev, tuple) else event.get("minutes_since_last", 0)
            mid_val = raw_ev[7] if isinstance(raw_ev, tuple) else event.get("mitre_id", "N/A")
            mname_val = raw_ev[8] if isinstance(raw_ev, tuple) else event.get("mitre_name", "Unknown Technique")
            mtactic_val = raw_ev[9] if isinstance(raw_ev, tuple) else event.get("mitre_tactic", "Unclassified / Unknown Tactic")

            timeline_node = {
                "step": index + 1,
                "timestamp": timestamp_val,
                "source": source_val,
                "user": user_val,
                "action": action_val,
                "details": details_val,
                "weight": weight_val,
                "delta_minutes": delta_val,
                "mitre_reference": {
                    "id": mid_val,
                    "technique": mname_val,
                    "tactic": mtactic_val
                },
                "ui_marker_color": self._get_tactic_hex_color(str(mtactic_val))
            }
            compiled_timeline.append(timeline_node)
            
        return compiled_timeline

    def _get_tactic_hex_color(self, tactic):
        """Maps attack stages to clear hex codes optimized for dark CSS templates."""
        color_map = {
            "Initial Access": "#ff4d4d", 
            "Execution": "#ff944d",
            "Persistence": "#ff3399", 
            "Privilege Escalation": "#cc33ff",
            "Credential Access": "#33ccff", 
            "Discovery": "#33ff99",
            "Lateral Movement": "#ffff33", 
            "Exfiltration": "#ff3333",
            "Reconnaissance": "#38bdf8", 
            "Collection": "#eab308",
            "Impact": "#ef4444"
        }
        
        if "/" in tactic:
            for sub_tactic in tactic.split("/"):
                sub_cleaned = sub_tactic.strip()
                if sub_cleaned in color_map:
                    return color_map[sub_cleaned]
                    
        return color_map.get(tactic.strip(), "#a3a3c2")


def generate_visual_narrative(incident_data, ai_narratives_map=None):
    """
    Day 11 UI Presentation Architecture Wrapper.
    Directly aligns with line 27 import expectations inside app.py.
    """
    if ai_narratives_map is None:
        ai_narratives_map = {}
        
    builder = TimelineBuilder()
    html_elements = []
    
    for inc_id, info in incident_data.items():
        timeline_nodes = builder.compile_incident_timeline(info)
        ai_meta = ai_narratives_map.get(inc_id, {
            "text": "Analyst summary pending inference calculation loop.",
            "duration": info.get("duration", 5),
            "status": info.get("status", "OPEN")
        })
        
        card = f"""
        <div data-incident-card data-severity-rank="{info.get('severity', 'LOW')}" 
             style="background: #131a26; border: 1px solid #1f293d; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: left;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1f293d; padding-bottom: 10px; margin-bottom: 15px;">
                <div>
                    <span style="font-size: 18px; font-weight: bold; color: #38bdf8;">{inc_id}</span>
                    <span style="margin-left: 15px; color: #94a3b8; font-size: 14px;">Host Target: {info.get('host')}</span>
                </div>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <span style="background: #1e293b; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; border: 1px solid #1f293d; color: #f8fafc;">
                        RISK SCORE: {info.get('risk_score')}
                    </span>
                    <button onclick="executeSingleIncidentPurge('{inc_id}')" 
                            style="background: #ef4444; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: bold;">
                        🗑️ Delete
                    </button>
                </div>
            </div>
            <p style="font-size: 14px; color: #f8fafc; margin: 0 0 10px 0;"><strong>Classification:</strong> {info.get('classification')}</p>
            <p style="font-size: 13px; color: #94a3b8; background: #0b0f19; padding: 10px; border-radius: 4px; border-left: 3px solid #a855f7; margin: 0 0 15px 0;">
                <strong>Ollama AI Synthesis:</strong> {ai_meta.get('text')}
            </p>
            
            <button onclick="toggleLogEventDetailsBlock('evt_{inc_id}')" 
                    style="background: #1e293b; color: #38bdf8; border: 1px solid #1f293d; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold;">
                Toggle Linked Chain Events ({len(timeline_nodes)})
            </button>
            
            <div id="evt_{inc_id}" style="display: none; margin-top: 15px; padding-top: 15px; border-top: 1px solid #1f293d;">
                <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                    <thead>
                        <tr style="color: #94a3b8; border-bottom: 1px solid #1f293d;">
                            <th style="padding: 6px;">Step</th>
                            <th style="padding: 6px;">Timestamp</th>
                            <th style="padding: 6px;">Event Vector</th>
                            <th style="padding: 6px;">MITRE Tactic</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for node in timeline_nodes:
            ref = node["mitre_reference"]
            card += f"""
                        <tr style="border-bottom: 1px solid #0b0f19; color: #f8fafc;">
                            <td style="padding: 6px; color: {node['ui_marker_color']}; font-weight: bold;">#{node['step']}</td>
                            <td style="padding: 6px;">{node['timestamp']}</td>
                            <td style="padding: 6px;">{node['action']}</td>
                            <td style="padding: 6px;"><span style="color: {node['ui_marker_color']}; font-weight: bold;">[{ref['id']}]</span> {ref['tactic']}</td>
                        </tr>
            """
            
        card += """
                    </tbody>
                </table>
            </div>
        </div>
        """
        html_elements.append(card)
        
    js_injection_script = """
    <script>
    function executeSingleIncidentPurge(incidentId) {
        if(confirm("Confirm removal of incident " + incidentId + "?")) {
            fetch('/delete/incident/' + incidentId, { method: 'POST' })
            .then(res => { if(res.ok) window.location.reload(); });
        }
    }
    function executeGlobalPurgeEngine() {
        if(confirm("CRITICAL WARNING: Wipe the entire operational matrix database?")) {
            fetch('/delete/all', { method: 'POST' })
            .then(res => { if(res.ok) window.location.reload(); });
        }
    }
    </script>
    """
    
    return "\n".join(html_elements) + js_injection_script if html_elements else "<p style='color: #94a3b8;'>No incident tracks found in backend telemetry blocks.</p>" + js_injection_script
