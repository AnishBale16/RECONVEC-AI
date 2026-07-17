def get_incident_summary_prompt(classification, events, host, incident_id, risk_score, confidence_score):
    """
    Day 8 Advanced SOC Prompt Controller - Day 11 Multi-Line Guarded.
    Builds strict prompt templates for Ollama (Llama 3.2:1b) inference chains.
    """
    timeline_str = ""
    for index, e in enumerate(events, start=1):
        # Defensive .get() lookups prevent crashing on inconsistent model fields
        ts = e.get('timestamp', '2026-07-16 10:00:00')
        evt_type = e.get('event_type', 'Unclassified Event')
        user = e.get('username', 'unknown')
        src = e.get('source', '127.0.0.1')
        msg = e.get('message', 'No raw log message payload available.')
        
        timeline_str += f"- Step {index} [{ts}]: Type '{evt_type}' by user '{user}' from source '{src}'. Payload: {msg}\n"
        
    prompt = f"""
[ROLE]
You are a Senior Cyber SOC Analyst generating an official corporate intelligence briefing.
Write in an authoritative, neutral, forensic tone.

[CONTEXT DATA MATRIX]
- Incident Tracking ID: {incident_id}
- Affected Target Asset: {host}
- Rule-Engine Classification: {classification}
- Computed Quantitative Risk Index: {risk_score}/100
- Telemetry Attribution Confidence: {confidence_score}%

[CHRONOLOGICAL TELEMETRY TIMELINE EVIDENCE]
{timeline_str}

[ANTI-HALLUCINATION CONSTRAINT ENFORCEMENT]
- Base your analysis strictly and exclusively on the chronological timeline evidence listed above.
- NEVER extrapolate, assume, or infer actions. Do not invent any filenames, credentials, port numbers, or processes.
- If specific data payload vectors or operational scopes are missing, output the term "Unknown based on restricted log access".

[EXPLICIT REPORT OUTPUT ARCHITECTURE]
Generate your response using the markdown headers below. Do not output any greetings or concluding text.

### 🔄 Detailed Attack Progression
[Provide a highly objective, fact-based description of the chronological progression of events.]

### 🎯 Likely Adversary Objective
[State the final logical payload objective of this specific signature chain. If unclear from the data, output 'Unknown'.]

### 🛡️ MITRE ATT&CK Matrix Mapping
[List all observed techniques and IDs from the evidence as clear bullet points.]

### 📊 Risk Profile Evaluation
[Provide a brief assessment justifying the calculated risk index of {risk_score} based on the highest level of system intrusion achieved.]

### 🚨 Direct Containment Recommendations
[Provide 2 to 3 actionable, host-level remediation steps to terminate this vector immediately based on standard incident response frameworks.]
"""
    return prompt.strip()
