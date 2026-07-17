import os
import time
import sqlite3
import ollama
from ai.prompts import get_incident_summary_prompt
from ai.response_parser import sanitize_llm_response

def get_ai_incident_explanation(incident_id, classification, events, host, risk_score, confidence_score, db_path="reconvec.db"):
    """
    Day 8 Upgraded API Controller Engine
    Feeds advanced asset metrics, risk indices, and structural contexts into the master prompt.
    """
    SETTINGS = {
        "model": "llama3.2:1b",
        "temperature": 0.1,       # Lowered to 0.1 to maximize analytical consistency and minimize creativity
        "max_tokens": 800,        # Increased to 800 tokens to accommodate the full structured markdown layout
        "timeout_seconds": 10      
    }
    
    # Step 2: Inject all context variables cleanly into the prompt builder
    prompt = get_incident_summary_prompt(classification, events, host, incident_id, risk_score, confidence_score)
    start_time = time.time()
    
    try:
        response = ollama.generate(
            model=SETTINGS["model"],
            prompt=prompt,
            options={
                "temperature": SETTINGS["temperature"],
                "num_predict": SETTINGS["max_tokens"]
            }
        )
        
        execution_time = round(time.time() - start_time, 2)
        raw_response = response.get('response', '')
        ai_summary = sanitize_llm_response(raw_response)
        
        log_ai_transaction(db_path, incident_id, prompt, ai_summary, execution_time)
        return ai_summary, execution_time, "ONLINE"
        
    except Exception as e:
        execution_time = round(time.time() - start_time, 2)
        fallback_msg = f"⚠️ RECONVEC-AI Engine Unavailable. Local service timeout or disconnected."
        log_ai_transaction(db_path, incident_id, prompt, f"ERROR: {str(e)}", execution_time)
        return fallback_msg, execution_time, "OFFLINE"
        
    except Exception as e:
        # Step 5 Timeout & Connection Error Fallback Shield: Prevents crash loops
        execution_time = round(time.time() - start_time, 2)
        fallback_msg = f"⚠️ RECONVEC-AI Engine Unavailable. Local service timeout or disconnected."
        
        log_ai_transaction(db_path, incident_id, prompt, f"ERROR: {str(e)}", execution_time)
        return fallback_msg, execution_time, "OFFLINE"

def log_ai_transaction(db_path, incident_id, prompt, response, duration):
    """Step 6 Database Logger: Records incident analytical records."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_summary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                prompt TEXT,
                response TEXT,
                execution_time_seconds REAL,
                timestamp TEXT
            )
        """)
        cursor.execute("""
            INSERT INTO ai_summary (incident_id, prompt, response, execution_time_seconds, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (incident_id, prompt, response, duration))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging fail: {str(e)}")
