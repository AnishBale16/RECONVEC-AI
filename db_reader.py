import sqlite3

def load_and_sort_events(db_path="reconvec.db"):
    """
    Connects to the SQLite database, extracts all normalized security logs, 
    and returns them strictly sorted by Timestamp, Host, and Source.
    """
    try:
        # 1. Establish database pathway connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 2. SQL execution statement containing your sorting constraints (ORDER BY)
        # We use ASC (Ascending) so old logs show first, newer logs show last.
        query = """
            SELECT timestamp, host, source, username, event_type, message 
            FROM normalized_events
            ORDER BY timestamp ASC, host ASC, source ASC;
        """
        
        cursor.execute(query)
        
        # 3. Pull all sorted rows out of the database memory array
        records = cursor.fetchall()
        
        # Convert raw tuples into a clean, readable dictionary structure for your app
        sorted_events = []
        for row in records:
            sorted_events.append({
                "timestamp": row[0],
                "host": row[1],
                "source": row[2], # Usually the Source IP address
                "username": row[3],
                "event_type": row[4],
                "message": row[5]
            })
            
        cursor.close()
        conn.close()
        return sorted_events

    except sqlite3.OperationalError as e:
        print(f"⚠️ Database Error: {e}. Check if table 'normalized_events' exists yet.")
        return []
