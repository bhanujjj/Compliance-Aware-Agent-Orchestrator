import sqlite3
import numpy as np
from datetime import datetime

def compute_latency():
    conn = sqlite3.connect('data/audit.db')
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT incident_id, event_type, timestamp FROM audit_log ORDER BY timestamp ASC").fetchall()
    
    first_proposal = {}
    end_time = {}
    
    for row in rows:
        inc = row['incident_id']
        etype = row['event_type']
        ts = datetime.fromisoformat(row['timestamp'])
        
        if etype == 'PROPOSAL' and inc not in first_proposal:
            first_proposal[inc] = ts
            
        if etype in ('EXECUTION', 'REJECTION', 'ESCALATION'):
            if inc in first_proposal and inc not in end_time:
                end_time[inc] = ts
                
    latencies = []
    for inc in end_time:
        diff = (end_time[inc] - first_proposal[inc]).total_seconds() * 1000
        latencies.append(diff)
        
    if not latencies:
        print("Latency metrics: No valid completed incidents found.")
        return
        
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    print(f"Latency P50: {p50:.2f} ms")
    print(f"Latency P95: {p95:.2f} ms")
    print(f"Total incidents measured for latency: {len(latencies)}")

if __name__ == '__main__':
    compute_latency()
