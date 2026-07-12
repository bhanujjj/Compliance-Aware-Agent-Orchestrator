import sqlite3
from collections import Counter

def check_metrics():
    print("="*50)
    print("Real Data Pipeline Metrics (from audit.db)")
    print("="*50)
    
    with sqlite3.connect("data/audit.db") as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Total distinct incidents
        cursor.execute("SELECT COUNT(DISTINCT incident_id) FROM audit_log WHERE incident_id IS NOT NULL")
        total_incidents = cursor.fetchone()[0]
        
        # Event type counts
        cursor.execute("SELECT event_type, COUNT(*) FROM audit_log GROUP BY event_type")
        event_counts = dict(cursor.fetchall())
        
        # Policy decisions
        cursor.execute("SELECT event_type, json_extract(payload, '$.action_type') as action_type, COUNT(*) FROM audit_log WHERE event_type IN ('APPROVAL', 'REJECTION', 'ESCALATION') GROUP BY event_type, json_extract(payload, '$.action_type')")
        decisions = cursor.fetchall()
        
    print(f"Total Unique Incidents Logged: {total_incidents}")
    print("\nEvent Counts by Type:")
    for etype, count in event_counts.items():
        print(f"  - {etype}: {count}")
        
    print("\nPolicy Decisions by Action Type:")
    for row in decisions:
        print(f"  - {row['event_type']} -> {row['action_type']}: {row['COUNT(*)']}")

if __name__ == "__main__":
    check_metrics()
