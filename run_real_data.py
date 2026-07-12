import os
import sqlite3
from sentinel.data.ingestion import RealDataIngestor
from sentinel.agents.investigation_agent import InvestigationAgent
from sentinel.agents.threat_intel_agent import ThreatIntelAgent
from sentinel.agents.response_agent import ResponseAgent
from sentinel.agents.escalation_agent import EscalationAgent
from sentinel.config.settings import settings
from sentinel.main import process_incident_scenario
from sentinel.audit.logger import fetch_events_sync
from sentinel.logging_config import configure_logging
import structlog

_log = structlog.get_logger("RunRealData")

def main():
    configure_logging()
    _log.info("pipeline_started", dataset="CIC-IDS2018")
    
    csv_path = "data/IDS.csv"
    if not os.path.exists(csv_path):
        _log.error("dataset_not_found", path=csv_path)
        return

    # Clear old database for fresh metrics
    db_path = str(settings.AUDIT_DB_PATH)
    if os.path.exists(db_path):
        os.remove(db_path)
    
    _log.info("ingesting_alerts", path=csv_path)
    ingestor = RealDataIngestor(csv_path)
    real_alerts = ingestor.stream_alerts(multiplier=100)
    _log.info("ingestion_complete", alert_count=len(real_alerts))
    
    if not real_alerts:
        _log.warning("no_malicious_alerts_found")
        return

    _log.info("clustering_alerts_start", window_seconds=3600)
    # Increase window seconds massively since real dataset spans hours
    inv_agent = InvestigationAgent(window_seconds=3600) 
    incidents = inv_agent.process_batch(real_alerts)
    _log.info("clustering_alerts_complete", incident_count=len(incidents))

    _log.info("governance_loop_started")
    response_agent = ResponseAgent(use_stub=False)
    intel_agent = ThreatIntelAgent(top_k=2, use_stub=True)
    escalation_agent = EscalationAgent()

    # Limit to 20 incidents to avoid hitting OpenRouter rate limits (free tier is often 20 RPM)
    sample_incidents = incidents[:20]
    for i, inc in enumerate(sample_incidents):
        if i % 5 == 0 or i == len(sample_incidents) - 1:
            _log.info("processing_incident", index=i+1, total=len(sample_incidents), attack_types=list(inc.attack_types))
            
        # Phase 3: Threat Intel RAG Mapping
        intel_result = intel_agent.map_incident(inc)
        
        # Process through Policy Engine and MCP Gateway (from main.py)
        process_incident_scenario(f"Real Dataset {i+1}", inc, response_agent)
        
        # Check escalation
        esc_result = escalation_agent.evaluate(inc, None, db_path=db_path)

    events = fetch_events_sync()
    total = len(incidents)
    escalated = sum(1 for e in events if e['event_type'] == 'ESCALATION')
    approved = sum(1 for e in events if e['event_type'] == 'APPROVAL')
    rejected = sum(1 for e in events if e['event_type'] == 'REJECTION')
    
    _log.info("final_metrics", total=total, approved=approved, rejected=rejected, escalated=escalated)
    _log.info("run_complete")

if __name__ == "__main__":
    main()
