import os
from sentinel.data.ingestion import RealDataIngestor
from sentinel.agents.investigation_agent import InvestigationAgent
from sentinel.orchestrator.runner import run_parallel
from sentinel.config.settings import settings
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
    real_alerts = ingestor.stream_alerts(multiplier=3)
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
    run_parallel(incidents, max_workers=8)

    events = fetch_events_sync()
    total = len(incidents)
    escalated = sum(1 for e in events if e['event_type'] == 'ESCALATION')
    approved = sum(1 for e in events if e['event_type'] == 'APPROVAL')
    rejected = sum(1 for e in events if e['event_type'] == 'REJECTION')
    
    _log.info("final_metrics", total=total, approved=approved, rejected=rejected, escalated=escalated)
    _log.info("run_complete")

if __name__ == "__main__":
    main()
