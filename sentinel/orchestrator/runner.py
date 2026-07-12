from concurrent.futures import ThreadPoolExecutor, as_completed
from sentinel.orchestrator.graph import build_sentinel_graph
from sentinel.models import Incident

from datetime import datetime
from sentinel.models import AuditEvent
from sentinel.audit.logger import log_event_sync

def run_parallel(incidents: list[Incident], max_workers: int = 16) -> list[dict]:
    graph = build_sentinel_graph()
    results = []
    
    def run_one(inc: Incident) -> dict:
        initial_state = {
            "incident": inc,
            "intel_result": None,
            "proposed_action": None,
            "policy_decision": None,
            "execution_result": None,
            "escalation_result": None,
            "retry_count": 0,
            "audit_trail": [],
            "final_status": "PENDING",
        }
        final_state = graph.invoke(initial_state)
        
        # Persist audit trail
        for step in final_state.get("audit_trail", []):
            log_event_sync(AuditEvent(
                timestamp=datetime.utcnow(),
                incident_id=inc.incident_id,
                event_type="TRACE",
                actor="LangGraph",
                payload={"step": step}
            ))
            
        return {
            "incident_id": inc.incident_id,
            "final_status": final_state["final_status"],
            "audit_trail": final_state["audit_trail"],
        }
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_one, inc): inc for inc in incidents}
        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            results.append(result)
            if i % 50 == 0:
                print(f"[ORCHESTRATOR] Processed {i+1}/{len(incidents)} incidents...")
    
    return results
