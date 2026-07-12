from sentinel.models import Incident, ProposedAction, PolicyDecision, AuditEvent
from sentinel.agents.response_agent import ResponseAgent
from sentinel.audit.logger import log_event_sync
from sentinel.policy.engine import evaluate  # real deterministic Policy Engine
from sentinel.agents.investigation_agent import InvestigationAgent
from sentinel.agents.threat_intel_agent import ThreatIntelAgent, ThreatIntelResult
from sentinel.gateway.mcp_client import MCPClient
from sentinel.agents.escalation_agent import EscalationAgent, should_escalate
from sentinel.audit.logger import log_execution_sync
from sentinel.logging_config import configure_logging
from sentinel.config.settings import settings
import structlog

_log = structlog.get_logger("Pipeline")

def process_incident_scenario(scenario_name: str, incident: Incident, agent: ResponseAgent):
    _log.info("scenario_started", scenario=scenario_name)

    # 1. Propose action
    proposed_action = agent.propose_action(incident)
    
    # Log proposal
    proposal_event = AuditEvent(
        incident_id=incident.incident_id,
        event_type="PROPOSAL",
        actor="ResponseAgent",
        payload={
            "action_type": proposed_action.action_type,
            "target": proposed_action.target,
            "role": proposed_action.role,
            "reason": proposed_action.reason,
            "severity": incident.severity
        }
    )
    log_event_sync(proposal_event)
    
    _log.info("proposal_made", action=proposed_action.action_type, target=proposed_action.target, role=proposed_action.role)

    # 2. Evaluate policy
    decision = evaluate(proposed_action, incident)
    
    _log.info("policy_decision", approved=decision.approved, escalate=decision.escalate)

    # 3. Handle decision
    if decision.approved and not decision.escalate:
        approval_event = AuditEvent(
            incident_id=incident.incident_id,
            event_type="APPROVAL",
            actor="PolicyEngine",
            payload={"reason": decision.reason}
        )
        log_event_sync(approval_event)
        _log.info("action_approved_and_logged")
        
        client = MCPClient(role=proposed_action.role)
        exec_result = client.execute(proposed_action)
        log_execution_sync(str(settings.AUDIT_DB_PATH), incident.incident_id, exec_result)
        _log.info("action_executed", success=exec_result.success, permission_denied=exec_result.permission_denied, message=exec_result.message)
    elif decision.approved and decision.escalate:
        escalation_event = AuditEvent(
            incident_id=incident.incident_id,
            event_type="ESCALATION",
            actor="PolicyEngine",
            payload={"reason": decision.reason}
        )
        log_event_sync(escalation_event)
        _log.warning("escalated_to_human")
    elif not decision.approved:
        rejection_event = AuditEvent(
            incident_id=incident.incident_id,
            event_type="REJECTION",
            actor="PolicyEngine",
            payload={"reason": decision.reason, "violated_rule": decision.violated_rule}
        )
        log_event_sync(rejection_event)
        _log.warning("action_rejected", reason=decision.reason)
        
        # Retry with a different action type
        _log.info("proposing_fallback_action")
        retry_action = ProposedAction(
            action_type="block_ip",
            target=incident.src_ips[0] if incident.src_ips else "unknown",
            reason="Fallback mitigation.",
            role="tier1_analyst"
        )
        
        retry_proposal_event = AuditEvent(
            incident_id=incident.incident_id,
            event_type="PROPOSAL",
            actor="ResponseAgent",
            payload={
                "action_type": retry_action.action_type,
                "target": retry_action.target,
                "role": retry_action.role,
                "reason": retry_action.reason,
                "severity": incident.severity
            }
        )
        log_event_sync(retry_proposal_event)
        _log.info("fallback_proposal_made", action=retry_action.action_type, target=retry_action.target, role=retry_action.role)
        
        retry_decision = evaluate(retry_action, incident)
        _log.info("fallback_decision", approved=retry_decision.approved, escalate=retry_decision.escalate)
        
        if retry_decision.approved:
            retry_approval_event = AuditEvent(
                incident_id=incident.incident_id,
                event_type="APPROVAL",
                actor="PolicyEngine",
                payload={"reason": retry_decision.reason}
            )
            log_event_sync(retry_approval_event)
            _log.info("fallback_action_approved_and_logged")
            
            client = MCPClient(role=retry_action.role)
            exec_result = client.execute(retry_action)
            log_execution_sync(str(settings.AUDIT_DB_PATH), incident.incident_id, exec_result)
            _log.info("fallback_action_executed", success=exec_result.success, permission_denied=exec_result.permission_denied, message=exec_result.message)

def run_phase2_demo():
    """
    Phase 2 demo: synthetic alerts → Investigation Agent → full governance loop.
    Uses synthetic alerts (no CSV download required).
    """
    print("\n" + "=" * 60)
    print("PHASE 2 DEMO — Investigation Agent")
    print("=" * 60)
    from datetime import datetime, timedelta
    from sentinel.models import Alert
    # Synthetic alert stream
    base_time = datetime.utcnow()
    synthetic_alerts = [
        Alert(src_ip="203.0.113.42", dst_ip="10.1.1.1",
              attack_type="SSH-Patator", severity_score=5.0,
              timestamp=base_time + timedelta(seconds=i * 5))
        for i in range(5)
    ] + [
        Alert(src_ip="198.51.100.7", dst_ip="10.1.1.5",
              attack_type="DDoS", severity_score=6.0,
              timestamp=base_time + timedelta(seconds=i * 3))
        for i in range(3)
    ]
    agent_inv = InvestigationAgent(window_seconds=60)
    incidents = agent_inv.process_batch(synthetic_alerts)
    print(f"\n[INGESTION]  Fed {len(synthetic_alerts)} synthetic alerts")
    print(f"[CLUSTERING] Formed {len(incidents)} incident(s):\n")
    response_agent = ResponseAgent(use_stub=True)
    for inc in incidents:
        print(f"  Incident {inc.incident_id[:8]}...")
        print(f"    Attack types : {inc.attack_types}")
        print(f"    Severity     : {inc.severity}")
        print(f"    Alert count  : {len(inc.alerts)}")
        print(f"    Summary      : {inc.summary}")
        print()
        process_incident_scenario(
            f"[Phase 2] {sorted(inc.attack_types)[0]}", inc, response_agent
        )

def run_phase3_demo():
    """
    Phase 3 demo: Incident → Threat Intel Agent → MITRE ATT&CK mapping.
    Uses stub mode (no index required), wires to real retriever when available.
    """
    print("\n" + "=" * 60)
    print("PHASE 3 DEMO — Threat Intel Agent (MITRE ATT&CK Mapping)")
    print("=" * 60)
    from sentinel.agents.investigation_agent import InvestigationAgent
    from sentinel.models import Alert
    from datetime import datetime, timedelta
    # Reuse the Phase 2 synthetic alerts
    base_time = datetime.utcnow()
    synthetic_alerts = [
        Alert(src_ip="203.0.113.42", dst_ip="10.1.1.1",
              attack_type="SSH-Patator", severity_score=5.0,
              timestamp=base_time + timedelta(seconds=i * 5))
        for i in range(5)
    ] + [
        Alert(src_ip="198.51.100.7", dst_ip="10.1.1.5",
              attack_type="DDoS", severity_score=6.0,
              timestamp=base_time + timedelta(seconds=i * 3))
        for i in range(3)
    ] + [
        Alert(src_ip="172.16.0.99", dst_ip="10.1.1.2",
              attack_type="Heartbleed", severity_score=9.0,
              timestamp=base_time + timedelta(seconds=i * 2))
        for i in range(2)
    ]
    # Form incidents
    incidents = InvestigationAgent(window_seconds=60).process_batch(synthetic_alerts)
    # Check if real index is available; fall back to stub if not
    from sentinel.rag.retriever import get_retriever
    use_stub = not get_retriever().is_ready()
    if use_stub:
        print("\n[INFO] RAG index not built yet — using stub mappings.")
        print("[INFO] Build the real index with: python sentinel/rag/build_index.py\n")
    else:
        print("\n[INFO] Real ChromaDB index found — using live RAG retrieval.\n")
    intel_agent = ThreatIntelAgent(top_k=2, use_stub=use_stub)
    response_agent = ResponseAgent(use_stub=True)
    for inc in incidents:
        result = intel_agent.map_incident(inc)
        print(f"Incident: {inc.incident_id[:8]}... | Attacks: {inc.attack_types}")
        if result.best_match:
            m = result.best_match
            print(f"  ├─ MITRE Technique : {m.technique_id} — {m.technique_name}")
            print(f"  ├─ Tactic          : {m.tactic}")
            print(f"  ├─ Confidence      : {m.confidence:.2f}")
            print(f"  └─ URL             : {m.mitre_url}")
        else:
            print(f"  └─ [WARN] No technique mapped — {result.error}")
        print()
        # Still run through governance loop with MITRE context
        process_incident_scenario(
            f"[Phase 3] {result.best_match.technique_id if result.best_match else 'Unknown'}",
            inc,
            response_agent,
        )

def run_phase4_demo():
    """
    Phase 4 demo: full loop — Investigation → Threat Intel → Response →
    Policy → MCP Gateway (RBAC) → Escalation Agent → Audit.
    No LLM needed — uses stub response agent.
    """
    print("\n" + "=" * 60)
    print("PHASE 4 DEMO — MCP Gateway + Escalation Agent")
    print("=" * 60)
    from sentinel.agents.investigation_agent import InvestigationAgent
    from sentinel.models import Alert
    from datetime import datetime, timedelta
    from sentinel.config.settings import settings
    # Synthetic alerts covering: approved, rejected (RBAC), escalated
    base_time = datetime.utcnow()
    synthetic_alerts = [
        # Heartbleed — severity 9 → escalation guaranteed
        Alert(src_ip="172.16.0.99", dst_ip="10.1.1.2",
              attack_type="Heartbleed", severity_score=9.0,
              timestamp=base_time + timedelta(seconds=i))
        for i in range(2)
    ] + [
        # SSH-Patator — severity 5 → block_ip approved
        Alert(src_ip="203.0.113.42", dst_ip="10.1.1.1",
              attack_type="SSH-Patator", severity_score=5.0,
              timestamp=base_time + timedelta(seconds=10 + i * 3))
        for i in range(3)
    ]
    incidents = InvestigationAgent(window_seconds=60).process_batch(synthetic_alerts)
    response_agent = ResponseAgent(use_stub=True)
    escalation_agent = EscalationAgent()
    db_path = str(settings.AUDIT_DB_PATH)
    print(f"\n[GATEWAY]   MCP Tool Gateway active (in-process, RBAC enforced)")
    print(f"[ESCALATION] Threshold: {escalation_agent.threshold}/10\n")
    for inc in incidents:
        print(f"{'─'*60}")
        print(f"Incident {inc.incident_id[:8]}... | Attacks: {inc.attack_types} | Sev: {inc.severity}")
        # Step 1: Propose action (stub)
        action = response_agent.propose_action(inc)
        print(f"[PROPOSAL]  {action.action_type} → {action.target} (role: {action.role})")
        log_event_sync(AuditEvent(
            incident_id=inc.incident_id,
            event_type="PROPOSAL",
            actor="ResponseAgent",
            payload={"action_type": action.action_type, "target": action.target, "role": action.role, "severity": inc.severity}
        ))
        # Step 2: Policy Engine
        from sentinel.policy.engine import evaluate
        env_state = {"isolated_hosts": [], "blocked_ips_count": 0}
        decision = evaluate(action, inc, env_state)
        print(f"[POLICY]    approved={decision.approved}  escalate={decision.escalate}")
        # Step 3: MCP Gateway (only if policy approved)
        client = MCPClient(role=action.role)
        if decision.approved:
            exec_result = client.execute(action)
            if exec_result.permission_denied:
                print(f"[GATEWAY]   ❌ Permission denied: {exec_result.message}")
                log_event_sync(AuditEvent(
                    incident_id=inc.incident_id, event_type="PERMISSION_DENIED",
                    actor="MCPGateway",
                    payload={"tool": action.action_type, "message": exec_result.message}
                ))
            else:
                print(f"[GATEWAY]   ✅ {exec_result.message}")
                log_execution_sync(db_path, inc.incident_id, exec_result)
        else:
            print(f"[POLICY]    ❌ Rejected: {decision.reason}")
            log_event_sync(AuditEvent(
                incident_id=inc.incident_id, event_type="REJECTION", actor="PolicyEngine",
                payload={"reason": decision.reason}
            ))
        # Step 4: Escalation Agent (always runs, independent of policy)
        esc_result = escalation_agent.evaluate(inc, decision, db_path=db_path)
        if esc_result.escalated:
            print(f"[ESCALATION] 🚨 Escalated — {esc_result.reason}")
            print(f"             Human queue ID: {esc_result.human_queue_id}")
        else:
            print(f"[ESCALATION] ✅ No escalation required.")
        print()

if __name__ == "__main__":
    configure_logging()
    agent = ResponseAgent(use_stub=True)
    
    # Toy incident for Phase 1:
    toy_incident = Incident(
        incident_id="INC-001",
        alerts=[],
        src_ips=["192.168.1.100"],
        dst_ips=["10.0.0.5"],
        attack_types={"SSH-Patator"},
        severity=5.0,
        host_count=1,
        summary="Brute-force SSH login attempts from 192.168.1.100 targeting 10.0.0.5"
    )
    
    # Scenario 1 — Normal approval
    process_incident_scenario("1: Normal Approval", toy_incident, agent)
    
    # Scenario 2 — Policy rejection
    incident_2 = Incident(
        incident_id="INC-002",
        src_ips=["192.168.1.101"],
        dst_ips=["10.0.0.6"],
        attack_types={"Infiltration"},
        severity=7.5,
        host_count=1,
        summary="High severity infiltration attempt."
    )
    process_incident_scenario("2: Policy rejection", incident_2, agent)
    
    # Scenario 3 — Escalation
    incident_3 = Incident(
        incident_id="INC-003",
        src_ips=["192.168.1.102"],
        dst_ips=["10.0.0.7"],
        attack_types={"SSH-Patator"},
        severity=9.0,
        host_count=3,
        summary="Critical brute force activity detected."
    )
    process_incident_scenario("3: Escalation", incident_3, agent)
    
    # End: Print summary table
    from sentinel.audit.logger import fetch_events_sync
    print("\nSummary of ALL Audit Events logged in Database:")
    print(f"{'TIMESTAMP':<28} | {'INCIDENT':<10} | {'EVENT_TYPE':<12} | {'ACTOR':<15} | PAYLOAD")
    print("-" * 120)
    events = fetch_events_sync()
    for e in reversed(events): # print chronological
        # Truncate payload for clean printing
        import json
        payload_str = str(e['payload'])
        if len(payload_str) > 50:
            payload_str = payload_str[:47] + "..."
        print(f"{e['timestamp'][:26]:<28} | {e['incident_id']:<10} | {e['event_type']:<12} | {e['actor']:<15} | {payload_str}")
        
    run_phase2_demo()
    run_phase3_demo()
    run_phase4_demo()
