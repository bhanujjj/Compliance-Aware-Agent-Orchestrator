from sentinel.orchestrator.state import SentinelState
from sentinel.agents.investigation_agent import InvestigationAgent
from sentinel.agents.threat_intel_agent import ThreatIntelAgent
from sentinel.agents.response_agent import ResponseAgent
from sentinel.agents.escalation_agent import EscalationAgent
import sentinel.policy.engine
from sentinel.gateway.mcp_client import MCPClient
from sentinel.audit.logger import log_event_sync

def investigation_node(state: SentinelState) -> dict:
    intel_agent = ThreatIntelAgent(top_k=2, use_stub=True)
    result = intel_agent.map_incident(state["incident"])
    tech_id = result.best_match.technique_id if result.best_match else "None"
    return {
        "intel_result": result,
        "audit_trail": state.get("audit_trail", []) + [f"ThreatIntel: Mapped to {tech_id}"]
    }

def threat_intel_node(state: SentinelState) -> dict:
    intel_agent = ThreatIntelAgent(top_k=2, use_stub=True)
    result = intel_agent.map_incident(state["incident"])
    tech_id = result.best_match.technique_id if result.best_match else "None"
    return {
        "intel_result": result,
        "audit_trail": state.get("audit_trail", []) + [f"ThreatIntel: Mapped to {tech_id}"]
    }

def response_node(state: SentinelState) -> dict:
    response_agent = ResponseAgent(use_stub=True)
    result = response_agent.propose_action(state["incident"])
    return {
        "proposed_action": result,
        "audit_trail": state.get("audit_trail", []) + [f"ResponseAgent: Proposed {result.action_type} on {result.target}"]
    }

def policy_node(state: SentinelState) -> dict:
    decision = sentinel.policy.engine.evaluate(state["proposed_action"], state["incident"])
    
    from sentinel.models import AuditEvent
    from datetime import datetime
    
    event_type = "APPROVAL" if decision.approved else "REJECTION"
    if decision.escalate:
        event_type = "ESCALATION"
        
    audit_event = AuditEvent(
        timestamp=datetime.utcnow(),
        incident_id=state["incident"].incident_id,
        event_type=event_type,
        actor="PolicyEngine",
        payload={
            "action_type": state["proposed_action"].action_type,
            "target": state["proposed_action"].target,
            "role": state["proposed_action"].role,
            "decision": decision.__dict__
        }
    )
    log_event_sync(audit_event)
    
    trail = state.get("audit_trail", [])
    if decision.approved:
        trail.append("PolicyEngine: APPROVED")
    else:
        trail.append(f"PolicyEngine: REJECTED — {decision.reason}")
        
    return {
        "policy_decision": decision,
        "audit_trail": trail,
        "retry_count": state.get("retry_count", 0) + (1 if not decision.approved else 0)
    }

def execution_node(state: SentinelState) -> dict:
    mcp_client = MCPClient(role="tier1_analyst")
    result = mcp_client.execute(state["proposed_action"])
    
    final_status = "MITIGATED" if result.success else "FAILED"
    # Create an audit event for execution
    from sentinel.models import AuditEvent
    from datetime import datetime
    exec_event = AuditEvent(
        timestamp=datetime.utcnow(),
        incident_id=state["incident"].incident_id,
        event_type="EXECUTION",
        actor="MCPClient",
        payload={
            "action_type": state["proposed_action"].action_type,
            "target": state["proposed_action"].target,
            "role": "tier1_analyst",
            "success": result.success,
            "message": result.message,
            "execution_result": result.__dict__
        }
    )
    log_event_sync(exec_event)
    
    trail = state.get("audit_trail", []) + [f"MCPGateway: Executed {result.tool_name} → {result.message}"]
    return {
        "execution_result": result,
        "final_status": final_status,
        "audit_trail": trail
    }

def escalation_node(state: SentinelState) -> dict:
    escalation_agent = EscalationAgent()
    result = escalation_agent.evaluate(state["incident"], state["policy_decision"])
    return {
        "escalation_result": result,
        "final_status": "ESCALATED",
        "audit_trail": state.get("audit_trail", []) + [f"EscalationAgent: 🚨 Escalated — {result.reason}"]
    }

def route_after_policy(state: SentinelState) -> str:
    decision = state["policy_decision"]
    if decision.escalate:
        return "escalation_node"
    elif not decision.approved:
        if state.get("retry_count", 0) < 3:
            return "response_node"   # loop back for retry
        else:
            return "escalation_node" # max retries exceeded, escalate
    else:
        return "execution_node"
