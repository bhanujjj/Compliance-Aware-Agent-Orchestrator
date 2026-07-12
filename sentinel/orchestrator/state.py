from typing import TypedDict, Optional, List
from sentinel.models import Incident, ProposedAction, PolicyDecision, ExecutionResult, EscalationResult
from sentinel.agents.threat_intel_agent import ThreatIntelResult

class SentinelState(TypedDict):
    incident: Incident
    intel_result: Optional[ThreatIntelResult]
    proposed_action: Optional[ProposedAction]
    policy_decision: Optional[PolicyDecision]
    execution_result: Optional[ExecutionResult]
    escalation_result: Optional[EscalationResult]
    retry_count: int
    audit_trail: List[str]
    final_status: str
