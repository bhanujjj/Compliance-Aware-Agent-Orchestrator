"""
Shared dataclasses for the Sentinel governance framework.
All agents import from here — do NOT redefine these elsewhere.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
import uuid


# ---------------------------------------------------------------------------
# Alert — one raw event from the alert stream
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    attack_type: str = "BENIGN"      # raw label from dataset
    severity_score: float = 0.0      # 0–10, mapped from attack_type
    raw_features: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Incident — cluster of related alerts (output of Investigation Agent)
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    alerts: list = field(default_factory=list)       # list[Alert]
    src_ips: list = field(default_factory=list)      # unique source IPs seen
    dst_ips: list = field(default_factory=list)      # unique destination IPs seen
    attack_types: set = field(default_factory=set)   # unique attack labels
    severity: float = 0.0                            # max(alert.severity_score)
    host_count: int = 1                              # number of distinct hosts involved
    summary: str = ""                                # human-readable one-liner


# ---------------------------------------------------------------------------
# ProposedAction — what the Response Agent wants to do
# ---------------------------------------------------------------------------

@dataclass
class ProposedAction:
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str = ""          # block_ip | isolate_host | kill_process | revoke_session | collect_forensics
    target: str = ""               # IP, hostname, user_id, pid — depends on action_type
    reason: str = ""               # LLM's justification
    role: str = "tier1_analyst"    # role the agent is acting as
    extra_params: dict = field(default_factory=dict)  # e.g. {"pid": 1234}


# ---------------------------------------------------------------------------
# PolicyDecision — output of the Policy Engine
# ---------------------------------------------------------------------------

@dataclass
class PolicyDecision:
    approved: bool = False
    reason: str = ""               # plain-English explanation (human-readable)
    escalate: bool = False         # True → route to human regardless of approval
    violated_rule: Optional[str] = None   # name of the rule that was violated, if any
    retry_allowed: bool = True     # False after max retries exceeded


# ---------------------------------------------------------------------------
# AuditEvent — one row in the audit log
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    incident_id: Optional[str] = None
    event_type: str = ""       # PROPOSAL | REJECTION | APPROVAL | ESCALATION | EXECUTION | ERROR
    actor: str = ""            # which agent/component fired this
    payload: dict = field(default_factory=dict)   # full context (action, decision, reason, etc.)
    latency_ms: Optional[int] = None


# ---------------------------------------------------------------------------
# TechniqueMapping — output of the Threat Intel Agent (RAG over MITRE ATT&CK)
# ---------------------------------------------------------------------------

@dataclass
class TechniqueMapping:
    technique_id: str = ""          # e.g. "T1110"
    technique_name: str = ""        # e.g. "Brute Force"
    tactic: str = ""                # e.g. "Credential Access"
    description: str = ""           # short excerpt from ATT&CK
    confidence: float = 0.0         # cosine similarity score 0.0–1.0
    mitre_url: str = ""             # https://attack.mitre.org/techniques/T1110/


# ---------------------------------------------------------------------------
# ExecutionResult — output of the MCP Tool Gateway (mock executor)
# ---------------------------------------------------------------------------

@dataclass
class ExecutionResult:
    success: bool = False
    tool_name: str = ""             # which MCP tool was called
    target: str = ""                # IP / hostname / user_id acted on
    message: str = ""              # human-readable outcome
    state_delta: dict = field(default_factory=dict)   # env state changes applied
    permission_denied: bool = False  # True if role lacked permission at gateway


# ---------------------------------------------------------------------------
# EscalationResult — output of the Escalation Agent
# ---------------------------------------------------------------------------

@dataclass
class EscalationResult:
    incident_id: str = ""
    escalated: bool = False
    reason: str = ""                # why escalation was triggered
    severity: float = 0.0
    human_queue_id: Optional[str] = None  # row ID in human_queue table
