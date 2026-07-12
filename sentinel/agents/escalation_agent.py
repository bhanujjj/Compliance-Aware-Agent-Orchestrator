# sentinel/agents/escalation_agent.py
"""
Escalation Agent — rule-based hard interrupt.
Triggers escalation if ANY of:
  1. incident.severity >= ESCALATION_THRESHOLD (default 8.0)
  2. policy_decision.escalate is True (Policy Engine flagged it)
  3. incident.attack_types contains a known critical label
NOT an LLM. Deterministic, fast, auditable.
"""
from datetime import datetime
from typing import Optional
from sentinel.models import Incident, PolicyDecision, EscalationResult
from sentinel.logging_config import get_logger

_log = get_logger("EscalationAgent")

ESCALATION_THRESHOLD: float = 8.0
CRITICAL_ATTACK_TYPES: set[str] = {
    "Heartbleed",
    "Infiltration",
}

def should_escalate(
    incident: Incident,
    policy_decision: Optional[PolicyDecision] = None,
) -> tuple[bool, str]:
    """
    Determine whether an incident should be escalated to a human.
    Returns:
        (True, reason_str) if escalation is needed
        (False, "") otherwise
    """
    # Rule 1: Severity threshold
    if incident.severity >= ESCALATION_THRESHOLD:
        return True, (
            f"Incident severity {incident.severity} >= threshold {ESCALATION_THRESHOLD}."
        )
    # Rule 2: Policy Engine flagged escalation
    if policy_decision and policy_decision.escalate:
        return True, f"Policy Engine flagged escalation: {policy_decision.reason}"
    # Rule 3: Known critical attack type
    for at in incident.attack_types:
        if at in CRITICAL_ATTACK_TYPES:
            return True, f"Critical attack type '{at}' detected — mandatory escalation."
    return False, ""

class EscalationAgent:
    """
    Stateless wrapper around the should_escalate function.
    Writes to human_queue if escalation is triggered.
    """
    def __init__(self, threshold: float = ESCALATION_THRESHOLD):
        self.threshold = threshold

    def evaluate(
        self,
        incident: Incident,
        policy_decision: Optional[PolicyDecision] = None,
        db_path: Optional[str] = None,
    ) -> EscalationResult:
        """
        Evaluate whether an incident needs escalation.
        If yes, write to human_queue table (if db_path provided).
        Returns EscalationResult.
        """
        escalate, reason = should_escalate(incident, policy_decision)
        result = EscalationResult(
            incident_id=incident.incident_id,
            escalated=escalate,
            reason=reason,
            severity=incident.severity,
        )
        if result.escalated:
            _log.warning("incident_escalated", incident_id=incident.incident_id[:8],
                         severity=incident.severity, reason=reason)
        else:
            _log.info("no_escalation", incident_id=incident.incident_id[:8],
                      severity=incident.severity)
        if escalate and db_path:
            queue_id = self._write_to_human_queue(incident, reason, db_path)
            result.human_queue_id = queue_id
        return result

    def _write_to_human_queue(
        self, incident: Incident, reason: str, db_path: str
    ) -> str:
        """Write an escalated incident to the human_queue SQLite table."""
        import sqlite3, uuid
        queue_id = str(uuid.uuid4())
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS human_queue (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    queue_id        TEXT NOT NULL UNIQUE,
                    incident_id     TEXT NOT NULL,
                    severity        REAL NOT NULL,
                    reason          TEXT NOT NULL,              
                    status          TEXT DEFAULT 'PENDING',     
                    created_at      TEXT DEFAULT (datetime('now')),
                    acknowledged_at TEXT
                )
            """)
            conn.execute("""
                INSERT INTO human_queue
                  (queue_id, incident_id, severity, reason)
                VALUES (?, ?, ?, ?)
            """, (
                queue_id,
                incident.incident_id,
                incident.severity,
                reason
            ))
            conn.commit()
        finally:
            conn.close()
        return queue_id
