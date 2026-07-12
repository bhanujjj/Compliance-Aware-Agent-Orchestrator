from sentinel.models import Incident, PolicyDecision
from sentinel.agents.escalation_agent import should_escalate, EscalationAgent

def test_high_severity_triggers_escalation():
    inc = Incident(severity=9.0, attack_types={"DDoS"})
    escalate, reason = should_escalate(inc)
    assert escalate is True
    assert "9.0" in reason

def test_severity_below_threshold_no_escalation():
    inc = Incident(severity=5.0, attack_types={"PortScan"})
    escalate, reason = should_escalate(inc)
    assert escalate is False

def test_exactly_at_threshold_escalates():
    inc = Incident(severity=8.0, attack_types={"DDoS"})
    escalate, _ = should_escalate(inc)
    assert escalate is True

def test_policy_decision_escalate_flag_triggers():
    inc = Incident(severity=3.0, attack_types={"PortScan"})
    pd = PolicyDecision(approved=True, escalate=True, reason="Manual flag")
    escalate, reason = should_escalate(inc, pd)
    assert escalate is True
    assert "Policy Engine" in reason

def test_critical_attack_type_triggers_escalation():
    inc = Incident(severity=5.0, attack_types={"Heartbleed"})
    escalate, reason = should_escalate(inc)
    assert escalate is True
    assert "Heartbleed" in reason

def test_infiltration_triggers_escalation():
    inc = Incident(severity=4.0, attack_types={"Infiltration"})
    escalate, _ = should_escalate(inc)
    assert escalate is True

def test_normal_incident_no_escalation():
    inc = Incident(severity=2.0, attack_types={"BENIGN"})
    escalate, _ = should_escalate(inc, PolicyDecision(escalate=False))
    assert escalate is False

def test_escalation_agent_evaluate_returns_result():
    agent = EscalationAgent()
    inc = Incident(severity=9.0, attack_types={"DDoS"})
    result = agent.evaluate(inc)
    assert result.escalated is True
    assert result.incident_id == inc.incident_id

def test_escalation_agent_no_escalation_result():
    agent = EscalationAgent()
    inc = Incident(severity=1.0, attack_types={"BENIGN"})
    result = agent.evaluate(inc)
    assert result.escalated is False

def test_human_queue_written_when_escalated(tmp_path):
    agent = EscalationAgent()
    inc = Incident(severity=9.0, attack_types={"Heartbleed"},
                   src_ips=["1.2.3.4"])
    db = str(tmp_path / "test.db")
    result = agent.evaluate(inc, db_path=db)
    assert result.escalated is True
    assert result.human_queue_id is not None
    # Verify row exists in DB
    import sqlite3
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT * FROM human_queue WHERE queue_id=?",
                       (result.human_queue_id,)).fetchone()
    conn.close()
    assert row is not None

def test_no_db_write_when_not_escalated(tmp_path):
    import os
    agent = EscalationAgent()
    inc = Incident(severity=2.0, attack_types={"PortScan"})
    db = str(tmp_path / "test.db")
    result = agent.evaluate(inc, db_path=db)
    assert result.escalated is False
    # DB may not even be created
    assert result.human_queue_id is None
