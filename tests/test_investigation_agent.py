from datetime import datetime, timedelta
from sentinel.models import Alert, Incident
from sentinel.agents.investigation_agent import InvestigationAgent, _generate_summary

def _alert(src_ip="1.2.3.4", dst_ip="10.0.0.1",
           attack_type="DDoS", severity=6.0,
           timestamp=None) -> Alert:
    return Alert(
        src_ip=src_ip, dst_ip=dst_ip,
        attack_type=attack_type, severity_score=severity,
        timestamp=timestamp or datetime.utcnow()
    )

def test_single_alert_creates_one_incident():
    agent = InvestigationAgent()
    agent.ingest(_alert(timestamp=datetime(2024, 1, 1, 0, 0, 0)))
    assert agent.open_count == 1
    assert agent.closed_count == 0

def test_two_alerts_same_src_ip_within_window_grouped():
    agent = InvestigationAgent(window_seconds=60)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(timestamp=t0))
    agent.ingest(_alert(timestamp=t0 + timedelta(seconds=30)))
    
    incidents = agent.finalize_all()
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 2

def test_two_alerts_same_src_ip_outside_window_creates_two_incidents():
    agent = InvestigationAgent(window_seconds=60)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(timestamp=t0))
    agent.ingest(_alert(timestamp=t0 + timedelta(seconds=90)))
    
    assert agent.open_count == 1
    assert agent.closed_count == 1
    
    incidents = agent.finalize_all()
    assert len(incidents) == 2
    assert len(incidents[0].alerts) == 1
    assert len(incidents[1].alerts) == 1

def test_different_src_ips_create_separate_incidents():
    agent = InvestigationAgent()
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(src_ip="1.1.1.1", timestamp=t0))
    agent.ingest(_alert(src_ip="2.2.2.2", timestamp=t0 + timedelta(seconds=10)))
    
    assert agent.open_count == 2
    incidents = agent.finalize_all()
    assert len(incidents) == 2

def test_benign_alert_does_not_open_new_incident():
    agent = InvestigationAgent()
    agent.ingest(_alert(attack_type="BENIGN"))
    assert agent.open_count == 0

def test_severity_is_max_of_all_alerts():
    agent = InvestigationAgent(window_seconds=60)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(severity=3.0, timestamp=t0))
    agent.ingest(_alert(severity=7.0, timestamp=t0 + timedelta(seconds=10)))
    agent.ingest(_alert(severity=4.0, timestamp=t0 + timedelta(seconds=20)))
    
    incidents = agent.finalize_all()
    assert len(incidents) == 1
    assert incidents[0].severity == 7.0

def test_incident_dst_ips_unique():
    agent = InvestigationAgent(window_seconds=60)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(dst_ip="10.0.0.1", timestamp=t0))
    agent.ingest(_alert(dst_ip="10.0.0.2", timestamp=t0 + timedelta(seconds=10)))
    agent.ingest(_alert(dst_ip="10.0.0.1", timestamp=t0 + timedelta(seconds=20)))
    
    incidents = agent.finalize_all()
    assert len(incidents) == 1
    assert set(incidents[0].dst_ips) == {"10.0.0.1", "10.0.0.2"}

def test_host_count_equals_unique_dst_ips():
    agent = InvestigationAgent(window_seconds=60)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(dst_ip="10.0.0.1", timestamp=t0))
    agent.ingest(_alert(dst_ip="10.0.0.2", timestamp=t0 + timedelta(seconds=10)))
    
    incidents = agent.finalize_all()
    assert incidents[0].host_count == 2

def test_attack_types_collected():
    agent = InvestigationAgent(window_seconds=60)
    t0 = datetime(2024, 1, 1, 0, 0, 0)
    agent.ingest(_alert(attack_type="DDoS", timestamp=t0))
    agent.ingest(_alert(attack_type="PortScan", timestamp=t0 + timedelta(seconds=10)))
    agent.ingest(_alert(attack_type="BENIGN", timestamp=t0 + timedelta(seconds=20)))
    
    incidents = agent.finalize_all()
    assert len(incidents) == 1
    assert incidents[0].attack_types == {"DDoS", "PortScan"}

def test_process_batch_resets_state():
    agent = InvestigationAgent()
    alerts1 = [_alert(src_ip="1.1.1.1")]
    alerts2 = [_alert(src_ip="2.2.2.2")]
    
    incidents1 = agent.process_batch(alerts1)
    assert len(incidents1) == 1
    assert incidents1[0].src_ips == ["1.1.1.1"]
    
    incidents2 = agent.process_batch(alerts2)
    assert len(incidents2) == 1
    assert incidents2[0].src_ips == ["2.2.2.2"]

def test_summary_generated_on_finalize():
    agent = InvestigationAgent()
    agent.ingest(_alert())
    incidents = agent.finalize_all()
    assert len(incidents) == 1
    assert len(incidents[0].summary) > 0

def test_generate_summary_content():
    incident = Incident(
        attack_types={"DDoS", "SQLi"},
        src_ips=["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
        severity=8.5,
        host_count=5
    )
    # fake 2 alerts for the count
    incident.alerts = [1, 2]
    
    summary = _generate_summary(incident)
    
    assert "DDoS, SQLi" in summary
    assert "1.1.1.1, 2.2.2.2, 3.3.3.3" in summary
    assert "(+1 more)" in summary
    assert "5 host(s)" in summary
    assert "8.5/10" in summary
    assert "count: 2" in summary

def test_no_src_ip_alert_skipped():
    agent = InvestigationAgent()
    agent.ingest(_alert(src_ip=""))
    assert agent.open_count == 0
    assert len(agent.finalize_all()) == 0
