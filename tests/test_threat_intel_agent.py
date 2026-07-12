from sentinel.models import Incident
from sentinel.agents.threat_intel_agent import ThreatIntelAgent

def test_map_incident_returns_result():
    # Any incident → ThreatIntelResult (not None, no exception)
    incident = Incident(attack_types={"DDoS"}, severity=6.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert result is not None
    assert result.incident_id == incident.incident_id

def test_ssh_maps_to_t1110():
    incident = Incident(attack_types={"SSH-Patator"}, severity=5.0)
    agent = ThreatIntelAgent(use_stub=True)
    result = agent.map_incident(incident)
    assert result.best_match.technique_id == "T1110"

def test_ddos_maps_to_t1498():
    incident = Incident(attack_types={"DDoS"}, severity=6.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert result.best_match.technique_id == "T1498"

def test_portscan_maps_to_t1046():
    incident = Incident(attack_types={"PortScan"}, severity=4.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert result.best_match.technique_id == "T1046"

def test_heartbleed_maps_to_t1190():
    incident = Incident(attack_types={"Heartbleed"}, severity=9.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert result.best_match.technique_id == "T1190"

def test_unknown_attack_type_returns_fallback():
    incident = Incident(attack_types={"ALIEN_ATTACK_9000"}, severity=3.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert result.best_match is not None   # graceful fallback, not None

def test_confidence_is_float_between_0_and_1():
    incident = Incident(attack_types={"DDoS"}, severity=6.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert 0.0 <= result.best_match.confidence <= 1.0

def test_mitre_url_format():
    incident = Incident(attack_types={"SSH-Patator"}, severity=5.0)
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert result.best_match.mitre_url.startswith("https://attack.mitre.org/")

def test_query_contains_attack_type():
    incident = Incident(attack_types={"DDoS"}, severity=6.0,
                        src_ips=["1.2.3.4"], dst_ips=["5.6.7.8"])
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert "DDoS" in result.query_used

def test_query_contains_severity():
    incident = Incident(attack_types={"PortScan"}, severity=4.0,
                        src_ips=["9.9.9.9"], dst_ips=["10.0.0.1"])
    result = ThreatIntelAgent(use_stub=True).map_incident(incident)
    assert "low severity" in result.query_used

def test_build_query_standalone():
    from sentinel.agents.threat_intel_agent import ThreatIntelAgent
    incident = Incident(attack_types={"SSH-Patator"},
                        src_ips=["1.2.3.4"], dst_ips=["10.0.0.1"],
                        severity=5.0)
    agent = ThreatIntelAgent()
    q = agent._build_query(incident)
    assert "SSH" in q or "brute" in q.lower()
    assert "1.2.3.4" in q

def test_retriever_unavailable_returns_graceful_result():
    # Use use_stub=False but patch the retriever to not be ready
    from unittest.mock import MagicMock, patch
    from sentinel.agents.threat_intel_agent import ThreatIntelAgent
    
    agent = ThreatIntelAgent(use_stub=False)
    mock_retriever = MagicMock()
    mock_retriever.is_ready.return_value = False
    agent._retriever = mock_retriever
    incident = Incident(attack_types={"DDoS"}, severity=6.0)
    result = agent.map_incident(incident)
    assert result.retriever_available is False
    assert result.error is not None
