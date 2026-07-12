import pytest
from sentinel.models import Incident
from sentinel.agents.response_agent import ResponseAgent

def test_ssh_brute_force_proposes_block_ip():
    incident = Incident(attack_types={"SSH-Patator"}, severity=5.0, src_ips=["1.2.3.4"])
    agent = ResponseAgent(use_stub=True)
    action = agent.propose_action(incident)
    assert action.action_type == "block_ip"
    assert action.target == "1.2.3.4"

def test_high_severity_proposes_isolate_host():
    incident = Incident(attack_types={"Infiltration"}, severity=8.0, dst_ips=["10.0.0.1"])
    agent = ResponseAgent(use_stub=True)
    action = agent.propose_action(incident)
    assert action.action_type == "isolate_host"
    assert action.target == "10.0.0.1"

def test_bot_proposes_revoke_session():
    incident = Incident(attack_types={"Bot"}, severity=4.0)
    agent = ResponseAgent(use_stub=True)
    action = agent.propose_action(incident)
    assert action.action_type == "revoke_session"
    assert action.target == "fake_user_123"

def test_proposed_action_has_reason():
    agent = ResponseAgent(use_stub=True)
    action = agent.propose_action(Incident(severity=3.0, attack_types={"PortScan"}, src_ips=["5.5.5.5"]))
    assert len(action.reason) > 10

def test_proposed_action_has_role():
    agent = ResponseAgent(use_stub=True)
    action = agent.propose_action(Incident(severity=3.0, attack_types={"PortScan"}, src_ips=["5.5.5.5"]))
    assert action.role == "tier1_analyst"

def test_build_prompt_contains_incident_id():
    incident = Incident(incident_id="INC-999", severity=6.0, attack_types={"DDoS"}, src_ips=[], dst_ips=[])
    agent = ResponseAgent(use_stub=True)
    prompt = agent.build_prompt(incident)
    assert "INC-999" in prompt

def test_llm_propose_raises_not_implemented():
    agent = ResponseAgent(use_stub=False)
    incident = Incident(
        src_ips=["1.2.3.4"],
        dst_ips=["10.0.0.1"],
        attack_types=["SSH-Patator"],
        severity=6.0,
        summary="Test"
    )
    import os
    if "OPENROUTER_API_KEY" in os.environ:
        del os.environ["OPENROUTER_API_KEY"]
        
    result = agent.propose_action(incident)
    assert result.action_type == "block_ip"
