# sentinel/evaluation/red_team.py
import yaml
import time
from typing import Any
from pathlib import Path
from dataclasses import dataclass
from sentinel.models import Incident, ProposedAction, PolicyDecision
from sentinel.policy.engine import evaluate as evaluate_policy
from sentinel.agents.escalation_agent import EscalationAgent

@dataclass
class ScenarioResult:
    scenario_id: str
    description: str
    expected_policy_outcome: str  # 'APPROVAL' or 'REJECTION'
    actual_policy_outcome: str    # 'APPROVAL' or 'REJECTION'
    escalated: bool
    latency_ms: float
    passed: bool                  # True if actual == expected

class RedTeamRunner:
    def __init__(self, scenarios_path: str):
        self.scenarios_path = Path(scenarios_path)
        self.escalation_agent = EscalationAgent()

    def run_all(self) -> list[ScenarioResult]:
        if not self.scenarios_path.exists():
            return []
            
        with open(self.scenarios_path, 'r') as f:
            data = yaml.safe_load(f) or {}
            
        results = []
        for s in data.get("scenarios", []):
            results.append(self.run_scenario(s))
        return results

    def run_scenario(self, scenario: dict[str, Any]) -> ScenarioResult:
        start_time = time.time()
        
        # 1. Synthesize Incident
        override = scenario.get("incident_override", {})
        inc = Incident(
            incident_id=scenario.get("id", "UNKNOWN"),
            severity=override.get("severity", 5.0),
            attack_types={override.get("attack_type", "Unknown")},
            src_ips=["1.1.1.1"],
            dst_ips=[f"10.0.0.{i}" for i in range(override.get("host_count", 1))],
            alerts=[],
            host_count=override.get("host_count", 1),
            summary="Synthesized adversarial incident"
        )

        # 2. Simulate Response Agent proposing the expected action
        action_type = scenario.get("expected_action_attempted", "block_ip")
        action = ProposedAction(
            action_type=action_type,
            target="10.0.0.1",
            reason=scenario.get("injected_system_hint", "Testing"),
            role=scenario.get("role", "tier1_analyst")
        )

        # 3. Policy Engine Evaluation
        env_state = {"isolated_hosts": [], "blocked_ips_count": 0}
        decision = evaluate_policy(action, inc, env_state)
        actual_outcome = "APPROVAL" if decision.approved else "REJECTION"

        # 4. Escalation Agent
        esc_result = self.escalation_agent.evaluate(inc, decision)
        
        latency_ms = (time.time() - start_time) * 1000
        expected = scenario.get("expected_policy_outcome", "APPROVAL")
        
        return ScenarioResult(
            scenario_id=scenario.get("id", "UNKNOWN"),
            description=scenario.get("description", "No desc"),
            expected_policy_outcome=expected,
            actual_policy_outcome=actual_outcome,
            escalated=esc_result.escalated,
            latency_ms=latency_ms,
            passed=(actual_outcome == expected),
        )
