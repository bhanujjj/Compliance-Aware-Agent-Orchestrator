from sentinel.evaluation.red_team import ScenarioResult, RedTeamRunner
from sentinel.evaluation.metrics import calculate_metrics

def test_calculate_metrics_guardrail_catch_rate():
    # 1 caught out of 2 adversarial -> 50%
    results = [
        ScenarioResult(
            scenario_id="1", description="", expected_policy_outcome="REJECTION",
            actual_policy_outcome="REJECTION", escalated=True, latency_ms=10.0, passed=True
        ),
        ScenarioResult(
            scenario_id="2", description="", expected_policy_outcome="REJECTION",
            actual_policy_outcome="APPROVAL", escalated=False, latency_ms=10.0, passed=False
        ),
        ScenarioResult(
            scenario_id="3", description="", expected_policy_outcome="APPROVAL",
            actual_policy_outcome="APPROVAL", escalated=False, latency_ms=10.0, passed=True
        )
    ]
    metrics = calculate_metrics(results)
    assert metrics["guardrail_catch_rate"] == 50.0
    assert metrics["total_scenarios"] == 3
    assert metrics["scenarios_passed"] == 2
    assert metrics["overall_pass_rate"] == (2/3) * 100

def test_calculate_metrics_empty():
    metrics = calculate_metrics([])
    assert metrics == {}

def test_calculate_metrics_no_adversarial():
    results = [
        ScenarioResult(
            scenario_id="1", description="", expected_policy_outcome="APPROVAL",
            actual_policy_outcome="APPROVAL", escalated=False, latency_ms=10.0, passed=True
        )
    ]
    metrics = calculate_metrics(results)
    assert metrics["guardrail_catch_rate"] == 100.0

def test_red_team_runner_missing_yaml_keys(tmp_path):
    import yaml
    yaml_path = tmp_path / "test.yaml"
    
    # Missing optional keys like incident_override, expected_action_attempted
    yaml_path.write_text(yaml.dump({
        "scenarios": [
            {
                "id": "SCEN-MISSING-KEYS"
            }
        ]
    }))
    
    runner = RedTeamRunner(str(yaml_path))
    results = runner.run_all()
    
    assert len(results) == 1
    r = results[0]
    assert r.scenario_id == "SCEN-MISSING-KEYS"
    # Default behavior expected
    assert r.expected_policy_outcome == "APPROVAL"
