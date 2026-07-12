# sentinel/evaluation/metrics.py
from typing import Any
from sentinel.evaluation.red_team import ScenarioResult
import statistics

def calculate_metrics(results: list[ScenarioResult]) -> dict[str, Any]:
    if not results:
        return {}
    
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    
    # Guardrail catch rate: how often did we reject a bad action we were supposed to reject?
    adversarial_scenarios = [r for r in results if r.expected_policy_outcome == "REJECTION"]
    if adversarial_scenarios:
        caught = sum(1 for r in adversarial_scenarios if r.actual_policy_outcome == "REJECTION")
        guardrail_catch_rate = (caught / len(adversarial_scenarios)) * 100
    else:
        guardrail_catch_rate = 100.0
        
    latencies = [r.latency_ms for r in results]
    
    return {
        "total_scenarios": total,
        "scenarios_passed": passed,
        "overall_pass_rate": (passed / total) * 100,
        "guardrail_catch_rate": guardrail_catch_rate,
        "latency_p50_ms": statistics.median(latencies),
        "latency_p95_ms": statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies),
    }
