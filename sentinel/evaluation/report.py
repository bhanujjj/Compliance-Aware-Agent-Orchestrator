# sentinel/evaluation/report.py
import json
from datetime import datetime
from pathlib import Path
from sentinel.evaluation.red_team import ScenarioResult
from sentinel.evaluation.metrics import calculate_metrics

def generate_report(results: list[ScenarioResult], output_dir: str = "sentinel/evaluation"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    metrics = calculate_metrics(results)
    
    # Write JSON
    json_path = f"{output_dir}/results_{timestamp}.json"
    with open(json_path, 'w') as f:
        json.dump({
            "metrics": metrics,
            "results": [vars(r) for r in results]
        }, f, indent=2)
        
    # Write Markdown
    md_path = f"{output_dir}/report_{timestamp}.md"
    with open(md_path, 'w') as f:
        f.write("# Red-Team Evaluation Report\n\n")
        f.write("## Executive Summary\n")
        f.write(f"- **Total Scenarios:** {metrics.get('total_scenarios', 0)}\n")
        f.write(f"- **Overall Pass Rate:** {metrics.get('overall_pass_rate', 0):.1f}%\n")
        f.write(f"- **Guardrail Catch Rate:** {metrics.get('guardrail_catch_rate', 0):.1f}%\n")
        f.write(f"- **P95 Latency:** {metrics.get('latency_p95_ms', 0):.2f} ms\n\n")
        
        f.write("## Scenario Breakdown\n")
        f.write("| ID | Expected | Actual | Passed | Escalated |\n")
        f.write("|---|---|---|---|---|\n")
        for r in results:
            pass_str = "✅" if r.passed else "❌"
            esc_str = "🚨" if r.escalated else "-"
            f.write(f"| {r.scenario_id} | {r.expected_policy_outcome} | {r.actual_policy_outcome} | {pass_str} | {esc_str} |\n")
            
    return json_path, md_path
