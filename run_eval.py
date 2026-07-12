import sys
import os
from sentinel.evaluation.red_team import RedTeamRunner
from sentinel.evaluation.report import generate_report

def main():
    runner = RedTeamRunner("data/scenarios/adversarial.yaml")
    results = runner.run_all()
    json_path, md_path = generate_report(results)
    print(f"Generated {json_path} and {md_path}")
    
    with open(md_path, 'r') as f:
        print("\n--- REPORT ---")
        print(f.read())

if __name__ == "__main__":
    main()
