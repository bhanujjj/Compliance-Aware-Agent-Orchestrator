import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.data.ingestion import RealDataIngestor
from sentinel.agents.investigation_agent import InvestigationAgent
from sentinel.agents.threat_intel_agent import ThreatIntelAgent

ingestor = RealDataIngestor("data/IDS.csv")
alerts = ingestor.stream_alerts(multiplier=1)[:50000] # Only first 50K alerts
print(f"Loaded {len(alerts)} alerts.")

agent = InvestigationAgent(window_seconds=3600)
incidents = agent.process_batch(alerts)
print(f"Clustered into {len(incidents)} incidents.")

sample = incidents[:20]

intel_agent = ThreatIntelAgent(top_k=1, use_stub=False)

print(f"{'Attack Types':<40} | {'Mapped Technique':<40}")
print("-" * 85)
correct = 0
for inc in sample:
    res = intel_agent.map_incident(inc)
    attack_str = ", ".join(inc.attack_types)
    if res.best_match:
        tech = f"{res.best_match.technique_id} ({res.best_match.technique_name})"
    else:
        tech = "None"
        
    print(f"{attack_str:<40} | {tech:<40}")

