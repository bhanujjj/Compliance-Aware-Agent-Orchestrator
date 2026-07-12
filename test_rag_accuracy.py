from sentinel.agents.threat_intel_agent import ThreatIntelAgent
from sentinel.models import Incident
import logging

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    # Ensure RAG index is active (use_stub=False)
    agent = ThreatIntelAgent(use_stub=False)
    
    # Mock Incident
    incident = Incident(
        attack_types={"SQL Injection"},
        src_ips=["192.168.1.100"],
        dst_ips=["10.0.0.5"],
        severity=7.5
    )
    
    # Map the incident
    result = agent.map_incident(incident)
    
    print("\n--- TEST RESULT ---")
    print("Attack Type: Brute Force -Web")
    print(f"Query Used: {result.query_used}\n")
    if result.best_match:
        print(f"Mapped Technique ID: {result.best_match.technique_id}")
        print(f"Mapped Technique Name: {result.best_match.technique_name}")
        print(f"Confidence: {result.best_match.confidence:.4f}")
    else:
        print("No match found.")
