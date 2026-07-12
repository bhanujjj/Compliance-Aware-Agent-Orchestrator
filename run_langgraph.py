import os
from sentinel.data.ingestion import RealDataIngestor
from sentinel.agents.investigation_agent import InvestigationAgent
from sentinel.orchestrator.runner import run_parallel
from sentinel.config.settings import settings

def main():
    print("=" * 60)
    print("🛡️  Sentinel LangGraph Orchestrator")
    print("=" * 60)
    
    # Step 1: Ingest real dataset
    csv_path = "data/IDS.csv"
    ingestor = RealDataIngestor(csv_path)
    alerts = ingestor.stream_alerts(multiplier=30)
    print(f"[1/3] Ingested {len(alerts)} malicious alerts from CIC-IDS2018")
    
    # Step 2: Cluster into incidents
    inv_agent = InvestigationAgent(window_seconds=3600)
    incidents = inv_agent.process_batch(alerts)
    print(f"[2/3] Investigation Agent formed {len(incidents)} incidents")
    
    # Step 3: Run full LangGraph parallel orchestration
    # Cap at 200 for a fast, clean demo run
    incidents_to_process = incidents[:200]
    print(f"[3/3] Launching LangGraph parallel orchestration on {len(incidents_to_process)} incidents...")
    print(f"      Workers: 16 | Retry limit: 3 per incident")
    print()
    
    results = run_parallel(incidents_to_process, max_workers=16)
    
    # Print summary
    statuses = {}
    for r in results:
        statuses[r["final_status"]] = statuses.get(r["final_status"], 0) + 1
    
    print()
    print("=" * 60)
    print("📊 LANGGRAPH ORCHESTRATION RESULTS")
    print("=" * 60)
    for status, count in sorted(statuses.items()):
        print(f"  {status:20s}: {count}")
    print(f"  {'TOTAL':20s}: {len(results)}")
    print()
    print("✅ Check your React dashboard at http://localhost:5173")
    print("🔍 Check LangSmith traces at https://smith.langchain.com")

if __name__ == "__main__":
    main()
