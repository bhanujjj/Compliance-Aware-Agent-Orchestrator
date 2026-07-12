# Sentinel: Compliance-Aware Agent Orchestrator

Sentinel is an advanced AI Agent Orchestration Framework designed with strict deterministic compliance, policy enforcement, and red-team validated safety guardrails. It enables multiple AI subagents to collaborate on security incident response while guaranteeing zero violations of organizational boundaries.

## 🌟 Key Features

* **Deterministic Policy Engine:** An impenetrable, deterministic policy engine (`sentinel/policy/engine.py`) that operates outside the LLM context to enforce strict Role-Based Access Control (RBAC), host-isolation blast radius limits, and mandatory escalation protocols.
* **Agentic Orchestration:**
  * **Investigation Agent:** Ingests live streams of network alerts, performs sliding-window clustering, and forms structured `Incident` objects.
  * **Threat Intel Agent:** Maps incidents directly to MITRE ATT&CK techniques using a RAG-powered retrieval architecture over ChromaDB.
  * **Response Agent:** Autonomously proposes remediation actions (e.g., `block_ip`, `isolate_host`) based on threat intelligence.
  * **Escalation Agent:** Intelligently drops incidents into a Human-In-The-Loop (HITL) queue when severity thresholds are breached.
* **Red-Team Evaluated:** Scored against 27 dynamic adversarial scenarios to guarantee a >95% Guardrail Catch Rate on overreactions, role violations, and unauthorized execution.
* **Full-Stack Visualization:** A FastAPI backend seamlessly feeding a beautiful React/Vite dashboard to track the live governance feed, execution audit logs, and system metrics.

## 🏗️ Architecture

```text
Alert Stream 
   ↓
[ Investigation Agent ] → Clusters into Incidents
   ↓
[ Threat Intel Agent ]  → RAG Mapping (MITRE)
   ↓
[ Response Agent ]      → Proposes Action (e.g., block_ip)
   ↓
[ POLICY ENGINE ]       → Hardcoded Rules, Limits, and RBAC
   ├─ [ Rejected ]      → Response Agent retries OR drops
   ├─ [ Escalated ]     → [ Human Queue ]
   └─ [ Approved ]      → [ MCP Gateway ] → Execution
```

## 🚀 Quickstart / Demo

You can spin up the entire framework (Mock Data Generator + FastAPI Backend + React Dashboard) with a single command!

### Prerequisites
* Python 3.12+
* Node.js 20+
* Docker & Docker Compose (Optional, but recommended)

### Running with Docker (Recommended)
We've provided a simple bash script that clears out the old database, generates fresh AI audit data using the core Python engine, and spins up the UI in Docker containers.

```bash
chmod +x run_demo.sh
./run_demo.sh
```

**Services:**
* **Dashboard:** [http://localhost:5173](http://localhost:5173)
* **API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

### Stopping the Demo
```bash
docker-compose down
```

## 🛠️ Project Structure

* `/sentinel/agents/` — The AI Orchestration agents.
* `/sentinel/policy/` — The deterministic, rule-based policy engine.
* `/sentinel/gateway/` — The Model Context Protocol (MCP) tool execution boundary.
* `/sentinel/evaluation/` — The Red-Team simulation engine and adversarial dataset.
* `/sentinel/api/` — FastAPI backend exposing the SQLite audit logs to the UI.
* `/sentinel/dashboard/ui/` — The React + Vite frontend dashboard.
* `data/` — Local SQLite databases and JSON metric exports.
