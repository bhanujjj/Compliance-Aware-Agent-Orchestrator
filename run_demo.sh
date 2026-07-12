#!/bin/bash

echo "======================================================"
echo "🛡️ Starting Sentinel: Compliance-Aware Agent Orchestrator"
echo "======================================================"

echo "[1/3] Generating Mock Audit Data..."
# Clear old data if exists
rm -f data/audit.db
# Run the demo script to populate the DB
python sentinel/main.py

echo "[2/3] Building and starting Docker containers..."
docker-compose up --build -d

echo ""
echo "[3/3] 🚀 Sentinel is live!"
echo "➡️ Dashboard: http://localhost:5173"
echo "➡️ API Docs:  http://localhost:8000/docs"
echo ""
echo "To view live logs, run: docker-compose logs -f"
echo "To stop the demo, run:  docker-compose down"
echo "======================================================"
