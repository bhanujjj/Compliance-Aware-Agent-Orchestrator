import json
import sqlite3
import asyncio
import aiosqlite
from pathlib import Path
from datetime import datetime
from sentinel.models import AuditEvent
from sentinel.config.settings import settings

DB_PATH = settings.AUDIT_DB_PATH
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def _ensure_db_sync():
    """Create DB and run schema if it doesn't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=15000;")
        schema = SCHEMA_PATH.read_text()
        conn.executescript(schema)
        conn.commit()

def log_event_sync(event: AuditEvent) -> None:
    """Synchronous version — use in tests and sync contexts."""
    _ensure_db_sync()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO audit_log 
               (event_id, timestamp, incident_id, event_type, actor, payload, latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.timestamp.isoformat(),
                event.incident_id,
                event.event_type,
                event.actor,
                json.dumps(event.payload, default=str),
                event.latency_ms,
            )
        )
        conn.commit()

async def log_event(event: AuditEvent) -> None:
    """Async version — use inside async agent loop."""
    _ensure_db_sync()
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            """INSERT INTO audit_log 
               (event_id, timestamp, incident_id, event_type, actor, payload, latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.timestamp.isoformat(),
                event.incident_id,
                event.event_type,
                event.actor,
                json.dumps(event.payload, default=str),
                event.latency_ms,
            )
        )
        await conn.commit()

async def log_escalation(incident_id: str, severity: float, reason: str) -> None:
    """Write to human_queue table."""
    import uuid
    _ensure_db_sync()
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            """INSERT INTO human_queue (queue_id, incident_id, severity, reason)
               VALUES (?, ?, ?, ?)""",
            (str(uuid.uuid4()), incident_id, severity, reason)
        )
        await conn.commit()

def fetch_events_sync(incident_id: str = None, limit: int = 100) -> list[dict]:
    """Read audit_log rows for a given incident (used by dashboard and tests)."""
    _ensure_db_sync()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if incident_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE incident_id = ? ORDER BY timestamp ASC LIMIT ?",
                (incident_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

def log_execution_sync(db_path: str, incident_id: str, result) -> None:
    """
    Log an MCP ExecutionResult to the audit_log table.
    result: sentinel.models.ExecutionResult
    """
    import sqlite3, json
    from sentinel.models import AuditEvent
    event = AuditEvent(
        incident_id=incident_id,
        event_type="EXECUTION" if result.success else "PERMISSION_DENIED",
        actor="MCPGateway",
        payload={
            "tool_name": result.tool_name,
            "target": result.target,
            "success": result.success,
            "message": result.message,
            "permission_denied": result.permission_denied,
            "state_delta": result.state_delta,
        },
    )
    # The existing log_event_sync only takes the event object and uses global DB_PATH
    log_event_sync(event)
