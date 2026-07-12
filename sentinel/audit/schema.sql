-- Sentinel audit log schema
-- Every proposal, rejection, approval, and escalation is a row here

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    timestamp       TEXT NOT NULL,              -- ISO 8601 UTC
    incident_id     TEXT,                       -- NULL for system events
    event_type      TEXT NOT NULL,              -- PROPOSAL | REJECTION | APPROVAL | ESCALATION | EXECUTION | ERROR
    actor           TEXT NOT NULL,              -- which agent/component fired this
    payload         TEXT NOT NULL,              -- JSON blob
    latency_ms      INTEGER,                    -- milliseconds, NULL if not applicable
    created_at      TEXT DEFAULT (datetime('now'))
);

-- Index for fast incident drill-down (dashboard use)
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

-- Human escalation queue
CREATE TABLE IF NOT EXISTS human_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_id        TEXT NOT NULL UNIQUE,
    incident_id     TEXT NOT NULL,
    severity        REAL NOT NULL,
    reason          TEXT NOT NULL,              -- why it was escalated
    status          TEXT DEFAULT 'PENDING',     -- PENDING | ACKNOWLEDGED | RESOLVED
    created_at      TEXT DEFAULT (datetime('now')),
    acknowledged_at TEXT
);
