import pytest
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from sentinel.models import AuditEvent
from sentinel.audit.logger import log_event_sync, fetch_events_sync
import sentinel.audit.logger as logger_module

@pytest.fixture(autouse=True)
def setup_temp_db(tmp_path, monkeypatch):
    temp_db_path = tmp_path / "test_audit.db"
    monkeypatch.setattr(logger_module, "DB_PATH", temp_db_path)
    return temp_db_path

def test_log_event_sync_creates_db(setup_temp_db):
    assert not setup_temp_db.exists()
    event = AuditEvent(event_type="TEST")
    log_event_sync(event)
    assert setup_temp_db.exists()

def test_log_event_sync_writes_row(setup_temp_db):
    event = AuditEvent(incident_id="INC-TEST", event_type="PROPOSAL", actor="TestActor")
    log_event_sync(event)
    
    events = fetch_events_sync()
    assert len(events) == 1
    assert events[0]["incident_id"] == "INC-TEST"
    assert events[0]["event_type"] == "PROPOSAL"
    assert events[0]["actor"] == "TestActor"

def test_log_event_type_is_preserved(setup_temp_db):
    event = AuditEvent(event_type="REJECTION")
    log_event_sync(event)
    
    events = fetch_events_sync()
    assert len(events) == 1
    assert events[0]["event_type"] == "REJECTION"

def test_payload_is_json_serialized(setup_temp_db):
    test_payload = {"key1": "value1", "key2": 42}
    event = AuditEvent(event_type="INFO", payload=test_payload)
    log_event_sync(event)
    
    events = fetch_events_sync()
    stored_payload_str = events[0]["payload"]
    assert isinstance(stored_payload_str, str)
    
    loaded_payload = json.loads(stored_payload_str)
    assert loaded_payload == test_payload

def test_duplicate_event_id_raises(setup_temp_db):
    event = AuditEvent(event_type="INFO")
    log_event_sync(event)
    
    with pytest.raises(sqlite3.IntegrityError):
        # Re-using the same exact event_id
        log_event_sync(event)

def test_fetch_events_by_incident(setup_temp_db):
    log_event_sync(AuditEvent(incident_id="INC-A", event_type="PROPOSAL"))
    log_event_sync(AuditEvent(incident_id="INC-A", event_type="APPROVAL"))
    log_event_sync(AuditEvent(incident_id="INC-A", event_type="EXECUTION"))
    
    log_event_sync(AuditEvent(incident_id="INC-B", event_type="PROPOSAL"))
    log_event_sync(AuditEvent(incident_id="INC-B", event_type="APPROVAL"))
    
    events_a = fetch_events_sync("INC-A")
    assert len(events_a) == 3
    
    events_b = fetch_events_sync("INC-B")
    assert len(events_b) == 2
