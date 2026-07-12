"""
Investigation Agent — clusters related raw alerts into Incident objects.
Grouping key: (src_ip)
Window:       configurable, default 60 seconds
Logic:        sliding window — if alert.src_ip matches an open incident AND
              alert.timestamp - incident.created_at < window_seconds → append.
              Otherwise → open new Incident.
"""
from datetime import datetime, timedelta
from typing import Iterator
from sentinel.models import Alert, Incident
from sentinel.logging_config import get_logger

_log = get_logger("InvestigationAgent")

class InvestigationAgent:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # open incidents keyed by src_ip
        self._open: dict[str, Incident] = {}
        self._closed: list[Incident] = []

    def ingest(self, alert: Alert) -> None:
        """
        Feed one alert into the clustering engine.
        Modifies internal state; call get_closed_incidents() to retrieve
        finalized incidents, or finalize_all() at the end of a batch.
        """
        if not alert.src_ip:
            return  # skip alerts with no source IP
            
        now = alert.timestamp
        existing = self._open.get(alert.src_ip)
        
        if existing is not None:
            elapsed = (now - existing.created_at).total_seconds()
            if elapsed <= self.window_seconds:
                # Append to existing incident
                self._append_alert(existing, alert)
                return
            else:
                # Window expired — close and start new
                self._close_incident(alert.src_ip)
                
        # Open a new incident
        if alert.attack_type != "BENIGN":
            inc = Incident(
                created_at=now,
                src_ips=[alert.src_ip],
                dst_ips=[alert.dst_ip] if alert.dst_ip else [],
                attack_types={alert.attack_type},
                severity=alert.severity_score,
                host_count=1,
            )
            inc.alerts.append(alert)
            self._open[alert.src_ip] = inc

    def _append_alert(self, incident: Incident, alert: Alert) -> None:
        incident.alerts.append(alert)
        if alert.src_ip and alert.src_ip not in incident.src_ips:
            incident.src_ips.append(alert.src_ip)
        if alert.dst_ip and alert.dst_ip not in incident.dst_ips:
            incident.dst_ips.append(alert.dst_ip)
        if alert.attack_type and alert.attack_type != "BENIGN":
            incident.attack_types.add(alert.attack_type)
        incident.severity = max(incident.severity, alert.severity_score)
        incident.host_count = len(set(incident.dst_ips))

    def _close_incident(self, src_ip: str) -> None:
        inc = self._open.pop(src_ip, None)
        if inc:
            inc.summary = _generate_summary(inc)
            self._closed.append(inc)
            _log.info("incident_closed", incident_id=inc.incident_id[:8], 
                      attack_types=list(inc.attack_types), severity=inc.severity,
                      alert_count=len(inc.alerts))

    def finalize_all(self) -> list[Incident]:
        """Close all open incidents and return the complete list."""
        for src_ip in list(self._open.keys()):
            self._close_incident(src_ip)
        return self._closed

    def get_closed_incidents(self) -> list[Incident]:
        """Return incidents that have been closed (window expired)."""
        return list(self._closed)

    def process_batch(self, alerts: list[Alert]) -> list[Incident]:
        """
        Convenience method: feed all alerts, finalize, return incidents.
        Resets internal state after each call — safe to call multiple times.
        """
        self._open = {}
        self._closed = []
        for alert in alerts:
            self.ingest(alert)
        return self.finalize_all()

    @property
    def open_count(self) -> int:
        return len(self._open)

    @property
    def closed_count(self) -> int:
        return len(self._closed)

def _generate_summary(incident: Incident) -> str:
    attack_str = ", ".join(sorted(incident.attack_types)) or "Unknown"
    src_str = ", ".join(incident.src_ips[:3])
    if len(incident.src_ips) > 3:
        src_str += f" (+{len(incident.src_ips)-3} more)"
    return (
        f"{attack_str} detected from {src_str} "
        f"targeting {incident.host_count} host(s). "
        f"Severity: {incident.severity:.1f}/10. "
        f"Alert count: {len(incident.alerts)}."
    )
