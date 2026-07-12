# sentinel/gateway/mock_executor.py
"""
Mock Environment — in-memory simulation of the target network state.
Tracks:
  - blocked_ips:       set of currently blocked IP addresses
  - isolated_hosts:    set of currently isolated hostnames
  - killed_procs:      list of {hostname, pid, timestamp} dicts
  - revoked_sessions:  list of {user_id, session_id, timestamp} dicts
  - forensics_jobs:    list of {hostname, timestamp} dicts
All methods return ExecutionResult from sentinel/models.py.
"""
from dataclasses import dataclass, field
from datetime import datetime
from sentinel.models import ExecutionResult

class MockEnvironment:
    """Singleton-safe: import and call directly. Thread-safety not required for Phase 4."""
    def __init__(self):
        self.blocked_ips: set[str] = set()
        self.isolated_hosts: set[str] = set()
        self.killed_procs: list[dict] = []
        self.revoked_sessions: list[dict] = []
        self.forensics_jobs: list[dict] = []

    def block_ip(self, ip: str, reason: str) -> ExecutionResult:
        if ip in self.blocked_ips:
            return ExecutionResult(
                success=True,
                tool_name="block_ip",
                target=ip,
                message=f"IP {ip} was already blocked (idempotent).",
                state_delta={"already_blocked": True},
            )
        self.blocked_ips.add(ip)
        return ExecutionResult(
            success=True,
            tool_name="block_ip",
            target=ip,
            message=f"IP {ip} blocked at perimeter firewall. Reason: {reason}",
            state_delta={"blocked_ips_added": [ip]},
        )

    def isolate_host(self, hostname: str, reason: str) -> ExecutionResult:
        if hostname in self.isolated_hosts:
            return ExecutionResult(
                success=True,
                tool_name="isolate_host",
                target=hostname,
                message=f"Host {hostname} was already isolated (idempotent).",
                state_delta={"already_isolated": True},
            )
        self.isolated_hosts.add(hostname)
        return ExecutionResult(
            success=True,
            tool_name="isolate_host",
            target=hostname,
            message=f"Host {hostname} quarantined from network. Reason: {reason}",
            state_delta={"isolated_hosts_added": [hostname]},
        )

    def kill_process(self, hostname: str, pid: int) -> ExecutionResult:
        entry = {"hostname": hostname, "pid": pid, "timestamp": datetime.utcnow().isoformat()}
        self.killed_procs.append(entry)
        return ExecutionResult(
            success=True,
            tool_name="kill_process",
            target=f"{hostname}:{pid}",
            message=f"Process {pid} on {hostname} terminated.",
            state_delta={"killed_proc": entry},
        )

    def revoke_session(self, user_id: str, session_id: str) -> ExecutionResult:
        entry = {"user_id": user_id, "session_id": session_id,
                 "timestamp": datetime.utcnow().isoformat()}
        self.revoked_sessions.append(entry)
        return ExecutionResult(
            success=True,
            tool_name="revoke_session",
            target=user_id,
            message=f"Session {session_id} for user {user_id} revoked.",
            state_delta={"revoked_session": entry},
        )

    def collect_forensics(self, hostname: str) -> ExecutionResult:
        entry = {"hostname": hostname, "timestamp": datetime.utcnow().isoformat()}
        self.forensics_jobs.append(entry)
        return ExecutionResult(
            success=True,
            tool_name="collect_forensics",
            target=hostname,
            message=f"Forensics snapshot initiated for {hostname}.",
            state_delta={"forensics_job": entry},
        )

    def get_state_summary(self) -> dict:
        return {
            "blocked_ips": sorted(self.blocked_ips),
            "isolated_hosts": sorted(self.isolated_hosts),
            "killed_procs_count": len(self.killed_procs),
            "revoked_sessions_count": len(self.revoked_sessions),
            "forensics_jobs_count": len(self.forensics_jobs),
        }

    def reset(self):
        """Reset all state — useful between test runs."""
        self.blocked_ips.clear()
        self.isolated_hosts.clear()
        self.killed_procs.clear()
        self.revoked_sessions.clear()
        self.forensics_jobs.clear()

# Module-level singleton — import this in mcp_server.py and mcp_client.py
ENV = MockEnvironment()
