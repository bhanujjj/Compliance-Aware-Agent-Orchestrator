# sentinel/gateway/mcp_server.py
"""
Sentinel MCP Tool Gateway — FastMCP server exposing 5 cyber response tools.
RBAC: Each tool checks the caller's role before executing.
State: Delegates to MockEnvironment singleton (mock_executor.ENV).
Run standalone:
    python sentinel/gateway/mcp_server.py
Or import and call tools directly in tests (no network needed):
    from sentinel.gateway.mcp_server import mcp
    result = block_ip(ip="1.2.3.4", reason="test", role="tier1_analyst")
"""
from fastmcp import FastMCP
from sentinel.gateway.mock_executor import ENV
from sentinel.models import ExecutionResult

mcp = FastMCP("sentinel-gateway")

# ── RBAC ─────────────────────────────────────────────────────────────────────
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "tier1_analyst": ["block_ip", "revoke_session"],
    "tier2_analyst": ["block_ip", "revoke_session", "isolate_host", "kill_process"],
    "tier3_analyst": ["block_ip", "revoke_session", "isolate_host", "kill_process",
                       "collect_forensics"],
}

def _check_permission(tool_name: str, role: str) -> None:
    """Raise PermissionError if role is not permitted to call tool_name."""
    allowed = ROLE_PERMISSIONS.get(role, [])
    if tool_name not in allowed:
        raise PermissionError(
            f"Role '{role}' is not permitted to call '{tool_name}'. "
            f"Permitted actions: {allowed}"
        )

def _exec_result_to_dict(result: ExecutionResult) -> dict:
    return {
        "success": result.success,
        "tool_name": result.tool_name,
        "target": result.target,
        "message": result.message,
        "state_delta": result.state_delta,
        "permission_denied": result.permission_denied,
    }

# ── Tools ─────────────────────────────────────────────────────────────────────
@mcp.tool()
def block_ip(ip: str, reason: str, role: str) -> dict:
    """Block an IP address at the perimeter firewall."""
    _check_permission("block_ip", role)
    result = ENV.block_ip(ip, reason)
    return _exec_result_to_dict(result)

@mcp.tool()
def isolate_host(hostname: str, reason: str, role: str) -> dict:
    """Quarantine a host by cutting it off from the network."""
    _check_permission("isolate_host", role)
    result = ENV.isolate_host(hostname, reason)
    return _exec_result_to_dict(result)

@mcp.tool()
def kill_process(hostname: str, pid: int, role: str) -> dict:
    """Terminate a running process on a host."""
    _check_permission("kill_process", role)
    result = ENV.kill_process(hostname, pid)
    return _exec_result_to_dict(result)

@mcp.tool()
def revoke_session(user_id: str, session_id: str, role: str) -> dict:
    """Revoke an active user authentication session."""
    _check_permission("revoke_session", role)
    result = ENV.revoke_session(user_id, session_id)
    return _exec_result_to_dict(result)

@mcp.tool()
def collect_forensics(hostname: str, role: str) -> dict:
    """Capture a memory and disk snapshot for forensic analysis."""
    _check_permission("collect_forensics", role)
    result = ENV.collect_forensics(hostname)
    return _exec_result_to_dict(result)

if __name__ == "__main__":
    mcp.run()
