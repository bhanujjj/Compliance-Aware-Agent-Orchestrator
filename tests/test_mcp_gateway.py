# tests/test_mcp_gateway.py
import pytest

from sentinel.gateway.mock_executor import MockEnvironment
from sentinel.gateway import mcp_server as server
from sentinel.gateway.mcp_client import MCPClient
from sentinel.models import ProposedAction, ExecutionResult

@pytest.fixture(autouse=True)
def reset_env():
    """Reset MockEnvironment state before each test."""
    from sentinel.gateway.mock_executor import ENV
    ENV.reset()
    yield
    ENV.reset()

# ── MockEnvironment tests ─────────────────────────────────────────────────────

def test_block_ip_adds_to_state():
    env = MockEnvironment()
    result = env.block_ip("1.2.3.4", "test")
    assert result.success is True
    assert "1.2.3.4" in env.blocked_ips

def test_block_ip_idempotent():
    env = MockEnvironment()
    env.block_ip("1.2.3.4", "test")
    result = env.block_ip("1.2.3.4", "test again")
    assert result.success is True
    assert result.state_delta.get("already_blocked") is True
    assert len(env.blocked_ips) == 1  # not added twice

def test_isolate_host_adds_to_state():
    env = MockEnvironment()
    result = env.isolate_host("web-01", "DDoS source")
    assert result.success is True
    assert "web-01" in env.isolated_hosts

def test_kill_process_appends_entry():
    env = MockEnvironment()
    result = env.kill_process("host-02", 1234)
    assert result.success is True
    assert len(env.killed_procs) == 1
    assert env.killed_procs[0]["pid"] == 1234

def test_revoke_session_appends_entry():
    env = MockEnvironment()
    result = env.revoke_session("user-99", "sess-abc")
    assert result.success is True
    assert len(env.revoked_sessions) == 1

def test_collect_forensics_appends_entry():
    env = MockEnvironment()
    result = env.collect_forensics("server-42")
    assert result.success is True
    assert len(env.forensics_jobs) == 1

def test_reset_clears_all_state():
    env = MockEnvironment()
    env.block_ip("1.1.1.1", "x")
    env.isolate_host("h1", "x")
    env.reset()
    assert len(env.blocked_ips) == 0
    assert len(env.isolated_hosts) == 0

# ── MCP Server RBAC tests ─────────────────────────────────────────────────────

def test_tier1_can_block_ip():
    result = server.block_ip(ip="5.5.5.5", reason="test", role="tier1_analyst")
    assert result["success"] is True

def test_tier1_cannot_isolate_host():
    with pytest.raises(PermissionError):
        server.isolate_host(hostname="host-01", reason="test", role="tier1_analyst")

def test_tier2_can_isolate_host():
    result = server.isolate_host(hostname="host-01", reason="test", role="tier2_analyst")
    assert result["success"] is True

def test_tier2_cannot_collect_forensics():
    with pytest.raises(PermissionError):
        server.collect_forensics(hostname="host-01", role="tier2_analyst")

def test_tier3_can_collect_forensics():
    result = server.collect_forensics(hostname="host-99", role="tier3_analyst")
    assert result["success"] is True

def test_unknown_role_cannot_do_anything():
    with pytest.raises(PermissionError):
        server.block_ip(ip="1.1.1.1", reason="x", role="intern")

def test_kill_process_tier2():
    result = server.kill_process(hostname="host-01", pid=9999, role="tier2_analyst")
    assert result["success"] is True

def test_revoke_session_tier1():
    result = server.revoke_session(user_id="usr-1", session_id="s-1", role="tier1_analyst")
    assert result["success"] is True

# ── MCP Client tests ──────────────────────────────────────────────────────────

def _action(action_type, target="1.2.3.4", role="tier1_analyst", extra=None):
    return ProposedAction(
        action_type=action_type,
        target=target,
        reason="test",
        role=role,
        extra_params=extra or {},
    )

def test_client_execute_block_ip_success():
    client = MCPClient(role="tier1_analyst")
    result = client.execute(_action("block_ip"))
    assert isinstance(result, ExecutionResult)
    assert result.success is True
    assert result.permission_denied is False

def test_client_permission_denied_returns_execution_result_not_raise():
    client = MCPClient(role="tier1_analyst")
    result = client.execute(_action("isolate_host", target="host-01"))
    assert result.success is False
    assert result.permission_denied is True
    assert "not permitted" in result.message

def test_client_unknown_tool_returns_failure():
    client = MCPClient(role="tier1_analyst")
    result = client.execute(_action("nuke_everything"))
    assert result.success is False
    assert result.permission_denied is False

def test_client_kill_process_with_pid():
    client = MCPClient(role="tier2_analyst")
    result = client.execute(_action("kill_process", target="host-02",
                                    role="tier2_analyst", extra={"pid": 4242}))
    assert result.success is True

def test_client_revoke_session():
    client = MCPClient(role="tier1_analyst")
    result = client.execute(_action("revoke_session", target="user-1",
                                    extra={"session_id": "sess-xyz"}))
    assert result.success is True

def test_client_collect_forensics_tier3():
    client = MCPClient(role="tier3_analyst")
    result = client.execute(_action("collect_forensics", target="server-1",
                                    role="tier3_analyst"))
    assert result.success is True
