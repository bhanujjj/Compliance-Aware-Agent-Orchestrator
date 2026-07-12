# sentinel/gateway/mcp_client.py
"""
Sentinel MCP Client — agent-side wrapper for calling MCP tools.
Phase 4: Calls tool functions directly (in-process).
Phase 7 upgrade: swap _call_tool to use httpx over SSE transport.
Usage:
    from sentinel.gateway.mcp_client import MCPClient
    client = MCPClient(role="tier1_analyst")
    result = client.execute(action_type="block_ip", target="1.2.3.4",
                            reason="DDoS source", extra_params={})
"""
from sentinel.models import ProposedAction, ExecutionResult
import sentinel.gateway.mcp_server as _server

# Map action_type string → the actual tool function in mcp_server
_TOOL_MAP = {
    "block_ip":        _server.block_ip,
    "isolate_host":    _server.isolate_host,
    "kill_process":    _server.kill_process,
    "revoke_session":  _server.revoke_session,
    "collect_forensics": _server.collect_forensics,
}

class MCPClient:
    """
    Agent-side MCP client. Wraps tool calls with permission error handling
    and converts dicts back to ExecutionResult objects.
    """
    def __init__(self, role: str = "tier1_analyst"):
        self.role = role

    def execute(self, action: ProposedAction) -> ExecutionResult:
        """
        Execute a ProposedAction through the MCP gateway.
        Returns ExecutionResult with permission_denied=True if the role
        lacks permission (PermissionError is caught, not re-raised).
        """
        tool_fn = _TOOL_MAP.get(action.action_type)
        if tool_fn is None:
            return ExecutionResult(
                success=False,
                tool_name=action.action_type,
                target=action.target,
                message=f"Unknown tool '{action.action_type}' — not registered in gateway.",
                permission_denied=False,
            )

        try:
            result_dict = self._call_tool(tool_fn, action)
            return ExecutionResult(
                success=result_dict.get("success", False),
                tool_name=result_dict.get("tool_name", action.action_type),
                target=result_dict.get("target", action.target),
                message=result_dict.get("message", ""),
                state_delta=result_dict.get("state_delta", {}),
                permission_denied=False,
            )
        except PermissionError as e:
            return ExecutionResult(
                success=False,
                tool_name=action.action_type,
                target=action.target,
                message=str(e),
                permission_denied=True,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                tool_name=action.action_type,
                target=action.target,
                message=f"Unexpected error: {e}",
            )

    def _call_tool(self, tool_fn, action: ProposedAction) -> dict:
        """
        Route action to the correct tool function with correct args.
        Extends action.extra_params into the call where applicable.
        """
        tool_name = action.action_type
        extra = action.extra_params or {}

        if tool_name == "block_ip":
            return tool_fn(ip=action.target, reason=action.reason, role=self.role)
        elif tool_name == "isolate_host":
            return tool_fn(hostname=action.target, reason=action.reason, role=self.role)
        elif tool_name == "kill_process":
            pid = extra.get("pid", 0)
            return tool_fn(hostname=action.target, pid=int(pid), role=self.role)
        elif tool_name == "revoke_session":
            session_id = extra.get("session_id", "unknown-session")
            return tool_fn(user_id=action.target, session_id=session_id, role=self.role)
        elif tool_name == "collect_forensics":
            return tool_fn(hostname=action.target, role=self.role)
        else:
            raise ValueError(f"Unhandled tool: {tool_name}")
