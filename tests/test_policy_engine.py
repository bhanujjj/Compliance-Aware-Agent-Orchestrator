"""
tests/test_policy_engine.py
Comprehensive pytest unit tests for sentinel/policy/engine.py.

Coverage targets: every branch of evaluate() and get_severity_tier().
No mocking of LLMs — engine is pure Python / YAML.
"""

import pytest

from sentinel.models import Incident, PolicyDecision, ProposedAction
from sentinel.policy.engine import evaluate, get_severity_tier

# ---------------------------------------------------------------------------
# Fixtures — reusable base objects
# ---------------------------------------------------------------------------


def _incident(severity: float = 5.0) -> Incident:
    """Return a minimal Incident with the given severity score."""
    return Incident(severity=severity)


def _action(action_type: str = "block_ip", role: str = "tier1_analyst") -> ProposedAction:
    """Return a minimal ProposedAction."""
    return ProposedAction(action_type=action_type, role=role)


# ---------------------------------------------------------------------------
# 1. Action allowlist rejection
# ---------------------------------------------------------------------------


def test_allowlist_rejection():
    """An action not in the allowlist must be rejected with violated_rule='action_allowlist'."""
    action = _action(action_type="nuke_server", role="tier3_analyst")
    incident = _incident(severity=5.0)

    decision = evaluate(action, incident)

    assert decision.approved is False
    assert decision.violated_rule == "action_allowlist"
    assert "nuke_server" in decision.reason


# ---------------------------------------------------------------------------
# 2. Role permission rejection
# ---------------------------------------------------------------------------


def test_role_permission_rejection():
    """tier1_analyst is not allowed to isolate_host — must be rejected."""
    action = _action(action_type="isolate_host", role="tier1_analyst")
    incident = _incident(severity=5.0)

    decision = evaluate(action, incident)

    assert decision.approved is False
    assert decision.violated_rule == "role_permission"
    # Reason must name both the role and the action
    assert "tier1_analyst" in decision.reason
    assert "isolate_host" in decision.reason


# ---------------------------------------------------------------------------
# 3. Role permission approval
# ---------------------------------------------------------------------------


def test_role_permission_approval():
    """tier1_analyst IS allowed to block_ip — must be approved (at low severity)."""
    action = _action(action_type="block_ip", role="tier1_analyst")
    incident = _incident(severity=2.0)  # low severity, no escalation

    decision = evaluate(action, incident)

    assert decision.approved is True
    assert decision.violated_rule is None
    assert decision.escalate is False


# ---------------------------------------------------------------------------
# 4. Blast radius — isolate_host rejection
# ---------------------------------------------------------------------------


def test_blast_radius_isolation_rejection():
    """When isolated_host_count == 3 (the limit), further isolation must be rejected."""
    action = _action(action_type="isolate_host", role="tier2_analyst")
    incident = _incident(severity=5.0)
    env_state = {"isolated_host_count": 3}  # already at limit

    decision = evaluate(action, incident, env_state=env_state)

    assert decision.approved is False
    assert decision.violated_rule == "blast_radius"
    assert "3" in decision.reason  # mentions current count


# ---------------------------------------------------------------------------
# 5. Blast radius — isolate_host approval when under limit
# ---------------------------------------------------------------------------


def test_blast_radius_isolation_approval():
    """When isolated_host_count is 0, isolate_host by tier2_analyst must be approved."""
    action = _action(action_type="isolate_host", role="tier2_analyst")
    incident = _incident(severity=5.0)
    env_state = {"isolated_host_count": 0}

    decision = evaluate(action, incident, env_state=env_state)

    assert decision.approved is True
    assert decision.escalate is False


# ---------------------------------------------------------------------------
# 6. Critical severity triggers escalation (but action itself valid)
# ---------------------------------------------------------------------------


def test_critical_severity_escalates():
    """Severity 9.5 exceeds the 8.0 threshold → approved=True but escalate=True."""
    action = _action(action_type="block_ip", role="tier1_analyst")
    incident = _incident(severity=9.5)

    decision = evaluate(action, incident)

    assert decision.approved is True
    assert decision.escalate is True
    assert decision.violated_rule is None


# ---------------------------------------------------------------------------
# 7. High severity (7.0) — below threshold, no escalation
# ---------------------------------------------------------------------------


def test_high_severity_no_escalation():
    """Severity 7.0 is below the 8.0 escalation threshold — should be approved without escalation."""
    action = _action(action_type="block_ip", role="tier2_analyst")
    incident = _incident(severity=7.0)

    decision = evaluate(action, incident)

    assert decision.approved is True
    assert decision.escalate is False


# ---------------------------------------------------------------------------
# 8. Unknown role rejection
# ---------------------------------------------------------------------------


def test_unknown_role_rejection():
    """A role not defined in the YAML config must be rejected with violated_rule='unknown_role'."""
    action = _action(action_type="block_ip", role="intern")
    incident = _incident(severity=3.0)

    decision = evaluate(action, incident)

    assert decision.approved is False
    assert decision.violated_rule == "unknown_role"
    assert "intern" in decision.reason


# ---------------------------------------------------------------------------
# 9. Rejection reason is human-readable (non-trivially long string)
# ---------------------------------------------------------------------------


def test_reason_is_human_readable():
    """Every rejection PolicyDecision must carry a non-empty, descriptive reason string."""
    test_cases = [
        (_action(action_type="nuke_server", role="tier3_analyst"), _incident(5.0), None),
        (_action(action_type="isolate_host", role="tier1_analyst"), _incident(5.0), None),
        (_action(action_type="block_ip", role="intern"), _incident(3.0), None),
        (
            _action(action_type="isolate_host", role="tier2_analyst"),
            _incident(5.0),
            {"isolated_host_count": 3},
        ),
    ]

    for action, incident, env_state in test_cases:
        decision = evaluate(action, incident, env_state=env_state)
        assert isinstance(decision.reason, str), "reason must be a str"
        assert len(decision.reason) > 10, (
            f"reason too short ({len(decision.reason)} chars): '{decision.reason}'"
        )
        assert decision.approved is False


# ---------------------------------------------------------------------------
# 10. get_severity_tier — all four tiers
# ---------------------------------------------------------------------------


def test_get_severity_tier():
    """Verify tier classification across boundary values."""
    # Load tiers from config to use real values (avoids hard-coding here)
    from sentinel.policy.engine import _load_config

    tiers = _load_config()["severity_tiers"]

    assert get_severity_tier(1.0, tiers) == "low"
    assert get_severity_tier(5.0, tiers) == "medium"
    assert get_severity_tier(7.5, tiers) == "high"
    assert get_severity_tier(9.0, tiers) == "critical"

    # Boundary edge cases
    assert get_severity_tier(3.0, tiers) == "low"    # exactly at low boundary
    assert get_severity_tier(3.1, tiers) == "medium"  # just above low boundary
    assert get_severity_tier(6.0, tiers) == "medium"  # exactly at medium boundary
    assert get_severity_tier(8.0, tiers) == "high"    # exactly at high boundary
    assert get_severity_tier(8.1, tiers) == "critical"  # just above high boundary


# ---------------------------------------------------------------------------
# Bonus: Blast radius IP block limit per role
# ---------------------------------------------------------------------------


def test_blast_radius_ip_block_tier1_limit():
    """tier1_analyst has max_ips_blocked_per_incident=5; at 5 already blocked, must reject."""
    action = _action(action_type="block_ip", role="tier1_analyst")
    incident = _incident(severity=2.0)
    env_state = {"ips_blocked_count": 5}  # at the limit for tier1

    decision = evaluate(action, incident, env_state=env_state)

    assert decision.approved is False
    assert decision.violated_rule == "blast_radius_ip"
    assert "tier1_analyst" in decision.reason


def test_blast_radius_ip_block_env_state_none():
    """When env_state is None, ips_blocked_count defaults to 0 — should not trigger blast radius."""
    action = _action(action_type="block_ip", role="tier2_analyst")
    incident = _incident(severity=2.0)

    decision = evaluate(action, incident, env_state=None)

    assert decision.approved is True
    assert decision.escalate is False


def test_escalation_threshold_exactly_at_boundary():
    """Severity exactly at 8.0 (the threshold) must escalate."""
    action = _action(action_type="block_ip", role="tier2_analyst")
    incident = _incident(severity=8.0)

    decision = evaluate(action, incident)

    assert decision.approved is True
    assert decision.escalate is True


def test_collect_forensics_tier3_approval():
    """collect_forensics is only allowed for tier3_analyst — should approve at low severity."""
    action = _action(action_type="collect_forensics", role="tier3_analyst")
    incident = _incident(severity=2.0)

    decision = evaluate(action, incident)

    assert decision.approved is True
    assert decision.escalate is False


def test_collect_forensics_tier2_rejection():
    """collect_forensics is NOT in tier2_analyst allowed_actions — must reject."""
    action = _action(action_type="collect_forensics", role="tier2_analyst")
    incident = _incident(severity=2.0)

    decision = evaluate(action, incident)

    assert decision.approved is False
    assert decision.violated_rule == "role_permission"
