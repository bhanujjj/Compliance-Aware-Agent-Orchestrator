"""
sentinel/policy/engine.py
Deterministic Policy Engine for Sentinel — the cyber incident response governance framework.

Evaluates a ProposedAction against the YAML-defined policy rules and returns a PolicyDecision.
No LLM calls. No randomness. 100% rule-based.
"""

from __future__ import annotations

import pathlib
from functools import lru_cache
from typing import Optional

import yaml

from sentinel.models import Incident, PolicyDecision, ProposedAction
from sentinel.logging_config import get_logger

_log = get_logger("PolicyEngine")

# ---------------------------------------------------------------------------
# Config loader — loaded once at module import time (or first call via lru_cache)
# ---------------------------------------------------------------------------

_CONFIG_PATH = (
    pathlib.Path(__file__).parent.parent / "config" / "policy_cyber.yaml"
)


@lru_cache(maxsize=1)
def _load_config() -> dict:
    """Load and cache the YAML policy config. Raises FileNotFoundError if missing."""
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Policy config not found at: {_CONFIG_PATH}. "
            "Ensure sentinel/config/policy_cyber.yaml exists."
        )
    with _CONFIG_PATH.open("r") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_severity_tier(severity_score: float, tiers_config: dict) -> str:
    """Return 'low', 'medium', 'high', or 'critical' based on score."""
    if severity_score <= tiers_config["low"]["max_score"]:
        return "low"
    elif severity_score <= tiers_config["medium"]["max_score"]:
        return "medium"
    elif severity_score <= tiers_config["high"]["max_score"]:
        return "high"
    else:
        return "critical"


# ---------------------------------------------------------------------------
# Core evaluation function
# ---------------------------------------------------------------------------


def evaluate(
    proposed_action: ProposedAction,
    incident: Incident,
    env_state: Optional[dict] = None,
) -> PolicyDecision:
    """
    Evaluate a proposed action against the loaded YAML policy.

    Checks (in order):
      1. Action allowlist
      2. Role permission
      3. Blast radius — isolate_host
      4. Blast radius — block_ip
      5. Severity / escalation threshold
      6. All passed → approve

    Args:
        proposed_action: The action the Response Agent wants to execute.
        incident: The active incident context.
        env_state: Live environment counters (isolated_host_count, ips_blocked_count, etc.).
                   Defaults to empty dict if None.

    Returns:
        PolicyDecision with approved/escalate flags, human-readable reason, and violated_rule.
    """
    config = _load_config()

    # -----------------------------------------------------------------------
    # 1. ACTION ALLOWLIST CHECK
    # -----------------------------------------------------------------------
    if proposed_action.action_type not in config["action_allowlist"]:
        decision = PolicyDecision(
            approved=False,
            reason=(
                f"Action '{proposed_action.action_type}' is not in the permitted action allowlist. "
                f"Allowed actions are: {config['action_allowlist']}."
            ),
            violated_rule="action_allowlist",
        )
        _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
        return decision

    # -----------------------------------------------------------------------
    # 2. ROLE PERMISSION CHECK
    # -----------------------------------------------------------------------
    role_cfg = config["roles"].get(proposed_action.role)

    if role_cfg is None:
        decision = PolicyDecision(
            approved=False,
            reason=(
                f"Unknown role '{proposed_action.role}'. "
                f"Valid roles are: {list(config['roles'].keys())}."
            ),
            violated_rule="unknown_role",
        )
        _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
        return decision

    if proposed_action.action_type not in role_cfg["allowed_actions"]:
        decision = PolicyDecision(
            approved=False,
            reason=(
                f"Role '{proposed_action.role}' is not permitted to call "
                f"'{proposed_action.action_type}'. "
                f"Permitted actions for this role: {role_cfg['allowed_actions']}."
            ),
            violated_rule="role_permission",
        )
        _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
        return decision

    # -----------------------------------------------------------------------
    # 3. OVERREACTION CHECK
    # -----------------------------------------------------------------------
    if incident.severity < 4.0 and proposed_action.action_type == "isolate_host":
        decision = PolicyDecision(
            approved=False,
            reason=(
                f"Action '{proposed_action.action_type}' is too disruptive for a "
                f"low severity ({incident.severity}) incident."
            ),
            violated_rule="overreaction",
        )
        _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
        return decision

    # -----------------------------------------------------------------------
    # 4. BLAST RADIUS CHECK — isolate_host
    # -----------------------------------------------------------------------
    if proposed_action.action_type == "isolate_host":
        target_count = len(incident.dst_ips) if incident.dst_ips else 1
        
        # Check role-specific limit
        role_max = role_cfg.get("max_hosts_per_action", 999)
        if target_count > role_max:
            decision = PolicyDecision(
                approved=False,
                reason=(
                    f"Role '{proposed_action.role}' can isolate max {role_max} hosts at once, "
                    f"but action targets {target_count} hosts."
                ),
                violated_rule="role_blast_radius",
            )
            _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
            return decision
            
        # Check global environment limit
        current_isolations = env_state.get("isolated_host_count", 0) if env_state else 0
        max_isolations = config["blast_radius"]["max_concurrent_isolations"]
        if current_isolations + target_count > max_isolations:
            decision = PolicyDecision(
                approved=False,
                reason=(
                    f"Blast radius limit reached: {current_isolations} hosts already isolated. "
                    f"Adding {target_count} exceeds maximum of {max_isolations}."
                ),
                violated_rule="blast_radius",
            )
            _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
            return decision

    # -----------------------------------------------------------------------
    # 5. BLAST RADIUS CHECK — block_ip
    # -----------------------------------------------------------------------
    if proposed_action.action_type == "block_ip":
        target_count = len(incident.src_ips) if incident.src_ips else 1
        ips_blocked = env_state.get("ips_blocked_count", 0) if env_state else 0
        role_limit = role_cfg.get("max_ips_blocked_per_incident", 999)
        
        if ips_blocked + target_count > role_limit:
            decision = PolicyDecision(
                approved=False,
                reason=(
                    f"IP block limit reached for role '{proposed_action.role}': "
                    f"{ips_blocked} IPs already blocked + {target_count} new exceeds limit {role_limit}."
                ),
                violated_rule="blast_radius_ip",
            )
            _log.warning("policy_rejected", action=proposed_action.action_type, role=proposed_action.role, rule=decision.violated_rule, reason=decision.reason)
            return decision

    # -----------------------------------------------------------------------
    # 5. SEVERITY / ESCALATION CHECK
    # -----------------------------------------------------------------------
    escalate = incident.severity >= config["escalation"]["severity_threshold"]
    severity_tier = get_severity_tier(incident.severity, config["severity_tiers"])
    tier_requires_human = config["severity_tiers"][severity_tier]["requires_human"]

    if tier_requires_human or escalate:
        decision = PolicyDecision(
            approved=True,  # action itself may be valid, but still needs human authorization
            reason=(
                f"Incident severity {incident.severity} exceeds escalation threshold "
                f"({config['escalation']['severity_threshold']}). Action is policy-compliant but "
                f"routed to human for authorization before execution."
            ),
            escalate=True,
            violated_rule=None,
        )
        _log.info("policy_approved", action=proposed_action.action_type, role=proposed_action.role, escalate=True, severity=incident.severity)
        return decision

    # -----------------------------------------------------------------------
    # 6. ALL CHECKS PASSED — approve
    # -----------------------------------------------------------------------
    decision = PolicyDecision(
        approved=True,
        reason=(
            f"Action '{proposed_action.action_type}' approved for role '{proposed_action.role}' "
            f"on incident with severity {incident.severity}."
        ),
        escalate=False,
    )
    _log.info("policy_approved", action=proposed_action.action_type, role=proposed_action.role, escalate=False, severity=incident.severity)
    return decision
