import json
from sentinel.models import Incident, ProposedAction
from sentinel.logging_config import get_logger

_log = get_logger("ResponseAgent")

SYSTEM_PROMPT = """You are a Tier-1 Security Operations Center (SOC) analyst.
You will be given details about a security incident and must propose ONE remediation action.
STRICT RULES:
1. You may ONLY propose actions from this list: block_ip, isolate_host, kill_process, revoke_session, collect_forensics
2. Your response MUST be valid JSON matching exactly this schema:
   {
     "action_type": "<one of the allowed actions>",
     "target": "<IP address, hostname, user_id, or PID — depending on action_type>",
     "reason": "<max 5 words explanation>",
     "role": "tier1_analyst"
   }
3. Do NOT propose actions outside the allowed list.
4. Do NOT propose isolating more than 1 host at a time.
5. If severity is below 5, prefer block_ip or revoke_session over isolation.
"""

def build_prompt(incident: Incident) -> str:
    return f"""Incident ID: {incident.incident_id}
Severity Score: {incident.severity}/10
Attack Types: {', '.join(incident.attack_types) or 'Unknown'}
Source IPs: {', '.join(incident.src_ips) or 'Unknown'}
Destination IPs: {', '.join(incident.dst_ips) or 'Unknown'}
Number of Hosts Involved: {incident.host_count}
Summary: {incident.summary}
Propose ONE remediation action. Respond with JSON only."""

class ResponseAgent:
    def __init__(self, use_stub: bool = True):
        self.use_stub = use_stub
        # In Phase 2: self.client = genai.Client(api_key=settings.GEMINI_API_KEY)

    def propose_action(self, incident: Incident) -> ProposedAction:
        """Returns a ProposedAction. Stub in Phase 1, real LLM in Phase 2."""
        if self.use_stub:
            return self._stub_propose(incident)
        else:
            return self._llm_propose(incident)   # Phase 2 — raises NotImplementedError now

    def _stub_propose(self, incident: Incident) -> ProposedAction:
        # Deterministic logic described above
        attack_types_str = " ".join(incident.attack_types).lower()
        
        action_type = "block_ip"
        target = incident.src_ips[0] if incident.src_ips else "unknown"
        reason = "Default mitigation."
        
        if "ssh" in attack_types_str or "ftp" in attack_types_str or "brute" in attack_types_str:
            action_type = "block_ip"
            reason = "Blocking source IP due to detected brute force/SSH/FTP attack."
        elif incident.severity >= 7.0:
            action_type = "isolate_host"
            target = incident.dst_ips[0] if incident.dst_ips else "unknown"
            reason = "Isolating host due to high severity threat."
        elif "bot" in attack_types_str:
            action_type = "revoke_session"
            target = "fake_user_123"
            reason = "Revoking session due to bot activity."
            
        _log.info("action_proposed", incident_id=incident.incident_id[:8],
                  action_type=action_type, target=target, reason=reason)
                  
        return ProposedAction(
            action_type=action_type,
            target=target,
            reason=reason,
            role="tier1_analyst"
        )

    def _llm_propose(self, incident: Incident) -> ProposedAction:
        import os
        import requests
        
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            _log.warning("no_openrouter_api_key_falling_back_to_stub")
            return self._stub_propose(incident)
            
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        prompt = self.build_prompt(incident)
        
        payload = {
            "model": "openrouter/free",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            # Ask the model to output JSON (if the model supports it, otherwise prompt engineering handles it)
            "response_format": {"type": "json_object"}
        }
        
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            
            # Clean up potential markdown formatting around JSON
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
                
            parsed = json.loads(content.strip())
            
            action_type = parsed.get("action_type", "block_ip")
            target = parsed.get("target", "unknown")
            reason = parsed.get("reason", "LLM decision")
            role = parsed.get("role", "tier1_analyst")
            
            _log.info("action_proposed_llm", incident_id=incident.incident_id[:8],
                      action_type=action_type, target=target, reason=reason)
                      
            return ProposedAction(
                action_type=action_type,
                target=target,
                reason=reason,
                role=role
            )
        except Exception as e:
            _log.error("llm_proposal_failed", error=str(e))
            # Fallback to stub on failure
            return self._stub_propose(incident)

    def build_prompt(self, incident: Incident) -> str:
        return build_prompt(incident)
