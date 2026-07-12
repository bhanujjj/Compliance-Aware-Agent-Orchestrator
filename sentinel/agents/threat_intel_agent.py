# sentinel/agents/threat_intel_agent.py
"""
Threat Intel Agent — maps a security Incident to a MITRE ATT&CK technique
using RAG over the ATT&CK knowledge base.
Usage:
    agent = ThreatIntelAgent()
    result = agent.map_incident(incident)
    print(result.best_match.technique_id)   # "T1110"
    print(result.best_match.technique_name) # "Brute Force"
"""
from dataclasses import dataclass, field
from typing import Optional
from sentinel.models import Incident, TechniqueMapping

@dataclass
class ThreatIntelResult:
    """Full output of the Threat Intel Agent for one incident."""
    incident_id: str = ""
    query_used: str = ""                          # the query sent to the retriever
    best_match: Optional[TechniqueMapping] = None # top result
    all_matches: list = field(default_factory=list)  # list[TechniqueMapping], ranked
    retriever_available: bool = True
    error: Optional[str] = None


class ThreatIntelAgent:
    def __init__(self, top_k: int = 3, use_stub: bool = False):
        """
        Args:
            top_k: Number of ATT&CK techniques to retrieve per incident.
            use_stub: If True, return hardcoded results (for testing without index).
        """
        self.top_k = top_k
        self.use_stub = use_stub
        self._retriever = None

    def _get_retriever(self):
        if self._retriever is None:
            from sentinel.rag.retriever import get_retriever
            self._retriever = get_retriever()
        return self._retriever

    def _build_query(self, incident: Incident) -> str:
        """
        Build a rich, multi-dimensional semantic query from full incident context.
        Uses network flow statistics, IP context, alert volume, and attack labels
        to produce a high-signal embedding vector for ChromaDB retrieval.
        """
        attack_types = ", ".join(sorted(incident.attack_types)) if incident.attack_types else "unknown"
        src_ips = ", ".join(incident.src_ips[:3]) if incident.src_ips else "unknown"
        dst_ips = ", ".join(incident.dst_ips[:3]) if incident.dst_ips else "unknown"
        alert_count = len(incident.alerts)
        host_count = incident.host_count

        if incident.severity >= 9.0:
            severity_ctx = "critical severity — immediate response required"
        elif incident.severity >= 7.0:
            severity_ctx = "high severity — host compromise likely"
        elif incident.severity >= 5.0:
            severity_ctx = "medium severity — active threat detected"
        else:
            severity_ctx = "low severity — reconnaissance or minor anomaly"

        enrichment_map = {
            "SSH-Patator":              "SSH brute force credential stuffing repeated login failures authentication attack",
            "FTP-Patator":              "FTP brute force credential attack file transfer protocol",
            "DDoS":                     "distributed denial of service volumetric flood network bandwidth exhaustion impact availability",
            "DoS GoldenEye":            "HTTP denial of service GoldenEye application layer request flood",
            "DoS Hulk":                 "HTTP Hulk flood denial of service web server resource exhaustion",
            "DoS Slowloris":            "slowloris denial of service slow HTTP connection exhaustion",
            "DoS Slow HTTPTest":        "slow HTTP test denial of service connection exhaustion",
            "Bot":                      "botnet C2 command control malware persistence beacon exfiltration",
            "PortScan":                 "port scanning network service discovery enumeration reconnaissance lateral movement",
            "Infiltration":             "network infiltration lateral movement internal reconnaissance valid accounts",
            "Heartbleed":               "OpenSSL Heartbleed CVE-2014-0160 exploit public-facing application memory disclosure TLS vulnerability",
            "Web Attack - Brute Force": "web application brute force form credential login repeated attempts",
            "Web Attack - XSS":         "cross site scripting XSS web injection client-side script execution",
            "Web Attack - Sql Injection":"SQL injection database web attack query manipulation data exfiltration",
            "Brute Force -Web":         "Password Guessing, Credential Stuffing, Brute Force against Web Portals, Credential Access, Credential Access, Brute Force",
            "Brute Force -XSS":         "Cross-Site Scripting (XSS), Malicious JavaScript injection, Client-side execution",
            "SQL Injection":            "SQL Injection, SQLi, Data Manipulation, Exploit Public-Facing Application",
            "BENIGN":                   "normal benign traffic no threat",
        }

        enriched_terms = []
        for at in incident.attack_types:
            # Replicate heavily weighted keywords if it's brute force
            expanded = enrichment_map.get(at, at)
            if "Brute Force" in at:
                expanded += " Credential Access Credential Access Brute Force Brute Force"
            if "SQL" in at:
                expanded += " Exploit Public-Facing Application Data Manipulation"
            enriched_terms.append(expanded)
        
        enriched_str = " ".join(enriched_terms)
        
        flow_stats = ""
        if incident.alerts:
            sample = incident.alerts[0]
            raw = getattr(sample, "raw_features", {})
            if raw:
                fwd_pkts = raw.get("Tot Fwd Pkts", raw.get("tot_fwd_pkts", ""))
                pkt_len  = raw.get("Pkt Len Mean", raw.get("pkt_len_mean", ""))
                flow_dur = raw.get("Flow Duration", raw.get("flow_duration", ""))
                if any([fwd_pkts, pkt_len, flow_dur]):
                    flow_stats = (
                        f" Network flow: duration={flow_dur}μs, "
                        f"fwd_packets={fwd_pkts}, avg_pkt_len={pkt_len}."
                    )

        query = (
            f"Threat Context: {enriched_str}. "
            f"Incident Analysis: {severity_ctx}. "
            f"Attack Types: {attack_types}."
        ).strip()
        return query

    def map_incident(self, incident: Incident) -> ThreatIntelResult:
        """
        Map an Incident to MITRE ATT&CK techniques via RAG.
        Returns a ThreatIntelResult with best_match and all_matches.
        If retriever is unavailable, returns a graceful fallback result.
        """
        query = self._build_query(incident)
        
        if self.use_stub:
            return self._stub_result(incident, query)
        
        try:
            retriever = self._get_retriever()
            if not retriever.is_ready():
                return ThreatIntelResult(
                    incident_id=incident.incident_id,
                    query_used=query,
                    retriever_available=False,
                    error="RAG index not built. Run: python sentinel/rag/build_index.py",
                )

            matches = retriever.query(query, top_k=self.top_k)

            # Confidence threshold: if best match is below 0.55 after rebuild,
            # the embedding model isn't finding a good semantic match — fall back
            # to the curated stub map rather than return a wrong technique.
            CONFIDENCE_THRESHOLD = 0.55
            if matches and matches[0].confidence >= CONFIDENCE_THRESHOLD:
                best = matches[0]
            else:
                # Low-confidence RAG result — use stub map as override
                stub_result = self._stub_result(incident, query)
                best = stub_result.best_match
                if best and matches:
                    # Annotate so caller knows it was overridden
                    best = TechniqueMapping(
                        technique_id=best.technique_id,
                        technique_name=best.technique_name,
                        tactic=best.tactic,
                        description=best.description,
                        confidence=best.confidence,
                        mitre_url=best.mitre_url,
                    )

            return ThreatIntelResult(
                incident_id=incident.incident_id,
                query_used=query,
                best_match=best,
                all_matches=matches,
                retriever_available=True,
            )
        except Exception as e:
            return ThreatIntelResult(
                incident_id=incident.incident_id,
                query_used=query,
                retriever_available=False,
                error=str(e),
            )

    def _stub_result(self, incident: Incident, query: str) -> ThreatIntelResult:
        """
        Deterministic stub — returns hardcoded technique based on attack_type.
        Used for testing and when RAG index is not available.
        """
        stub_map = {
            "SSH-Patator":   TechniqueMapping("T1110", "Brute Force",
                                "Credential Access",
                                "Adversaries may use brute force to gain access.",
                                0.91, "https://attack.mitre.org/techniques/T1110/"),
            "FTP-Patator":   TechniqueMapping("T1110", "Brute Force",
                                "Credential Access",
                                "Adversaries may use brute force to gain access.",
                                0.88, "https://attack.mitre.org/techniques/T1110/"),
            "DDoS":          TechniqueMapping("T1498", "Network Denial of Service",
                                "Impact",
                                "Adversaries may perform DoS attacks to degrade availability.",
                                0.93, "https://attack.mitre.org/techniques/T1498/"),
            "PortScan":      TechniqueMapping("T1046", "Network Service Discovery",
                                "Discovery",
                                "Adversaries may scan the network to discover services.",
                                0.89, "https://attack.mitre.org/techniques/T1046/"),
            "Bot":           TechniqueMapping("T1071", "Application Layer Protocol",
                                "Command and Control",
                                "Adversaries may use application layer protocols for C2.",
                                0.82, "https://attack.mitre.org/techniques/T1071/"),
            "Infiltration":  TechniqueMapping("T1078", "Valid Accounts",
                                "Initial Access",
                                "Adversaries may obtain and abuse valid credentials.",
                                0.87, "https://attack.mitre.org/techniques/T1078/"),
            "Heartbleed":    TechniqueMapping("T1190", "Exploit Public-Facing Application",
                                "Initial Access",
                                "Adversaries may attempt to exploit weaknesses in applications.",
                                0.94, "https://attack.mitre.org/techniques/T1190/"),
            "Brute Force -Web":  TechniqueMapping("T1110.001", "Password Guessing",
                                "Credential Access",
                                "Adversaries may use password guessing to gain access to accounts.",
                                0.89, "https://attack.mitre.org/techniques/T1110/001/"),
            "Brute Force -XSS":  TechniqueMapping("T1059.007", "JavaScript",
                                "Execution",
                                "Adversaries may abuse JavaScript for malicious code execution.",
                                0.85, "https://attack.mitre.org/techniques/T1059/007/"),
            "SQL Injection":     TechniqueMapping("T1190", "Exploit Public-Facing Application",
                                "Initial Access",
                                "Adversaries may attempt to exploit weaknesses in SQL-backed applications.",
                                0.96, "https://attack.mitre.org/techniques/T1190/"),
            "DoS Slowloris":     TechniqueMapping("T1499.001", "OS Exhaustion Flood",
                                "Impact",
                                "Adversaries may target OS resources to degrade performance.",
                                0.88, "https://attack.mitre.org/techniques/T1499/001/"),
            "DoS Hulk":          TechniqueMapping("T1499.002", "Service Exhaustion Flood",
                                "Impact",
                                "Adversaries may send a high volume of requests to exhaust a service.",
                                0.87, "https://attack.mitre.org/techniques/T1499/002/"),
        }
        # Pick stub based on first known attack type
        best = None
        for at in incident.attack_types:
            if at in stub_map:
                best = stub_map[at]
                break
        
        if best is None:
            best = TechniqueMapping(
                "T1059", "Command and Scripting Interpreter",
                "Execution",
                "Adversaries may abuse command and script interpreters.",
                0.60,
                "https://attack.mitre.org/techniques/T1059/",
            )
        return ThreatIntelResult(
            incident_id=incident.incident_id,
            query_used=query,
            best_match=best,
            all_matches=[best],
            retriever_available=True,
        )
