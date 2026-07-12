import os
from langgraph.graph import StateGraph, END
from sentinel.orchestrator.state import SentinelState
from sentinel.orchestrator.nodes import (
    threat_intel_node, response_node, policy_node,
    execution_node, escalation_node, route_after_policy
)

if os.environ.get("LANGCHAIN_API_KEY"):
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = "sentinel-orchestrator"
else:
    os.environ["LANGCHAIN_TRACING_V2"] = "false"

def build_sentinel_graph():
    graph = StateGraph(SentinelState)
    
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("response", response_node)
    graph.add_node("policy", policy_node)
    graph.add_node("execution", execution_node)
    graph.add_node("escalation", escalation_node)
    
    graph.set_entry_point("threat_intel")
    graph.add_edge("threat_intel", "response")
    graph.add_edge("response", "policy")
    
    graph.add_conditional_edges(
        "policy",
        route_after_policy,
        {
            "response_node": "response",
            "execution_node": "execution",
            "escalation_node": "escalation",
        }
    )
    
    graph.add_edge("execution", END)
    graph.add_edge("escalation", END)
    
    return graph.compile()
