"""
Unit tests for sentinel/rag/retriever.py.
All tests use an in-memory ChromaDB — no STIX download required.
"""
import pytest
import chromadb
from chromadb.utils import embedding_functions
from unittest.mock import patch, MagicMock
from sentinel.models import TechniqueMapping

# ── Fixture: in-memory ChromaDB with synthetic techniques ────────────────────

SYNTHETIC_TECHNIQUES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access.",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "chunk_text": "T1110 Brute Force. Tactic: Credential Access. Adversaries may use brute force.",
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "chunk_text": "T1046 Network Service Discovery. Tactic: Discovery. Port scanning to enumerate services.",
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Denial of Service attacks to degrade or block availability.",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "chunk_text": "T1498 Network Denial of Service. Tactic: Impact. DDoS flood attacks.",
    },
]

@pytest.fixture(scope="module")
def mock_retriever():
    """
    Creates an AttackRetriever whose internal collection is an in-memory ChromaDB
    populated with SYNTHETIC_TECHNIQUES.
    """
    from sentinel.rag.retriever import AttackRetriever
    
    ef = embedding_functions.DefaultEmbeddingFunction()
    
    # Use EphemeralClient for chromadb version >= 0.4.0 where Client() is deprecated
    client = chromadb.EphemeralClient()
    col = client.create_collection("mitre_attack", embedding_function=ef)
    
    col.add(
        ids=[t["id"] for t in SYNTHETIC_TECHNIQUES],
        documents=[t["chunk_text"] for t in SYNTHETIC_TECHNIQUES],
        metadatas=[
            {
                "name": t["name"],
                "tactic": t["tactic"],
                "description": t["description"],
                "url": t["url"],
            }
            for t in SYNTHETIC_TECHNIQUES
        ],
    )
    
    retriever = AttackRetriever()
    retriever._col = col   # inject the in-memory collection directly
    return retriever

# ── Tests ────────────────────────────────────────────────────────────────────

def test_query_returns_list(mock_retriever):
    results = mock_retriever.query("brute force SSH login", top_k=2)
    assert isinstance(results, list)
    assert len(results) <= 2

def test_query_returns_technique_mapping_objects(mock_retriever):
    results = mock_retriever.query("brute force", top_k=1)
    assert len(results) >= 1
    assert isinstance(results[0], TechniqueMapping)

def test_brute_force_query_returns_t1110(mock_retriever):
    results = mock_retriever.query("SSH brute force login attempts repeated password", top_k=1)
    assert results[0].technique_id == "T1110"

def test_port_scan_query_returns_t1046(mock_retriever):
    results = mock_retriever.query("port scanning network service enumeration", top_k=1)
    assert results[0].technique_id == "T1046"

def test_ddos_query_returns_t1498(mock_retriever):
    results = mock_retriever.query("DDoS denial of service flood attack", top_k=1)
    assert results[0].technique_id == "T1498"

def test_confidence_between_zero_and_one(mock_retriever):
    results = mock_retriever.query("network attack", top_k=3)
    for r in results:
        assert 0.0 <= r.confidence <= 1.0, f"Confidence out of range: {r.confidence}"

def test_results_sorted_by_confidence_descending(mock_retriever):
    results = mock_retriever.query("attack intrusion", top_k=3)
    confidences = [r.confidence for r in results]
    assert confidences == sorted(confidences, reverse=True)

def test_technique_name_populated(mock_retriever):
    results = mock_retriever.query("brute force", top_k=1)
    assert len(results[0].technique_name) > 0

def test_tactic_populated(mock_retriever):
    results = mock_retriever.query("brute force", top_k=1)
    assert len(results[0].tactic) > 0

def test_mitre_url_populated(mock_retriever):
    results = mock_retriever.query("brute force", top_k=1)
    assert results[0].mitre_url.startswith("https://attack.mitre.org/")

def test_top_k_respected(mock_retriever):
    results = mock_retriever.query("attack", top_k=2)
    assert len(results) <= 2

def test_is_ready_true_when_indexed(mock_retriever):
    assert mock_retriever.is_ready() is True

def test_is_ready_false_when_no_index(tmp_path):
    from unittest.mock import patch
    from sentinel.rag import retriever as retriever_module
    from sentinel.rag.retriever import AttackRetriever
    # Patch CHROMA_PATH to a non-existent dir so is_ready() returns False
    # regardless of whether the real index has been built on this machine.
    with patch.object(retriever_module, "CHROMA_PATH", tmp_path / "nonexistent"):
        r = AttackRetriever()
        assert r.is_ready() is False
