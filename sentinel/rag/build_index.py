"""
Build the MITRE ATT&CK ChromaDB index for Sentinel RAG.
Run once:
    python sentinel/rag/build_index.py

Persists to: data/chroma_db/
Re-run is safe (checks if index already exists and skips rebuild).
"""
import json
import sys
from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT  = Path(__file__).parent.parent.parent
STIX_PATH     = PROJECT_ROOT / "data" / "attack_stix" / "enterprise-attack.json"
CHROMA_PATH   = PROJECT_ROOT / "data" / "chroma_db"
COLLECTION    = "mitre_attack"

# ── Embedding — ChromaDB default (all-MiniLM-L6-v2 via ONNX, no API key) ─────
DEFAULT_EF = embedding_functions.DefaultEmbeddingFunction()

def _extract_techniques(stix_path: Path) -> list[dict]:
    """Parse STIX bundle → list of technique dicts."""
    with stix_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        
        # Skip deprecated / revoked techniques
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract external ID (T1xxx) and URL
        technique_id, url = "", ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        
        if not technique_id.startswith("T"):
            continue  # skip software, groups, etc.

        # Extract tactic from kill_chain_phases
        tactic = ""
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = phase.get("phase_name", "").replace("-", " ").title()
                break

        name = obj.get("name", "")
        description = obj.get("description", "")[:500]  # truncate for chunk size

        techniques.append({
            "id":          technique_id,
            "name":        name,
            "tactic":      tactic,
            "description": description,
            "url":         url,
            # This is what gets embedded — rich text for better retrieval
            "chunk_text":  (
                f"{technique_id} {name}. "
                f"Tactic: {tactic}. "
                f"{description}"
            ),
        })
    return techniques

def build_index(force_rebuild: bool = False) -> chromadb.Collection:
    """
    Build or load the ChromaDB index.
    Args:
        force_rebuild: If True, delete existing collection and rebuild.
    Returns:
        The ChromaDB collection.
    """
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))

    # Check if collection already exists and has data
    existing = [c.name for c in client.list_collections()]
    if COLLECTION in existing and not force_rebuild:
        col = client.get_collection(COLLECTION, embedding_function=DEFAULT_EF)
        count = col.count()
        if count > 0:
            print(f"[INFO] Loaded existing index: {count} techniques in '{COLLECTION}'.")
            return col
        # Collection exists but empty — fall through to rebuild

    if COLLECTION in existing:
        client.delete_collection(COLLECTION)

    if not STIX_PATH.exists():
        print(f"[ERROR] STIX bundle not found at: {STIX_PATH}")
        print("        Run: bash data/download_attack.sh")
        sys.exit(1)

    print(f"[INFO] Parsing STIX bundle from {STIX_PATH} ...")
    techniques = _extract_techniques(STIX_PATH)
    print(f"[INFO] Extracted {len(techniques)} active techniques.")

    col = client.create_collection(
        COLLECTION,
        embedding_function=DEFAULT_EF,
        metadata={"hnsw:space": "cosine"},  # cosine similarity, not L2
    )

    # Batch insert (ChromaDB handles embedding internally)
    print("[INFO] Embedding and indexing techniques (first run may download model) ...")
    batch_size = 100
    for i in range(0, len(techniques), batch_size):
        batch = techniques[i : i + batch_size]
        col.add(
            ids       = [t["id"] for t in batch],
            documents = [t["chunk_text"] for t in batch],
            metadatas = [
                {
                    "name":        t["name"],
                    "tactic":      t["tactic"],
                    "description": t["description"],
                    "url":         t["url"],
                }
                for t in batch
            ],
        )
        print(f"  Indexed {min(i + batch_size, len(techniques))}/{len(techniques)} ...", end="\r")

    print(f"\n[INFO] ✅ Index built: {col.count()} techniques in '{COLLECTION}'.")
    return col

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Force rebuild even if index exists")
    args = parser.parse_args()
    build_index(force_rebuild=args.force)
