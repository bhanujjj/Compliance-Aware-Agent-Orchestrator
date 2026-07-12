import csv
from datetime import datetime
from sentinel.models import Alert

SEVERITY_MAP = {
    "BENIGN":                    0.0,
    "Bot":                       4.0,
    "DDoS":                      6.0,
    "DoS GoldenEye":             7.0,
    "DoS Hulk":                  7.0,
    "DoS Slowloris":             6.0,
    "DoS slowloris":             6.0,
    "DoS Slowhttptest":          6.0,
    "FTP-Patator":               5.0,
    "SSH-Patator":               5.0,
    "Infiltration":              8.0,
    "Web Attack – Brute Force":  6.0,
    "Web Attack – XSS":          5.0,
    "Web Attack – Sql Injection":7.0,
    "Web Attack - Brute Force":  6.0,
    "Web Attack - XSS":          5.0,
    "Web Attack - Sql Injection":7.0,
    "Heartbleed":                9.0,
    "PortScan":                  4.0,
}

DEFAULT_SEVERITY = 3.0

def _strip_key(row: dict, *candidates: str) -> str:
    """Try multiple column name variants (with/without leading spaces)."""
    for key in candidates:
        val = row.get(key, row.get(key.strip(), "")).strip()
        if val:
            return val
    return ""

def row_to_alert(row: dict) -> Alert:
    """
    Convert one CSV row dict (from csv.DictReader) → Alert.
    
    Handles:
    - Leading/trailing whitespace in column names and values
    - Missing columns (returns empty string, not crash)
    - Invalid numeric values in raw_features (keeps as str)
    - Unknown attack labels (maps to DEFAULT_SEVERITY)
    """
    src_ip      = _strip_key(row, " Source IP", "Source IP", "source_ip")
    dst_ip      = _strip_key(row, " Destination IP", "Destination IP", "destination_ip")
    protocol    = _strip_key(row, " Protocol", "Protocol", "protocol")
    attack_type = _strip_key(row, " Label", "Label", "label").strip()
    
    severity_score = SEVERITY_MAP.get(attack_type, DEFAULT_SEVERITY)
    
    # Store all remaining columns as raw_features
    skip_keys = {" Source IP", "Source IP", " Destination IP", "Destination IP",
                 " Protocol", "Protocol", " Label", "Label"}
    raw_features = {
        k.strip(): v.strip()
        for k, v in row.items()
        if k not in skip_keys and v is not None
    }
    
    return Alert(
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        attack_type=attack_type if attack_type else "BENIGN",
        severity_score=severity_score,
        raw_features=raw_features,
    )

def parse_csv_file(filepath: str) -> list[Alert]:
    """
    Parse an entire CICIDS2017 CSV file → list of Alerts.
    Skips rows that raise exceptions (logs warning, continues).
    Returns list in file order.
    """
    alerts = []
    errors = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            try:
                alerts.append(row_to_alert(row))
            except Exception as e:
                errors += 1
                if errors <= 5:  # only log first 5 errors to avoid spam
                    print(f"[WARN] Skipping row {i}: {e}")
    print(f"[INFO] Parsed {len(alerts)} alerts, {errors} rows skipped.")
    return alerts
