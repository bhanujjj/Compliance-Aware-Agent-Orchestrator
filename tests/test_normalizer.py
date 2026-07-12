import pytest
from sentinel.ingestion.normalizer import row_to_alert, parse_csv_file, DEFAULT_SEVERITY, SEVERITY_MAP

def test_row_to_alert_basic():
    row = {" Source IP": "1.2.3.4", " Destination IP": "5.6.7.8",
           " Protocol": "6", " Label": "DDoS"}
    alert = row_to_alert(row)
    assert alert.src_ip == "1.2.3.4"
    assert alert.dst_ip == "5.6.7.8"
    assert alert.attack_type == "DDoS"
    assert alert.severity_score == 6.0

def test_row_to_alert_no_leading_space_columns():
    row = {"Source IP": "9.9.9.9", "Destination IP": "8.8.8.8",
           "Protocol": "17", "Label": "PortScan"}
    alert = row_to_alert(row)
    assert alert.src_ip == "9.9.9.9"
    assert alert.severity_score == 4.0

def test_benign_severity_is_zero():
    row = {" Source IP": "1.1.1.1", " Destination IP": "2.2.2.2",
           " Protocol": "6", " Label": "BENIGN"}
    alert = row_to_alert(row)
    assert alert.severity_score == 0.0

def test_unknown_label_gets_default_severity():
    row = {" Source IP": "1.1.1.1", " Destination IP": "2.2.2.2",
           " Protocol": "6", " Label": "UNKNOWN_ATTACK_XYZ"}
    alert = row_to_alert(row)
    assert alert.severity_score == DEFAULT_SEVERITY

def test_raw_features_populated():
    row = {" Source IP": "1.1.1.1", " Destination IP": "2.2.2.2",
           " Protocol": "6", " Label": "BENIGN",
           "Flow Duration": "12345", "Total Fwd Packets": "10"}
    alert = row_to_alert(row)
    assert "Flow Duration" in alert.raw_features
    assert alert.raw_features["Flow Duration"] == "12345"

def test_whitespace_stripped_from_label():
    row = {" Source IP": "1.1.1.1", " Destination IP": "2.2.2.2",
           " Protocol": "6", " Label": "  SSH-Patator  "}
    alert = row_to_alert(row)
    assert alert.attack_type == "SSH-Patator"
    assert alert.severity_score == 5.0

def test_empty_ip_handled_gracefully():
    row = {" Source IP": "", " Destination IP": "", " Protocol": "", " Label": "BENIGN"}
    alert = row_to_alert(row)  # must not raise
    assert alert.src_ip == ""

def test_severity_map_completeness():
    # Every value in SEVERITY_MAP must be a float in 0–10
    for label, score in SEVERITY_MAP.items():
        assert isinstance(score, float), f"{label} score is not float"
        assert 0.0 <= score <= 10.0, f"{label} score {score} out of range"

def test_parse_csv_file_synthetic(tmp_path):
    # Write a synthetic CSV and parse it
    csv_content = (
        " Source IP, Destination IP, Protocol, Label\n"
        "1.2.3.4,5.6.7.8,6,DDoS\n"
        "9.9.9.9,8.8.8.8,17,BENIGN\n"
    )
    f = tmp_path / "test.csv"
    f.write_text(csv_content)
    alerts = parse_csv_file(str(f))
    assert len(alerts) >= 2
