import pytest
import csv
from sentinel.ingestion.alert_replayer import AlertReplayer

def _write_synthetic_csv(tmp_path, rows: list[dict]) -> str:
    """Helper to write a synthetic CICIDS-formatted CSV."""
    file_path = tmp_path / "synthetic.csv"
    if not rows:
        file_path.write_text("Source IP,Destination IP,Protocol,Label\n")
        return str(file_path)
    
    with open(file_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return str(file_path)

def test_load_all_returns_alerts(tmp_path):
    rows = [
        {"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"},
        {"Source IP": "3.3.3.3", "Destination IP": "4.4.4.4", "Protocol": "6", "Label": "DDoS"}
    ]
    csv_path = _write_synthetic_csv(tmp_path, rows)
    replayer = AlertReplayer(csv_path)
    
    alerts = replayer.load_all()
    assert len(alerts) == 2
    assert alerts[0].attack_type == "BENIGN"
    assert alerts[1].attack_type == "DDoS"

def test_stream_max_alerts_limit(tmp_path):
    rows = [{"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"} for _ in range(10)]
    csv_path = _write_synthetic_csv(tmp_path, rows)
    replayer = AlertReplayer(csv_path)
    
    streamed = list(replayer.stream(speed=0, max_alerts=3))
    assert len(streamed) == 3

def test_stream_attack_only_filters_benign(tmp_path):
    rows = [
        {"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"},
        {"Source IP": "3.3.3.3", "Destination IP": "4.4.4.4", "Protocol": "6", "Label": "DDoS"},
        {"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"},
        {"Source IP": "5.5.5.5", "Destination IP": "6.6.6.6", "Protocol": "6", "Label": "PortScan"},
        {"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"}
    ]
    csv_path = _write_synthetic_csv(tmp_path, rows)
    replayer = AlertReplayer(csv_path)
    
    streamed = list(replayer.stream(speed=0, attack_only=True))
    assert len(streamed) == 2
    assert streamed[0].attack_type == "DDoS"
    assert streamed[1].attack_type == "PortScan"

def test_stream_zero_speed_no_sleep(tmp_path):
    import time
    rows = [{"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"} for _ in range(50)]
    csv_path = _write_synthetic_csv(tmp_path, rows)
    replayer = AlertReplayer(csv_path)
    
    start = time.time()
    list(replayer.stream(speed=0, max_alerts=50))
    elapsed = time.time() - start
    
    assert elapsed < 2.0  # Should be near-instantaneous

def test_stats_returns_expected_keys(tmp_path):
    rows = [
        {"Source IP": "1.1.1.1", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "BENIGN"},
        {"Source IP": "3.3.3.3", "Destination IP": "2.2.2.2", "Protocol": "6", "Label": "DDoS"}
    ]
    csv_path = _write_synthetic_csv(tmp_path, rows)
    replayer = AlertReplayer(csv_path)
    
    stats = replayer.stats()
    assert "total_alerts" in stats
    assert "attack_labels" in stats
    assert "unique_src_ips" in stats
    assert "unique_dst_ips" in stats
    
    assert stats["total_alerts"] == 2
    assert stats["unique_src_ips"] == 2
    assert stats["unique_dst_ips"] == 1
    assert stats["attack_labels"]["BENIGN"] == 1
    assert stats["attack_labels"]["DDoS"] == 1

def test_file_not_found_raises(tmp_path):
    replayer = AlertReplayer("/nonexistent/path.csv")
    with pytest.raises(FileNotFoundError):
        replayer.load_all()
