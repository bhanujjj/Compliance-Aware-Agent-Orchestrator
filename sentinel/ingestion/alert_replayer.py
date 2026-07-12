"""
Alert Replayer — re-emits parsed Alerts at configurable speed.
Usage:
    replayer = AlertReplayer("data/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    for alert in replayer.stream(speed=10.0, max_alerts=500):
        process(alert)
Speed multiplier:
    1.0  = realtime (based on inter-row interval estimate)
    10.0 = 10× faster
    0    or math.inf = no sleep, emit as fast as possible (use for testing)
"""
import math
import time
from pathlib import Path
from typing import Iterator, Optional
from sentinel.ingestion.normalizer import parse_csv_file
from sentinel.models import Alert

class AlertReplayer:
    def __init__(self, csv_path: str):
        self.csv_path = Path(csv_path)
        self._alerts: Optional[list[Alert]] = None

    def _load(self) -> list[Alert]:
        if self._alerts is None:
            if not self.csv_path.exists():
                raise FileNotFoundError(
                    f"CICIDS2017 CSV not found at: {self.csv_path}\n"
                    f"Run:  bash data/download_cicids.sh"
                )
            self._alerts = parse_csv_file(str(self.csv_path))
        return self._alerts

    def stream(
        self,
        speed: float = 1.0,
        max_alerts: Optional[int] = None,
        attack_only: bool = False,
    ) -> Iterator[Alert]:
        """
        Yield alerts one by one.
        Args:
            speed: Playback multiplier. 1.0 = ~1 alert/second (simulated);
                   math.inf or 0 = no delay (burst mode for testing).
            max_alerts: Stop after this many alerts (None = entire file).
            attack_only: If True, skip BENIGN alerts.
        """
        alerts = self._load()
        count = 0
        # Simulated inter-alert delay: assume 1 alert per second at 1× speed
        base_delay = 1.0  # seconds between alerts at speed=1.0
        if speed == 0 or speed == math.inf:
            delay = 0.0
        else:
            delay = base_delay / speed

        for alert in alerts:
            if attack_only and alert.attack_type == "BENIGN":
                continue
            
            yield alert
            
            count += 1
            if max_alerts and count >= max_alerts:
                break
                
            if delay > 0:
                time.sleep(delay)

    def load_all(self, attack_only: bool = False) -> list[Alert]:
        """Load all alerts into memory without streaming (for testing/batch)."""
        alerts = self._load()
        if attack_only:
            return [a for a in alerts if a.attack_type != "BENIGN"]
        return alerts

    def stats(self) -> dict:
        """Return summary statistics about the loaded dataset."""
        alerts = self._load()
        from collections import Counter
        label_counts = Counter(a.attack_type for a in alerts)
        return {
            "total_alerts": len(alerts),
            "attack_labels": dict(label_counts),
            "unique_src_ips": len({a.src_ip for a in alerts if a.src_ip}),
            "unique_dst_ips": len({a.dst_ip for a in alerts if a.dst_ip}),
        }
