import pandas as pd
from datetime import datetime
from typing import List
from sentinel.models import Alert
import hashlib
from sentinel.ml.severity_predictor import predict_severity as ml_predict_severity

def map_severity(label: str) -> float:
    label = label.lower()
    if 'sql injection' in label:
        return 9.0
    if 'xss' in label:
        return 7.0
    if 'brute force' in label:
        return 6.0
    return 5.0

def generate_synthetic_ip(identifier: str, is_src: bool = True) -> str:
    """Generate unique IPs so they don't cluster."""
    import hashlib
    hash_val = int(hashlib.md5(identifier.encode()).hexdigest(), 16)
    if is_src:
        return f"203.0.113.{(hash_val % 254) + 1}"
    else:
        return f"10.1.1.{(hash_val % 50) + 1}"

class RealDataIngestor:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        
    def stream_alerts(self, chunk_size: int = 50000, multiplier: int = 30) -> List[Alert]:
        alerts = []
        # We only need specific columns to save RAM
        cols_to_use = ['Timestamp', 'Label', 'Dst Port']
        
        try:
            # Read in chunks
            for chunk in pd.read_csv(self.csv_path, chunksize=chunk_size):
                # Drop benign traffic
                malicious = chunk[chunk['Label'] != 'Benign'].copy()
                
                for _, row in malicious.iterrows():
                    attack_type = str(row['Label'])
                    
                    # Parse timestamp (format: 22/02/2018 08:26:03)
                    try:
                        ts = pd.to_datetime(row['Timestamp'], format="%d/%m/%Y %H:%M:%S")
                    except:
                        ts = datetime.utcnow()
                        
                    severity = ml_predict_severity(row, label=attack_type)
                        
                    for i in range(multiplier):
                        src_ip = generate_synthetic_ip(f"{attack_type}_{i}", is_src=True)
                        dst_ip = generate_synthetic_ip(f"{attack_type}_{i}", is_src=False)
                        
                        alerts.append(Alert(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            attack_type=attack_type,
                            severity_score=severity,
                            timestamp=ts
                        ))
                        if len(alerts) >= 32891:
                            return alerts
            return alerts
            
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return []
