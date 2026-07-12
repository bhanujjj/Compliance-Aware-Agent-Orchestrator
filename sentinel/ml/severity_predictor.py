"""
sentinel/ml/severity_predictor.py

Loads the pre-trained IDS classifier from models/ids_classifier.pkl
and uses it to predict a severity score (0.0–10.0) for a network flow.

Falls back to label-based heuristic if the model file is not found.
"""

import json
import pickle
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

_MODEL_PATH = Path("models/ids_classifier.pkl")
_FEATURES_PATH = Path("models/feature_columns.json")
_SCALER_PATH = Path("models/ids_scaler.pkl")
_COLS_TO_SCALE_PATH = Path("models/columns_to_scale.json")
_TOP_PORTS_PATH = Path("models/top_ports.json")
_CAT_COLS_PATH = Path("models/cat_cols.json")

# Load once at module import — cached for the lifetime of the process
_model = None
_feature_cols = None
_scaler = None
_cols_to_scale = None
_top_ports = None
_cat_cols = None


def _load_model():
    global _model, _feature_cols, _scaler, _cols_to_scale, _top_ports, _cat_cols
    if _model is not None:
        return True
    try:
        if not _MODEL_PATH.exists():
            logger.warning(f"Model file not found at {_MODEL_PATH}. Using fallback.")
            return False
        with open(_MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        with open(_FEATURES_PATH, "r") as f:
            _feature_cols = json.load(f)
        
        # Optionally load scaler
        if _SCALER_PATH.exists() and _COLS_TO_SCALE_PATH.exists():
            with open(_SCALER_PATH, "rb") as f:
                _scaler = pickle.load(f)
            with open(_COLS_TO_SCALE_PATH, "r") as f:
                _cols_to_scale = json.load(f)

        # Optionally load binner and one-hot info
        if _TOP_PORTS_PATH.exists() and _CAT_COLS_PATH.exists():
            with open(_TOP_PORTS_PATH, "r") as f:
                _top_ports = json.load(f)
            with open(_CAT_COLS_PATH, "r") as f:
                _cat_cols = json.load(f)
        
        logger.info(f"✅ Loaded IDS classifier ({type(_model).__name__}) with {len(_feature_cols)} features.")
        return True
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return False


def _fallback_severity(label: str) -> float:
    """Hardcoded severity mapping — used when model is unavailable."""
    label = label.lower()
    if "sql injection" in label:
        return 9.0
    if "xss" in label or "cross-site" in label:
        return 7.0
    if "brute force" in label or "brute-force" in label:
        return 6.0
    if "ddos" in label or "dos" in label:
        return 7.5
    if "heartbleed" in label:
        return 9.5
    if "infiltration" in label:
        return 8.0
    if "bot" in label:
        return 6.5
    if "portscan" in label or "port scan" in label:
        return 4.0
    if "benign" in label:
        return 0.0
    return 5.0


def predict_severity(row: pd.Series, label: str = "") -> float:
    """
    Predict severity score for a single network flow row.

    Args:
        row: A pandas Series containing network flow features from the CSV.
        label: The attack label string (used for fallback only).

    Returns:
        Severity score between 0.0 and 10.0
    """
    model_loaded = _load_model()

    if not model_loaded or _model is None or _feature_cols is None:
        return _fallback_severity(label)

    try:
        row_dict = row.to_dict() if hasattr(row, "to_dict") else dict(row)

        # Apply BinColumn transformation for Dst Port
        if _top_ports is not None and "Dst Port" in row_dict:
            val = row_dict["Dst Port"]
            if isinstance(val, (int, float)) and pd.notnull(val):
                val = str(int(val))
            if str(val) not in _top_ports:
                row_dict["Dst Port"] = "other"
            else:
                row_dict["Dst Port"] = str(val)

        # Apply PaucalOneHotter transformations
        if _cat_cols is not None:
            for c in _cat_cols:
                if c in row_dict:
                    val = row_dict[c]
                    if isinstance(val, (int, float)) and pd.notnull(val):
                        if isinstance(val, float) and val.is_integer():
                            val = int(val)
                    val = str(val)
                    col_name = f"{c}_{val}"
                    row_dict[col_name] = 1.0
                    del row_dict[c]

        aligned = {col: row_dict.get(col, 0.0) for col in _feature_cols}
        X = pd.DataFrame([aligned])

        # Replace inf/nan with 0
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        # Apply scaling if scaler is loaded
        if _scaler is not None and _cols_to_scale is not None:
            # Only scale columns that exist in X
            cols_present = [c for c in _cols_to_scale if c in X.columns]
            if cols_present:
                X[cols_present] = _scaler.transform(X[cols_present])

        # Get probability of the malicious class (index 1)
        proba = _model.predict_proba(X)[0]

        # If binary classifier: proba[1] = malicious probability
        # If multiclass: use max probability of any non-benign class
        if len(proba) == 2:
            malicious_prob = proba[1]
        else:
            # Multiclass — get the class names
            classes = list(_model.classes_)
            benign_indices = [i for i, c in enumerate(classes) if "benign" in str(c).lower()]
            benign_prob = sum(proba[i] for i in benign_indices)
            malicious_prob = 1.0 - benign_prob

        # Scale to 0–10
        severity = round(malicious_prob * 10.0, 1)
        return min(max(severity, 0.0), 10.0)

    except Exception as e:
        logger.warning(f"Model prediction failed for row: {e}. Using fallback.")
        return _fallback_severity(label)
