# models/

This directory contains pre-trained ML model artifacts used by Sentinel's severity prediction pipeline.

## Required Files (generate from the Kaggle notebook)

| File | Description |
|---|---|
| `ids_classifier.pkl` | Pickled trained model (Random Forest / XGBoost). Generate by running the Kaggle notebook locally and saving `pickle.dump(model, open("models/ids_classifier.pkl", "wb"))` |
| `feature_columns.json` | Ordered list of feature column names the model expects. Generate with `json.dump(list(X_train.columns), open("models/feature_columns.json", "w"))` |

## How to Generate These Files

1. Open your downloaded Kaggle `.ipynb` notebook in Jupyter or VS Code
2. Run all cells up to and including `model.fit(X_train, y_train)`
3. Add and run this cell at the bottom:

```python
import pickle, json

with open("models/ids_classifier.pkl", "wb") as f:
    pickle.dump(model, f)

feature_cols = list(X_train.columns)
with open("models/feature_columns.json", "w") as f:
    json.dump(feature_cols, f)

print(f"✅ Model saved. Features: {len(feature_cols)} columns.")
```

4. Place the generated files in this directory.

## DO NOT Commit

Add `ids_classifier.pkl` to `.gitignore` if the file exceeds 100MB (GitHub limit).
The `.ipynb` reference file can stay in this folder for documentation purposes.
