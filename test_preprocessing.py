import pandas as pd
import json

with open('models/feature_columns.json', 'r') as f:
    feature_cols = json.load(f)
with open('models/top_ports.json', 'r') as f:
    top_ports = json.load(f)
with open('models/cat_cols.json', 'r') as f:
    cat_cols = json.load(f)

df = pd.read_csv('data/IDS.csv', nrows=5)
X = df.drop('Label', axis=1) if 'Label' in df.columns else df

row_dict = X.iloc[0].to_dict()
print("Original Dst Port:", row_dict.get("Dst Port"))
print("Original Fwd PSH Flags:", row_dict.get("Fwd PSH Flags"))

if "Dst Port" in row_dict:
    val = row_dict["Dst Port"]
    if isinstance(val, (int, float)) and pd.notnull(val):
        val = str(int(val))
    if val not in top_ports:
        row_dict["Dst Port"] = "other"
    else:
        row_dict["Dst Port"] = val

for c in cat_cols:
    if c in row_dict:
        val = row_dict[c]
        if isinstance(val, (int, float)) and pd.notnull(val):
            if isinstance(val, float) and val.is_integer():
                val = int(val)
        val = str(val)
        col_name = f"{c}_{val}"
        row_dict[col_name] = 1.0
        # keep or del original doesn't matter for alignment, but let's del
        del row_dict[c]

aligned = {col: row_dict.get(col, 0.0) for col in feature_cols}
print("Aligned Dst Port dummy keys:", [k for k in aligned.keys() if 'Dst Port' in k and aligned[k] == 1.0])
print("Aligned Fwd PSH Flags dummy keys:", [k for k in aligned.keys() if 'Fwd PSH Flags' in k and aligned[k] == 1.0])
