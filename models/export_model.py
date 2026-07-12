import json
import pickle
import os

with open("models/cyber-intrusion-detection-ml-pipeline.ipynb") as f:
    nb = json.load(f)

code_cells = []
for cell in nb.get("cells", []):
    if cell.get("cell_type") == "code":
        source = cell.get("source", [])
        if isinstance(source, list):
            source = "".join(source)
        code_cells.append(source)

full_code = "\n\n".join(code_cells)
full_code = full_code.replace("'../input/02152018-threats/02-15-2018.csv'", "'data/IDS.csv'")
full_code = full_code.replace("from sklearn.metrics import plot_confusion_matrix", "")

lines = full_code.split("\n")
clean_lines = []
for line in lines:
    if "hist(" in line or "plt." in line or "ConfusionMatrixDisplay" in line or "ROCAUC(" in line or ".show(" in line:
        clean_lines.append(line.replace(line.strip(), "pass"))
        continue
    clean_lines.append(line)
    if line.strip().startswith("rf_clf.fit"):
        break

full_code = "\n".join(clean_lines)

# Remove the downsampling logic
full_code = full_code.replace(
    "temp_df = pd.DataFrame()\nfor i,lbl in enumerate(counts.index):\n    print(i,lbl)\n    temp_df = pd.concat([temp_df,train_df[train_df['Label'] == lbl].sample(frac=class_ratios[i])])",
    "temp_df = train_df.copy()"
)

# Use class_weight='balanced'
full_code = full_code.replace(
    "rf_clf = RandomForestClassifier(n_estimators=50, random_state = random_state)",
    "rf_clf = RandomForestClassifier(n_estimators=50, random_state=random_state, class_weight='balanced', n_jobs=-1)"
)

export_code = """
print("Training finished. Exporting model and preprocessing info...")
import pickle
import json

with open("models/ids_classifier.pkl", "wb") as f:
    pickle.dump(rf_clf, f)

with open("models/ids_scaler.pkl", "wb") as f:
    pickle.dump(sc, f)

feature_cols = [c for c in temp_df.drop('Label', axis=1).columns if c not in ["Label", "label", " Label"]]
with open("models/feature_columns.json", "w") as f:
    json.dump(feature_cols, f, indent=2)

with open("models/columns_to_scale.json", "w") as f:
    json.dump(list(columns_to_scale), f, indent=2)

# Export Binner info
top_ports = list(binner.top_bins_names.index)
with open("models/top_ports.json", "w") as f:
    json.dump([str(x) for x in top_ports], f, indent=2)

# Export Categorical columns info
cat_cols = list(p_one_hotter.categorical_columns)
with open("models/cat_cols.json", "w") as f:
    json.dump(cat_cols, f, indent=2)

print(f"✅ Exported all artifacts!")
"""

full_code += "\n" + export_code

print("Running extracted notebook code...")
exec(full_code, globals())
