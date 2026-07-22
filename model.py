from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

data_file = Path("data/network_logs.csv")
model_folder = Path("models")
model_file = model_folder / "network_attack_model.joblib"

if not data_file.exists():
    raise FileNotFoundError("Network dataset was not found.")

df = pd.read_csv(data_file)

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce",
)

df["bytes"] = pd.to_numeric(
    df["bytes"],
    errors="coerce",
)

df["protocol"] = (
    df["protocol"]
    .astype(str)
    .str.strip()
    .str.upper()
)

df["status"] = (
    df["status"]
    .astype(str)
    .str.strip()
    .str.title()
)

df = df.dropna(
    subset=[
        "timestamp",
        "protocol",
        "bytes",
        "status",
    ]
)

df["hour"] = df["timestamp"].dt.hour

df["target"] = df["status"].map(
    {
        "Normal": 0,
        "Attack": 1,
    }
)

df = df.dropna(subset=["target"])

features = df[
    [
        "protocol",
        "bytes",
        "hour",
    ]
]

target = df["target"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    features,
    target,
    test_size=0.30,
    random_state=42,
    stratify=target,
)

preprocessor = ColumnTransformer(
    transformers=[
        (
            "protocol_encoder",
            OneHotEncoder(handle_unknown="ignore"),
            ["protocol"],
        ),
    ],
    remainder="passthrough",
)

model = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=100,
                random_state=42,
            ),
        ),
    ]
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions,
)

model_folder.mkdir(
    parents=True,
    exist_ok=True,
)

joblib.dump(
    model,
    model_file,
)

print("Model trained successfully. - model.py:126")
print(f"Model accuracy: {accuracy * 100:.2f}% - model.py:127")
print(f"Model saved to: {model_file} - model.py:128")