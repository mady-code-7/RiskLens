"""
train_model.py — one-time (or re-runnable) offline training script.

Reads dataset.csv, converts every URL into numeric features using the
SAME extract_features() function used by the live API (features.py),
trains a RandomForestClassifier on those features, evaluates it, and
saves the trained model to model.pkl using joblib.

This script is NOT called by the live API — it's a manual/offline step.
Re-run it whenever dataset.csv changes or you want to retrain the model:

    python train_model.py
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

from features import extract_features, FEATURE_NAMES

DATASET_PATH = "dataset.csv"
MODEL_OUTPUT_PATH = "model.pkl"


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(
            f"{path} must contain 'url' and 'label' columns. "
            f"Found: {list(df.columns)}"
        )
    return df


def build_feature_table(df: pd.DataFrame) -> pd.DataFrame:
    """Applies extract_features() to every URL and returns a feature table."""
    feature_rows = [extract_features(url) for url in df["url"]]
    return pd.DataFrame(feature_rows, columns=FEATURE_NAMES)


def train_and_evaluate(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nTest accuracy: {accuracy:.4f}\n")
    print("Classification report:")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    # Feature importances give a quick sanity check that the model is
    # actually using sensible signals (not just noise).
    print("Feature importances:")
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda pair: pair[1],
        reverse=True,
    )
    for name, importance in importances:
        print(f"  {name}: {importance:.4f}")

    return model


def main():
    print(f"Loading dataset from {DATASET_PATH}...")
    df = load_dataset(DATASET_PATH)
    print(f"Loaded {len(df)} rows ({df['label'].sum()} phishing, "
          f"{(df['label'] == 0).sum()} legitimate)")

    print("Extracting features from URLs...")
    X = build_feature_table(df)
    y = df["label"]

    print("Training RandomForestClassifier...")
    model = train_and_evaluate(X, y)

    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
    