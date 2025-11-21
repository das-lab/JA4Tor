import os
import ipaddress
from typing import Dict, List

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


INPUT_DIR = "data"
TRAIN_PATH = os.path.join(INPUT_DIR, "train.csv")
TEST_PATH = os.path.join(INPUT_DIR, "test.csv")
RANDOM_STATE = 42

LABEL_MAP: Dict[int, str] = {
    0: "Normal",
    1: "Tor",
    2: "Tor_SS",
    3: "Tor_Trojan",
    4: "Tor_VMess",
}
TARGET_NAMES: List[str] = [LABEL_MAP[i] for i in sorted(LABEL_MAP.keys())]


def ip_to_int(ip_str: str) -> int:
    try:
        return int(ipaddress.ip_address(ip_str))
    except Exception:
        return 0


def preprocess_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    for col in df.columns:
        if "ip" in col.lower():
            df[col] = df[col].apply(ip_to_int)

    for col in df.columns:
        if not np.issubdtype(df[col].dtype, np.number):
            df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.fillna(0.0)
    return df


def calculate_jsd_score(
    feature_col: pd.Series,
    target_col: pd.Series,
    n_bins: int = 50,
) -> float:
    labels = np.unique(target_col)
    if len(labels) < 2:
        return 0.0

    values = feature_col.to_numpy(dtype=float)
    if not np.isfinite(values).any():
        return 0.0

    min_val = np.nanmin(values)
    max_val = np.nanmax(values)
    if not np.isfinite(min_val) or not np.isfinite(max_val) or min_val == max_val:
        return 0.0

    bins = np.linspace(min_val, max_val, n_bins + 1)
    distributions = []

    label_array = target_col.to_numpy()
    for lbl in labels:
        subset = values[label_array == lbl]
        if subset.size == 0:
            return 0.0
        hist, _ = np.histogram(subset, bins=bins, density=True)
        prob = hist + 1e-10
        total = prob.sum()
        if total <= 0:
            return 0.0
        distributions.append(prob / total)

    scores: List[float] = []
    for i in range(len(distributions)):
        for j in range(i + 1, len(distributions)):
            d = jensenshannon(distributions[i], distributions[j])
            if np.isfinite(d):
                scores.append(float(d))

    if not scores:
        return 0.0
    return float(np.mean(scores))


def get_top_k_features(
    X: pd.DataFrame,
    y: pd.Series,
    k: int = 15,
) -> List[str]:
    jsd_scores: Dict[str, float] = {}
    for col in X.columns:
        jsd_scores[col] = calculate_jsd_score(X[col], y)
    sorted_feats = sorted(jsd_scores.items(), key=lambda item: item[1], reverse=True)
    return [name for name, _ in sorted_feats[:k]]


def train_hierarchical_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    top_k: int = 15,
):
    y_train_l1 = y_train.apply(lambda v: 0 if v == 0 else 1)

    mask_l2 = y_train != 0
    y_train_l2 = y_train[mask_l2].apply(lambda v: 1 if v == 1 else 2)

    mask_l3 = y_train.isin([2, 3, 4])
    y_train_l3 = y_train[mask_l3]

    l1_features = get_top_k_features(X_train, y_train_l1, k=top_k)
    rf_l1 = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_l1.fit(X_train[l1_features], y_train_l1)

    X_train_l2 = X_train[mask_l2]
    l2_features = get_top_k_features(X_train_l2, y_train_l2, k=top_k)
    rf_l2 = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_l2.fit(X_train_l2[l2_features], y_train_l2)

    X_train_l3 = X_train[mask_l3]
    l3_features = get_top_k_features(X_train_l3, y_train_l3, k=top_k)
    rf_l3 = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_l3.fit(X_train_l3[l3_features], y_train_l3)

    models = {
        "l1": (rf_l1, l1_features),
        "l2": (rf_l2, l2_features),
        "l3": (rf_l3, l3_features),
    }
    return models


def predict_hierarchical(
    models,
    X_test: pd.DataFrame,
) -> pd.Series:
    rf_l1, l1_features = models["l1"]
    rf_l2, l2_features = models["l2"]
    rf_l3, l3_features = models["l3"]

    final_preds = pd.Series(index=X_test.index, data=0, dtype=int)

    y_pred_l1 = rf_l1.predict(X_test[l1_features])
    final_preds[y_pred_l1 == 0] = 0
    malicious_indices = X_test.index[y_pred_l1 == 1]

    if malicious_indices.size > 0:
        X_test_l2 = X_test.loc[malicious_indices]
        y_pred_l2 = rf_l2.predict(X_test_l2[l2_features])
        l2_pred_series = pd.Series(y_pred_l2, index=malicious_indices)

        tor_indices = l2_pred_series[l2_pred_series == 1].index
        final_preds.loc[tor_indices] = 1

        encap_indices = l2_pred_series[l2_pred_series == 2].index
        if encap_indices.size > 0:
            X_test_l3 = X_test.loc[encap_indices]
            y_pred_l3 = rf_l3.predict(X_test_l3[l3_features])
            l3_pred_series = pd.Series(y_pred_l3, index=encap_indices)
            final_preds.loc[encap_indices] = l3_pred_series

    return final_preds


def main():
    train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)

    X_train = preprocess_df(train_df.drop(columns=["traffic_type"]))
    y_train = train_df["traffic_type"].astype(int)

    X_test = preprocess_df(test_df.drop(columns=["traffic_type"]))
    y_test = test_df["traffic_type"].astype(int)

    common_cols = sorted(set(X_train.columns) & set(X_test.columns))
    X_train = X_train[common_cols]
    X_test = X_test[common_cols]

    models = train_hierarchical_models(X_train, y_train, top_k=15)
    y_pred = predict_hierarchical(models, X_test)

    print(classification_report(y_test, y_pred, target_names=TARGET_NAMES, digits=4))
    acc = accuracy_score(y_test, y_pred)
    print(f"Overall accuracy: {acc:.4f}")

    output = pd.DataFrame(
        {
            "true_label": y_test,
            "predicted_label": y_pred,
        }
    )
    output.to_csv("hierarchical_rf_predictions.csv", index=False)


if __name__ == "__main__":
    main()
