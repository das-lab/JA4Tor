import argparse
import ipaddress
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


def ip_to_int(ip_str: str) -> int:
    try:
        return int(ipaddress.ip_address(ip_str))
    except Exception:
        return 0


def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    if "Src IP" in df.columns:
        df["Src IP"] = df["Src IP"].apply(ip_to_int)
    if "Dst IP" in df.columns:
        df["Dst IP"] = df["Dst IP"].apply(ip_to_int)

    cols_to_drop = ["Flow ID", "Timestamp", "Protocol"]
    df = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors="ignore")

    df = df.fillna(0)
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def calculate_jsd(feature_col: pd.Series, target_col: pd.Series, n_bins: int = 50) -> float:
    unique_labels = np.unique(target_col)
    if len(unique_labels) < 2:
        return 0.0

    min_val, max_val = feature_col.min(), feature_col.max()
    if min_val == max_val:
        return 0.0

    bins = np.linspace(min_val, max_val, n_bins + 1)

    distributions = []
    for label in unique_labels:
        subset = feature_col[target_col == label]
        hist, _ = np.histogram(subset, bins=bins, density=True)
        prob = hist + 1e-12
        distributions.append(prob / prob.sum())

    scores = []
    for i in range(len(distributions)):
        for j in range(i + 1, len(distributions)):
            scores.append(jensenshannon(distributions[i], distributions[j]))

    return float(np.mean(scores)) if scores else 0.0


def select_features_jsd(
    X: pd.DataFrame,
    y: pd.Series,
    n_bins: int = 50,
    alpha: float = 0.5,
    min_k: int = 5,
) -> List[str]:
    jsd_scores: Dict[str, float] = {}
    for col in X.columns:
        jsd_scores[col] = calculate_jsd(X[col], y, n_bins=n_bins)

    sorted_items = sorted(jsd_scores.items(), key=lambda item: item[1], reverse=True)
    if not sorted_items:
        return []

    min_k = max(1, min(min_k, len(sorted_items)))
    selected = [name for name, _ in sorted_items[:min_k]]

    for i in range(min_k, len(sorted_items)):
        current_score = sorted_items[i][1]
        prev_score = sorted_items[i - 1][1]

        if prev_score <= 0:
            break

        if current_score < alpha * prev_score:
            break

        selected.append(sorted_items[i][0])

    return selected


def train_predict_pipeline(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    n_bins: int,
    alpha: float,
    min_k: int,
    n_estimators: int,
    random_state: int,
) -> Tuple[pd.Series, Dict[str, Dict[str, object]]]:
    # Level 1: NonTor vs Others
    y_train_l1 = y_train.apply(lambda x: 0 if x == 0 else 1)
    l1_feats = select_features_jsd(X_train, y_train_l1, n_bins=n_bins, alpha=alpha, min_k=min_k)

    # Level 2: Tor vs Tor-over-proxy
    mask_l2 = y_train != 0
    X_train_l2 = X_train[mask_l2]
    y_train_l2 = y_train[mask_l2].apply(lambda x: 1 if x == 1 else 2)
    l2_feats = select_features_jsd(X_train_l2, y_train_l2, n_bins=n_bins, alpha=alpha, min_k=min_k)

    # Level 3: Proxy type classification among encap classes
    mask_l3 = y_train.isin([2, 3, 4])
    X_train_l3 = X_train[mask_l3]
    y_train_l3 = y_train[mask_l3]
    l3_feats = select_features_jsd(X_train_l3, y_train_l3, n_bins=n_bins, alpha=alpha, min_k=min_k)

    final_feature_set = sorted(list(set(l1_feats + l2_feats + l3_feats)))
    if not final_feature_set:
        final_feature_set = list(X_train.columns)

    rf_l1 = RandomForestClassifier(
        n_estimators=n_estimators, n_jobs=-1, random_state=random_state
    )
    rf_l2 = RandomForestClassifier(
        n_estimators=n_estimators, n_jobs=-1, random_state=random_state
    )
    rf_l3 = RandomForestClassifier(
        n_estimators=n_estimators, n_jobs=-1, random_state=random_state
    )

    rf_l1.fit(X_train[final_feature_set], y_train_l1)
    rf_l2.fit(X_train_l2[final_feature_set], y_train_l2)
    rf_l3.fit(X_train_l3[final_feature_set], y_train_l3)

    final_preds = pd.Series(0, index=X_test.index, dtype=int)
    X_test_filtered = X_test[final_feature_set]

    pred_l1 = rf_l1.predict(X_test_filtered)
    malicious_idx = X_test.index[pred_l1 == 1]

    if len(malicious_idx) > 0:
        X_test_l2 = X_test_filtered.loc[malicious_idx]
        pred_l2 = rf_l2.predict(X_test_l2)
        l2_series = pd.Series(pred_l2, index=malicious_idx)

        tor_idx = l2_series[l2_series == 1].index
        final_preds.loc[tor_idx] = 1

        encap_idx = l2_series[l2_series == 2].index
        if len(encap_idx) > 0:
            X_test_l3 = X_test_filtered.loc[encap_idx]
            pred_l3 = rf_l3.predict(X_test_l3)
            final_preds.loc[encap_idx] = pred_l3

    meta = {
        "features": {
            "l1": l1_feats,
            "l2": l2_feats,
            "l3": l3_feats,
            "final": final_feature_set,
        },
        "models": {"l1": rf_l1, "l2": rf_l2, "l3": rf_l3},
    }
    return final_preds, meta


def evaluate(y_true: pd.Series, y_pred: pd.Series) -> Dict[str, float]:
    out = {}
    out["accuracy"] = accuracy_score(y_true, y_pred)
    out["precision_macro"] = precision_score(y_true, y_pred, average="macro", zero_division=0)
    out["recall_macro"] = recall_score(y_true, y_pred, average="macro", zero_division=0)
    out["f1_macro"] = f1_score(y_true, y_pred, average="macro", zero_division=0)
    out["precision_weighted"] = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    out["recall_weighted"] = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    out["f1_weighted"] = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    return out


def setup_logger(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("ja4tor")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


def run_once(
    train_csv: Path,
    test_csv: Path,
    n_bins: int,
    alpha: float,
    min_k: int,
    n_estimators: int,
    random_state: int,
    logger: logging.Logger,
) -> Dict[str, object]:
    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)

    if "traffic_type" not in train_df.columns or "traffic_type" not in test_df.columns:
        raise ValueError("Missing traffic_type column in train or test CSV")

    y_train = train_df["traffic_type"]
    X_train = preprocess_data(train_df.drop("traffic_type", axis=1))

    y_test = test_df["traffic_type"]
    X_test = preprocess_data(test_df.drop("traffic_type", axis=1))

    common_cols = X_train.columns.intersection(X_test.columns)
    X_train = X_train[common_cols]
    X_test = X_test[common_cols]

    preds, meta = train_predict_pipeline(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        n_bins=n_bins,
        alpha=alpha,
        min_k=min_k,
        n_estimators=n_estimators,
        random_state=random_state,
    )

    metrics = evaluate(y_test, preds)

    feat_info = meta["features"]
    result = {
        "alpha": alpha,
        "n_bins": n_bins,
        "min_k": min_k,
        "n_features_l1": len(feat_info["l1"]),
        "n_features_l2": len(feat_info["l2"]),
        "n_features_l3": len(feat_info["l3"]),
        "n_features_final": len(feat_info["final"]),
        **metrics,
    }

    logger.info(
        f"alpha={alpha} n_bins={n_bins} min_k={min_k} "
        f"final_features={result['n_features_final']} "
        f"f1_macro={result['f1_macro']:.6f} f1_weighted={result['f1_weighted']:.6f}"
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=str, default="data/train.csv")
    parser.add_argument("--test", type=str, default="data/test.csv")
    parser.add_argument("--alpha", type=float, default=0.5)
    parser.add_argument("--n-bins", type=int, default=50)
    parser.add_argument("--min-k", type=int, default=5)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--random-state", type=int, default=0)
    parser.add_argument("--log-file", type=str, default="results/run_one.log")
    args = parser.parse_args()

    train_csv = Path(args.train)
    test_csv = Path(args.test)
    log_path = Path(args.log_file)

    logger = setup_logger(log_path)

    if not train_csv.exists():
        raise FileNotFoundError(f"Train CSV not found: {train_csv}")
    if not test_csv.exists():
        raise FileNotFoundError(f"Test CSV not found: {test_csv}")

    logger.info(f"Train CSV: {train_csv}")
    logger.info(f"Test CSV: {test_csv}")

    np.random.seed(args.random_state)

    _ = run_once(
        train_csv=train_csv,
        test_csv=test_csv,
        n_bins=args.n_bins,
        alpha=args.alpha,
        min_k=args.min_k,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
        logger=logger,
    )


if __name__ == "__main__":
    main()