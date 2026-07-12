#!/usr/bin/env python3
"""Run the SII-free Dual-Path PAST Fusion experiment."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


LABELS = {"NonTor": 0, "Tor": 1, "Tor-SS": 2, "Tor-Trojan": 3, "Tor-Vmess": 4}
CLASS_NAMES = ["NonTor", "Tor", "Tor-SS", "Tor-Trojan", "Tor-Vmess"]
DROP_COLUMNS = {
    "Flow ID",
    "Timestamp",
    "Protocol",
    "Src IP",
    "Dst IP",
    "Src Port",
    "Dst Port",
    "tls_sni_domain",
    "http_host_hash",
    "http_user_agent_hash",
    "http_req_header_hash",
    "http_req_cookie_hash",
    "tls_client_cipher_hash",
    "tls_client_extension_hash",
    "tls_server_extension_hash",
}
SETUP_PREFIXES = ("http_", "tls_")
PERFORMANCE_TOKENS = (
    "Duration",
    "Bytes/s",
    "Packets/s",
    "IAT",
    "Active",
    "Idle",
    "latency",
)


def prohibited(column: str) -> bool:
    normalized = column.lower().replace(" ", "_")
    exact = {
        "flow_id", "timestamp", "protocol", "src_ip", "dst_ip",
        "src_port", "dst_port", "tls_sni_domain",
    }
    high_cardinality = (
        normalized.endswith("_hash")
        or "host_hash" in normalized
        or "domain_hash" in normalized
    )
    return column in DROP_COLUMNS or normalized in exact or high_cardinality


def load_partition(manifest: pd.DataFrame, split: str, cap: int, seed: int) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    selected = manifest.loc[manifest["split"] == split]
    for row in selected.to_dict(orient="records"):
        frame = pd.read_csv(row["csv_path"], low_memory=False)
        frame["traffic_type"] = LABELS[row["class"]]
        frame["capture_id"] = row["capture_id"]
        frames.append(frame)
    if not frames:
        raise ValueError(f"No rows for split {split}")
    data = pd.concat(frames, ignore_index=True)
    sampled = []
    for label, group in data.groupby("traffic_type", sort=True):
        count = min(cap, len(group))
        sampled.append(group.sample(n=count, random_state=seed + int(label)))
    return pd.concat(sampled, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)


def fit_preprocessor(train: pd.DataFrame, *others: pd.DataFrame) -> tuple[pd.DataFrame, ...]:
    feature_columns = [
        column
        for column in train.columns
        if column not in {"traffic_type", "capture_id"} and not prohibited(column)
    ]
    outputs = []
    category_maps: dict[str, dict[str, int]] = {}
    for column in feature_columns:
        if train[column].dtype == "object":
            values = sorted(train[column].fillna("").astype(str).unique())
            category_maps[column] = {value: index for index, value in enumerate(values)}
    for frame in (train, *others):
        numeric = pd.DataFrame(index=frame.index)
        for column in feature_columns:
            if column in category_maps:
                numeric[column] = (
                    frame[column].fillna("").astype(str).map(category_maps[column]).fillna(-1)
                )
            else:
                numeric[column] = pd.to_numeric(frame[column], errors="coerce")
        numeric = numeric.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        outputs.append(numeric.astype(float))
    return tuple(outputs)


def calculate_jsd(feature: pd.Series, target: pd.Series, bins: int = 50) -> float:
    if feature.min() == feature.max():
        return 0.0
    edges = np.linspace(feature.min(), feature.max(), bins + 1)
    distributions = []
    for label in sorted(target.unique()):
        histogram, _ = np.histogram(feature[target == label], bins=edges)
        probability = histogram.astype(float) + 1e-12
        distributions.append(probability / probability.sum())
    distances = [
        jensenshannon(distributions[left], distributions[right])
        for left in range(len(distributions))
        for right in range(left + 1, len(distributions))
    ]
    return float(np.mean(distances)) if distances else 0.0


def select_jsd(X: pd.DataFrame, y: pd.Series, alpha: float = 0.5, min_k: int = 5) -> list[str]:
    ranked = sorted(
        ((column, calculate_jsd(X[column], y)) for column in X.columns),
        key=lambda item: item[1],
        reverse=True,
    )
    selected = [column for column, _ in ranked[: min(min_k, len(ranked))]]
    for index in range(len(selected), len(ranked)):
        if ranked[index - 1][1] <= 0 or ranked[index][1] < alpha * ranked[index - 1][1]:
            break
        selected.append(ranked[index][0])
    return selected


def feature_views(columns: list[str]) -> dict[str, list[str]]:
    setup = [column for column in columns if column.startswith(SETUP_PREFIXES)]
    performance = [column for column in columns if any(token in column for token in PERFORMANCE_TOKENS)]
    transport = [column for column in columns if column not in set(setup + performance)]
    return {"full": columns, "pt": performance + transport, "as": setup}


def train_hierarchy(X: pd.DataFrame, y: pd.Series, seed: int, use_jsd: bool) -> dict:
    y1 = y.map(lambda value: 0 if value == 0 else 1)
    mask2 = y != 0
    y2 = y[mask2].map(lambda value: 1 if value == 1 else 2)
    mask3 = y.isin([2, 3, 4])
    y3 = y[mask3]
    if use_jsd:
        features = sorted(
            set(
                select_jsd(X, y1)
                + select_jsd(X.loc[mask2], y2)
                + select_jsd(X.loc[mask3], y3)
            )
        )
    else:
        features = list(X.columns)
    kwargs = dict(n_estimators=100, n_jobs=-1, random_state=seed)
    models = [
        RandomForestClassifier(**kwargs).fit(X[features], y1),
        RandomForestClassifier(**kwargs).fit(X.loc[mask2, features], y2),
        RandomForestClassifier(**kwargs).fit(X.loc[mask3, features], y3),
    ]
    return {"models": models, "features": features}


def hierarchy_probabilities(bundle: dict, X: pd.DataFrame) -> np.ndarray:
    first, second, third = bundle["models"]
    features = bundle["features"]
    q1 = first.predict_proba(X[features])
    q2 = second.predict_proba(X[features])
    q3 = third.predict_proba(X[features])
    probability = np.zeros((len(X), 5))
    probability[:, 0] = q1[:, 0]
    probability[:, 1] = q1[:, 1] * q2[:, 0]
    probability[:, 2:] = q1[:, 1, None] * q2[:, 1, None] * q3
    return probability


def hard_hierarchy(bundle: dict, X: pd.DataFrame) -> np.ndarray:
    first, second, third = bundle["models"]
    features = bundle["features"]
    prediction = np.zeros(len(X), dtype=int)
    level1 = first.predict(X[features])
    tunnel_indices = np.where(level1 == 1)[0]
    if len(tunnel_indices):
        level2 = second.predict(X.iloc[tunnel_indices][features])
        prediction[tunnel_indices[level2 == 1]] = 1
        proxy_indices = tunnel_indices[level2 == 2]
        if len(proxy_indices):
            prediction[proxy_indices] = third.predict(X.iloc[proxy_indices][features])
    return prediction


def metrics(y_true: pd.Series, prediction: np.ndarray) -> dict[str, float]:
    return {
        "accuracy": accuracy_score(y_true, prediction),
        "precision_macro": precision_score(y_true, prediction, average="macro", zero_division=0),
        "recall_macro": recall_score(y_true, prediction, average="macro", zero_division=0),
        "f1_macro": f1_score(y_true, prediction, average="macro", zero_division=0),
    }


def run_seed(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_validation: pd.DataFrame,
    y_validation: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    seed: int,
    view: str,
    use_jsd: bool,
    mode: str,
    fixed_weight: float | None,
) -> tuple[list[dict], dict, np.ndarray]:
    columns = feature_views(list(X_train.columns))[view]
    if not columns:
        raise ValueError(f"Feature view {view} is empty")
    train_start = time.perf_counter()
    hierarchy = train_hierarchy(X_train[columns], y_train, seed, use_jsd)
    global_model = RandomForestClassifier(
        n_estimators=100,
        n_jobs=-1,
        random_state=seed,
        max_features=0.5,
        criterion="entropy",
    ).fit(X_train[columns], y_train)
    training_seconds = time.perf_counter() - train_start

    h_validation = hierarchy_probabilities(hierarchy, X_validation[columns])
    g_validation = global_model.predict_proba(X_validation[columns])
    candidates = [0.0, 0.25, 0.5, 0.75, 1.0]
    validation_scores = {
        weight: f1_score(
            y_validation,
            ((1.0 - weight) * h_validation + weight * g_validation).argmax(axis=1),
            average="macro",
        )
        for weight in candidates
    }
    selected_weight = (
        fixed_weight
        if fixed_weight is not None
        else max(candidates, key=lambda weight: (validation_scores[weight], -weight))
    )

    inference_start = time.perf_counter()
    h_test = hierarchy_probabilities(hierarchy, X_test[columns])
    g_test = global_model.predict_proba(X_test[columns])
    dpf_prediction = ((1.0 - selected_weight) * h_test + selected_weight * g_test).argmax(axis=1)
    inference_ms = (time.perf_counter() - inference_start) * 1000.0 / len(X_test)

    variants = {
        f"Hierarchical-{view.upper()}": h_test.argmax(axis=1),
        f"Global-{view.upper()}": g_test.argmax(axis=1),
        f"DPF-{view.upper()}{'' if use_jsd else '-NoJSD'}": dpf_prediction,
        f"HardHierarchy-{view.upper()}": hard_hierarchy(hierarchy, X_test[columns]),
    }
    if mode == "hierarchical":
        variants = {key: value for key, value in variants.items() if key.startswith("Hierarchical")}
    elif mode == "global":
        variants = {key: value for key, value in variants.items() if key.startswith("Global")}
    rows = []
    for variant, prediction in variants.items():
        rows.append(
            {
                "variant": variant,
                "seed": seed,
                "fusion_weight": selected_weight if variant.startswith("DPF") else np.nan,
                "training_seconds": training_seconds,
                "inference_ms_per_flow": inference_ms,
                "input_features": len(columns),
                "hierarchy_features": len(hierarchy["features"]),
                **metrics(y_test, prediction),
            }
        )
    detail = {
        "seed": seed,
        "view": view,
        "use_jsd": use_jsd,
        "validation_f1_by_weight": validation_scores,
        "selected_weight": selected_weight,
        "selected_hierarchy_features": hierarchy["features"],
        "classification_report": classification_report(
            y_test,
            dpf_prediction,
            labels=list(range(5)),
            target_names=CLASS_NAMES,
            output_dict=True,
            zero_division=0,
        ),
    }
    return rows, detail, confusion_matrix(y_test, dpf_prediction, labels=list(range(5)))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=["hierarchical", "global", "dual-path"], default="dual-path")
    parser.add_argument("--fusion-weight", type=float, default=None)
    parser.add_argument("--random-seed", type=int, default=None)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--train-cap", type=int, default=4000)
    parser.add_argument("--validation-cap", type=int, default=500)
    parser.add_argument("--test-cap", type=int, default=1000)
    args = parser.parse_args()

    manifest = pd.read_csv(args.split_manifest)
    split_sets = {
        split: set(manifest.loc[manifest["split"] == split, "capture_id"])
        for split in ["train", "validation", "test"]
    }
    if split_sets["train"] & split_sets["validation"] or split_sets["train"] & split_sets["test"] or split_sets["validation"] & split_sets["test"]:
        raise ValueError("capture_id leakage across manifest splits")

    train = load_partition(manifest, "train", args.train_cap, 42)
    validation = load_partition(manifest, "validation", args.validation_cap, 42)
    test = load_partition(manifest, "test", args.test_cap, 42)
    X_train, X_validation, X_test = fit_preprocessor(train, validation, test)
    y_train = train["traffic_type"]
    y_validation = validation["traffic_type"]
    y_test = test["traffic_type"]

    seeds = [args.random_seed] if args.random_seed is not None else list(range(args.seeds))
    all_rows: list[dict] = []
    all_details: list[dict] = []
    confusion_matrices: list[np.ndarray] = []
    for seed in seeds:
        for view, use_jsd in [("full", True), ("full", False), ("pt", True), ("as", True)]:
            rows, detail, matrix = run_seed(
                X_train,
                y_train,
                X_validation,
                y_validation,
                X_test,
                y_test,
                int(seed),
                view,
                use_jsd,
                args.mode,
                args.fusion_weight,
            )
            all_rows.extend(rows)
            all_details.append(detail)
            if view == "full" and use_jsd:
                confusion_matrices.append(matrix)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = pd.DataFrame(all_rows)
    results.to_csv(args.output_dir / "results.csv", index=False)
    summary = results.groupby("variant", sort=False).agg(
        macro_f1_mean=("f1_macro", "mean"),
        macro_f1_std=("f1_macro", "std"),
        accuracy_mean=("accuracy", "mean"),
        precision_mean=("precision_macro", "mean"),
        recall_mean=("recall_macro", "mean"),
        training_seconds_mean=("training_seconds", "mean"),
        inference_ms_per_flow_mean=("inference_ms_per_flow", "mean"),
    )
    summary.to_csv(args.output_dir / "summary.csv")
    (args.output_dir / "details.json").write_text(
        json.dumps(all_details, indent=2, default=float), encoding="utf-8"
    )
    np.save(args.output_dir / "confusion_matrix.npy", np.mean(confusion_matrices, axis=0))
    config = {
        "manifest": str(args.split_manifest.resolve()),
        "seeds": seeds,
        "sample_caps": {
            "train": args.train_cap,
            "validation": args.validation_cap,
            "test": args.test_cap,
        },
        "dropped_columns": sorted(DROP_COLUMNS),
        "fusion_grid": [0.0, 0.25, 0.5, 0.75, 1.0],
        "mode": args.mode,
        "fixed_fusion_weight": args.fusion_weight,
        "lambda_selected_on": "validation only",
    }
    (args.output_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(summary.to_string())


if __name__ == "__main__":
    main()

