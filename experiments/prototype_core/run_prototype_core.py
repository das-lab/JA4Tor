#!/usr/bin/env python3
"""Validation-only search and frozen-test evaluation for Prototype-Core JA4Tor."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


LABELS = {"NonTor": 0, "Tor": 1, "Tor-SS": 2, "Tor-Trojan": 3, "Tor-Vmess": 4}
CLASS_NAMES = ["NonTor", "Tor", "Tor-SS", "Tor-Trojan", "Tor-Vmess"]
FUSION_GRID = [0.0, 0.25, 0.5, 0.75, 1.0]


def normalized(name: str) -> str:
    return name.strip().lower().replace(" ", "_")


def prohibited(name: str) -> bool:
    value = normalized(name)
    return (
        value in {
            "flow_id", "timestamp", "protocol", "src_ip", "dst_ip",
            "src_port", "dst_port", "tls_sni_domain", "capture_id", "traffic_type",
        }
        or value.endswith("_hash")
        or "host_hash" in value
        or "domain_hash" in value
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_limits(budget: int) -> dict[str, int]:
    train = int(budget * 0.70)
    validation = int(budget * 0.10)
    return {"train": train, "validation": validation, "test": budget - train - validation}


def read_candidates(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"capture_id", "class", "csv_path", "selection_rank", "split"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Candidate file missing fields: {required}")
    return rows


def selected_records(candidates: list[dict], budget: int, splits: set[str]) -> list[dict]:
    limits = split_limits(budget)
    return [
        row for row in candidates
        if row["split"] in splits and int(row["selection_rank"]) <= limits[row["split"]]
    ]


def load_records(records: list[dict], balance_seed: int = 4242) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for row in records:
        frame = pd.read_csv(row["csv_path"], low_memory=False)
        frame["traffic_type"] = LABELS[row["class"]]
        frame["capture_id"] = row["capture_id"]
        frames.append(frame)
    data = pd.concat(frames, ignore_index=True)
    smallest = int(data.groupby("traffic_type").size().min())
    balanced = [
        group.sample(n=smallest, random_state=balance_seed + int(label))
        for label, group in data.groupby("traffic_type", sort=True)
    ]
    return pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=balance_seed).reset_index(drop=True)


def preprocess(train: pd.DataFrame, *others: pd.DataFrame) -> tuple[pd.DataFrame, ...]:
    columns = [
        column for column in train.columns
        if column not in {"traffic_type", "capture_id"} and not prohibited(column)
    ]
    category_maps: dict[str, dict[str, int]] = {}
    for column in columns:
        if train[column].dtype == "object":
            values = sorted(train[column].fillna("").astype(str).unique())
            category_maps[column] = {value: index for index, value in enumerate(values)}
    outputs: list[pd.DataFrame] = []
    for frame in (train, *others):
        numeric = pd.DataFrame(index=frame.index)
        for column in columns:
            if column in category_maps:
                numeric[column] = frame[column].fillna("").astype(str).map(category_maps[column]).fillna(-1)
            else:
                numeric[column] = pd.to_numeric(frame[column], errors="coerce")
        outputs.append(numeric.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(float))
    return tuple(outputs)


def jsd_score(feature: pd.Series, target: pd.Series, bins: int = 50) -> float:
    low, high = float(feature.min()), float(feature.max())
    if low == high:
        return 0.0
    edges = np.linspace(low, high, bins + 1)
    distributions = []
    for label in sorted(target.unique()):
        histogram, _ = np.histogram(feature[target == label], bins=edges)
        probability = histogram.astype(float) + 1e-12
        distributions.append(probability / probability.sum())
    distances = [
        jensenshannon(distributions[i], distributions[j])
        for i in range(len(distributions)) for j in range(i + 1, len(distributions))
    ]
    return float(np.mean(distances)) if distances else 0.0


def ranked_jsd(X: pd.DataFrame, y: pd.Series) -> list[tuple[str, float]]:
    return sorted(
        ((column, jsd_score(X[column], y)) for column in X.columns),
        key=lambda item: item[1], reverse=True,
    )


def select_jsd(X: pd.DataFrame, y: pd.Series, min_k: int = 5, alpha: float = 0.5) -> list[str]:
    ranked = ranked_jsd(X, y)
    selected = [name for name, _ in ranked[: min(min_k, len(ranked))]]
    for index in range(len(selected), len(ranked)):
        previous = ranked[index - 1][1]
        if previous <= 0 or ranked[index][1] < alpha * previous:
            break
        selected.append(ranked[index][0])
    return selected


def hierarchy_features(X: pd.DataFrame, y: pd.Series) -> list[str]:
    y1 = y.map(lambda value: 0 if value == 0 else 1)
    mask2 = y != 0
    y2 = y[mask2].map(lambda value: 1 if value == 1 else 2)
    mask3 = y.isin([2, 3, 4])
    return sorted(set(select_jsd(X, y1) + select_jsd(X.loc[mask2], y2) + select_jsd(X.loc[mask3], y[mask3])))


def train_experts(X: pd.DataFrame, y: pd.Series, seed: int, n_estimators: int, max_features, features: list[str]) -> dict:
    kwargs = dict(n_estimators=n_estimators, max_features=max_features, n_jobs=-1, random_state=seed)
    y1 = y.map(lambda value: 0 if value == 0 else 1)
    mask2 = y != 0
    y2 = y[mask2].map(lambda value: 1 if value == 1 else 2)
    mask3 = y.isin([2, 3, 4])
    hierarchy = [
        RandomForestClassifier(**kwargs).fit(X[features], y1),
        RandomForestClassifier(**kwargs).fit(X.loc[mask2, features], y2),
        RandomForestClassifier(**kwargs).fit(X.loc[mask3, features], y[mask3]),
    ]
    global_model = RandomForestClassifier(
        **kwargs, criterion="entropy"
    ).fit(X, y)
    return {"hierarchy": hierarchy, "global": global_model, "features": features}


def expert_probabilities(bundle: dict, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    first, second, third = bundle["hierarchy"]
    features = bundle["features"]
    q1 = first.predict_proba(X[features])
    q2 = second.predict_proba(X[features])
    q3 = third.predict_proba(X[features])
    hierarchical = np.zeros((len(X), 5))
    hierarchical[:, 0] = q1[:, 0]
    hierarchical[:, 1] = q1[:, 1] * q2[:, 0]
    hierarchical[:, 2:] = q1[:, 1, None] * q2[:, 1, None] * q3
    return hierarchical, bundle["global"].predict_proba(X)


def hard_hierarchy(bundle: dict, X: pd.DataFrame) -> np.ndarray:
    first, second, third = bundle["hierarchy"]
    features = bundle["features"]
    output = np.zeros(len(X), dtype=int)
    level1 = first.predict(X[features])
    indices2 = np.where(level1 == 1)[0]
    if len(indices2):
        level2 = second.predict(X.iloc[indices2][features])
        output[indices2[level2 == 1]] = 1
        indices3 = indices2[level2 == 2]
        if len(indices3):
            output[indices3] = third.predict(X.iloc[indices3][features])
    return output


def metric_row(y_true, prediction) -> dict[str, float]:
    return {
        "accuracy": accuracy_score(y_true, prediction),
        "precision_macro": precision_score(y_true, prediction, average="macro", zero_division=0),
        "recall_macro": recall_score(y_true, prediction, average="macro", zero_division=0),
        "f1_macro": f1_score(y_true, prediction, average="macro", zero_division=0),
    }


def parse_max_features(value: str):
    return value if value == "sqrt" else float(value)


def prepare_budget(candidates: list[dict], budget: int, include_test: bool):
    splits = {"train", "validation", "test"} if include_test else {"train", "validation"}
    records = selected_records(candidates, budget, splits)
    train = load_records([row for row in records if row["split"] == "train"])
    validation = load_records([row for row in records if row["split"] == "validation"])
    if include_test:
        test = load_records([row for row in records if row["split"] == "test"])
        X_train, X_validation, X_test = preprocess(train, validation, test)
        return train, validation, test, X_train, X_validation, X_test
    X_train, X_validation = preprocess(train, validation)
    return train, validation, X_train, X_validation


def validation_search(args, candidates: list[dict]) -> None:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    search_rows: list[dict] = []
    budgets = [int(value) for value in args.budgets.split(",")]

    def search_budget(budget: int) -> None:
        train, validation, X_train, X_validation = prepare_budget(candidates, budget, False)
        y_train = train["traffic_type"]
        y_validation = validation["traffic_type"]
        features = hierarchy_features(X_train, y_train)
        for n_estimators in (100, 300):
            for max_features_text in ("sqrt", "0.5"):
                by_weight = {weight: [] for weight in FUSION_GRID}
                for seed in range(args.validation_seeds):
                    bundle = train_experts(
                        X_train, y_train, seed, n_estimators,
                        parse_max_features(max_features_text), features,
                    )
                    h_prob, g_prob = expert_probabilities(bundle, X_validation)
                    for weight in FUSION_GRID:
                        prediction = ((1 - weight) * h_prob + weight * g_prob).argmax(axis=1)
                        by_weight[weight].append(f1_score(y_validation, prediction, average="macro"))
                for weight, values in by_weight.items():
                    search_rows.append(
                        {
                            "budget": budget,
                            "n_estimators": n_estimators,
                            "max_features": max_features_text,
                            "fusion_weight": weight,
                            "validation_macro_f1_mean": float(np.mean(values)),
                            "validation_macro_f1_std": float(np.std(values, ddof=1)),
                            "validation_seeds": args.validation_seeds,
                            "hierarchy_features": len(features),
                        }
                    )

    for budget in budgets:
        search_budget(budget)
    best = max(search_rows, key=lambda row: (row["validation_macro_f1_mean"], -row["budget"], -row["n_estimators"]))
    if best["validation_macro_f1_mean"] < args.target_macro_f1 and 400 not in budgets:
        search_budget(400)
        best = max(search_rows, key=lambda row: (row["validation_macro_f1_mean"], -row["budget"], -row["n_estimators"]))

    pd.DataFrame(search_rows).to_csv(args.output_dir / "validation_search.csv", index=False)
    frozen = {
        "candidate_file": str(args.selection_manifest.resolve()),
        "candidate_sha256": file_sha256(args.selection_manifest),
        "selected_budget": int(best["budget"]),
        "n_estimators": int(best["n_estimators"]),
        "max_features": best["max_features"],
        "fusion_weight": float(best["fusion_weight"]),
        "validation_macro_f1_mean": float(best["validation_macro_f1_mean"]),
        "validation_macro_f1_std": float(best["validation_macro_f1_std"]),
        "validation_seeds": list(range(args.validation_seeds)),
        "target_macro_f1": args.target_macro_f1,
        "selection_basis": "validation only",
        "test_opened": False,
        "feature_policy": "SII-free PAST; Prototype-Core ranking uses P/T",
    }
    (args.output_dir / "frozen_config.json").write_text(json.dumps(frozen, indent=2), encoding="utf-8")
    print(json.dumps(frozen, indent=2))


def save_jsd_scores(X: pd.DataFrame, y: pd.Series, output: Path) -> None:
    stages = {
        "NonTor / Tor-family": y.map(lambda value: 0 if value == 0 else 1),
        "Tor / Tor-over-proxy": y[y != 0].map(lambda value: 1 if value == 1 else 2),
        "Proxy family": y[y.isin([2, 3, 4])],
        "Global five-class": y,
    }
    rows = []
    for stage, target in stages.items():
        stage_X = X.loc[target.index]
        for feature, score in ranked_jsd(stage_X, target):
            rows.append({"stage": stage, "feature": feature, "jsd_score": score})
    pd.DataFrame(rows).to_csv(output, index=False)


def frozen_test(args, candidates: list[dict]) -> None:
    config = json.loads(args.frozen_config.read_text(encoding="utf-8"))
    if config.get("candidate_sha256") != file_sha256(args.selection_manifest):
        raise ValueError("Candidate file differs from frozen validation search")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if (args.output_dir / "test_results.csv").exists():
        raise FileExistsError("Test results already exist; refusing repeated test evaluation")

    budget = int(config["selected_budget"])
    train, validation, test, X_train, X_validation, X_test = prepare_budget(candidates, budget, True)
    combined = pd.concat([train, validation], ignore_index=True)
    X_combined, X_test = preprocess(combined, test)
    y_combined = combined["traffic_type"]
    y_test = test["traffic_type"]
    features = hierarchy_features(X_combined, y_combined)
    rows: list[dict] = []
    reports: list[dict] = []
    matrices: list[np.ndarray] = []
    ratio_rows: list[dict] = []
    open_world_rows: list[dict] = []

    for seed in range(args.test_seeds):
        start = time.perf_counter()
        bundle = train_experts(
            X_combined, y_combined, seed, int(config["n_estimators"]),
            parse_max_features(str(config["max_features"])), features,
        )
        h_prob, g_prob = expert_probabilities(bundle, X_test)
        weight = float(config["fusion_weight"])
        predictions = {
            "Hard Hierarchy": hard_hierarchy(bundle, X_test),
            "JA4Tor-H": h_prob.argmax(axis=1),
            "JA4Tor-G": g_prob.argmax(axis=1),
            "JA4Tor-DPF": ((1 - weight) * h_prob + weight * g_prob).argmax(axis=1),
        }
        expert_elapsed = time.perf_counter() - start
        runtimes = {name: expert_elapsed for name in predictions}

        baselines = {
            "Logistic Regression": make_pipeline(
                StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed)
            ),
            "ExtraTrees": ExtraTreesClassifier(n_estimators=300, max_features=0.5, n_jobs=-1, random_state=seed),
            "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=200, random_state=seed),
        }
        for name, model in baselines.items():
            baseline_start = time.perf_counter()
            model.fit(X_combined, y_combined)
            predictions[name] = model.predict(X_test)
            runtimes[name] = time.perf_counter() - baseline_start

        for name, prediction in predictions.items():
            rows.append({"variant": name, "seed": seed, "training_and_inference_seconds": runtimes[name], **metric_row(y_test, prediction)})
        dpf_prediction = predictions["JA4Tor-DPF"]
        matrices.append(confusion_matrix(y_test, dpf_prediction, labels=list(range(5))))
        report = classification_report(y_test, dpf_prediction, labels=list(range(5)), target_names=CLASS_NAMES, output_dict=True, zero_division=0)
        for class_name in CLASS_NAMES:
            reports.append({"seed": seed, "class": class_name, **report[class_name]})

        non_tor = np.where(y_test.to_numpy() == 0)[0]
        tor_family = {label: np.where(y_test.to_numpy() == label)[0] for label in [1, 2, 3, 4]}
        for ratio in [0.25, 0.5, 1, 2, 4, 8]:
            tor_total = max(4, int(len(non_tor) / ratio))
            per_class = max(1, tor_total // 4)
            rng = np.random.default_rng(10000 + seed + int(ratio * 100))
            chosen = list(non_tor)
            for label in [1, 2, 3, 4]:
                count = min(per_class, len(tor_family[label]))
                chosen.extend(rng.choice(tor_family[label], size=count, replace=False).tolist())
            chosen = np.asarray(chosen)
            ratio_rows.append(
                {
                    "seed": seed,
                    "nontor_to_torfamily_ratio": ratio,
                    "macro_f1": f1_score(y_test.iloc[chosen], dpf_prediction[chosen], average="macro"),
                    "accuracy": accuracy_score(y_test.iloc[chosen], dpf_prediction[chosen]),
                    "sample_count": len(chosen),
                }
            )

        if seed < 5:
            for held_label in [2, 3, 4]:
                known_train = y_combined != held_label
                open_model = RandomForestClassifier(
                    n_estimators=int(config["n_estimators"]),
                    max_features=parse_max_features(str(config["max_features"])),
                    criterion="entropy", n_jobs=-1, random_state=seed,
                ).fit(X_combined.loc[known_train], y_combined.loc[known_train])
                confidence = open_model.predict_proba(X_test).max(axis=1)
                unknown_mask = y_test.to_numpy() == held_label
                known_mask = ~unknown_mask
                for threshold in np.linspace(0.5, 0.95, 10):
                    unknown_detection = float(np.mean(confidence[unknown_mask] < threshold))
                    known_retention = float(np.mean(confidence[known_mask] >= threshold))
                    open_world_rows.append(
                        {
                            "seed": seed,
                            "held_out_class": CLASS_NAMES[held_label],
                            "threshold": threshold,
                            "unknown_detection_rate": unknown_detection,
                            "known_retention_rate": known_retention,
                            "balanced_rate": 0.5 * (unknown_detection + known_retention),
                        }
                    )

    results = pd.DataFrame(rows)
    results.to_csv(args.output_dir / "test_results.csv", index=False)
    summary = results.groupby("variant", sort=False).agg(
        accuracy_mean=("accuracy", "mean"), accuracy_std=("accuracy", "std"),
        precision_mean=("precision_macro", "mean"), recall_mean=("recall_macro", "mean"),
        macro_f1_mean=("f1_macro", "mean"), macro_f1_std=("f1_macro", "std"),
        runtime_mean=("training_and_inference_seconds", "mean"),
    )
    summary.to_csv(args.output_dir / "summary.csv")
    pd.DataFrame(reports).to_csv(args.output_dir / "per_class_metrics.csv", index=False)
    pd.DataFrame(ratio_rows).to_csv(args.output_dir / "class_ratio.csv", index=False)
    pd.DataFrame(open_world_rows).to_csv(args.output_dir / "open_world.csv", index=False)
    np.save(args.output_dir / "confusion_matrix.npy", np.mean(matrices, axis=0))
    save_jsd_scores(X_combined, y_combined, args.output_dir / "jsd_scores.csv")
    access = {
        "test_opened": True,
        "test_seeds": list(range(args.test_seeds)),
        "budget": budget,
        "test_capture_count": len(selected_records(candidates, budget, {"test"})),
        "test_flow_rows_per_class": int(test.groupby("traffic_type").size().min()),
    }
    (args.output_dir / "test_access.json").write_text(json.dumps(access, indent=2), encoding="utf-8")
    print(summary.to_string())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--validation-only", action="store_true")
    parser.add_argument("--frozen-config", type=Path)
    parser.add_argument("--budgets", default="100,200,300")
    parser.add_argument("--validation-seeds", type=int, default=5)
    parser.add_argument("--test-seeds", type=int, default=10)
    parser.add_argument("--target-macro-f1", type=float, default=0.985)
    args = parser.parse_args()
    if args.validation_only == bool(args.frozen_config):
        raise ValueError("Choose exactly one of --validation-only or --frozen-config")
    candidates = read_candidates(args.selection_manifest)
    if args.validation_only:
        validation_search(args, candidates)
    else:
        frozen_test(args, candidates)


if __name__ == "__main__":
    main()
