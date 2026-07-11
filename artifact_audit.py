#!/usr/bin/env python3
"""Audit shortcut-prone inputs in the public JA4Tor train/test tables."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import classifier


SII_COLUMNS = ["Src IP", "Dst IP", "Src Port", "Dst Port"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit(repo: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()


def run_audit(repo: Path, seeds: int) -> tuple[pd.DataFrame, dict]:
    train_path = repo / "data" / "train.csv"
    test_path = repo / "data" / "test.csv"
    train = pd.read_csv(train_path, low_memory=False)
    test = pd.read_csv(test_path, low_memory=False)

    y_train = train.pop("traffic_type")
    y_test = test.pop("traffic_type")
    # Start from the legacy matrix, then remove fields per audit policy.
    x_train = classifier.preprocess_data(train, include_sii=True)
    x_test = classifier.preprocess_data(test, include_sii=True)
    common = list(x_train.columns.intersection(x_test.columns))
    x_train = x_train[common]
    x_test = x_test[common]

    setup_columns = [
        column
        for column in common
        if column.startswith("http_") or column.startswith("tls_")
    ]
    variants = {
        "Legacy public artifact": common,
        "Destination port removed": [
            column for column in common if column != "Dst Port"
        ],
        "All IP/port SII removed": [
            column for column in common if column not in SII_COLUMNS
        ],
        "Behavior only (P+T)": [
            column
            for column in common
            if column not in SII_COLUMNS + setup_columns
        ],
    }

    rows = []
    for variant, columns in variants.items():
        for seed in range(seeds):
            prediction, metadata = classifier.train_predict_pipeline(
                x_train[columns],
                y_train,
                x_test[columns],
                y_test,
                n_bins=50,
                alpha=0.5,
                min_k=5,
                n_estimators=100,
                random_state=seed,
            )
            rows.append(
                {
                    "variant": variant,
                    "seed": seed,
                    "input_features": len(columns),
                    "selected_features": len(metadata["features"]["final"]),
                    **classifier.evaluate(y_test, prediction),
                }
            )

    metadata = {
        "scope": "public artifact audit only",
        "repository": "https://github.com/das-lab/JA4Tor",
        "commit": git_commit(repo),
        "train_sha256": sha256(train_path),
        "test_sha256": sha256(test_path),
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "seeds": seeds,
        "warning": (
            "The public CSV files contain no pcap/session/run identifiers, "
            "so this audit cannot test group-level leakage."
        ),
    }
    return pd.DataFrame(rows), metadata


def plot_audit(results: pd.DataFrame, output: Path) -> None:
    order = list(results["variant"].drop_duplicates())
    summary = results.groupby("variant", sort=False)["f1_macro"].agg(["mean", "std"])
    baseline = float(summary.loc[order[0], "mean"])
    delta = (summary["mean"] - baseline) * 100.0
    error = summary["std"].fillna(0.0) * 100.0

    colors = ["#4C78A8", "#F58518", "#54A24B", "#B279A2"]
    fig, ax = plt.subplots(figsize=(7.2, 3.4), constrained_layout=True)
    positions = np.arange(len(order))
    ax.errorbar(
        positions,
        delta.loc[order],
        yerr=error.loc[order],
        fmt="none",
        ecolor="#333333",
        elinewidth=1.1,
        capsize=3,
        zorder=2,
    )
    ax.scatter(
        positions,
        delta.loc[order],
        s=60,
        c=colors,
        edgecolor="black",
        linewidth=0.5,
        zorder=3,
    )
    ax.axhline(0.0, color="#666666", linewidth=0.9, linestyle="--")
    ax.set_ylabel(r"$\Delta$ Macro-F1 vs. legacy (percentage points)")
    ax.set_xticks(positions, ["Legacy", "No dst. port", "No IP/ports", "P+T only"])
    ax.grid(axis="y", color="#D9D9D9", linewidth=0.7)
    ax.spines[["top", "right"]].set_visible(False)
    for index, variant in enumerate(order):
        absolute = float(summary.loc[variant, "mean"] * 100.0)
        ax.annotate(
            f"{absolute:.2f}%",
            (index, float(delta.loc[variant])),
            xytext=(0, 9 if delta.loc[variant] >= -0.2 else -15),
            textcoords="offset points",
            ha="center",
            fontsize=8,
        )
    fig.savefig(output, format="pdf", bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("artifact_audit"))
    parser.add_argument("--figure", type=Path, default=Path("artifact_sii_audit.pdf"))
    parser.add_argument("--seeds", type=int, default=10)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.figure.parent.mkdir(parents=True, exist_ok=True)
    results, metadata = run_audit(args.repo.resolve(), args.seeds)
    results.to_csv(args.output_dir / "results.csv", index=False)
    summary = results.groupby("variant", sort=False).agg(
        macro_f1_mean=("f1_macro", "mean"),
        macro_f1_std=("f1_macro", "std"),
        accuracy_mean=("accuracy", "mean"),
        weighted_f1_mean=("f1_weighted", "mean"),
        selected_features_mean=("selected_features", "mean"),
    )
    summary.to_csv(args.output_dir / "summary.csv")
    (args.output_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    plot_audit(results, args.figure)
    print(summary.to_string())
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
