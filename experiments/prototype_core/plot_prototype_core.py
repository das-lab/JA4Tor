#!/usr/bin/env python3
"""Generate large-font vector figures from measured Prototype-Core CSV outputs."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Rectangle


BLUE = "#0072B2"
GREEN = "#009E73"
ORANGE = "#E69F00"
GRAY = "#6B7280"
LIGHT_GRAY = "#D1D5DB"

mpl.rcParams.update(
    {
        "font.family": "STIXGeneral",
        "font.size": 12,
        "axes.labelsize": 12,
        "axes.titlesize": 12,
        "xtick.labelsize": 11,
        "ytick.labelsize": 11,
        "legend.fontsize": 10.8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)


def save(fig: plt.Figure, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, format="pdf", bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)


def vector_heatmap(ax: plt.Axes, matrix: np.ndarray, cmap_name: str, vmin: float, vmax: float) -> None:
    """Draw heatmap cells as vector rectangles instead of embedded raster images."""
    cmap = mpl.colormaps[cmap_name]
    norm = mpl.colors.Normalize(vmin=vmin, vmax=vmax)
    for row in range(matrix.shape[0]):
        for column in range(matrix.shape[1]):
            ax.add_patch(
                Rectangle(
                    (column, row), 1, 1,
                    facecolor=cmap(norm(matrix[row, column])),
                    edgecolor="white", linewidth=0.35,
                )
            )


def summary_frame(result_dir: Path) -> pd.DataFrame:
    return pd.read_csv(result_dir / "summary.csv", index_col=0)


def main_comparison(result_dir: Path, out: Path) -> None:
    summary = summary_frame(result_dir)
    order = [
        "Logistic Regression", "HistGradientBoosting", "ExtraTrees",
        "Hard Hierarchy", "JA4Tor-H", "JA4Tor-G", "JA4Tor-DPF",
    ]
    present = [name for name in order if name in summary.index]
    means = np.array([summary.loc[name, "macro_f1_mean"] * 100 for name in present])
    stds = np.array([summary.loc[name, "macro_f1_std"] * 100 for name in present])
    colors = [GRAY if name in {"Logistic Regression", "HistGradientBoosting", "ExtraTrees"} else BLUE for name in present]
    colors[-1] = ORANGE
    markers = ["s" if color == GRAY else "o" for color in colors]
    y = np.arange(len(present))
    fig, ax = plt.subplots(figsize=(5.2, 4.4), constrained_layout=True)
    for value, error, position, color, marker in zip(means, stds, y, colors, markers):
        ax.errorbar(value, position, xerr=error, fmt=marker, color=color, ecolor=color, capsize=4, markersize=7, linewidth=1.5)
        ax.text(value + 0.08, position, f"{value:.2f}", va="center", ha="left", fontsize=10.8, color=color)
    ax.set_yticks(y, present)
    ax.invert_yaxis()
    ax.set_xlabel("Macro-F1 (%)")
    ax.set_xlim(max(0, np.floor(means.min()) - 1), min(100.2, means.max() + 0.7))
    ax.grid(axis="x", color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    save(fig, out / "main_comparison.pdf")


def ablation_sensitivity(result_dir: Path, out: Path) -> None:
    summary = summary_frame(result_dir)
    labels = ["Hard route", "H only", "G only", "DPF"]
    variants = ["Hard Hierarchy", "JA4Tor-H", "JA4Tor-G", "JA4Tor-DPF"]
    values = [summary.loc[name, "macro_f1_mean"] * 100 for name in variants]
    search = pd.read_csv(result_dir / "validation_search.csv")
    config = __import__("json").loads((result_dir / "frozen_config.json").read_text())
    chosen = search[
        (search["budget"] == config["selected_budget"])
        & (search["n_estimators"] == config["n_estimators"])
        & (search["max_features"].astype(str) == str(config["max_features"]))
    ].sort_values("fusion_weight")

    fig, axes = plt.subplots(1, 2, figsize=(5.6, 4.3), constrained_layout=True, gridspec_kw={"wspace": 0.38})
    colors = [GRAY, BLUE, GREEN, ORANGE]
    axes[0].barh(np.arange(4), values, color=colors, height=0.62)
    axes[0].set_yticks(np.arange(4), labels)
    axes[0].invert_yaxis()
    axes[0].set_xlabel("Test macro-F1 (%)")
    axes[0].set_xlim(max(0, np.floor(min(values)) - 1), min(100.2, max(values) + 0.8))
    for index, value in enumerate(values):
        axes[0].text(value + 0.08, index, f"{value:.2f}", va="center", fontsize=10.8, color=colors[index])
    axes[0].text(0.0, 1.04, "(a) Components", transform=axes[0].transAxes, fontweight="bold")

    axes[1].plot(chosen["fusion_weight"], chosen["validation_macro_f1_mean"] * 100, color=BLUE, marker="o", linewidth=1.8, markersize=6)
    axes[1].fill_between(
        chosen["fusion_weight"].to_numpy(dtype=float),
        (chosen["validation_macro_f1_mean"] - chosen["validation_macro_f1_std"]).to_numpy(dtype=float) * 100,
        (chosen["validation_macro_f1_mean"] + chosen["validation_macro_f1_std"]).to_numpy(dtype=float) * 100,
        color=BLUE, alpha=0.16,
    )
    axes[1].axvline(config["fusion_weight"], color=ORANGE, linestyle="--", linewidth=1.5, label=f"selected λ={config['fusion_weight']}")
    axes[1].set_xlabel("Fusion weight λ")
    axes[1].set_ylabel("Validation macro-F1 (%)")
    axes[1].set_xticks([0, 0.25, 0.5, 0.75, 1])
    axes[1].grid(color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    axes[1].legend(frameon=False, loc="lower right")
    axes[1].text(0.0, 1.04, "(b) Validation sensitivity", transform=axes[1].transAxes, fontweight="bold")
    save(fig, out / "dpf_ablation_sensitivity.pdf")


def budget_sensitivity(result_dir: Path, out: Path) -> None:
    search = pd.read_csv(result_dir / "validation_search.csv")
    best = search.groupby("budget", as_index=False).apply(
        lambda frame: frame.loc[frame["validation_macro_f1_mean"].idxmax()]
    ).reset_index(drop=True)
    fig, ax = plt.subplots(figsize=(4.7, 3.5), constrained_layout=True)
    ax.plot(best["budget"], best["validation_macro_f1_mean"] * 100, color=BLUE, marker="o", linewidth=1.8, markersize=7)
    for _, row in best.iterrows():
        ax.annotate(f"{row['validation_macro_f1_mean']*100:.2f}", (row["budget"], row["validation_macro_f1_mean"] * 100), xytext=(0, 8), textcoords="offset points", ha="center", fontsize=10.8)
    ax.set_xlabel("Selected captures per class")
    ax.set_ylabel("Best validation macro-F1 (%)")
    ax.set_xticks(sorted(best["budget"].astype(int).unique()))
    ax.grid(color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    save(fig, out / "capture_budget_sensitivity.pdf")


def confusion(result_dir: Path, out: Path) -> None:
    matrix = np.load(result_dir / "confusion_matrix.npy")
    matrix = matrix / matrix.sum(axis=1, keepdims=True) * 100
    names = ["NonTor", "Tor", "Tor-SS", "Tor-Trojan", "Tor-Vmess"]
    fig, ax = plt.subplots(figsize=(4.7, 4.5), constrained_layout=True)
    vector_heatmap(ax, matrix, "Blues", 0, 100)
    ax.set_xlim(0, 5); ax.set_ylim(5, 0)
    ax.set_xticks(np.arange(5) + 0.5, names, rotation=28, ha="right")
    ax.set_yticks(np.arange(5) + 0.5, names)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    for i in range(5):
        for j in range(5):
            ax.text(j + 0.5, i + 0.5, f"{matrix[i,j]:.1f}", ha="center", va="center", fontsize=10.8, color="white" if matrix[i,j] > 55 else "black")
    ax.text(1.0, 1.02, "Darker = higher row percentage", transform=ax.transAxes, ha="right", fontsize=10.8)
    save(fig, out / "confusion_matrix_dpf.pdf")


def jsd_heatmap(result_dir: Path, out: Path) -> None:
    data = pd.read_csv(result_dir / "jsd_scores.csv")
    stages = ["NonTor / Tor-family", "Tor / Tor-over-proxy", "Proxy family", "Global five-class"]
    pivot = data.pivot(index="stage", columns="feature", values="jsd_score").reindex(stages)
    features = pivot.mean(axis=0).sort_values(ascending=False).head(6).index.tolist()
    matrix = pivot[features].to_numpy()
    labels = [name.replace("_", " ").replace("Total Length of ", "Len ") for name in features]
    fig, ax = plt.subplots(figsize=(5.6, 3.9), constrained_layout=True)
    vector_heatmap(ax, matrix, "YlGnBu", 0, max(0.01, float(np.nanmax(matrix))))
    ax.set_xlim(0, 6); ax.set_ylim(4, 0)
    ax.set_xticks(np.arange(6) + 0.5, labels, rotation=28, ha="right")
    ax.set_yticks(np.arange(4) + 0.5, stages)
    for i in range(4):
        for j in range(6):
            ax.text(j + 0.5, i + 0.5, f"{matrix[i,j]:.2f}", ha="center", va="center", fontsize=10.8)
    ax.text(1.0, 1.02, "Darker = larger JSD", transform=ax.transAxes, ha="right", fontsize=10.8)
    save(fig, out / "JSD-1.pdf")


def class_ratio(result_dir: Path, out: Path) -> None:
    data = pd.read_csv(result_dir / "class_ratio.csv")
    grouped = data.groupby("nontor_to_torfamily_ratio")["macro_f1"].agg(["mean", "std"]).reset_index()
    labels = ["1:4", "1:2", "1:1", "2:1", "4:1", "8:1"]
    fig, ax = plt.subplots(figsize=(4.7, 3.5), constrained_layout=True)
    x = np.arange(len(grouped))
    ax.errorbar(x, grouped["mean"] * 100, yerr=grouped["std"] * 100, color=BLUE, marker="o", capsize=4, linewidth=1.8, markersize=7)
    ax.set_xticks(x, labels)
    ax.set_xlabel("NonTor : Tor-family flow ratio")
    ax.set_ylabel("Macro-F1 (%)")
    ax.grid(color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    save(fig, out / "normal_proportion.pdf")


def open_world(result_dir: Path, out: Path) -> None:
    data = pd.read_csv(result_dir / "open_world.csv")
    grouped = data.groupby("threshold")[["unknown_detection_rate", "known_retention_rate", "balanced_rate"]].mean().reset_index()
    best = grouped.loc[grouped["balanced_rate"].idxmax()]
    fig, ax = plt.subplots(figsize=(4.8, 3.6), constrained_layout=True)
    ax.plot(grouped["threshold"], grouped["unknown_detection_rate"] * 100, color=BLUE, marker="o", linewidth=1.8, label="Unknown detection")
    ax.plot(grouped["threshold"], grouped["known_retention_rate"] * 100, color=GREEN, marker="s", linestyle="--", linewidth=1.8, label="Known retention")
    ax.axvline(best["threshold"], color=ORANGE, linestyle=":", linewidth=1.8, label=f"balanced threshold={best['threshold']:.2f}")
    ax.set_xlabel("Maximum-posterior threshold")
    ax.set_ylabel("Rate (%)")
    ax.set_ylim(0, 102)
    ax.grid(color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    ax.legend(frameon=False, loc="center right")
    save(fig, out / "open-world_analysis.pdf")


def split_stability(result_dir: Path, out: Path) -> None:
    data = pd.read_csv(result_dir / "split_stability.csv")
    values = data["macro_f1"].to_numpy() * 100
    seeds = data["split_seed"].astype(int).tolist()
    fig, ax = plt.subplots(figsize=(4.7, 3.5), constrained_layout=True)
    box = ax.boxplot([values], patch_artist=True, widths=0.28, medianprops={"color": "white", "linewidth": 1.5})
    box["boxes"][0].set_facecolor(BLUE)
    offsets = np.linspace(-0.12, 0.12, len(values))
    ax.scatter(1 + offsets, values, color=ORANGE, marker="o", s=42, zorder=3)
    for offset, value, seed in zip(offsets, values, seeds):
        ax.annotate(str(seed), (1 + offset, value), xytext=(0, 8), textcoords="offset points", ha="center", fontsize=10.8)
    ax.set_xticks([1], ["JA4Tor-DPF"])
    ax.set_xlabel("Labels above points are split seeds")
    ax.set_ylabel("Macro-F1 (%)")
    ax.grid(axis="y", color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    save(fig, out / "pcap_split_stability.pdf")


def runtime_plot(result_dir: Path, out: Path) -> None:
    summary = summary_frame(result_dir)
    order = ["Logistic Regression", "HistGradientBoosting", "ExtraTrees", "Hard Hierarchy", "JA4Tor-H", "JA4Tor-G", "JA4Tor-DPF"]
    offsets = {
        "Logistic Regression": (6, -12), "HistGradientBoosting": (-104, 8), "ExtraTrees": (6, -12),
        "Hard Hierarchy": (-84, -2), "JA4Tor-H": (6, -14), "JA4Tor-G": (6, 8), "JA4Tor-DPF": (6, 18),
    }
    fig, ax = plt.subplots(figsize=(5.2, 3.8), constrained_layout=True)
    for name in order:
        if name not in summary.index:
            continue
        x = summary.loc[name, "runtime_mean"]
        y = summary.loc[name, "macro_f1_mean"] * 100
        color = GRAY if name in {"Logistic Regression", "HistGradientBoosting", "ExtraTrees"} else BLUE
        if name == "JA4Tor-DPF": color = ORANGE
        marker = "s" if color == GRAY else "o"
        ax.scatter(x, y, color=color, marker=marker, s=52)
        label = name
        if name == "JA4Tor-G" and "JA4Tor-DPF" in summary.index:
            same_point = np.isclose(x, summary.loc["JA4Tor-DPF", "runtime_mean"]) and np.isclose(
                y, summary.loc["JA4Tor-DPF", "macro_f1_mean"] * 100
            )
            if same_point:
                continue
        if name == "JA4Tor-DPF" and "JA4Tor-G" in summary.index:
            same_point = np.isclose(x, summary.loc["JA4Tor-G", "runtime_mean"]) and np.isclose(
                y, summary.loc["JA4Tor-G", "macro_f1_mean"] * 100
            )
            if same_point:
                label = "JA4Tor-G / DPF"
        ax.annotate(label, (x, y), xytext=offsets[name], textcoords="offset points", fontsize=10.8, color=color)
    ax.set_xscale("log")
    ax.set_xlabel("Training + inference time (s, log scale)")
    ax.set_ylabel("Macro-F1 (%)")
    ax.grid(color=LIGHT_GRAY, linewidth=0.8, alpha=0.7)
    save(fig, out / "runtime_accuracy.pdf")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    main_comparison(args.result_dir, args.output_dir)
    ablation_sensitivity(args.result_dir, args.output_dir)
    budget_sensitivity(args.result_dir, args.output_dir)
    confusion(args.result_dir, args.output_dir)
    jsd_heatmap(args.result_dir, args.output_dir)
    class_ratio(args.result_dir, args.output_dir)
    open_world(args.result_dir, args.output_dir)
    split_stability(args.result_dir, args.output_dir)
    runtime_plot(args.result_dir, args.output_dir)
    print(f"Generated vector figures in {args.output_dir}")


if __name__ == "__main__":
    main()
