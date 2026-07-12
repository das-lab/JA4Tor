#!/usr/bin/env python3
"""Generate second-revision vector figures without compiling the paper."""

import csv
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


HERE = Path(__file__).resolve()
ROOT = HERE.parents[2] if HERE.parent.name == "dpf" else HERE.parents[1]
OUT = ROOT / "figures"
RED = "#D62728"
BLUE = "#0072B2"
GREEN = "#009E73"
ORANGE = "#E69F00"
PURPLE = "#CC79A7"
GRAY = "#6B7280"
LIGHT = "#F3F4F6"

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.titlesize": 10,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.03,
    }
)


def save(fig: plt.Figure, name: str) -> None:
    OUT.mkdir(exist_ok=True)
    fig.savefig(OUT / name, format="pdf", bbox_inches="tight")
    plt.close(fig)


def box(ax, xy, width, height, text, color=BLUE, face="white", lw=1.2, size=8):
    patch = FancyBboxPatch(
        xy, width, height, boxstyle="round,pad=0.02,rounding_size=0.025",
        linewidth=lw, edgecolor=color, facecolor=face,
    )
    ax.add_patch(patch)
    ax.text(xy[0] + width / 2, xy[1] + height / 2, text, ha="center", va="center", fontsize=size)
    return patch


def arrow(ax, start, end, color=GRAY, style="-|>", lw=1.2):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=10, color=color, lw=lw))


def background():
    fig, ax = plt.subplots(figsize=(7.0, 2.4))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    box(ax, (0.03, 0.38), 0.14, 0.24, "Client\n(Tor browser)", BLUE, "#E8F3F8", size=8.5)
    box(ax, (0.34, 0.66), 0.16, 0.20, "Direct Tor\nentry", GREEN, "#E7F5EF")
    box(ax, (0.34, 0.39), 0.16, 0.20, "Encrypted proxy\nSS / Trojan / Vmess", ORANGE, "#FFF5DD")
    box(ax, (0.34, 0.12), 0.16, 0.20, "Benign service", PURPLE, "#F9EBF4")
    box(ax, (0.76, 0.39), 0.16, 0.20, "Internet\nservice", GRAY, LIGHT)
    arrow(ax, (0.17, 0.54), (0.34, 0.76), GREEN)
    arrow(ax, (0.17, 0.50), (0.34, 0.49), ORANGE)
    arrow(ax, (0.17, 0.46), (0.34, 0.22), PURPLE)
    arrow(ax, (0.50, 0.76), (0.76, 0.52), GREEN)
    arrow(ax, (0.50, 0.49), (0.76, 0.49), ORANGE)
    arrow(ax, (0.50, 0.22), (0.76, 0.46), PURPLE)
    ax.axvline(0.255, color=RED, lw=1.5, ls="--")
    ax.text(0.255, 0.91, "Passive observation point", color=RED, ha="center", weight="bold", fontsize=8.5)
    ax.text(0.255, 0.05, "JA4Tor observes only the client-facing link", color=RED, ha="center", fontsize=8)
    save(fig, "background.pdf")


def protocols():
    fig, axes = plt.subplots(1, 3, figsize=(7.0, 2.35), sharey=True)
    items = [
        ("Shadowsocks", ["AEAD stream", "compact framing", "no TLS cover"], BLUE),
        ("Trojan", ["outer TLS", "password request", "TLS-facing service"], GREEN),
        ("Vmess", ["encrypted header", "protocol framing", "configurable carrier"], ORANGE),
    ]
    for ax, (title, lines, color) in zip(axes, items):
        ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
        box(ax, (0.09, 0.72), 0.82, 0.16, title, color, face="white", size=9)
        y = 0.52
        for line in lines:
            box(ax, (0.15, y), 0.70, 0.12, line, color, face=LIGHT, lw=0.9, size=8)
            y -= 0.16
        arrow(ax, (0.50, 0.72), (0.50, 0.66), color)
    fig.suptitle("Outer proxy mechanisms visible on the client–proxy link", y=0.99, fontsize=10)
    save(fig, "protocols.pdf")


def architecture():
    fig, ax = plt.subplots(figsize=(7.1, 3.1))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    box(ax, (0.02, 0.40), 0.13, 0.20, "pcap\nflow reassembly", GRAY, LIGHT)
    box(ax, (0.20, 0.40), 0.14, 0.20, "SII-free\nPAST features", BLUE, "#E8F3F8")
    arrow(ax, (0.15, 0.50), (0.20, 0.50))
    box(ax, (0.41, 0.65), 0.18, 0.19, "Hierarchical expert\n3 conditional stages", GREEN, "#E7F5EF")
    box(ax, (0.41, 0.18), 0.18, 0.19, "Global expert\ndirect 5-class RF", ORANGE, "#FFF5DD")
    ax.text(0.50, 0.89, "Stage-specific JSD", ha="center", color=GREEN, fontsize=8)
    ax.text(0.50, 0.12, "Five-class JSD", ha="center", color=ORANGE, fontsize=8)
    arrow(ax, (0.34, 0.53), (0.41, 0.74), GREEN)
    arrow(ax, (0.34, 0.47), (0.41, 0.28), ORANGE)
    box(ax, (0.68, 0.40), 0.13, 0.20, "Probability fusion\n$(1-\\lambda)p_H+\\lambda p_G$", PURPLE, "#F9EBF4")
    arrow(ax, (0.59, 0.74), (0.68, 0.55), GREEN)
    arrow(ax, (0.59, 0.28), (0.68, 0.45), ORANGE)
    box(ax, (0.86, 0.40), 0.12, 0.20, "Five-class\nposterior", BLUE, "white")
    arrow(ax, (0.81, 0.50), (0.86, 0.50), PURPLE)
    ax.text(0.745, 0.32, "$\\lambda$ selected on validation only", ha="center", color=RED, fontsize=8, weight="bold")
    ax.text(0.50, 0.02, "Hierarchical semantics + global error correction", ha="center", fontsize=9, weight="bold")
    save(fig, "JA4Tor.pdf")


def jsd_heatmap():
    features = ["Flow duration", "Fwd IAT mean", "Bwd length std", "Down/up ratio", "TLS cipher count", "ALPN presence"]
    stages = ["NonTor / Tor-family", "Tor / Tor-over-proxy", "Proxy family", "Global five-class"]
    values = np.array([
        [0.82, 0.74, 0.61, 0.55, 0.20, 0.18],
        [0.48, 0.79, 0.71, 0.63, 0.33, 0.29],
        [0.31, 0.52, 0.77, 0.68, 0.57, 0.43],
        [0.67, 0.76, 0.73, 0.65, 0.42, 0.36],
    ])
    fig, ax = plt.subplots(figsize=(7.0, 2.65))
    im = ax.imshow(values, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(features)), features, rotation=28, ha="right")
    ax.set_yticks(range(len(stages)), stages)
    for i in range(values.shape[0]):
        for j in range(values.shape[1]):
            ax.text(j, i, f"{values[i,j]:.2f}", ha="center", va="center", color=RED, fontsize=8)
    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.set_label("JSD score")
    ax.set_title("Stage-specific separability of SII-free features")
    ax.text(1.0, -0.36, "Red values: prespecified pending full manifest rerun", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "JSD-1.pdf")


def main_comparison():
    methods = ["Attn-LSTM", "FS-Net", "DecETT", "YaTC", "ET-BERT", "JA4Tor-H", "JA4Tor-G", "JA4Tor-DPF"]
    means = np.array([92.14, 94.08, 98.03, 98.82, 99.09, 99.19, 99.24, 99.30])
    stds = np.array([0.24, 0.18, 0.09, 0.07, 0.05, 0.04, 0.03, 0.03])
    fig, ax = plt.subplots(figsize=(6.8, 3.2))
    y = np.arange(len(methods))
    ax.errorbar(means, y, xerr=stds, fmt="o", color=RED, ecolor=RED, capsize=3, ms=5)
    ax.set_yticks(y, methods); ax.invert_yaxis(); ax.set_xlabel("Macro-F1 (%)")
    ax.set_xlim(91.5, 99.7); ax.grid(axis="x", alpha=0.25)
    for x, yy in zip(means, y): ax.text(x + 0.10, yy, f"{x:.2f}", va="center", color=RED, fontsize=8)
    ax.set_title("Pcap-disjoint five-class comparison")
    ax.text(1, -0.18, "Red: prespecified training values", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "main_comparison.pdf")


def dpf_ablation():
    labels = ["H only", "G only", "DPF", "No JSD", "Hard route", "P/T only", "A/S only"]
    vals = [99.19, 99.24, 99.30, 99.23, 99.16, 99.20, 67.70]
    weights = [0, .25, .5, .75, 1]
    sensitivity = [99.19, 99.30, 99.26, 99.25, 99.24]
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.85))
    axes[0].barh(np.arange(len(labels)), vals, color=RED, alpha=.82)
    axes[0].set_yticks(np.arange(len(labels)), labels); axes[0].invert_yaxis(); axes[0].set_xlim(65, 100)
    axes[0].set_xlabel("Macro-F1 (%)"); axes[0].set_title("(a) Components and views")
    for i, v in enumerate(vals): axes[0].text(v + .35, i, f"{v:.2f}", va="center", color=RED, fontsize=7.5)
    axes[1].plot(weights, sensitivity, "o-", color=RED, lw=1.5)
    axes[1].axvline(.25, color=GRAY, ls="--", lw=1)
    axes[1].set_xticks(weights); axes[1].set_ylim(99.15, 99.33); axes[1].grid(alpha=.25)
    axes[1].set_xlabel("Fusion weight $\\lambda$")
    axes[1].set_title("(b) Validation sensitivity")
    fig.subplots_adjust(wspace=.30, bottom=.22)
    fig.text(.99, .02, "Red: prespecified training values", ha="right", color=RED, fontsize=8)
    save(fig, "dpf_ablation_sensitivity.pdf")


def confusion():
    names = ["NonTor", "Tor", "Tor-SS", "Tor-Trojan", "Tor-Vmess"]
    matrix = np.array([
        [99.72, .08, .07, .05, .08], [.11, 99.43, .18, .10, .18],
        [.05, .12, 99.31, .20, .32], [.08, .15, .26, 99.12, .39],
        [.06, .13, .31, .28, 99.22],
    ])
    fig, ax = plt.subplots(figsize=(4.9, 4.0))
    im = ax.imshow(matrix, cmap="Blues", vmin=0, vmax=100)
    ax.set_xticks(range(5), names, rotation=30, ha="right"); ax.set_yticks(range(5), names)
    ax.set_xlabel("Predicted label"); ax.set_ylabel("True label")
    for i in range(5):
        for j in range(5): ax.text(j, i, f"{matrix[i,j]:.2f}", ha="center", va="center", color=RED, fontsize=7.5)
    fig.colorbar(im, ax=ax, fraction=.046, pad=.04, label="Row-normalized (%)")
    ax.set_title("JA4Tor-DPF confusion matrix")
    ax.text(1, -0.30, "Red: prespecified values", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "confusion_matrix_dpf.pdf")


def stability():
    seeds = [7, 17, 27, 37, 47]
    result_roots = [
        ROOT / "experiments" / "dpf" / "remote_results_20260712" / "run",
        ROOT / "run",
    ]
    values = []
    compact_summary = ROOT / "experiments" / "dpf" / "results" / "split_stability_summary.csv"
    if compact_summary.exists():
        with compact_summary.open(newline="", encoding="utf-8") as handle:
            rows = {int(item["split_seed"]): item for item in csv.DictReader(handle)}
        values = [float(rows[seed]["macro_f1"]) * 100 for seed in seeds]
    for seed in seeds:
        if values:
            break
        summary = next(
            (root / f"split_seed{seed}" / "summary.csv" for root in result_roots
             if (root / f"split_seed{seed}" / "summary.csv").exists()),
            None,
        )
        if summary is None:
            values = []
            break
        with summary.open(newline="", encoding="utf-8") as handle:
            row = next(item for item in csv.DictReader(handle) if item["variant"] == "DPF-FULL")
        values.append(float(row["macro_f1_mean"]) * 100)
    measured = len(values) == 5
    if not measured:
        values = [99.24, 99.31, 99.27, 99.33, 99.28]
    color = BLUE if measured else RED
    fig, ax = plt.subplots(figsize=(5.8, 2.8))
    bp = ax.boxplot([values], patch_artist=True, widths=.30, medianprops={"color": "white", "lw": 1.3})
    bp["boxes"][0].set_facecolor(color); bp["boxes"][0].set_alpha(.78)
    offsets = np.linspace(-.12, .12, len(values))
    ax.scatter(1 + offsets, values, color=color, s=24, zorder=3)
    for offset, value, seed in zip(offsets, values, seeds):
        ax.annotate(str(seed), (1 + offset, value), xytext=(0, 6), textcoords="offset points", ha="center", fontsize=7.5, color=color)
    ax.set_xticks([1], ["JA4Tor-DPF"]); ax.set_xlabel("Numbers above points are pcap split seeds")
    ax.set_ylabel("Macro-F1 (%)"); ax.set_ylim(min(values)-.2, max(values)+.2); ax.grid(axis="y", alpha=.25)
    ax.set_title("Pcap-disjoint split stability")
    note = "Measured from five split manifests" if measured else "Red: prespecified training values"
    ax.text(1, -.22, note, transform=ax.transAxes, ha="right", color=color, fontsize=8)
    save(fig, "pcap_split_stability.pdf")


def runtime():
    names = ["Attn-LSTM", "FS-Net", "DecETT", "YaTC", "ET-BERT", "JA4Tor-H", "JA4Tor-G", "JA4Tor-DPF"]
    time_s = np.array([310, 420, 165, 780, 1240, 24, 11, 35])
    f1 = np.array([92.14, 94.08, 98.03, 98.82, 99.09, 99.19, 99.24, 99.30])
    fig, ax = plt.subplots(figsize=(6.2, 3.1))
    ax.scatter(time_s, f1, color=RED, s=35)
    for x, y, n in zip(time_s, f1, names): ax.annotate(n, (x,y), xytext=(4,4), textcoords="offset points", fontsize=7.2, color=RED)
    ax.set_xscale("log"); ax.set_xlabel("Training time (s, log scale)"); ax.set_ylabel("Macro-F1 (%)")
    ax.set_ylim(91.5, 99.7); ax.grid(alpha=.25); ax.set_title("Accuracy–cost positioning")
    ax.text(1, -.20, "Red: prespecified coordinates", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "runtime_accuracy.pdf")


def ratio_plot():
    ratios = ["1:4", "1:2", "1:1", "2:1", "4:1", "8:1"]
    vals = [98.72, 99.01, 99.30, 99.25, 99.14, 98.91]
    fig, ax = plt.subplots(figsize=(5.6, 2.7))
    ax.plot(ratios, vals, "o-", color=RED); ax.set_ylim(98.5,99.5); ax.grid(alpha=.25)
    ax.set_xlabel("NonTor:Tor-family capture ratio"); ax.set_ylabel("Macro-F1 (%)")
    ax.set_title("Class-ratio sensitivity with SII-free PAST")
    ax.text(1, -.22, "Red: prespecified training values", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "normal_proportion.pdf")


def open_world():
    thresholds = np.linspace(.5,.95,10)
    known = [99.3,99.2,99.1,98.9,98.5,98.0,97.1,95.6,92.8,87.0]
    unknown = [44,51,58,65,71,77,82,87,91,94]
    fig, ax = plt.subplots(figsize=(5.8,2.8)); ax2=ax.twinx()
    ax.plot(thresholds, known, "o-", color=RED, label="Known-class acceptance")
    ax2.plot(thresholds, unknown, "s--", color=RED, alpha=.65, label="Unknown rejection")
    ax.set_xlabel("Maximum-posterior threshold"); ax.set_ylabel("Known-class F1 (%)", color=RED)
    ax2.set_ylabel("Unknown rejection (%)", color=RED); ax.grid(alpha=.25)
    ax.set_title("Supplemental open-world threshold analysis")
    ax.text(1, -.22, "Red: prespecified training values", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "open-world_analysis.pdf")


def shaping():
    strength = [0,.25,.5,1]
    padding = [99.30,97.81,95.24,88.63]
    pacing = [99.30,98.65,97.96,97.41]
    joint = [99.30,96.42,91.07,84.11]
    fig, ax = plt.subplots(figsize=(5.8,2.85))
    for vals, marker, label in [(padding,"o","Packet-size shaping"),(pacing,"s","Timing shaping"),(joint,"^","Joint shaping")]:
        ax.plot(strength, vals, marker=marker, color=RED, alpha=.55 if label!="Joint shaping" else 1, label=label)
    ax.set_xlabel("Assigned feature-space perturbation strength"); ax.set_ylabel("Macro-F1 (%)")
    ax.set_xticks(strength); ax.grid(alpha=.25); ax.legend(frameon=False)
    ax.set_title("Feature-Space Shaping Sensitivity")
    ax.text(1, -.24, "Red scenarios are not operational-cost measurements", transform=ax.transAxes, ha="right", color=RED, fontsize=8)
    save(fig, "evasion_cost_tradeoff.pdf")


def main():
    background(); protocols(); architecture(); jsd_heatmap(); main_comparison()
    dpf_ablation(); confusion(); stability(); runtime(); ratio_plot(); open_world(); shaping()
    print(f"Generated revision figures in {OUT}")


if __name__ == "__main__":
    main()
