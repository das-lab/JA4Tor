#!/usr/bin/env python3
"""Generate LaTeX result macros from measured CSV outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


VARIANTS = {
    "Logistic Regression": "ProtoLogReg",
    "HistGradientBoosting": "ProtoHistGB",
    "ExtraTrees": "ProtoExtraTrees",
    "Hard Hierarchy": "ProtoHard",
    "JA4Tor-H": "ProtoH",
    "JA4Tor-G": "ProtoG",
    "JA4Tor-DPF": "ProtoDPF",
}

STRICT_VARIANTS = {
    "Hierarchical-FULL": "StrictH",
    "Global-FULL": "StrictG",
    "DPF-FULL": "StrictDPF",
    "DPF-FULL-NoJSD": "StrictNoJSD",
    "HardHierarchy-FULL": "StrictHard",
    "DPF-PT": "StrictPT",
    "DPF-AS": "StrictAS",
}


def pct(value: float) -> str:
    return f"{value * 100:.2f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--strict-summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    summary = pd.read_csv(args.result_dir / "summary.csv", index_col=0)
    strict = pd.read_csv(args.strict_summary, index_col=0)
    config = json.loads((args.result_dir / "frozen_config.json").read_text(encoding="utf-8"))
    lines = [
        "% Auto-generated from measured Prototype-Core CSV outputs.",
        "% Do not edit numeric values manually; rerun generate_paper_values.py.",
    ]
    for variant, prefix in VARIANTS.items():
        row = summary.loc[variant]
        lines.extend(
            [
                f"\\newcommand{{\\{prefix}Accuracy}}{{{pct(row['accuracy_mean'])}}}",
                f"\\newcommand{{\\{prefix}Precision}}{{{pct(row['precision_mean'])}}}",
                f"\\newcommand{{\\{prefix}Recall}}{{{pct(row['recall_mean'])}}}",
                f"\\newcommand{{\\{prefix}Fone}}{{{pct(row['macro_f1_mean'])}}}",
                f"\\newcommand{{\\{prefix}FoneStd}}{{{pct(row['macro_f1_std'])}}}",
                f"\\newcommand{{\\{prefix}Runtime}}{{{row['runtime_mean']:.2f}}}",
            ]
        )
    lines.extend(
        [
            f"\\newcommand{{\\ProtoBudget}}{{{int(config['selected_budget'])}}}",
            f"\\newcommand{{\\ProtoLambda}}{{{float(config['fusion_weight']):g}}}",
            f"\\newcommand{{\\ProtoValidationFone}}{{{pct(config['validation_macro_f1_mean'])}}}",
        ]
    )
    for variant, prefix in STRICT_VARIANTS.items():
        row = strict.loc[variant]
        lines.extend(
            [
                f"\\newcommand{{\\{prefix}Fone}}{{{pct(row['macro_f1_mean'])}}}",
                f"\\newcommand{{\\{prefix}FoneStd}}{{{pct(row['macro_f1_std'])}}}",
            ]
        )
    split_path = args.result_dir / "split_stability.csv"
    if split_path.exists():
        split = pd.read_csv(split_path)
        lines.extend(
            [
                f"\\newcommand{{\\ProtoSplitMean}}{{{pct(split['macro_f1'].mean())}}}",
                f"\\newcommand{{\\ProtoSplitStd}}{{{pct(split['macro_f1'].std(ddof=1))}}}",
            ]
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
