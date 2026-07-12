#!/usr/bin/env python3
"""Repeat the frozen Prototype-Core configuration on independent pcap splits."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--feature-root", type=Path, required=True)
    parser.add_argument("--candidate-cache", type=Path, required=True)
    parser.add_argument("--frozen-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--selector", type=Path, required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--budget", type=int, required=True)
    parser.add_argument("--split-seeds", default="7,17,27,37,47")
    args = parser.parse_args()

    base_config = json.loads(args.frozen_config.read_text(encoding="utf-8"))
    rows: list[dict[str, float | int]] = []
    for seed in [int(value) for value in args.split_seeds.split(",")]:
        seed_dir = args.output_dir / f"seed_{seed}"
        result_dir = seed_dir / "result"
        if (result_dir / "test_results.csv").exists():
            raise FileExistsError(f"Refusing repeated test evaluation: {result_dir}")
        manifest = seed_dir / f"manifest_budget{args.budget}_seed{seed}.csv"
        run(
            [
                sys.executable,
                str(args.selector),
                "--raw-root", str(args.raw_root),
                "--feature-root", str(args.feature_root),
                "--output-manifest", str(manifest),
                "--per-class-budget", str(args.budget),
                "--split-seed", str(seed),
                "--min-pcap-mib", "0.5",
                "--max-pcap-mib", "20",
                "--min-flow-rows", "4",
                "--candidate-cache", str(args.candidate_cache),
                "--hash-cache", str(args.output_dir / "hash_cache.json"),
            ]
        )
        candidate = seed_dir / "selection_candidates.csv"
        config = dict(base_config)
        config.update(
            {
                "candidate_file": str(candidate.resolve()),
                "candidate_sha256": sha256(candidate),
                "split_seed": seed,
                "model_configuration_frozen_from_split_seed": 42,
            }
        )
        config_path = seed_dir / "frozen_config_for_split.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        run(
            [
                sys.executable,
                str(args.runner),
                "--selection-manifest", str(candidate),
                "--output-dir", str(result_dir),
                "--frozen-config", str(config_path),
                "--test-seeds", "1",
            ]
        )
        with (result_dir / "summary.csv").open(newline="", encoding="utf-8") as handle:
            summary = {row["variant"]: row for row in csv.DictReader(handle)}
        rows.append({"split_seed": seed, "macro_f1": float(summary["JA4Tor-DPF"]["macro_f1_mean"])})

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "split_stability.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["split_seed", "macro_f1"])
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
