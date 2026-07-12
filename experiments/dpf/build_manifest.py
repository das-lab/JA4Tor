#!/usr/bin/env python3
"""Build deterministic pcap-group manifests from one-CSV-per-capture features."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import numpy as np


CLASS_DIRS = {
    "NonTor": "normal",
    "Tor": "tor",
    "Tor-SS": "tor_ss",
    "Tor-Trojan": "tor_trojan",
    "Tor-Vmess": "tor_vmess",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def row_count(path: Path) -> int:
    with path.open("rb") as handle:
        return max(sum(1 for _ in handle) - 1, 0)


def assign_splits(paths: list[Path], seed: int) -> dict[Path, str]:
    rng = np.random.default_rng(seed)
    ordered = sorted(paths)
    shuffled = [ordered[index] for index in rng.permutation(len(ordered))]
    train_end = int(len(shuffled) * 0.70)
    validation_end = train_end + int(len(shuffled) * 0.10)
    return {
        path: (
            "train"
            if index < train_end
            else "validation"
            if index < validation_end
            else "test"
        )
        for index, path in enumerate(shuffled)
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split-seed", type=int, default=42)
    parser.add_argument("--directory-suffix", default="")
    parser.add_argument("--csv-subdir", default="cic_csv")
    args = parser.parse_args()

    rows: list[dict[str, object]] = []
    for class_name, directory in CLASS_DIRS.items():
        csv_dir = args.data_root / f"{directory}{args.directory_suffix}"
        if args.csv_subdir:
            csv_dir = csv_dir / args.csv_subdir
        paths = sorted(csv_dir.glob("*.csv"))
        if not paths:
            raise FileNotFoundError(f"No feature CSV files found in {csv_dir}")
        split_by_path = assign_splits(paths, args.split_seed)
        for path in paths:
            rows.append(
                {
                    "capture_id": f"{directory}:{path.stem}",
                    "class": class_name,
                    "csv_path": str(path.resolve()),
                    "row_count": row_count(path),
                    "split": split_by_path[path],
                    "sha256": sha256(path),
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["capture_id", "class", "csv_path", "row_count", "split", "sha256"],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} capture groups to {args.output}")


if __name__ == "__main__":
    main()

