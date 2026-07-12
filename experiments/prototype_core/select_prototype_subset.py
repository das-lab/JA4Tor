#!/usr/bin/env python3
"""Build a reproducible Prototype-Core manifest from raw pcaps and cached features."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd


CLASS_DIRS = {
    "NonTor": "normal",
    "Tor": "tor",
    "Tor-SS": "tor_ss",
    "Tor-Trojan": "tor_trojan",
    "Tor-Vmess": "tor_vmess",
}
SETUP_PREFIXES = ("http_", "tls_")


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


def pt_columns(columns: list[str]) -> list[str]:
    return [
        column for column in columns
        if not prohibited(column) and not normalized(column).startswith(SETUP_PREFIXES)
    ]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assign_splits(records: list[dict], seed: int) -> None:
    by_class: dict[str, list[dict]] = {}
    for record in records:
        by_class.setdefault(record["class"], []).append(record)
    for class_records in by_class.values():
        ordered = sorted(
            class_records,
            key=lambda item: hashlib.sha256(
                f"{seed}:{item['capture_id']}".encode("utf-8")
            ).hexdigest(),
        )
        train_end = int(len(ordered) * 0.70)
        validation_end = train_end + int(len(ordered) * 0.10)
        for index, record in enumerate(ordered):
            record["split"] = (
                "train" if index < train_end
                else "validation" if index < validation_end
                else "test"
            )


def read_embedding(csv_path: Path) -> tuple[int, list[str], np.ndarray]:
    frame = pd.read_csv(csv_path, low_memory=False)
    columns = pt_columns(list(frame.columns))
    numeric = frame[columns].apply(pd.to_numeric, errors="coerce")
    median = numeric.median(axis=0, skipna=True).fillna(0.0).to_numpy(dtype=float)
    iqr = (
        numeric.quantile(0.75, numeric_only=True)
        - numeric.quantile(0.25, numeric_only=True)
    ).fillna(0.0).to_numpy(dtype=float)
    return len(frame), columns, np.concatenate([median, iqr])


def build_candidates(args: argparse.Namespace) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    embeddings: list[np.ndarray] = []
    embedding_columns: list[str] | None = None
    min_bytes = int(args.min_pcap_mib * 1024 * 1024)
    max_bytes = int(args.max_pcap_mib * 1024 * 1024)

    for class_name, directory in CLASS_DIRS.items():
        pcap_dir = args.raw_root / directory / "pcap"
        csv_dir = args.feature_root / f"{directory}{args.feature_suffix}"
        for pcap_path in sorted(pcap_dir.glob("*.pcap")):
            csv_path = csv_dir / f"{pcap_path.stem}.csv"
            if not csv_path.exists():
                continue
            size = pcap_path.stat().st_size
            if size < min_bytes or size > max_bytes:
                continue
            row_count, columns, vector = read_embedding(csv_path)
            if row_count < args.min_flow_rows:
                continue
            if embedding_columns is None:
                embedding_columns = [f"median:{name}" for name in columns] + [
                    f"iqr:{name}" for name in columns
                ]
            if len(vector) != len(embedding_columns):
                raise ValueError(f"Feature schema mismatch in {csv_path}")
            records.append(
                {
                    "capture_id": f"{directory}:{pcap_path.stem}",
                    "class": class_name,
                    "pcap_path": str(pcap_path.resolve()),
                    "csv_path": str(csv_path.resolve()),
                    "pcap_size": size,
                    "row_count": row_count,
                }
            )
            embeddings.append(vector)

    assign_splits(records, args.split_seed)
    matrix = np.vstack(embeddings)
    prototype_params: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    for class_name in CLASS_DIRS:
        class_indices = [i for i, row in enumerate(records) if row["class"] == class_name]
        train_indices = [i for i in class_indices if records[i]["split"] == "train"]
        train_matrix = matrix[train_indices]
        center = np.nanmedian(train_matrix, axis=0)
        mad = np.nanmedian(np.abs(train_matrix - center), axis=0)
        scale = np.where(mad > 1e-12, mad, 1.0)
        prototype_params[class_name] = (center, scale)
    for index, record in enumerate(records):
        distances = {
            class_name: float(np.nanmedian(np.abs((matrix[index] - center) / scale)))
            for class_name, (center, scale) in prototype_params.items()
        }
        own = distances[record["class"]]
        nearest_other = min(
            value for class_name, value in distances.items() if class_name != record["class"]
        )
        record["prototype_distance"] = own
        record["prototype_margin"] = nearest_other - own
    return records, embedding_columns or []


def rerank(records: list[dict], ranking_mode: str) -> str:
    use_margin = ranking_mode == "margin"
    if use_margin and not all(row.get("prototype_margin") not in (None, "") for row in records):
        raise ValueError("Margin ranking requested but prototype_margin is unavailable")
    groups: dict[tuple[str, str], list[dict]] = {}
    for record in records:
        groups.setdefault((record["class"], record["split"]), []).append(record)
    for group in groups.values():
        if use_margin:
            group.sort(
                key=lambda item: (
                    -float(item["prototype_margin"]),
                    float(item["prototype_distance"]),
                    item["capture_id"],
                )
            )
        else:
            group.sort(key=lambda item: (float(item["prototype_distance"]), item["capture_id"]))
        for rank, record in enumerate(group, start=1):
            record["selection_rank"] = rank
    return (
        "descending nearest-other minus own-class robust prototype distance"
        if use_margin
        else "ascending own-class robust prototype distance"
    )


def split_limits(budget: int) -> dict[str, int]:
    train = int(budget * 0.70)
    validation = int(budget * 0.10)
    return {"train": train, "validation": validation, "test": budget - train - validation}


def load_hash_cache(path: Path) -> dict[str, str]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--feature-root", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--per-class-budget", type=int, required=True)
    parser.add_argument("--split-seed", type=int, default=42)
    parser.add_argument("--min-pcap-mib", type=float, default=0.5)
    parser.add_argument("--max-pcap-mib", type=float, default=20.0)
    parser.add_argument("--min-flow-rows", type=int, default=4)
    parser.add_argument("--feature-suffix", default="-0927")
    parser.add_argument("--candidate-cache", type=Path)
    parser.add_argument("--hash-cache", type=Path)
    parser.add_argument("--ranking", choices=["own-distance", "margin"], default="own-distance")
    args = parser.parse_args()

    args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
    candidate_path = args.output_manifest.parent / "selection_candidates.csv"
    if args.candidate_cache:
        with args.candidate_cache.open(newline="", encoding="utf-8") as handle:
            records = list(csv.DictReader(handle))
        assign_splits(records, args.split_seed)
        embedding_columns: list[str] = []
    else:
        records, embedding_columns = build_candidates(args)
    ranking = rerank(records, args.ranking)

    candidate_fields = [
        "capture_id", "class", "pcap_path", "csv_path", "pcap_size", "row_count",
        "prototype_distance", "prototype_margin", "selection_rank", "split",
    ]
    with candidate_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=candidate_fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in candidate_fields} for row in records)

    limits = split_limits(args.per_class_budget)
    selected = [
        row for row in records if int(row["selection_rank"]) <= limits[row["split"]]
    ]
    counts = {(class_name, split): 0 for class_name in CLASS_DIRS for split in limits}
    for row in selected:
        counts[(row["class"], row["split"])] += 1
    expected = {
        (class_name, split): count
        for class_name in CLASS_DIRS for split, count in limits.items()
    }
    if counts != expected:
        raise ValueError(f"Insufficient candidates: expected {expected}, got {counts}")

    hash_cache_path = args.hash_cache or args.output_manifest.parent / "hash_cache.json"
    hashes = load_hash_cache(hash_cache_path)
    for row in selected:
        for key in ("pcap_path", "csv_path"):
            path = row[key]
            if path not in hashes:
                hashes[path] = sha256(Path(path))
        row["pcap_sha256"] = hashes[row["pcap_path"]]
        row["csv_sha256"] = hashes[row["csv_path"]]
    hash_cache_path.write_text(json.dumps(hashes, indent=2), encoding="utf-8")

    manifest_fields = candidate_fields + ["pcap_sha256", "csv_sha256"]
    with args.output_manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=manifest_fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in manifest_fields} for row in selected)

    metadata = {
        "raw_root": str(args.raw_root.resolve()),
        "feature_root": str(args.feature_root.resolve()),
        "filters": {
            "min_pcap_mib": args.min_pcap_mib,
            "max_pcap_mib": args.max_pcap_mib,
            "min_flow_rows": args.min_flow_rows,
        },
        "per_class_budget": args.per_class_budget,
        "split_seed": args.split_seed,
        "split_limits": limits,
        "eligible_captures": len(records),
        "selected_captures": len(selected),
        "embedding_columns": embedding_columns,
        "prototype_source": "training candidates only",
        "ranking": ranking,
    }
    (args.output_manifest.parent / "selection_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    print(json.dumps({"candidate_count": len(records), "selected_count": len(selected), "counts": {str(k): v for k, v in counts.items()}}, indent=2))


if __name__ == "__main__":
    main()
