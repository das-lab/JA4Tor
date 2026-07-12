# JA4TOR: Exposing Tor-over-Proxy Tunnels via Protocol-Constrained Behavioral Dynamics

This repository contains the research artifact for **“JA4TOR: Exposing Tor-over-Proxy Tunnels via Protocol-Constrained Behavioral Dynamics.”** It supports feature extraction, legacy row-level reproduction, and the manifest-backed Dual-Path PAST Fusion (DPF) experiment. Raw pcaps are not yet included; users must provide one extracted CSV per capture to reproduce the pcap-disjoint experiment.

## Project Structure

- `ja4tor/`: core feature extraction framework proposed in the paper.  
  
  This module implements the multi-dimensional representation and interpretable feature engineering pipeline that constitutes the heart of JA4Tor.
  
- `classifier/`: classifier implementation used in this work.  
  
  It combines an improved Jensen–Shannon distance(JSD) based feature selection algorithm with a hierarchical Random Forest model to perform multi-class tunnel classification and produce predictions.
  
- `data/`: sample datasets derived from our self-built JA4Tor dataset and from public benchmarks, used here for demonstration and partial reproduction.

## JA4Tor Self-Built Dataset (Summary)

The self-built dataset used in our experiments is summarized as follows:

| #    | Traffic Type Description | pcap Count | Size   |
| ---- | ------------------------ | ---------- | ------ |
| 1    | NonTor   traffic         | 4248       | 20.6GB |
| 2    | Tor traffic              | 1333       | 6.12GB |
| 3    | Tor - Trojan             | 761        | 3.92GB |
| 4    | Tor - ShadowSocks        | 1560       | 7.47GB |
| 5    | Tor - Vmess              | 1120       | 3.79GB |

The documented inventory contains **9,022 pcaps (41.90 GB)** in total.

At this stage, the raw pcap files are not publicly released. Until the raw captures and row-level provenance manifest are added, results from the derived CSV files should be interpreted as flow-row reproduction rather than proof of group-independent generalization.

## Provided Data in This Repository

The data currently included in this repository are **selected subsets** derived from the original self-built JA4Tor dataset and used for lightweight experiments and examples in this codebase, rather than the complete dataset.

- The main training and test splits are extracted from the above self-built dataset after processing with the JA4Tor feature extraction framework.

- The `test-cross` split is a **mixed evaluation set** where:
  - the *Normal* class traffic originates from our self-built JA4Tor dataset, and  
  
  - the *Tor* class traffic is sampled from the **ISCX-Tor (UNB-CIC Tor) dataset**
    
    (dataset information and download: https://www.unb.ca/cic/datasets/tor.html).

These subsets are intended to illustrate the usage of JA4Tor and the classifier pipeline without requiring users to download the full raw pcap collections.

## Classifier Feature Policy

The default classifier excludes source/destination IP addresses and ports because these fields are sample-identifying information and may encode capture context:

```bash
python classifier.py --train data/train.csv --test data/test.csv
```

For exact reproduction of the legacy public artifact only, restore those columns explicitly:

```bash
python classifier.py --train data/train.csv --test data/test.csv --include-sii
```

Run the ten-seed shortcut audit and generate its vector PDF figure with:

```bash
python artifact_audit.py --repo . --seeds 10
```

The current CSV files do not include pcap, session, website, proxy-endpoint, capture-time, or run identifiers. A future manifest must provide these groups before a leakage-resistant split can be independently audited.

## Pcap-Disjoint Dual-Path PAST Fusion

DPF combines a probabilistic three-level hierarchy with a global five-class expert:

```text
p(y|x) = (1 - lambda) p_H(y|x) + lambda p_G(y|x)
```

Build a six-field manifest from one feature CSV per pcap:

```bash
python experiments/dpf/build_manifest.py \
  --data-root /path/to/per-capture/features \
  --output run/manifest_seed42.csv \
  --split-seed 42
```

Run ten model seeds. The fusion weight is selected from `{0, 0.25, 0.5, 0.75, 1}` on validation data only:

```bash
python experiments/dpf/run_dpf.py \
  --split-manifest run/manifest_seed42.csv \
  --output-dir run/main_seed42 \
  --mode dual-path \
  --seeds 10
```

The public interface also exposes:

```text
--mode {hierarchical,global,dual-path}
--fusion-weight FLOAT
--split-manifest PATH
--random-seed INT
```

Each run writes `results.csv`, `summary.csv`, `details.json`, `confusion_matrix.npy`, and `config.json`. The default input policy fails closed on Flow ID, timestamps, protocol numbers, IP addresses, ports, SNI/domain strings, and high-cardinality hashes.

## Prototype-Core Capture Selection

Prototype-Core is a controlled companion regime. It hashes capture IDs into
70/10/20 partitions before fitting class prototypes, represents every capture
with median/IQR summaries of SII-free P/T features, and ranks captures by
increasing robust distance to the training-defined own-class prototype.

Build the candidate index and a materialized manifest without copying pcaps:

```bash
python experiments/prototype_core/select_prototype_subset.py \
  --raw-root /path/to/ja4tor/pcap-root \
  --feature-root /path/to/per-capture/csv-root \
  --output-manifest run/manifest_budget400_seed42.csv \
  --per-class-budget 400 \
  --split-seed 42 \
  --min-pcap-mib 0.5 \
  --max-pcap-mib 20 \
  --min-flow-rows 4
```

Select the budget and model configuration on validation only, then run the
frozen test once:

```bash
python experiments/prototype_core/run_prototype_core.py \
  --selection-manifest run/selection_candidates.csv \
  --output-dir run/search \
  --validation-only \
  --budgets 100,200,300 \
  --validation-seeds 5

python experiments/prototype_core/run_prototype_core.py \
  --selection-manifest run/selection_candidates.csv \
  --output-dir run/final \
  --frozen-config run/search/frozen_config.json \
  --test-seeds 10
```

The test command refuses repeated evaluation when `test_results.csv` already
exists. Complete manifests, configs, per-seed outputs, and figures are under
`experiments/prototype_core/results/` and `figures/prototype_core/`.

## Result Status

The synchronized unrestricted pcap-disjoint snapshot is under
`experiments/dpf/results/`. On split seed 42, ten model seeds give macro-F1
93.983% for the hierarchical expert, 95.117% for the global expert, and 95.072%
for DPF.

The measured Prototype-Core validation search selects 200 captures per class,
300 trees, `max_features=0.5`, and `lambda=1`. Its frozen ten-seed test gives:

| Method | Macro-F1 (%) |
|---|---:|
| Logistic Regression | 86.83 |
| ExtraTrees | 92.69 |
| HistGradientBoosting | 93.98 |
| Hard Hierarchy | 93.73 |
| JA4Tor-H | 93.61 |
| JA4Tor-G | 93.77 |
| JA4Tor-DPF | 93.77 |

Across pcap split seeds 7, 17, 27, 37, and 47, JA4Tor-DPF obtains
94.39±1.02% macro-F1. This experiment did not reach the 98.5% target; the test
result was not used to alter the selection rule or frozen configuration.

The historical ET-BERT 99.20% and JA4Tor 98.96% values belong to the original
flow-level study and are not comparable with either pcap-disjoint table. The
current manuscript contains no active training-value placeholders. Packet-level
shaping results are omitted until a functional replay experiment is available.
