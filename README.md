# JA4TOR: Exposing Tor-over-Proxy Tunnels via Protocol-Constrained Behavioral Dynamics

This repository contains the research artifact for **“JA4TOR: Exposing Tor-over-Proxy Tunnels via Protocol-Constrained Behavioral Dynamics.”** The repository currently supports feature extraction, row-level classifier reproduction, and shortcut-feature auditing. It does not yet contain the raw pcap inventory or the group metadata needed to verify pcap/session/run-disjoint evaluation.

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
