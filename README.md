# JA4Tor: Interpretable Multi-Dimensional Framework for Classifying Covert Encrypted Tunnels

This repository contains the official implementation of the paper **“JA4Tor: Multi-Dimensional Interpretable Classification of Covert Encrypted Tunnels”**, which is currently under review.  

Upon acceptance, we will fully open-source the complete codebase and datasets and provide more detailed documentation and reproduction instructions.

## Project Structure

- `ja4tor/`: core feature extraction framework proposed in the paper.  
  
  This module implements the multi-dimensional representation and interpretable feature engineering pipeline that constitutes the heart of JA4Tor.
  
- `classifier/`: classifier implementation used in this work.  
  
  It combines an improved Jensen–Shannon divergence (JSD) based feature selection algorithm with a hierarchical Random Forest model to perform multi-class tunnel classification and produce predictions.
  
- `data/`: sample datasets derived from our self-built JA4Tor dataset and from public benchmarks, used here for demonstration and partial reproduction.

## JA4Tor Self-Built Dataset (Summary)

The self-built dataset used in our experiments is summarized as follows:

| #    | Traffic Type Description                         | pcap Count | Size   |
| ---- | ------------------------------------------------ | ---------- | ------ |
| 1    | NonTor   traffic                                 | 4248       | 20.6GB |
| 2    | Tor traffic                                      | 1333       | 6.12GB |
| 3    | Tor + Trojan                                     | 761        | 3.92GB |
| 4    | Tor + ShadowSocks                                | 1560       | 7.47GB |
| 5    | Tor + Vmess                                      | 1120       | 3.79GB |

At this stage, the raw pcap files of the full self-built dataset are not yet publicly released. They will be made fully available in this repository after the paper is accepted.

## Provided Data in This Repository

The data currently included in this repository are **selected subsets** derived from the original self-built JA4Tor dataset and used for lightweight experiments and examples in this codebase, rather than the complete dataset.

- The main training and test splits are extracted from the above self-built dataset after processing with the JA4Tor feature extraction framework.

- The `test-cross` split is a **mixed evaluation set** where:
  - the *Normal* class traffic originates from our self-built JA4Tor dataset, and  
  
  - the *Tor* class traffic is sampled from the **ISCX-Tor (UNB-CIC Tor) dataset**
    
    (dataset information and download: https://www.unb.ca/cic/datasets/tor.html).

These subsets are intended to illustrate the usage of JA4Tor and the classifier pipeline without requiring users to download the full raw pcap collections.

## Classifier: Improved JSD + Hierarchical Random Forest

The `classifier/` module implements the classification pipeline adopted in the paper:

1. **Feature selection with improved JSD**  
   - For each candidate feature, an improved variant of the Jensen–Shannon divergence is computed across class-conditional distributions.  
   - Features are ranked by their JSD-based discriminative power, and the top-ranked features are retained for model training.

2. **Hierarchical Random Forest classifier**  
   - A multi-stage Random Forest architecture is built to reflect the hierarchical structure of the traffic labels (e.g., Normal vs. Tor vs. specific covert tunnel types).  
   - The first-level Random Forest separates Normal traffic from covert-tunnel traffic.  
   - Subsequent levels refine the classification inside the covert-tunnel subtree (e.g., Tor basic vs. Tor+Trojan vs. Tor+ShadowSocks vs. Tor+Vmess).

3. **Prediction and evaluation**  
   - The pipeline outputs final class predictions for each flow/trace, and evaluation scripts report standard metrics such as accuracy and per-class performance.

More detailed descriptions of the feature extraction process, the improved JSD formulation, and the hierarchical Random Forest design will be added after the paper is accepted and the full version of the code is released.
