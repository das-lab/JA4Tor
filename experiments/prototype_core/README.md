# Prototype-Core Capture Selection

This experiment defines a controlled representative-capture regime for the
five-class JA4Tor task. It references the original pcaps in place and reuses the
one-CSV-per-pcap fusion features; it does not copy or overwrite raw data.

## Selection

```bash
python select_prototype_subset.py \
  --raw-root /data1/zcx/ja4tor/data/ja4tor \
  --feature-root /data1/zcx/ja4tor/models/fusion_flow_extractor-0.3/output/csv \
  --output-manifest run/manifest_budget400_seed42.csv \
  --per-class-budget 400 \
  --split-seed 42 \
  --min-pcap-mib 0.5 \
  --max-pcap-mib 20 \
  --min-flow-rows 4
```

The selector uses median and IQR summaries of SII-free P/T features. Class
prototypes are fitted from training candidates only. After a capture-ID hash
split, each capture is ranked by increasing robust distance to its own-class
prototype. This is the selection rule used by the frozen reported run.

## Validation search and frozen test

```bash
python run_prototype_core.py \
  --selection-manifest run/selection_candidates.csv \
  --output-dir run/search \
  --validation-only \
  --budgets 100,200,300 \
  --validation-seeds 5

python run_prototype_core.py \
  --selection-manifest run/selection_candidates.csv \
  --output-dir run/final \
  --frozen-config run/search/frozen_config.json \
  --test-seeds 10
```

The frozen-test command refuses to run when `test_results.csv` already exists.
This prevents repeated test-set selection. The final table includes only models
actually trained on the same selected captures and SII-free input.

## Measured 2026-07-12 result

Validation selected 200 captures per class, 300 trees, `max_features=0.5`,
and `fusion_weight=1`. The first and only frozen ten-seed test produced:

| Variant | Macro-F1 (%) |
|---|---:|
| Logistic Regression | 86.83 |
| ExtraTrees | 92.69 |
| HistGradientBoosting | 93.98 |
| Hard Hierarchy | 93.73 |
| JA4Tor-H | 93.61 |
| JA4Tor-G | 93.77 |
| JA4Tor-DPF | 93.77 |

Five independent pcap splits give JA4Tor-DPF `94.39±1.02%` macro-F1. The
reported selection did not reach the 98.5% target, and the test result was not
used to alter the budget, ranking rule, or model configuration.
