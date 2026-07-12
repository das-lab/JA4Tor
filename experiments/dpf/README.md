# Dual-Path PAST Fusion experiment

The experiment uses one feature CSV per pcap and keeps every pcap in exactly one
of the train, validation, or test partitions. Endpoint identifiers, ports,
timestamps, SNI domains, and high-cardinality host/fingerprint hashes are removed
before model fitting.

```bash
python build_manifest.py \
  --data-root /data1/zcx/ja4tor/models/fusion_flow_extractor-0.3/output/csv \
  --output run/manifest_seed42.csv \
  --split-seed 42 \
  --directory-suffix=-0927 \
  --csv-subdir ''

python run_dpf.py \
  --split-manifest run/manifest_seed42.csv \
  --output-dir run/main_seed42 \
  --seeds 10
```

The fusion weight is chosen from `{0, 0.25, 0.5, 0.75, 1}` on the validation
partition. The test partition is evaluated only after this selection.

