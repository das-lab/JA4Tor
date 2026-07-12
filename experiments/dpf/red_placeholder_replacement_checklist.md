# Red placeholder replacement checklist

- [ ] The expected 10 model seeds exist for every main-table method.
- [ ] The expected five pcap split seeds exist for JA4Tor-DPF.
- [ ] `capture_id` intersections across train, validation, and test are empty.
- [ ] Input columns contain no Flow ID, timestamp, protocol, IP, port, SNI/domain, or high-cardinality hash.
- [ ] Every fusion weight is selected from validation metrics; no test metric is read during selection.
- [ ] Per-class labels are exactly NonTor, Tor, Tor-SS, Tor-Trojan, and Tor-Vmess.
- [ ] Tables, prose, and PDFs are regenerated from the same versioned result CSV.
- [ ] Confusion-matrix rows sum to 1 within numerical tolerance.
- [ ] Runtime records identify hardware and include training and inference units.
- [ ] Only after all checks pass: replace `\TrainPlaceholder{value}` with measured values and regenerate plots without red placeholder styling.
- [ ] Preserve the historical ET-BERT 99.20 and JA4Tor 98.96 values in `initial_version_change_log_zh.md`.

