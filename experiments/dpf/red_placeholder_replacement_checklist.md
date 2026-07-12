# Final measured-result checklist (historical filename retained)

- [x] Ten model seeds exist for every Prototype-Core main-table method.
- [x] Five independent pcap split seeds exist for JA4Tor-DPF.
- [x] `capture_id` intersections across train, validation, and test are empty.
- [x] Input columns exclude Flow ID, timestamp, protocol, IP, port, SNI/domain, and high-cardinality hashes.
- [x] Fusion weight and model configuration are selected from validation metrics before test access.
- [x] Per-class labels are exactly NonTor, Tor, Tor-SS, Tor-Trojan, and Tor-Vmess.
- [x] Tables, prose, and PDFs are generated from the versioned result CSVs.
- [x] Confusion-matrix rows are normalized from measured predictions.
- [x] Training-plus-inference units are seconds and all compared models run on the same server.
- [x] The current manuscript contains no active training-value macro or red result styling.
- [x] Historical ET-BERT 99.20 and JA4Tor 98.96 values remain in a separate flow-level table.

Packet-level shaping is not checked because it was not measured; the associated
table and figure are excluded from the rendered manuscript.
