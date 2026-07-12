# Prototype-Core selection protocol

## Purpose

Prototype-Core is a controlled representative-capture regime. It is designed to
measure classification on captures that exhibit a stable protocol core. It does
not replace the full pcap-disjoint benchmark and must be reported beside that
strict result.

## Candidate construction

Each original pcap must have a same-stem fusion-feature CSV. A capture is
eligible when its size is between 0.5 and 20 MiB and its CSV contains at least
four flow rows. The rule is identical for all five classes. IP addresses, ports,
timestamps, protocol identifiers, SNI/domain strings, and high-cardinality
hashes are excluded.

## Split and ranking

Capture IDs are assigned 70/10/20 to train, validation, and test by a
class-stratified SHA-256 ordering. Training candidates define the prototypes.
For each capture, the selector concatenates the median and IQR of every SII-free
P/T feature. For class `c`, it computes a component-wise median center and MAD
scale from training captures only.

Let `d_c(x)` be the median absolute robust-z distance from capture `x` to class
prototype `c`. Captures are sorted by increasing `d_y(x)` within each class and
split, with capture ID as a deterministic tie breaker. The class label is used
because this is a labeled benchmark-construction rule; the rule and its
limitation are disclosed in the paper.

## Model selection and test access

Budgets 100, 200, and 300 captures per class are compared using validation
macro-F1 over seeds 0--4. Budget 400 is added only if the target is not met.
Tree count, `max_features`, and fusion weight are selected on validation data.
The resulting configuration is written to `frozen_config.json`. The final test
command refuses to run if `test_results.csv` already exists.

The measured validation search selected budget 200, 300 trees,
`max_features=0.5`, and `lambda=1`. The configuration was then evaluated once
on the test partition for seeds 0--9. A separate discriminative-margin trial is
retained under the remote `run/margin/` directory, but it was not used for the
reported test because its validation macro-F1 was lower.
