# Completed experiment results

This directory contains the processed results from the completed MacStealer
Mininet-WiFi matrix:

```text
5 client counts x 4 AP profiles x 30 valid trials = 600 trials
```

## Files

- `analysis.json`: machine-readable cell summaries and quality-control totals.
- `summary.csv`: one row for each of the 20 profile/client-count cells.
- `trials.csv`: one row for each of the 600 valid trials.
- `success-rate.png`: observed attack success with slightly offset profile
  series so equal values remain visible.
- `interception-ratio.png`: median tagged UDP interception ratio.
- `reconnect-latency.png`: median attacker reconnection time.
- `trial-outcomes.png`: valid positive, valid secure-negative, and invalid
  trial counts by profile.

Raw per-trial directories, logs, and packet captures are not included in this
repository. They remain part of the original experiment archive because they
are substantially larger than the processed dataset.

## Quality-control totals

- Results found: 600
- Valid trials: 600
- Analysis cells: 20
- Valid trials per cell: 30
- Infrastructure failure classes in the final dataset: none
- Combined TCP-or-UDP successes: 600/600
- Strict TCP successes: 600/600

## Aggregate traffic result

- Tagged packets sent: 599,987
- Unique tagged packets intercepted: 599,921
- Aggregate interception ratio: 99.989%
- Tagged UDP payload intercepted: 719,905,200 bytes

Every AP-profile series reached 100% observed success and 100% median
interception. The regenerated figures offset equal series slightly around each
client-count tick so all four remain visible.
