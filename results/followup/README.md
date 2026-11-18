# Completed focused follow-up results

This directory contains the processed results and reproducibility metadata for
the focused MacStealer follow-up:

```text
1 client count x 4 profiles x 30 valid trials = 120 trials
```

The client count was fixed at five: one victim plus four background stations.
The loaded profiles divided a measured 20 Mbit/s uplink stream across the four
background stations.

## Files

- `manifest.json`: randomized trial plan, parameters, and environment.
- `run-summary.json`: execution totals and completion timestamp.
- `environment.json`: kernel, tool, and pinned MacStealer versions.
- `analysis/analysis.json`: machine-readable summaries and quality totals.
- `analysis/summary.csv`: one row per profile.
- `analysis/trials.csv`: one row per trial.
- `analysis/success-rate.png`: observed success rate by profile.
- `analysis/interception-ratio.png`: per-trial interception with median/IQR.
- `analysis/reconnect-latency.png`: per-trial reconnect time with median/IQR.
- `analysis/background-throughput.png`: offered and received loaded traffic.
- `analysis/trial-outcomes.png`: positive, secure-negative, and invalid counts.

## Quality-control totals

- Results found: 120
- Valid trials: 120
- Valid trials per profile: 30
- Infrastructure failures in the final dataset: 0
- Same-domain attack successes: 90/90
- Separated-domain secure negatives: 30/30

## Observed outcomes

| Profile | Attack success | Median interception | Median reconnect | Median offered/received load |
|---|---:|---:|---:|---:|
| `baseline_idle` | 30/30 | 100% | 81.82 ms | — |
| `baseline_load20` | 30/30 | 100% | 94.46 ms | 20.002 / 19.672 Mbit/s |
| `wmm_disabled_load20` | 30/30 | 100% | 99.71 ms | 20.001 / 19.674 Mbit/s |
| `vlan_separated` | 0/30 | 0% | 106.98 ms | — |

Across the three vulnerable profiles, 89,974 of 89,988 tagged packets were
intercepted (99.984%). In the separated profile, none of the 29,994 tagged
victim packets reached the attacker.

The separated profile is a portable Mininet-WiFi negative control using two
same-SSID BSSes backed by isolated layer-2/IP domains. It demonstrates the
effect of credential-bound forwarding separation, but it is not a same-BSS
hostapd dynamic-VLAN implementation.

Raw per-trial logs and packet captures remain in the external experiment
archive and are not committed here.
