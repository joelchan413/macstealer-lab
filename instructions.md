# MacStealer Mininet-WiFi demonstration and measurement lab

This directory contains everything needed to:

1. record the normal, unmodified same-BSS MacStealer attack;
2. vary associated-client count and AP configuration;
3. measure binary attack success, timing, packets, bytes, and interception
   ratio;
4. preserve per-trial logs and packet captures; and
5. aggregate the results into CSV files and figures.

Use it only in the isolated Mininet-WiFi teaching VM or another network you are
authorized to test.

## Files

| File | Purpose |
|---|---|
| `macstealer_lab.py` | Interactive/recording topology using upstream MacStealer |
| `record_demo.sh` | Reproducible client-isolation + normal-attack recording sequence |
| `macstealer_measure.py` | Instrumented wrapper; it does not modify upstream MacStealer |
| `traffic_generator.py` | Sequence-tagged UDP measurement stream |
| `background_traffic.py` | Measured UDP sender/sinks for loaded profiles |
| `single_trial.py` | One clean Mininet-WiFi measurement trial |
| `run_experiments.py` | Randomized, resumable experiment matrix |
| `analyze_results.py` | CSV aggregation, Wilson intervals, and PNG figures |
| `check_environment.py` | Read-only prerequisite checks |
| `lab_common.py` | Shared profiles, addresses, and configuration generation |
| `EXPERIMENT_PLAN.md` | Experimental rationale and reporting plan |

## 1. Prepare the VM

Take a snapshot first. The recommended baseline is Ubuntu 22.04, hostapd 2.10,
and a working `mac80211_hwsim` module from the existing Mininet-WiFi OVA.

Install the additional packages:

```bash
sudo apt update
sudo apt install -y \
  hostapd dnsmasq tcpdump iw rfkill git pkg-config build-essential \
  libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
  libdbus-1-dev net-tools python3-venv python3-matplotlib
```

The OVA must already provide Mininet-WiFi. Confirm that `mn` and the Python
module `mn_wifi` are available before continuing.

## 2. Install the pinned MacStealer revision

Choose a location and keep it unchanged for the experiment:

```bash
MACSTEALER_DIR=/opt/macstealer
sudo git clone https://github.com/vanhoefm/macstealer.git "$MACSTEALER_DIR"
sudo git -C "$MACSTEALER_DIR" checkout 83851791bc2657bd9f2f384d6b739956ab2c3ea8
sudo chown -R "$(id -u):$(id -g)" "$MACSTEALER_DIR"

cd "$MACSTEALER_DIR/research"
./build.sh
./pysetup.sh
```

If the repository already exists, do not overwrite local work. Verify it is
clean, fetch the pinned commit, and check it out deliberately.

## 3. Copy and check this lab bundle

Copy the complete `macstealer-lab` directory into the VM. Then run:

```bash
LAB_DIR=/path/to/macstealer-lab
MACSTEALER_DIR=/opt/macstealer

cd "$LAB_DIR"
python3 check_environment.py --macstealer "$MACSTEALER_DIR"
```

All checks should pass. A different MacStealer commit is treated as a failed
check because it makes results harder to reproduce.

Before a run, clear any interrupted Mininet topology:

```bash
sudo mn -c
```

Do not run another Mininet-WiFi topology, hostapd, dnsmasq, or wpa_supplicant
experiment at the same time.

## 4. Record the normal attack

The recording sequence uses upstream `macstealer.py` unchanged. It first shows
that direct client-to-client traffic is blocked and then executes the default
same-BSS attack.

1. Configure OBS Studio, SimpleScreenRecorder, or the hypervisor recorder for
   1080p at 30 fps.
2. Use a readable terminal font and close unrelated windows.
3. Run:

```bash
cd "$LAB_DIR"
./record_demo.sh "$MACSTEALER_DIR" recording-artifacts
```

4. Start the screen recorder when prompted and press Enter.
5. Keep the final positive result visible for several seconds.

The directory `recording-artifacts` contains environment metadata and a
terminal typescript. The recording should show:

- `CLIENT ISOLATION CONFIRMED`;
- the victim and attacker using distinct PSKs;
- the intercepted retransmitted SYN/ACK; and
- `POSITIVE NORMAL ATTACK CONFIRMED`.

The recording should not claim that this demonstrates bypassing TLS. It shows
Wi-Fi-layer security-context override. Also, the MFP experiment below uses a
voluntary scripted reconnect; it does not demonstrate a practical MFP
deauthentication bypass.

## 5. Understand the automated experiment

The original completed matrix used five associated-client counts:

```text
1, 5, 10, 20, 40
```

`N` means the victim plus `N - 1` idle background stations immediately before
the security-context transition. Idle stations are intentional: making every
additional station generate traffic would confound client count with load.

Four AP profiles are included:

| Profile | Main change |
|---|---|
| `baseline` | Multi-PSK, isolation on, MFP off, WMM on |
| `no_isolation` | Client isolation off; positive control, not a meaningful bypass |
| `mfp_required` | MFP required with WPA-PSK-SHA256 |
| `wmm_disabled` | WMM disabled to study queue/timing effects |

For each trial, the original TCP SYN/ACK remains the binary success measure.
A separate 1,200-byte UDP stream is sent at 100 packets/second. Every payload
contains a trial ID, sequence number, and monotonic send timestamp. Only unique
packets sent during the ten-second post-association observation window count
toward intercepted volume. This prevents TCP retransmissions and old ARP-queued
UDP packets from inflating results.

### Follow-up four-profile study

The runner now defaults to a focused follow-up study at `N=5`:

| Profile | Configuration | Expected result |
|---|---|---|
| `baseline_idle` | Baseline AP with four idle background stations | High success and interception |
| `baseline_load20` | Baseline plus 20 Mbit/s aggregate downlink load | High success, potentially lower or more variable volume |
| `wmm_disabled_load20` | WMM disabled under the same 20 Mbit/s load | Potentially different loss and latency |
| `vlan_separated` | Victim and attacker pinned to isolated BSS forwarding domains and DHCP subnets | Valid `secure_negative` with no interception |

The two loaded profiles divide a measured 20 Mbit/s offered stream across all
background stations. They therefore require at least two associated clients.
The sender and every receiver write JSON counters so the trial is invalid if
the background stream did not actually run. The offered sender rate must reach
at least 90% of its 20 Mbit/s target; delivered background rate and delivery
ratio are recorded separately rather than used as a validity threshold.

The portable VLAN negative control uses two BSSes with the same SSID. The
victim is pinned to the BSS backed by `10.77.10.0/24`; the attacker is pinned
to an isolated BSS backed by `10.77.20.0/24`. Both sides must authenticate and
obtain DHCP independently. This models the forwarding boundary created by
credential-bound VLANs without depending on hostapd dynamic-VLAN support.

## 6. Run a small smoke test

Start with one baseline trial:

```bash
cd "$LAB_DIR"
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --output-root results \
  --clients 1 \
  --profiles baseline \
  --trials 1
```

The runner prints the experiment directory. A good result reports:

```text
valid=True tcp=True udp=<non-zero count> failure=None
```

Inspect its `trials/<trial-id>/` directory before scaling up. In particular,
review `result.json`, `macstealer.log`, `hostapd.log`, `server.pcap`, and
`attacker.pcap`.

Smoke-test the new study as four trials at `N=5`:

```bash
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --output-root followup-smoke \
  --clients 5 \
  --profiles baseline_idle,baseline_load20,wmm_disabled_load20,vlan_separated \
  --trials 1 \
  --trial-timeout 300
```

The VLAN trial is expected to report `valid=True`, `attack=False`, `tcp=False`,
`udp=0`, and `failure=secure_negative`. Authentication or DHCP failure is not
an acceptable mitigation result.

## 7. Run the pilot matrix

The five-trial-per-cell pilot produces 100 trials:

```bash
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --output-root results \
  --clients 1,5,10,20,40 \
  --profiles baseline,no_isolation,mfp_required,wmm_disabled \
  --trials 5 \
  --seed 20261115
```

If 40 hwsim stations are unstable because of VM resources, replace 40 with the
largest stable value and record that decision. Do not count hwsim, DHCP,
authentication, server, or tool failures as secure AP results.

The runner returns status 2 when one or more trials are invalid. After fixing
the cause, resume and rerun only invalid trials:

```bash
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --resume /absolute/path/to/results/macstealer-YYYYMMDDTHHMMSSZ \
  --rerun-invalid
```

Without `--rerun-invalid`, resume skips every trial that already has a result.

## 8. Run the full matrix

After the pilot passes its quality checks, run 30 valid trials per cell:

```bash
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --output-root results-full \
  --clients 1,5,10,20,40 \
  --profiles baseline,no_isolation,mfp_required,wmm_disabled \
  --trials 30 \
  --seed 20261115
```

This plans 600 trials. The order is randomized within each AP-profile block.
Use `--dry-run` to print the planned order without starting Mininet-WiFi.

Do not enable `--hwsim-pcap` for the full matrix unless raw over-the-air
captures are required; those files can be large. Server and attacker pcaps are
enabled whenever `tcpdump` is installed.

### Run the focused follow-up

Run a five-trial pilot first:

```bash
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --output-root followup-pilot \
  --clients 5 \
  --profiles baseline_idle,baseline_load20,wmm_disabled_load20,vlan_separated \
  --trials 5 \
  --seed 20261117 \
  --trial-timeout 300
```

After all four cells pass their validity checks, collect 30 trials per cell:

```bash
sudo python3 run_experiments.py \
  --macstealer "$MACSTEALER_DIR" \
  --output-root followup-full \
  --clients 5 \
  --profiles baseline_idle,baseline_load20,wmm_disabled_load20,vlan_separated \
  --trials 30 \
  --seed 20261117 \
  --trial-timeout 300
```

This plans 120 trials. Do not combine these results with the original 600-row
matrix; analyze them as a separate experiment version.

## 9. Analyze results

Run the analysis after a pilot or full matrix:

```bash
sudo python3 analyze_results.py \
  --run /absolute/path/to/results/macstealer-YYYYMMDDTHHMMSSZ
```

The `analysis/` directory contains:

- `trials.csv`: one row per attempted trial;
- `summary.csv`: one row per AP-profile/client-count cell;
- `analysis.json`: machine-readable summary and failure counts;
- `success-rate.png`: success with Wilson 95% confidence intervals;
- `interception-ratio.png`: median unique UDP interception ratio;
- `reconnect-latency.png`: median attacker reconnection time; and
- `failure-classes.png`: infrastructure/tool failure counts when present.

Report both unconditional intercepted volume, where valid attack failures count
as zero, and volume conditional on successful TCP interception. The summary CSV
contains both.

## 10. Trial artifacts and failure interpretation

Every trial directory is self-contained and includes generated client/AP
settings, environment metadata, structured events, logs, captures, and its
final `result.json`.

Failure classes are interpreted as follows:

| Failure class | Meaning |
|---|---|
| `secure_negative` | Valid trial, but neither TCP nor tagged UDP was intercepted |
| `auth_failure` | Victim or attacker could not authenticate |
| `dhcp_failure` | Association worked but DHCP did not |
| `server_failure` | No tagged server packets existed in the observation window |
| `background_load_failure` | The configured background sender or receivers produced no measured traffic |
| `hwsim_failure` | Reserved for radio/emulation failures identified during review |
| `tool_failure` | Measurement wrapper or upstream tool exited unexpectedly |

Only `secure_negative` is a valid attack failure. The other classes describe
lab reliability and should be corrected and rerun.

## 11. Troubleshooting

### Background stations do not associate

- Reduce the client count to 1 and rerun the smoke test.
- Check `hostapd.log` and generated `hostapd-effective-settings.txt`.
- Run `sudo mn -c` before retrying.
- Confirm NetworkManager is not controlling hwsim interfaces.

### Two DHCP offers appear

Another dnsmasq or DHCP service is active on the emulated network. Stop the
other topology/service, run `sudo mn -c`, and retry. A trial with competing
DHCP offers is invalid.

### TCP succeeds but UDP count is zero

Inspect `server-events.jsonl`, `server.pcap`, `attacker.pcap`, and
`measurement-events.jsonl`. Confirm the fixed victim lease is `10.77.0.20` and
that packets were sent during the recorded `attacker_ready_ns` window.

### MFP profile cannot connect

Confirm the pinned bundled wpa_supplicant was built successfully. The MFP
profile uses `WPA-PSK-SHA256` and `ieee80211w=2` on both the AP and clients.

### Interrupted matrix

Run `sudo mn -c`, then use `--resume`. The manifest preserves the original
randomized plan and measurement parameters.

## 12. Reproducibility checklist

Before reporting final results, preserve:

- the VM/OVA snapshot identifier;
- `manifest.json` and `environment.json` files;
- the pinned MacStealer commit;
- this complete lab directory;
- all `result.json` files and structured event logs;
- raw pcaps or, if storage is limited, their checksums; and
- the generated analysis CSV/JSON and figures.

The detailed rationale, definitions, quality gates, and reporting guidance are
in `EXPERIMENT_PLAN.md`.
