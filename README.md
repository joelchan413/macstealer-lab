# MacStealer Mininet-WiFi Lab: Overview

Setup and operating instructions are in [instructions.md](instructions.md).
The complete dataset is under
[results/analysis](results/analysis/README.md).

## Executive summary

I built a controlled Mininet-WiFi lab to demonstrate and measure the MacStealer
client-isolation bypass (CVE-2022-47522). The attack was tested only against
simulated stations and a local server inside an isolated virtual machine.

The work had two parts:

1. Demonstrate the normal upstream MacStealer attack and preserve terminal,
   configuration, and packet-capture evidence.
2. Run a repeatable experiment measuring attack success, intercepted traffic,
   and reconnection timing while changing the number of associated clients and
   selected AP settings.

The final experiment contained 600 valid trials. The attack succeeded in all
600 trials, including all 600 strict TCP checks. It intercepted 599,921 of
599,987 tagged UDP packets, an aggregate interception ratio of 99.989%.

## What MacStealer demonstrates

Wi-Fi authentication establishes encryption keys, but downstream traffic is
normally routed to a station using its MAC address. MacStealer disconnects a
victim and reconnects with the victim's MAC address while using the attacker's
own valid credentials. On a vulnerable network, the AP associates the victim's
MAC address with the attacker's new encryption keys. Traffic intended for the
victim can then be encrypted for and delivered to the attacker.

This is relevant when client isolation is enabled. Client isolation may block
ordinary station-to-station attacks, but it does not necessarily prevent this
security-context replacement.

MacStealer does not break WPA encryption or recover the victim's password. It
assumes a malicious insider who already has valid network credentials. TLS and
other end-to-end encryption still protect application payload contents.

Upstream project: <https://github.com/vanhoefm/macstealer>

## Lab environment

- Ubuntu/Mininet-WiFi virtual machine
- Linux kernel 5.15.0-139-generic
- Mininet-WiFi with `mac80211_hwsim`
- hostapd 2.12 development version
- MacStealer commit `83851791bc2657bd9f2f384d6b739956ab2c3ea8`
- MacStealer installed under `/opt/macstealer`
- Lab harness under `~/macstealer-lab`
- Local-only server; no external systems were targeted

### Simplified topology

```text
                           +----------------------+
                           | local test server    |
                           | TCP 4444 / UDP 5555  |
                           | 10.77.0.1            |
                           +----------+-----------+
                                      |
                            +---------+---------+
                            | Mininet-WiFi AP   |
                            | WPA2 multi-PSK    |
                            +---------+---------+
                                      |
              +-----------------------+----------------------+
              |                       |                      |
       victim/attacker            background             background
       lab-wlan0                   station(s)             station(s)
       10.77.0.20
```

The victim and attacker used different PSKs on the same SSID. During the
attack, the attacker reconnected using the victim's MAC address but retained
the attacker's valid credential identity.

## Measurement design

### Independent variables

Five associated-client counts were tested:

- 1 client
- 5 clients
- 10 clients
- 20 clients
- 40 clients

The count includes the victim. The remaining clients were idle background
stations, allowing the experiment to test association scale without also
changing offered traffic load.

Four AP profiles were tested:

| Profile | Configuration | Role in experiment |
|---|---|---|
| `baseline` | Client isolation on, MFP off, WMM on | Main vulnerable case |
| `no_isolation` | Client isolation off | Positive control |
| `mfp_required` | Client isolation on, MFP required | Tests whether MFP changes the outcome |
| `wmm_disabled` | Client isolation on, WMM off | Tests queuing/QoS timing effects |

These profiles are configuration comparisons, not four proposed defenses.
In particular, MFP can make forced disconnection harder in a real network, but
it is not a complete mitigation for this attack flow.

### Trial matrix

```text
5 client counts x 4 AP profiles x 30 trials = 600 trials
```

Client counts were randomized inside each AP-profile block. Each trial started
a fresh topology and produced its own logs, JSON result, and packet captures.

### Traffic measurement

The original TCP SYN/SYN-ACK proof was retained as a strict binary test. A
separate tagged UDP stream was added to measure volume:

- 100 UDP packets per second
- 1,200-byte tagged payload
- 10-second post-association observation window
- Unique sequence numbers used to prevent double-counting
- Nominal payload per trial: 1,200,000 bytes

The local server recorded which packets it sent, and the attacker recorded the
unique packets it received after association. This allowed the interception
ratio to be calculated as:

```text
unique tagged packets received / unique tagged packets sent in the window
```

### Trial validity

A trial was valid only when:

- victim authentication succeeded;
- attacker authentication succeeded;
- DHCP and local server preflight checks succeeded;
- the measurement process completed successfully; and
- tagged server traffic existed during the observation window.

Authentication, DHCP, server, emulator, and tool failures were treated as lab
failures and were rerun. A valid trial with no intercepted TCP or UDP traffic
would have been classified as `secure_negative`.

## Automation and artifacts

The harness automated the following work for every trial:

1. Generate the AP and client configuration.
2. Create the selected number of hwsim stations.
3. Start hostapd, background supplicants, DHCP, the local server, and captures.
4. Verify all preconditions.
5. Start the tagged traffic generator.
6. Run the instrumented same-BSS MacStealer transition.
7. Observe traffic for ten seconds after attacker association.
8. Write structured results and clean up the topology.

Important output files included:

- `result.json` per trial
- `server-events.jsonl`
- `measurement-events.jsonl`
- `hostapd.log`
- `macstealer.log`
- `server.pcap` and `attacker.pcap`
- generated hostapd and supplicant settings
- `trials.csv`, `summary.csv`, and `analysis.json`
- success-rate, interception-ratio, and reconnection-latency figures

## Results

### Completeness and success

- 600 unique results found
- 600 valid trials
- 20 profile/client-count cells
- 30 valid trials per cell
- no remaining infrastructure failure classes
- 600/600 combined TCP-or-UDP successes
- 600/600 strict TCP successes

Each cell observed 30 successes in 30 valid trials. The per-cell Wilson 95%
confidence interval is approximately 88.65% to 100%. The observed point
estimate is 100%; the interval reflects the finite sample size.

### Intercepted traffic

- Tagged packets sent: 599,987
- Unique tagged packets intercepted: 599,921
- Packets not observed by the attacker: 66
- Aggregate interception ratio: 99.989%
- Tagged UDP payload intercepted: 719,905,200 bytes
- Median tagged payload per trial: 1,200,000 bytes

Individual windows contained 999 to 1,001 packets because of timer scheduling
at observation-window boundaries. All packet, byte, and ratio calculations
were internally consistent.

### Reconnection timing

| Profile | Aggregate median attacker reconnect time |
|---|---:|
| Baseline | 78.75 ms |
| No isolation | 79.14 ms |
| MFP required | 95.58 ms |
| WMM disabled | 76.51 ms |

MFP required approximately 16.8 ms more median reconnect time than baseline,
but did not reduce attack success or intercepted volume. This should be
reported as a descriptive result rather than proof of causation, because AP
profiles were run in blocks.

### Effect of client count

There was no monotonic relationship between associated-client count and attack
success, intercepted volume, or attacker reconnect time. The background
stations were idle, so this result means that association count alone did not
materially change the outcome in this hwsim experiment. It does not describe a
congested radio network.

### Figure interpretation

The success-rate and interception-ratio graphs contain four series, but all
four overlap. The last series drawn visually covers the others. Suitable
captions are:

> All four AP-profile curves overlap at 100% observed attack success. Each
> point represents 30 valid trials; error bars are Wilson 95% confidence
> intervals.

> Median UDP interception was 100% in every cell. Across all raw trials,
> 599,921 of 599,987 tagged packets were intercepted (99.989%).

![Attack success rate](results/analysis/success-rate.png)

![UDP interception ratio](results/analysis/interception-ratio.png)

![Attacker reconnect latency](results/analysis/reconnect-latency.png)

## Main conclusions

1. The controlled Mininet-WiFi AP was consistently vulnerable to MacStealer.
2. Client isolation did not prevent the security-context override.
3. Increasing idle associated clients from 1 to 40 did not reduce reliability.
4. MFP increased reconnection latency but did not stop the scripted attack.
5. Disabling WMM did not produce a material difference at this traffic level.
6. Once the attacker reconnected, almost all downstream tagged traffic for the
   victim was delivered to the attacker.

## Follow-up study implemented

The harness now includes a focused four-profile follow-up intended to avoid the
all-positive ceiling in the original matrix:

| Profile | Configuration | Expected result |
|---|---|---|
| `baseline_idle` | Baseline with idle background stations | Near-total success and interception |
| `baseline_load20` | Baseline under measured 20 Mbit/s downlink load | High success with potentially lower or more variable volume |
| `wmm_disabled_load20` | WMM disabled under the same load | Potentially different loss and latency |
| `vlan_separated` | Victim and attacker on isolated BSS forwarding domains | No interception |

The strongest negative control models per-credential VLAN separation:

```text
VictimPass123   -> VLAN 10 -> victim subnet
AttackerPass123 -> VLAN 20 -> attacker subnet

Firewall: VLAN 20 cannot reach VLAN 10
```

For portability across Mininet-WiFi and hostapd builds, the automated profile
uses two BSSes with the same SSID and separate layer-2/IP domains. The victim is
pinned to the `10.77.10.0/24` BSS and the attacker to `10.77.20.0/24`. This
tests the relevant forwarding separation, but it is not a same-BSS hostapd
dynamic-VLAN implementation. Both credentials must work normally and obtain
independent DHCP leases while victim traffic remains confined to the victim
domain.

Expected mitigation result:

```text
valid_trial: true
victim_auth_ok: true
attacker_auth_ok: true
dhcp_ok: true
attack_success: false
tcp_success: false
udp_packets_intercepted_unique: 0
failure_class: secure_negative
```

This is a mitigation for the tested MacStealer path, not a universal solution
to all wireless client-isolation attacks. It should use proper firewall rules
and separate group-key handling.

Another upstream mitigation concept is to remember the credential/security
association recently used by each MAC address. An AP or controller can delay or
reject a rapid reconnection when the same MAC is presented with a different
credential. That requires AP/controller logic rather than a simple MFP switch.

The follow-up pilot and full-run commands are in
[instructions.md](instructions.md#run-the-focused-follow-up).

## Limitations

- `mac80211_hwsim` is deterministic and does not reproduce real interference,
  fading, hidden nodes, or hardware/firmware behavior.
- Background clients were idle, so the study tests client count but not
  increasing channel load.
- All profiles achieved a ceiling result, preventing meaningful comparison of
  success probability or volume between them.
- AP profiles were blocked rather than fully interleaved, so timing differences
  may include block/order effects.
- The byte metric counts tagged UDP payload, not Wi-Fi framing overhead.
- Results apply to the tested hostapd, kernel, Mininet-WiFi, and MacStealer
  versions.
- Higher-layer encryption such as TLS was outside the test; it would protect
  content even if link-layer frames were redirected.
