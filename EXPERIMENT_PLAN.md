# MacStealer recording and experiment plan

## 1. Objectives

This work has two separate deliverables:

1. A short recording of the unmodified, default same-BSS MacStealer attack.
2. A repeatable dataset measuring:
   - attack success rate;
   - reconnection and time-to-interception latency;
   - unique packets and bytes intercepted;
   - interception ratio;
   - the effect of associated-client count and AP security configuration.

Keep the recording run separate from the measurement implementation. The
recording should use the upstream tool unchanged; measurement can use a clearly
labelled instrumentation patch or wrapper.

## 2. Definitions

- **Associated-client count (`N`)**: stations associated immediately before
  MacStealer starts its victim-to-attacker transition. It includes the simulated
  victim but not the attacker after it replaces the victim's MAC/security
  context. Create `N - 1` background stations.
- **Valid trial**: both credentials authenticate, DHCP succeeds, and the local
  server is verified reachable before the attack. Infrastructure failures are
  recorded separately and repeated; they are not counted as secure AP results.
- **Attack success**: the attacker receives either the original TCP SYN/ACK or
  at least one tagged UDP packet addressed to the victim after completing the
  attacker association. Also report the stricter upstream TCP-only indicator
  separately.
- **Intercepted packet**: a tagged, unique measurement packet received after
  attacker association. Deduplicate packets by `(trial_id, sequence_number)`.
- **Interception ratio**: unique measurement packets received by the attacker
  divided by packets sent during the post-association observation window.

## 3. Recording of the normal attack

### Recording preparation

- Use a fresh VM snapshot and the baseline AP profile.
- Set the terminal to a readable font and hide unrelated windows.
- Record at 1080p/30 fps. OBS Studio, SimpleScreenRecorder, or the hypervisor's
  recorder are all adequate.
- Put the topology and commands in a second terminal before recording so the
  presentation does not depend on typing long paths correctly.
- Do one unrecorded rehearsal and preserve the successful VM snapshot.

### Recommended 4–6 minute shot list

1. **Scope and topology (20–30 seconds)**
   - State that this is an isolated hwsim teaching network.
   - Show `lab-wlan0/lab-wlan1 -> ap1 -> local server`.
2. **Environment evidence (20 seconds)**
   - Show `uname -r`, `hostapd -v`, and the pinned MacStealer commit.
3. **AP security configuration (30 seconds)**
   - Show the SSID, WPA2 multi-PSK, two distinct credentials,
     `ap_isolate=1`, and same-VLAN placement.
4. **Client-isolation control (45–60 seconds)**
   - Run MacStealer's `--c2c lab-wlan1` check.
   - Highlight the output saying direct client-to-client traffic is disabled.
5. **Normal attack (60–90 seconds)**
   - Run the upstream default same-BSS command with no `--other-bss`, `--fast`,
     or measurement modifications.
   - Explain the victim SYN, reconnection with the attacker PSK under the same
     MAC address, and retransmitted SYN/ACK.
6. **Positive result and interpretation (30–45 seconds)**
   - Freeze briefly on `This means the network is vulnerable!`.
   - Explain that the AP encrypted traffic intended for the victim under the
     attacker's newly negotiated key.
7. **Limitations (20 seconds)**
   - State that TLS payloads would remain protected, VLAN separation is a
     defense, and the result applies to this controlled configuration.

Save the terminal output and a pcap from the same recorded run. This gives a
second artifact if text in the video is difficult to read.

## 4. Independent variables

### Client count

Use the following initial levels:

| Level | Associated clients before transition | Background clients |
|---:|---:|---:|
| N1 | 1 | 0 |
| N5 | 5 | 4 |
| N10 | 10 | 9 |
| N20 | 20 | 19 |
| N40 | 40 | 39 |

Run a five-trial pilot first. If N40 causes hwsim or VM instability unrelated
to the attack, replace it with the largest stable value and document the limit.

Background clients should be idle in the primary experiment. Otherwise client
count and offered load are confounded. A secondary stress experiment may use a
fixed **total** background load (for example, 2 Mbit/s divided across all
background clients) at every `N`.

### AP profiles

| ID | Configuration | Purpose and expected result |
|---|---|---|
| P1 | WPA2 multi-PSK, distinct PSKs, `ap_isolate=1`, same VLAN | Vulnerable baseline; expected positive |
| P2 | P1 with `ap_isolate=0` | Positive control; attack may work, but there is no isolation to bypass |
| P3 | P1 with MFP required (`ieee80211w=2`) | Tests MFP; default scripted voluntary reconnect is still expected to work |
| P4 | P1 with WMM disabled (`wmm_enabled=0`) | Tests whether AP queuing/QoS configuration changes timing or volume |

VLAN separation remains a valuable follow-up negative control, but is not part
of the portable automated matrix because dynamic-VLAN behavior differs across
hostapd builds and Mininet-WiFi AP backends. If it is added later, first verify
both VLANs can independently reach the measurement server and treat it as a
separate experiment version.

Do not combine multiple changes in one profile unless the profile is explicitly
described as a defense bundle. Record the complete generated hostapd config for
every trial.

## 5. Traffic-volume measurement

MacStealer's default SYN/ACK proves interception but does not measure useful
volume. Add a separate, tagged UDP stream for measurement:

- Fixed victim address via a dnsmasq reservation for `lab-wlan0`.
- UDP destination port: `5555`.
- Packet rate: 100 packets/second for the initial experiment.
- Payload: 1,200 bytes containing `trial_id`, sequence number, and send time.
- Stream duration: begin two seconds before attacker reconnection and continue
  for ten seconds after attacker association.
- Keep the existing TCP SYN/ACK check active as the binary success measure.

UDP is preferred for volume because TCP retransmissions would inflate captured
packet counts. Count unique UDP sequence numbers, not raw capture frames.

Create an instrumentation mode or a separate `macstealer_measure.py` that:

1. emits machine-readable JSON events for victim connected, SYN sent,
   attacker-connect start, attacker connected, first intercepted packet, and
   trial end;
2. does not exit after the first TCP SYN/ACK;
3. listens for the full ten-second observation window;
4. records unique tagged UDP packets and bytes received after attacker
   association;
5. leaves upstream `macstealer.py` unchanged for the video demonstration.

Capture at three points when practical:

- server egress (`srv-eth0`) for ground-truth packets sent;
- `lab-wlan0` for decrypted packets delivered to the attacker;
- `hwsim0` for an optional over-the-air audit capture.

## 6. Experimental procedure

For each trial:

1. Generate a unique `trial_id` and record the environment metadata.
2. Start a fresh Mininet-WiFi topology using the selected AP profile and `N`.
3. Wait until all background clients are associated.
4. Verify that exactly one DHCP server is active.
5. Verify victim and attacker credentials independently.
6. Start hostapd, DHCP, MacStealer, and capture logs with timestamps.
7. Start the tagged traffic generator at the defined experiment event.
8. Run the default same-BSS transition and observe for ten seconds after
   attacker association.
9. Stop captures cleanly and write one JSON result plus the raw artifacts.
10. Tear down the topology, supplicants, leases, neighbor state, and hostapd
    before the next trial.

Randomize `N` within each AP-profile block. Switching VLAN/AP profiles may be
expensive, so profiles can be blocked, but do not run all low-client trials
before all high-client trials.

## 7. Trial count and matrix

Perform five pilot trials per cell first:

```text
5 client levels × 4 AP profiles × 5 pilot trials = 100 pilot trials
```

After fixing any instrumentation problems, use 30 valid trials per cell:

```text
5 client levels × 4 AP profiles × 30 trials = 600 valid trials
```

If time is constrained, use 20 valid trials per cell and explicitly report the
wider uncertainty. Do not silently discard failures. Classify them as valid
negative results or infrastructure failures using predetermined rules.

## 8. Data schema

Store one JSON object or CSV row per trial with at least:

```text
trial_id, utc_time, random_seed
kernel_version, hostapd_version, mininet_wifi_version, macstealer_commit
ap_profile, ap_isolate, mfp_mode, wmm_enabled, auth_mode
associated_clients, background_load_bps
victim_auth_ok, attacker_auth_ok, dhcp_ok, server_preflight_ok
reconnect_ms, first_intercept_ms, tcp_success
udp_packets_sent_window, udp_packets_intercepted_unique
udp_bytes_intercepted, interception_ratio
valid_trial, failure_class, notes
hostapd_log, macstealer_log, server_pcap, attacker_pcap, hwsim_pcap
```

Use the same monotonic clock inside the VM for event deltas. Also record UTC for
artifact correlation.

### Failure classes

- `secure_negative`: all preflights passed; no victim traffic reached attacker.
- `auth_failure`: one configured credential could not authenticate.
- `dhcp_failure`: association succeeded but DHCP did not.
- `server_failure`: local test traffic was not emitted or reachable.
- `hwsim_failure`: radio/interface disappeared or wpa_supplicant failed to start.
- `tool_failure`: MacStealer or measurement process crashed.

Only `secure_negative` is included as an attack failure. Other classes are
reported as lab reliability and rerun to obtain a valid trial.

## 9. Analysis

For every `(AP profile, N)` cell report:

- successes / valid trials, plus strict TCP-only successes;
- success percentage with a Wilson 95% confidence interval;
- median and interquartile range of reconnection latency;
- median and interquartile range of time to first interception;
- median intercepted bytes and interception ratio;
- both unconditional volume (failures count as zero) and volume conditional on
  successful interception.

Recommended figures:

1. Success rate versus associated-client count, one line per AP profile.
2. Interception ratio versus client count, using box or violin plots.
3. Reconnection latency versus client count.
4. Failure-class counts, kept separate from security results.

Use a binomial/logistic model or Fisher's exact test for success rates and
bootstrap confidence intervals for volume and latency. Emphasize effect sizes
and confidence intervals rather than only p-values.

## 10. Quality gates

Do not start the full 600-trial run until:

- P1 succeeds reliably in the five-trial pilot;
- all four profiles pass victim/attacker authentication and local-server
  preflight checks;
- server and attacker packet counts agree on trial IDs and sequence ranges;
- rerunning one fixed seed produces the same topology and AP configuration;
- every trial directory is self-contained and includes its generated config.

Archive the scripts, version metadata, raw JSON/CSV, generated AP configs,
pcaps, and analysis notebook together. Keep the large pcaps outside version
control and retain checksums in the dataset manifest.
