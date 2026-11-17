import tempfile
import unittest
from pathlib import Path

from analyze_results import summarize, wilson_interval
from background_traffic import metrics
from lab_common import PROFILES, STUDY_PROFILES, render_client_config
from run_experiments import read_result
from single_trial import wait_for_background_receivers
from traffic_generator import build_payload


class HarnessTests(unittest.TestCase):
    def test_measurement_payload_has_exact_size_and_header(self):
        payload = build_payload("trial-1", 7, 123456, 1200)
        self.assertEqual(len(payload), 1200)
        self.assertTrue(payload.startswith(b"MSLAB1|trial-1|7|123456|"))

    def test_mfp_client_config_is_symmetric(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client.conf"
            render_client_config(path, "mfp_required")
            text = path.read_text()
        self.assertEqual(text.count("ieee80211w=2"), 2)
        self.assertEqual(text.count("key_mgmt=WPA-PSK-SHA256"), 2)

    def test_followup_study_profiles_match_design(self):
        self.assertEqual(
            STUDY_PROFILES,
            [
                "baseline_idle",
                "baseline_load20",
                "wmm_disabled_load20",
                "vlan_separated",
            ],
        )
        self.assertEqual(PROFILES["baseline_idle"]["background_load_mbps"], 0.0)
        self.assertEqual(PROFILES["baseline_load20"]["background_load_mbps"], 20.0)
        self.assertEqual(
            PROFILES["baseline_load20"]["background_direction"],
            "uplink_to_server",
        )
        self.assertEqual(
            PROFILES["wmm_disabled_load20"]["background_load_mbps"], 20.0
        )
        self.assertEqual(PROFILES["wmm_disabled_load20"]["wmm_enabled"], 0)
        self.assertEqual(
            PROFILES["vlan_separated"]["network_mode"],
            "separate_bss_vlan",
        )

    def test_vlan_client_config_pins_distinct_bssids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client.conf"
            render_client_config(
                path,
                "vlan_separated",
                victim_bssid="02:00:00:00:10:01",
                attacker_bssid="02:00:00:00:20:01",
            )
            text = path.read_text()
        self.assertIn("bssid=02:00:00:00:10:01", text)
        self.assertIn("bssid=02:00:00:00:20:01", text)

    def test_background_metrics_report_achieved_rate(self):
        snapshot = metrics(
            "sender",
            1_000_000_000,
            packets=100,
            payload_bytes=1_000_000,
            target_mbps=20.0,
        )
        self.assertGreater(snapshot["achieved_mbps"], 0)
        self.assertEqual(snapshot["target_mbps"], 20.0)

    def test_background_receiver_preflight_reads_each_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [
                Path(directory) / "bg001.json",
                Path(directory) / "bg002.json",
            ]
            paths[0].write_text('{"packets": 12}\n')
            paths[1].write_text('{"packets": 9}\n')
            counts = wait_for_background_receivers(paths, timeout=0.01)
        self.assertEqual(counts, [12, 9])

    def test_wilson_interval_contains_observed_rate(self):
        low, high = wilson_interval(15, 30)
        self.assertLess(low, 0.5)
        self.assertGreater(high, 0.5)

    def test_empty_result_is_reported_as_damaged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text("")
            result, error = read_result(path)
        self.assertIsNone(result)
        self.assertIn("JSONDecodeError", error)

    def test_summary_separates_valid_and_infrastructure_failures(self):
        trials = [
            {
                "profile": "baseline",
                "associated_clients": 1,
                "valid_trial": True,
                "attack_success": True,
                "tcp_success": True,
                "udp_bytes_intercepted": 1200,
                "interception_ratio": 1.0,
                "reconnect_ms": 100,
            },
            {
                "profile": "baseline",
                "associated_clients": 1,
                "valid_trial": False,
                "failure_class": "dhcp_failure",
            },
        ]
        row = summarize(trials)[0]
        self.assertEqual(row["valid_trials"], 1)
        self.assertEqual(row["infrastructure_failures"], 1)
        self.assertEqual(row["success_rate"], 1.0)

    def test_summary_counts_valid_secure_negative(self):
        row = summarize(
            [
                {
                    "profile": "vlan_separated",
                    "associated_clients": 5,
                    "valid_trial": True,
                    "failure_class": "secure_negative",
                    "attack_success": False,
                    "tcp_success": False,
                    "udp_bytes_intercepted": 0,
                    "interception_ratio": 0.0,
                    "reconnect_ms": 120,
                    "background_load_target_mbps": 0.0,
                    "background_load_actual_mbps": 0.0,
                }
            ]
        )[0]
        self.assertEqual(row["valid_trials"], 1)
        self.assertEqual(row["attack_successes"], 0)
        self.assertEqual(row["secure_negatives"], 1)
        self.assertEqual(row["success_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
