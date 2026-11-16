import tempfile
import unittest
from pathlib import Path

from analyze_results import summarize, wilson_interval
from lab_common import render_client_config
from run_experiments import read_result
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


if __name__ == "__main__":
    unittest.main()
