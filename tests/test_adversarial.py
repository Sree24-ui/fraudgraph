"""Known evasions are passing tests that preserve candid detector limitations.

The assertions do not claim these attacks are stopped: most deliberately assert
no detection. All scenario intent and labels are explicitly synthetic.
"""

import unittest

from fraudgraph.detector import detect_account
from fraudgraph.synthetic import SCENARIOS, generate_scenario


NOW = 1_750_000_290_000  # 90 seconds after an epoch-aligned five-minute boundary.


def evaluate_scenario(name):
    sample = generate_scenario(name, now_ms=NOW, seed=7)
    accounts = sorted({row["sender"] for row in sample["transactions"]}
                      | {row["receiver"] for row in sample["transactions"]})
    flags = {account: detect_account(account, sample["transactions"], sample["evaluation_time_ms"])
             for account in accounts}
    return sample, {account: candidates for account, candidates in flags.items() if candidates}


class AdversarialTests(unittest.TestCase):
    def test_baseline_laundering_fixture_is_detected(self):
        sample, flags = evaluate_scenario("fan_in_fan_out")
        self.assertEqual(set(flags), {"synthetic:mule"})
        self.assertTrue(sample["ground_truth"]["synthetic:mule"])

    def test_fixed_bucket_boundary_evasion_is_stopped_by_sliding_windows(self):
        sample, flags = evaluate_scenario("window_boundary")
        times = [row["occurred_at"] for row in sample["transactions"]]
        self.assertGreater(len({value // 300_000 for value in times}), 1)
        self.assertIn("synthetic:mule", flags)
        self.assertIn(300, [c["window_seconds"] for c in flags["synthetic:mule"]])

    def test_slow_laundering_evades_two_hour_horizon(self):
        sample, flags = evaluate_scenario("slow_laundering")
        self.assertTrue(any(sample["ground_truth"].values()))
        self.assertEqual(flags, {}, "Known weakness: the detector has no >2-hour rule")

    def test_distributed_hubs_evade_minimum_degree(self):
        sample, flags = evaluate_scenario("distributed_hubs")
        self.assertEqual(len(sample["ground_truth"]), 4)
        settlement = {row["receiver"] for row in sample["transactions"] if "shared-settlement" in row["receiver"]}
        self.assertEqual(len(settlement), 3)
        self.assertEqual(flags, {}, "Known weakness: coordinated subthreshold hubs evade a per-account rule")

    def test_reusing_source_accounts_evades_recipient_novelty(self):
        sample, flags = evaluate_scenario("recipient_reuse")
        self.assertTrue(any(sample["ground_truth"].values()))
        self.assertEqual(flags, {}, "Known weakness: circular laundering is outside this fresh-recipient rule")

    def test_immediate_interleaved_draining_evades_phase_gate(self):
        sample, flags = evaluate_scenario("interleaved_draining")
        self.assertTrue(any(sample["ground_truth"].values()))
        self.assertEqual(flags, {}, "Known weakness: only three payouts remain after four sources arrive")

    def test_retaining_40_percent_evades_value_ratio(self):
        sample, flags = evaluate_scenario("low_passthrough")
        self.assertTrue(any(sample["ground_truth"].values()))
        self.assertEqual(flags, {}, "Known weakness: 60% outgoing value falls below the frozen ratio")

    def test_ordinary_merchant_is_not_flagged(self):
        sample, flags = evaluate_scenario("ordinary_merchant")
        self.assertFalse(any(sample["ground_truth"].values()))
        self.assertEqual(flags, {})

    def test_legitimate_aggregator_false_positive_is_reported(self):
        sample, flags = evaluate_scenario("legitimate_aggregator")
        self.assertFalse(any(sample["ground_truth"].values()))
        self.assertEqual(set(flags), {"synthetic:legitimate_aggregator"},
                         "Known false positive: account/merchant context is needed to distinguish this shape")

    def test_all_scenarios_match_published_expectations(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                sample, flags = evaluate_scenario(name)
                self.assertEqual(bool(flags), sample["expected_rule_alert"])


if __name__ == "__main__":
    unittest.main()
