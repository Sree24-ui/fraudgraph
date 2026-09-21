"""Invariant and boundary tests with explicitly synthetic transaction fixtures."""

import random
import unittest

from fraudgraph.detector import CONFIG, DETECTOR_VERSION, detect_account, detector_config
from fraudgraph.synthetic import generate_scenario


NOW = 1_750_000_090_000


def tx(identifier, sender, receiver, amount, at):
    return {"id": identifier, "sender": sender, "receiver": receiver,
            "amount_paise": amount, "occurred_at": at, "provenance": "synthetic"}


def four_by_four(outgoing_amount=10_000):
    return ([tx(f"in-{i}", f"source-{i}", "hub", 10_000, NOW - 120_000 + i * 1_000) for i in range(4)]
            + [tx(f"out-{i}", "hub", f"recipient-{i}", outgoing_amount, NOW - 60_000 + i * 1_000) for i in range(4)])


class DetectorTests(unittest.TestCase):
    def test_frozen_thresholds_and_explicit_score_semantics(self):
        self.assertEqual(CONFIG.windows_seconds, (300, 1800, 7200))
        self.assertEqual(CONFIG.min_sources, 4)
        self.assertEqual(CONFIG.min_recipients, 4)
        self.assertEqual((CONFIG.min_passthrough, CONFIG.max_passthrough), (0.65, 1.35))
        self.assertEqual(CONFIG.min_new_recipient_fraction, 0.8)
        self.assertEqual(detector_config()["score_kind"], "heuristic_not_probability")

    def test_canonical_pattern_evidence_is_recomputable(self):
        rows = four_by_four()
        candidates = detect_account("hub", rows, NOW)
        self.assertEqual([c["window_seconds"] for c in candidates], [300, 1800, 7200])
        candidate = candidates[0]
        self.assertEqual(candidate["detector_version"], DETECTOR_VERSION)
        self.assertEqual(candidate["score_kind"], "heuristic_not_probability")
        evidence = candidate["evidence"]
        self.assertCountEqual(evidence["transaction_ids"], [r["id"] for r in rows])
        self.assertEqual(evidence["incoming_paise"], sum(r["amount_paise"] for r in rows if r["receiver"] == "hub"))
        self.assertEqual(evidence["outgoing_paise"], sum(r["amount_paise"] for r in rows if r["sender"] == "hub"))
        self.assertEqual(evidence["passthrough_ratio"], 1)
        self.assertEqual(evidence["unique_sources"], 4)
        self.assertEqual(evidence["unique_recipients"], 4)
        self.assertGreater(evidence["first_payout_at"], evidence["fanin_established_at"])
        self.assertEqual(evidence["provenance"], ["synthetic"])
        self.assertGreaterEqual(candidate["score"], 0)
        self.assertLessEqual(candidate["score"], 100)

    def test_event_order_independent_of_arrival_order(self):
        rows = four_by_four()
        expected = detect_account("hub", rows, NOW)
        random.Random(42).shuffle(rows)
        self.assertEqual(detect_account("hub", rows, NOW), expected)

    def test_identical_retries_do_not_inflate_evidence(self):
        rows = four_by_four()
        self.assertEqual(detect_account("hub", rows + rows, NOW), detect_account("hub", rows, NOW))

    def test_conflicting_transaction_id_is_rejected(self):
        rows = four_by_four()
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate"):
            detect_account("hub", rows + [{**rows[0], "amount_paise": 1}], NOW)

    def test_repeated_source_does_not_create_distinct_counterparties(self):
        rows = four_by_four()
        for row in rows[:4]:
            row["sender"] = "same-source"
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_repeated_recipient_does_not_create_distinct_counterparties(self):
        rows = four_by_four()
        for row in rows[4:]:
            row["receiver"] = "same-recipient"
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_ratio_boundaries_use_exact_integer_comparison(self):
        for amount, expected in [(6499, False), (6500, True), (13500, True), (13501, False)]:
            with self.subTest(amount=amount):
                self.assertEqual(bool(detect_account("hub", four_by_four(amount), NOW)), expected)

    def test_novel_recipient_fraction_boundary(self):
        rows = four_by_four()
        rows[4]["receiver"] = "source-0"  # 3/4 = 0.75 < 0.8.
        self.assertEqual(detect_account("hub", rows, NOW), [])
        rows.append(tx("extra-out", "hub", "fifth-recipient", 1, NOW - 10_000))
        result = detect_account("hub", rows, NOW)
        self.assertEqual(result[0]["evidence"]["new_recipient_fraction"], 0.8)

    def test_window_left_boundary_inclusive_and_one_ms_outside_excluded(self):
        rows = four_by_four()
        rows[0]["occurred_at"] = NOW - 300_000
        self.assertIn(300, [c["window_seconds"] for c in detect_account("hub", rows, NOW)])
        rows[0]["occurred_at"] -= 1
        self.assertNotIn(300, [c["window_seconds"] for c in detect_account("hub", rows, NOW)])
        self.assertIn(1800, [c["window_seconds"] for c in detect_account("hub", rows, NOW)])

    def test_longest_window_expiration(self):
        rows = four_by_four()
        rows[0]["occurred_at"] = NOW - 7_200_000 - 1
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_future_events_do_not_influence_now(self):
        rows = four_by_four()
        rows[-1]["occurred_at"] = NOW + 1
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_equal_timestamps_cannot_establish_flow_order(self):
        rows = four_by_four()
        for row in rows:
            row["occurred_at"] = NOW - 1_000
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_reverse_order_is_not_laundering_evidence(self):
        rows = four_by_four()
        for row in rows[4:]:
            row["occurred_at"] -= 120_000
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_late_deposit_cannot_camouflage_overlarge_redistribution(self):
        rows = four_by_four(20_000)
        rows.append(tx("late-in", "late-source", "hub", 40_000, NOW - 1_000))
        self.assertEqual(detect_account("hub", rows, NOW), [])

    def test_self_transfers_and_unrelated_events_are_ignored(self):
        rows = four_by_four()
        extras = [tx("self", "hub", "hub", 100_000_000, NOW - 50_000),
                  tx("other", "elsewhere", "another", 100_000_000, NOW - 50_000)]
        self.assertEqual(detect_account("hub", rows + extras, NOW), detect_account("hub", rows, NOW))

    def test_amount_scale_is_not_an_assumed_legal_threshold(self):
        baseline = four_by_four()
        for factor in (1, 100, 1_000_000_000):
            rows = [{**row, "amount_paise": row["amount_paise"] * factor} for row in baseline]
            self.assertTrue(detect_account("hub", rows, NOW))

    def test_malformed_events_fail_closed(self):
        for patch in ({"amount_paise": 0}, {"amount_paise": -1}, {"amount_paise": 10.5},
                      {"amount_paise": True}, {"occurred_at": -1}, {"occurred_at": True},
                      {"provenance": "unknown"}, {"sender": ""}, {"receiver": None}, {"id": ""}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                detect_account("hub", [{**four_by_four()[0], **patch}], NOW)

    def test_generator_is_deterministic_and_truth_is_explicitly_synthetic(self):
        sample = generate_scenario(now_ms=NOW, seed=71)
        self.assertEqual(sample, generate_scenario(now_ms=NOW, seed=71))
        self.assertEqual(sample["provenance"], "synthetic")
        self.assertTrue(all(row["provenance"] == "synthetic" for row in sample["transactions"]))
        self.assertIn("not estimates", sample["warning"])

    def test_empty_graph_has_no_alert(self):
        self.assertEqual(detect_account("hub", [], NOW), [])


if __name__ == "__main__":
    unittest.main()
