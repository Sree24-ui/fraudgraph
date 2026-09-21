#!/usr/bin/env python3
"""Recompute synthetic adversarial outcomes and actual persistence probes.

Run from the project directory: python scripts/run_adversarial.py
All scenarios, intended labels, and transaction values are synthetic. No result
in this file estimates accuracy against real UPI activity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from fraudgraph.detector import detect_account, detector_config  # noqa: E402
from fraudgraph.synthetic import SCENARIOS, generate_scenario  # noqa: E402


REASONS = {
    "fan_in_fan_out": "Canonical fixture satisfies every frozen predicate.",
    "ordinary_merchant": "One supplier payout does not satisfy four distinct recipients.",
    "legitimate_aggregator": "Known false positive: legitimate aggregation has an indistinguishable payment shape without customer/business context.",
    "window_boundary": "Overlapping trailing event-time windows preserve the motif across epoch-aligned bucket boundaries.",
    "slow_laundering": "Known evasion: the earliest incoming funds are outside every window when redistribution arrives.",
    "distributed_hubs": "Known evasion: four coordinating hubs share settlement accounts, but each hub has only three sources and recipients; no group-level rule exists.",
    "recipient_reuse": "Known evasion: recipients also occur in the source set, defeating the fresh-recipient predicate.",
    "interleaved_draining": "Known evasion: only three payouts remain after the fourth unique source establishes the phase gate.",
    "low_passthrough": "Known evasion: outgoing value is 60% of incoming value, below the frozen 65% minimum.",
    "reverse_order": "Negative control: paying out before receiving from the sources does not establish the required temporal relationship.",
}


def evaluate_fixture(name: str, now_ms: int, seed: int) -> dict:
    fixture = generate_scenario(name, now_ms=now_ms, seed=seed)
    rows = fixture["transactions"]
    accounts = sorted({row["sender"] for row in rows} | {row["receiver"] for row in rows})
    snapshot = {account: [candidate["window_seconds"] for candidate in detect_account(account, rows, now_ms)]
                for account in accounts}
    snapshot = {account: windows for account, windows in snapshot.items() if windows}
    # Replay all endpoints with original timestamps. Future events in rows are
    # ignored by the same production detector; timestamp ties remain unordered.
    stream = {}
    for endpoint in sorted({row["occurred_at"] for row in rows}):
        for account in accounts:
            candidates = detect_account(account, rows, endpoint)
            if candidates and account not in stream:
                stream[account] = {"first_detection_at": endpoint,
                                   "windows_seconds": [candidate["window_seconds"] for candidate in candidates]}
    truth = fixture["ground_truth"]
    return {
        "scenario": name,
        "provenance": "synthetic",
        "description": fixture["description"],
        "transactions": len(rows),
        "accounts": len(accounts),
        "intended_hub_labels": truth,
        "snapshot_flagged_accounts_and_windows": snapshot,
        "chronological_replay_ever_flagged": stream,
        "missed_intended_mules": [account for account, label in truth.items() if label and account not in stream],
        "false_positive_benign_hubs": [account for account, label in truth.items() if not label and account in stream],
        "expected_rule_alert": fixture["expected_rule_alert"],
        "expectation_matches_observed": bool(snapshot) == fixture["expected_rule_alert"],
        "interpretation": REASONS[name],
    }


def service_probes(now_ms: int) -> dict:
    """Exercise real SQLite ingestion and replay, without mocking persistence."""
    from fraudgraph.db import connect, initialize
    from fraudgraph.service import ingest

    rows = []
    for i in range(4):
        rows.append({"id": f"late-in-{i}", "sender": f"synthetic:source-{i}",
                     "receiver": "synthetic:late-hub", "amount_paise": 10_000,
                     "occurred_at": now_ms - 120_000 + i * 1_000, "provenance": "synthetic"})
    for i in range(4):
        rows.append({"id": f"late-out-{i}", "sender": "synthetic:late-hub",
                     "receiver": f"synthetic:recipient-{i}", "amount_paise": 10_000,
                     "occurred_at": now_ms - 60_000 + i * 1_000, "provenance": "synthetic"})
    with tempfile.TemporaryDirectory(prefix="fraudgraph-adversarial-") as temp:
        settings = SimpleNamespace(db_path=str(Path(temp) / "late.sqlite3"))
        initialize(settings.db_path)
        first = ingest(settings, rows[:3] + rows[4:], "synthetic-adversarial-probe")
        late = ingest(settings, [rows[3]], "synthetic-adversarial-probe")
        retry = ingest(settings, rows, "synthetic-adversarial-probe")
        db = connect(settings.db_path)
        try:
            alerts = [dict(row) for row in db.execute("SELECT * FROM alerts")]
            persisted = db.execute("SELECT count(*) FROM transactions").fetchone()[0]
        finally:
            db.close()
        evidence = json.loads(alerts[0]["evidence"]) if alerts else {}
        late_checks = {
            "initial_seven_events_no_alert": first["accepted"] == 7 and first["alert_ids"] == [],
            "late_fourth_source_creates_historical_alert": late["accepted"] == 1 and len(late["alert_ids"]) == 1,
            "retry_is_idempotent": retry["accepted"] == 0 and retry["duplicates"] == 8 and persisted == 8,
            "one_case_persisted": len(alerts) == 1,
            "evidence_exactly_matches_eight_events": set(evidence.get("transaction_ids", [])) == {row["id"] for row in rows},
            "sums_match_ledger": evidence.get("incoming_paise") == 40_000 and evidence.get("outgoing_paise") == 40_000,
        }
        tied_settings = SimpleNamespace(db_path=str(Path(temp) / "ties.sqlite3"))
        initialize(tied_settings.db_path)
        tied = ingest(tied_settings, [{**row, "occurred_at": now_ms - 120_000} for row in rows],
                      "synthetic-timestamp-probe")
        isolated_settings = SimpleNamespace(db_path=str(Path(temp) / "provenance.sqlite3"))
        initialize(isolated_settings.db_path)
        mixed = [{**row, "provenance": "real" if i >= 4 else "synthetic"} for i, row in enumerate(rows)]
        # Deliberately exercise source isolation in a disposable DB. These are
        # still synthetic fixture values, even though four carry a test 'real'
        # routing label. Nothing is sent to the running server or real ledger.
        isolated = ingest(isolated_settings, mixed, "synthetic-provenance-probe")
        return {
            "provenance": "synthetic",
            "late_arrival": late_checks,
            "same_timestamp_events_do_not_fabricate_order": tied["accepted"] == 8 and tied["alert_ids"] == [],
            "data_source_isolation": isolated["accepted"] == 8 and isolated["alert_ids"] == [],
            "isolation_probe_caveat": "Disposable synthetic fixtures included a test 'real' routing label solely to test isolation; no real transaction data was used.",
            "all_passed": all(late_checks.values()) and tied["alert_ids"] == [] and isolated["alert_ids"] == [],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT / "evidence" / "adversarial.json")
    parser.add_argument("--now-ms", type=int, default=1_750_000_290_000)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    results = [evaluate_fixture(name, args.now_ms, args.seed) for name in SCENARIOS]
    probes = service_probes(args.now_ms)
    report = {
        "report_version": 1,
        "provenance": "synthetic",
        "warning": "Deliberately constructed SYNTHETIC scenarios. Outcomes are not real-world accuracy estimates. A passing evasion test can intentionally mean an attack was MISSED.",
        "evaluation_time_ms": args.now_ms,
        "seed": args.seed,
        "detector_config": detector_config(),
        "detector_sha256": hashlib.sha256((PROJECT / "fraudgraph" / "detector.py").read_bytes()).hexdigest(),
        "aggregate_accuracy": None,
        "aggregate_accuracy_reason": "The scenario mix was selected to probe predicates, not sampled from any deployment population.",
        "results": results,
        "service_probes": probes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    for result in results:
        flags = ", ".join(result["chronological_replay_ever_flagged"]) or "none"
        print(f"SYNTHETIC {result['scenario']}: flagged={flags}; missed={len(result['missed_intended_mules'])}; false_positive_hubs={len(result['false_positive_benign_hubs'])}")
    print(f"SQLite service probes passed: {probes['all_passed']}")
    print(f"Wrote {args.output}")
    return 0 if all(result["expectation_matches_observed"] for result in results) and probes["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
