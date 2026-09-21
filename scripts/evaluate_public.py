#!/usr/bin/env python3
"""Evaluate the frozen production detector on independently published SYNTHETIC data.

Run from project root. No labels enter detection, no parameter fitting is done,
no timestamps are compressed, and original USD amounts remain USD minor units.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import itertools
import json
import sys
import subprocess
import time
import zipfile
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from fraudgraph.detector import CONFIG, detect_account, detector_config  # noqa: E402

SOURCE_URL = "https://www.dropbox.com/sh/l3grpumqfgbxqak/AAAj0fIjtJI6n9fdIBy2V7Lia/banks/v2.1?dl=0"
SOURCE_PAGE = "https://github.com/IBM/AMLSim/wiki/Download-Example-Data-Set"
EXPECTED = {
    "accounts.csv.gz": "c07436098bc13d345d52b9c063dbe08e674adf71b955c95c8907a1e3e54a602f",
    "transactions.csv.gz": "d32cd92994941ae61128a29e1d59ca828ae389d9a90aef962f281d450e676d08",
    "alert_accounts.csv.gz": "a17be41c7db8cfe78a9a28a1d38a48bfa91058bd4a7af72ee0661d473b16cbbb",
    "alert_transactions.csv.gz": "d32d38c93ec32c2fa38f3d55fbb4e8907811e61e3a1a8a438540fd37ef964336",
}


def sha256(path: Path) -> str:
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def download(destination: Path) -> None:
    """Download publisher's ZIP, extract only fixed expected names, verify bytes."""
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / "ibm-amlsim-v2.1.zip"
    # Use system certificate trust through curl. Do not disable TLS validation.
    # Argument-list invocation deliberately avoids shell interpretation.
    subprocess.run(["curl", "--proto", "=https", "--proto-redir", "=https",
                    "--fail", "--show-error", "--location", "--max-time", "120",
                    SOURCE_URL, "--output", str(archive)], check=True)
    with zipfile.ZipFile(archive) as zipped:
        for name, expected in EXPECTED.items():
            target = destination / name
            target.write_bytes(zipped.read("data/bank_mixed/" + name))
            if sha256(target) != expected:
                raise ValueError(f"Publisher file {name} differs from reviewed SHA-256; do not silently substitute")


def rows(path: Path):
    with gzip.open(path, "rt", newline="") as handle:
        yield from csv.DictReader(handle)


def milliseconds(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def minor_units(value: str) -> int:
    exact = Decimal(value) * 100
    if exact != exact.to_integral_value() or exact <= 0:
        raise ValueError("Invalid source amount; no rounding or dropping data is allowed")
    return int(exact)


def confusion(predicted: set[str], positive: set[str], universe: set[str]) -> dict:
    tp = len(predicted & positive)
    fp = len(predicted - positive)
    fn = len(positive - predicted)
    tn = len(universe - (positive | predicted))
    return {
        "unit": "unique_account_over_entire_replay",
        "true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "precision_note": "Undefined when no accounts are alerted; null is not perfect precision",
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "formula": {"precision": "TP / (TP + FP)", "recall": "TP / (TP + FN)",
                    "false_positive_rate": "FP / (FP + TN)", "f1": "2TP / (2TP + FP + FN)"},
    }


def evaluate(data: Path) -> dict:
    frozen_path = PROJECT / "fraudgraph" / "detector.py"
    detector_hash = sha256(frozen_path)
    for name, expected in EXPECTED.items():
        actual = sha256(data / name)
        if actual != expected:
            raise ValueError(f"Hash mismatch for {name}: {actual}; expected {expected}")
    account_rows = list(rows(data / "accounts.csv.gz"))
    universe = {row["acct_id"] for row in account_rows}
    positive = {row["acct_id"] for row in account_rows if row["prior_sar_count"].lower() == "true"}
    memberships = list(rows(data / "alert_accounts.csv.gz"))
    if positive != {r["acct_id"] for r in memberships if r["is_sar"].lower() == "true"}:
        raise ValueError("Source label tables disagree")
    incident = defaultdict(deque)
    predicted: set[str] = set()
    ids: set[str] = set()
    observed: set[str] = set()
    alert_examples = []
    counters = Counter()
    clock_start = time.perf_counter()
    first_timestamp = None
    last_timestamp = None
    max_window_ms = max(CONFIG.windows_seconds) * 1000
    # Publisher's stream is chronological. Verify it instead of silently sorting
    # or modifying timestamps. Group equal timestamps so file order gives no
    # artificial chronology to events whose ordering is not observable.
    for iso, block in itertools.groupby(rows(data / "transactions.csv.gz"), key=lambda r: r["tran_timestamp"]):
        at = milliseconds(iso)
        if last_timestamp is not None and at <= last_timestamp:
            raise ValueError("Source is not nondecreasing by event time")
        if first_timestamp is None:
            first_timestamp = at
        last_timestamp = at
        counters["timestamp_groups"] += 1
        counters["non_midnight_timestamp_groups"] += not iso.endswith("T00:00:00Z")
        touched: set[str] = set()
        for row in block:
            if row["tran_id"] in ids:
                raise ValueError("Source has duplicate transaction IDs")
            ids.add(row["tran_id"])
            if row["orig_acct"] not in universe or row["bene_acct"] not in universe:
                raise ValueError("Source references an unknown account")
            tx = {"id": "amlsim-v21-" + row["tran_id"], "sender": row["orig_acct"],
                  "receiver": row["bene_acct"], "occurred_at": at,
                  # This field is the core detector's integer minor-unit API.
                  # These numbers represent SYNTHETIC USD CENTS, NOT INR paise.
                  # The frozen detector uses ratios, not absolute amount gates.
                  "amount_paise": minor_units(row["base_amt"]), "provenance": "external_synthetic"}
            for account in {tx["sender"], tx["receiver"]}:
                incident[account].append(tx)
                touched.add(account)
                observed.add(account)
            counters["transactions"] += 1
            counters["sar_transactions"] += row["is_sar"].lower() == "true"
        for account in sorted(touched):
            history = incident[account]
            while history and history[0]["occurred_at"] < at - max_window_ms:
                history.popleft()
            result = detect_account(account, list(history), at)
            counters["account_timestamp_evaluations"] += 1
            counters["candidate_window_matches"] += len(result)
            if result:
                predicted.add(account)
                if len(alert_examples) < 20:
                    alert_examples.append(result[0])
    runtime = time.perf_counter() - clock_start
    if sha256(frozen_path) != detector_hash:
        raise ValueError("Detector changed during evaluation; rerun against one fixed version")

    # Label-only coverage analysis happens after detector predictions are fixed.
    # It explains benchmark incompatibility, never supplies features or tuning.
    by_pattern = defaultdict(list)
    for row in rows(data / "alert_transactions.csv.gz"):
        by_pattern[row["alert_id"]].append(row)
    patterns = Counter()
    gather_hubs = set()
    duration_seconds = []
    full_horizon_four_by_four = 0
    within_frozen_largest_window = 0
    for pattern in by_pattern.values():
        typology = pattern[0]["alert_type"]
        patterns[typology] += 1
        if typology != "gather_scatter":
            continue
        sources = {r["orig_acct"] for r in pattern}
        recipients = {r["bene_acct"] for r in pattern}
        hubs = sources & recipients
        gather_hubs.update(hubs)
        duration = (max(milliseconds(r["tran_timestamp"]) for r in pattern) -
                    min(milliseconds(r["tran_timestamp"]) for r in pattern)) / 1000
        duration_seconds.append(duration)
        within_frozen_largest_window += duration <= max(CONFIG.windows_seconds)
        for hub in hubs:
            incoming_sources = {r["orig_acct"] for r in pattern if r["bene_acct"] == hub}
            outgoing_recipients = {r["bene_acct"] for r in pattern if r["orig_acct"] == hub}
            full_horizon_four_by_four += (len(incoming_sources) >= CONFIG.min_sources and
                                         len(outgoing_recipients) >= CONFIG.min_recipients)
    result = {
        "dataset": "IBM AMLSim v2.1 bank_mixed",
        "data_kind": "independently_published_external_synthetic_not_UPI_not_real_banking_data",
        "source_page": SOURCE_PAGE, "download_url": SOURCE_URL,
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sha256_files": EXPECTED, "detector_sha256": detector_hash, "detector": detector_config(),
        "protocol": {"tuning": "none; frozen production thresholds", "labels_used_for_detection": False,
                     "time_rescaling": False, "same_timestamp_policy": "all events added before one evaluation per affected account; strict causal gate preserved",
                     "monetary_units": "synthetic USD cents mapped losslessly to integer detector amount field; no INR conversion",
                     "preprocessing": "verified SHA-256; all source transactions replayed in original chronological timestamp groups; source ID retained with namespace prefix",
                     "evaluation_scope": "core production detector replay, not HTTP ingestion throughput or live UPI validation"},
        "counts": {**counters, "accounts": len(universe), "observed_accounts": len(observed),
                   "sar_accounts": len(positive), "unique_alerted_accounts": len(predicted)},
        "account_sar_confusion": confusion(predicted, positive, universe),
        "gather_scatter_hubs": {"ground_truth_hubs": len(gather_hubs), "detected_hubs": len(gather_hubs & predicted),
                                "recall": len(gather_hubs & predicted) / len(gather_hubs) if gather_hubs else None},
        "coverage": {"source_patterns_by_type": dict(patterns),
                     "gather_scatter_duration_seconds_min": min(duration_seconds),
                     "gather_scatter_duration_seconds_max": max(duration_seconds),
                     "gather_scatter_patterns_entirely_within_largest_frozen_window": within_frozen_largest_window,
                     "gather_scatter_hubs_meeting_four_by_four_over_entire_pattern": full_horizon_four_by_four,
                     "first_timestamp_ms": first_timestamp, "last_timestamp_ms": last_timestamp},
        "elapsed_seconds_core_replay_and_csv_parsing": runtime,
        "source_rows_per_second_core_replay_and_csv_parsing": counters["transactions"] / runtime,
        "predicted_accounts": sorted(predicted), "candidate_examples_first_20": alert_examples,
        "interpretation": "External validation failure for this operational window, not evidence of high accuracy. Day-resolution source data cannot establish strictly later inflow-to-outflow causality inside a 2-hour window; source SAR labels also include cycle participants and non-hub members beyond this rule's target.",
        "limitations": ["External synthetic, US/USD banking simulation, not UPI data or proof of real-world effectiveness",
                        "All original timestamps are preserved; source daily granularity differs from near-real-time UPI",
                        "SAR account truth covers all typology participants, while rule targets hubs",
                        "Runtime covers in-process detector replay and CSV parsing on this machine, not service latency or sustainable throughput",
                        "No threshold optimization, feature leakage, money conversion or timestamp compression"],
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True, help="Directory holding four publisher .csv.gz files")
    parser.add_argument("--download", action="store_true", help="Download the publisher's public files first")
    parser.add_argument("--output", type=Path, default=PROJECT / "evidence" / "public_evaluation.json")
    args = parser.parse_args()
    if args.download:
        download(args.data_dir)
    evidence = evaluate(args.data_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"evidence": str(args.output), "counts": evidence["counts"],
                      "confusion": evidence["account_sar_confusion"], "coverage": evidence["coverage"],
                      "elapsed_seconds": evidence["elapsed_seconds_core_replay_and_csv_parsing"]}, indent=2))


if __name__ == "__main__":
    main()
