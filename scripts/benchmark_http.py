#!/usr/bin/env python3
"""Measure actual loopback HTTP ingestion using ONLY generated synthetic data.

Starts one disposable Uvicorn worker on an OS-assigned port, records every
request sample, checks durable ledger/case counts, and deletes its temporary DB.
No application preview, production database, or real payment network is touched.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import os
import platform
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from fraudgraph.db import connect, initialize, now_ms  # noqa: E402
from fraudgraph.security import PASSWORDS  # noqa: E402
from fraudgraph.synthetic import generate_scenario  # noqa: E402


def percentiles(values):
    ordered = sorted(values)
    return {f"p{percentile}_ms": ordered[max(0, math.ceil(len(ordered) * percentile / 100) - 1)]
            for percentile in (50, 95, 99)} if ordered else {}


def workload(rings, benign, timestamp):
    result = []
    for index in range(rings):
        sample = generate_scenario("fan_in_fan_out", now_ms=timestamp, seed=index)
        for row in sample["transactions"]:
            changed = {**row, "id": f"bench-{index}-{row['id']}",
                       "sender": f"{row['sender']}:bench-{index}",
                       "receiver": f"{row['receiver']}:bench-{index}"}
            result.append((changed, "synthetic_ring"))
    for index in range(benign):
        result.append(({"id": f"bench-benign-{index}", "sender": f"synthetic:benign-source-{index}",
                        "receiver": f"synthetic:benign-recipient-{index}", "amount_paise": 10_000 + index,
                        "occurred_at": timestamp - 240_000 + index * 400,
                        "provenance": "synthetic"}, "synthetic_benign"))
    return sorted(result, key=lambda item: (item[0]["occurred_at"], item[0]["id"]))


def hardware():
    value = {"platform": platform.platform(), "architecture": platform.machine(),
             "processor": platform.processor(), "logical_cpu_count": os.cpu_count()}
    if platform.system() == "Darwin":
        for field, key in (("physical_memory_bytes", "hw.memsize"), ("processor_model", "machdep.cpu.brand_string")):
            completed = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, check=False)
            if completed.returncode == 0:
                value[field] = int(completed.stdout.strip()) if field.endswith("bytes") else completed.stdout.strip()
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rings", type=int, default=100)
    parser.add_argument("--benign", type=int, default=400)
    parser.add_argument("--output", type=Path, default=PROJECT / "evidence" / "http_benchmark.json")
    args = parser.parse_args()
    if not (1 <= args.rings <= 500 and 0 <= args.benign <= 2000):
        parser.error("Bounded local benchmark accepts 1–500 rings and 0–2000 benign transfers")
    generated_at = now_ms()
    rows = workload(args.rings, args.benign, generated_at - 600_000)
    raw_samples, triggers, first_alerts = [], [], set()
    with tempfile.TemporaryDirectory(prefix="fraudgraph-http-benchmark-") as temp:
        path = Path(temp) / "synthetic-benchmark.sqlite3"
        initialize(path)
        password = secrets.token_urlsafe(24)
        db = connect(path)
        try:
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       ("benchmark_admin", PASSWORDS.hash(password), "admin", now_ms()))
            db.commit()
        finally:
            db.close()
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        environment = {**os.environ, "FRAUDGRAPH_DB": str(path), "FRAUDGRAPH_ENV": "development", "FRAUDGRAPH_ORIGIN": origin}
        log = (Path(temp) / "server.log").open("w+")
        process = None

        def start():
            nonlocal process
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", "fraudgraph.app:create_app", "--factory",
                                        "--host", "127.0.0.1", "--port", str(port), "--workers", "1",
                                        "--no-proxy-headers", "--no-access-log"],
                                       cwd=PROJECT, env=environment, stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    if httpx.get(origin + "/healthz", timeout=1).status_code == 200:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
            raise RuntimeError("Benchmark server did not become healthy")

        def stop():
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

        try:
            start()
            with httpx.Client(base_url=origin, timeout=30) as client:
                response = client.post("/api/login", headers={"Origin": origin},
                                       json={"username": "benchmark_admin", "password": password})
                assert response.status_code == 200, response.text
                client.headers.update({"Origin": origin, "X-CSRF-Token": response.json()["csrf"]})
                for _ in range(20):
                    assert client.get("/healthz").status_code == 200
                started = time.perf_counter()
                for index, (row, kind) in enumerate(rows):
                    request_start = time.perf_counter()
                    response = client.post("/api/transactions/batch", json={"transactions": [row]})
                    request_end = time.perf_counter()
                    latency = (request_end - request_start) * 1000
                    assert response.status_code == 200, f"Request {index}: {response.status_code} {response.text}"
                    result = response.json()
                    assert result["accepted"] == 1 and result["duplicates"] == 0, result
                    new_alerts = set(result["alert_ids"]) - first_alerts
                    first_alerts.update(result["alert_ids"])
                    sample = {"request_index": index, "transaction_id": row["id"], "provenance": "synthetic",
                              "workload_kind": kind, "started_seconds_from_workload": request_start - started,
                              "request_latency_ms": latency, "server_processing_ms": result["processing_ms"],
                              "status_code": response.status_code, "accepted": result["accepted"],
                              "alert_ids": result["alert_ids"], "first_observed_alert_ids": sorted(new_alerts)}
                    raw_samples.append(sample)
                    for alert_id in sorted(new_alerts):
                        triggers.append({"alert_id": alert_id, "trigger_transaction_id": row["id"],
                                         "request_index": index, "trigger_request_start_to_ack_ms": latency})
                elapsed = time.perf_counter() - started
                before_restart = client.get("/api/metrics?provenance=synthetic").json()
                assert before_restart["transactions"] == len(rows), before_restart
                assert sum(before_restart["alerts"].values()) == args.rings, before_restart
                assert len(first_alerts) == args.rings, first_alerts
                stop()
                start()
                after_response = client.get("/api/metrics?provenance=synthetic")
                assert after_response.status_code == 200, after_response.text
                after_restart = after_response.json()
                assert after_restart["transactions"] == len(rows), after_restart
                assert sum(after_restart["alerts"].values()) == args.rings, after_restart
                stop()
                db = connect(path)
                try:
                    durable_transactions = db.execute("SELECT count(*) FROM transactions").fetchone()[0]
                    durable_alerts = db.execute("SELECT count(*) FROM alerts").fetchone()[0]
                    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
                finally:
                    db.close()
                assert durable_transactions == len(rows) and durable_alerts == args.rings and integrity == "ok"
        finally:
            stop()
            log.close()
    latencies = [sample["request_latency_ms"] for sample in raw_samples]
    trigger_latencies = [sample["trigger_request_start_to_ack_ms"] for sample in triggers]
    report = {
        "report_version": 1,
        "provenance": "synthetic",
        "generated_at_ms": generated_at,
        "scope": "Actual single-worker Uvicorn, SQLite FULL synchronous/WAL, loopback HTTP, one transaction per sequential authenticated request.",
        "hardware": hardware(),
        "runtime": {"python": sys.version, "sqlite": sqlite3.sqlite_version,
                    "httpx": httpx.__version__, "uvicorn": importlib.metadata.version("uvicorn")},
        "workload": {"synthetic_rings": args.rings, "transactions_per_ring": 12,
                     "synthetic_benign_transfers": args.benign, "total_transactions": len(rows),
                     "concurrent_clients": 1, "uvicorn_workers": 1, "batch_size": 1,
                     "arrival_order": "Sorted original synthetic event timestamps, no pacing or rescaling.",
                     "health_warmup_requests_excluded": 20},
        "measurement": {"timer": "time.perf_counter", "elapsed_seconds": elapsed,
                        "observed_transactions_per_second": len(rows) / elapsed,
                        "throughput_formula": "accepted transactions / elapsed seconds around entire sequential ingestion loop",
                        "request_latency": {**percentiles(latencies), "minimum_ms": min(latencies), "maximum_ms": max(latencies)},
                        "percentile_method": "nearest rank: sorted sample at ceil(percentile / 100 * sample_count) - 1",
                        "trigger_to_ack": {"count": len(triggers), **percentiles(trigger_latencies)},
                        "trigger_definition": "Elapsed processing time from client request start for the transaction whose acknowledgment first reports an alert, to receiving that acknowledgment. Excludes upstream/event-generation delay."},
        "durability": {"server_restarted": True, "session_survived_restart": True,
                       "expected_transaction_count": len(rows), "observed_transaction_count": durable_transactions,
                       "expected_alert_count": args.rings, "observed_alert_count": durable_alerts,
                       "sqlite_integrity_check": integrity},
        "caveats": [
            "All transfers, ring labels, and accounts are synthetic. Alert counts demonstrate fixture behavior, not fraud accuracy.",
            "One short local run with one sequential client; neither saturation throughput, production p99, nor a capacity guarantee.",
            "No TLS, reverse proxy, remote network latency, external queue, multiple workers, failover, or simultaneous analysts.",
            "Small independent hubs with twelve events each; not representative of highly connected accounts, long-lived ledgers, or adversarial event-budget pressure.",
            "Throughput and percentiles vary with host load, filesystem, hardware, and SQLite synchronization costs.",
            "Trigger-to-ack is a measured request duration for first alerts, not event-time lag or detection delay at a payment provider.",
        ],
        "raw_request_samples": raw_samples,
        "raw_trigger_to_ack_samples": triggers,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"transactions": len(rows), "alerts": durable_alerts,
                      "elapsed_seconds": elapsed, "transactions_per_second": len(rows) / elapsed,
                      "request_latency": percentiles(latencies), "trigger_to_ack": percentiles(trigger_latencies),
                      "restart_durability_verified": True, "report": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
