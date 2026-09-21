"""Boot an isolated real HTTP server and probe security using SYNTHETIC data.

Run: python scripts/security_probe.py --output evidence/security_live.json
Does not touch the configured application database or require default passwords.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fraudgraph.db import connect, initialize, now_ms
from fraudgraph.security import PASSWORDS
from fraudgraph.synthetic import generate_scenario


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/security_live.json")
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix="fraudgraph-security-") as temp:
        temp = Path(temp)
        path = temp / "synthetic-security.sqlite3"
        password = secrets.token_urlsafe(24)
        initialize(path)
        db = connect(path)
        hashed = PASSWORDS.hash(password)
        for role in ("admin", "analyst", "viewer", "ingestor"):
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (f"probe_{role}", hashed, role, now_ms()))
        db.commit()
        db.close()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        env = {**os.environ, "FRAUDGRAPH_DB": str(path), "FRAUDGRAPH_ENV": "development", "FRAUDGRAPH_ORIGIN": origin}
        log = (temp / "server.log").open("w+")
        process = None
        clients = []
        def start():
            nonlocal process
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", "fraudgraph.app:create_app", "--factory", "--host", "127.0.0.1", "--port", str(port), "--no-proxy-headers"], cwd=ROOT, env=env, stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    if httpx.get(origin + "/healthz", timeout=1).status_code == 200:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(.05)
            raise RuntimeError("Server did not become healthy")
        def stop():
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        def check(name, response, expected):
            assert response.status_code == expected, f"{name}: {response.status_code} {response.text}"
            checks.append({"name": name, "status": response.status_code, "expected": expected, "passed": True})
            return response
        def login(role):
            client = httpx.Client(base_url=origin, timeout=15)
            clients.append(client)
            response = check(f"{role} login", client.post("/api/login", headers={"Origin": origin}, json={"username": f"probe_{role}", "password": password}), 200)
            client.headers.update({"Origin": origin, "X-CSRF-Token": response.json()["csrf"]})
            return client
        try:
            start()
            with httpx.Client(base_url=origin) as anon:
                check("anonymous alerts denied", anon.get("/api/alerts"), 401)
                check("anonymous users denied", anon.get("/api/users"), 401)
                check("untrusted host denied", anon.get("/healthz", headers={"Host": "attacker.invalid"}), 400)
                check("cross-origin login denied", anon.post("/api/login", headers={"Origin": "https://attacker.invalid"}, json={"username": "probe_admin", "password": password}), 403)
                check("oversize body denied", anon.post("/api/login", content=b"x" * 131073), 413)
            admin, viewer, ingestor = login("admin"), login("viewer"), login("ingestor")
            check("viewer cannot administer users", viewer.get("/api/users"), 403)
            check("ingestor cannot read alerts", ingestor.get("/api/alerts"), 403)
            check("missing CSRF denied", admin.post("/api/logout", headers={"X-CSRF-Token": ""}), 403)
            check("non-ASCII CSRF denied", admin.post("/api/logout", headers={b"X-CSRF-Token": b"\xff"}), 403)
            rows = generate_scenario(now_ms=now_ms())["transactions"]
            ingest = check("synthetic real-HTTP ingestion", ingestor.post("/api/transactions/batch", json={"transactions": rows}), 200)
            alert_id = ingest.json()["alert_ids"][0]
            assert ingest.json()["accepted"] == len(rows)
            retry = check("exact retry idempotent", ingestor.post("/api/transactions/batch", json={"transactions": rows}), 200)
            assert retry.json()["accepted"] == 0 and retry.json()["duplicates"] == len(rows)
            check("conflicting retry denied", ingestor.post("/api/transactions/batch", json={"transactions": [{**rows[0], "amount_paise": 1}]}), 409)
            detail = check("authorized analyst data available", admin.get(f"/api/alerts/{alert_id}"), 200).json()
            review = {"status": "investigating", "note": "SYNTHETIC independent live security probe", "version": detail["version"]}
            check("viewer review denied", viewer.post(f"/api/alerts/{alert_id}/review", json=review), 403)
            check("admin review persisted", admin.post(f"/api/alerts/{alert_id}/review", json=review), 200)
            check("stale review conflict", admin.post(f"/api/alerts/{alert_id}/review", json=review), 409)
            stop()
            start()
            persisted = check("session and case survive server restart", admin.get(f"/api/alerts/{alert_id}"), 200).json()
            assert persisted["status"] == "investigating" and len(persisted["reviews"]) == 1
            assert admin.get("/api/metrics").json()["transactions"] == len(rows)
            users = admin.get("/api/users").json()["items"]
            viewer_id = next(u["id"] for u in users if u["role"] == "viewer")
            check("admin disables viewer", admin.patch(f"/api/users/{viewer_id}", json={"active": False}), 200)
            check("disabled viewer session denied", viewer.get("/api/me"), 401)
            token = ingestor.cookies["fraudgraph_session"]
            check("logout succeeds", ingestor.post("/api/logout"), 200)
            ingestor.cookies.set("fraudgraph_session", token)
            check("logged-out bearer reuse denied", ingestor.get("/api/me"), 401)
        finally:
            stop()
            for client in clients:
                client.close()
            log.close()
    result = {"scope": "Independent local real-HTTP security probe against a booted Uvicorn process", "data": "Entirely SYNTHETIC generated fixture; no real UPI data", "generated_at_ms": now_ms(), "checks_passed": len(checks), "checks": checks, "limitations": ["Loopback HTTP development configuration; production TLS, reverse proxy, MFA, browser DOM behavior and large-scale abuse are not tested by this probe.", "Assertions abort on first failure; a written report represents all listed checks completing."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"checks_passed": len(checks), "report": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
