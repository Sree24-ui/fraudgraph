"""Check that a later motif cannot rewrite evidence an analyst already reviewed."""

import json
import secrets

from fastapi.testclient import TestClient

from fraudgraph.app import create_app
from fraudgraph.db import connect, initialize, now_ms
from fraudgraph.security import PASSWORDS, Settings
from fraudgraph.synthetic import generate_scenario


def test_review_evidence_and_prior_revisions_survive_new_pattern(tmp_path):
    path = tmp_path / "synthetic-evidence.sqlite3"
    initialize(path)
    password = secrets.token_urlsafe(24)
    db = connect(path)
    try:
        db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                   ("evidence_admin", PASSWORDS.hash(password), "admin", now_ms()))
        db.commit()
    finally:
        db.close()
    origin = "http://testserver"
    app = create_app(Settings(db_path=str(path), environment="development", origin=origin))
    timestamp = now_ms() - 600_000
    first_rows = generate_scenario(now_ms=timestamp, seed=71)["transactions"]
    with TestClient(app, base_url=origin) as client:
        login = client.post("/api/login", headers={"Origin": origin},
                            json={"username": "evidence_admin", "password": password})
        assert login.status_code == 200, login.text
        client.headers.update({"Origin": origin, "X-CSRF-Token": login.json()["csrf"]})
        initial = client.post("/api/transactions/batch", json={"transactions": first_rows})
        assert initial.status_code == 200, initial.text
        alert_id = initial.json()["alert_ids"][0]
        before = client.get(f"/api/alerts/{alert_id}").json()
        reviewed_evidence = before["evidence"]
        reviewed_version = before["version"]
        review = client.post(f"/api/alerts/{alert_id}/review", json={
            "status": "dismissed", "note": "SYNTHETIC evidence history test; initial snapshot reviewed.",
            "version": reviewed_version,
        })
        assert review.status_code == 200, review.text
        original_review = client.get(f"/api/alerts/{alert_id}").json()["reviews"][0]
        assert original_review["evidence"] == reviewed_evidence
        assert original_review["alert_version"] == reviewed_version
        second_rows = generate_scenario(now_ms=timestamp + 300_000, seed=72)["transactions"]
        # Same hub, fresh counterparties, temporally nearby: expands this case.
        second_rows = [{**row,
                        "sender": row["sender"] if row["sender"] == "synthetic:mule" else row["sender"] + ":second",
                        "receiver": row["receiver"] if row["receiver"] == "synthetic:mule" else row["receiver"] + ":second"}
                       for row in second_rows]
        changed = client.post("/api/transactions/batch", json={"transactions": second_rows})
        assert changed.status_code == 200, changed.text
        assert changed.json()["alert_ids"] == [alert_id]
        after = client.get(f"/api/alerts/{alert_id}").json()
        assert after["status"] == "open"
        assert after["version"] > review.json()["version"]
        assert after["evidence"] != reviewed_evidence
        assert after["reviews"] == [original_review]
        assert set(reviewed_evidence["transaction_ids"]).issubset(after["evidence"]["transaction_ids"])
        revisions_response = client.get(f"/api/alerts/{alert_id}/revisions")
        assert revisions_response.status_code == 200, revisions_response.text
        revisions = revisions_response.json()["items"]
        assert any(item["evidence"] == reviewed_evidence for item in revisions)
        assert all(item["version"] < after["version"] for item in revisions)
        db = connect(path)
        try:
            stored = db.execute("SELECT alert_version,evidence FROM review_evidence").fetchall()
        finally:
            db.close()
        assert len(stored) == 1
        assert stored[0]["alert_version"] == reviewed_version
        assert json.loads(stored[0]["evidence"]) == reviewed_evidence
        # Anonymous history access must not reveal the snapshot.
        client.cookies.clear()
        assert client.get(f"/api/alerts/{alert_id}/revisions").status_code == 401
