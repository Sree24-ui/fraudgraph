"""Independent abuse-case tests, added by the security reviewer.

Fixtures and payloads are synthetic. These tests prove only the checked behavior,
not general production security or accuracy on real UPI transactions.
"""
import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from fraudgraph.db import connect, initialize, now_ms
from fraudgraph.security import PASSWORDS, Settings

PASSWORD = "Only-a-synthetic-test-password-287!"
ORIGIN = "http://testserver"


@pytest.fixture
def review_system(tmp_path):
    from fraudgraph.app import create_app
    path = tmp_path / "review.sqlite3"
    initialize(path)
    hashed = PASSWORDS.hash(PASSWORD)
    db = connect(path)
    try:
        for role in ("admin", "analyst", "viewer", "ingestor"):
            db.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                (f"review_{role}", hashed, role, now_ms()),
            )
        db.commit()
    finally:
        db.close()
    app = create_app(Settings(db_path=str(path), environment="development", origin=ORIGIN))
    clients = []

    def login(role):
        client = TestClient(app)
        clients.append(client)
        response = client.post("/api/login", json={"username": f"review_{role}", "password": PASSWORD}, headers={"Origin": ORIGIN})
        assert response.status_code == 200, response.text
        identity = client.get("/api/me")
        assert identity.status_code == 200, identity.text
        client.headers.update({"Origin": ORIGIN, "X-CSRF-Token": identity.json()["csrf"]})
        return client

    yield {"app": app, "path": path, "login": login}
    for client in clients:
        client.close()


def event(**overrides):
    value = {"id": "review-tx-1", "occurred_at": now_ms(), "sender": "source@synthetic", "receiver": "recipient@synthetic", "amount_paise": 10000, "provenance": "synthetic"}
    value.update(overrides)
    return value


def count_rows(path, table):
    assert table in {"transactions", "alerts", "audit", "users", "sessions"}
    db = connect(path)
    try:
        return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        db.close()


@pytest.mark.parametrize("value", [True, False, 1.5, "100", 0, -1, 100000000001])
def test_rejects_noncanonical_money(review_system, value):
    client = review_system["login"]("ingestor")
    response = client.post("/api/transactions/batch", json={"transactions": [event(amount_paise=value)]})
    assert response.status_code == 422, response.text
    assert count_rows(review_system["path"], "transactions") == 0


@pytest.mark.parametrize("changes", [
    {"sender": "source@synthetic", "receiver": "source@synthetic"},
    {"id": "x'; DROP TABLE users; --"},
    {"sender": "<img src=x onerror=alert(1)>"},
    {"occurred_at": True},
    {"occurred_at": "123"},
    {"occurred_at": -1},
    {"provenance": "unspecified"},
    {"unexpected": "should not be silently ignored"},
])
def test_rejects_malformed_ingestion_without_effect(review_system, changes):
    client = review_system["login"]("ingestor")
    response = client.post("/api/transactions/batch", json={"transactions": [event(**changes)]})
    assert response.status_code == 422, response.text
    assert count_rows(review_system["path"], "transactions") == 0


def test_batch_limit(review_system):
    client = review_system["login"]("ingestor")
    response = client.post("/api/transactions/batch", json={"transactions": [event(id=f"limited-{i}") for i in range(101)]})
    assert response.status_code == 422, response.text
    assert count_rows(review_system["path"], "transactions") == 0


def test_fresh_database_and_wal_permissions(tmp_path):
    path = tmp_path / "permission.sqlite3"
    initialize(path)
    db = connect(path)
    try:
        db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", ("permission-user", "not-a-real-hash", "viewer", 0))
        db.commit()
        for file in tmp_path.glob("permission.sqlite3*"):
            assert file.stat().st_mode & 0o077 == 0, f"{file.name} exposes group/other permissions"
    finally:
        db.close()


def test_old_event_in_same_batch_cannot_hide_later_complete_motif(review_system):
    from fraudgraph.synthetic import generate_scenario
    now = now_ms()
    rows = generate_scenario(now_ms=now)["transactions"]
    old = {**rows[0], "id": "review-old-event", "sender": "synthetic:old-source", "occurred_at": now - 10_800_000}
    client = review_system["login"]("ingestor")
    response = client.post("/api/transactions/batch", json={"transactions": [old, *rows]})
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == len(rows) + 1
    assert response.json()["alert_ids"], "Mixed-time batch silently omitted a fresh complete motif"


def test_anonymous_cannot_enumerate_data_or_mutate(review_system):
    with TestClient(review_system["app"]) as client:
        for path in ["/api/me", "/api/config", "/api/metrics", "/api/alerts", "/api/alerts/1", "/api/users", "/api/audit", "/api/demo/scenarios"]:
            response = client.get(path)
            assert response.status_code == 401, (path, response.text)
        mutations = [
            ("post", "/api/transactions/batch", {"transactions": [event()]}),
            ("post", "/api/alerts/1/review", {"status": "dismissed", "note": "Unauthorized", "version": 1}),
            ("post", "/api/users", {"username": "attacker", "password": PASSWORD, "role": "admin"}),
            ("patch", "/api/users/1", {"active": False}),
            ("post", "/api/logout", {}),
        ]
        for method, path, body in mutations:
            response = client.request(method, path, json=body, headers={"Origin": ORIGIN})
            assert response.status_code == 401, (path, response.text)
    assert count_rows(review_system["path"], "transactions") == 0
    assert count_rows(review_system["path"], "users") == 4


def test_role_route_matrix_and_denied_writes(review_system):
    for role in ("admin", "analyst", "viewer", "ingestor"):
        client = review_system["login"](role)
        for path in ["/api/config", "/api/metrics", "/api/alerts"]:
            response = client.get(path)
            assert response.status_code == (403 if role == "ingestor" else 200), (role, path, response.text)
        for path in ["/api/users", "/api/audit", "/api/demo/scenarios"]:
            response = client.get(path)
            assert response.status_code == (200 if role == "admin" else 403), (role, path, response.text)
        if role != "admin":
            response = client.post("/api/users", json={"username": f"escalation_{role}", "password": PASSWORD, "role": "admin"})
            assert response.status_code == 403, response.text
            response = client.patch("/api/users/1", json={"active": False})
            assert response.status_code == 403, response.text
        response = client.post("/api/transactions/batch", json={"transactions": [event(id=f"rbac-{role}")]})
        assert response.status_code == (200 if role in {"admin", "ingestor"} else 403), (role, response.text)
        response = client.post("/api/alerts/987654/review", json={"status": "dismissed", "note": "Unauthorized attempt", "version": 1})
        assert response.status_code == (404 if role in {"admin", "analyst"} else 403), (role, response.text)
    assert count_rows(review_system["path"], "transactions") == 2
    assert count_rows(review_system["path"], "users") == 4


def test_csrf_origin_and_other_session_token_cannot_mutate(review_system):
    client = review_system["login"]("admin")
    other = review_system["login"]("analyst")
    cases = [
        {"Origin": ORIGIN, "X-CSRF-Token": ""},
        {"Origin": ORIGIN, "X-CSRF-Token": "incorrect"},
        {"Origin": ORIGIN, "X-CSRF-Token": other.headers["X-CSRF-Token"]},
        {"Origin": "https://attacker.invalid", "X-CSRF-Token": client.headers["X-CSRF-Token"]},
        {"Origin": ORIGIN + ".attacker.invalid", "X-CSRF-Token": client.headers["X-CSRF-Token"]},
        {"Origin": "null", "X-CSRF-Token": client.headers["X-CSRF-Token"]},
        {"Origin": "", "X-CSRF-Token": client.headers["X-CSRF-Token"]},
    ]
    for headers in cases:
        response = client.post("/api/transactions/batch", json={"transactions": [event()]}, headers=headers)
        assert response.status_code == 403, (headers["Origin"], response.text)
    assert count_rows(review_system["path"], "transactions") == 0


def test_login_rejects_cross_origin_and_wrong_credentials(review_system):
    with TestClient(review_system["app"]) as client:
        for origin in [None, "null", "https://attacker.invalid", ORIGIN + ".attacker.invalid"]:
            response = client.post("/api/login", json={"username": "review_admin", "password": PASSWORD}, headers={} if origin is None else {"Origin": origin})
            assert response.status_code == 403
            assert "fraudgraph_session" not in client.cookies
        bodies = []
        for username in ["review_admin", "not_a_user"]:
            response = client.post("/api/login", json={"username": username, "password": "definitely_wrong"}, headers={"Origin": ORIGIN})
            assert response.status_code == 401
            bodies.append(response.json())
            assert "fraudgraph_session" not in client.cookies
        assert bodies[0] == bodies[1]


def test_login_throttle_ignores_spoofed_forwarded_headers(review_system):
    with TestClient(review_system["app"]) as client:
        results = []
        for i in range(11):
            response = client.post("/api/login", json={"username": f"no_user_{i}", "password": "incorrect"}, headers={"Origin": ORIGIN, "X-Forwarded-For": f"192.0.2.{i + 1}"})
            results.append(response.status_code)
        assert results[:10] == [401] * 10
        assert results[10] == 429
        assert response.headers.get("retry-after") == "900"
        assert count_rows(review_system["path"], "sessions") == 0


def test_session_is_hashed_and_revoked_after_logout(review_system):
    client = review_system["login"]("viewer")
    token = client.cookies["fraudgraph_session"]
    assert len(token) >= 32
    db = connect(review_system["path"])
    try:
        row = db.execute("SELECT token_hash FROM sessions").fetchone()
        assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in str(dict(row))
    finally:
        db.close()
    response = client.post("/api/logout")
    assert response.status_code == 200
    client.cookies.set("fraudgraph_session", token)
    assert client.get("/api/me").status_code == 401
    assert count_rows(review_system["path"], "sessions") == 0


def test_expired_and_tampered_session_denied(review_system):
    client = review_system["login"]("viewer")
    original = client.cookies["fraudgraph_session"]
    client.cookies.clear()
    client.cookies.set("fraudgraph_session", original[:-1] + ("a" if original[-1] != "a" else "b"))
    assert client.get("/api/me").status_code == 401
    client.cookies.clear()
    client.cookies.set("fraudgraph_session", original)
    db = connect(review_system["path"])
    try:
        db.execute("UPDATE sessions SET expires_at=?", (now_ms() - 1,))
        db.commit()
    finally:
        db.close()
    assert client.get("/api/me").status_code == 401


def test_disabling_user_revokes_active_session_and_login(review_system):
    admin = review_system["login"]("admin")
    viewer = review_system["login"]("viewer")
    users = admin.get("/api/users").json()["items"]
    user_id = next(u["id"] for u in users if u["role"] == "viewer")
    response = admin.patch(f"/api/users/{user_id}", json={"active": False})
    assert response.status_code == 200, response.text
    assert viewer.get("/api/me").status_code == 401
    response = viewer.post("/api/login", json={"username": "review_viewer", "password": PASSWORD})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}


def test_password_change_requires_current_secret_and_revokes_all_sessions(review_system):
    first = review_system["login"]("viewer")
    second = review_system["login"]("viewer")
    response = first.post("/api/password", json={"current_password": "wrong", "new_password": PASSWORD + "new"})
    assert response.status_code == 401
    assert second.get("/api/me").status_code == 200
    response = first.post("/api/password", json={"current_password": PASSWORD, "new_password": PASSWORD + "new"})
    assert response.status_code == 200, response.text
    assert second.get("/api/me").status_code == 401
    assert count_rows(review_system["path"], "sessions") == 0


def test_retries_conflicts_and_mid_batch_conflict_are_atomic(review_system):
    client = review_system["login"]("ingestor")
    row = event()
    first = client.post("/api/transactions/batch", json={"transactions": [row]})
    assert first.status_code == 200
    retry = client.post("/api/transactions/batch", json={"transactions": [row]})
    assert retry.status_code == 200
    assert retry.json()["accepted"] == 0 and retry.json()["duplicates"] == 1
    conflict = client.post("/api/transactions/batch", json={"transactions": [event(id="must-roll-back"), {**row, "amount_paise": row["amount_paise"] + 1}]})
    assert conflict.status_code == 409, conflict.text
    assert count_rows(review_system["path"], "transactions") == 1
    same_batch = client.post("/api/transactions/batch", json={"transactions": [event(id="same-batch"), event(id="same-batch", amount_paise=456)]})
    assert same_batch.status_code == 409
    assert count_rows(review_system["path"], "transactions") == 1


def test_injected_audit_failure_rolls_back_ingestion(review_system, monkeypatch):
    import fraudgraph.service as service
    client = review_system["login"]("ingestor")
    before_audit = count_rows(review_system["path"], "audit")
    def fail_audit(*args, **kwargs):
        raise sqlite3.OperationalError("forced isolated review failure")
    monkeypatch.setattr(service, "audit", fail_audit)
    response = client.post("/api/transactions/batch", json={"transactions": [event()]})
    assert response.status_code == 503, response.text
    assert "forced isolated" not in response.text
    assert count_rows(review_system["path"], "transactions") == 0
    assert count_rows(review_system["path"], "alerts") == 0
    assert count_rows(review_system["path"], "audit") == before_audit


def test_future_poison_rejected_and_batch_rolled_back(review_system):
    client = review_system["login"]("ingestor")
    response = client.post("/api/transactions/batch", json={"transactions": [event(id="valid-then-poison"), event(id="future", occurred_at=now_ms() + 10_000_000)]})
    assert response.status_code == 422, response.text
    assert count_rows(review_system["path"], "transactions") == 0


def test_bounded_body_and_query_and_no_sensitive_static_paths(review_system):
    client = review_system["login"]("viewer")
    response = client.post("/api/login", content=b"x" * 131073, headers={"Content-Type": "application/json"})
    assert response.status_code == 413, response.text
    for path in ["/api/alerts?limit=101", "/api/alerts?offset=-1", "/api/metrics?provenance=invalid"]:
        assert client.get(path).status_code == 422
    for path in ["/docs", "/openapi.json", "/static/../fraudgraph.sqlite3", "/static/%2e%2e/db.py", "/static/%2e%2e/%2e%2e/data/fraudgraph.sqlite3"]:
        response = client.get(path)
        assert response.status_code == 404, (path, response.text)
    response = client.get("/api/me")
    assert response.headers["cache-control"] == "no-store"
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_untrusted_host_rejected(review_system):
    with TestClient(review_system["app"]) as client:
        response = client.get("/healthz", headers={"Host": "attacker.invalid"})
        assert response.status_code == 400


def test_sql_metacharacters_are_literal_search(review_system):
    client = review_system["login"]("viewer")
    response = client.get("/api/alerts", params={"q": "' OR 1=1; DROP TABLE users;--"})
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 0
    assert count_rows(review_system["path"], "users") == 4


def test_non_ascii_csrf_rejected_without_server_error(review_system):
    client = review_system["login"]("viewer")
    response = client.post("/api/logout", headers={b"Origin": ORIGIN.encode(), b"X-CSRF-Token": b"\xff"})
    assert response.status_code == 403, response.text
    assert client.get("/api/me").status_code == 200


def test_production_cookie_headers_and_demo_disabled(review_system):
    from fraudgraph.app import create_app
    origin = "https://testserver"
    app = create_app(Settings(db_path=str(review_system["path"]), environment="production", origin=origin))
    with TestClient(app, base_url=origin) as client:
        response = client.post("/api/login", json={"username": "review_admin", "password": PASSWORD}, headers={"Origin": origin})
        assert response.status_code == 200, response.text
        cookie = response.headers["set-cookie"].lower()
        for attribute in ["httponly", "secure", "samesite=strict", "path=/", "max-age=28800"]:
            assert attribute in cookie
        assert "domain=" not in cookie
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        response = client.post("/api/demo/fan_in_fan_out", headers={"Origin": origin, "X-CSRF-Token": response.json()["csrf"]})
        assert response.status_code == 404
        assert count_rows(review_system["path"], "transactions") == 0


def test_cross_provenance_fragments_do_not_complete_one_motif(review_system):
    from fraudgraph.synthetic import generate_scenario
    rows = generate_scenario(now_ms=now_ms())["transactions"]
    for row in rows:
        if row["sender"] == "synthetic:mule":
            row["provenance"] = "external_synthetic"
    client = review_system["login"]("ingestor")
    response = client.post("/api/transactions/batch", json={"transactions": rows})
    assert response.status_code == 200, response.text
    assert response.json()["alert_ids"] == []
    assert count_rows(review_system["path"], "transactions") == len(rows)


def test_conflicting_analyst_decision_keeps_first_audited_review(review_system):
    from fraudgraph.synthetic import generate_scenario
    admin = review_system["login"]("admin")
    reader = review_system["login"]("analyst")
    response = admin.post("/api/transactions/batch", json={"transactions": generate_scenario(now_ms=now_ms())["transactions"]})
    assert response.status_code == 200, response.text
    alert_id = response.json()["alert_ids"][0]
    before = reader.get(f"/api/alerts/{alert_id}").json()
    payload = {"status": "investigating", "note": "Synthetic review with <script>alert(1)</script> kept literal", "version": before["version"]}
    first = reader.post(f"/api/alerts/{alert_id}/review", json=payload)
    assert first.status_code == 200, first.text
    stale = admin.post(f"/api/alerts/{alert_id}/review", json={**payload, "status": "dismissed", "note": "Stale review must fail"})
    assert stale.status_code == 409
    after = reader.get(f"/api/alerts/{alert_id}").json()
    assert after["status"] == "investigating"
    assert after["version"] == before["version"] + 1
    assert len(after["reviews"]) == 1
    assert after["reviews"][0]["note"] == payload["note"]


def test_successful_logins_do_not_consume_failed_peer_budget(review_system):
    with TestClient(review_system["app"]) as client:
        for _ in range(12):
            response = client.post("/api/login", json={"username": "review_viewer", "password": PASSWORD}, headers={"Origin": ORIGIN})
            assert response.status_code == 200, response.text


def test_concurrent_admin_deactivation_keeps_an_active_admin(review_system, monkeypatch):
    """Both requests authenticate first; serialization must recheck authority."""
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from threading import Barrier
    import fraudgraph.app as app_module

    first = review_system["login"]("admin")
    response = first.post("/api/users", json={"username": "review_second_admin", "password": PASSWORD, "role": "admin"})
    assert response.status_code == 201, response.text
    with TestClient(review_system["app"]) as second:
        response = second.post("/api/login", json={"username": "review_second_admin", "password": PASSWORD}, headers={"Origin": ORIGIN})
        assert response.status_code == 200, response.text
        second.headers.update({"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf"]})
        users = first.get("/api/users").json()["items"]
        first_id = next(user["id"] for user in users if user["username"] == "review_admin")
        second_id = next(user["id"] for user in users if user["username"] == "review_second_admin")
        barrier = Barrier(2)
        original_transaction = app_module.transaction

        @contextmanager
        def synchronized_transaction(path):
            barrier.wait(timeout=5)
            with original_transaction(path) as db:
                yield db

        monkeypatch.setattr(app_module, "transaction", synchronized_transaction)
        with ThreadPoolExecutor(max_workers=2) as executor:
            attempts = [
                executor.submit(first.patch, f"/api/users/{second_id}", json={"active": False}),
                executor.submit(second.patch, f"/api/users/{first_id}", json={"active": False}),
            ]
            statuses = [attempt.result(timeout=10).status_code for attempt in attempts]
        assert statuses.count(200) == 1, statuses
        assert sum(status in {401, 403, 409} for status in statuses) == 1, statuses
        db = connect(review_system["path"])
        try:
            assert db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] == 1
        finally:
            db.close()


def test_ingestion_rechecks_session_after_waiting_for_write_lock(review_system, monkeypatch):
    """Deactivation after request authentication must prevent a later commit."""
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from threading import Event
    import fraudgraph.service as service

    admin = review_system["login"]("admin")
    ingestor = review_system["login"]("ingestor")
    users = admin.get("/api/users").json()["items"]
    ingestor_id = next(user["id"] for user in users if user["role"] == "ingestor")
    waiting, release = Event(), Event()
    original_transaction = service.transaction

    @contextmanager
    def blocked_transaction(path):
        waiting.set()
        assert release.wait(timeout=10), "Review synchronization was not released"
        with original_transaction(path) as db:
            yield db

    monkeypatch.setattr(service, "transaction", blocked_transaction)
    with ThreadPoolExecutor(max_workers=1) as executor:
        attempt = executor.submit(ingestor.post, "/api/transactions/batch", json={"transactions": [event()]})
        try:
            assert waiting.wait(timeout=5), "Ingestion did not reach write transaction"
            disabled = admin.patch(f"/api/users/{ingestor_id}", json={"active": False})
            assert disabled.status_code == 200, disabled.text
        finally:
            release.set()
        response = attempt.result(timeout=10)
    assert response.status_code == 401, response.text
    assert count_rows(review_system["path"], "transactions") == 0
    assert count_rows(review_system["path"], "alerts") == 0


def test_inflight_old_password_login_rejected_after_password_change(review_system, monkeypatch):
    """Password rotation must not allow an already-verifying old login to commit."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock
    import fraudgraph.app as app_module

    existing = review_system["login"]("viewer")
    verified, release = Event(), Event()
    guard = Lock()
    claimed = False
    original_verify = app_module.verify_password

    def paused_first_verification(stored, supplied):
        nonlocal claimed
        result = original_verify(stored, supplied)
        with guard:
            pause = not claimed
            claimed = True
        if pause:
            verified.set()
            assert release.wait(timeout=10), "Review synchronization was not released"
        return result

    monkeypatch.setattr(app_module, "verify_password", paused_first_verification)
    with TestClient(review_system["app"]) as anonymous:
        with ThreadPoolExecutor(max_workers=1) as executor:
            attempt = executor.submit(anonymous.post, "/api/login", json={"username": "review_viewer", "password": PASSWORD}, headers={"Origin": ORIGIN})
            try:
                assert verified.wait(timeout=5), "Old login did not finish password verification"
                changed = existing.post("/api/password", json={"current_password": PASSWORD, "new_password": PASSWORD + "rotated"})
                assert changed.status_code == 200, changed.text
            finally:
                release.set()
            response = attempt.result(timeout=10)
        assert response.status_code == 401, response.text
        assert "fraudgraph_session" not in anonymous.cookies
    assert count_rows(review_system["path"], "sessions") == 0
