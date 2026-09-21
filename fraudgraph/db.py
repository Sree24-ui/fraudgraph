import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer','ingestor')),
 active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts(key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transactions(
 id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL, sender TEXT NOT NULL, receiver TEXT NOT NULL,
 amount_paise INTEGER NOT NULL CHECK(amount_paise>0), provenance TEXT NOT NULL,
 received_at INTEGER NOT NULL, payload_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS tx_sender ON transactions(provenance,sender,occurred_at);
CREATE INDEX IF NOT EXISTS tx_receiver ON transactions(provenance,receiver,occurred_at);
CREATE INDEX IF NOT EXISTS tx_time ON transactions(provenance,occurred_at);
CREATE TABLE IF NOT EXISTS alerts(
 id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, provenance TEXT NOT NULL, rule TEXT NOT NULL,
 score REAL NOT NULL, window_seconds INTEGER NOT NULL, evidence TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open', assigned_to INTEGER REFERENCES users(id),
 version INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 first_event INTEGER NOT NULL, last_event INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alert_account ON alerts(provenance,account_id,last_event);
CREATE TABLE IF NOT EXISTS reviews(
 id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id), user_id INTEGER NOT NULL REFERENCES users(id),
 status TEXT NOT NULL, note TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_revisions(
 alert_id INTEGER NOT NULL REFERENCES alerts(id), version INTEGER NOT NULL, evidence TEXT NOT NULL,
 created_at INTEGER NOT NULL, PRIMARY KEY(alert_id,version));
CREATE TABLE IF NOT EXISTS review_evidence(
 review_id INTEGER PRIMARY KEY REFERENCES reviews(id), alert_version INTEGER NOT NULL, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT,
 detail TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
"""

def now_ms():
    return int(time.time() * 1000)

def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=15000')
    db.execute('PRAGMA synchronous=FULL')
    return db

def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except FileExistsError:
        Path(path).chmod(0o600)
    db = connect(path)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        if db.execute('SELECT version FROM schema_version').fetchone()[0] != 1:
            raise RuntimeError('Unsupported schema version')
    finally:
        db.close()
    Path(path).chmod(0o600)

@contextmanager
def transaction(path):
    db = connect(path)
    try:
        db.execute('BEGIN IMMEDIATE')
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()

def audit(db, actor, action, object_id=None, detail=None):
    db.execute('INSERT INTO audit(actor,action,object_id,detail,created_at) VALUES(?,?,?,?,?)',
               (str(actor), action, str(object_id) if object_id is not None else None,
                json.dumps(detail or {}, sort_keys=True), now_ms()))
