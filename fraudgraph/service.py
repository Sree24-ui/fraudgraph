"""Atomic ingestion; the durable ledger is also the source for detector replay."""
import hashlib
import json
import time

from fastapi import HTTPException
from .db import audit, now_ms, transaction
from .detector import detect_account, DETECTOR_VERSION
from .security import assert_session

MAX_WINDOW_MS = 7_200_000
MAX_LATENESS_MS = 86_400_000
MAX_ACCOUNT_EVENTS = 10_000

def ingest(settings, records, actor, auth_context=None):
    started = time.perf_counter()
    accepted, duplicates, changed = 0, 0, set()
    received = now_ms()
    with transaction(settings.db_path) as db:
        if auth_context is not None:
            assert_session(db, auth_context, {'admin','ingestor'})
        # Validate and store whole batch before evaluating; any failure rolls it all back.
        affected = {}
        watermarks = {r[0]: r[1] for r in db.execute('SELECT provenance, MAX(occurred_at) FROM transactions GROUP BY provenance')}
        for record in records:
            tx = record.model_dump() if hasattr(record, 'model_dump') else record
            encoded = json.dumps(tx, sort_keys=True, separators=(',', ':'))
            fingerprint = hashlib.sha256(encoded.encode()).hexdigest()
            existing = db.execute('SELECT payload_hash FROM transactions WHERE id=?', (tx['id'],)).fetchone()
            if existing:
                if existing['payload_hash'] != fingerprint:
                    raise HTTPException(409, 'Transaction ID already exists with a different payload; batch rolled back')
                duplicates += 1
                continue
            if tx['occurred_at'] > received + 300_000:
                raise HTTPException(422, 'Future timestamp exceeds five-minute clock tolerance; batch rolled back')
            mark = watermarks.get(tx['provenance'], tx['occurred_at'])
            if tx['occurred_at'] < mark - MAX_LATENESS_MS:
                raise HTTPException(422, 'Event is over 24 hours behind its data-source watermark; use offline evaluation')
            db.execute('INSERT INTO transactions VALUES(?,?,?,?,?,?,?,?)',
                       (tx['id'],tx['occurred_at'],tx['sender'],tx['receiver'],tx['amount_paise'],tx['provenance'],received,fingerprint))
            accepted += 1
            for account in (tx['sender'], tx['receiver']):
                key = (tx['provenance'], account)
                bounds = affected.get(key, (tx['occurred_at'],tx['occurred_at']))
                affected[key] = (min(bounds[0],tx['occurred_at']),max(bounds[1],tx['occurred_at']))
        # Re-evaluate subsequent endpoints too: late arrivals can complete historical motifs.
        for (provenance, account), (earliest, latest) in sorted(affected.items()):
            events = [dict(r) for r in db.execute('''SELECT id,occurred_at,sender,receiver,amount_paise,provenance
                FROM transactions WHERE provenance=? AND (sender=? OR receiver=?) AND occurred_at>=? AND occurred_at<=?
                ORDER BY occurred_at,id LIMIT ?''',
                (provenance, account, account, earliest-MAX_WINDOW_MS, latest+MAX_WINDOW_MS, MAX_ACCOUNT_EVENTS+1))]
            if len(events) > MAX_ACCOUNT_EVENTS:
                raise HTTPException(429, 'Account event budget exceeded; batch rolled back. Retry after operator review')
            endpoints = sorted({e['occurred_at'] for e in events if e['occurred_at'] >= earliest})
            # Explicit work budget, no silent sampling or truncation of detection.
            if len(endpoints)*len(events) > 2_000_000:
                raise HTTPException(429, 'Replay work budget exceeded; batch rolled back. Use smaller batches or offline evaluation')
            for endpoint in endpoints:
                candidates = detect_account(account, events, endpoint)
                if not candidates:
                    continue
                candidate = max(candidates, key=lambda c: (c['score'], -c['window_seconds']))
                evidence = dict(candidate['evidence'])
                evidence['detector_version'] = DETECTOR_VERSION
                ids = evidence['transaction_ids']
                selected = [e for e in events if e['id'] in set(ids)]
                first = min(e['occurred_at'] for e in selected)
                last = max(e['occurred_at'] for e in selected)
                old = db.execute('SELECT * FROM alerts WHERE account_id=? AND provenance=? AND last_event>=? AND first_event<=? ORDER BY id DESC LIMIT 1',
                                 (account,provenance,first-MAX_WINDOW_MS,last+MAX_WINDOW_MS)).fetchone()
                if old:
                    old_ids = set(json.loads(old['evidence'])['transaction_ids'])
                    if set(ids) <= old_ids:
                        continue
                    db.execute('INSERT OR IGNORE INTO evidence_revisions VALUES(?,?,?,?)',
                               (old['id'],old['version'],old['evidence'],received))
                    # New evidence reopens resolved cases; preserve every analyst action in reviews.
                    status = 'open' if old['status'] in {'dismissed','escalated'} else old['status']
                    db.execute('''UPDATE alerts SET score=?,window_seconds=?,evidence=?,updated_at=?,
                        first_event=MIN(first_event,?),last_event=MAX(last_event,?),version=version+1,status=? WHERE id=?''',
                        (candidate['score'],candidate['window_seconds'],json.dumps(evidence),received,first,last,status,old['id']))
                    changed.add(old['id'])
                    audit(db, actor, 'alert.evidence_updated', old['id'], {'status': status,'detector_version':DETECTOR_VERSION})
                else:
                    cursor = db.execute('''INSERT INTO alerts(account_id,provenance,rule,score,window_seconds,evidence,created_at,updated_at,first_event,last_event)
                        VALUES(?,?,?,?,?,?,?,?,?,?)''', (account,provenance,candidate['rule'],candidate['score'],candidate['window_seconds'],json.dumps(evidence),received,received,first,last))
                    changed.add(cursor.lastrowid)
                    audit(db, actor, 'alert.created', cursor.lastrowid, {'detector_version':DETECTOR_VERSION})
        audit(db, actor, 'transactions.ingested', detail={'accepted':accepted,'duplicates':duplicates,'alert_ids':sorted(changed)})
    return {'accepted':accepted,'duplicates':duplicates,'alert_ids':sorted(changed),
            'processing_ms':round((time.perf_counter()-started)*1000,3),'detector_version':DETECTOR_VERSION}
