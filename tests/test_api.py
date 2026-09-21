from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
import json
from fastapi.testclient import TestClient
import pytest
from fraudgraph.app import create_app
from fraudgraph.security import Settings, PASSWORDS
from fraudgraph.db import transaction, now_ms, connect
from fraudgraph.synthetic import generate_scenario

ORIGIN='http://testserver'

@pytest.fixture
def system(tmp_path):
    settings=Settings(db_path=str(tmp_path/'test.sqlite3'),environment='development',origin=ORIGIN)
    app=create_app(settings)
    with transaction(settings.db_path) as db:
        for role in ['admin','analyst','viewer','ingestor']:
            db.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(role,PASSWORDS.hash('safe-test-password-only'),role,now_ms()))
    return app,settings

def login(app,role='admin'):
    client=TestClient(app)
    r=client.post('/api/login',json={'username':role,'password':'safe-test-password-only'},headers={'Origin':ORIGIN})
    assert r.status_code==200,r.text
    client.headers.update({'Origin':ORIGIN,'X-CSRF-Token':r.json()['csrf']})
    return client

def sample():
    return generate_scenario('fan_in_fan_out',now_ms=now_ms()-1000)['transactions']

def test_real_ingestion_idempotency_atomic_conflict_and_review(system):
    app,settings=system
    client=login(app)
    txs=sample()
    first=client.post('/api/transactions/batch',json={'transactions':txs})
    assert first.status_code==200,first.text
    assert first.json()['accepted']==len(txs)
    assert first.json()['alert_ids']
    again=client.post('/api/transactions/batch',json={'transactions':txs})
    assert again.json()['accepted']==0 and again.json()['duplicates']==len(txs)
    conflict=dict(txs[0],amount_paise=3)
    new=dict(txs[0],id='new-rollback')
    assert client.post('/api/transactions/batch',json={'transactions':[new,conflict]}).status_code==409
    assert client.get('/api/metrics').json()['transactions']==len(txs)
    alert_id=first.json()['alert_ids'][0]
    detail=client.get(f'/api/alerts/{alert_id}').json()
    assert detail['transactions'] and detail['provenance']=='synthetic'
    reviewer=login(app,'analyst')
    body={'status':'investigating','note':'Check linked counterparties','version':detail['version']}
    assert reviewer.post(f'/api/alerts/{alert_id}/review',json=body).status_code==200
    assert reviewer.post(f'/api/alerts/{alert_id}/review',json=body).status_code==409
    assert client.get(f'/api/alerts/{alert_id}').json()['reviews'][0]['note']==body['note']
    restarted=login(create_app(settings))
    assert restarted.get('/api/metrics').json()['transactions']==len(txs)
    assert restarted.get(f'/api/alerts/{alert_id}').json()['status']=='investigating'

def test_late_arrival_replays_later_payouts(system):
    app,_=system; c=login(app); txs=sample()
    # Reverse arrival order, one event per batch. Historic inflows complete a stored pattern.
    ids=set()
    for tx in reversed(txs):
        r=c.post('/api/transactions/batch',json={'transactions':[tx]})
        assert r.status_code==200,r.text
        ids.update(r.json()['alert_ids'])
    assert ids

def test_multihour_batch_evaluates_recent_motif(system):
    app,_=system; c=login(app); txs=sample()
    hub=txs[0]['receiver']
    old={'id':'old','occurred_at':min(t['occurred_at'] for t in txs)-10_800_000,'sender':'old-source','receiver':hub,'amount_paise':1,'provenance':'synthetic'}
    r=c.post('/api/transactions/batch',json={'transactions':[old,*txs]})
    assert r.status_code==200,r.text
    assert r.json()['alert_ids']

def test_source_partition_prevents_synthetic_real_mixing(system):
    app,_=system;c=login(app);txs=sample()
    hub=txs[0]['receiver']
    for tx in txs:
        if tx['sender']==hub:
            tx['provenance']='real'
    r=c.post('/api/transactions/batch',json={'transactions':txs})
    assert r.status_code==200 and r.json()['alert_ids']==[]

def test_concurrent_retries_exactly_one_ledger_copy(system):
    app,_=system;c=login(app);txs=sample()
    def call(_):
        return c.post('/api/transactions/batch',json={'transactions':txs})
    with ThreadPoolExecutor(max_workers=4) as executor:
        results=list(executor.map(call,range(4)))
    assert all(r.status_code==200 for r in results),[r.text for r in results]
    assert sum(r.json()['accepted'] for r in results)==len(txs)
    assert c.get('/api/metrics').json()['transactions']==len(txs)

def test_production_replay_disabled_and_secure_cookie(tmp_path):
    settings=Settings(str(tmp_path/'prod.db'),'production','https://testserver')
    app=create_app(settings)
    with transaction(settings.db_path) as db:
        db.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',('admin',PASSWORDS.hash('safe-test-password-only'),'admin',now_ms()))
    c=TestClient(app,base_url='https://testserver')
    r=c.post('/api/login',json={'username':'admin','password':'safe-test-password-only'},headers={'Origin':'https://testserver'})
    assert r.status_code==200
    cookie=SimpleCookie(r.headers['set-cookie'])['fraudgraph_session']
    assert cookie['secure'] and cookie['httponly'] and cookie['samesite']=='strict'
    c.headers.update({'Origin':'https://testserver','X-CSRF-Token':r.json()['csrf']})
    assert c.post('/api/demo/fan_in_fan_out').status_code==404
