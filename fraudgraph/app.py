import json
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .db import initialize, connect, transaction, audit, now_ms
from .security import Settings, PASSWORDS, DUMMY_HASH, verify_password, digest, assert_session
from .models import Login, UserCreate, UserUpdate, Batch, Review, PasswordChange
from .service import ingest
from .detector import detector_config

STATIC = Path(__file__).parent / 'static'
COOKIE = 'fraudgraph_session'

class BodyLimit:
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > self.limit:
                return await JSONResponse({'detail':'Request body too large'}, status_code=413)(scope, receive, send)
            chunks.append(message.get('body', b''))
            if not message.get('more_body'):
                break
        supplied = False
        async def replay():
            nonlocal supplied
            if supplied:
                return await receive()
            supplied = True
            return {'type':'http.request','body':b''.join(chunks),'more_body':False}
        await self.app(scope, replay, send)

def create_app(settings=None):
    settings = settings or Settings.from_env()
    initialize(settings.db_path)
    app = FastAPI(title='FraudGraph', version='0.1.0', docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.add_middleware(BodyLimit, limit=settings.max_body_bytes)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[urlparse(settings.origin).hostname])

    @app.middleware('http')
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        if settings.secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.exception_handler(sqlite3.OperationalError)
    async def db_failure(request, exc):
        return JSONResponse({'detail':'Storage temporarily unavailable; retry with the same transaction IDs'},status_code=503)

    def check_origin(request):
        if request.headers.get('origin') != settings.origin:
            raise HTTPException(403, 'Origin rejected')

    def current(request: Request):
        token = request.cookies.get(COOKIE)
        if not token or len(token) > 100:
            raise HTTPException(401,'Authentication required')
        with closing(connect(settings.db_path)) as db:
            row = db.execute('''SELECT u.id,u.username,u.role,s.csrf,s.token_hash,s.expires_at FROM sessions s
                JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.active=1 AND s.expires_at>?''',
                (digest(token),now_ms())).fetchone()
        if row is None:
            raise HTTPException(401,'Session expired or revoked')
        if request.method not in {'GET','HEAD','OPTIONS'}:
            check_origin(request)
            supplied_csrf = request.headers.get('x-csrf-token','')
            if not supplied_csrf.isascii() or not secrets.compare_digest(supplied_csrf,row['csrf']):
                raise HTTPException(403,'CSRF token rejected')
        return dict(row)

    def roles(*allowed):
        def permitted(user=Depends(current)):
            if user['role'] not in allowed:
                raise HTTPException(403,'Role is not permitted for this action')
            return user
        return permitted
    reader = roles('admin','analyst','viewer')
    analyst = roles('admin','analyst')
    admin = roles('admin')

    @app.get('/healthz')
    def health():
        with closing(connect(settings.db_path)) as db:
            db.execute('SELECT 1').fetchone()
        return {'status':'ok'}

    @app.post('/api/login')
    def login(data: Login, request: Request, response: Response):
        check_origin(request)
        timestamp = now_ms()
        # Ignore forwarded-for headers; only trust the actual server peer.
        peer = request.client.host if request.client else 'unknown'
        keys = [digest('ip:'+peer), digest('user:'+data.username.lower())]
        with transaction(settings.db_path) as db:
            db.execute('DELETE FROM login_attempts WHERE reset_at<=?',(timestamp,))
            for key in keys:
                row = db.execute('SELECT count FROM login_attempts WHERE key=?',(key,)).fetchone()
                if row and row['count'] >= 10:
                    raise HTTPException(429,'Too many login attempts; retry after 15 minutes',headers={'Retry-After':'900'})
            # Commit the attempt counter even on failure; raising inside this transaction would roll it back.
            for key in keys:
                db.execute('INSERT INTO login_attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key,timestamp+900_000))
            row = db.execute('SELECT * FROM users WHERE username=?',(data.username,)).fetchone()
        valid = verify_password(row['password_hash'] if row else DUMMY_HASH,data.password)
        if not row or not row['active'] or not valid:
            with transaction(settings.db_path) as db:
                audit(db,'anonymous','auth.failed',detail={'username_digest':digest(data.username)})
            raise HTTPException(401,'Invalid username or password')
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with transaction(settings.db_path) as db:
            # Check disabled status again after the expensive password verification.
            latest = db.execute('SELECT active,password_hash FROM users WHERE id=?',(row['id'],)).fetchone()
            if not latest or not latest['active'] or latest['password_hash'] != row['password_hash']:
                raise HTTPException(401,'Invalid username or password')
            db.execute('DELETE FROM sessions WHERE expires_at<=?',(timestamp,))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(digest(token),row['id'],csrf,timestamp+settings.session_seconds*1000,timestamp))
            db.execute('DELETE FROM login_attempts WHERE key=?',(keys[1],))
            db.execute('UPDATE login_attempts SET count=MAX(0,count-1) WHERE key=?',(keys[0],))
            audit(db,row['username'],'auth.login')
        response.set_cookie(COOKIE,token,max_age=settings.session_seconds,httponly=True,secure=settings.secure,samesite='strict',path='/')
        return {'user':{k:row[k] for k in ('id','username','role')},'csrf':csrf}

    @app.get('/api/me')
    def me(user=Depends(current)):
        return {'user':{k:user[k] for k in ('id','username','role')},'csrf':user['csrf'], 'environment':settings.environment}

    @app.post('/api/logout')
    def logout(response:Response,user=Depends(current)):
        with transaction(settings.db_path) as db:
            assert_session(db, user)
            db.execute('DELETE FROM sessions WHERE token_hash=?',(user['token_hash'],))
            audit(db,user['username'],'auth.logout')
        response.delete_cookie(COOKIE,secure=settings.secure,httponly=True,samesite='strict')
        return {'ok':True}

    @app.post('/api/password')
    def password(data:PasswordChange,response:Response,user=Depends(current)):
        with closing(connect(settings.db_path)) as db:
            stored = db.execute('SELECT password_hash FROM users WHERE id=?',(user['id'],)).fetchone()[0]
        if not verify_password(stored,data.current_password):
            raise HTTPException(401,'Current password is incorrect')
        hashed = PASSWORDS.hash(data.new_password)
        with transaction(settings.db_path) as db:
            assert_session(db, user)
            db.execute('UPDATE users SET password_hash=? WHERE id=?',(hashed,user['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
            audit(db,user['username'],'auth.password_changed')
        response.delete_cookie(COOKIE)
        return {'ok':True,'detail':'Password changed; all sessions revoked'}

    @app.get('/api/config')
    def config(user=Depends(reader)):
        return {'detector':detector_config(),'environment':settings.environment,'source_labels':{'real':'Real / supplied data','synthetic':'Synthetic · local generator','external_synthetic':'Synthetic · external dataset'}}

    @app.post('/api/transactions/batch')
    def batch(data:Batch,user=Depends(roles('admin','ingestor'))):
        return ingest(settings,data.transactions,user['username'],auth_context=user)

    @app.get('/api/metrics')
    def metrics(provenance:str=Query('synthetic',pattern='^(real|synthetic|external_synthetic)$'),user=Depends(reader)):
        with closing(connect(settings.db_path)) as db:
            tx = dict(db.execute('SELECT count(*) AS transactions,COALESCE(sum(amount_paise),0) AS volume_paise,MAX(occurred_at) AS watermark FROM transactions WHERE provenance=?',(provenance,)).fetchone())
            counts = {r[0]:r[1] for r in db.execute('SELECT status,count(*) FROM alerts WHERE provenance=? GROUP BY status',(provenance,))}
            accounts = db.execute('SELECT count(*) FROM (SELECT sender FROM transactions WHERE provenance=? UNION SELECT receiver FROM transactions WHERE provenance=?)',(provenance,provenance)).fetchone()[0]
        return {**tx,'accounts':accounts,'alerts':counts,'server_time':now_ms(),'provenance':provenance}

    @app.get('/api/alerts')
    def alerts(provenance:str=Query('synthetic',pattern='^(real|synthetic|external_synthetic)$'),status:str=Query('all',pattern='^(all|open|investigating|escalated|dismissed)$'),q:str=Query('',max_length=96),offset:int=Query(0,ge=0),limit:int=Query(50,ge=1,le=100),user=Depends(reader)):
        sql = 'FROM alerts WHERE provenance=? AND (?=\'all\' OR status=?) AND instr(account_id,?)>0'
        params = (provenance,status,status,q)
        with closing(connect(settings.db_path)) as db:
            total = db.execute('SELECT count(*) '+sql,params).fetchone()[0]
            rows = [dict(r) for r in db.execute('SELECT id,account_id,provenance,rule,score,window_seconds,status,version,updated_at,first_event,last_event '+sql+' ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?',params+(limit,offset))]
        return {'items':rows,'total':total,'offset':offset,'limit':limit}

    @app.get('/api/alerts/{alert_id}')
    def alert_detail(alert_id:int,user=Depends(reader)):
        with closing(connect(settings.db_path)) as db:
            row = db.execute('SELECT * FROM alerts WHERE id=?',(alert_id,)).fetchone()
            if not row:
                raise HTTPException(404,'Alert not found')
            value = dict(row)
            value['evidence'] = json.loads(value['evidence'])
            ids = value['evidence']['transaction_ids']
            value['transactions'] = [dict(r) for r in db.execute('SELECT id,occurred_at,sender,receiver,amount_paise,provenance FROM transactions WHERE id IN ('+','.join('?' for _ in ids)+') ORDER BY occurred_at,id',ids)]
            value['reviews'] = [dict(r) for r in db.execute('''SELECT r.status,r.note,r.created_at,u.username,e.alert_version,e.evidence
                FROM reviews r JOIN users u ON u.id=r.user_id LEFT JOIN review_evidence e ON e.review_id=r.id
                WHERE alert_id=? ORDER BY r.id DESC''',(alert_id,))]
            for review in value['reviews']:
                review['evidence'] = json.loads(review['evidence']) if review['evidence'] else None
        return value

    @app.get('/api/alerts/{alert_id}/revisions')
    def revisions(alert_id:int,offset:int=Query(0,ge=0),user=Depends(reader)):
        with closing(connect(settings.db_path)) as db:
            rows = [dict(r) for r in db.execute('SELECT version,evidence,created_at FROM evidence_revisions WHERE alert_id=? ORDER BY version DESC LIMIT 20 OFFSET ?',(alert_id,offset))]
            for row in rows:
                row['evidence'] = json.loads(row['evidence'])
        return {'items':rows}

    @app.post('/api/alerts/{alert_id}/review')
    def review(alert_id:int,data:Review,user=Depends(analyst)):
        with transaction(settings.db_path) as db:
            assert_session(db, user, {'admin','analyst'})
            row = db.execute('SELECT version,evidence FROM alerts WHERE id=?',(alert_id,)).fetchone()
            if not row:
                raise HTTPException(404,'Alert not found')
            if row['version'] != data.version:
                raise HTTPException(409,'Alert changed; reload before reviewing')
            db.execute('UPDATE alerts SET status=?,assigned_to=?,version=version+1,updated_at=? WHERE id=?',(data.status,user['id'],now_ms(),alert_id))
            cursor = db.execute('INSERT INTO reviews(alert_id,user_id,status,note,created_at) VALUES(?,?,?,?,?)',(alert_id,user['id'],data.status,data.note,now_ms()))
            db.execute('INSERT INTO review_evidence VALUES(?,?,?)',(cursor.lastrowid,row['version'],row['evidence']))
            audit(db,user['username'],'alert.reviewed',alert_id,{'status':data.status,'evidence_version':row['version']})
        return {'ok':True,'version':data.version+1}

    @app.get('/api/users')
    def users(user=Depends(admin)):
        with closing(connect(settings.db_path)) as db:
            return {'items':[dict(r) for r in db.execute('SELECT id,username,role,active,created_at FROM users ORDER BY id')]}

    @app.post('/api/users',status_code=201)
    def create_user(data:UserCreate,user=Depends(admin)):
        hashed = PASSWORDS.hash(data.password)
        try:
            with transaction(settings.db_path) as db:
                assert_session(db, user, {'admin'})
                cursor = db.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(data.username,hashed,data.role,now_ms()))
                audit(db,user['username'],'user.created',cursor.lastrowid,{'username':data.username,'role':data.role})
        except sqlite3.IntegrityError:
            raise HTTPException(409,'Username already exists')
        return {'ok':True}

    @app.patch('/api/users/{user_id}')
    def update_user(user_id:int,data:UserUpdate,user=Depends(admin)):
        if user_id == user['id'] and not data.active:
            raise HTTPException(409,'You cannot disable your own administrator account')
        with transaction(settings.db_path) as db:
            assert_session(db, user, {'admin'})
            target = db.execute('SELECT id,role,active FROM users WHERE id=?',(user_id,)).fetchone()
            if not target:
                raise HTTPException(404,'User not found')
            if not data.active and target['active'] and target['role']=='admin':
                count = db.execute("SELECT count(*) FROM users WHERE active=1 AND role='admin'").fetchone()[0]
                if count <= 1:
                    raise HTTPException(409, 'Cannot disable the last active administrator')
            db.execute('UPDATE users SET active=? WHERE id=?',(int(data.active),user_id))
            db.execute('DELETE FROM sessions WHERE user_id=?',(user_id,))
            audit(db,user['username'],'user.active_changed',user_id,{'active':data.active})
        return {'ok':True}

    @app.get('/api/audit')
    def audit_log(offset:int=Query(0,ge=0),user=Depends(admin)):
        with closing(connect(settings.db_path)) as db:
            return {'items':[dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100 OFFSET ?',(offset,))]}

    @app.get('/api/demo/scenarios')
    def scenarios(user=Depends(admin)):
        from .synthetic import SCENARIOS
        return {'items':SCENARIOS,'enabled':not settings.secure}

    @app.post('/api/demo/{scenario}')
    def demo(scenario:str,user=Depends(admin)):
        if settings.secure:
            raise HTTPException(404,'Synthetic replay is disabled in production')
        from .synthetic import generate_scenario, SCENARIOS
        if scenario not in SCENARIOS:
            raise HTTPException(404,'Unknown synthetic scenario')
        data = generate_scenario(scenario,now_ms=now_ms()-1000,seed=secrets.randbelow(1_000_000))
        suffix = secrets.token_hex(4)
        for item in data['transactions']:
            item['id'] += ':'+suffix
            item['sender'] += ':'+suffix
            item['receiver'] += ':'+suffix
        result = ingest(settings,Batch(transactions=data['transactions']).transactions,user['username'],auth_context=user)
        return {**result,'provenance':'synthetic','description':data['description']}

    app.mount('/static', StaticFiles(directory=STATIC), name='static')

    @app.get('/')
    def index():
        return FileResponse(STATIC/'index.html')

    return app
