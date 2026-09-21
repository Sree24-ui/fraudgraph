import argparse
import getpass
import os
import secrets
from pathlib import Path
from .db import initialize, transaction, audit, now_ms
from .security import PASSWORDS, Settings

def main():
    parser = argparse.ArgumentParser(description='FraudGraph administration')
    parser.add_argument('command', choices=['init-admin','serve'])
    parser.add_argument('--username', default='admin')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.command == 'init-admin':
        from .models import UserCreate
        password = getpass.getpass('New administrator password (14+ characters): ')
        if password != getpass.getpass('Confirm password: '):
            raise SystemExit('Passwords do not match')
        data = UserCreate(username=args.username,password=password,role='admin')
        initialize(settings.db_path)
        with transaction(settings.db_path) as db:
            if db.execute("SELECT 1 FROM users WHERE role='admin' AND active=1").fetchone():
                raise SystemExit('An active administrator already exists; use the authenticated users API')
            db.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(data.username,PASSWORDS.hash(data.password),'admin',now_ms()))
            audit(db,'local-cli','admin.bootstrapped',detail={'username':data.username})
        print('Administrator created. No default credentials were installed.')
    else:
        import uvicorn
        uvicorn.run('fraudgraph.app:create_app',factory=True,host='127.0.0.1',port=args.port,proxy_headers=False,access_log=False)

if __name__ == '__main__':
    main()
