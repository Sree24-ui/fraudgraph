import hashlib
import secrets
from dataclasses import dataclass
import os
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException
from .db import now_ms

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
ROLES = {'admin', 'analyst', 'viewer', 'ingestor'}

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def verify_password(stored, value):
    try:
        return PASSWORDS.verify(stored, value)
    except (VerificationError, InvalidHashError):
        return False

def assert_session(db, user, allowed_roles=None):
    """Recheck authority under the same write lock as the protected mutation."""
    row = db.execute('''SELECT u.role FROM users u JOIN sessions s ON s.user_id=u.id
        WHERE u.id=? AND u.active=1 AND s.token_hash=? AND s.expires_at>?''',
        (user['id'], user['token_hash'], now_ms())).fetchone()
    if row is None:
        raise HTTPException(401, 'Session expired or revoked before the write')
    if allowed_roles and row['role'] not in allowed_roles:
        raise HTTPException(403, 'Role is not permitted for this action')

@dataclass(frozen=True)
class Settings:
    db_path: str = 'data/fraudgraph.sqlite3'
    environment: str = 'production'
    origin: str = 'https://localhost'
    session_seconds: int = 28800
    max_body_bytes: int = 131072

    @property
    def secure(self):
        return self.environment != 'development'

    @classmethod
    def from_env(cls):
        value = cls(db_path=os.getenv('FRAUDGRAPH_DB', 'data/fraudgraph.sqlite3'),
                    environment=os.getenv('FRAUDGRAPH_ENV', 'production'),
                    origin=os.getenv('FRAUDGRAPH_ORIGIN', 'https://localhost'))
        parsed = urlparse(value.origin)
        if value.environment not in {'development', 'production'}:
            raise ValueError('FRAUDGRAPH_ENV must be development or production')
        if not parsed.hostname or parsed.path or parsed.query or parsed.username or parsed.fragment:
            raise ValueError('FRAUDGRAPH_ORIGIN must be a canonical origin without a path')
        if value.secure and parsed.scheme != 'https':
            raise ValueError('Production requires an HTTPS origin')
        if not value.secure and parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
            raise ValueError('Development mode is restricted to a loopback origin')
        return value
