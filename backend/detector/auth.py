"""Minimal email/password auth: signup, login, and JWT session tokens.

Not tied into the scan pipeline yet — scans stay global regardless of
who's logged in. This just gets accounts working end to end.
"""

import sqlite3
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import jwt

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scan_history.db"
SECRET_PATH = Path(__file__).resolve().parent.parent / "data" / ".jwt_secret"
TOKEN_TTL = timedelta(days=7)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _get_secret() -> str:
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SECRET_PATH.exists():
        return SECRET_PATH.read_text(encoding="utf-8").strip()
    secret = secrets.token_hex(32)
    SECRET_PATH.write_text(secret, encoding="utf-8")
    return secret


_SECRET = _get_secret()


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


class AuthError(Exception):
    pass


def signup(name: str, email: str, password: str) -> dict:
    email = email.strip().lower()
    if not name.strip():
        raise AuthError("Name is required.")
    if "@" not in email:
        raise AuthError("Enter a valid email address.")
    if len(password) < 8:
        raise AuthError("Password needs to be at least 8 characters.")

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    with _connect() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise AuthError("An account with that email already exists.")
        cursor = conn.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name.strip(), email, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        user_id = cursor.lastrowid

    return _issue_token(user_id, name.strip(), email)


def login(email: str, password: str) -> dict:
    email = email.strip().lower()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not row or not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8")):
        raise AuthError("Incorrect email or password.")

    return _issue_token(row["id"], row["name"], row["email"])


def _issue_token(user_id: int, name: str, email: str) -> dict:
    payload = {
        "sub": str(user_id),
        "name": name,
        "email": email,
        "exp": datetime.now(timezone.utc) + TOKEN_TTL,
    }
    token = jwt.encode(payload, _SECRET, algorithm="HS256")
    return {"token": token, "name": name, "email": email}


def current_user(token: str) -> dict:
    try:
        payload = jwt.decode(token, _SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise AuthError("Session expired or invalid — please log in again.") from exc
    return {"name": payload["name"], "email": payload["email"]}
