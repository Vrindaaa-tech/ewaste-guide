#!/usr/bin/env python3
"""E-Waste Guide backend.

Zero dependencies (Python 3.9+ standard library, SQLite).
Serves the front end at / and a JSON API under /api.

    python3 server.py            # http://127.0.0.1:8000

Environment:
    PORT=8000  HOST=127.0.0.1  EWG_DB=ewaste.db  COOKIE_SECURE=1 (set behind HTTPS)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = os.environ.get("EWG_DB", str(BASE / "ewaste.db"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE") == "1"

ITEM_IDS = {"phone", "charger", "battery", "laptop", "bulb", "tv", "audio", "appl"}
ROLES = {"resident", "admin", "kabadiwala"}
SESSION_DAYS = 14
MAX_BODY = 64 * 1024
PBKDF2_ROUNDS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  name_key TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  salt BLOB NOT NULL,
  pw_hash BLOB NOT NULL,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS deposits(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  item TEXT NOT NULL,
  qty INTEGER NOT NULL CHECK(qty BETWEEN 1 AND 1000),
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  item TEXT NOT NULL,
  qty INTEGER NOT NULL CHECK(qty BETWEEN 1 AND 1000),
  addr TEXT NOT NULL,
  pickup_date TEXT NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  collected_by INTEGER REFERENCES users(id),
  collected_at TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS societies(
  user_id INTEGER PRIMARY KEY REFERENCES users(id),
  name TEXT NOT NULL,
  loc TEXT NOT NULL,
  box TEXT NOT NULL,
  updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  message TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_dep_user ON deposits(user_id);
CREATE INDEX IF NOT EXISTS idx_req_user ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_req_done ON requests(done);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db():
    db = connect()
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    db.commit()
    db.close()


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


# ---------- validation helpers ----------
def text(body, key, maxlen, required=True):
    v = body.get(key, "")
    if not isinstance(v, str):
        raise ApiError(400, f"'{key}' must be text.")
    v = " ".join(v.split()) if key != "message" else v.strip()
    if required and not v:
        raise ApiError(400, f"'{key}' is required.")
    if len(v) > maxlen:
        raise ApiError(400, f"'{key}' is too long (max {maxlen}).")
    return v


def item_id(body):
    v = body.get("item")
    if v not in ITEM_IDS:
        raise ApiError(400, "Unknown item.")
    return v


def qty(body):
    v = body.get("qty")
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 1000:
        raise ApiError(400, "Quantity must be a whole number from 1 to 1000.")
    return v


# ---------- passwords & sessions ----------
def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)


def sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user_id):
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions VALUES(?,?,?)",
        (sha(token), user_id, time.time() + SESSION_DAYS * 86400),
    )
    return token


FAILS = {}  # (ip, name_key) -> [timestamps]


def check_rate(key):
    window = [t for t in FAILS.get(key, []) if time.time() - t < 300]
    FAILS[key] = window
    if len(window) >= 5:
        raise ApiError(429, "Too many failed attempts. Try again in a few minutes.")


def public_user(row):
    return {"name": row["name"], "role": row["role"]}


# ---------- route handlers ----------
# Each returns (status, payload, extra_headers). `ctx` holds db, user, body, ip.
def auth(ctx, _m):
    body = ctx["body"]
    name = text(body, "name", 40)
    password = body.get("pass")
    if not isinstance(password, str) or not 6 <= len(password) <= 200:
        raise ApiError(400, "Password must be at least 6 characters.")
    role = body.get("role", "resident")
    if role not in ROLES:
        raise ApiError(400, "Unknown role.")
    key = name.casefold()
    db = ctx["db"]
    check_rate((ctx["ip"], key))
    row = db.execute("SELECT * FROM users WHERE name_key=?", (key,)).fetchone()
    created = False
    if row is None:
        salt = secrets.token_bytes(16)
        cur = db.execute(
            "INSERT INTO users(name,name_key,role,salt,pw_hash,created_at) VALUES(?,?,?,?,?,?)",
            (name, key, role, salt, hash_pw(password, salt), now()),
        )
        row = db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        created = True
    elif not hmac.compare_digest(hash_pw(password, row["salt"]), row["pw_hash"]):
        FAILS.setdefault((ctx["ip"], key), []).append(time.time())
        raise ApiError(401, "Wrong name or password.")
    token = create_session(db, row["id"])
    cookie = f"ewg_sid={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_DAYS * 86400}"
    if COOKIE_SECURE:
        cookie += "; Secure"
    return 200, {"user": public_user(row), "created": created}, {"Set-Cookie": cookie}


def logout(ctx, _m):
    if ctx.get("token"):
        ctx["db"].execute("DELETE FROM sessions WHERE token_hash=?", (sha(ctx["token"]),))
    return 200, {"ok": True}, {"Set-Cookie": "ewg_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"}


def me(ctx, _m):
    u = ctx["user"]
    return 200, {"user": public_user(u) if u else None}, {}


def need_user(ctx):
    if not ctx["user"]:
        raise ApiError(401, "Please log in first.")
    return ctx["user"]


def need_role(ctx, role, msg):
    u = need_user(ctx)
    if u["role"] != role:
        raise ApiError(403, msg)
    return u


def deposits_list(ctx, _m):
    u = need_user(ctx)
    rows = ctx["db"].execute(
        "SELECT id,item,qty,created_at AS \"on\" FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 500",
        (u["id"],),
    ).fetchall()
    return 200, {"deposits": [dict(r) for r in rows]}, {}


def deposits_add(ctx, _m):
    u = need_user(ctx)
    b = ctx["body"]
    it, q = item_id(b), qty(b)
    cur = ctx["db"].execute(
        "INSERT INTO deposits(user_id,item,qty,created_at) VALUES(?,?,?,?)", (u["id"], it, q, now())
    )
    return 201, {"id": cur.lastrowid}, {}


REQ_COLS = "id,item,qty,addr,pickup_date AS date,done,created_at"


def requests_list(ctx, _m):
    u = need_user(ctx)
    rows = ctx["db"].execute(
        f"SELECT {REQ_COLS} FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 500", (u["id"],)
    ).fetchall()
    return 200, {"requests": [dict(r, done=bool(r["done"])) for r in rows]}, {}


def requests_add(ctx, _m):
    u = need_user(ctx)
    b = ctx["body"]
    it, q = item_id(b), qty(b)
    addr = text(b, "addr", 300)
    date = text(b, "date", 10)
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise ApiError(400, "Date must look like YYYY-MM-DD.")
    cur = ctx["db"].execute(
        "INSERT INTO requests(user_id,item,qty,addr,pickup_date,created_at) VALUES(?,?,?,?,?,?)",
        (u["id"], it, q, addr, date, now()),
    )
    return 201, {"id": cur.lastrowid}, {}


def requests_open(ctx, _m):
    need_role(ctx, "kabadiwala", "Only kabadiwalas can see all requests.")
    rows = ctx["db"].execute(
        "SELECT r.id,r.item,r.qty,r.addr,r.pickup_date AS date,r.done,u.name AS \"by\" "
        "FROM requests r JOIN users u ON u.id=r.user_id "
        "ORDER BY r.done ASC, r.pickup_date ASC, r.id ASC LIMIT 500"
    ).fetchall()
    return 200, {"requests": [dict(r, done=bool(r["done"])) for r in rows]}, {}


def request_collect(ctx, m):
    u = need_role(ctx, "kabadiwala", "Only kabadiwalas can mark pickups collected.")
    rid = int(m.group(1))
    db = ctx["db"]
    cur = db.execute(
        "UPDATE requests SET done=1,collected_by=?,collected_at=? WHERE id=? AND done=0",
        (u["id"], now(), rid),
    )
    if cur.rowcount == 0 and not db.execute("SELECT 1 FROM requests WHERE id=?", (rid,)).fetchone():
        raise ApiError(404, "Request not found.")
    return 200, {"ok": True}, {}  # idempotent if already collected


def society_get(ctx, _m):
    u = need_user(ctx)
    row = ctx["db"].execute(
        "SELECT name,loc,box FROM societies WHERE user_id=?", (u["id"],)
    ).fetchone()
    return 200, {"society": dict(row) if row else None}, {}


def society_put(ctx, _m):
    u = need_role(ctx, "admin", "Only society admins can register a society.")
    b = ctx["body"]
    name, loc, box = text(b, "name", 80), text(b, "loc", 80), text(b, "box", 120)
    ctx["db"].execute(
        "INSERT INTO societies(user_id,name,loc,box,updated_at) VALUES(?,?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET name=excluded.name,loc=excluded.loc,"
        "box=excluded.box,updated_at=excluded.updated_at",
        (u["id"], name, loc, box, now()),
    )
    return 200, {"society": {"name": name, "loc": loc, "box": box}}, {}


def stats(ctx, _m):
    db = ctx["db"]
    by = {r["item"]: r["n"] for r in db.execute("SELECT item,SUM(qty) n FROM deposits GROUP BY item")}
    done = db.execute("SELECT COUNT(*) FROM requests WHERE done=1").fetchone()[0]
    open_ = db.execute("SELECT COUNT(*) FROM requests WHERE done=0").fetchone()[0]
    return 200, {"items": sum(by.values()), "done": done, "open": open_, "byItem": by}, {}


def feedback_add(ctx, _m):
    msg = text(ctx["body"], "message", 1000)
    u = ctx["user"]
    ctx["db"].execute(
        "INSERT INTO feedback(user_id,message,created_at) VALUES(?,?,?)",
        (u["id"] if u else None, msg, now()),
    )
    return 201, {"ok": True}, {}


ROUTES = [
    ("POST", r"/api/auth", auth),
    ("POST", r"/api/logout", logout),
    ("GET", r"/api/me", me),
    ("GET", r"/api/deposits", deposits_list),
    ("POST", r"/api/deposits", deposits_add),
    ("GET", r"/api/requests", requests_list),
    ("POST", r"/api/requests", requests_add),
    ("GET", r"/api/requests/open", requests_open),
    ("POST", r"/api/requests/(\d+)/collect", request_collect),
    ("GET", r"/api/society", society_get),
    ("PUT", r"/api/society", society_put),
    ("POST", r"/api/society", society_put),
    ("GET", r"/api/stats", stats),
    ("POST", r"/api/feedback", feedback_add),
]
ROUTES = [(m, re.compile(p + r"$"), f) for m, p, f in ROUTES]

SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'"
    ),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "EwasteGuide/1.0"

    def _reply(self, code, payload=None, headers=None, raw=None, ctype="application/json"):
        data = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "text" in ctype or "json" in ctype else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in {**SEC_HEADERS, **(headers or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _session_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = SimpleCookie(raw)
        except Exception:
            return None
        return c["ewg_sid"].value if "ewg_sid" in c else None

    def _body(self):
        if self.command in ("GET", "HEAD"):
            return {}
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            raise ApiError(415, "Send JSON (Content-Type: application/json).")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "Bad Content-Length.")
        if n > MAX_BODY:
            raise ApiError(413, "Request too large.")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(400, "Invalid JSON.")
        if not isinstance(body, dict):
            raise ApiError(400, "JSON body must be an object.")
        return body

    def _dispatch(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html") and self.command in ("GET", "HEAD"):
            return self._reply(200, raw=(BASE / "public" / "index.html").read_bytes(), ctype="text/html")
        if not path.startswith("/api/"):
            return self._reply(404, {"error": "Not found."})
        matched, allowed = None, []
        for method, rx, fn in ROUTES:
            m = rx.match(path)
            if m:
                allowed.append(method)
                if method == self.command:
                    matched = (fn, m)
        if not matched:
            if allowed:
                return self._reply(405, {"error": "Method not allowed."}, {"Allow": ", ".join(allowed)})
            return self._reply(404, {"error": "Not found."})
        db = connect()
        try:
            token = self._session_token()
            user = None
            if token:
                user = db.execute(
                    "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                    "WHERE s.token_hash=? AND s.expires_at>?",
                    (sha(token), time.time()),
                ).fetchone()
            ctx = {"db": db, "user": user, "token": token, "ip": self.client_address[0], "body": self._body()}
            fn, m = matched
            code, payload, headers = fn(ctx, m)
            db.commit()
            self._reply(code, payload, headers)
        except ApiError as e:
            db.rollback()
            self._reply(e.code, {"error": e.msg})
        except Exception as e:  # never leak internals
            db.rollback()
            self.log_error("unhandled: %r", e)
            self._reply(500, {"error": "Server error."})
        finally:
            db.close()

    do_GET = do_POST = do_PUT = do_HEAD = _dispatch


def main():
    init_db()
    # drop expired sessions on startup
    db = connect()
    db.execute("DELETE FROM sessions WHERE expires_at<?", (time.time(),))
    db.commit()
    db.close()
    print(f"E-Waste Guide running on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
