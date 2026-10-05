"""SQLite repository. Each operation uses its own connection for worker safety."""
import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import AccessDenied, Result, ValidationError, utcnow
from .security import password_hash, password_matches, require, username

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
 name TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL,
 failures INTEGER NOT NULL DEFAULT 0, locked_until TEXT);
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
 created_at TEXT NOT NULL, owner TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
 name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
 source TEXT NOT NULL, acquired_at TEXT NOT NULL, imported_at TEXT NOT NULL,
 size INTEGER NOT NULL, data_kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
 module TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, result TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL,
 previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS watchlist (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
 kind TEXT NOT NULL, target TEXT NOT NULL, last_checked TEXT);
"""


class Store:
    def __init__(self, home: Path):
        self.home = home
        self.path = home / "cyberintel.sqlite"
        with self.connection() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] > 1:
                raise ValidationError("This workspace uses a newer database schema. Upgrade CyberIntel Suite.")
            db.executescript(SCHEMA)
            db.execute("PRAGMA user_version=1")
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def initialized(self):
        with self.connection() as db:
            return db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

    @staticmethod
    def _audit(db, actor, action, detail):
        previous = db.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        timestamp = utcnow()
        payload = json.dumps([timestamp, actor, action, detail, previous], separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        db.execute("INSERT INTO audit(timestamp,actor,action,detail,previous_hash,entry_hash) VALUES(?,?,?,?,?,?)",
                   (timestamp, actor, action, detail, previous, digest))

    def bootstrap(self, name, password):
        name = username(name)
        hashed = password_hash(password)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM users").fetchone():
                raise AccessDenied("Administrator already exists.")
            db.execute("INSERT INTO users(name,password,role) VALUES(?,?,?)", (name, hashed, "admin"))
            self._audit(db, name, "bootstrap", "Initial administrator created")

    def login(self, name, password):
        failure = False
        role = None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
            if row and row["locked_until"] and row["locked_until"] > utcnow():
                raise AccessDenied("Account temporarily locked. Retry after 5 minutes.")
            if not row or not password_matches(password, row["password"]):
                if row:
                    failures = (0 if row["locked_until"] else row["failures"]) + 1
                    lock = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat() if failures >= 5 else None
                    db.execute("UPDATE users SET failures=?, locked_until=? WHERE name=?", (failures, lock, name))
                self._audit(db, "authentication", "login_failed", "Invalid credentials")
                failure = True
            else:
                role = row["role"]
                db.execute("UPDATE users SET failures=0, locked_until=NULL WHERE name=?", (name,))
                self._audit(db, name, "login", "Session started")
        if failure:
            raise AccessDenied("Invalid username or password.")
        return Session(self, name, role)

    def cache_get(self, key):
        with self.connection() as db:
            row = db.execute("SELECT result FROM cache WHERE key=?", (key,)).fetchone()
            if not row:
                return None
            try:
                result = Result(**json.loads(row[0]))
                date = datetime.fromisoformat(result.collected_at)
                if date.tzinfo is None:
                    raise ValueError("Timestamp has no timezone")
                return result
            except (ValueError, TypeError):
                # Cache is disposable; damaged entries must not prevent fresh collection.
                db.execute("DELETE FROM cache WHERE key=?", (key,))
                return None

    def cache_put(self, key, result):
        with self.connection() as db:
            db.execute("INSERT OR REPLACE INTO cache VALUES(?,?)", (key, json.dumps(result.to_dict())))


class Session:
    def __init__(self, store, actor, role):
        self.store, self.actor, self.role = store, actor, role

    def check(self, permission):
        # Refresh role from the database so a revoked privilege takes effect immediately.
        with self.store.connection() as db:
            row = db.execute("SELECT role FROM users WHERE name=?", (self.actor,)).fetchone()
        self.role = row[0] if row else ""
        require(self.role, permission)

    def rows(self, table, case_id=None):
        self.check("read")
        if table not in {"cases", "evidence", "findings", "audit", "users", "watchlist"}:
            raise ValidationError("Unknown table")
        if table == "users":
            self.check("users")
        columns = "name, role" if table == "users" else "*"
        sql = f"SELECT {columns} FROM {table}"
        params = ()
        if case_id and table in {"evidence", "findings", "watchlist"}:
            sql += " WHERE case_id=?"
            params = (case_id,)
        order = {"cases": "created_at DESC", "evidence": "imported_at DESC", "findings": "created_at DESC",
                 "audit": "id DESC", "users": "name", "watchlist": "rowid DESC"}[table]
        sql += " ORDER BY " + order
        with self.store.connection() as db:
            return [dict(row) for row in db.execute(sql, params)]

    def create_case(self, title, description=""):
        self.check("case")
        if not title.strip() or len(title) > 200:
            raise ValidationError("Case title must be 1–200 characters.")
        identifier = str(uuid.uuid4())
        with self.store.connection() as db:
            db.execute("INSERT INTO cases VALUES(?,?,?,?,?)", (identifier, title.strip(), description, utcnow(), self.actor))
            self.store._audit(db, self.actor, "case_created", identifier)
        return identifier

    def add_user(self, name, password, role):
        self.check("users")
        name = username(name)
        if role not in {"admin", "analyst", "viewer"}:
            raise ValidationError("Invalid role")
        with self.store.connection() as db:
            db.execute("INSERT INTO users(name,password,role) VALUES(?,?,?)", (name, password_hash(password), role))
            self.store._audit(db, self.actor, "user_created", f"{name}: {role}")

    def add_evidence(self, case_id, path, source, acquired_at, data_kind="actual"):
        self.check("evidence")
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValidationError("Select a regular evidence file, not a symlink.")
        if path.suffix.lower() not in {".csv", ".xlsx", ".pcap", ".pcapng", ".json", ".txt", ".pdf"}:
            raise ValidationError("Unsupported evidence extension.")
        if path.stat().st_size > 200 * 1024 * 1024:
            raise ValidationError("Evidence limit is 200 MiB.")
        if not source.strip():
            raise ValidationError("Evidence source is required.")
        date = datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValidationError("Acquisition time must include a timezone.")
        if data_kind not in {"actual", "inferred", "synthetic"}:
            raise ValidationError("Invalid data provenance kind.")
        with self.store.connection() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValidationError("Select an existing case.")
        identifier = str(uuid.uuid4())
        directory = self.store.home / "evidence" / case_id
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination = directory / (identifier + path.suffix.lower())
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as src, destination.open("xb") as out:
                while chunk := src.read(1024 * 1024):
                    size += len(chunk)
                    if size > 200 * 1024 * 1024:
                        raise ValidationError("Evidence exceeded limit while copying.")
                    digest.update(chunk)
                    out.write(chunk)
            os.chmod(destination, 0o600)
            with self.store.connection() as db:
                db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (identifier, case_id, path.name, str(destination), digest.hexdigest(), source,
                            date.isoformat(), utcnow(), size, data_kind))
                self.store._audit(db, self.actor, "evidence_imported", f"{identifier} SHA256={digest.hexdigest()}")
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return identifier

    def verify_evidence(self, case_id):
        rows = self.rows("evidence", case_id)
        results = []
        for row in rows:
            path = Path(row["path"])
            digest = hashlib.sha256()
            try:
                with path.open("rb") as file:
                    while chunk := file.read(1024 * 1024):
                        digest.update(chunk)
                valid = digest.hexdigest() == row["sha256"]
            except OSError:
                valid = False
            results.append({"name": row["name"], "valid": valid, "expected_sha256": row["sha256"]})
        self.audit("evidence_verified", json.dumps(results))
        return results

    def save_finding(self, case_id, module, result):
        self.check("collect")
        identifier = str(uuid.uuid4())
        with self.store.connection() as db:
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?)",
                       (identifier, case_id, module, json.dumps(result.to_dict()), utcnow()))
            self.store._audit(db, self.actor, "finding_saved", f"{case_id}: {module}: {identifier}")
        return identifier

    def add_watch(self, case_id, kind, target):
        self.check("collect")
        if kind not in {"email", "domain"}:
            raise ValidationError("Invalid watch type.")
        from .connectors import domain, email
        target = (email if kind == "email" else domain)(target)
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM watchlist WHERE case_id=? AND kind=? AND target=?", (case_id, kind, target)).fetchone():
                raise ValidationError("This exposure watch already exists in the case.")
            if db.execute("SELECT COUNT(*) FROM watchlist WHERE case_id=?", (case_id,)).fetchone()[0] >= 25:
                raise ValidationError("Monitor limit is 25 watches per case.")
            db.execute("INSERT INTO watchlist VALUES(?,?,?,?,NULL)", (str(uuid.uuid4()), case_id, kind, target))
            self.store._audit(db, self.actor, "watch_added", f"{case_id}: {kind}")

    def remove_watch(self, identifier):
        self.check("collect")
        with self.store.connection() as db:
            db.execute("DELETE FROM watchlist WHERE id=?", (identifier,))
            self.store._audit(db, self.actor, "watch_removed", identifier)

    def audit(self, action, detail):
        self.check("read")
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self.store._audit(db, self.actor, action, detail)

    def verify_audit(self):
        previous = "0" * 64
        for row in sorted(self.rows("audit"), key=lambda r: r["id"]):
            payload = json.dumps([row["timestamp"], row["actor"], row["action"], row["detail"], previous], separators=(",", ":"))
            if row["previous_hash"] != previous or hashlib.sha256(payload.encode()).hexdigest() != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True
