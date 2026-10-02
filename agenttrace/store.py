"""Append-only, tamper-evident event store (SQLite + hash chain).

One hash-chained `event` table is the source of truth; artifact/replication/
incident tables are indexes derived from it. The chain means an agent running
as a normal user cannot alter a past row without breaking every later hash.
"""
import sqlite3
import hashlib
import json
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS event (
    id        INTEGER PRIMARY KEY,
    ts        REAL NOT NULL,
    kind      TEXT NOT NULL,          -- read|write|action|verdict|os_event|incident
    session   TEXT,
    agent     TEXT,
    data      TEXT NOT NULL,          -- JSON payload
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifact (
    id           TEXT PRIMARY KEY,    -- sha256 of normalized content
    kind         TEXT,                -- file|mail|message|memory
    location     TEXT,
    from_internet INTEGER DEFAULT 0,
    tainted      INTEGER DEFAULT 0,
    infected     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS replication (
    id            INTEGER PRIMARY KEY,
    src           TEXT NOT NULL,      -- artifact id copied FROM
    replica       TEXT NOT NULL,      -- artifact id copied INTO
    similarity    REAL,
    directive     REAL,
    next_action   TEXT,
    event_id      INTEGER
);
CREATE TABLE IF NOT EXISTS incident (
    id       INTEGER PRIMARY KEY,
    ts       REAL,
    rule     TEXT,
    evidence TEXT,                    -- JSON list of event ids
    source   TEXT,                    -- origin artifact id
    scope    TEXT,                    -- JSON list of infected artifact ids
    status   TEXT DEFAULT 'open'
);
"""

GENESIS = "0" * 64


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def _last_hash(self):
        row = self.db.execute("SELECT hash FROM event ORDER BY id DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def append(self, kind, data, session=None, agent=None, ts=None):
        """Append one hash-chained event. Returns the new event id."""
        ts = time.time() if ts is None else ts
        prev = self._last_hash()
        payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
        # hash covers the previous hash + this row's canonical content
        h = hashlib.sha256(
            f"{prev}|{ts}|{kind}|{session}|{agent}|{payload}".encode()
        ).hexdigest()
        cur = self.db.execute(
            "INSERT INTO event(ts,kind,session,agent,data,prev_hash,hash) "
            "VALUES(?,?,?,?,?,?,?)",
            (ts, kind, session, agent, payload, prev, h),
        )
        self.db.commit()
        return cur.lastrowid

    def verify_chain(self):
        """Return (ok, first_broken_id). ok=True means no row was altered."""
        prev = GENESIS
        for r in self.db.execute("SELECT * FROM event ORDER BY id"):
            h = hashlib.sha256(
                f"{prev}|{r['ts']}|{r['kind']}|{r['session']}|{r['agent']}|{r['data']}".encode()
            ).hexdigest()
            if h != r["hash"] or r["prev_hash"] != prev:
                return False, r["id"]
            prev = h
        return True, None

    # --- artifact state (upsert; latest flags win) ---
    def upsert_artifact(self, aid, kind=None, location=None, from_internet=None):
        self.db.execute(
            "INSERT INTO artifact(id,kind,location,from_internet) VALUES(?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "kind=COALESCE(excluded.kind,kind), "
            "location=COALESCE(excluded.location,location), "
            "from_internet=COALESCE(excluded.from_internet,from_internet)",
            (aid, kind, location, 1 if from_internet else (None if from_internet is None else 0)),
        )
        self.db.commit()

    def set_flag(self, aid, **flags):
        for k, v in flags.items():
            assert k in ("tainted", "infected"), k
            self.db.execute(f"UPDATE artifact SET {k}=? WHERE id=?", (1 if v else 0, aid))
        self.db.commit()

    def artifact(self, aid):
        return self.db.execute("SELECT * FROM artifact WHERE id=?", (aid,)).fetchone()

    def add_replication(self, src, replica, similarity, directive, next_action, event_id):
        self.db.execute(
            "INSERT INTO replication(src,replica,similarity,directive,next_action,event_id) "
            "VALUES(?,?,?,?,?,?)",
            (src, replica, similarity, directive, next_action, event_id),
        )
        self.db.commit()

    def replications(self):
        return self.db.execute("SELECT * FROM replication").fetchall()

    def add_incident(self, rule, evidence, source, scope, ts=None):
        cur = self.db.execute(
            "INSERT INTO incident(ts,rule,evidence,source,scope) VALUES(?,?,?,?,?)",
            (ts or time.time(), rule, json.dumps(evidence), source, json.dumps(scope)),
        )
        self.db.commit()
        return cur.lastrowid

    def incidents(self):
        return self.db.execute("SELECT * FROM incident ORDER BY id DESC").fetchall()

    def event(self, eid):
        return self.db.execute("SELECT * FROM event WHERE id=?", (eid,)).fetchone()
